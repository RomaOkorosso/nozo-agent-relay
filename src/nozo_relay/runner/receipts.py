"""Durable local receipts and outbox (06_EXECUTION_PROTOCOL steps 4, 6, 7).

Everything the supervisor must remember across a crash lives on disk under ``<state_dir>``:

``receipts/<run_id>.json``   one lifecycle record per run (state machine below), atomic + fsynced writes
``outbox/<run_id>.<kind>.json``  messages for the relay with a PERMANENT idempotency key. A lost response
                                 is repeated with the same key; the model is never re-run for it.
``outbox/done/`` ``outbox/rejected/``  delivered / permanently refused entries (kept for audit)

Receipt states::

    reserved -> launching -> running -> (stopping ->) finished
                                              \\-> any non-terminal state --reconcile--> finished(outcome=lost|stop_unknown)

``launching`` is written BEFORE the process is spawned: a crash anywhere after that point leaves a receipt
that reconciliation can act on (kill + confirm absent + quarantine) even if the pid was never recorded.
Terminal receipts are never rewritten except to attach delivery bookkeeping - a lost run cannot be revived.

Receipts contain ids, hashes, pids and reasons only: never environment values, credentials or child output.
"""

from __future__ import annotations

import contextlib
import fcntl
import json
import os
import re
import uuid
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from nozo_relay.clock import Clock, SystemClock

NON_TERMINAL = frozenset({"reserved", "launching", "running", "stopping"})
TERMINAL = frozenset({"finished"})
_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,80}$")
MAX_HISTORY = 100
BACKOFF_SECONDS = (1, 2, 4, 8, 16, 30)
PERMANENT_STATUS = frozenset({400, 401, 403, 404, 409, 412, 422})  # never retried without handling the cause


class ReceiptError(RuntimeError):
    pass


class RunAlreadyUsed(ReceiptError):
    """A receipt for this run id exists: run ids are single-use (no revival of a lost/finished run)."""


def _check_id(value: str) -> str:
    if not _ID.match(value):
        raise ReceiptError(f"invalid identifier {value!r}")
    return value


def _fsync_dir(path: Path) -> None:
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def atomic_write_json(path: Path, data: Any, *, exclusive: bool = False) -> None:
    payload = json.dumps(data, sort_keys=True, indent=1).encode()
    tmp = path.with_name(f".{path.name}.{uuid.uuid4().hex}.tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC, 0o600)
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(payload)
            fh.flush()
            os.fsync(fh.fileno())
        if exclusive:
            try:
                os.link(tmp, path)  # atomic create-if-absent
            except FileExistsError:
                raise
            finally:
                os.unlink(tmp)
        else:
            os.replace(tmp, path)
        _fsync_dir(path.parent)
    except BaseException:
        with contextlib.suppress(OSError):
            os.unlink(tmp)
        raise


def read_json(path: Path) -> Any:
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        with os.fdopen(fd, "rb") as fh:
            return json.loads(fh.read())
    except json.JSONDecodeError as exc:
        raise ReceiptError(f"corrupt state file {path.name}") from exc


class ReceiptStore:
    def __init__(self, root: Path, clock: Clock | None = None) -> None:
        self.root = root
        self.dir = root / "receipts"
        self.clock = clock or SystemClock()
        self.dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.chmod(self.dir, 0o700)

    def path(self, run_id: str) -> Path:
        return self.dir / f"{_check_id(run_id)}.json"

    @contextlib.contextmanager
    def _locked(self, run_id: str) -> Iterator[None]:
        fd = os.open(self.dir / f".{_check_id(run_id)}.lock", os.O_CREAT | os.O_RDWR | os.O_CLOEXEC, 0o600)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX)
            yield
        finally:
            os.close(fd)

    def create(self, run_id: str, **fields: Any) -> dict[str, Any]:
        now = self.clock.now_ms()
        rec: dict[str, Any] = {
            "version": 1, "run_id": run_id, "state": "reserved", "outcome": None,
            "created_at": now, "updated_at": now, "history": [{"state": "reserved", "at": now, "note": "created"}],
            **fields,
        }
        try:
            atomic_write_json(self.path(run_id), rec, exclusive=True)
        except FileExistsError as exc:
            raise RunAlreadyUsed(f"run {run_id} already has a receipt; run ids are single-use") from exc
        return rec

    def get(self, run_id: str) -> dict[str, Any] | None:
        try:
            return read_json(self.path(run_id))
        except FileNotFoundError:
            return None

    def update(self, run_id: str, *, state: str | None = None, note: str = "", **changes: Any) -> dict[str, Any]:
        with self._locked(run_id):
            rec = self.get(run_id)
            if rec is None:
                raise ReceiptError(f"no receipt for run {run_id}")
            if rec["state"] in TERMINAL and (state is not None or set(changes) - {"delivery", "notes"}):
                raise ReceiptError(f"run {run_id} is terminal ({rec['outcome']}); it cannot be revived or rewritten")
            now = self.clock.now_ms()
            if state is not None and state != rec["state"]:
                rec["history"].append({"state": state, "at": now, "note": note[:200]})
                rec["history"] = rec["history"][-MAX_HISTORY:]
                rec["state"] = state
            rec.update(changes)
            rec["updated_at"] = now
            atomic_write_json(self.path(run_id), rec)
            return rec

    def all(self) -> list[dict[str, Any]]:
        out = []
        for p in sorted(self.dir.glob("*.json")):
            with contextlib.suppress(FileNotFoundError, ReceiptError):
                out.append(read_json(p))
        return out

    def non_terminal(self) -> list[dict[str, Any]]:
        return [r for r in self.all() if r["state"] in NON_TERMINAL]

    def for_job(self, job_id: str) -> list[dict[str, Any]]:
        return [r for r in self.all() if r.get("job_id") == job_id]

    def for_binding(self, binding_id: str) -> list[dict[str, Any]]:
        return [r for r in self.all() if r.get("binding_id") == binding_id]


# --------------------------------------------------------------------------------------------- outbox
@dataclass(frozen=True)
class DeliveryResult:
    status: int | None  # HTTP status, None for a transport failure
    retry_after: float | None = None
    detail: str = ""


class Outbox:
    """At-least-once delivery with a stable idempotency key per (run, kind) -> effectively once."""

    def __init__(self, root: Path, clock: Clock | None = None) -> None:
        self.dir = root / "outbox"
        self.clock = clock or SystemClock()
        for d in (self.dir, self.dir / "done", self.dir / "rejected"):
            d.mkdir(parents=True, exist_ok=True, mode=0o700)
            os.chmod(d, 0o700)

    def _path(self, run_id: str, kind: str) -> Path:
        return self.dir / f"{_check_id(run_id)}.{_check_id(kind)}.json"

    def enqueue(self, run_id: str, kind: str, endpoint: str, body: dict[str, Any]) -> dict[str, Any]:
        """Idempotent per (run_id, kind): a second call returns the first entry and changes nothing."""
        now = self.clock.now_ms()
        entry = {
            "id": str(uuid.uuid4()), "run_id": run_id, "kind": kind, "endpoint": endpoint,
            "idempotency_key": str(uuid.uuid4()), "body": body, "created_at": now,
            "attempts": 0, "next_attempt_at": 0, "last_error": None,
        }
        path = self._path(run_id, kind)
        try:
            atomic_write_json(path, entry, exclusive=True)
            return entry
        except FileExistsError:
            return read_json(path)

    def get(self, run_id: str, kind: str) -> dict[str, Any] | None:
        for base in (self.dir, self.dir / "done", self.dir / "rejected"):
            p = base / f"{run_id}.{kind}.json"
            if p.exists():
                return read_json(p)
        return None

    def pending(self) -> list[dict[str, Any]]:
        out = []
        for p in sorted(self.dir.glob("*.json"), key=lambda x: x.stat().st_mtime_ns):
            with contextlib.suppress(FileNotFoundError, ReceiptError):
                out.append(read_json(p))
        return out

    def deliver_pending(self, send: Callable[[dict[str, Any]], DeliveryResult]) -> dict[str, int]:
        """Send due entries. The SAME entry (same key, same body) is resent after a lost response."""
        stats = {"delivered": 0, "rejected": 0, "retry": 0, "skipped": 0}
        now = self.clock.now_ms()
        for entry in self.pending():
            path = self._path(entry["run_id"], entry["kind"])
            if entry["next_attempt_at"] > now:
                stats["skipped"] += 1
                continue
            try:
                res = send(entry)
            except Exception as exc:  # noqa: BLE001 - sender bugs must not lose the entry
                res = DeliveryResult(None, detail=type(exc).__name__)
            entry["attempts"] += 1
            if res.status is not None and 200 <= res.status < 300:
                entry["delivered_at"] = now
                atomic_write_json(path, entry)
                os.replace(path, self.dir / "done" / path.name)
                stats["delivered"] += 1
            elif res.status in PERMANENT_STATUS:
                entry["last_error"] = f"http {res.status}: {res.detail[:200]}"
                atomic_write_json(path, entry)
                os.replace(path, self.dir / "rejected" / path.name)
                stats["rejected"] += 1
            else:
                step = BACKOFF_SECONDS[min(entry["attempts"] - 1, len(BACKOFF_SECONDS) - 1)]
                delay = max(float(step), res.retry_after or 0.0)
                entry["next_attempt_at"] = now + int(delay * 1000)
                entry["last_error"] = (f"http {res.status}" if res.status else f"transport: {res.detail}")[:200]
                atomic_write_json(path, entry)
                stats["retry"] += 1
        return stats
