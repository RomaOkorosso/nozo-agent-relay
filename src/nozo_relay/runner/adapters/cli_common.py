"""Shared adapter-side machinery for the real CLI adapters (T08 Cursor, T09 Codex).

Everything here runs in the SUPERVISOR process: binary discovery, bounded host-side probe commands, and the common
``prepare/observe/collect/cancel/reconcile`` parts of the adapter protocol. The agent CLI itself is only ever started by
``cli_wrapper.py`` inside the sandbox (or by the explicitly named unsandboxed host-probe runner used for evidence).
"""

from __future__ import annotations

import contextlib
import glob
import json
import os
import re
import shutil
import signal
import subprocess
import time
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from pydantic import ValidationError

from nozo_relay.runner.adapters.base import (
    CancelPlan,
    CollectedReport,
    Observation,
    PrepareContext,
    PreparedRun,
    ReconcileView,
    ReportInvalid,
    read_report_bytes,
)
from nozo_relay.runner.adapters import cli_wrapper

WRAPPER_SCRIPT = Path(cli_wrapper.__file__).resolve()
PROBE_TIMEOUT = 25.0
PROBE_TTL_SECONDS = 60.0
FORBIDDEN_ARGV = ("--yolo", "--force", "-f", "--dangerously-bypass-approvals-and-sandbox", "danger-full-access", "--api-key")

_HOST_ENV_PASSTHROUGH = ("PATH", "HOME", "LANG", "LC_ALL", "XDG_CONFIG_HOME", "XDG_DATA_HOME", "XDG_CACHE_HOME", "CODEX_HOME")


# ------------------------------------------------------------------------------------------------ discovery
@dataclass(frozen=True)
class BinaryLocation:
    path: Path | None
    how: str  # "explicit" | "env:<NAME>" | "path:<name>" | "known_location" | "not_found"
    tried: tuple[str, ...] = ()


def discover_binary(
    *, explicit: str | os.PathLike[str] | None, env_name: str, names: Sequence[str], globs: Sequence[str], environ: Mapping[str, str] | None = None
) -> BinaryLocation:
    """Config path -> env var -> PATH -> well-known install locations. A path is never taken from task/model input."""
    environ = os.environ if environ is None else environ
    tried: list[str] = []

    def usable(p: str | os.PathLike[str]) -> Path | None:
        path = Path(p).expanduser()
        tried.append(str(path))
        return path.resolve() if path.is_file() and os.access(path, os.X_OK) else None

    if explicit:
        if (p := usable(explicit)) is not None:
            return BinaryLocation(p, "explicit", tuple(tried))
        return BinaryLocation(None, "not_found", tuple(tried))  # an explicit path that is wrong must not silently fall through
    if environ.get(env_name):
        if (p := usable(environ[env_name])) is not None:
            return BinaryLocation(p, f"env:{env_name}", tuple(tried))
        return BinaryLocation(None, "not_found", tuple(tried))
    for name in names:
        found = shutil.which(name, path=environ.get("PATH"))
        tried.append(f"PATH:{name}")
        if found and (p := usable(found)) is not None:
            return BinaryLocation(p, f"path:{name}", tuple(tried))
    for pattern in globs:
        home = environ.get("HOME")
        expanded = (home + pattern[1:]) if (home and pattern.startswith("~/")) else os.path.expanduser(pattern)
        for cand in sorted(glob.glob(expanded), reverse=True):  # newest version directory first
            if (p := usable(cand)) is not None:
                return BinaryLocation(p, "known_location", tuple(tried))
    return BinaryLocation(None, "not_found", tuple(tried))


# --------------------------------------------------------------------------------------------- probe commands
@dataclass(frozen=True)
class ProbeRun:
    rc: int | None
    out: str
    err: str
    timed_out: bool = False
    error: str = ""

    @property
    def ok(self) -> bool:
        return self.rc == 0 and not self.timed_out and not self.error

    @property
    def text(self) -> str:
        return f"{self.out}\n{self.err}"


def host_env(extra: Mapping[str, str] | None = None, environ: Mapping[str, str] | None = None) -> dict[str, str]:
    """Allow-listed environment for host-side probe commands (nothing else of the supervisor's env is inherited)."""
    environ = os.environ if environ is None else environ
    env = {k: environ[k] for k in _HOST_ENV_PASSTHROUGH if k in environ}
    env.setdefault("PATH", "/usr/local/bin:/usr/bin:/bin")
    env["NO_COLOR"] = "1"
    env["NO_OPEN_BROWSER"] = "1"
    env.update(extra or {})
    return env


def run_probe(argv: Sequence[str], *, env: Mapping[str, str], cwd: Path | None = None, timeout: float = PROBE_TIMEOUT,
              redact: Iterable[str] = ()) -> ProbeRun:
    """Bounded, argv-only, own process group, never a shell. Output is redacted and size-capped."""
    try:
        proc = subprocess.Popen(  # noqa: S603
            list(argv), cwd=cwd, env=dict(env), stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True)
    except OSError as exc:
        return ProbeRun(None, "", "", error=f"{type(exc).__name__}: {exc.strerror or exc}")
    try:
        out, err = proc.communicate(timeout=timeout)
        timed = False
    except subprocess.TimeoutExpired:
        timed = True
        with contextlib.suppress(ProcessLookupError, PermissionError):
            os.killpg(proc.pid, signal.SIGKILL)
        out, err = proc.communicate()
    with contextlib.suppress(ProcessLookupError, PermissionError):
        os.killpg(proc.pid, signal.SIGKILL)  # nothing the probe started may linger

    def clean(b: bytes) -> str:
        return cli_wrapper.redact(b[:200_000].decode("utf-8", "replace"), redact)

    return ProbeRun(proc.returncode, clean(out), clean(err), timed_out=timed)


def parse_version(text: str) -> str | None:
    m = re.search(r"\d{1,4}(?:\.\d+){1,3}(?:[-+][0-9A-Za-z.]+)?", text)
    return m.group(0) if m else None


# --------------------------------------------------------------------------------------------- adapter base
class WrappedCliAdapter:
    """Common half of the real adapters. Subclasses provide ``name``, ``probe``, ``launch`` and the wrapper config."""

    name = "wrapped"
    provider = ""

    # ---- helpers for subclasses
    def _write_ro(self, ctx: PrepareContext, name: str, content: str | bytes) -> Path:
        path = ctx.ro_dir / name
        if isinstance(content, str):
            content = content.encode()
        path.write_bytes(content)
        return path

    def _install_wrapper(self, ctx: PrepareContext, cfg: Mapping[str, Any]) -> tuple[Path, Path]:
        script = ctx.ro_dir / "cli_wrapper.py"
        shutil.copyfile(WRAPPER_SCRIPT, script)
        cfg_path = self._write_ro(ctx, "wrapper_cfg.json", json.dumps(cfg))
        return script, cfg_path

    @staticmethod
    def assert_argv_policy(argv: Iterable[str]) -> None:
        """Structural guard: a bypass flag can never be part of a CLI argv built by an adapter unless the adapter's explicit,
        owner-set policy adds it AFTER this check (see CursorPolicy.allow_force)."""
        bad = [a for a in argv if a in FORBIDDEN_ARGV]
        if bad:
            raise ValueError(f"argv contains a forbidden bypass/secret flag: {bad[0]}")

    # ---- protocol parts shared by all wrapped CLIs
    def observe(self, line: str) -> Observation:
        try:
            doc = json.loads(line)
        except ValueError:
            return Observation("unparsed")  # raw CLI output never steers the supervisor
        if not isinstance(doc, dict) or doc.get("event") not in ("started", "progress"):
            return Observation("unparsed")
        return Observation("progress", {k: v for k, v in doc.items() if isinstance(v, (str, int, float, bool))})

    def collect(self, prepared: PreparedRun) -> CollectedReport:
        raw = read_report_bytes(prepared.report_path)
        try:
            return CollectedReport.model_validate_json(raw)
        except ValidationError as exc:
            fields = sorted({".".join(map(str, e["loc"])) or "?" for e in exc.errors()})[:8]
            raise ReportInvalid(f"report violates the strict schema (fields: {', '.join(fields)})") from None

    def cancel(self, prepared: PreparedRun) -> CancelPlan:
        return CancelPlan(grace_seconds=3.0, note=f"{self.name}: SIGTERM the whole tree, then kill; the wrapper never restarts the CLI")

    def reconcile(self, receipt: Mapping[str, Any]) -> ReconcileView:
        # The workspace is a disposable clone and the CLI conversation is fresh per run (07_ADAPTERS): nothing to resume.
        return ReconcileView(self.name, str(receipt.get("run_id")), safe_to_discard=True, note="fresh CLI session per run; no resume")


class ProbeCache:
    def __init__(self, ttl: float = PROBE_TTL_SECONDS) -> None:
        self.ttl = ttl
        self._value: Any = None
        self._at = 0.0

    def get(self) -> Any:
        return self._value if self._value is not None and time.monotonic() - self._at < self.ttl else None

    def put(self, value: Any) -> Any:
        self._value, self._at = value, time.monotonic()
        return value

    def clear(self) -> None:
        self._value = None
