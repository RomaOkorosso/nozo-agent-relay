"""Child-side wrapper for real agent CLIs (stdlib only; T08 Cursor, T09 Codex).

It runs INSIDE the supervisor's sandbox as ``python -I cli_wrapper.py <wrapper_cfg.json>`` (and is importable by the
adapters/tests for its pure functions). Its job is the part of an adapter that must see the CLI's raw output:

* start the CLI exactly ONCE (argv list from the adapter's config, never a shell string; no retry, no fallback),
* stream the CLI's JSON events, emit only SANITISED progress lines on stdout (``{"event": ...}``), never raw output,
* classify failures into typed codes (auth / rate-limit / quota / permission / network / malformed / timeout),
* write ``report.json`` (CollectedReport shape; strictly re-validated host-side by the adapter's ``collect``).

Trust model: this process is as untrusted as the CLI it starts. The host only believes the strict-schema parse of
``report.json`` and its own manifest/hash checks, never an exit code or a self-claimed "done".

Exit code: 0 whenever a typed report was written (including ``blocked``/``failed`` reports); non-zero only if the
wrapper itself crashed. A ``blocked`` report is the signal "owner action needed, do NOT auto-retry".
"""

from __future__ import annotations

import json
import os
import re
import shutil
import signal
import subprocess
import sys
import threading
import time
from collections.abc import Callable, Iterable, Mapping
from pathlib import Path
from typing import Any

REPORT_BEGIN = "<<<NOZO_REPORT_JSON"
REPORT_END = "NOZO_REPORT_JSON>>>"
IMPLEMENTER_REPORT_KEYS = frozenset({"status", "summary", "checks", "claimed_changed_paths", "error_code"})
MAX_SUMMARY = 3900
MAX_STDERR = 64 * 1024
MAX_LINE = 1024 * 1024

# Typed failure codes. All of them are final for the run: nothing here selects a paid fallback or a weaker policy.
BLOCKING_CODES = ("auth_required", "rate_limited", "quota_exceeded", "permission_required", "network_unreachable")
_RULES: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("auth_required", re.compile(
        r"not logged in|not authenticated|authentication (is )?(required|failed)|unauthori[sz]ed|\b401\b|"
        r"invalid (api[ _-]?)?(key|token|credentials)|(run|use) .{0,40}login|login required|log in to|sign in|"
        r"missing (api[ _-]?)?(key|token)|no (api[ _-]?)?(key|token) (found|provided)|refresh token", re.I)),
    ("rate_limited", re.compile(r"\b429\b|rate[ _-]?limit|too many requests", re.I)),
    ("quota_exceeded", re.compile(
        r"quota|usage limit|out of (credits|usage|requests)|billing|payment required|\b402\b|insufficient (credits|funds)|"
        r"(hit|reached|exceeded) (your |the )?(\w+ )?limit|upgrade (your )?(plan|to)|spend limit|credits? (have )?(run|ran) out", re.I)),
    ("permission_required", re.compile(
        r"permission denied|operation not permitted|approval (is )?required|requires? (user )?approval|denied by (policy|user|rule)|"
        r"blocked by (policy|sandbox)|command (is )?not allowed|not allowed to (run|execute|write|edit)|rejected by user", re.I)),
    ("network_unreachable", re.compile(
        r"ENOTFOUND|EAI_AGAIN|getaddrinfo|could not resolve|failed to lookup address|network is unreachable|"
        r"fetch failed|ECONNREFUSED|ETIMEDOUT|connection (refused|reset|timed out)|dns error", re.I)),
)
NEXT_ACTION = {
    "auth_required": "owner: sign in (`agent login` / `codex login`) or register the provider API key with the supervisor credentials store; the run was NOT retried",
    "rate_limited": "provider returned 429/rate limit: wait for the limit window; the run was NOT retried and no other model/provider was used",
    "quota_exceeded": "provider quota/usage limit reached: owner decides about plan/limits; nothing was purchased, no paid fallback was used",
    "permission_required": "the CLI asked for a permission the policy does not grant: owner must widen the scope/policy explicitly; --force/--yolo was NOT used",
    "network_unreachable": "provider host unreachable from the run environment: check the sandbox egress/DNS allowlist",
}


# ------------------------------------------------------------------------------------------------ pure helpers
def redact(text: str, secrets: Iterable[str] = ()) -> str:
    for s in secrets:
        if s and len(s) >= 6:
            text = text.replace(s, "[REDACTED]")
    return text


def truncate(text: str, limit: int = MAX_SUMMARY) -> str:
    return text if len(text) <= limit else text[: limit - 15] + "...[truncated]"


def classify_failure(text: str) -> str | None:
    """First matching typed code (auth wins over rate/quota, then permission, then network); ``None`` = unclassified."""
    for code, rx in _RULES:
        if rx.search(text):
            return code
    return None


def extract_report_block(text: str) -> tuple[dict[str, Any] | None, str]:
    """(report, problem). The LAST marker block of ``text`` must be one JSON object."""
    b = text.rfind(REPORT_BEGIN)
    if b < 0:
        return None, "final report block is missing"
    start = b + len(REPORT_BEGIN)
    e = text.find(REPORT_END, start)
    if e < 0:
        return None, "final report block is not terminated"
    body = text[start:e].strip()
    try:
        doc = json.loads(body)
    except ValueError:
        return None, "final report block is not valid JSON"
    if not isinstance(doc, dict):
        return None, "final report block is not a JSON object"
    return doc, ""


def blocked_report(code: str, detail: str, secrets: Iterable[str] = ()) -> dict[str, Any]:
    return {"status": "blocked", "error_code": code,
            "summary": truncate(f"{code}: {redact(detail, secrets).strip()[:600]} | next: {NEXT_ACTION[code]}")}


def failed_report(code: str, detail: str, secrets: Iterable[str] = ()) -> dict[str, Any]:
    return {"status": "failed", "error_code": code, "summary": truncate(f"{code}: {redact(detail, secrets).strip()[:900]}")}


def _classified(text: str, fallback_code: str, fallback_detail: str, secrets: Iterable[str]) -> dict[str, Any]:
    code = classify_failure(text)
    if code:
        return blocked_report(code, text[:600], secrets)
    return failed_report(fallback_code, fallback_detail, secrets)


# ----------------------------------------------------------------------------------------------- Cursor stream
class CursorStream:
    """Parser for ``agent -p --output-format stream-json`` (NDJSON, one event object per line).

    Documented event types (cursor.com/docs/cli/headless): ``system`` (subtype ``init``), ``user``, ``assistant``,
    ``tool_call`` (subtype ``started``/``completed``), ``result`` (terminal). Parsing is deliberately tolerant about
    unknown ``type`` values (counted, ignored) and intolerant about non-JSON lines (acceptance is blocked).
    """

    def __init__(self) -> None:
        self.lines = 0
        self.malformed = 0
        self.init: dict[str, Any] | None = None
        self.result: dict[str, Any] | None = None
        self.assistant_text: list[str] = []
        self.error_text: list[str] = []
        self.tool_calls: dict[str, int] = {}
        self.unknown_types: dict[str, int] = {}

    def feed(self, line: str) -> dict[str, Any] | None:
        """Returns a sanitised progress event for the supervisor, or None."""
        line = line.strip()
        if not line:
            return None
        self.lines += 1
        try:
            ev = json.loads(line)
        except ValueError:
            self.malformed += 1
            return None
        if not isinstance(ev, dict) or not isinstance(ev.get("type"), str):
            self.malformed += 1
            return None
        kind = ev["type"]
        sub = ev.get("subtype") if isinstance(ev.get("subtype"), str) else ""
        if kind == "system" and sub == "init":
            self.init = {k: ev.get(k) for k in ("model", "permissionMode", "apiKeySource") if isinstance(ev.get(k), str)}
            return {"event": "started", "provider": "cursor", **self.init}
        if kind == "assistant":
            msg = ev.get("message")
            parts = msg.get("content") if isinstance(msg, dict) else None
            for part in parts if isinstance(parts, list) else []:
                if isinstance(part, dict) and part.get("type") == "text" and isinstance(part.get("text"), str):
                    self.assistant_text.append(part["text"])
            return {"event": "progress", "provider": "cursor", "type": "assistant"}
        if kind == "tool_call":
            body = ev.get("tool_call")
            name = next(iter(body), "unknown") if isinstance(body, dict) and body else "unknown"
            name = re.sub(r"[^A-Za-z0-9_.-]", "", str(name))[:40] or "unknown"
            if sub == "started":
                self.tool_calls[name] = self.tool_calls.get(name, 0) + 1
            return {"event": "progress", "provider": "cursor", "type": "tool_call", "tool": name, "phase": sub[:20]}
        if kind == "result":
            self.result = ev
            return {"event": "progress", "provider": "cursor", "type": "result", "is_error": bool(ev.get("is_error"))}
        if kind == "error":
            msg = ev.get("message") or ev.get("error")
            self.error_text.append(str(msg)[:1000] if msg is not None else json.dumps(ev)[:1000])
            return {"event": "progress", "provider": "cursor", "type": "error"}
        if kind in ("user", "thinking", "status"):
            return None
        self.unknown_types[kind[:40]] = self.unknown_types.get(kind[:40], 0) + 1
        return None

    def final_text(self) -> str:
        if self.result is not None and isinstance(self.result.get("result"), str):
            return self.result["result"]
        return "\n".join(self.assistant_text)


def finalize_cursor(st: CursorStream, *, exit_code: int | None, stderr: str, timed_out: bool, secrets: Iterable[str] = ()) -> dict[str, Any]:
    """Map a finished Cursor run to a CollectedReport-shaped dict. Never raises."""
    secrets = tuple(secrets)
    err_blob = "\n".join([*st.error_text, stderr])
    if timed_out:
        return failed_report("timeout", "CLI exceeded the adapter timeout and was killed", secrets)
    res = st.result
    res_error = bool(res and (res.get("is_error") or str(res.get("subtype", "")).startswith("error")))
    if res_error:
        text = "\n".join([str(res.get("result", "")), err_blob])
        return _classified(text, "agent_error", f"CLI reported an error result ({text.strip()[:500] or 'no detail'})", secrets)
    if exit_code not in (0, None) and res is None:
        return _classified(err_blob, "cli_nonzero_exit", f"CLI exited with {exit_code}: {err_blob.strip()[:500]}", secrets)
    if exit_code not in (0, None):
        return failed_report("cli_nonzero_exit", f"CLI exited with {exit_code} after a result event", secrets)
    if st.malformed:
        return failed_report("malformed_output", f"{st.malformed} stdout line(s) were not valid stream-json events; acceptance blocked", secrets)
    if res is None:
        return _classified(err_blob, "malformed_output", "stream ended without a terminal result event; acceptance blocked", secrets)
    doc, problem = extract_report_block(st.final_text())
    if doc is None:
        return failed_report("malformed_output", f"{problem}; acceptance blocked", secrets)
    unknown = sorted(set(doc) - IMPLEMENTER_REPORT_KEYS)
    if unknown:
        return failed_report("report_schema_violation", f"final report has unknown field(s): {', '.join(k[:30] for k in unknown[:8])}", secrets)
    if not isinstance(doc.get("status"), str) or not isinstance(doc.get("summary"), str) or not doc["summary"].strip():
        return failed_report("malformed_output", "final report lacks a string status/summary", secrets)
    return json.loads(redact(json.dumps(doc), secrets))


# ----------------------------------------------------------------------------------------------- Codex stream
class CodexStream:
    """Parser for ``codex exec --json`` (JSONL): thread.started, turn.started, item.completed(agent_message|command_execution|...),
    turn.completed, turn.failed, error."""

    def __init__(self) -> None:
        self.lines = 0
        self.malformed = 0
        self.messages: list[str] = []
        self.failed: str | None = None
        self.errors: list[str] = []
        self.completed = False
        self.usage: dict[str, int] = {}
        self.items: dict[str, int] = {}

    def feed(self, line: str) -> dict[str, Any] | None:
        line = line.strip()
        if not line:
            return None
        self.lines += 1
        try:
            ev = json.loads(line)
        except ValueError:
            self.malformed += 1
            return None
        if not isinstance(ev, dict) or not isinstance(ev.get("type"), str):
            self.malformed += 1
            return None
        kind = ev["type"]
        if kind == "thread.started":
            return {"event": "started", "provider": "codex"}
        if kind in ("item.completed", "item.started"):
            item = ev.get("item")
            itype = str(item.get("type", "unknown"))[:40] if isinstance(item, dict) else "unknown"
            if kind == "item.completed":
                self.items[itype] = self.items.get(itype, 0) + 1
                if itype == "agent_message" and isinstance(item.get("text"), str):
                    self.messages.append(item["text"])
            return {"event": "progress", "provider": "codex", "type": kind, "item": itype}
        if kind == "turn.completed":
            self.completed = True
            usage = ev.get("usage")
            if isinstance(usage, dict):
                self.usage = {k: v for k, v in usage.items() if isinstance(v, int)}
            return {"event": "progress", "provider": "codex", "type": "turn.completed"}
        if kind == "turn.failed":
            err = ev.get("error")
            self.failed = str(err.get("message") if isinstance(err, dict) else err)[:2000]
            return {"event": "progress", "provider": "codex", "type": "turn.failed"}
        if kind == "error":
            self.errors.append(str(ev.get("message"))[:1000])
            return {"event": "progress", "provider": "codex", "type": "error"}
        return None


def finalize_codex(st: CodexStream, *, exit_code: int | None, stderr: str, timed_out: bool, last_message: str | None,
                   secrets: Iterable[str] = ()) -> tuple[dict[str, Any] | None, dict[str, Any] | None]:
    """(codex_audit_json, failure_report). Exactly one is not None."""
    secrets = tuple(secrets)
    blob = "\n".join([st.failed or "", *st.errors, stderr])
    if timed_out:
        return None, failed_report("timeout", "Codex exceeded the adapter timeout and was killed", secrets)
    if st.failed or (exit_code not in (0, None)):
        return None, _classified(blob, "cli_nonzero_exit", f"codex exited with {exit_code}: {blob.strip()[:500]}", secrets)
    if st.malformed:
        return None, failed_report("malformed_output", f"{st.malformed} stdout line(s) were not valid JSONL events; acceptance blocked", secrets)
    text = last_message if last_message is not None else (st.messages[-1] if st.messages else None)
    if text is None or not text.strip():
        return None, _classified(blob, "malformed_output", "codex produced no final message; acceptance blocked", secrets)
    try:
        doc = json.loads(text)
    except ValueError:
        return None, failed_report("malformed_output", "final message is not JSON; acceptance blocked", secrets)
    if not isinstance(doc, dict):
        return None, failed_report("malformed_output", "final message is not a JSON object; acceptance blocked", secrets)
    return json.loads(redact(json.dumps(doc), secrets)), None


# ------------------------------------------------------------------------------------------------ process I/O
class StreamResult:
    def __init__(self) -> None:
        self.exit_code: int | None = None
        self.stderr = ""
        self.timed_out = False
        self.pid: int | None = None


def _kill_group(proc: subprocess.Popen[bytes], sig: int) -> None:
    try:
        os.killpg(proc.pid, sig)
    except (ProcessLookupError, PermissionError):
        try:
            proc.send_signal(sig)
        except (ProcessLookupError, PermissionError):
            pass


def run_stream(argv: list[str], *, env: Mapping[str, str], cwd: str, stdin: bytes | None, timeout: float,
               on_line: Callable[[str], None]) -> StreamResult:
    """Start argv ONCE in its own process group, feed stdout lines to ``on_line``, kill the group on timeout/SIGTERM."""
    res = StreamResult()
    proc = subprocess.Popen(  # noqa: S603 - argv list, never a shell
        argv, cwd=cwd, env=dict(env), stdin=subprocess.PIPE if stdin is not None else subprocess.DEVNULL,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True, close_fds=True)
    res.pid = proc.pid
    err_chunks: list[bytes] = []

    def pump_err() -> None:
        assert proc.stderr is not None
        total = 0
        for chunk in iter(lambda: proc.stderr.read(4096), b""):  # type: ignore[union-attr]
            if total < MAX_STDERR:
                err_chunks.append(chunk[: MAX_STDERR - total])
                total += len(chunk)

    def pump_out() -> None:
        assert proc.stdout is not None
        for raw in iter(lambda: proc.stdout.readline(MAX_LINE), b""):  # type: ignore[union-attr]
            on_line(raw.decode("utf-8", "replace").rstrip("\r\n"))

    def on_term(signum: int, _frame: Any) -> None:
        _kill_group(proc, signal.SIGKILL)
        os._exit(128 + signum)

    old = signal.signal(signal.SIGTERM, on_term)
    t_err = threading.Thread(target=pump_err, daemon=True)
    t_out = threading.Thread(target=pump_out, daemon=True)
    t_err.start()
    t_out.start()
    if stdin is not None and proc.stdin is not None:
        try:
            proc.stdin.write(stdin)
            proc.stdin.close()
        except OSError:
            pass
    deadline = time.monotonic() + timeout
    while proc.poll() is None:
        if time.monotonic() > deadline:
            res.timed_out = True
            _kill_group(proc, signal.SIGTERM)
            time.sleep(0.5)
            _kill_group(proc, signal.SIGKILL)
            break
        time.sleep(0.05)
    try:
        proc.wait(10)
    except subprocess.TimeoutExpired:
        _kill_group(proc, signal.SIGKILL)
        proc.wait(5)
    _kill_group(proc, signal.SIGKILL)  # whatever the CLI left behind in its group
    t_out.join(5)
    t_err.join(5)
    signal.signal(signal.SIGTERM, old)
    res.exit_code = proc.returncode
    res.stderr = b"".join(err_chunks).decode("utf-8", "replace")
    return res


def emit(obj: Mapping[str, Any]) -> None:
    sys.stdout.write(json.dumps(obj, sort_keys=True) + "\n")
    sys.stdout.flush()


def _write_json(path: Path, doc: Mapping[str, Any]) -> None:
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(json.dumps(doc))
    os.replace(tmp, path)


def _secrets(cfg: Mapping[str, Any]) -> list[str]:
    return [os.environ[n] for n in cfg.get("secret_env", []) if os.environ.get(n)]


# ------------------------------------------------------------------------------------------------- harness checks
def _copy_tree_without_metadata_syscalls(source: Path, scratch: Path) -> None:
    """Disposable, WRITABLE copy of a (read-only) snapshot. Runs inside the sandbox, where seccomp denies
    chmod/chown/utime (T12/F04): so no ``copystat``/``chmod`` - modes are chosen at creation time instead."""
    os.makedirs(scratch, mode=0o755)
    for dirpath, dirnames, filenames in os.walk(source, followlinks=False):
        rel = os.path.relpath(dirpath, source)
        out_dir = scratch if rel == "." else scratch / rel
        for name in dirnames:
            src_dir = os.path.join(dirpath, name)
            if os.path.islink(src_dir):
                os.symlink(os.readlink(src_dir), out_dir / name)
            else:
                os.makedirs(out_dir / name, mode=0o755, exist_ok=True)
        for name in filenames:
            src_file = os.path.join(dirpath, name)
            dst_file = out_dir / name
            if os.path.islink(src_file):
                os.symlink(os.readlink(src_file), dst_file)
                continue
            mode = 0o755 if os.stat(src_file).st_mode & 0o111 else 0o644
            fd = os.open(dst_file, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
            with os.fdopen(fd, "wb") as out, open(src_file, "rb") as inp:
                shutil.copyfileobj(inp, out)


def run_harness_checks(checks: list[dict[str, Any]], source: Path, scratch: Path, secrets: Iterable[str]) -> list[dict[str, Any]]:
    """Owner-configured argv checks, run in a DISPOSABLE COPY of the audited snapshot (never in the source)."""
    out: list[dict[str, Any]] = []
    if not checks:
        return out
    if scratch.exists():
        shutil.rmtree(scratch)
    _copy_tree_without_metadata_syscalls(source, scratch)
    env = {"PATH": "/usr/local/bin:/usr/bin:/bin", "HOME": str(scratch.parent), "LANG": "C.UTF-8", "PYTHONDONTWRITEBYTECODE": "1",
           "PYTHONNOUSERSITE": "1", "NO_COLOR": "1"}
    for spec in checks:
        argv = [sys.executable if a == "{python}" else a for a in spec["argv"]]
        started = time.monotonic()
        entry: dict[str, Any] = {"id": spec["id"], "command_label": spec["label"], "required": bool(spec.get("required", True)),
                                 "expected": "exit code 0", "exit_code": None}
        try:
            cp = subprocess.run(argv, cwd=scratch, env=env, capture_output=True, timeout=float(spec.get("timeout", 120)),  # noqa: S603
                                stdin=subprocess.DEVNULL, check=False)
            blob = (cp.stdout + b"\n" + cp.stderr).decode("utf-8", "replace")
            entry.update(status="pass" if cp.returncode == 0 else "fail", exit_code=cp.returncode, observed=truncate(redact(blob.strip(), secrets)[-1500:], 1500))
        except subprocess.TimeoutExpired:
            entry.update(status="fail", observed="timeout")
        except OSError as exc:
            entry.update(status="not_run", observed=f"cannot start: {type(exc).__name__}")
        entry["duration_ms"] = int((time.monotonic() - started) * 1000)
        out.append(entry)
    return out


# ------------------------------------------------------------------------------------------------------- main
def run_cursor(cfg: Mapping[str, Any]) -> None:
    out_dir = Path(cfg["out_dir"])
    secrets = _secrets(cfg)
    st = CursorStream()

    def on_line(line: str) -> None:
        ev = st.feed(line)
        if ev:
            emit(ev)

    emit({"event": "progress", "provider": "cursor", "type": "launching"})
    try:
        res = run_stream(list(cfg["argv"]), env=os.environ, cwd=cfg["cwd"], stdin=None, timeout=float(cfg["timeout_seconds"]), on_line=on_line)
    except OSError as exc:
        _write_json(out_dir / "report.json", failed_report("cli_unavailable", f"cannot start the CLI: {type(exc).__name__}", secrets))
        return
    report = finalize_cursor(st, exit_code=res.exit_code, stderr=res.stderr, timed_out=res.timed_out, secrets=secrets)
    _write_json(out_dir / "report.json", report)
    _write_json(out_dir / "cli_summary.json", {
        "provider": "cursor", "exit_code": res.exit_code, "timed_out": res.timed_out, "events": st.lines, "malformed_lines": st.malformed,
        "tool_calls": st.tool_calls, "unknown_event_types": st.unknown_types, "init": st.init,
        "stderr_tail": truncate(redact(res.stderr, secrets)[-800:], 800)})
    emit({"event": "progress", "provider": "cursor", "type": "finished", "report_status": report.get("status")})


def run_codex(cfg: Mapping[str, Any]) -> None:
    out_dir = Path(cfg["out_dir"])
    secrets = _secrets(cfg)
    cx = cfg["codex"]
    checks = run_harness_checks(cx.get("checks", []), Path(cfg["cwd"]), Path(cx["scratch"]), secrets)
    emit({"event": "progress", "provider": "codex", "type": "harness_checks_done", "count": len(checks)})
    st = CodexStream()

    def on_line(line: str) -> None:
        ev = st.feed(line)
        if ev:
            emit(ev)

    last = Path(cx["last_message"])
    stdin = Path(cx["prompt_file"]).read_bytes()
    try:
        res = run_stream(list(cfg["argv"]), env=os.environ, cwd=cfg["cwd"], stdin=stdin, timeout=float(cfg["timeout_seconds"]), on_line=on_line)
    except OSError as exc:
        fail = failed_report("cli_unavailable", f"cannot start the CLI: {type(exc).__name__}", secrets)
        _write_json(out_dir / "report.json", fail)
        _write_json(out_dir / "audit_report.json", {"schema": 1, "provider": "codex", "failure": fail, "codex_report": None, "harness_checks": checks})
        return
    last_text = last.read_text() if last.is_file() and last.stat().st_size < 256 * 1024 else None
    doc, failure = finalize_codex(st, exit_code=res.exit_code, stderr=res.stderr, timed_out=res.timed_out, last_message=last_text, secrets=secrets)
    envelope = {"schema": 1, "provider": "codex", "failure": failure, "codex_report": doc, "harness_checks": checks,
                "cli": {"exit_code": res.exit_code, "timed_out": res.timed_out, "events": st.lines, "items": st.items, "usage": st.usage,
                        "stderr_tail": truncate(redact(res.stderr, secrets)[-800:], 800)}}
    _write_json(out_dir / "audit_report.json", envelope)
    if failure is not None:
        _write_json(out_dir / "report.json", failure)
    else:
        _write_json(out_dir / "report.json", {"status": "ready_for_review", "summary": truncate(str((doc or {}).get("summary", "audit report produced")) or "audit report produced")})
    emit({"event": "progress", "provider": "codex", "type": "finished", "ok": failure is None})


def main(argv: list[str]) -> int:
    cfg = json.loads(Path(argv[1]).read_text())
    {"cursor": run_cursor, "codex": run_codex}[cfg["provider"]](cfg)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
