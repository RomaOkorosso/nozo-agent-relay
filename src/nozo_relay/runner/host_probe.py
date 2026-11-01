"""EXPLICITLY UNSANDBOXED host probe runner (evidence/capability only - NEVER a production launch path).

Why it exists: T07's Landlock profile denies UDP/DNS/unix sockets, so a real provider CLI (Cursor, Codex) cannot reach its
endpoint from inside it, and the interactive login caches live in the user's real HOME, which the sandbox never mounts.
To still obtain REAL evidence (T08/T09) this module starts the adapter's wrapper directly on the host, on a DISPOSABLE copy
of a fixture, with an allow-listed environment, a hard timeout and verified process-tree cleanup.

What it does NOT do (and tests assert):

* it is not imported by the supervisor and is not reachable from any API/MCP/model input;
* it never applies to a canonical repository: callers pass a disposable fixture directory they created;
* it has no bypass flags: the adapter builds the CLI argv (``--force``/``--yolo``/``danger-full-access`` are never emitted);
* production runs remain inside ``supervisor.py`` + Landlock; the egress gap is reported as ``blocked_external`` there.

Every result carries ``execution_mode = "host_probe_no_landlock"`` so evidence can never be mistaken for sandboxed evidence.
"""

from __future__ import annotations

import contextlib
import os
import subprocess
import sys
import threading
import time
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from nozo_relay.runner.adapters.base import CollectedReport, PrepareContext, ReportInvalid, TaskInput
from nozo_relay.runner.adapters.cli_common import host_env
from nozo_relay.runner.processes import ProcfsTree, proc_id, terminate_tree

EXECUTION_MODE = "host_probe_no_landlock"


@dataclass
class HostRunResult:
    run_dir: Path
    execution_mode: str = EXECUTION_MODE
    exit_code: int | None = None
    timed_out: bool = False
    tree_absent: bool = True
    report: CollectedReport | None = None
    report_error: str | None = None
    events: list[dict[str, Any]] = field(default_factory=list)
    stdout_tail: str = ""
    stderr_tail: str = ""
    prepared: Any = None
    ctx: PrepareContext | None = None
    duration_s: float = 0.0


def run_host_probe(
    adapter: Any,
    task: TaskInput,
    workspace: Path,
    run_root: Path,
    *,
    run_id: str,
    timeout: float = 600.0,
    pass_env: Sequence[str] = (),
    extra_env: Mapping[str, str] | None = None,
    real_home: bool = False,
    environ: Mapping[str, str] | None = None,
) -> HostRunResult:
    """Prepare + launch + observe + collect for ONE adapter run on the host. ``workspace`` must be a disposable directory."""
    environ = os.environ if environ is None else environ
    run_root.mkdir(parents=True, exist_ok=True)
    dirs = {n: run_root / n for n in ("ro", "out", "home", "tmp")}
    for d in dirs.values():
        d.mkdir(mode=0o700, exist_ok=True)
    ctx = PrepareContext(run_id=run_id, task=task, workspace=workspace, ro_dir=dirs["ro"], out_dir=dirs["out"], home=dirs["home"], tmp=dirs["tmp"],
                         interpreter=Path(sys.executable), attempt=0, profile_digest="host-probe-unsandboxed")
    result = HostRunResult(run_dir=run_root, ctx=ctx)
    prepared = adapter.prepare(ctx)
    result.prepared = prepared
    if hasattr(adapter, "launch_host"):
        argv, extra = adapter.launch_host(prepared, ctx)
        fixed: dict[str, str] = dict(extra)
    else:
        spec = adapter.launch(prepared, ctx)
        argv, fixed = spec.argv, dict(spec.fixed_env)
    env = host_env(None, environ)
    if not real_home:
        env["HOME"] = str(dirs["home"])
    env["TMPDIR"] = str(dirs["tmp"])
    env.update(fixed)
    env.update({k: environ[k] for k in pass_env if k in environ})
    env.update(extra_env or {})
    started = time.monotonic()
    proc = subprocess.Popen(  # noqa: S603 - argv list from the adapter, never a shell
        list(argv), cwd=workspace, env=env, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True)
    root = proc_id(proc.pid)
    tree = ProcfsTree(root=root) if root else None
    out_lines: list[str] = []
    err_lines: list[str] = []

    def pump(stream: Any, sink: list[str], observe: bool) -> None:
        for raw in iter(stream.readline, b""):
            line = raw.decode("utf-8", "replace").rstrip("\r\n")
            sink.append(line)
            if observe:
                with contextlib.suppress(Exception):
                    obs = adapter.observe(line)
                    if obs.kind != "unparsed":
                        result.events.append({"kind": obs.kind, **dict(obs.data)})

    threads = [threading.Thread(target=pump, args=(proc.stdout, out_lines, True), daemon=True),
               threading.Thread(target=pump, args=(proc.stderr, err_lines, False), daemon=True)]
    [t.start() for t in threads]
    deadline = time.monotonic() + timeout
    while proc.poll() is None:
        if tree is not None:
            tree.members()  # keep the (pid,start) history for the fallback tree
        if time.monotonic() > deadline:
            result.timed_out = True
            break
        time.sleep(0.1)
    if tree is not None:
        result.tree_absent, _remaining = terminate_tree(tree, grace=2.0 if result.timed_out else 0.0, kill_wait=5.0)
    with contextlib.suppress(Exception):
        proc.wait(10)
    [t.join(5) for t in threads]
    result.exit_code = proc.returncode
    result.duration_s = round(time.monotonic() - started, 2)
    result.stdout_tail = "\n".join(out_lines[-20:])[-2000:]
    result.stderr_tail = "\n".join(err_lines[-20:])[-2000:]
    try:
        result.report = adapter.collect(prepared)
    except ReportInvalid as exc:
        result.report_error = str(exc)
    return result


__all__ = ["EXECUTION_MODE", "HostRunResult", "run_host_probe"]
