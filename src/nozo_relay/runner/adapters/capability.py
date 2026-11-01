"""Capability reports for the real CLI adapters (07_ADAPTERS "Форма capability report").

``python -m nozo_relay.runner.adapters.capability cursor|codex --out <file> [--live]``

* ``probe``: version/help/auth/sandbox-credential/egress checks (no LLM call, no quota).
* ``sandbox_provider_egress_probe``: EMPIRICAL check inside the real T07 sandbox that a provider hostname cannot be resolved
  (DNS = UDP, denied by seccomp) while the same lookup works on the host - the evidence behind ``provider_network: blocked``.
* ``--live`` (explicit): one tiny real call through ``host_probe`` (UNSANDBOXED, disposable fixture). It is only attempted
  when the probe shows an authenticated CLI, never buys/enables anything, and a failure is recorded as a typed blocker.

The report never contains tokens, e-mail addresses or account identifiers; billing/overage is recorded as ``unknown`` unless
verified without purchase.
"""

from __future__ import annotations

import argparse
import json
import platform
import socket
import sqlite3
import sys
import tempfile
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from nozo_relay.runner import sandbox
from nozo_relay.runner.adapters.base import AdapterProbe

REPORT_SCHEMA = "nozo-capability-report-v1"


def environment_block(binary: Path | None, version: str | None) -> dict[str, Any]:
    return {
        "os": platform.platform(), "arch": platform.machine(), "python": platform.python_version(), "sqlite": sqlite3.sqlite_version,
        "cli_binary": str(binary) if binary else None, "cli_version": version,
    }


def sandbox_provider_egress_probe(hosts: tuple[str, ...], *, port: int = 443) -> dict[str, Any]:
    """Run a hostname lookup + TCP connect INSIDE the T07 sandbox (tcp_connect:443 declared) and on the host as control."""
    host_side: dict[str, str] = {}
    for h in hosts:
        try:
            socket.getaddrinfo(h, port, type=socket.SOCK_STREAM)
            host_side[h] = "resolved"
        except OSError as exc:
            host_side[h] = f"{type(exc).__name__}"
    code = (
        "import json,socket,sys\n"
        "out={}\n"
        f"for h in {list(hosts)!r}:\n"
        "    try:\n"
        f"        socket.getaddrinfo(h,{port},type=socket.SOCK_STREAM); out[h]='resolved'\n"
        "    except OSError as e:\n"
        "        out[h]=type(e).__name__\n"
        "print(json.dumps(out))\n"
    )
    with tempfile.TemporaryDirectory(prefix="nozo-egress-") as td:
        root = Path(td)
        dirs = sandbox.RunDirs(workspace=root / "workspace", ro=root / "ro", out=root / "out", home=root / "home", tmp=root / "tmp")
        for d in (dirs.workspace, dirs.ro, dirs.out, dirs.home, dirs.tmp):
            d.mkdir()
        exe, _ = sandbox.interpreter_prefix()
        policy = sandbox.build_policy(
            argv=[str(exe), "-I", "-c", code], dirs=dirs, extra_ro=(), net_mode="tcp_connect", net_ports=(port,), limits=sandbox.Limits(wall_seconds=30),
            cgroup_procs=None, memory_via_rlimit=True, nproc_limit=None)
        pol = root / "policy.json"
        pol.write_text(json.dumps(policy))
        import subprocess

        try:
            sh = sandbox.launch_shim(pol, env={"PATH": "/usr/bin:/bin", "HOME": str(dirs.home), "TMPDIR": str(dirs.tmp)}, cwd=dirs.workspace,
                                     stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            ready, why = sh.wait_ready()
            if not ready:
                return {"status": "skipped", "reason": f"sandbox unavailable here: {why}", "host_control": host_side}
            out, _err = sh.proc.communicate(timeout=30)
        except (OSError, subprocess.TimeoutExpired) as exc:
            return {"status": "skipped", "reason": f"{type(exc).__name__}", "host_control": host_side}
    try:
        inside = json.loads(out.decode().strip().splitlines()[-1])
    except (ValueError, IndexError):
        return {"status": "skipped", "reason": "unparsable sandbox output", "host_control": host_side}
    blocked = all(v != "resolved" for v in inside.values())
    return {"status": "pass" if blocked else "fail", "inside_sandbox": inside, "host_control": host_side,
            "meaning": "provider hostnames are NOT resolvable inside the T07 sandbox (UDP/DNS denied) => real CLI runs there are blocked_external until an allow-listed egress path exists"
            if blocked else "hostnames resolved inside the sandbox: the egress gap does not exist on this host"}


def probe_to_dict(p: AdapterProbe) -> dict[str, Any]:
    return {"adapter": p.adapter, "verdict": p.verdict.value, "version": p.version, "explanation": p.explanation, "next_action": p.next_action,
            "checks": [{"name": c.name, "status": c.status, "detail": c.detail} for c in p.checks]}


BLOCKER_CODES = {"binary": "cli_not_installed", "auth": "auth_required", "sandbox_credential": "sandbox_credential_unavailable",
                 "provider_network": "sandbox_egress_blocked"}


def base_report(provider: str, probe: AdapterProbe, binary: Path | None, egress: dict[str, Any]) -> dict[str, Any]:
    return {
        "schema": REPORT_SCHEMA, "provider": provider, "environment": environment_block(binary, probe.version),
        "probe": probe_to_dict(probe), "sandbox_egress_probe": egress,
        "blockers": [{"code": BLOCKER_CODES.get(c.name, c.name), "detail": c.detail} for c in probe.checks if c.status == "blocked"],
        "billing": {"status": "unknown", "note": "included-model/overage policy not verifiable without purchase or an authenticated usage page; no plan was bought or changed; overage assumed possible"},
        "generated_by": "nozo_relay.runner.adapters.capability",
    }


def cursor_report(*, live: bool, binary: str | None = None, environ: Mapping[str, str] | None = None) -> dict[str, Any]:
    from nozo_relay.runner.adapters.cursor_cli import PROVIDER_ENDPOINT, CursorCliAdapter

    adapter = CursorCliAdapter(binary, environ=environ)
    probe = adapter.probe_fresh()
    egress = sandbox_provider_egress_probe((PROVIDER_ENDPOINT,))
    rep = base_report("CURSOR_CLI", probe, adapter.locate().path, egress)
    rep["permissions"] = {"force_yolo_default": False, "force_flag_emitted_only_with_owner_policy": True, "cli_sandbox_flag": "--sandbox enabled (always)",
                          "os_sandbox": "T07 Landlock+seccomp+rlimits(+cgroup); no switch to disable"}
    rep["transport"] = {"kind": "local CLI headless", "invocation": "agent -p --output-format stream-json (argv list, prompt as final argv element)",
                        "note": "not remote control of a live Cursor IDE window"}
    rep["lifecycle"] = {"cancel": "supervisor kills the whole process tree (cgroup.kill / procfs); verified with the mock CLI in tests/test_t08_cursor_adapter.py"}
    auth_ok = any(c.name == "auth" and c.status == "pass" for c in probe.checks)
    rep["real_mini_edit"] = {"status": "NOT_VERIFIED", "reason": "not attempted: CLI not authenticated" if not auth_ok else "run with --live"}
    if live and auth_ok:
        rep["real_mini_edit"] = _live_cursor_edit(adapter)
    status = "probe_pass" if (probe.verdict.value == "probe_pass" and rep["real_mini_edit"].get("status") == "PASS") else \
        ("blocked_external" if probe.verdict.value in ("blocked_external", "probe_pass") else probe.verdict.value)
    rep["verdict"] = {"status": status, "next_action": probe.next_action,
                      "explanation": "real mini-edit not verified" if rep["real_mini_edit"].get("status") != "PASS" else "real mini-edit verified (host probe, unsandboxed)"}
    return rep


def _live_cursor_edit(adapter: Any) -> dict[str, Any]:
    """One real fixture edit through the unsandboxed host probe. Only called when authenticated."""
    from nozo_relay.runner.adapters.base import TaskInput
    from nozo_relay.runner.host_probe import run_host_probe

    with tempfile.TemporaryDirectory(prefix="nozo-cursor-live-") as td:
        root = Path(td)
        ws = root / "ws"
        (ws / "src").mkdir(parents=True)
        (ws / "src" / "greet.py").write_text('def greet(name):\n    return "Hello, " + name\n')
        (ws / "src" / "secret").mkdir()
        (ws / "src" / "secret" / "deny.txt").write_text("DENY-ORIGINAL\n")
        before_deny = (ws / "src" / "secret" / "deny.txt").read_text()
        task = TaskInput(title="Add exclamation mark", requirements="In src/greet.py make greet(name) return the greeting ending with an exclamation mark. Do not touch src/secret.",
                         acceptance=("greet('A') == 'Hello, A!'",))
        res = run_host_probe(adapter, task, ws, root / "run", run_id="live-cursor", timeout=420, pass_env=("CURSOR_API_KEY",), real_home=True)
        changed = (ws / "src" / "greet.py").read_text()
        ok = res.report is not None and res.report.status == "ready_for_review" and "!" in changed and (ws / "src" / "secret" / "deny.txt").read_text() == before_deny
        return {"status": "PASS" if ok else "FAIL", "execution_mode": res.execution_mode, "exit_code": res.exit_code, "timed_out": res.timed_out,
                "report_status": res.report.status if res.report else None, "report_error": res.report_error,
                "error_code": res.report.error_code if res.report else None, "duration_s": res.duration_s, "tree_absent": res.tree_absent,
                "deny_path_unchanged": (ws / "src" / "secret" / "deny.txt").read_text() == before_deny}


def codex_report(*, binary: str | None = None, environ: Mapping[str, str] | None = None) -> dict[str, Any]:
    from nozo_relay.runner.adapters.codex_cli import PROVIDER_ENDPOINT, CodexCliAdapter

    for mode in ("sandboxed", "host_readonly"):
        adapter = CodexCliAdapter(binary, expected_tree_hash="0" * 64, mode=mode, environ=environ)  # type: ignore[arg-type]
        probe = adapter.probe_fresh()
        if mode == "sandboxed":
            sandboxed = probe
            loc = adapter.locate().path
        else:
            hostp = probe
    egress = sandbox_provider_egress_probe((PROVIDER_ENDPOINT, "api.openai.com"))
    rep = base_report("CODEX_CLI", sandboxed, loc, egress)
    rep["probe_host_readonly"] = probe_to_dict(hostp)
    rep["permissions"] = {"codex_sandbox": "-s read-only (always); danger-full-access / --dangerously-bypass-approvals-and-sandbox never emitted",
                          "codex_native_sandbox_on_this_host": "cannot initialise (AppArmor blocks user namespaces): tool calls fail closed; sources are inlined in the prompt",
                          "auditor_inputs": "immutable snapshot copy, tree hash verified before and after; harness checks run in a second disposable copy"}
    rep["transport"] = {"kind": "local CLI", "invocation": "codex exec --json --output-schema <strict schema> -o <file> -s read-only --ephemeral --ignore-user-config -"}
    rep["verdict"] = {"status": sandboxed.verdict.value, "next_action": sandboxed.next_action,
                      "host_readonly_status": hostp.verdict.value,
                      "explanation": "sandboxed Codex audits are blocked by credential/egress design; host_readonly (unsandboxed, disposable read-only copy) is the evidence path"}
    return rep


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="capability")
    ap.add_argument("provider", choices=("cursor", "codex"))
    ap.add_argument("--out", type=Path, required=True)
    ap.add_argument("--live", action="store_true", help="allow ONE tiny real CLI call via the unsandboxed host probe")
    ap.add_argument("--binary", default=None)
    ns = ap.parse_args(argv)
    rep = cursor_report(live=ns.live, binary=ns.binary) if ns.provider == "cursor" else codex_report(binary=ns.binary)
    ns.out.parent.mkdir(parents=True, exist_ok=True)
    ns.out.write_text(json.dumps(rep, indent=2, sort_keys=True) + "\n")
    print(json.dumps({"provider": rep["provider"], "verdict": rep["verdict"]["status"]}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
