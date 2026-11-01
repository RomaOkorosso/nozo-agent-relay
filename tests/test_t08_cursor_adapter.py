"""T08: Cursor CLI adapter. Mock CLI through the REAL supervisor sandbox + probe against the REAL installed binary.

QA mapping: Q27 (edit / deny / result / cancel with descendants), Q29 (auth/quota/permission -> exact blocker, no paid fallback,
no bypass), Q36 (hostile model JSON is never executed), inherited T07 isolation (the mock runs inside Landlock+seccomp).

What is NOT claimed: a real Cursor model edit. The installed CLI is not logged in on this host, so
``test_real_cli_mini_edit`` is skipped (NOT_VERIFIED) unless NOZO_RUN_REAL_CLI=1 AND the CLI is authenticated. Mock results
are labelled mock everywhere and can never be reported as REAL_CLI evidence.
"""

from __future__ import annotations

import ast
import dataclasses
import inspect
import json
import os
import re
import time
from pathlib import Path
from typing import Any

import pytest

from nozo_relay.domain.enums import CapabilityStatus
from nozo_relay.runner import snapshots
from nozo_relay.runner.adapters import cli_common, cli_wrapper, cursor_cli
from nozo_relay.runner.adapters.base import (
    Adapter,
    LaunchSpec,
    NetworkNeeds,
    PrepareContext,
    ReportInvalid,
    TaskInput,
)
from nozo_relay.runner.adapters.cli_wrapper import CursorStream, classify_failure, extract_report_block, finalize_cursor
from nozo_relay.runner.adapters.cursor_cli import API_KEY_ENV, CursorCliAdapter, CursorPolicy
from nozo_relay.runner.credentials import CredentialsManager
from nozo_relay.runner.supervisor import HeartbeatOutcome, RunRequest, Supervisor, SupervisorConfig
from nozo_relay.runner.sandbox import Limits
from mock_cli import invocations, make_mock_agent
from test_t07_runner_isolation import (  # noqa: F401  (fixtures + helpers of the T07 harness)
    BINDING,
    OK_HB,
    PROJECT,
    SCOPE,
    CachedBackend,
    World,
    assert_absent_everywhere,
    make_req,
    pid_alive,
    sandbox_ok,
    sandbox_report,
    world,
)

KEY = "SENTINEL_CURSOR_API_KEY_9d41c07be2"
REAL_BIN = cursor_cli.CursorCliAdapter().locate().path
TASK = TaskInput(title="Fixture task", requirements="do the fixture thing", acceptance=("it works",))


# ------------------------------------------------------------------------------------------------------ helpers
def mock_env(tmp: Path) -> dict[str, str]:
    return {"PATH": "/usr/bin:/bin", "HOME": str(tmp), "CURSOR_API_KEY": KEY}


def mock_adapter(tmp: Path, scenario: str = "edit", params: dict | None = None, *, creds: CredentialsManager | None = None, **kw: Any) -> CursorCliAdapter:
    binary = make_mock_agent(tmp / f"bin-{scenario}", scenario, params)
    return CursorCliAdapter(binary, credentials=creds, assume_provider_network=True, network=NetworkNeeds(), environ=mock_env(tmp), **kw)


def sup_for(w: World, adapter: CursorCliAdapter, creds: CredentialsManager, **cfg: Any) -> Supervisor:
    config = SupervisorConfig(
        state_dir=w.state, heartbeat_interval=0.1, watchdog_window=30.0, stop_grace=1.0, kill_wait=5.0, use_cgroup=cfg.pop("use_cgroup", None),
        limits=Limits(wall_seconds=60, cpu_seconds=60, memory_bytes=1024**3, pids_max=64), **cfg)
    return Supervisor(config, {"cursor": adapter}, w.registry, credentials=creds, sandbox=CachedBackend(), clock=w.clock)


def cursor_req() -> RunRequest:
    return dataclasses.replace(make_req(), adapter="cursor")


def creds_with_key() -> CredentialsManager:
    creds = CredentialsManager()
    creds.register_provider_credential("cursor", API_KEY_ENV, KEY)
    return creds


def run_mock(w: World, scenario: str, params: dict | None = None, **kw: Any) -> tuple[Supervisor, Any, str, CursorCliAdapter]:
    creds = creds_with_key()
    adapter = mock_adapter(w.tmp, scenario, params, creds=creds)
    sup = sup_for(w, adapter, creds, **kw)
    req = cursor_req()
    out = sup.execute(req, heartbeat=OK_HB)
    return sup, out, req.run_id, adapter


def fail_code(sup: Supervisor, rid: str) -> str:
    return sup.outbox.get(rid, "fail")["body"]["error_code"]


def sample_stream(result_text: str, *, is_error: bool = False) -> list[str]:
    return [
        json.dumps({"type": "system", "subtype": "init", "apiKeySource": "login", "model": "m", "permissionMode": "default", "session_id": "s"}),
        json.dumps({"type": "user", "message": {"role": "user", "content": [{"type": "text", "text": "hi"}]}}),
        json.dumps({"type": "assistant", "message": {"role": "assistant", "content": [{"type": "text", "text": "ok"}]}}),
        json.dumps({"type": "tool_call", "subtype": "started", "call_id": "1", "tool_call": {"readToolCall": {"args": {"path": "a"}}}}),
        json.dumps({"type": "tool_call", "subtype": "completed", "call_id": "1", "tool_call": {"readToolCall": {"result": {}}}}),
        json.dumps({"type": "result", "subtype": "error" if is_error else "success", "is_error": is_error, "result": result_text, "duration_ms": 3}),
    ]


def feed(lines: list[str]) -> CursorStream:
    st = CursorStream()
    for line in lines:
        st.feed(line)
    return st


def block(doc: dict) -> str:
    return f"done\n{cli_wrapper.REPORT_BEGIN}\n{json.dumps(doc)}\n{cli_wrapper.REPORT_END}"


GOOD = {"status": "ready_for_review", "summary": "changed greet"}


# ============================================================================================ unit: stream parsing / typed failures
def test_adapter_implements_the_protocol_and_is_not_a_shell() -> None:
    a = CursorCliAdapter(REAL_BIN)
    assert isinstance(a, Adapter) and a.name == "cursor"
    with pytest.raises(TypeError):
        LaunchSpec(argv="agent -p 'x'")  # type: ignore[arg-type]  # a command string is structurally impossible


def test_stream_json_success_extracts_the_final_report_and_sanitises_progress() -> None:
    st = feed(sample_stream(block(GOOD)))
    assert st.malformed == 0 and st.init == {"model": "m", "permissionMode": "default", "apiKeySource": "login"} and st.tool_calls == {"readToolCall": 1}
    rep = finalize_cursor(st, exit_code=0, stderr="", timed_out=False)
    assert rep == GOOD
    a = CursorCliAdapter(REAL_BIN)
    assert a.observe(json.dumps({"event": "progress", "provider": "cursor", "type": "tool_call", "tool": "readToolCall"})).kind == "progress"
    for hostile in ("not json", json.dumps({"type": "assistant"}), json.dumps({"event": "stop_all", "x": 1}), json.dumps([1]), "{"):
        assert a.observe(hostile).kind == "unparsed"  # raw CLI output / control-looking JSON cannot steer the supervisor


@pytest.mark.parametrize(
    "lines,code",
    [
        (["this is not json"] + sample_stream(block(GOOD)), "malformed_output"),  # a stray non-JSON line blocks acceptance
        (sample_stream(block(GOOD))[:-1], "malformed_output"),  # stream ended without a terminal result
        (sample_stream("finished, no block"), "malformed_output"),
        (sample_stream("<<<NOZO_REPORT_JSON\n{nope}\nNOZO_REPORT_JSON>>>"), "malformed_output"),
        (sample_stream(block({"status": "ready_for_review", "summary": "x", "role": "owner", "shell": "rm -rf /"})), "report_schema_violation"),
        (sample_stream(block({"status": "ready_for_review"})), "malformed_output"),
    ],
)
def test_malformed_or_hostile_output_never_becomes_an_accepted_report(lines: list[str], code: str) -> None:
    rep = finalize_cursor(feed(lines), exit_code=0, stderr="", timed_out=False)
    assert rep["status"] == "failed" and rep["error_code"] == code


@pytest.mark.parametrize(
    "stderr,result,exit_code,code",
    [
        ("Error: Not logged in. Run `agent login`", None, 1, "auth_required"),
        ("401 Unauthorized: invalid API key", None, 1, "auth_required"),
        ("HTTP 429 Too Many Requests", None, 1, "rate_limited"),
        ("", "You've hit your usage limit. Upgrade your plan", 1, "quota_exceeded"),
        ("", "Out of credits: payment required (402)", 1, "quota_exceeded"),
        ("", "Command not allowed: requires approval", 1, "permission_required"),
        ("EACCES: permission denied, open 'x'", None, 1, "permission_required"),
        ("getaddrinfo EAI_AGAIN api2.cursor.sh", None, 1, "network_unreachable"),
    ],
)
def test_typed_blocking_failures_give_the_exact_owner_action_and_no_fallback(stderr: str, result: str | None, exit_code: int, code: str) -> None:
    lines = sample_stream(result, is_error=True) if result is not None else sample_stream("x")[:2]
    rep = finalize_cursor(feed(lines), exit_code=exit_code, stderr=stderr, timed_out=False)
    assert rep["status"] == "blocked" and rep["error_code"] == code, rep
    assert "next: " + cli_wrapper.NEXT_ACTION[code][:60] in rep["summary"]  # the exact owner action is part of the blocker
    assert set(rep) == {"status", "error_code", "summary"}  # nothing that could select a fallback/model/plan travels in the report


def test_unclassified_failures_and_timeouts_are_failed_not_blocked_and_never_success() -> None:
    assert finalize_cursor(feed(sample_stream("boom", is_error=True)), exit_code=1, stderr="", timed_out=False)["error_code"] == "agent_error"
    assert finalize_cursor(feed([]), exit_code=3, stderr="weird", timed_out=False)["error_code"] == "cli_nonzero_exit"
    assert finalize_cursor(feed(sample_stream(block(GOOD))), exit_code=0, stderr="", timed_out=True)["error_code"] == "timeout"
    assert classify_failure("everything is fine") is None
    # assistant chatter is NOT scanned for failure patterns (only error channels are)
    ok = feed(sample_stream(block(GOOD)) + [])
    ok.assistant_text.append("the user said 401 unauthorized and rate limit")
    assert finalize_cursor(ok, exit_code=0, stderr="", timed_out=False) == GOOD


def test_extract_report_block_takes_the_last_block_only() -> None:
    text = f"{block({'status': 'failed', 'summary': 'old'})}\nmore\n{block(GOOD)}"
    doc, problem = extract_report_block(text)
    assert doc == GOOD and problem == ""


# ============================================================================================ unit: argv / policy (Q29, 05_SECURITY)
def build(a: CursorCliAdapter, tmp: Path) -> tuple[str, ...]:
    return a.build_cli_argv(Path("/opt/agent"), tmp / "ws", "PROMPT")


def test_default_argv_has_no_bypass_flag_and_enables_the_cli_sandbox(tmp_path: Path) -> None:
    argv = build(CursorCliAdapter(REAL_BIN), tmp_path)
    assert argv[:2] == ("/opt/agent", "-p") and argv[-1] == "PROMPT"
    assert ("--output-format", "stream-json") == argv[2:4] and ("--sandbox", "enabled") == argv[4:6]
    assert not {"--force", "--yolo", "-f", "--api-key"} & set(argv)
    assert not any("KEY" in a or "sk-" in a for a in argv)


def test_force_only_exists_behind_an_explicit_owner_policy_flag_and_yolo_never(tmp_path: Path) -> None:
    argv = build(CursorCliAdapter(REAL_BIN, policy=CursorPolicy(allow_force=True)), tmp_path)
    assert "--force" in argv and "--yolo" not in argv and ("--sandbox", "enabled") == argv[4:6]  # OS sandbox + cli sandbox stay
    assert CursorPolicy().allow_force is False
    src = inspect.getsource(cursor_cli)
    # structural: --yolo is only ever mentioned in strings that FORBID it; --force is appended in exactly one place
    assert src.count('argv.append("--force")') == 1 and 'append("--yolo")' not in src and '"--yolo"' not in src.replace('"--yolo" in argv', "").replace('"--yolo" in helptxt.text', "")
    assert "--yolo" in cli_common.FORBIDDEN_ARGV and "--force" in cli_common.FORBIDDEN_ARGV
    with pytest.raises(ValueError):
        cli_common.WrappedCliAdapter.assert_argv_policy(["agent", "--yolo"])


def test_no_failure_path_can_retry_with_force_or_another_model() -> None:
    wrapper_src = inspect.getsource(cli_wrapper)
    assert wrapper_src.count("run_stream(list(cfg[\"argv\"])") == 2  # one launch per provider function, nothing in a retry loop
    tree = ast.parse(wrapper_src)
    for node in ast.walk(tree):
        if isinstance(node, (ast.While, ast.For)):
            assert "run_stream" not in ast.unparse(node), "the CLI must never be (re)started inside a loop"
    scrubbed = wrapper_src.replace("--force/--yolo was NOT used", "")
    assert "--force" not in scrubbed and "--yolo" not in scrubbed  # a failure path has no flag to escalate with


def test_prepare_never_puts_secrets_in_argv_or_files_and_requests_only_the_registered_credential(tmp_path: Path) -> None:
    creds = creds_with_key()
    a = mock_adapter(tmp_path, creds=creds)
    ctx = PrepareContext("r1", TASK, tmp_path / "ws", tmp_path / "ro", tmp_path / "out", tmp_path / "home", tmp_path / "tmp", Path("/usr/bin/python3"), 0, "d" * 64)
    for d in (ctx.workspace, ctx.ro_dir, ctx.out_dir, ctx.home, ctx.tmp):
        d.mkdir()
    prepared = a.prepare(ctx)
    spec = a.launch(prepared, ctx)
    assert spec.credential_env == (API_KEY_ENV,) and spec.network == NetworkNeeds()
    assert spec.argv[:2] == ("/usr/bin/python3", "-I") and KEY not in " ".join(spec.argv)
    for f in ctx.ro_dir.iterdir():
        assert KEY.encode() not in f.read_bytes()
    cfg = json.loads((ctx.ro_dir / "wrapper_cfg.json").read_text())
    assert cfg["provider"] == "cursor" and cfg["argv"][1] == "-p" and cfg["secret_env"] == [API_KEY_ENV]
    assert spec.extra_ro == (a.locate().path.parent,)  # the CLI install dir only, read-only
    # without a registered key nothing is requested (a real run would fail typed as auth_required, never silently use another identity)
    assert mock_adapter(tmp_path / "nokey", "edit").launch(prepared, ctx).credential_env == ()


def test_real_network_profile_declares_tcp_443_only() -> None:
    assert CursorCliAdapter(REAL_BIN).network == NetworkNeeds("tcp_connect", (443,))


# ============================================================================================ probe: real binary (auth may fail)
@pytest.mark.skipif(REAL_BIN is None, reason="Cursor CLI is not installed on this host (set NOZO_CURSOR_AGENT_BIN)")
def test_probe_real_binary_reports_version_flags_and_auth_honestly() -> None:
    probe = CursorCliAdapter(REAL_BIN, environ={"PATH": "/usr/bin:/bin", "HOME": os.environ["HOME"]}).probe_fresh()
    checks = {c.name: c for c in probe.checks}
    assert checks["binary"].status == "pass" and checks["version"].status == "pass" and probe.version
    assert re.fullmatch(r"\d{4}\.\d+\.\d+(-[0-9a-f]+)?", probe.version)
    assert checks["help_flags"].status == "pass" and checks["bypass_flags"].status == "pass"
    assert checks["auth"].status in ("pass", "blocked")
    # without a registered API key and an egress path the verdict can NEVER be probe_pass (honest, not optimistic)
    assert probe.verdict in (CapabilityStatus.BLOCKED_EXTERNAL, CapabilityStatus.PROBE_FAIL)
    assert checks["sandbox_credential"].status == "blocked" and checks["provider_network"].status == "blocked"
    assert checks["real_mini_edit"].status == "skipped" and "NOT_VERIFIED" in checks["real_mini_edit"].detail
    if checks["auth"].status == "blocked":
        assert probe.next_action and "login" in probe.next_action and API_KEY_ENV in probe.next_action and "purchase" in probe.next_action
    blob = json.dumps([probe.explanation, probe.next_action, [c.detail for c in probe.checks]])
    assert "@" not in blob.replace("@openai", "")  # no e-mail / account identifier in the report


def test_probe_discovery_prefers_explicit_then_env_and_never_guesses_a_wrong_explicit_path(tmp_path: Path) -> None:
    good = make_mock_agent(tmp_path / "g")
    assert cursor_cli.CursorCliAdapter(good).locate().how == "explicit"
    env_loc = CursorCliAdapter(environ={"PATH": "/nonexistent", "HOME": str(tmp_path), cursor_cli.ENV_BIN: str(good)}).locate()
    assert env_loc.how == f"env:{cursor_cli.ENV_BIN}" and env_loc.path == good.resolve()
    wrong = CursorCliAdapter(tmp_path / "does-not-exist", environ={"PATH": "/nonexistent", "HOME": str(tmp_path)}).locate()
    assert wrong.path is None  # an explicit but wrong path does not fall through to another binary
    nothing = CursorCliAdapter(environ={"PATH": "/nonexistent", "HOME": str(tmp_path / "nohome")}).probe_fresh()
    assert nothing.verdict is CapabilityStatus.BLOCKED_EXTERNAL and ENV_HINT in (nothing.next_action or "")


ENV_HINT = cursor_cli.ENV_BIN


# ============================================================================================ probe: mock binaries (all branches)
def test_probe_mock_logged_out_is_blocked_with_the_exact_owner_action(tmp_path: Path) -> None:
    binary = make_mock_agent(tmp_path / "b", "edit", {"status": "logged_out"})
    p = CursorCliAdapter(binary, assume_provider_network=True, environ={"PATH": "/usr/bin:/bin", "HOME": str(tmp_path)}).probe_fresh()
    assert p.verdict is CapabilityStatus.BLOCKED_EXTERNAL
    auth = next(c for c in p.checks if c.name == "auth")
    assert auth.status == "blocked" and p.next_action and f"{binary.resolve()} login" in p.next_action and API_KEY_ENV in p.next_action


def test_probe_mock_everything_satisfied_is_probe_pass_but_real_edit_stays_not_verified(tmp_path: Path) -> None:
    creds = creds_with_key()
    p = mock_adapter(tmp_path, creds=creds).probe_fresh()
    assert p.verdict is CapabilityStatus.PROBE_PASS and p.next_action is None
    names = {c.name: c.status for c in p.checks}
    assert names["auth"] == "pass" and names["sandbox_credential"] == "pass" and names["real_mini_edit"] == "skipped"
    assert KEY not in json.dumps([c.detail for c in p.checks]) and KEY not in p.explanation


def test_probe_mock_missing_flags_is_probe_fail(tmp_path: Path) -> None:
    d = tmp_path / "old"
    d.mkdir()
    script = d / "agent"
    script.write_text(f"#!{os.path.realpath(__import__('sys')._base_executable)}\nimport sys\nprint('1.0.0' if sys.argv[1:]==['--version'] else 'Usage: agent [options]')\n")
    script.chmod(0o755)
    p = CursorCliAdapter(script, environ={"PATH": "/usr/bin:/bin", "HOME": str(tmp_path)}).probe_fresh()
    assert p.verdict is CapabilityStatus.PROBE_FAIL and "missing flags" in next(c.detail for c in p.checks if c.name == "help_flags")


def test_probe_is_cached_between_supervisor_calls(tmp_path: Path) -> None:
    a = mock_adapter(tmp_path, creds=creds_with_key())
    first = a.probe()
    (tmp_path / "bin-edit" / "agent").unlink()  # a second subprocess round would now fail
    assert a.probe() is first


# ============================================================================================ supervisor integration (mock CLI, REAL sandbox)
def test_mock_edit_goes_through_the_real_supervisor_and_yields_a_snapshot(world: World, sandbox_ok: Any) -> None:
    sup, out, rid, adapter = run_mock(world, "edit")
    assert out.outcome == "ready_for_review", (out.outcome, out.reason)
    body = sup.outbox.get(rid, "implementation-result")["body"]
    assert [f["path"] for f in body["scope_manifest"]["changed_files"]] == ["src/app.py"]
    assert body["summary"] == "mock edit done" and body["snapshot"]["tree_hash"] and body["snapshot"]["manifest"]["local_only"] is True
    run_dir = world.run_dir(rid)
    inv = invocations(run_dir)
    assert len(inv) == 1, "exactly one CLI launch"
    argv = inv[0]["argv"]
    assert argv[0] == "-p" and ["--sandbox", "enabled"] == argv[argv.index("--sandbox"):argv.index("--sandbox") + 2] and "--force" not in argv and "--yolo" not in argv
    assert inv[0]["cwd"].endswith("/workspace")
    allowed = {"PATH", "HOME", "TMPDIR", "LANG", "LC_ALL", "NO_COLOR", "PYTHONNOUSERSITE", "PYTHONDONTWRITEBYTECODE", "CURSOR_API_KEY", "AGENT_CLI_CREDENTIAL_STORE", "LC_CTYPE"}
    assert set(inv[0]["env_names"]) <= allowed, set(inv[0]["env_names"]) - allowed
    assert (world.repo / "src" / "app.py").read_text() == "def main():\n    return 1\n"  # canonical repo untouched
    assert_absent_everywhere(world, KEY)


def test_deny_path_write_is_quarantined_and_the_canonical_deny_file_is_unchanged(world: World, sandbox_ok: Any) -> None:
    before = (world.repo / "src" / "secret" / "keys.txt").read_text()
    sup, out, rid, _ = run_mock(world, "deny_write")
    assert out.outcome == "quarantined" and out.snapshot is None and any(v["kind"] in ("denied_path", "scope_violation", "path_denied") or "secret" in v["detail"] for v in out.violations)
    assert fail_code(sup, rid) == "scope_violation" and sup.outbox.get(rid, "implementation-result") is None
    assert (world.repo / "src" / "secret" / "keys.txt").read_text() == before
    assert snapshots.dirty_paths(world.repo) == []


def test_child_inside_the_cursor_run_cannot_read_outside_paths(world: World, sandbox_ok: Any) -> None:
    targets = {"sentinel": str(world.sentinel), "canonical": str(world.repo / "src" / "app.py"), "owner_db": str(world.owner_db), "etc_shadow": "/etc/shadow"}
    sup, out, rid, _ = run_mock(world, "read_outside", {"targets": targets})
    res = json.loads((world.run_dir(rid) / "out" / "attempts.json").read_text())
    assert set(res) == set(targets) and all(v.startswith("DENIED:") for v in res.values()), res
    assert out.outcome == "ready_for_review"


@pytest.mark.parametrize(
    "scenario,code,outcome",
    [("auth", "auth_required", "failed"), ("rate", "rate_limited", "failed"), ("quota", "quota_exceeded", "failed"),
     ("permission", "permission_required", "failed"), ("malformed", "malformed_output", "failed"), ("no_result", "malformed_output", "failed"),
     ("no_block", "malformed_output", "failed"), ("bad_json_block", "malformed_output", "failed")],
)
def test_typed_failures_block_without_a_second_launch_or_any_fallback(world: World, sandbox_ok: Any, scenario: str, code: str, outcome: str) -> None:
    sup, out, rid, adapter = run_mock(world, scenario)
    assert out.outcome == outcome and not out.technical and not out.retryable, (out.outcome, out.reason)
    fail = sup.outbox.get(rid, "fail")["body"]
    assert fail["error_code"] == code and fail["retryable"] is False
    assert sup.outbox.get(rid, "implementation-result") is None and out.snapshot is None
    inv = invocations(world.run_dir(rid))
    assert len(inv) == 1 and "--force" not in inv[0]["argv"] and "--yolo" not in inv[0]["argv"]
    # a repeated execute of the SAME request (e.g. a lost response) does not start a second CLI: run ids are single-use
    assert sup.receipts.get(rid)["state"] == "finished"
    assert_absent_everywhere(world, KEY)


def test_crash_is_a_technical_failure_not_a_success(world: World, sandbox_ok: Any) -> None:
    sup, out, rid, _ = run_mock(world, "crash")
    assert out.outcome == "failed" and out.snapshot is None and sup.outbox.get(rid, "implementation-result") is None
    assert fail_code(sup, rid) in ("malformed_output", "cli_nonzero_exit", "child_crashed", "no_report", "report_invalid")


def test_hostile_report_fields_are_a_validation_failure_and_nothing_is_executed(world: World, sandbox_ok: Any) -> None:
    sup, out, rid, _ = run_mock(world, "hostile")
    assert out.outcome == "failed" and fail_code(sup, rid) == "report_schema_violation" and sup.outbox.get(rid, "implementation-result") is None
    assert not (world.run_dir(rid) / "out" / "PWNED").exists()


def test_self_reported_empty_change_list_cannot_hide_an_edit(world: World, sandbox_ok: Any) -> None:
    sup, out, rid, _ = run_mock(world, "claims_nothing")
    assert out.outcome == "quarantined" and "inconsistent_manifest" in {v["kind"] for v in out.violations}
    assert fail_code(sup, rid) == "manifest_inconsistent"


def test_secret_echoed_by_the_cli_is_redacted_everywhere(world: World, sandbox_ok: Any) -> None:
    sup, out, rid, _ = run_mock(world, "echo_secret")
    assert out.outcome == "ready_for_review"
    assert_absent_everywhere(world, KEY)
    logs = (world.run_dir(rid) / "control" / "logs")
    assert KEY not in "".join(p.read_text() for p in logs.iterdir())
    assert KEY not in json.dumps(sup.outbox.get(rid, "implementation-result"))


def test_cancel_kills_the_whole_cursor_process_tree_and_confirms_absence(world: World, sandbox_ok: Any) -> None:
    creds = creds_with_key()
    adapter = mock_adapter(world.tmp, "hang_tree", creds=creds)
    sup = sup_for(world, adapter, creds)
    req = cursor_req()
    h = sup.start(req, heartbeat=OK_HB)
    assert h.outcome is None, h.outcome
    deadline = time.monotonic() + 30
    members: set = set()
    while time.monotonic() < deadline:
        members = h.tree.members()
        if len(members) >= 5:  # wrapper, mock agent, sleep(setsid), double-forked sleeper (+ the agent's own fork parent may be gone)
            break
        time.sleep(0.1)
    assert len(members) >= 4, f"tree never grew: {members}"
    pids = [m.pid for m in members]
    res = h.stop("control", control_id="00000000-0000-4000-8000-0000000000c1", target_epoch=1)
    assert res.confirmed and res.remaining_pids == () and [p for p in pids if pid_alive(p)] == []
    assert res.outcome and res.outcome.outcome == "stopped" and res.outcome.tree_absent
    assert sup.outbox.get(req.run_id, "stopped")["body"]["process_tree_absent"] is True
    assert sup.outbox.get(req.run_id, "implementation-result") is None
    assert len(invocations(world.run_dir(req.run_id))) == 1


def test_supervisor_blocks_the_real_binary_with_exact_actions_instead_of_launching(world: World, sandbox_ok: Any) -> None:
    if REAL_BIN is None:
        pytest.skip("Cursor CLI not installed")
    creds = CredentialsManager()
    adapter = CursorCliAdapter(REAL_BIN, credentials=creds, environ={"PATH": "/usr/bin:/bin", "HOME": os.environ["HOME"]})
    sup = sup_for(world, adapter, creds)
    req = cursor_req()
    out = sup.execute(req, heartbeat=OK_HB)
    assert out.outcome == "blocked" and "adapter_unavailable" in out.reason
    assert sup.outbox.get(req.run_id, "fail")["body"]["error_code"] == "adapter_unavailable"
    assert snapshots.dirty_paths(world.repo) == []


# ============================================================================================ real CLI (opt-in, quota-consuming)
@pytest.mark.real_cli
@pytest.mark.real_llm
def test_real_cli_mini_edit(tmp_path: Path) -> None:
    if os.environ.get("NOZO_RUN_REAL_CLI") != "1":
        pytest.skip("real Cursor run is opt-in: set NOZO_RUN_REAL_CLI=1 (consumes Cursor quota)")
    adapter = CursorCliAdapter(REAL_BIN)
    probe = adapter.probe_fresh()
    auth = next(c for c in probe.checks if c.name == "auth")
    if REAL_BIN is None or auth.status != "pass":
        pytest.skip(f"NOT_VERIFIED: Cursor CLI not authenticated ({probe.next_action})")
    from nozo_relay.runner.adapters.capability import _live_cursor_edit

    res = _live_cursor_edit(adapter)
    if res.get("error_code") in ("auth_required", "rate_limited", "quota_exceeded", "permission_required"):
        pytest.skip(f"NOT_VERIFIED: blocked by {res['error_code']}")
    assert res["status"] == "PASS", res
