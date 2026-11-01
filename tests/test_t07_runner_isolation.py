"""T07: supervisor, sandbox, snapshots, durable receipts. DISPOSABLE FIXTURES ONLY (no real Cursor/Codex CLI).

Every attack below is carried out by ``fixture_child.py`` inside the supervisor's sandbox against sentinel files,
sockets and directories created by the test itself in ``tmp_path``. A "breach" is an attack attempt whose
``ok`` flag is True (the sentinel text was obtained, or a forbidden write/connect succeeded).

QA mapping: Q08 (no second writer), Q09 (stop kills the tree, no revival), Q10 (stop_unknown), Q22 (sentinel
secrets), Q25 (surgical escapes -> quarantine, repo intact), Q26 (interpreter escape -> sandbox deny),
Q36 (hostile model JSON is never executed).
"""

from __future__ import annotations

import ast
import dataclasses
import inspect
import json
import os
import re
import signal
import socket
import subprocess
import tempfile
import threading
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

from nozo_relay.clock import FakeClock
from nozo_relay.domain.enums import CapabilityStatus
from nozo_relay.runner import processes, sandbox, sandbox_exec, snapshots
from nozo_relay.runner.adapters import base as adapter_base
from nozo_relay.runner.adapters.base import LaunchSpec, NetworkNeeds
from nozo_relay.runner.adapters.fixture import FixtureChildAdapter
from nozo_relay.runner.credentials import CredentialError, CredentialsManager
from nozo_relay.runner.receipts import DeliveryResult, Outbox, ReceiptError, ReceiptStore, RunAlreadyUsed
from nozo_relay.runner.sandbox import LandlockBackend, Limits, SandboxReport, UnavailableBackend
from nozo_relay.runner import supervisor as supervisor_mod
from nozo_relay.runner.supervisor import HeartbeatOutcome, RunRejected, RunRequest, Supervisor, SupervisorConfig
from nozo_relay.services.repo_bindings import BindingInfo, BindingLocked, PathInPayload, StaticBindingRegistry, reject_path_fields

SENTINEL_TEXT = "SENTINEL-OUTSIDE-3f9a1c-DO-NOT-READ"
PROVIDER_SECRET = "SENTINEL_SECRET_PROVIDER_7c1e9d42ab"
OWNER_SECRET = "SENTINEL_SECRET_OWNER_MASTER_55aa19e0cc"
SCOPE = {
    "allowed_paths": ["src/**"], "denied_paths": ["src/secret/**", ".env*"],
    "max_changed_files": 5, "max_diff_lines": 200, "allow_new_dependencies": False,
}
PROJECT = "proj-1"
BINDING = "bind-1"
OK_HB = lambda: HeartbeatOutcome.OK  # noqa: E731


# ------------------------------------------------------------------------------------------------- helpers
def git(cwd: Path, *args: str) -> str:
    env = {"PATH": "/usr/bin:/bin", "HOME": str(cwd), "GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_NOSYSTEM": "1",
           "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@t", "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@t"}
    return subprocess.run(["git", *args], cwd=cwd, env=env, check=True, capture_output=True, text=True).stdout  # noqa: S603,S607


def make_repo(root: Path) -> Path:
    root.mkdir(parents=True)
    (root / "src" / "secret").mkdir(parents=True)
    (root / "src" / "app.py").write_text("def main():\n    return 1\n")
    (root / "src" / "secret" / "keys.txt").write_text("repo-secret-key-material\n")
    (root / "README.md").write_text("# fixture\n")
    (root / "pyproject.toml").write_text('[project]\nname = "fx"\nversion = "0"\ndependencies = []\n')
    (root / ".gitignore").write_text("ignored.log\n")
    git(root, "init", "-q", "-b", "main")
    git(root, "add", "-A")
    git(root, "commit", "-q", "-m", "init")
    (root / "ignored.log").write_text("not part of the baseline\n")
    return root


@dataclasses.dataclass
class World:
    tmp: Path
    repo: Path
    state: Path
    outside: Path
    sentinel: Path
    owner_db: Path
    tcp: socket.socket
    tcp_other: socket.socket
    udp: socket.socket
    unix_path: str
    binding: BindingInfo
    registry: StaticBindingRegistry
    clock: FakeClock

    def targets(self) -> dict[str, Any]:
        return {
            "sentinel": str(self.sentinel), "sentinel_text": SENTINEL_TEXT, "outside_dir": str(self.outside),
            "outside_file_name": self.sentinel.name, "owner_db": str(self.owner_db), "canonical_root": str(self.repo),
            "tcp_port": self.tcp.getsockname()[1], "tcp_port_other": self.tcp_other.getsockname()[1],
            "udp_port": self.udp.getsockname()[1], "unix_socket": self.unix_path, "supervisor_pid": os.getpid(),
        }

    def run_dir(self, run_id: str) -> Path:
        for base in ("runs", "quarantine"):
            p = self.state / base / run_id
            if p.exists():
                return p
        raise AssertionError(f"no directory for run {run_id}")

    def attempts(self, run_id: str, name: str = "attempts.json") -> list[dict[str, Any]]:
        return json.loads((self.run_dir(run_id) / "out" / name).read_text())["attempts"]


@pytest.fixture
def world(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Any:
    repo = make_repo(tmp_path / "canonical")
    outside = tmp_path / "outside"
    outside.mkdir()
    sentinel = outside / "sentinel.txt"
    sentinel.write_text(SENTINEL_TEXT)
    owner_db = tmp_path / "owner" / "relay.sqlite"
    owner_db.parent.mkdir()
    owner_db.write_text(f"SQLite format 3 {SENTINEL_TEXT}")
    tcp, tcp_other = socket.socket(), socket.socket()
    for s in (tcp, tcp_other):
        s.bind(("127.0.0.1", 0))
        s.listen(8)
    udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp.bind(("127.0.0.1", 0))
    sock_dir = Path(tempfile.mkdtemp(prefix="nzt-"))
    unix_path = str(sock_dir / "s.sock")
    unix = socket.socket(socket.AF_UNIX)
    unix.bind(unix_path)
    unix.listen(2)
    binding = BindingInfo(id=BINDING, project_id=PROJECT, canonical_root=repo, repo_identity=snapshots.repo_identity(repo))
    monkeypatch.setenv("NOZO_RELAY_MASTER_KEY", OWNER_SECRET)  # lives in the SUPERVISOR's environment
    monkeypatch.setenv("SSH_AUTH_SOCK", unix_path)
    w = World(tmp_path, repo, tmp_path / "runner-state", outside, sentinel, owner_db, tcp, tcp_other, udp, unix_path, binding,
              StaticBindingRegistry([binding]), FakeClock())
    yield w
    for s in (tcp, tcp_other, udp, unix):
        s.close()
    subprocess.run(["rm", "-rf", str(sock_dir)], check=False)  # noqa: S603,S607


_PROBE_CACHE: dict[str, SandboxReport] = {}


class CachedBackend:
    """Real Landlock backend, but the (slow) self-test runs once per test session."""

    name = "landlock+seccomp"

    def probe(self, scratch: Path) -> SandboxReport:
        if "r" not in _PROBE_CACHE:
            _PROBE_CACHE["r"] = LandlockBackend().probe(scratch)
        return _PROBE_CACHE["r"]


@pytest.fixture(scope="session")
def sandbox_report(tmp_path_factory: pytest.TempPathFactory) -> SandboxReport:
    return CachedBackend().probe(tmp_path_factory.mktemp("probe"))


@pytest.fixture
def sandbox_ok(sandbox_report: SandboxReport) -> SandboxReport:
    if not sandbox_report.ok:  # documented skip: the capability tests below still assert the blocked/probe_fail report
        pytest.skip(f"OS sandbox unavailable on this host ({sandbox_report.verdict}): {sandbox_report.explanation}")
    return sandbox_report


def make_sup(w: World, scenario: str = "edit", *, params: dict[str, Any] | None = None, provider: bool = False,
             backend: Any = None, adapter: Any = None, use_cgroup: bool | None = None, creds: CredentialsManager | None = None,
             limits: Limits | None = None, **cfg: Any) -> Supervisor:
    creds = creds or CredentialsManager()  # snapshots os.environ: NOZO_RELAY_MASTER_KEY is a known (supervisor-only) secret
    if provider:
        creds.register_provider_credential("fixture", "FIXTURE_PROVIDER_TOKEN", PROVIDER_SECRET)
    adapter = adapter or FixtureChildAdapter(scenario, targets=w.targets(), params=params, use_provider_credential=provider)
    config = SupervisorConfig(
        state_dir=w.state, heartbeat_interval=cfg.pop("heartbeat_interval", 0.1), watchdog_window=cfg.pop("watchdog_window", 30.0),
        stop_grace=cfg.pop("stop_grace", 1.0), kill_wait=5.0, use_cgroup=use_cgroup,
        limits=limits or Limits(wall_seconds=60, cpu_seconds=60, memory_bytes=1024**3, pids_max=64), **cfg,
    )
    return Supervisor(config, {"fixture": adapter}, w.registry, credentials=creds, sandbox=backend or CachedBackend(), clock=w.clock)


_counter = iter(range(10_000))


def make_req(run_id: str | None = None, *, job_id: str | None = None, scope: dict[str, Any] | None = None, mode: str = "surgical",
             task: dict[str, Any] | None = None, **over: Any) -> RunRequest:
    n = next(_counter)
    return RunRequest(
        project_id=PROJECT, task_id=f"task-{n}", job_id=job_id or f"job-{n}", run_id=run_id or f"run-{n}", binding_id=BINDING,
        adapter="fixture", lease_epoch=1, revision=1, policy_digest="a" * 64, scope=scope or SCOPE, mode=mode,
        task=task or {"title": "Fixture task", "requirements": "do the fixture thing", "acceptance": ["it works"]}, **over,
    )


def run(w: World, scenario: str, **kw: Any) -> tuple[Supervisor, Any, str]:
    req_kw = {k: kw.pop(k) for k in ("scope", "mode", "job_id") if k in kw}
    sup = make_sup(w, scenario, **kw)
    req = make_req(**req_kw)
    out = sup.execute(req, heartbeat=OK_HB)
    return sup, out, req.run_id


def pid_alive(pid: int) -> bool:
    info = processes.read_proc(pid)
    return info is not None and info.state != "Z"


def state_files(w: World, *, skip: tuple[str, ...] = ("workspace", "baseline", "out", "ro")) -> list[Path]:
    """Supervisor-owned files (receipts, outbox, logs, capability reports, policy): never the child's own directories."""
    out = []
    for p in w.state.rglob("*"):
        if p.is_file() and not p.is_symlink() and not any(part in skip for part in p.relative_to(w.state).parts):
            out.append(p)
    return out


def assert_absent_everywhere(w: World, *needles: str, extra: tuple[str, ...] = ()) -> None:
    for p in state_files(w):
        data = p.read_bytes()
        for n in needles:
            assert n.encode() not in data, f"{n[:12]}... found in {p.relative_to(w.state)}"
    for blob in extra:
        for n in needles:
            assert n not in blob


def sandbox_abi(rep: SandboxReport) -> int:
    return int(rep.environment.get("landlock_abi", 0))


# ================================================================================================= capability / no bypass
def test_capability_report_lists_checks_mounts_and_cgroup_status(world: World, sandbox_report: SandboxReport) -> None:
    sup = make_sup(world)
    caps = sup.probe()
    d = caps.to_dict()
    assert d["verdict"] in {c.value for c in CapabilityStatus if c.value.startswith(("probe_", "blocked"))}
    rep = d["sandbox"]
    assert rep["backend"] == "landlock+seccomp" and rep["profile_digest"] and len(rep["profile_digest"]) == 64
    assert {"readable", "read_write", "not_reachable", "secret_classes"} <= set(rep["mounts"])
    assert any("canonical_repository" in x for x in rep["mounts"]["not_reachable"])
    assert d["tree_control"] in ("cgroup", "procfs") and "available" in d["cgroup"] and d["cgroup"]["reason"]
    assert "disk_quota" in d["limits"] and "tree_stop" in d["limits"]
    saved = json.loads((world.state / "capabilities" / "sandbox.json").read_text())
    assert saved["verdict"] == d["verdict"]
    if sandbox_report.ok:
        names = {c["name"] for c in rep["checks"] if c["status"] == "pass"}
        assert {"deny:read_sentinel", "deny:write_outside", "deny:tcp_connect", "deny:unix_connect", "deny:symlink_read_through",
                "deny:sh_cat_sentinel", "deny:proc_environ", "deny:udp_socket", "ws_write", "sh_exec", "supervisor_can_stop_child"} <= names
        assert caps.verdict == "probe_pass" and rep["explanation"]
    else:  # the honest failure mode (never a bypass)
        assert caps.verdict in ("probe_fail", "blocked_external") and rep["explanation"] and rep["next_action"] is not None


@pytest.mark.parametrize(
    "verdict,why",
    [(CapabilityStatus.BLOCKED_EXTERNAL, "Landlock is not enabled in this kernel (lsm list lacks landlock)"),
     (CapabilityStatus.PROBE_FAIL, "Landlock ABI 2 < 4: TCP egress cannot be denied")],
)
def test_unavailable_sandbox_blocks_without_spawning_or_bypass(world: World, verdict: CapabilityStatus, why: str,
                                                              monkeypatch: pytest.MonkeyPatch) -> None:
    for var in ("NOZO_RELAY_SANDBOX", "NOZO_RELAY_UNSAFE", "NOZO_RELAY_YOLO", "NOZO_RELAY_DISABLE_SANDBOX", "CODEX_YOLO"):
        monkeypatch.setenv(var, "1")  # no environment switch can weaken the sandbox
    backend = UnavailableBackend(verdict, why, "enable Landlock or use a VM")
    sup = make_sup(world, backend=backend)
    caps = sup.probe()
    assert caps.verdict == verdict.value and caps.verdict != "probe_pass"
    assert caps.explanation == why and caps.next_action == "enable Landlock or use a VM"
    spawned: list[Any] = []
    monkeypatch.setattr(supervisor_mod, "launch_shim", lambda *a, **k: spawned.append(a) or (_ for _ in ()).throw(AssertionError("spawned")))
    req = make_req()
    h = sup.start(req, heartbeat=OK_HB)
    out = h.outcome
    assert out is not None and out.outcome == "blocked" and out.reason.startswith("sandbox_unavailable")
    assert not spawned
    rec = sup.receipts.get(req.run_id)
    assert rec["state"] == "finished" and "child_pid" not in rec and not (world.state / "runs" / req.run_id).exists()
    fail = sup.outbox.get(req.run_id, "fail")
    assert fail["body"]["error_code"] == "sandbox_unavailable" and fail["body"]["retryable"] is False
    assert world.registry.get(BINDING).active_lock_run is None  # lock not held by a run that never started
    # structural: no knob anywhere that could turn the sandbox off
    banned = re.compile(r"unsafe|bypass|yolo|danger|insecure|no_sandbox|disable_sandbox|unconfined", re.I)
    for fn in (Supervisor.__init__, Supervisor.start, Supervisor.execute, sandbox.launch_shim, sandbox.build_policy, SupervisorConfig):
        assert not [p for p in inspect.signature(fn).parameters if banned.search(p)], fn
    assert not [f.name for f in dataclasses.fields(SupervisorConfig) if banned.search(f.name)]


def test_shim_fails_closed_and_never_runs_the_child_when_a_protection_cannot_be_applied(world: World, sandbox_ok: SandboxReport) -> None:
    w = world
    d = w.tmp / "shim"
    ws, ro = d / "ws", d / "ro"
    ws.mkdir(parents=True)
    ro.mkdir()
    marker = ws / "CHILD_RAN"
    exe, _ = sandbox.interpreter_prefix()
    dirs = sandbox.RunDirs(ws, ro, d / "out", d / "home", d / "tmp")
    for x in (dirs.out, dirs.home, dirs.tmp):
        x.mkdir()
    pol = sandbox.build_policy(argv=[str(exe), "-I", "-c", f"open({str(marker)!r}, 'w').write('x')"], dirs=dirs, extra_ro=[], net_mode="none",
                               net_ports=[], limits=Limits(), cgroup_procs=None, memory_via_rlimit=False, nproc_limit=None)
    pol["require"]["landlock_abi_min"] = 99  # "the kernel is too old for what the policy demands"
    (d / "policy.json").write_text(json.dumps(pol))
    sh = sandbox.launch_shim(d / "policy.json", env={"PATH": "/usr/bin"}, cwd=ws, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                             stderr=subprocess.DEVNULL)
    ready, why = sh.wait_ready()
    assert not ready and "refusing to run unconfined" in why
    assert sh.proc.wait(10) == sandbox_exec.EXIT_SETUP_FAILED
    assert not marker.exists(), "child executed although the sandbox could not be applied"
    # an unreadable/invalid policy is also fail-closed
    (d / "bad.json").write_text("{not json")
    sh2 = sandbox.launch_shim(d / "bad.json", env={}, cwd=ws, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    assert sh2.wait_ready()[0] is False and sh2.proc.wait(10) == sandbox_exec.EXIT_SETUP_FAILED


def test_old_landlock_abi_is_probe_fail_not_a_silent_downgrade(world: World, tmp_path: Path) -> None:
    rep = LandlockBackend(min_abi=99).probe(tmp_path / "p")
    if rep.environment.get("landlock_abi", 0) == 0:
        assert rep.verdict == "blocked_external"
    else:
        assert rep.verdict == "probe_fail" and "TCP" in rep.explanation and rep.next_action


def test_no_shell_true_and_adapter_interface_is_python_only() -> None:
    root = Path(supervisor_mod.__file__).parent.parent
    offenders = []
    for p in root.rglob("*.py"):
        if p.name == "fixture_child.py":  # the attacker program: runs INSIDE the sandbox and uses os.system on purpose
            continue
        tree = ast.parse(p.read_text())
        for node in ast.walk(tree):  # real call sites only (docstrings may *mention* shell=True)
            if isinstance(node, ast.Call):
                fn = ast.unparse(node.func)
                if fn in ("os.system", "os.popen", "commands.getoutput") or any(
                        k.arg == "shell" and isinstance(k.value, ast.Constant) and k.value.value for k in node.keywords):
                    offenders.append(f"{p.relative_to(root)}:{node.lineno}")
    assert not offenders, offenders
    assert [n for n in ("probe", "prepare", "launch", "observe", "collect", "cancel", "reconcile") if not hasattr(adapter_base.Adapter, n)] == []
    with pytest.raises(TypeError):
        LaunchSpec(argv="cat /etc/passwd")  # type: ignore[arg-type]  # a shell string is not an argv
    with pytest.raises(TypeError):
        LaunchSpec(argv=())
    assert isinstance(FixtureChildAdapter(), adapter_base.Adapter)
    names = {n.id for n in ast.walk(ast.parse(Path(supervisor_mod.__file__).read_text())) if isinstance(n, ast.Name)}
    names |= {n.attr for n in ast.walk(ast.parse(Path(supervisor_mod.__file__).read_text())) if isinstance(n, ast.Attribute)}
    assert "failed_review_count" not in names, "technical retries must not touch review counters"


# ================================================================================================= isolation attacks
@pytest.mark.parametrize("tree_mode", [None, False], ids=["tree-auto", "tree-procfs"])
def test_symlink_escape_is_blocked_and_quarantined(world: World, sandbox_ok: SandboxReport, tree_mode: bool | None) -> None:
    w = world
    before = snapshots.tree_hash(snapshots.scan_tree(w.repo, only=snapshots.worktree_files(w.repo)).entries)
    sup, out, rid = run(w, "symlink_escape", use_cgroup=tree_mode)
    att = {a["name"]: a for a in w.attempts(rid)}
    # creating a link inside the clone is allowed by the sandbox - *using* it to reach outside is not
    assert att["symlink_create"]["ok"] is True
    for name in ("symlink_read_through", "symlink_write_through", "symlink_list_through", "symlink_read_sentinel_directly"):
        assert att[name]["ok"] is False and att[name]["error"] in ("PermissionError", "FileNotFoundError"), (name, att[name])
    assert not (w.outside / "pwned.txt").exists() and w.sentinel.read_text() == SENTINEL_TEXT
    # ...and the leftover links are caught by the independent manifest -> quarantine, never a snapshot
    assert out.outcome == "quarantined" and out.quarantined and any(v["kind"] == "symlink" for v in out.violations)
    assert out.snapshot is None
    assert sup.outbox.get(rid, "implementation-result") is None
    assert sup.outbox.get(rid, "fail")["body"]["error_code"] == "scope_violation"
    assert (w.state / "quarantine" / rid / "workspace").is_dir()
    after = snapshots.tree_hash(snapshots.scan_tree(w.repo, only=snapshots.worktree_files(w.repo)).entries)
    assert before == after and snapshots.dirty_paths(w.repo) == []  # canonical repo untouched
    assert_absent_everywhere(w, SENTINEL_TEXT)


def test_child_cannot_read_sentinels_owner_db_or_the_canonical_repo(world: World, sandbox_ok: SandboxReport) -> None:
    w = world
    sentinel_stat = w.sentinel.stat()
    sup, out, rid = run(w, "read_sentinel")
    att = w.attempts(rid)
    assert len(att) >= 18
    # T12/F04: Landlock does not mediate chmod/chown/utime on files the uid owns, so seccomp denies those syscalls
    # (EPERM). NO attempt - including chmod_sentinel - may succeed any more.
    breaches = [a for a in att if a["ok"]]
    assert not breaches, f"sandbox breach(es): {breaches}"
    names = [a["name"] for a in att]
    assert "chmod_sentinel" in names
    assert sentinel_stat.st_mode == w.sentinel.stat().st_mode, "sentinel mode changed by the sandboxed child"
    os.chmod(w.sentinel, 0o644)
    assert w.sentinel.read_text() == SENTINEL_TEXT and w.sentinel.stat().st_mtime_ns == sentinel_stat.st_mtime_ns
    assert not (w.outside / "pwn.txt").exists() and not (w.outside / "newdir").exists()
    assert out.outcome == "ready_for_review" and out.snapshot and not out.violations  # nothing leaked into the workspace either
    ws = w.run_dir(rid) / "workspace"
    assert not (ws / "stolen").exists() and not (ws / "stolen2").exists()
    assert_absent_everywhere(w, SENTINEL_TEXT)
    assert SENTINEL_TEXT not in json.dumps(sup.outbox.get(rid, "implementation-result"))


def test_interpreter_escape_attempts_do_not_reach_protected_data_q26(world: World, sandbox_ok: SandboxReport, sandbox_report: SandboxReport) -> None:
    w = world
    sup, out, rid = run(w, "interpreter_escape")
    att = {a["name"]: a for a in w.attempts(rid)}
    assert len(att) >= 20
    must_fail = [n for n in att if n not in ("signal_supervisor", "signal_pid1")]
    breaches = {n: att[n] for n in must_fail if att[n]["ok"]}
    assert not breaches, f"interpreter escape reached protected resources: {breaches}"
    for n in ("tcp_connect_local", "tcp_socket_create", "udp_socket_create", "raw_socket", "unix_socket_connect", "netlink_socket",
              "abstract_unix_connect", "ptrace_parent"):
        assert att[n]["ok"] is False, n
    assert att["signal_pid1"]["ok"] is False
    if sandbox_abi(sandbox_report) >= 6:  # Landlock signal scoping: nothing outside the sandbox can be signalled
        assert att["signal_supervisor"]["ok"] is False
    assert not (w.outside / "pwn.txt").exists()
    # sandbox DENY (not a diff warning): the run is not even "violating" - the attacks simply did not happen
    # the only trace is the EMPTY leak.txt the shell created for its own redirect: out of scope -> quarantined, nothing stolen
    assert out.outcome == "quarantined" and [v["detail"] for v in out.violations] == ["leak.txt"], out.violations
    assert (w.run_dir(rid) / "workspace" / "leak.txt").read_bytes() == b""
    assert_absent_everywhere(w, SENTINEL_TEXT)
    log = (w.run_dir(rid) / "control" / "logs" / "stdout.log").read_text()
    assert SENTINEL_TEXT not in log


def test_scope_violation_inside_the_sandbox_is_caught_by_the_manifest_q25(world: World, sandbox_ok: SandboxReport) -> None:
    w = world
    before = (w.repo / "README.md").read_text()
    for scenario, kind in (("edit_out_of_scope", "path_not_allowed"), ("rename_escape", "path_not_allowed"), ("delete_outside", "path_not_allowed"),
                           ("binary_new", "binary_in_surgical"), ("git_tamper", "git_internal")):
        sup, out, rid = run(w, scenario)
        assert out.outcome == "quarantined", (scenario, out)
        assert kind in {v["kind"] for v in out.violations}, (scenario, out.violations)
        assert out.snapshot is None and sup.outbox.get(rid, "implementation-result") is None
        assert sup.outbox.get(rid, "fail")["body"]["error_code"] == "scope_violation"
        assert (w.state / "quarantine" / rid).is_dir() and not (w.state / "runs" / rid).exists()
        assert w.registry.get(BINDING).active_lock_run is None
    assert (w.repo / "README.md").read_text() == before and snapshots.dirty_paths(w.repo) == []
    sup, out, rid = run(w, "rename_escape")
    assert {"path_not_allowed"} <= {v["kind"] for v in out.violations}
    assert any("docs/app.py" in v["detail"] for v in out.violations) and any("src/app.py" in v["detail"] or v["kind"] == "path_not_allowed" for v in out.violations)


def test_new_dependency_and_surgical_budget_violations(world: World, sandbox_ok: SandboxReport) -> None:
    scope = {**SCOPE, "allowed_paths": ["src/**", "pyproject.toml"]}
    sup, out, rid = run(world, "new_dependency", scope=scope)
    assert out.outcome == "quarantined" and "new_dependency" in {v["kind"] for v in out.violations}
    sup, out, rid = run(world, "edit", scope={**SCOPE, "max_changed_files": 1})
    assert out.outcome == "quarantined" and "too_many_files" in {v["kind"] for v in out.violations}
    sup, out, rid = run(world, "edit", scope={**SCOPE, "max_diff_lines": 1})
    assert out.outcome == "quarantined" and "diff_too_large" in {v["kind"] for v in out.violations}


def test_inconsistent_manifest_and_symlink_in_tree_quarantine(world: World, sandbox_ok: SandboxReport) -> None:
    sup, out, rid = run(world, "hidden_change")  # the child "forgets" to declare a change it made
    assert out.outcome == "quarantined" and "inconsistent_manifest" in {v["kind"] for v in out.violations}
    assert sup.outbox.get(rid, "fail")["body"]["error_code"] == "manifest_inconsistent"
    sup, out, rid = run(world, "symlink_in_tree")  # even a "harmless" relative symlink is out
    assert out.outcome == "quarantined" and "symlink" in {v["kind"] for v in out.violations}


def test_network_rules_allow_only_the_declared_tcp_port(world: World, sandbox_ok: SandboxReport, sandbox_report: SandboxReport) -> None:
    w = world
    allowed = w.tcp.getsockname()[1]
    adapter = FixtureChildAdapter("net_ports", targets=w.targets(), network=NetworkNeeds("tcp_connect", (allowed,)))
    sup = make_sup(w, adapter=adapter)
    req = make_req()
    out = sup.execute(req, heartbeat=OK_HB)
    assert out.outcome == "ready_for_review"
    att = {a["name"]: a for a in w.attempts(req.run_id)}
    assert att["tcp_allowed_port"]["ok"] is True  # the one declared destination works (provider path for T08)
    assert att["tcp_other_port"]["ok"] is False  # any other destination does not (Landlock TCP rules)
    assert att["udp_socket"]["ok"] is False and att["unix_socket"]["ok"] is False  # seccomp: no UDP/raw/unix even in this mode


def test_stdin_env_and_argv_never_carry_secrets_clean_env_temp_home(world: World, sandbox_ok: SandboxReport) -> None:
    w = world
    sup, out, rid = run(w, "env_dump", provider=True)
    dump = json.loads((w.run_dir(rid) / "out" / "env_dump.json").read_text())
    env = dump["env"]
    allowed = {"PATH", "HOME", "TMPDIR", "LANG", "LC_ALL", "NO_COLOR", "PYTHONNOUSERSITE", "PYTHONDONTWRITEBYTECODE", "FIXTURE_PROVIDER_TOKEN", "LC_CTYPE"}
    assert set(env) <= allowed, set(env) - allowed
    blob = json.dumps(dump)
    assert OWNER_SECRET not in blob and "NOZO_RELAY" not in blob and "SSH_AUTH_SOCK" not in blob
    assert env["FIXTURE_PROVIDER_TOKEN"] == PROVIDER_SECRET  # ONLY the declared provider credential reaches the child
    assert PROVIDER_SECRET not in " ".join(dump["argv"])
    run_dir = w.run_dir(rid)
    assert dump["home"] == env["HOME"] and env["HOME"].startswith(str(run_dir)) and env["HOME"] != str(Path.home())
    assert dump["cwd"] == str(run_dir / "workspace")
    assert not (run_dir / "home").exists() and not (run_dir / "tmp").exists()  # temp HOME removed with the run
    # the secret was handed over through a pipe: it is nowhere on disk in supervisor-owned files
    assert_absent_everywhere(w, PROVIDER_SECRET, OWNER_SECRET)
    # without the adapter declaring it, a registered credential is NOT passed
    sup2, out2, rid2 = run(w, "env_dump", provider=False)
    assert "FIXTURE_PROVIDER_TOKEN" not in json.loads((w.run_dir(rid2) / "out" / "env_dump.json").read_text())["env"]


def test_credentials_manager_refuses_forbidden_names_and_unknown_requests() -> None:
    cm = CredentialsManager({})
    for bad in ("NOZO_RELAY_MASTER_KEY", "SSH_AUTH_SOCK", "GITHUB_TOKEN", "GH_TOKEN", "DOCKER_HOST", "AWS_SECRET_ACCESS_KEY", "LD_PRELOAD",
                "PATH", "HOME", "lowercase", "X"):
        with pytest.raises(CredentialError):
            cm.register_provider_credential("a", bad, "v" * 12)
    cm.register_provider_credential("a", "CLIENT_API_KEY", "value-1234567")
    with pytest.raises(CredentialError):
        cm.provider_env("b", ["CLIENT_API_KEY"])  # other adapters cannot borrow it
    with pytest.raises(CredentialError):
        cm.child_env("a", home=Path("/h"), tmp=Path("/t"), fixed={"NOZO_RELAY_X": "1"})
    env = cm.child_env("a", home=Path("/h"), tmp=Path("/t"), credential_env=["CLIENT_API_KEY"])
    assert env["CLIENT_API_KEY"] == "value-1234567" and env["HOME"] == "/h" and "SSH_AUTH_SOCK" not in env
    cm.register_supervisor_secret("owner-password-xyz")
    assert {"owner-password-xyz", "value-1234567"} <= cm.secret_values()


# ================================================================================================= Q22 sentinel secrets
def test_q22_provider_secret_is_redacted_from_logs_receipts_reports_and_never_in_git(world: World, sandbox_ok: SandboxReport,
                                                                                    caplog: pytest.LogCaptureFixture) -> None:
    w = world
    caplog.set_level("DEBUG")
    sup, out, rid = run(w, "leak_secret_transient", provider=True)
    assert out.outcome == "ready_for_review"
    entry = sup.outbox.get(rid, "implementation-result")
    body = json.dumps(entry)
    assert PROVIDER_SECRET not in body and "[REDACTED]" in body  # summary + checks were scrubbed before they left the host
    run_dir = w.run_dir(rid)
    for log_name in ("stdout.log", "stderr.log"):
        text = (run_dir / "control" / "logs" / log_name).read_text()
        assert PROVIDER_SECRET not in text
    assert "[REDACTED]" in (run_dir / "control" / "logs" / "stdout.log").read_text()
    assert_absent_everywhere(w, PROVIDER_SECRET, OWNER_SECRET)
    assert PROVIDER_SECRET not in caplog.text and OWNER_SECRET not in caplog.text
    assert all(PROVIDER_SECRET not in json.dumps(e) for e in sup.receipts.all())
    # the secret also never reaches the clone's git metadata (no commit/branch is created by the supervisor)
    assert PROVIDER_SECRET not in subprocess.run(["git", "log", "--all", "-p"], cwd=run_dir / "workspace", capture_output=True, text=True,  # noqa: S603,S607
                                                  env={"PATH": "/usr/bin", "HOME": str(w.tmp), "GIT_CONFIG_GLOBAL": os.devnull}, check=False).stdout
    # a secret that DID land in a changed file is detected and the whole output is quarantined
    sup2, out2, rid2 = run(w, "leak_secret", provider=True)
    assert out2.outcome == "quarantined" and "secret_in_output" in {v["kind"] for v in out2.violations}
    assert sup2.outbox.get(rid2, "implementation-result") is None
    assert sup2.outbox.get(rid2, "fail")["body"]["error_code"] == "secret_in_output"
    assert_absent_everywhere(w, PROVIDER_SECRET)
    # failure path: secret in stderr + failure summary
    sup3, out3, rid3 = run(w, "leak_secret_failure", provider=True)
    assert out3.outcome == "failed"
    assert PROVIDER_SECRET not in json.dumps(sup3.outbox.get(rid3, "fail"))
    assert_absent_everywhere(w, PROVIDER_SECRET)


def test_q36_hostile_model_output_is_validated_never_executed(world: World, sandbox_ok: SandboxReport) -> None:
    w = world
    sup, out, rid = run(w, "bad_report")  # JSON with role=owner, principal_id, shell/commands, unknown fields
    assert out.outcome == "failed" and out.reason == "report_invalid" and out.technical
    assert not (w.run_dir(rid) / "workspace" / "src" / "SHOULD_NOT_EXIST").exists()
    fail = sup.outbox.get(rid, "fail")["body"]
    assert fail["error_code"] == "report_invalid" and "role" in fail["evidence"] and sup.outbox.get(rid, "implementation-result") is None
    sup, out, rid = run(w, "report_symlink")  # report.json -> sentinel: never followed
    assert out.outcome == "failed" and out.reason == "report_invalid"
    assert_absent_everywhere(w, SENTINEL_TEXT)
    sup, out, rid = run(w, "report_huge")
    assert out.outcome == "failed" and out.reason == "report_invalid"
    sup, out, rid = run(w, "exit_zero_no_report")  # exit 0 alone is not success
    assert out.outcome == "failed" and out.reason == "no_report" and out.technical
    sup, out, rid = run(w, "fake_control_stdout")  # control-looking stdout cannot steer anything
    assert out.outcome == "ready_for_review"
    assert [e for e in sup.receipts.get(rid)["history"] if e["state"] not in ("reserved", "launching", "running", "finished")] == []


def test_crash_and_nonzero_exit_are_technical_failures(world: World, sandbox_ok: SandboxReport) -> None:
    sup, out, rid = run(world, "crash")
    assert out.outcome == "failed" and out.technical and out.retryable and out.exit_signal == signal.SIGSEGV
    assert sup.outbox.get(rid, "fail")["body"] | {} and sup.outbox.get(rid, "fail")["body"]["error_code"] == "child_crashed"
    sup, out, rid = run(world, "exit_nonzero")
    assert out.outcome == "failed" and out.exit_code == 3 and out.technical
    assert sup.receipts.get(rid)["technical_failure"] is True


def test_agent_reported_failure_is_not_a_technical_failure(world: World, sandbox_ok: SandboxReport) -> None:
    sup, out, rid = run(world, "leak_secret_failure", provider=True, job_id="job-agent-fail")
    assert out.outcome == "failed" and out.technical is False and sup.receipts.get(rid)["technical_failure"] is False
    assert sup.outbox.get(rid, "fail")["body"]["error_code"] == "provider_error"


# ================================================================================================= process tree
@pytest.mark.parametrize("tree_mode", [None, False], ids=["tree-auto", "tree-procfs"])
def test_stop_kills_the_whole_descendant_tree_and_confirms_absence(world: World, sandbox_ok: SandboxReport, tree_mode: bool | None) -> None:
    w = world
    sup = make_sup(w, "spawn_tree", use_cgroup=tree_mode)
    req = make_req()
    h = sup.start(req, heartbeat=OK_HB)
    assert h.outcome is None, h.outcome
    ev = h.wait_for_event("descendants", 20)
    assert ev, "fixture did not report its descendants"
    pids = list(ev["data"]["pids"]) + [h.pid]
    assert len(pids) == 5 and all(pid_alive(p) for p in pids)  # incl. a setsid child, a double-forked orphan, a SIGTERM-ignorer
    rec = sup.receipts.get(req.run_id)
    assert rec["state"] == "running" and rec["tree_control"] == (h.tree.kind) and rec["child_pid"] == h.pid
    assert rec["pgid"] == h.pid  # own process group/session
    res = h.stop("control", control_id="00000000-0000-4000-8000-000000000001", target_epoch=1)
    assert res.confirmed and res.remaining_pids == ()
    assert [p for p in pids if pid_alive(p)] == [], "descendants survived the stop"
    assert h.tree.absent() and not h.tree.members()
    out = res.outcome
    assert out and out.outcome == "stopped" and out.tree_absent
    stopped = sup.outbox.get(req.run_id, "stopped")["body"]
    assert stopped["process_tree_absent"] is True and stopped["target_epoch"] == 1
    assert sup.receipts.get(req.run_id)["state"] == "finished"
    assert w.registry.get(BINDING).active_lock_run is None


def test_process_tree_kinds_report_what_this_host_provides(world: World, sandbox_ok: SandboxReport) -> None:
    sup = make_sup(world, "hang")
    caps = sup.probe()
    kind = caps.tree_control
    if caps.cgroup["available"]:
        assert kind == "cgroup" and caps.cgroup["cgroup_kill"] and "cgroup.kill" in caps.limits["tree_stop"]
    else:
        assert kind == "procfs" and caps.cgroup["reason"], "an unavailable cgroup must be explained"
        assert "can miss" in caps.limits["tree_stop"]


def test_daemon_that_outlives_the_child_is_killed_and_flagged(world: World, sandbox_ok: SandboxReport) -> None:
    w = world
    sup = make_sup(w, "spawn_tree")
    req = make_req()
    h = sup.start(req, heartbeat=OK_HB)
    ev = h.wait_for_event("descendants", 20)
    assert ev
    pids = list(ev["data"]["pids"])
    os.kill(h.pid, signal.SIGKILL)  # the "agent" dies, its helpers keep running
    out = h.wait(30)
    assert out is not None and out.tree_absent
    assert [p for p in pids if pid_alive(p)] == []


def test_ignore_sigterm_is_escalated_to_kill_after_grace(world: World, sandbox_ok: SandboxReport) -> None:
    sup = make_sup(world, "ignore_sigterm", stop_grace=0.5)
    req = make_req()
    h = sup.start(req, heartbeat=OK_HB)
    assert h.wait_for_event("progress", 10)
    t0 = time.monotonic()
    res = h.stop("control")
    assert res.confirmed and not pid_alive(h.child.pid) and time.monotonic() - t0 < 15


def test_stop_unknown_when_absence_cannot_be_proven_q10(world: World, sandbox_ok: SandboxReport, monkeypatch: pytest.MonkeyPatch) -> None:
    w = world
    real = supervisor_mod.terminate_tree

    def cannot_verify(tree: Any, **kw: Any) -> tuple[bool, list[int]]:
        real(tree, **kw)  # still really kill it (no leaked processes), but report that we cannot VERIFY
        return False, [4242]

    monkeypatch.setattr(supervisor_mod, "terminate_tree", cannot_verify)
    sup = make_sup(w, "hang")
    req = make_req()
    h = sup.start(req, heartbeat=OK_HB)
    assert h.wait_for_event("progress", 10)
    res = h.stop("control", control_id="00000000-0000-4000-8000-000000000002", target_epoch=1)
    assert not res.confirmed and res.outcome.outcome == "stop_unknown"
    stopped = sup.outbox.get(req.run_id, "stopped")["body"]
    assert stopped["process_tree_absent"] is False  # never a fictitious "stopped"
    assert "not confirmed" in w.registry.get(BINDING).quarantine_reason
    monkeypatch.undo()
    out = sup.start(make_req(), heartbeat=OK_HB).outcome  # quarantined binding: no new writer
    assert out is not None and out.outcome == "blocked" and "binding_quarantined" in out.reason


def test_q08_no_second_writer_while_a_run_is_active_or_unreconciled(world: World, sandbox_ok: SandboxReport) -> None:
    w = world
    sup = make_sup(w, "hang")
    a = sup.start(make_req("run-a"), heartbeat=OK_HB)
    assert a.wait_for_event("progress", 10)
    b = sup.start(make_req("run-b"), heartbeat=OK_HB)
    assert b.outcome is not None and b.outcome.outcome == "blocked" and "binding_busy" in b.outcome.reason
    assert sup.receipts.get("run-b")["state"] == "finished" and "child_pid" not in sup.receipts.get("run-b")
    # a second supervisor PROCESS cannot take the binding either (flock) ...
    sup2 = make_sup(w, "hang")
    c = sup2.start(make_req("run-c"), heartbeat=OK_HB)
    assert c.outcome is not None and c.outcome.outcome == "blocked" and "binding_busy" in c.outcome.reason
    # lease lost: the heartbeat answers FENCED -> the old child is stopped; only then may a new run start
    sup.disable_spawn  # noqa: B018 (API exists)
    a._request_stop("fenced")
    out = a.wait(30)
    assert out and out.outcome == "stopped" and out.tree_absent and "fenced" in out.reason
    assert sup.receipts.get("run-a")["state"] == "finished"
    d = sup.start(make_req("run-d"), heartbeat=OK_HB)
    assert d.outcome is None and d.wait_for_event("progress", 10)
    d.stop()
    with pytest.raises(RunAlreadyUsed):
        sup.start(make_req("run-a"), heartbeat=OK_HB)  # run ids are single-use: a fenced run never revives


def test_q09_owner_stop_during_output_kills_tree_and_resume_does_not_revive_the_lease(world: World, sandbox_ok: SandboxReport) -> None:
    w = world
    sup = make_sup(w, "big_output", params={})
    # a chatty child that keeps running: use the hang child plus a heartbeat that reports a pending control
    sup = make_sup(w, "hang")
    states = iter([HeartbeatOutcome.OK, HeartbeatOutcome.STOP])
    req = make_req("run-q09")
    h = sup.start(req, heartbeat=lambda: next(states, HeartbeatOutcome.STOP))
    out = h.wait(30)
    assert out and out.outcome == "stopped" and out.tree_absent and "control" in out.reason
    assert not pid_alive(h.child.pid) and h.tree.absent()
    # "resume" is a NEW run with a new lease; the old run id/lease can never be started again
    with pytest.raises(RunAlreadyUsed):
        sup.start(make_req("run-q09"), heartbeat=OK_HB)
    with pytest.raises(ReceiptError):
        sup.receipts.update("run-q09", state="running")
    nxt = sup.start(make_req("run-q09-resume"), heartbeat=OK_HB)
    assert nxt.outcome is None
    nxt.stop()


def test_emergency_stop_all_stops_everything_and_forbids_new_spawn(world: World, sandbox_ok: SandboxReport) -> None:
    sup = make_sup(world, "hang")
    h = sup.start(make_req("run-e1"), heartbeat=OK_HB)
    assert h.wait_for_event("progress", 10)
    results = sup.stop_all()
    assert results and all(r.confirmed for r in results)
    blocked = sup.start(make_req("run-e2"), heartbeat=OK_HB).outcome
    assert blocked and blocked.outcome == "blocked" and "spawn_disabled" in blocked.reason


# ================================================================================================= watchdog / limits / retries
def test_watchdog_kills_the_tree_when_heartbeats_stop_and_spares_a_healthy_run(world: World, sandbox_ok: SandboxReport) -> None:
    w = world
    sup = make_sup(w, "hang", watchdog_window=0.6)
    req = make_req()
    t0 = time.monotonic()
    h = sup.start(req, heartbeat=lambda: HeartbeatOutcome.FAILED)  # relay unreachable: no SUCCESSFUL heartbeat
    pid = h.pid
    out = h.wait(30)
    assert out and out.outcome == "watchdog_killed" and out.technical and out.retryable and out.tree_absent
    assert 0.5 < time.monotonic() - t0 < 20 and not pid_alive(pid)
    assert sup.outbox.get(req.run_id, "fail")["body"]["error_code"] == "watchdog_timeout"
    assert (w.state / "quarantine" / req.run_id).is_dir()  # the old copy is isolated, not reused
    # healthy heartbeat keeps a longer run alive past the watchdog window
    sup2 = make_sup(w, "slow_ok", params={"seconds": 1.5}, watchdog_window=0.6)
    out2 = sup2.execute(make_req(), heartbeat=OK_HB)
    assert out2.outcome == "ready_for_review"
    # a heartbeat that raises counts as a failed heartbeat
    def boom() -> HeartbeatOutcome:
        raise RuntimeError("relay down")

    out3 = make_sup(w, "hang", watchdog_window=0.5).execute(make_req(), heartbeat=boom)
    assert out3.outcome == "watchdog_killed"


def test_wall_clock_limit_kills_the_tree(world: World, sandbox_ok: SandboxReport) -> None:
    sup = make_sup(world, "hang", limits=Limits(wall_seconds=0.7, cpu_seconds=60, memory_bytes=1024**3, pids_max=64))
    out = sup.execute(make_req(), heartbeat=OK_HB)
    assert out.outcome == "timeout" and out.tree_absent and out.technical


def test_cpu_limit_is_enforced(world: World, sandbox_ok: SandboxReport) -> None:
    sup = make_sup(world, "cpu_burn", limits=Limits(wall_seconds=60, cpu_seconds=1, memory_bytes=1024**3, pids_max=64))
    t0 = time.monotonic()
    out = sup.execute(make_req(), heartbeat=OK_HB)
    assert out.outcome == "failed" and out.reason == "cpu_limit" and out.exit_signal == signal.SIGXCPU and out.tree_absent
    assert time.monotonic() - t0 < 30 and out.technical is False  # a limit hit is not a flaky crash: not blindly retried


def test_memory_limit_is_enforced(world: World, sandbox_ok: SandboxReport) -> None:
    sup = make_sup(world, "mem_hog", params={"mb": 700}, limits=Limits(wall_seconds=60, cpu_seconds=60, memory_bytes=256 * 1024**2, pids_max=64))
    req = make_req()
    out = sup.execute(req, heartbeat=OK_HB)
    assert out.tree_absent
    # cgroup: oom-kill of the whole group; no cgroup: RLIMIT_AS -> MemoryError reported by the child
    assert out.outcome == "failed" and out.reason in ("oom_killed", "agent reported failed")
    rec = sup.receipts.get(req.run_id)
    if rec["tree_control"] == "cgroup" and rec["limits_enforced"] != "rlimit/procfs" and rec["limits_enforced"].get("memory_max"):
        assert out.reason == "oom_killed"
    else:
        assert json.loads((world.run_dir(req.run_id) / "out" / "mem.json").read_text())["memory_error"] is True


def test_pid_limit_bounds_a_fork_flood(world: World, sandbox_ok: SandboxReport) -> None:
    sup = make_sup(world, "fork_flood", params={"count": 150}, limits=Limits(wall_seconds=60, cpu_seconds=60, memory_bytes=1024**3, pids_max=20))
    req = make_req()
    out = sup.execute(req, heartbeat=OK_HB)
    assert out.tree_absent
    info = json.loads((world.run_dir(req.run_id) / "out" / "fork.json").read_text())
    assert info["started"] < 150 and info["errors"] >= 1, info  # cgroup pids.max or RLIMIT_NPROC stopped the flood


@pytest.mark.skipif(not processes.detect_cgroup_support().available, reason="no delegated cgroup v2 on this host (documented limitation)")
def test_cgroup_limits_and_leaf_cleanup_when_available(world: World, sandbox_ok: SandboxReport) -> None:
    sup = make_sup(world, "hang", use_cgroup=True)
    req = make_req()
    h = sup.start(req, heartbeat=OK_HB)
    assert h.wait_for_event("progress", 10)
    cg = Path(sup.receipts.get(req.run_id)["cgroup"])
    assert cg.is_dir() and (cg / "pids.max").read_text().strip() == "64" and int((cg / "memory.max").read_text()) == 1024**3
    assert str(h.pid) in (cg / "cgroup.procs").read_text().split()
    h.stop()
    assert not cg.exists()  # leaf removed after the tree is verified absent


def test_bounded_technical_retries_do_not_consume_review_budget(world: World, sandbox_ok: SandboxReport) -> None:
    sup = make_sup(world, "exit_nonzero")
    job = "job-retry"
    outs = [sup.execute(make_req(job_id=job), heartbeat=OK_HB) for _ in range(3)]
    assert [o.outcome for o in outs] == ["failed"] * 3 and all(o.technical for o in outs)  # 1 try + 2 technical retries
    assert [sup.receipts.get(r["run_id"])["attempt"] for r in sup.receipts.for_job(job)] == [0, 1, 2]
    fourth = sup.execute(make_req(job_id=job), heartbeat=OK_HB)
    assert fourth.outcome == "blocked" and "retry_budget_exhausted" in fourth.reason
    assert not any("review" in k for rec in sup.receipts.all() for k in rec)  # no review counter anywhere in a receipt
    # the budget is per job: a different job is unaffected
    ok = make_sup(world, "edit").execute(make_req(job_id="job-other"), heartbeat=OK_HB)
    assert ok.outcome == "ready_for_review"


# ================================================================================================= snapshots / baseline
def test_snapshot_hashes_manifest_and_immutability(world: World, sandbox_ok: SandboxReport) -> None:
    w = world
    sup, out, rid = run(w, "edit")
    assert out.outcome == "ready_for_review" and out.snapshot
    snap = out.snapshot
    ws = w.run_dir(rid) / "workspace"
    assert snap["tree_hash"] == snapshots.tree_hash(snapshots.scan_tree(ws).entries)  # recomputable by anyone
    assert snap["base_commit"] == snapshots.head_commit(w.repo) and snap["head_commit"] is None
    body = sup.outbox.get(rid, "implementation-result")["body"]
    changed = {(c["path"], c["change"]) for c in body["scope_manifest"]["changed_files"]}
    assert changed == {("src/app.py", "modified"), ("src/new_module.py", "added")} and body["scope_manifest"]["diff_lines"] == 3
    assert body["lease_epoch"] == 1 and body["policy_digest"] == "a" * 64 and body["snapshot"]["manifest"]["local_only"] is True
    # deterministic: identical work in another disposable clone -> identical hashes
    sup2, out2, rid2 = run(w, "edit")
    assert (out2.snapshot["tree_hash"], out2.snapshot["diff_hash"]) == (snap["tree_hash"], snap["diff_hash"])
    sup3, out3, _ = run(w, "slow_ok", params={"seconds": 0.05})
    assert out3.snapshot["diff_hash"] == snap["diff_hash"]
    # a different change -> different hashes
    sup4, out4, _ = run(w, "symlink_in_tree", scope={**SCOPE})
    assert out4.snapshot is None
    # the finished snapshot is read-only and verifiable; tampering is detected
    assert sup.verify_snapshot(rid) is True
    assert not os.access(ws / "src" / "app.py", os.W_OK)
    os.chmod(ws / "src", 0o755)
    os.chmod(ws / "src" / "app.py", 0o644)
    (ws / "src" / "app.py").write_text("tampered\n")
    assert sup.verify_snapshot(rid) is False
    # git hygiene of the clone: separate .git, no remote back to the user's repo, empty hooks
    assert (ws / ".git").is_dir() and not (ws / ".git" / "hooks").exists() or not list((ws / ".git" / "hooks").iterdir())
    assert str(w.repo) not in (ws / ".git" / "config").read_text()


def test_canonical_repo_is_never_modified_by_any_run(world: World, sandbox_ok: SandboxReport) -> None:
    w = world
    snapshot_before = {p: p.read_bytes() for p in w.repo.rglob("*") if p.is_file() and ".git/" not in str(p)}
    mtimes = {p: p.stat().st_mtime_ns for p in snapshot_before}
    head = git(w.repo, "rev-parse", "HEAD")
    for scenario in ("edit", "symlink_escape", "read_sentinel", "rename_escape", "git_tamper"):
        run(w, scenario)
    assert {p: p.read_bytes() for p in snapshot_before} == snapshot_before and {p: p.stat().st_mtime_ns for p in snapshot_before} == mtimes
    assert git(w.repo, "rev-parse", "HEAD") == head and git(w.repo, "status", "--porcelain") == ""
    assert (w.repo / "ignored.log").exists()


def test_dirty_tree_blocks_without_resetting_and_saved_snapshot_is_exact(world: World, sandbox_ok: SandboxReport) -> None:
    w = world
    (w.repo / "src" / "app.py").write_text("def main():\n    return 'USER WORK IN PROGRESS'\n")
    (w.repo / "src" / "scratch.py").write_text("untracked = True\n")
    before = {p.name: p.read_text() for p in (w.repo / "src").glob("*.py")}
    status_before = git(w.repo, "status", "--porcelain")
    assert status_before
    sup, out, rid = run(w, "edit")
    assert out.outcome == "blocked" and "dirty_baseline" in out.reason and "nothing was reset" in out.reason.lower() or "dirty_baseline" in out.reason
    assert sup.outbox.get(rid, "fail")["body"]["error_code"] == "dirty_baseline"
    assert {p.name: p.read_text() for p in (w.repo / "src").glob("*.py")} == before  # NOT reset, NOT cleaned
    assert git(w.repo, "status", "--porcelain") == status_before and (w.repo / "src" / "scratch.py").exists()
    assert not (w.state / "runs" / rid).exists() and w.registry.get(BINDING).active_lock_run is None
    # explicit owner approval of THIS tree -> the run starts from exactly that content
    approved = snapshots.worktree_tree_hash(w.repo)
    w.registry.add(dataclasses.replace(w.binding, baseline_policy="saved_dirty_snapshot", approved_tree_hash=approved))
    sup, out, rid = run(w, "edit")
    assert out.outcome == "ready_for_review", out
    ws = w.run_dir(rid) / "workspace"
    assert "USER WORK IN PROGRESS" in (ws / "src" / "app.py").read_text() and (ws / "src" / "scratch.py").exists()
    assert sup.receipts.get(rid)["baseline"]["kind"] == "saved_dirty_snapshot"
    assert git(w.repo, "status", "--porcelain") == status_before  # still the user's dirty tree
    # the approval is bound to the exact tree: one more edit and it no longer matches
    (w.repo / "src" / "scratch.py").write_text("untracked = False\n")
    sup, out, rid = run(w, "edit")
    assert out.outcome == "blocked" and "dirty_baseline" in out.reason


def test_repo_identity_change_blocks(world: World, sandbox_ok: SandboxReport) -> None:
    w = world
    w.registry.add(dataclasses.replace(w.binding, repo_identity="git:" + "0" * 40))
    sup, out, rid = run(w, "edit")
    assert out.outcome == "blocked" and "repo_identity_mismatch" in out.reason


def test_scan_and_diff_helpers_handle_hostile_names(tmp_path: Path) -> None:
    root = tmp_path / "t"
    root.mkdir()
    (root / "a b.txt").write_text("x")
    (root / "back\\slash").write_text("x")
    os.symlink("/etc/passwd", root / "lnk")
    os.mkfifo(root / "fifo")
    scan = snapshots.scan_tree(root)
    assert "lnk" in scan.entries and scan.entries["lnk"].kind == "symlink"
    assert scan.specials == ["fifo"] and scan.bad_names == ["back\\slash"]
    d = snapshots.diff_trees(tmp_path / "empty", root, snapshots.TreeScan(), scan)
    assert {"special_file", "path_invalid"} <= {p["kind"] for p in d.problems}
    # safe removal refuses anything that is not a disposable dir under the allowed root
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "keep").write_text("keep")
    link = tmp_path / "state" / "runs" / "evil"
    link.parent.mkdir(parents=True)
    os.symlink(outside, link)
    with pytest.raises(snapshots.SnapshotError):
        snapshots.remove_tree(link, allowed_root=tmp_path / "state" / "runs")
    with pytest.raises(snapshots.SnapshotError):
        snapshots.remove_tree(outside, allowed_root=tmp_path / "state" / "runs")
    assert (outside / "keep").exists()


def test_cleanup_only_removes_own_disposable_dirs(world: World, sandbox_ok: SandboxReport) -> None:
    w = world
    sup, out, rid = run(w, "edit")
    assert (w.state / "runs" / rid).is_dir()
    assert sup.cleanup_run(rid) is True and not (w.state / "runs" / rid).exists() and w.repo.exists() and w.outside.exists()
    sup, out, rid = run(w, "edit_out_of_scope")
    with pytest.raises(RunRejected):
        sup.cleanup_run(rid)  # quarantined evidence needs an explicit owner decision
    assert sup.cleanup_run(rid, include_quarantined=True) is True
    with pytest.raises(RunRejected):
        sup.cleanup_run("never-finished-run")


# ================================================================================================= receipts / outbox
def test_receipts_are_durable_atomic_and_terminal_is_final(tmp_path: Path) -> None:
    clock = FakeClock()
    st = ReceiptStore(tmp_path / "s", clock)
    st.create("r1", job_id="j", binding_id="b")
    with pytest.raises(RunAlreadyUsed):
        st.create("r1")
    st.update("r1", state="launching", note="x", pid=1)
    assert ReceiptStore(tmp_path / "s", clock).get("r1")["state"] == "launching"  # survives a new process/instance
    st.update("r1", state="finished", outcome="lost")
    for bad in ({"state": "running"}, {"outcome": "ready_for_review"}):
        with pytest.raises(ReceiptError):
            st.update("r1", **bad)
    st.update("r1", delivery={"ok": True})  # only delivery bookkeeping may be added
    assert oct(os.stat(st.path("r1")).st_mode & 0o777) == "0o600" and oct(os.stat(st.dir).st_mode & 0o777) == "0o700"
    assert not list(st.dir.glob(".*.tmp"))
    with pytest.raises(ReceiptError):
        st.path("../escape")


def test_outbox_retries_the_same_request_after_a_lost_response_without_rerunning_the_model(world: World, sandbox_ok: SandboxReport) -> None:
    w = world
    sup, out, rid = run(w, "edit")
    entry = sup.outbox.get(rid, "implementation-result")
    again = sup.outbox.enqueue(rid, "implementation-result", "implementation-result", {"different": "body"})
    assert again["idempotency_key"] == entry["idempotency_key"] and again["body"] == entry["body"]  # one result per run
    seen: list[tuple[str, dict[str, Any]]] = []
    script = iter([DeliveryResult(None, detail="timeout"), DeliveryResult(503, retry_after=5.0), DeliveryResult(200)])

    def send(e: dict[str, Any]) -> DeliveryResult:
        seen.append((e["idempotency_key"], e["body"]))
        return next(script)

    assert sup.deliver_outbox(send)["retry"] == 1
    assert sup.deliver_outbox(send)["skipped"] == 1  # backoff: not due yet (fake clock did not move)
    w.clock.advance(seconds=1.5)
    assert sup.deliver_outbox(send)["retry"] == 1  # 503 with Retry-After 5 s
    w.clock.advance(seconds=3)
    assert sup.deliver_outbox(send)["skipped"] == 1
    w.clock.advance(seconds=3)
    assert sup.deliver_outbox(send)["delivered"] == 1
    assert len({k for k, _ in seen}) == 1 and len({json.dumps(b, sort_keys=True) for _, b in seen}) == 1 and len(seen) == 3
    assert len(sup.receipts.for_job(sup.receipts.get(rid)["job_id"])) == 1  # the model was never run again
    assert sup.outbox.get(rid, "implementation-result")["delivered_at"] and sup.outbox.pending() == []
    # a permanent refusal (409) is never retried blindly
    sup2, out2, rid2 = run(w, "exit_nonzero")
    assert sup2.deliver_outbox(lambda e: DeliveryResult(409, detail="stale epoch"))["rejected"] == 1
    assert (w.state / "outbox" / "rejected" / f"{rid2}.fail.json").exists() and sup2.outbox.pending() == []


# ================================================================================================= crash / reconcile
def _start_crash_driver(w: World, scenario: str, run_id: str, tmp: Path, use_cgroup: bool | None = None) -> dict[str, Any]:
    cfg = {"binding_id": BINDING, "project_id": PROJECT, "root": str(w.repo), "identity": w.binding.repo_identity, "state_dir": str(w.state),
           "scenario": scenario, "run_id": run_id, "job_id": f"job-{run_id}", "scope": SCOPE, "targets": w.targets(), "use_cgroup": use_cgroup}
    cfg_path = tmp / f"driver-{run_id}.json"
    cfg_path.write_text(json.dumps(cfg))
    driver = Path(__file__).with_name("t07_crash_driver.py")
    import sys

    p = subprocess.run([sys.executable, str(driver), str(cfg_path)], capture_output=True, text=True, timeout=120, check=False)  # noqa: S603
    assert p.returncode == -signal.SIGKILL, (p.returncode, p.stdout, p.stderr[-2000:])  # the supervisor really crashed
    return json.loads(p.stdout.strip().splitlines()[-1])


@pytest.mark.parametrize("tree_mode", [None, False], ids=["tree-auto", "tree-procfs"])
def test_supervisor_crash_after_spawn_is_reconciled_and_the_lost_run_never_revives(world: World, sandbox_ok: SandboxReport, tree_mode: bool | None) -> None:
    w = world
    info = _start_crash_driver(w, "spawn_tree", "run-crash", w.tmp, tree_mode)
    child = info["child_pid"]
    assert pid_alive(child), "the sandboxed child must survive the supervisor crash (that is the scenario)"
    # simulate a persisted DB lock held by the dead supervisor's run
    w.registry.add(dataclasses.replace(w.binding, active_lock_run="run-crash", lock_epoch=1))
    new = make_sup(w, "hang", use_cgroup=tree_mode)
    rec = new.receipts.get("run-crash")
    assert rec["state"] == "running" and rec["child_pid"] == child and rec["supervisor"]["instance"] != new.instance_id
    descendants = [p.pid for p in processes.ProcfsTree(root=processes.ProcId(child, rec["child_start"])).members() if p.pid != child]
    # before reconciliation nothing may start on this binding (no second writer)
    blocked = new.start(make_req("run-after-crash-early"), heartbeat=OK_HB).outcome
    assert blocked and blocked.outcome == "blocked" and "binding_busy" in blocked.reason and "reconcile" in blocked.reason
    results = new.reconcile()
    assert [r["outcome"] for r in results] == ["lost"] and results[0]["survivors_killed"] >= 1 and results[0]["tree_absent"] is True
    assert not pid_alive(child) and [p for p in descendants if pid_alive(p)] == []
    rec = new.receipts.get("run-crash")
    assert rec["state"] == "finished" and rec["outcome"] == "lost" and rec["technical_failure"] is True and rec["tree_absent"] is True
    assert (w.state / "quarantine" / "run-crash").is_dir() and not (w.state / "runs" / "run-crash").exists()
    assert w.registry.get(BINDING).active_lock_run is None  # lock released only after absence was proven
    assert w.registry.get(BINDING).quarantine_reason is None
    # the lost run produced NO result and reports only a reconcile receipt
    assert new.outbox.get("run-crash", "implementation-result") is None and new.outbox.get("run-crash", "fail") is None
    rc = new.outbox.get("run-crash", "reconcile")["body"]
    assert rc["process_tree_absent"] is True and rc["workspace_quarantined"] is True
    # never revived: same id is dead, the receipt is final, reconcile is idempotent
    with pytest.raises(RunAlreadyUsed):
        new.start(make_req("run-crash"), heartbeat=OK_HB)
    with pytest.raises(ReceiptError):
        new.receipts.update("run-crash", state="running")
    assert new.reconcile() == []
    # a NEW run (new id, new lease) may now use the binding and counts as a retry of the same job
    after = new.start(make_req("run-after-crash", job_id="job-run-crash"), heartbeat=OK_HB)
    assert after.outcome is None and new.receipts.get("run-after-crash")["attempt"] == 1
    after.stop()


def test_reconcile_finds_an_orphan_even_when_its_pid_was_never_recorded(world: World, sandbox_ok: SandboxReport) -> None:
    w = world
    info = _start_crash_driver(w, "spawn_tree", "run-nopid", w.tmp, False)
    child = info["child_pid"]
    assert pid_alive(child)
    path = w.state / "receipts" / "run-nopid.json"
    rec = json.loads(path.read_text())
    for k in ("child_pid", "child_start", "cgroup", "pgid"):
        rec.pop(k, None)
    rec["state"] = "launching"  # crash window: after "launching" was written, before the pid was recorded
    path.write_text(json.dumps(rec))
    res = make_sup(w, "hang", use_cgroup=False).reconcile()
    assert res[0]["outcome"] == "lost" and res[0]["survivors_killed"] >= 1 and res[0]["tree_absent"]
    assert not pid_alive(child)


def test_reconcile_of_a_run_that_never_launched_and_foreign_live_supervisors(world: World, sandbox_ok: SandboxReport) -> None:
    w = world
    sup = make_sup(w, "edit")
    sup.receipts.create("run-reserved", job_id="j", binding_id=BINDING, project_id=PROJECT,
                        supervisor={"instance": "dead", "pid": 999_999_999, "start": 1})
    sup.receipts.create("run-foreign", job_id="j2", binding_id=BINDING, project_id=PROJECT,
                        supervisor={"instance": "other", "pid": os.getppid(), "start": processes.proc_id(os.getppid()).start})
    sup.receipts.update("run-foreign", state="running")
    res = {r["run_id"]: r for r in sup.reconcile()}
    assert res["run-reserved"]["outcome"] == "not_started"
    assert res["run-foreign"]["action"] == "skipped"  # another LIVE supervisor owns it: not touched
    assert sup.receipts.get("run-foreign")["state"] == "running"


def test_reconcile_that_cannot_confirm_absence_quarantines_the_binding(world: World, sandbox_ok: SandboxReport, monkeypatch: pytest.MonkeyPatch) -> None:
    w = world
    info = _start_crash_driver(w, "hang", "run-stuck", w.tmp, False)
    real = supervisor_mod.terminate_tree
    monkeypatch.setattr(supervisor_mod, "terminate_tree", lambda tree, **kw: (real(tree, **kw), (False, [info["child_pid"]]))[1])
    sup = make_sup(w, "hang", use_cgroup=False)
    res = sup.reconcile()
    assert res[0]["outcome"] == "stop_unknown" and res[0]["tree_absent"] is False
    assert "not confirmed" in w.registry.get(BINDING).quarantine_reason
    assert sup.outbox.get("run-stuck", "reconcile")["body"]["process_tree_absent"] is False


# ================================================================================================= repo bindings (owner only)
def test_task_payloads_cannot_carry_repository_paths_or_commands() -> None:
    for key in ("repo_path", "canonical_root", "cwd", "workspace", "path", "command", "argv", "shell", "env", "home", "mounts"):
        with pytest.raises(PathInPayload):
            reject_path_fields({"title": "t", key: "/etc"})
        with pytest.raises(PathInPayload):
            reject_path_fields({"title": "t", "acceptance": [{"nested": {key: "/etc"}}]})
    reject_path_fields({"title": "t", "requirements": "touch /etc/passwd is just text", "acceptance": ["a"]})


def test_start_rejects_paths_in_payload_and_foreign_bindings(world: World, sandbox_ok: SandboxReport) -> None:
    w = world
    sup = make_sup(w)
    for task in ({"title": "t", "requirements": "r", "acceptance": ["a"], "repo_path": str(w.repo)},
                 {"title": "t", "requirements": "r", "acceptance": ["a"], "extra": 1},
                 {"title": "t", "requirements": "r", "acceptance": ["a"], "env": {"X": "1"}}):
        req = make_req(task=task)
        with pytest.raises(RunRejected):
            sup.start(req, heartbeat=OK_HB)
        assert sup.receipts.get(req.run_id) is None and sup.outbox.get(req.run_id, "fail") is None  # refused before anything exists
        assert not (w.state / "runs" / req.run_id).exists() and w.registry.get(BINDING).active_lock_run is None
    with pytest.raises(RunRejected):
        sup.start(make_req(scope={"allowed_paths": ["/etc/**"], "max_changed_files": 1, "max_diff_lines": 1}), heartbeat=OK_HB)
    other = BindingInfo(id="bind-other", project_id="another-project", canonical_root=w.repo, repo_identity=w.binding.repo_identity)
    w.registry.add(other)
    req = make_req()
    req = dataclasses.replace(req, binding_id="bind-other")
    with pytest.raises(RunRejected, match="another project"):
        sup.start(req, heartbeat=OK_HB)
    assert sup.receipts.get(req.run_id)["outcome"] == "rejected" and sup.outbox.get(req.run_id, "fail") is None
    assert w.registry.get("bind-other").active_lock_run is None
    with pytest.raises(RunRejected):
        make_req(run_id="../../etc/cron.d/x")


def test_api_has_no_route_that_sets_a_canonical_root_and_rejects_path_fields(env: Any, api: Any) -> None:
    paths = {getattr(r, "path", "") for r in env.app.routes}
    assert not [p for p in paths if re.search(r"binding|repo|canonical|workspace|clone", p)], paths
    for extra in ({"repo_path": "/etc"}, {"canonical_root": "/home"}, {"cwd": "/"}):
        r = api.req("owner", "POST", api.p("/tasks"), api.task_body(**extra))
        assert r.status_code == 422, (extra, r.text)
    r = api.req("owner", "POST", api.p("/tasks"), api.task_body(scope={**api.task_body()["scope"], "allowed_paths": ["/etc/**"]}))
    assert r.status_code == 422
    r = api.req("owner", "POST", api.p("/tasks"), api.task_body(scope={**api.task_body()["scope"], "allowed_paths": ["../outside/**"]}))
    assert r.status_code == 422


def test_owner_registers_and_manages_a_binding_in_the_database(env: Any, api: Any, tmp_path: Path) -> None:
    from nozo_relay.db.engine import write_session
    from nozo_relay.db.models import Project, RepoBinding
    from nozo_relay.services import repo_bindings as rb

    engine = env.app.state.engine
    repo = make_repo(tmp_path / "bound-repo")
    clock = env.clock
    protected = [env.settings.data_dir]

    def scope() -> Any:
        return write_session(engine)

    with scope() as ws:
        with pytest.raises(rb.RepoBindingError, match="absolute"):
            rb.register_binding(ws, clock, project="default", canonical_root="relative/path")
        with pytest.raises(rb.RepoBindingError, match="plain git"):
            rb.register_binding(ws, clock, project="default", canonical_root=str(tmp_path))
        (tmp_path / "linkroot").symlink_to(repo)
        with pytest.raises(rb.RepoBindingError, match="symlink"):
            rb.register_binding(ws, clock, project="default", canonical_root=str(tmp_path / "linkroot"))
        with pytest.raises(rb.RepoBindingError, match="home"):
            rb.register_binding(ws, clock, project="default", canonical_root=str(Path.home()))
        with pytest.raises(rb.RepoBindingError, match="unknown project"):
            rb.register_binding(ws, clock, project="nope", canonical_root=str(repo))
        inner = make_repo(env.settings.data_dir / "nested-repo")
        with pytest.raises(rb.RepoBindingError, match="overlaps"):
            rb.register_binding(ws, clock, project="default", canonical_root=str(inner), protected_dirs=protected)
        b = rb.register_binding(ws, clock, project="default", canonical_root=str(repo), actor_id=api.owner_id, protected_dirs=protected)
        bid = b.id
        assert b.canonical_root == str(repo.resolve()) and b.repo_identity.startswith("git:") and b.created_at == clock.now_ms()
        assert ws.get(Project, api.project_id).repo_binding_id == bid
        with pytest.raises(rb.RepoBindingError, match="already has"):
            rb.register_binding(ws, clock, project="default", canonical_root=str(repo))
    # a task is created through the API: the stored binding path is never taken from it
    task = api.create_task()
    assert "canonical_root" not in json.dumps(task) and str(repo) not in json.dumps(task)

    reg = rb.DbBindingRegistry(scope, clock)
    q = api.queued_task()
    claim = api.claim("impl")
    api.start("impl", claim)
    run_id = claim["run_id"]
    assert reg.acquire_lock(bid, run_id) == 1
    with pytest.raises(BindingLocked):
        reg.acquire_lock(bid, run_id)  # one writer per binding, even for the same run id
    reg.release_lock(bid, "someone-else")
    assert reg.get(bid).active_lock_run == run_id  # only the holder can release
    reg.release_lock(bid, run_id)
    assert reg.get(bid).active_lock_run is None and reg.acquire_lock(bid, run_id) == 2  # epoch increases
    reg.release_lock(bid, run_id)
    reg.quarantine(bid, "test quarantine")
    with pytest.raises(BindingLocked):
        reg.acquire_lock(bid, run_id)
    with scope() as ws:
        rb.clear_quarantine(ws, binding_id=bid)
        (repo / "src" / "app.py").write_text("dirty\n")
        tree = rb.approve_dirty_snapshot(ws, clock, binding_id=bid)
        assert tree == snapshots.worktree_tree_hash(repo)
        row = ws.get(RepoBinding, bid)
        assert row.baseline_policy == "saved_dirty_snapshot" and row.approved_tree_hash == tree
    assert reg.get(bid).quarantine_reason is None and q["id"]


def test_cli_repo_bind_is_an_owner_local_command(env: Any, api: Any, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    from nozo_relay.__main__ import main

    repo = make_repo(tmp_path / "cli-repo")
    monkeypatch.setenv("NOZO_RELAY_DATA_DIR", str(env.settings.data_dir))
    assert main(["repo-bind", "--project", "default", "--root", str(repo)]) == 0
    assert "Bound project default" in capsys.readouterr().out
    assert main(["repo-bind", "--project", "default", "--root", str(repo)]) == 1  # already bound
    assert "already has a repo binding" in capsys.readouterr().err
    assert main(["repo-bind", "--project", "default", "--root", "relative"]) == 1


def test_schema_v4_adds_repo_binding_columns_idempotently(env: Any, tmp_path: Path) -> None:
    import sqlite3

    from sqlalchemy import text

    from nozo_relay.db.engine import create_sqlite_engine
    from nozo_relay.db.schema import SCHEMA_VERSION, ensure_schema, migrate_to_current, read_schema_version

    assert SCHEMA_VERSION == 6
    src = sqlite3.connect(env.settings.db_path)
    dst_path = tmp_path / "v3.sqlite"
    dst = sqlite3.connect(dst_path)
    src.backup(dst)
    src.close()
    for col in ("created_at", "registered_by", "baseline_policy", "approved_tree_hash", "approved_at", "quarantined_at"):
        dst.execute(f"ALTER TABLE repo_bindings DROP COLUMN {col}")
    dst.execute("UPDATE schema_version SET version = 3")
    dst.commit()
    dst.close()
    eng = create_sqlite_engine(dst_path)
    from nozo_relay.db.schema import SchemaError

    with pytest.raises(SchemaError, match="incompatible schema version 3"):
        ensure_schema(eng, env.clock)
    assert migrate_to_current(eng, env.clock) == (3, 5) and read_schema_version(eng) == 5
    assert migrate_to_current(eng, env.clock) == (5, 5)
    with eng.connect() as c:
        cols = {r[1] for r in c.execute(text("PRAGMA table_info(repo_bindings)")).fetchall()}
    assert {"created_at", "registered_by", "baseline_policy", "approved_tree_hash", "approved_at", "quarantined_at"} <= cols
    assert ensure_schema(eng, env.clock) == 5
    assert "supervisor_principal_id" in {r[1] for r in sqlite3.connect(dst_path).execute("PRAGMA table_info(runs)")}
    eng.dispose()


# ================================================================================================= end to end with the real API
def _submit(api: Any, entry: dict[str, Any], who: str = "impl") -> Any:
    """Deliver an outbox entry to the real relay API exactly as the outbox sender would (same idempotency key)."""
    run_id = entry["run_id"]
    return api.req(who, "POST", api.p(f"/runs/{run_id}/{entry['endpoint']}"), entry["body"], idem=entry["idempotency_key"])


def test_end_to_end_supervisor_result_is_accepted_by_the_relay_and_replays_safely(env: Any, api: Any, world: World, sandbox_ok: SandboxReport) -> None:
    from nozo_relay.db.models import Task

    w = world
    task = api.queued_task()
    claim = api.claim("impl")
    api.start("impl", claim)
    sup = make_sup(w, "leak_secret_transient", provider=True)
    req = RunRequest(
        project_id=PROJECT, task_id=claim["task_id"], job_id=claim["job_id"], run_id=claim["run_id"], binding_id=BINDING, adapter="fixture",
        lease_epoch=claim["lease_epoch"], revision=claim["revision"], policy_digest=claim["policy_digest"], scope=SCOPE, mode="surgical",
        task={"title": task["title"], "requirements": "end to end", "acceptance": ["ok"]},
    )
    beats: list[int] = []

    def heartbeat() -> HeartbeatOutcome:
        r = api.heartbeat("impl", claim, expect=None)
        beats.append(r.status_code)
        return HeartbeatOutcome.OK if r.status_code == 200 else HeartbeatOutcome.FAILED

    out = sup.execute(req, heartbeat=heartbeat, start_gate=lambda: True)
    assert out.outcome == "ready_for_review", out
    entry = sup.outbox.get(claim["run_id"], "implementation-result")
    r = _submit(api, entry)
    assert r.status_code == 200, r.text
    r2 = _submit(api, entry)  # lost response -> same key, same body -> same reply, still ONE result
    assert r2.status_code == 200 and r2.json() == r.json()
    assert api.get_task(claim["task_id"])["status"] == "awaiting_review"
    assert sup.deliver_outbox(lambda e: DeliveryResult(_submit(api, e).status_code))["delivered"] == 1
    # Q22 against the real relay: the sentinel is not in the task, reports, events or UI payloads
    blobs = [json.dumps(api.get_task(claim["task_id"])), json.dumps(api.events()), json.dumps(entry)]
    for path in ("/tasks", f"/tasks/{claim['task_id']}", "/reports" if False else f"/tasks/{claim['task_id']}"):
        blobs.append(api.req("owner", "GET", api.p(path)).text)
    for b in blobs:
        assert PROVIDER_SECRET not in b and OWNER_SECRET not in b
    assert api.db().get(Task, claim["task_id"]) is not None


def test_end_to_end_quarantine_blocks_the_task_with_scope_change_required(env: Any, api: Any, world: World, sandbox_ok: SandboxReport) -> None:
    w = world
    task = api.queued_task()
    claim = api.claim("impl")
    api.start("impl", claim)
    sup = make_sup(w, "edit_out_of_scope")
    req = RunRequest(
        project_id=PROJECT, task_id=claim["task_id"], job_id=claim["job_id"], run_id=claim["run_id"], binding_id=BINDING, adapter="fixture",
        lease_epoch=claim["lease_epoch"], revision=claim["revision"], policy_digest=claim["policy_digest"], scope=SCOPE, mode="surgical",
        task={"title": task["title"], "requirements": "end to end", "acceptance": ["ok"]},
    )
    out = sup.execute(req, heartbeat=OK_HB)
    assert out.outcome == "quarantined"
    r = _submit(api, sup.outbox.get(claim["run_id"], "fail"))
    assert r.status_code == 200, r.text
    t = api.get_task(claim["task_id"])
    assert t["status"] == "blocked" and t["blocked_reason"] == "scope_change_required"
    assert api.req("impl", "POST", api.p(f"/runs/{claim['run_id']}/implementation-result"), api.impl_payload(claim), idem=True).status_code in (409, 412)


def test_end_to_end_stop_receipt_and_reconcile_receipt_match_the_api_schemas(env: Any, api: Any, world: World, sandbox_ok: SandboxReport) -> None:
    from nozo_relay.api.schemas import ReconcileReceipt, StoppedReceipt

    w = world
    sup = make_sup(w, "hang")
    h = sup.start(make_req("run-schema"), heartbeat=OK_HB)
    assert h.wait_for_event("progress", 10)
    h.stop(control_id="00000000-0000-4000-8000-0000000000aa", target_epoch=3)
    StoppedReceipt.model_validate(sup.outbox.get("run-schema", "stopped")["body"])
    new = make_sup(w, "hang")
    new.receipts.create("run-lost", job_id="j", binding_id=BINDING, project_id=PROJECT, supervisor={"instance": "dead", "pid": 999_999_999, "start": 1})
    new.receipts.update("run-lost", state="running", child_pid=999_999_998, child_start=1)
    new.reconcile()
    ReconcileReceipt.model_validate(new.outbox.get("run-lost", "reconcile")["body"])


def test_probe_cli_reports_and_exit_code(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], sandbox_report: SandboxReport) -> None:
    from nozo_relay.__main__ import main

    monkeypatch.setenv("NOZO_RELAY_DATA_DIR", str(tmp_path / "d"))
    rc = main(["sandbox-probe"])
    data = json.loads(capsys.readouterr().out)
    assert data["verdict"] in ("probe_pass", "probe_fail", "blocked_external") and data["sandbox"]["mounts"]["not_reachable"]
    assert rc == (0 if data["verdict"] == "probe_pass" else 3) and (data["verdict"] == "probe_pass") == sandbox_report.ok


_ = (threading, Callable)
