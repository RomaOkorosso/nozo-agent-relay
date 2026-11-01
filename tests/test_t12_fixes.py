"""T12 fix round: regression tests for Codex findings F01-F07 beyond the independent audit file."""

from __future__ import annotations

import errno
import json
import os
import sqlite3
import stat
import subprocess
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from api_helpers import Api, uid
from nozo_relay import backup
from nozo_relay.api.errors import is_disk_full
from nozo_relay.db.engine import create_sqlite_engine, write_session
from nozo_relay.db.models import Credential, Membership, Principal, Run
from nozo_relay.db.schema import SCHEMA_VERSION, ensure_schema, migrate_to_current, read_schema_version
from nozo_relay.keymint import mint_key
from nozo_relay.services.acl import scope_within
from nozo_relay.services.scope import glob_covers, path_matches

# ============================================================================================== F01


def _s(*paths: str, files: int = 5, lines: int = 200, deps: bool = False) -> dict:
    return {"allowed_paths": list(paths), "max_changed_files": files, "max_diff_lines": lines, "allow_new_dependencies": deps}


@pytest.mark.parametrize(
    ("scope", "ceiling", "expected"),
    [
        ("src/*.py", "src/*.py", True),  # identical
        ("src/**", "src/**", True),
        ("src/foo.py", "src/*.py", True),  # literal under a single-segment glob
        ("src/foo.py", "src/**", True),
        ("src/*.py", "src/*", True),
        ("src/*.py", "src/**", True),
        ("src/a/b.py", "src/**", True),
        ("src/**/x.py", "src/**", True),
        ("src/*.py", "src/**/*.py", True),
        ("src/?.py", "src/*.py", True),
        ("src/*.py", "src/*y", True),
        ("*.py", "**", True),
        ("a/*.py", "*.py", True),  # bare ceiling name also matches at any depth
        # ---- widening / unproven: all must be False
        ("src/*.sh", "src/*.py", False),  # F01 reproduction
        ("src/*", "src/*.py", False),
        ("src/**", "src/*", False),  # recursion widens a single segment
        ("src/a/b.py", "src/*", False),
        ("src/**", "src/**/x.py", False),
        ("src/**/*.py", "src/*.py", False),
        ("src/*.py", "src/?.py", False),
        ("docs/**", "src/**", False),
        ("*.py", "src/**", False),
        ("src/**", "**/*.py", False),
        ("src/../etc/**", "src/**", False),  # traversal spelling is never proven
        ("/etc/passwd", "**", False),
        ("src//x", "src/**", False),
        ("./src/x", "**", False),
        ("src\\x", "**", False),
        ("src/*.py", "src/*.py/", False),
    ],
)
def test_f01_glob_covers_matrix(scope: str, ceiling: str, expected: bool) -> None:
    assert scope_within(_s(scope), _s(ceiling)) is expected


def test_f01_glob_covers_agrees_with_path_matches_on_samples() -> None:
    """If glob_covers(a, b) then no sample path may match a but not b (soundness cross-check)."""
    patterns = ["src/*.py", "src/*.sh", "src/*", "src/**", "src/**/x.py", "src/?.py", "*.py", "**", "docs/**", "src/a/*.py", "**/*.py"]
    samples = ["src/a.py", "src/x.py", "src/a.sh", "src/a/b.py", "src/a/x.py", "src/x", "x.py", "a/b/c.py", "docs/r.md", "src/", "src/.py", "src/ab.py", "src/a/b/x.py"]
    for a in patterns:
        for b in patterns:
            if glob_covers(a, b):
                for p in samples:
                    assert not path_matches(a, p) or path_matches(b, p), (a, b, p)


def test_f01_budgets_and_dependencies_still_enforced() -> None:
    assert not scope_within(_s("src/**", files=6), _s("src/**", files=5))
    assert not scope_within(_s("src/**", lines=201), _s("src/**", lines=200))
    assert not scope_within(_s("src/**", deps=True), _s("src/**"))
    assert scope_within(_s("src/a.py", "src/b/**"), _s("src/**"))
    assert not scope_within(_s("src/a.py", "web/x"), _s("src/**"))  # every pattern must be covered
    assert not scope_within(_s("src/a.py"), _s("web/**", "docs/**"))  # no ceiling pattern covers it


def test_f01_pathological_globs_terminate_and_fail_closed() -> None:
    assert glob_covers("a" + "*/" * 40 + "b", "**") is True
    assert glob_covers("**/" * 30 + "x", "*/" * 5 + "x") is False


def test_f01_delegation_revision_cannot_widen_glob(api: Api) -> None:
    cid, key = api.make_principal("coordinator", "t12-coordinator")
    until = datetime.fromtimestamp(api.clock.now_ms() / 1000, UTC) + timedelta(hours=1)
    ceil = {"allowed_paths": ["src/*.py"], "max_changed_files": 5, "max_diff_lines": 200, "allow_autonomous": True}
    d = api.req("owner", "POST", api.p("/delegations"), {"coordinator_id": cid, "allowed_actions": ["task.create", "task.enqueue"], "scope_ceiling": ceil, "valid_until": until.isoformat()})
    assert d.status_code == 201, d.text
    ok = api.task_body(delegation_id=d.json()["id"], scope={"allowed_paths": ["src/a.py"], "denied_paths": [], "max_changed_files": 5, "max_diff_lines": 200, "allow_new_dependencies": False})
    assert api.req(api.client_for_key(key), "POST", api.p("/tasks"), ok).status_code == 201


# ============================================================================================== F02


def test_f02_run_binds_the_claimed_supervisor_and_it_can_confirm(api: Api) -> None:
    task = api.queued_task()
    run = api.claim()
    api.start("impl", run)
    with api.db() as s:
        row = s.get(Run, run["run_id"])
        assert row is not None and row.supervisor_principal_id == api.runner_id
    stop = api.control(task["id"], "cancel").json()["control"]
    assert api.stopped(run, stop).json()["task"]["status"] == "cancelled"


def test_f02_claim_rejects_unknown_non_runner_inactive_and_foreign_supervisors(api: Api) -> None:
    api.queued_task()
    body = lambda sup: {"stage": "implement", "claim_request_id": uid(), "runner_instance_id": "r", "supervisor_principal_id": sup}  # noqa: E731
    assert api.req("impl", "POST", api.p("/jobs/claim"), body(uid())).status_code == 422  # unknown id
    assert api.req("impl", "POST", api.p("/jobs/claim"), body(api.aud_id)).status_code == 422  # not a runner
    other_runner, _ = api.make_principal("runner", "other")
    with write_session(api.app.state.engine) as ws:
        ws.get(Principal, other_runner).active = False
    assert api.req("impl", "POST", api.p("/jobs/claim"), body(other_runner)).status_code == 422  # inactive
    with write_session(api.app.state.engine) as ws:
        p = Principal(display_name="lonely", kind="runner", active=True, created_at=api.clock.now_ms())
        ws.add(p)
        ws.flush()
        lonely = p.id  # runner without membership of this project
    assert api.req("impl", "POST", api.p("/jobs/claim"), body(lonely)).status_code == 422
    assert api.req("impl", "POST", api.p("/jobs/claim"), {**body(api.runner_id), "supervisor_principal_id": "not-a-uuid"}).status_code == 422
    # nothing was leased by the rejected attempts
    assert api.req("impl", "POST", api.p("/jobs/claim"), body(api.runner_id)).status_code == 200


def test_f02_omitted_supervisor_needs_exactly_one_runner(api: Api) -> None:
    api.queued_task()
    api.make_principal("runner", "second-runner")  # now two active runners: ambiguous
    r = api.req("impl", "POST", api.p("/jobs/claim"), {"stage": "implement", "claim_request_id": uid(), "runner_instance_id": "r"})
    assert r.status_code == 422 and r.json()["error"]["code"] == "supervisor_required"


def test_f02_unrelated_runner_cannot_reconcile_a_lost_run(api: Api) -> None:
    task = api.queued_task()
    run = api.claim()
    api.start("impl", run)
    api.clock.advance(seconds=91)
    from nozo_relay.services.leases import sweep

    with write_session(api.app.state.engine) as ws:
        sweep(ws, api.clock, api.env.settings)
    assert api.get_task(task["id"])["status"] == "blocked"
    _, key = api.make_principal("runner", "intruder")
    body = {"process_tree_absent": True, "workspace_quarantined": True, "receipt": "forged"}
    url = api.p(f"/runs/{run['run_id']}/reconcile")
    r = api.req(api.client_for_key(key), "POST", url, body)
    assert r.status_code in (403, 404), r.text
    assert api.get_task(task["id"])["status"] == "blocked"
    ok = api.req("runner", "POST", url, body)
    assert ok.status_code == 200 and ok.json()["outcome"] == "paused_ready_to_resume", ok.text


def test_f02_legacy_run_without_supervisor_can_never_be_confirmed(api: Api) -> None:
    task = api.queued_task()
    run = api.claim()
    api.start("impl", run)
    stop = api.control(task["id"], "cancel").json()["control"]
    with write_session(api.app.state.engine) as ws:
        ws.get(Run, run["run_id"]).supervisor_principal_id = None
    r = api.stopped(run, stop, expect=None)
    assert r.status_code == 404
    assert api.get_task(task["id"])["status"] == "stop_requested"


def test_f02_migration_adds_column_to_a_v4_database(env, tmp_path: Path) -> None:
    src = sqlite3.connect(env.settings.db_path)
    path = tmp_path / "v4.sqlite"
    dst = sqlite3.connect(path)
    src.backup(dst)
    src.close()
    dst.execute("PRAGMA foreign_keys=OFF")
    dst.execute("ALTER TABLE runs RENAME TO runs_new")
    cols = [r[1] for r in dst.execute("PRAGMA table_info(runs_new)") if r[1] != "supervisor_principal_id"]
    dst.execute(f"CREATE TABLE runs AS SELECT {', '.join(cols)} FROM runs_new")
    dst.execute("DROP TABLE runs_new")
    dst.execute("UPDATE schema_version SET version = 4")
    dst.commit()
    assert "supervisor_principal_id" not in {r[1] for r in dst.execute("PRAGMA table_info(runs)")}
    dst.close()
    eng = create_sqlite_engine(path)
    assert migrate_to_current(eng, env.clock) == (4, SCHEMA_VERSION) and read_schema_version(eng) == SCHEMA_VERSION
    assert ensure_schema(eng, env.clock) == SCHEMA_VERSION
    assert migrate_to_current(eng, env.clock) == (SCHEMA_VERSION, SCHEMA_VERSION)
    with sqlite3.connect(path) as c:
        assert "supervisor_principal_id" in {r[1] for r in c.execute("PRAGMA table_info(runs)")}
    eng.dispose()


# ============================================================================================== F03


def test_f03_runner_cannot_read_or_write_project_content(api: Api) -> None:
    task = api.queued_task()
    run = api.claim()
    api.start("impl", run)
    api.req("owner", "POST", api.p("/messages"), {"client_message_id": uid(), "kind": "note", "body": "secret discussion"})
    reads = [
        api.p(), api.p("/tasks"), api.p(f"/tasks/{task['id']}"), api.p("/messages"), api.p("/events"),
        api.p("/approval-requests"), api.p("/snapshot"), api.p("/delegations"), api.p("/policy"), "/api/v1/projects", "/api/v1/agents",
    ]
    for url in reads:
        r = api.req("runner", "GET", url)
        assert r.status_code in (403, 404), (url, r.status_code)
        assert "secret discussion" not in r.text
    r = api.req("runner", "POST", api.p("/messages"), {"client_message_id": uid(), "kind": "note", "body": "x"})
    assert r.status_code == 403
    # still allowed: the supervisor's lifecycle receipts for its own run
    stop = api.control(task["id"], "cancel").json()["control"]
    assert api.stopped(run, stop).status_code == 200


def test_f03_runner_websocket_is_refused(api: Api, env) -> None:
    client = api.client_for_key(api.keys["runner"])
    with pytest.raises(Exception):  # noqa: B017, PT011 - denial before accept surfaces as a starlette disconnect/denial
        with client.websocket_connect(f"ws://127.0.0.1:8765/ws/v1/projects/{api.project_id}"):
            pass


def test_f03_runner_is_refused_by_the_mcp_gateway(api: Api) -> None:
    c = api.client_for_key(api.keys["runner"])
    r = c.post(
        "/mcp", json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
        headers={"Accept": "application/json, text/event-stream"},
    )
    assert r.status_code == 403 and r.json()["error"]["code"] == "runner_not_allowed", r.text


# ============================================================================================== F04


def _run_in_sandbox(tmp_path: Path, code: str) -> int:
    from nozo_relay.runner.sandbox import Limits, RunDirs, build_policy, interpreter_prefix, launch_shim

    dirs = RunDirs(*(tmp_path / n for n in ("workspace", "ro", "out", "home", "tmp")))
    for d in (dirs.workspace, dirs.ro, dirs.out, dirs.home, dirs.tmp):
        d.mkdir()
    exe, _ = interpreter_prefix()
    policy = build_policy(
        argv=[str(exe), "-I", "-c", code], dirs=dirs, extra_ro=[], net_mode="none", net_ports=[],
        limits=Limits(), cgroup_procs=None, memory_via_rlimit=False, nproc_limit=None,
    )
    path = tmp_path / "policy.json"
    path.write_text(json.dumps(policy))
    child = launch_shim(path, env={"PATH": "/usr/bin:/bin"}, cwd=dirs.workspace, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    ready, why = child.wait_ready()
    assert ready, why
    child.proc.wait(timeout=20)
    return child.proc.returncode


def test_f04_metadata_syscalls_are_denied_on_outside_files(tmp_path: Path) -> None:
    sentinel = tmp_path / "outside"
    sentinel.write_text("x")
    sentinel.chmod(0o600)
    before = sentinel.stat()
    code = (
        "import os,sys\n"
        f"p={str(sentinel)!r}\n"
        "ok=[]\n"
        "for name,fn in [('chmod',lambda: os.chmod(p,0o666)),('utime',lambda: os.utime(p,(1,1))),('utime_ns',lambda: os.utime(p,ns=(1,1))),"
        "('chown',lambda: os.chown(p,os.getuid(),os.getgid())),('lchown',lambda: os.lchown(p,os.getuid(),os.getgid()))]:\n"
        "    try: fn(); ok.append(name)\n"
        "    except OSError: pass\n"
        "sys.exit(len(ok))\n"
    )
    assert _run_in_sandbox(tmp_path, code) == 0, "a metadata syscall succeeded inside the sandbox"
    after = sentinel.stat()
    assert (stat.S_IMODE(after.st_mode), after.st_mtime_ns) == (stat.S_IMODE(before.st_mode), before.st_mtime_ns)


def test_f04_seccomp_tables_cover_the_metadata_syscalls() -> None:
    from nozo_relay.runner.sandbox_exec import _SYSCALLS

    for machine, names in {
        "x86_64": {"chmod", "fchmod", "fchmodat", "chown", "fchown", "lchown", "fchownat", "utime", "utimes", "utimensat"},
        "aarch64": {"fchmod", "fchmodat", "fchown", "fchownat", "utimensat"},
    }.items():
        assert names <= set(_SYSCALLS[machine]), machine


# ============================================================================================== F05


def _backup_with_artifact(api: Api, env, tmp_path: Path) -> tuple[Path, dict]:
    r = api.clients["impl"].post(api.p("/artifacts"), content=b"evidence bytes", headers={"Idempotency-Key": uid()})
    assert r.status_code == 201, r.text
    dest = tmp_path / "bk"
    return dest, backup.create_backup(env.settings, dest, env.clock)


def _rewrite_manifest(dest: Path, **changes) -> None:
    mf = dest / "manifest.json"
    m = json.loads(mf.read_text())
    m.update(changes)
    mf.write_text(json.dumps(m))


def test_f05_complete_backup_restores_and_checks_artifact_set(api: Api, env, tmp_path: Path) -> None:
    dest, manifest = _backup_with_artifact(api, env, tmp_path)
    assert manifest["complete"] is True and len(manifest["artifacts"]) == 1
    rep = backup.restore_backup(dest, tmp_path / "restored", env.clock)
    assert rep["target"].endswith("restored")


def test_f05_verify_rejects_incomplete_flag_problems_and_omitted_artifacts(api: Api, env, tmp_path: Path) -> None:
    dest, manifest = _backup_with_artifact(api, env, tmp_path)
    _rewrite_manifest(dest, complete=False)
    with pytest.raises(backup.BackupError, match="complete=false"):
        backup.verify_backup(dest)
    _rewrite_manifest(dest, complete=True, problems=["artifact x: file missing or unsafe"])
    with pytest.raises(backup.BackupError, match="problems"):
        backup.verify_backup(dest)
    _rewrite_manifest(dest, complete=True, problems=[], artifacts=[])  # DB still holds the artifact row
    with pytest.raises(backup.BackupError, match="artifact row"):
        backup.verify_backup(dest)
    with pytest.raises(backup.BackupError):
        backup.restore_backup(dest, tmp_path / "never", env.clock)
    assert not (tmp_path / "never").exists()
    _rewrite_manifest(dest, complete=True, problems=[], artifacts=manifest["artifacts"], **{})
    assert backup.verify_backup(dest)["complete"] is True


def test_f05_corrupt_artifact_makes_backup_incomplete_and_unrestorable(api: Api, env, tmp_path: Path) -> None:
    r = api.clients["impl"].post(api.p("/artifacts"), content=b"to be corrupted", headers={"Idempotency-Key": uid()})
    aid = r.json()["id"]
    (env.settings.artifacts_dir / aid[:2] / aid).write_bytes(b"corrupted!!")
    dest = tmp_path / "bk"
    manifest = backup.create_backup(env.settings, dest, env.clock)
    assert manifest["complete"] is False and manifest["problems"]
    with pytest.raises(backup.BackupError):
        backup.restore_backup(dest, tmp_path / "restored", env.clock)


# ============================================================================================== F06


def test_f06_file_write_failure_revokes_the_committed_credential(api: Api, env, monkeypatch) -> None:
    real_open = os.open

    def failing(path, flags, mode=0o777, *a, **kw):  # noqa: ANN001
        if "minted_keys" in str(path):
            raise OSError(errno.EIO, "injected write failure")
        return real_open(path, flags, mode, *a, **kw)

    monkeypatch.setattr(os, "open", failing)
    with pytest.raises(OSError, match="injected"):
        mint_key(env.settings, api.impl_id, clock=env.clock)
    monkeypatch.undo()
    assert list((env.settings.data_dir / "minted_keys").glob("*.json")) == []
    with api.db() as s:
        creds = s.query(Credential).filter(Credential.principal_id == api.impl_id).all()
        assert len(creds) == 2 and sum(c.revoked_at is not None for c in creds) == 1  # bootstrap key + revoked mint


def test_f06_success_writes_one_private_file_matching_the_committed_credential(api: Api, env) -> None:
    res = mint_key(env.settings, api.impl_id, clock=env.clock)
    assert stat.S_IMODE(res.path.stat().st_mode) == 0o600
    data = json.loads(res.path.read_text())
    assert data["credential_id"] == res.credential_id
    with api.db() as s:
        cred = s.get(Credential, res.credential_id)
        assert cred is not None and cred.revoked_at is None
    assert api.req(api.client_for_key(data["key"]), "GET", api.p("/tasks")).status_code == 200


# ============================================================================================== F07


def test_f07_is_disk_full_classifier() -> None:
    assert is_disk_full(sqlite3.OperationalError("database or disk is full"))
    assert is_disk_full(sqlite3.OperationalError("SQLITE_FULL"))
    assert is_disk_full(OSError(errno.ENOSPC, "No space left on device"))
    assert is_disk_full(_chained(sqlite3.OperationalError("database or disk is full")))
    assert not is_disk_full(sqlite3.OperationalError("database is locked"))
    assert not is_disk_full(ValueError("boom"))


def _chained(inner: BaseException) -> BaseException:
    try:
        try:
            raise inner
        except BaseException as e:  # noqa: BLE001
            raise RuntimeError("outer") from e
    except RuntimeError as outer:
        return outer


def test_f07_raw_sqlite_error_outside_sqlalchemy_is_503_and_busy_stays_503(api: Api) -> None:
    from fastapi import APIRouter

    router = APIRouter()
    state = {"msg": "database or disk is full"}

    @router.get("/__t12_raw")
    def raw() -> dict:  # pragma: no cover - exercised through the client
        raise sqlite3.OperationalError(state["msg"])

    api.app.include_router(router)
    c = api.client_for_key(api.keys["impl"])
    c._transport.raise_server_exceptions = False  # type: ignore[attr-defined]
    r = c.get("/__t12_raw")
    assert r.status_code == 503 and r.json()["error"]["code"] == "storage_full" and r.json()["error"]["retryable"] is True
    state["msg"] = "database is locked"
    assert c.get("/__t12_raw").json()["error"]["code"] == "database_busy"
    state["msg"] = "syntax error"
    assert c.get("/__t12_raw").status_code == 500
