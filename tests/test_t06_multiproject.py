"""T06: multi-project isolation, policy, delegations, scheduling, approvals, artifacts, backup/restore.

Q13 (loop A->B->A), Q14 (cross-project IDs), Q24 (backup/restore/migration), Q25 (surgical scope exits,
fixture level), Q33 (approval binding/expiry/reuse), Q34 (paused project / owner stop) + revoke delegation.
"""

from __future__ import annotations

import concurrent.futures
import contextlib
import dataclasses
import json
import logging
import os
import shutil
import sqlite3
import stat
import threading
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from sqlalchemy import func, select, text
from starlette.testclient import WebSocketDenialResponse, WebSocketDisconnect

from api_helpers import SCOPE, Api, uid
from conftest import BASE_URL, OWNER_PASSWORD, Env, login, make_settings
from nozo_relay import backup as backup_mod
from nozo_relay import logsafe
from nozo_relay.auth.credentials import issue_credential
from nozo_relay.config import Settings
from nozo_relay.db.engine import create_sqlite_engine, write_session
from nozo_relay.db.models import (
    ApprovalRequest,
    Artifact,
    Event,
    Membership,
    Message,
    Principal,
    Report,
    Run,
    SessionRow,
    Snapshot,
    Task,
)
from nozo_relay.db.schema import SCHEMA_VERSION, SchemaError, ensure_schema, migrate_to_current, read_schema_version
from nozo_relay.domain.fingerprints import AuditRound, detect_loop
from nozo_relay.main import create_app
from nozo_relay.retention import RETENTION_RULES
from nozo_relay.services import approvals as approvals_svc

Rejected = (WebSocketDisconnect, WebSocketDenialResponse)
ORIGIN = BASE_URL
SHA_A = "a" * 64
SHA_B = "b" * 64


@pytest.fixture
def settings(tmp_path: Path) -> Settings:
    return make_settings(tmp_path, artifact_max_bytes=4096)


# ====================================================================== helpers


def pp(pid: str, suffix: str = "") -> str:
    return f"/api/v1/projects/{pid}{suffix}"


def add_member(api: Api, principal_id: str, pid: str, role: str) -> None:
    with write_session(api.app.state.engine) as ws:  # type: ignore[attr-defined]
        ws.add(Membership(principal_id=principal_id, project_id=pid, role=role))


def make_principal(api: Api, kind: str, name: str, *, projects: list[str] | None = None) -> tuple[str, str]:
    with write_session(api.app.state.engine) as ws:  # type: ignore[attr-defined]
        p = Principal(display_name=name, kind=kind, active=True, created_at=api.clock.now_ms())
        ws.add(p)
        ws.flush()
        for pid in projects if projects is not None else [api.project_id]:
            ws.add(Membership(principal_id=p.id, project_id=pid, role=kind))
        key, _ = issue_credential(ws, api.clock, p.id)
    return p.id, key.full_key


def new_project(api: Api, slug: str = "beta", *, agents: bool = True) -> str:
    """Second project; the existing test implementer/auditor become members (multi-project agents)."""
    r = api.req("owner", "POST", "/api/v1/projects", {"slug": slug, "name": slug.title()})
    assert r.status_code == 201, r.text
    pid = r.json()["id"]
    if agents:
        add_member(api, api.impl_id, pid, "implementer")
        add_member(api, api.aud_id, pid, "auditor")
        add_member(api, api.runner_id, pid, "runner")  # default supervisor (T12/F02: runs bind to a runner member)
    return pid


def task_in(api: Api, pid: str, *, who: Any = "owner", queued: bool = True, **over: Any) -> dict[str, Any]:
    r = api.req(who, "POST", pp(pid, "/tasks"), api.task_body(**over))
    assert r.status_code == 201, r.text
    t = r.json()
    if queued:
        r = api.req(who, "POST", pp(pid, f"/tasks/{t['id']}/enqueue"), if_match=t["version"])
        assert r.status_code == 200, r.text
        t = r.json()
    return t


def claim_any(api: Api, who: str = "impl", stage: str = "implement", *, expect: int | None = 200):
    r = api.req(who, "POST", "/api/v1/jobs/claim", {"stage": stage, "claim_request_id": uid(), "runner_instance_id": "r1"})
    if expect is not None:
        assert r.status_code == expect, r.text
    return r.json() if r.status_code == 200 else r


def start_in(api: Api, who: str, claim: dict[str, Any]) -> None:
    r = api.req(who, "POST", pp(claim["project_id"], f"/runs/{claim['run_id']}/start"), api.guard(claim))
    assert r.status_code == 200, r.text


def submit_impl_in(api: Api, claim: dict[str, Any], *, expect: int | None = 200, **over: Any):
    r = api.req(
        "impl", "POST", pp(claim["project_id"], f"/runs/{claim['run_id']}/implementation-result"),
        api.impl_payload(claim, **over),
    )
    if expect is not None:
        assert r.status_code == expect, r.text
    return r


def submit_audit_in(api: Api, claim: dict[str, Any], verdict: str, *, expect: int | None = 200, **over: Any):
    r = api.req(
        "aud", "POST", pp(claim["project_id"], f"/runs/{claim['run_id']}/audit-result"),
        api.audit_payload(claim, verdict, **over),
    )
    if expect is not None:
        assert r.status_code == expect, r.text
    return r


def delegation_in(api: Api, pid: str, cid: str, *, valid_for: timedelta = timedelta(hours=1), **ceiling: Any) -> dict[str, Any]:
    ceil = {"allowed_paths": ["src/**"], "max_changed_files": 5, "max_diff_lines": 200, **ceiling}
    until = datetime.fromtimestamp(api.clock.now_ms() / 1000, tz=UTC) + valid_for
    r = api.req(
        "owner", "POST", pp(pid, "/delegations"),
        {"coordinator_id": cid, "allowed_actions": ["task.create", "task.enqueue", "task.control"],
         "scope_ceiling": ceil, "valid_until": until.isoformat()},
    )
    assert r.status_code == 201, r.text
    return r.json()


def code(r) -> str:  # noqa: ANN001
    return r.json()["error"]["code"]


def project_version(api: Api, pid: str) -> int:
    return api.req("owner", "GET", pp(pid)).json()["version"]


def pause(api: Api, pid: str, *, resume: bool = False):
    r = api.req("owner", "POST", pp(pid, "/controls"), {"command": "resume" if resume else "pause", "reason": "t"})
    assert r.status_code in (200, 202), r.text
    return r


def put_policy(api: Api, pid: str, policy: dict[str, Any], *, who: Any = "owner", expect: int | None = 200):
    v = project_version(api, pid)
    r = api.req(who, "PUT", pp(pid, "/policy"), {"policy": policy, "reason": "test"}, if_match=v)
    if expect is not None:
        assert r.status_code == expect, r.text
    return r


def reauth(api: Api, password: str = OWNER_PASSWORD):
    return api.req("owner", "POST", "/api/v1/auth/reauth", {"password": password})


def appr_body(**over: Any) -> dict[str, Any]:
    body: dict[str, Any] = {
        "kind": "publish",
        "summary": "publish v1 to the package index",
        "action": {"destination": "pypi:nozo-agent-relay", "commit_digest": SHA_A, "max_cost_cents": 0},
        "expires_in_seconds": 3600,
    }
    body.update(over)
    return body


def request_approval(api: Api, pid: str | None = None, *, who: Any = "impl", expect: int = 201, **over: Any):
    r = api.req(who, "POST", pp(pid or api.project_id, "/approval-requests"), appr_body(**over))
    assert r.status_code == expect, r.text
    return r.json() if expect == 201 else r


def decide(api: Api, pid: str, approval: dict[str, Any], decision: str = "approve", *, digest: str | None = None, who: Any = "owner"):
    return api.req(
        who, "POST", pp(pid, f"/approval-requests/{approval['id']}/decision"),
        {"decision": decision, "action_digest": digest or approval["action_digest"], "reason": "ok"},
    )


def run_to_audit_fail(api: Api, variant: str, n: int) -> None:
    c = api.claim("impl")
    api.start("impl", c)
    api.submit_impl(c, variant=variant)
    a = api.claim("aud", "audit")
    api.start("aud", a)
    api.submit_audit(a, "FAIL", findings=[api.finding(n)], checks=[{"id": "c1", "command_label": "pytest", "status": "fail"}])


# ====================================================================== multi-project: memberships, queues, pause scopes


def test_projects_have_independent_memberships_and_lists(api: Api):
    b = new_project(api, "beta", agents=False)
    lone_id, lone_key = make_principal(api, "implementer", "lone", projects=[b])
    lone = api.client_for_key(lone_key)
    # a member of beta only: sees beta, never the default project
    assert [p["slug"] for p in api.req(lone, "GET", "/api/v1/projects").json()["items"]] == ["beta"]
    assert api.req(lone, "GET", api.p()).status_code == 404
    assert api.req(lone, "GET", pp(b)).status_code == 200
    # the shared agents see exactly the projects they were added to
    c = new_project(api, "gamma", agents=False)
    assert sorted(p["slug"] for p in api.req("impl", "GET", "/api/v1/projects").json()["items"]) == ["default"]
    assert api.req("impl", "GET", pp(c)).status_code == 404
    me = api.req(lone, "GET", "/api/v1/me").json()
    assert [m["project_id"] for m in me["memberships"]] == [b]


def test_queues_and_pause_scopes_are_independent(api: Api):
    b = new_project(api)
    ta = task_in(api, api.project_id, title="in A")
    tb = task_in(api, b, title="in B")
    pause(api, b)
    projects = {p["id"]: p for p in api.req("owner", "GET", "/api/v1/projects").json()["items"]}
    assert projects[api.project_id]["paused"] is False and projects[b]["paused"] is True
    # B's queue is closed, A's still serves its own job and nothing of B
    r = api.req("impl", "POST", pp(b, "/jobs/claim"), {"stage": "implement", "claim_request_id": uid(), "runner_instance_id": "r"})
    assert r.status_code == 409 and code(r) == "project_paused"
    c = claim_any(api)
    assert c["project_id"] == api.project_id and c["task_id"] == ta["id"]
    assert claim_any(api, expect=204).status_code == 204  # B is paused, A is drained
    # pausing B paused B's own queued task only; A's task was untouched (it is running in the lease above)
    assert api.req("owner", "GET", pp(b, f"/tasks/{tb['id']}")).json()["status"] == "paused"
    assert api.req("owner", "GET", pp(api.project_id, f"/tasks/{ta['id']}")).json()["status"] == "claimed"
    pause(api, b, resume=True)
    assert claim_any(api)["task_id"] == tb["id"]


def test_claim_in_one_project_never_returns_another_projects_job(api: Api):
    b = new_project(api)
    tb = task_in(api, b)
    r = api.req("impl", "POST", api.p("/jobs/claim"), {"stage": "implement", "claim_request_id": uid(), "runner_instance_id": "r"})
    assert r.status_code == 204  # default project queue is empty even though beta has work
    r = api.req("impl", "POST", pp(b, "/jobs/claim"), {"stage": "implement", "claim_request_id": uid(), "runner_instance_id": "r"})
    assert r.status_code == 200 and r.json()["task_id"] == tb["id"]


# ====================================================================== scheduling: tier + urgency + round-robin


def test_round_robin_across_projects_within_equal_tier_and_urgency(api: Api):
    b = new_project(api)
    ids: dict[str, str] = {}
    for pid, name in ((api.project_id, "a1"), (api.project_id, "a2"), (b, "b1"), (b, "b2")):
        ids[task_in(api, pid, title=name)["id"]] = name
        api.clock.advance(seconds=1)  # strict FIFO inside a project, A is OLDER than B
    order = [ids[claim_any(api)["task_id"]] for _ in range(4)]
    # plain FIFO would give a1,a2,b1,b2; round-robin alternates between the projects
    assert order == ["a1", "b1", "a2", "b2"]


def test_urgency_beats_round_robin(api: Api):
    b = new_project(api)
    # A was served most recently; B is "due" in round-robin terms
    task_in(api, api.project_id, title="a-first")
    claim_any(api)
    api.clock.advance(seconds=1)
    low_b = task_in(api, b, title="b-normal")
    high_a = task_in(api, api.project_id, title="a-high", urgency="high")
    assert claim_any(api)["task_id"] == high_a["id"]  # urgency first, even though A was served last
    assert claim_any(api)["task_id"] == low_b["id"]


def test_p1_autonomous_high_urgency_does_not_outrank_p0(api: Api):
    cid, ckey = make_principal(api, "coordinator", "coord")
    coord = api.client_for_key(ckey)
    d = delegation_in(api, api.project_id, cid, allow_autonomous=True)
    p1 = task_in(api, api.project_id, who=coord, urgency="high", autonomous=True, delegation_id=d["id"], title="p1")
    api.clock.advance(seconds=1)
    p0 = task_in(api, api.project_id, urgency="low", title="p0")
    assert [claim_any(api)["task_id"] for _ in range(2)] == [p0["id"], p1["id"]]


def test_claim_any_requires_the_stage_role_and_is_idempotent(api: Api):
    b = new_project(api)
    task_in(api, b)
    assert claim_any(api, "aud", "implement", expect=403).status_code == 403
    assert claim_any(api, "impl", "audit", expect=403).status_code == 403
    key, rid = uid(), uid()
    body = {"stage": "implement", "claim_request_id": rid, "runner_instance_id": "r1"}
    r1 = api.req("impl", "POST", "/api/v1/jobs/claim", body, idem=key)
    r2 = api.req("impl", "POST", "/api/v1/jobs/claim", body, idem=uid())  # fresh key, same claim_request_id
    assert r1.status_code == r2.status_code == 200 and r1.json()["run_id"] == r2.json()["run_id"]
    assert api.count(Run) == 1


# ====================================================================== Q34: paused project / owner stop


def test_q34_high_priority_in_paused_project_never_starts_and_owner_stop_is_not_queued(api: Api):
    b = new_project(api)
    low_a = task_in(api, api.project_id, urgency="low")
    pause(api, b)
    hi_b = task_in(api, b, urgency="high")  # accepted, queued, but the project is paused
    assert claim_any(api)["task_id"] == low_a["id"]  # the paused project's high urgency job is not offered
    assert claim_any(api, expect=204).status_code == 204
    r = api.req("impl", "POST", pp(b, "/jobs/claim"), {"stage": "implement", "claim_request_id": uid(), "runner_instance_id": "r"})
    assert r.status_code == 409 and code(r) == "project_paused"
    assert api.req("owner", "GET", pp(b, f"/tasks/{hi_b['id']}")).json()["status"] == "queued"
    # flood the queue with high urgency work: the owner's emergency stop is synchronous, never queued behind it
    for i in range(5):
        task_in(api, api.project_id, urgency="high", title=f"flood{i}")
    r = api.req("owner", "POST", "/api/v1/controls/emergency-stop", {"reason": "panic"})
    assert r.status_code in (200, 202) and len(r.json()["projects"]) == 2
    assert all(p["paused"] for p in r.json()["projects"])
    assert claim_any(api, expect=204).status_code == 204  # every project is closed now


def test_paused_project_excludes_audit_claims_too(api: Api):
    b = new_project(api)
    task_in(api, b)
    c = claim_any(api)
    start_in(api, "impl", c)
    assert submit_impl_in(api, c).status_code == 200
    pause(api, b)
    assert claim_any(api, "aud", "audit", expect=204).status_code == 204
    pause(api, b, resume=True)
    assert claim_any(api, "aud", "audit")["project_id"] == b


# ====================================================================== delegations + ceilings + revoke


def test_delegation_ceiling_expiry_and_owner_only(api: Api):
    cid, ckey = make_principal(api, "coordinator", "coord")
    coord = api.client_for_key(ckey)
    d = delegation_in(api, api.project_id, cid)
    ok = api.req(coord, "POST", api.p("/tasks"), api.task_body(autonomous=False, delegation_id=d["id"]))
    assert ok.status_code == 201 and ok.json()["authority_tier"] == "P1"
    over = {"autonomous": False, "delegation_id": d["id"]}
    for scope in (
        {**SCOPE, "max_changed_files": 6},
        {**SCOPE, "max_diff_lines": 201},
        {**SCOPE, "allowed_paths": ["other/**"]},
        {**SCOPE, "allowed_paths": ["**"]},
        {**SCOPE, "allow_new_dependencies": True},
    ):
        r = api.req(coord, "POST", api.p("/tasks"), api.task_body(scope=scope, **over))
        assert r.status_code == 403, scope
    assert api.req(coord, "POST", api.p("/tasks"), api.task_body(autonomous=True, delegation_id=d["id"])).status_code == 403
    # a coordinator can neither mint delegations nor widen its own ceiling
    body = {"coordinator_id": cid, "allowed_actions": ["task.create"], "valid_until": "2099-01-01T00:00:00+00:00",
            "scope_ceiling": {"allowed_paths": ["**"], "max_changed_files": 99, "max_diff_lines": 9999}}
    assert api.req(coord, "POST", api.p("/delegations"), body).status_code == 403
    assert api.req("impl", "POST", api.p("/delegations"), body).status_code == 403
    api.clock.advance(seconds=3601)  # expiry kills the authority
    assert api.req(coord, "POST", api.p("/tasks"), api.task_body(autonomous=False, delegation_id=d["id"])).status_code == 403


def test_revoke_delegation_is_owner_only_immediate_and_idempotent(api: Api):
    cid, ckey = make_principal(api, "coordinator", "coord")
    coord = api.client_for_key(ckey)
    d = delegation_in(api, api.project_id, cid)
    draft = api.req(coord, "POST", api.p("/tasks"), api.task_body(autonomous=False, delegation_id=d["id"])).json()
    revoke = api.p(f"/delegations/{d['id']}/revoke")
    for who in (coord, "impl", "aud"):
        assert api.req(who, "POST", revoke, {"reason": "x"}).status_code == 403
    r = api.req("owner", "POST", revoke, {"reason": "compromised"})
    assert r.status_code == 200 and r.json()["revoked"] is True and r.json()["revoked_at"]
    # takes effect on the very next request: create, enqueue and control all die
    assert api.req(coord, "POST", api.p("/tasks"), api.task_body(autonomous=False, delegation_id=d["id"])).status_code == 403
    assert api.req(coord, "POST", api.p(f"/tasks/{draft['id']}/enqueue"), if_match=draft["version"]).status_code == 403
    t = api.get_task(draft["id"])
    assert api.req(coord, "POST", api.p(f"/tasks/{draft['id']}/controls"), {"command": "pause", "reason": "x"}, if_match=t["version"]).status_code == 403
    # the owner still drives that task
    assert api.req("owner", "POST", api.p(f"/tasks/{draft['id']}/enqueue"), if_match=draft["version"]).status_code == 200
    # idempotent: second revoke is a no-op (one event)
    assert api.req("owner", "POST", revoke, {"reason": "again"}).status_code == 200
    assert len([e for e in api.events() if e["type"] == "delegation.revoked"]) == 1
    assert api.req("owner", "GET", api.p("/delegations")).json()["items"][0]["revoked"] is True
    assert api.req("owner", "POST", api.p(f"/delegations/{uid()}/revoke"), {"reason": "x"}).status_code == 404


def test_delegation_cannot_exceed_project_policy_ceiling(api: Api):
    cid, _ = make_principal(api, "coordinator", "coord")
    put_policy(api, api.project_id, {"scope_ceiling": {"allowed_paths": ["src/**"], "max_changed_files": 3, "max_diff_lines": 100}})
    until = (datetime.fromtimestamp(api.clock.now_ms() / 1000, tz=UTC) + timedelta(hours=1)).isoformat()
    wide = {"coordinator_id": cid, "allowed_actions": ["task.create"], "valid_until": until,
            "scope_ceiling": {"allowed_paths": ["src/**"], "max_changed_files": 4, "max_diff_lines": 100}}
    r = api.req("owner", "POST", api.p("/delegations"), wide)
    assert r.status_code == 422 and code(r) == "policy_violation"
    wide["scope_ceiling"]["max_changed_files"] = 3
    assert api.req("owner", "POST", api.p("/delegations"), wide).status_code == 201


def test_delegation_of_project_a_is_useless_in_project_b(api: Api):
    b = new_project(api)
    cid, ckey = make_principal(api, "coordinator", "coord", projects=[api.project_id, b])
    coord = api.client_for_key(ckey)
    d = delegation_in(api, api.project_id, cid)
    r = api.req(coord, "POST", pp(b, "/tasks"), api.task_body(autonomous=False, delegation_id=d["id"]))
    assert r.status_code == 403  # valid in A, not in B
    assert api.req("owner", "POST", pp(b, f"/delegations/{d['id']}/revoke"), {"reason": "x"}).status_code == 404


# ====================================================================== policy: owner-only, failure budget, racing with claim


def test_policy_changing_endpoints_are_owner_only(api: Api):
    cid, ckey = make_principal(api, "coordinator", "coord")
    coord = api.client_for_key(ckey)
    v = project_version(api, api.project_id)
    until = "2099-01-01T00:00:00+00:00"
    d = delegation_in(api, api.project_id, cid)
    approval = request_approval(api)
    calls = [
        ("PUT", api.p("/policy"), {"policy": {}, "reason": "x"}, v),
        ("PATCH", api.p(), {"paused": True}, v),
        ("POST", api.p("/controls"), {"command": "pause", "reason": "x"}, None),
        ("POST", api.p("/delegations"), {"coordinator_id": cid, "allowed_actions": ["task.create"], "valid_until": until,
                                         "scope_ceiling": {"allowed_paths": ["src/**"], "max_changed_files": 1, "max_diff_lines": 1}}, None),
        ("POST", api.p(f"/delegations/{d['id']}/revoke"), {"reason": "x"}, None),
        ("POST", api.p(f"/approval-requests/{approval['id']}/decision"), {"decision": "approve", "action_digest": approval["action_digest"]}, None),
        ("POST", api.p(f"/approval-requests/{approval['id']}/execute"), {"action_digest": approval["action_digest"]}, None),
        ("POST", "/api/v1/controls/emergency-stop", {"reason": "x"}, None),
        ("POST", "/api/v1/agents", {"display_name": "x", "kind": "implementer", "project_ids": [api.project_id]}, None),
        ("POST", "/api/v1/projects", {"slug": "evil", "name": "Evil"}, None),
    ]
    for who in (coord, "impl", "aud"):
        for method, path, body, ifm in calls:
            r = api.req(who, method, path, body, if_match=ifm)
            assert r.status_code == 403, (method, path, r.status_code, r.text)
    assert api.req("owner", "GET", api.p("/policy")).json()["policy_revision"] == 1  # nothing changed
    assert api.req(coord, "GET", api.p("/delegations")).status_code == 403


def test_policy_failure_budget_scope_ceiling_and_autonomy(api: Api):
    r = put_policy(api, api.project_id, {"max_failed_reviews_cap": 2, "allow_autonomous": False,
                                         "scope_ceiling": {"allowed_paths": ["src/**"], "max_changed_files": 5, "max_diff_lines": 200}})
    assert r.json()["policy_revision"] == 2
    bad = api.req("owner", "POST", api.p("/tasks"), api.task_body(autonomous=False, max_failed_reviews=3))
    assert bad.status_code == 422 and code(bad) == "policy_violation"
    assert api.req("owner", "POST", api.p("/tasks"), api.task_body(autonomous=True, max_failed_reviews=2)).status_code == 422
    wide = api.req("owner", "POST", api.p("/tasks"), api.task_body(autonomous=False, max_failed_reviews=2, scope={**SCOPE, "max_changed_files": 6}))
    assert wide.status_code == 422 and code(wide) == "policy_violation"  # the owner is bound by the project ceiling too
    assert api.req("owner", "POST", api.p("/tasks"), api.task_body(autonomous=False, max_failed_reviews=2)).status_code == 201
    # a no-op update is not a new policy revision
    put_policy(api, api.project_id, {"max_failed_reviews_cap": 2, "allow_autonomous": False,
                                     "scope_ceiling": {"allowed_paths": ["src/**"], "max_changed_files": 5, "max_diff_lines": 200}})
    assert api.req("owner", "GET", api.p("/policy")).json()["policy_revision"] == 2
    # stale If-Match -> 412, unknown fields -> 422
    assert api.req("owner", "PUT", api.p("/policy"), {"policy": {}, "reason": "x"}, if_match=1).status_code == 412
    assert put_policy(api, api.project_id, {"bogus": 1}, expect=422).status_code == 422


def test_policy_change_makes_queued_work_stale_until_the_owner_revises(api: Api):
    t = api.queued_task()
    put_policy(api, api.project_id, {"max_failed_reviews_cap": 2})
    r = api.req("impl", "POST", api.p("/jobs/claim"), {"stage": "implement", "claim_request_id": uid(), "runner_instance_id": "r"})
    assert r.status_code == 409 and code(r) == "policy_stale" and t["id"] in r.json()["error"]["details"]["task_ids"]
    assert claim_any(api, expect=409).status_code == 409
    api.control(t["id"], "revise", expect=200, revision={"acceptance": ["still fine"]})
    c = claim_any(api)  # the new revision carries the new policy digest
    assert c["task_id"] == t["id"] and c["revision"] == 2


def test_policy_update_racing_with_claim_is_serialised(api: Api):
    """BEGIN IMMEDIATE: either the claim saw the old policy (and its lease is internally consistent)
    or the policy was already new (409 policy_stale). Never a lease on a stale digest."""
    outcomes: set[str] = set()
    for i in range(4):
        t = api.queued_task(title=f"race{i}")
        v = project_version(api, api.project_id)
        pol = {"runtime_retry_limit": i + 1}
        owner = api.owner_client()
        impl = api.client_for_key(api.keys["impl"])
        barrier = threading.Barrier(2)

        def do_put() -> Any:
            barrier.wait()
            return api.req(owner, "PUT", api.p("/policy"), {"policy": pol, "reason": "race"}, if_match=v,
                           headers={"X-CSRF-Token": api.csrf})

        def do_claim() -> Any:
            barrier.wait()
            return api.req(impl, "POST", api.p("/jobs/claim"), {"stage": "implement", "claim_request_id": uid(), "runner_instance_id": "r"})

        with concurrent.futures.ThreadPoolExecutor(2) as pool:
            fp, fc = pool.submit(do_put), pool.submit(do_claim)
            rp, rc = fp.result(), fc.result()
        assert rp.status_code == 200, rp.text
        assert rc.status_code in (200, 409), rc.text
        if rc.status_code == 200:
            outcomes.add("claimed_before")
            with api.db() as s:
                run = s.get(Run, rc.json()["run_id"])
                assert run is not None and run.policy_digest == rc.json()["policy_digest"]
            # the lease is only an old-policy lease: a new revision under the new policy is required next time
        else:
            outcomes.add("stale_after")
            assert code(rc) == "policy_stale"
            api.control(t["id"], "revise", expect=200, revision={"acceptance": [f"ok{i}"]})
        # drain this task's lease/job so the next round starts clean
        with write_session(api.app.state.engine) as ws:  # type: ignore[attr-defined]
            ws.execute(text("UPDATE jobs SET status='cancelled' WHERE status IN ('ready','leased')"))
            ws.execute(text("UPDATE runs SET status='cancelled' WHERE status IN ('leased','running','stopping')"))
    assert outcomes  # at least one valid interleaving was exercised


def test_project_runtime_retry_limit_comes_from_policy(api: Api):
    put_policy(api, api.project_id, {"runtime_retry_limit": 0})
    api.queued_task()
    c = api.claim("impl")
    api.start("impl", c)
    r = api.req("impl", "POST", api.p(f"/runs/{c['run_id']}/fail"), {**api.guard(c), "error_code": "crash", "retryable": True})
    assert r.status_code == 200 and r.json()["outcome"] == "blocked"  # default server limit would retry


# ====================================================================== Q14: cross-project isolation


def _a_state(api: Api) -> dict[str, str]:
    """Resources that live in the default project A (task/job/run/snapshot/report/artifact/approval/control/message)."""
    t_manual = api.queued_task(autonomous=False, title="manual")
    job_id = [j for j in api.jobs(t_manual["id"])][0].id
    t = api.queued_task(title="auto")
    c = api.claim("impl")
    api.start("impl", c)
    up = api.client_for_key(api.keys["impl"]).post(
        api.p("/artifacts"), content=b"evidence-A", headers={"Idempotency-Key": uid(), "X-Run-Id": c["run_id"]}
    )
    assert up.status_code == 201, up.text
    api.submit_impl(c, artifacts=[up.json()["id"]])
    task = api.get_task(t["id"])
    msg = api.req("impl", "POST", api.p("/messages"), {"client_message_id": "m1", "kind": "note", "body": "hello A", "task_id": t["id"]})
    assert msg.status_code == 201
    ctl = api.control(t_manual["id"], "pause", expect=200)
    approval = request_approval(api, task_id=t["id"])
    cid, _ = make_principal(api, "coordinator", "coord")
    d = delegation_in(api, api.project_id, cid)
    return {
        "task": t["id"], "manual_task": t_manual["id"], "job": job_id, "run": c["run_id"],
        "snapshot": task["current_snapshot_id"], "report": task["latest_report_id"], "artifact": up.json()["id"],
        "approval": approval["id"], "control": ctl.json()["control"]["id"],
        "message": msg.json()["id"], "delegation": d["id"], "approval_digest": approval["action_digest"],
    }


def test_q14_other_projects_ids_are_404_for_members_of_both_via_wrong_path(api: Api):
    b = new_project(api)
    s = _a_state(api)
    gets = [
        f"/tasks/{s['task']}", f"/tasks/{s['task']}/messages", f"/reports/{s['report']}",
        f"/snapshots/{s['snapshot']}", f"/artifacts/{s['artifact']}", f"/approval-requests/{s['approval']}",
        f"/controls/{s['control']}",
    ]
    for who in ("owner", "impl", "aud"):
        for suffix in gets:
            r = api.req(who, "GET", pp(b, suffix))
            assert r.status_code == 404, (who, suffix, r.status_code)
            assert s["task"] not in r.text and "evidence-A" not in r.text
    posts = [
        (f"/tasks/{s['manual_task']}/enqueue", None, {}),
        (f"/tasks/{s['manual_task']}/controls", {"command": "pause", "reason": "x"}, {"if_match": 1}),
        (f"/jobs/{s['job']}/dispatch", {"expected_task_version": 1}, {}),
        (f"/delegations/{s['delegation']}/revoke", {"reason": "x"}, {}),
        (f"/approval-requests/{s['approval']}/decision", {"decision": "approve", "action_digest": s["approval_digest"]}, {}),
        (f"/approval-requests/{s['approval']}/execute", {"action_digest": s["approval_digest"]}, {}),
    ]
    for suffix, body, kw in posts:
        r = api.req("owner", "POST", pp(b, suffix), body, **kw)
        assert r.status_code in (404, 428), (suffix, r.status_code, r.text)
    with api.db() as db:
        row = db.get(ApprovalRequest, s["approval"])
        assert row is not None and row.status == "pending"
    # runs of A are invisible through B for the principals that own them
    r = api.req("impl", "POST", pp(b, f"/runs/{s['run']}/heartbeat"), {"lease_epoch": 1, "revision": 1, "policy_digest": SHA_A})
    assert r.status_code == 404
    # a message in B cannot hang on A's task, and reply_to cannot reach into A
    r = api.req("impl", "POST", pp(b, "/messages"), {"client_message_id": "x1", "kind": "note", "body": "x", "task_id": s["task"]})
    assert r.status_code == 404
    r = api.req("impl", "POST", pp(b, "/messages"), {"client_message_id": "x2", "kind": "note", "body": "x", "reply_to": s["message"]})
    assert r.status_code == 422
    assert api.count(Message, Message.project_id == b) == 0
    # artifact uploads in B cannot bind A's task or run
    c = api.client_for_key(api.keys["impl"])
    for hdr in ({"X-Task-Id": s["task"]}, {"X-Run-Id": s["run"]}):
        r = c.post(pp(b, "/artifacts"), content=b"x", headers={"Idempotency-Key": uid(), **hdr})
        assert r.status_code == 404, hdr
    assert api.count(Artifact, Artifact.project_id == b) == 0
    # B's event log and snapshot never mention A
    ev = api.req("owner", "GET", pp(b, "/events")).json()["events"]
    assert all(e["project_id"] == b for e in ev) and s["task"] not in json.dumps(ev)
    assert s["task"] not in json.dumps(api.req("owner", "GET", pp(b, "/snapshot")).json())


def test_q14_non_member_gets_404_everywhere_and_ws_is_refused(api: Api):
    b = new_project(api)
    s = _a_state(api)
    tb = task_in(api, b, title="B secret")
    _, key = make_principal(api, "implementer", "intruder", projects=[b])
    intruder = api.client_for_key(key)
    # every REST path of project A answers 404 (not 403): no existence oracle
    for method, suffix in (
        ("GET", ""), ("GET", "/tasks"), ("GET", f"/tasks/{s['task']}"), ("GET", "/events"), ("GET", "/snapshot"),
        ("GET", f"/reports/{s['report']}"), ("GET", f"/snapshots/{s['snapshot']}"), ("GET", f"/artifacts/{s['artifact']}"),
        ("GET", "/approval-requests"), ("GET", f"/approval-requests/{s['approval']}"), ("GET", "/messages"),
        ("GET", "/policy"), ("GET", "/delegations"),
    ):
        assert api.req(intruder, method, api.p(suffix)).status_code == 404, suffix
    for suffix, body in (
        ("/jobs/claim", {"stage": "implement", "claim_request_id": uid(), "runner_instance_id": "r"}),
        ("/messages", {"client_message_id": "i1", "kind": "note", "body": "x"}),
        ("/approval-requests", appr_body()),
        ("/tasks", api.task_body()),
        ("/controls", {"command": "pause", "reason": "x"}),
    ):
        assert api.req(intruder, "POST", api.p(suffix), body).status_code == 404, suffix
    assert api.req(intruder, "POST", api.p("/artifacts"), None).status_code in (404, 422)
    assert api.count(Artifact) == 1
    # cross-project claim never offers A's work to someone who is only in B
    got = api.req(intruder, "POST", "/api/v1/jobs/claim", {"stage": "implement", "claim_request_id": uid(), "runner_instance_id": "r"})
    assert got.status_code == 204  # A's jobs are not its to see, B's job is assigned to someone else
    assert api.req("owner", "GET", pp(b, f"/tasks/{tb['id']}")).json()["status"] == "queued"
    # WebSocket of project A: refused before accept
    base = str(intruder.base_url).replace("http://", "ws://").rstrip("/")
    with pytest.raises(Rejected):
        with intruder.websocket_connect(base + f"/ws/v1/projects/{api.project_id}?after_seq=0"):
            pass
    ok = api.clients["owner"]
    with pytest.raises(Rejected):  # unknown project id behaves identically
        with ok.websocket_connect(base + f"/ws/v1/projects/{uid()}?after_seq=0", headers={"Origin": ORIGIN}):
            pass


def test_q14_artifact_or_snapshot_of_another_project_cannot_be_used_as_evidence(api: Api):
    b = new_project(api)
    up = api.client_for_key(api.keys["impl"]).post(api.p("/artifacts"), content=b"A-only", headers={"Idempotency-Key": uid()})
    assert up.status_code == 201
    task_in(api, b)
    c = claim_any(api)
    assert c["project_id"] == b
    start_in(api, "impl", c)
    r = submit_impl_in(api, c, expect=None, artifacts=[up.json()["id"]])
    assert r.status_code == 422 and code(r) == "unknown_artifact"
    r = submit_impl_in(api, c, expect=None, checks=[{"id": "u", "command_label": "pytest", "status": "pass", "evidence_artifact_ids": [up.json()["id"]]}])
    assert r.status_code == 422
    assert api.count(Snapshot, Snapshot.project_id == b) == 0 and api.count(Report) == 0
    # and a foreign snapshot id cannot be audited under another project's job
    a_task = api.queued_task()
    ca = api.claim("impl")
    api.start("impl", ca)
    api.submit_impl(ca)
    snap_a = api.get_task(a_task["id"])["current_snapshot_id"]
    assert submit_impl_in(api, c, variant="ok").status_code == 200
    ab = claim_any(api, "aud", "audit")
    assert ab["project_id"] == b
    start_in(api, "aud", ab)
    r = submit_audit_in(api, ab, "PASS", expect=None, snapshot_id=snap_a)
    assert r.status_code == 409 and code(r) == "snapshot_mismatch"


# ====================================================================== artifacts


def _upload(api: Api, who: str, data: bytes, pid: str | None = None, **headers: str):
    return api.client_for_key(api.keys[who]).post(
        pp(pid or api.project_id, "/artifacts"), content=data, headers={"Idempotency-Key": uid(), **headers}
    )


def test_artifact_roundtrip_is_server_named_integrity_checked_and_always_an_attachment(api: Api, env: Env):
    html = b"<html><script>alert(1)</script></html>"
    r = _upload(api, "impl", html, **{"Content-Type": "text/html"})
    assert r.status_code == 201
    art = r.json()
    assert set(art) == {"id", "project_id", "task_id", "run_id", "sha256", "size_bytes", "media_type", "created_at"}
    assert art["media_type"] == "text/plain" and art["size_bytes"] == len(html)  # sniffed, not client-declared
    assert "path" not in json.dumps(art) and "storage" not in json.dumps(art)
    for who in ("impl", "aud", "owner"):
        d = api.req(who, "GET", api.p(f"/artifacts/{art['id']}"))
        assert d.status_code == 200 and d.content == html
        assert d.headers["content-type"] == "application/octet-stream"
        assert d.headers["content-disposition"].startswith("attachment;")
        assert d.headers["x-content-type-options"] == "nosniff" and d.headers["x-artifact-sha256"] == art["sha256"]
    # stored under a server-chosen key, private permissions
    stored = env.settings.artifacts_dir / art["id"][:2] / art["id"]
    assert stored.read_bytes() == html and stat.S_IMODE(stored.stat().st_mode) == 0o600
    assert stat.S_IMODE(env.settings.artifacts_dir.stat().st_mode) == 0o700
    # integrity: tampered bytes are never served
    stored.write_bytes(b"tampered")
    bad = api.req("owner", "GET", api.p(f"/artifacts/{art['id']}"))
    assert bad.status_code == 500 and code(bad) == "artifact_corrupt"
    # a symlink swapped in for the file is refused, not followed
    stored.unlink()
    target = env.settings.data_dir / "outside.txt"
    target.write_bytes(html)
    stored.symlink_to(target)
    assert api.req("owner", "GET", api.p(f"/artifacts/{art['id']}")).status_code == 500


def test_artifact_limits_idempotency_and_validation(api: Api):
    r = _upload(api, "impl", b"x" * 4097)
    assert r.status_code == 413  # artifact_max_bytes=4096 in this module
    assert _upload(api, "impl", b"").status_code == 422
    assert _upload(api, "impl", b"x", **{"X-Task-Id": "../../etc/passwd"}).status_code == 422
    assert api.client_for_key(api.keys["impl"]).post(api.p("/artifacts"), content=b"x").status_code == 428  # no key
    key = uid()
    c = api.client_for_key(api.keys["impl"])
    r1 = c.post(api.p("/artifacts"), content=b"same", headers={"Idempotency-Key": key})
    r2 = c.post(api.p("/artifacts"), content=b"same", headers={"Idempotency-Key": key})
    assert r1.status_code == r2.status_code == 201 and r1.json() == r2.json() and api.count(Artifact) == 1
    r3 = c.post(api.p("/artifacts"), content=b"other", headers={"Idempotency-Key": key})
    assert r3.status_code == 409
    anon = api.env.client()
    assert anon.post(api.p("/artifacts"), content=b"x", headers={"Idempotency-Key": uid()}).status_code == 401
    assert anon.get(api.p(f"/artifacts/{r1.json()['id']}")).status_code == 401
    # run binding: only the run's own principal (or the owner) may attach to it
    t = api.queued_task()
    cl = api.claim("impl")
    ok = _upload(api, "impl", b"log", **{"X-Run-Id": cl["run_id"], "X-Task-Id": t["id"]})
    assert ok.status_code == 201 and ok.json()["run_id"] == cl["run_id"]
    assert _upload(api, "aud", b"log", **{"X-Run-Id": cl["run_id"]}).status_code == 404


# ====================================================================== Q25: surgical exits (fixture level)


QUARANTINE_CASES: list[tuple[str, dict[str, Any], str]] = [
    ("rename out of scope", {"changed_files": [{"path": "src/a.py", "change": "renamed", "renamed_from": "etc/passwd"}], "diff_lines": 1}, "path_not_allowed"),
    ("rename into protected path", {"changed_files": [{"path": "src/secret/k.py", "change": "renamed", "renamed_from": "src/a.py"}], "diff_lines": 1}, "path_not_allowed"),
    ("rename without source", {"changed_files": [{"path": "src/a.py", "change": "renamed"}], "diff_lines": 1}, "rename_without_source"),
    ("symlink", {"changed_files": [{"path": "src/link", "change": "added", "symlink": True}], "diff_lines": 1}, "symlink"),
    ("binary in surgical", {"changed_files": [{"path": "src/a.bin", "change": "added", "binary": True}], "diff_lines": 1}, "binary_in_surgical"),
    ("new file outside", {"changed_files": [{"path": "docs/new.md", "change": "added"}], "diff_lines": 1}, "path_not_allowed"),
    ("deleted file outside", {"changed_files": [{"path": "config/prod.yaml", "change": "deleted"}], "diff_lines": 1}, "path_not_allowed"),
    ("deleted protected file", {"changed_files": [{"path": ".env.local", "change": "deleted"}], "diff_lines": 1}, "path_not_allowed"),
    ("git hook", {"changed_files": [{"path": "src/.git/hooks/pre-commit", "change": "added"}], "diff_lines": 1}, "git_internal"),
    ("git config upper case", {"changed_files": [{"path": ".GIT/config", "change": "modified"}], "diff_lines": 1}, "git_internal"),
    ("deny wins case-insensitively", {"changed_files": [{"path": "src/Secret/key.py", "change": "modified"}], "diff_lines": 1}, "path_not_allowed"),
    ("non-canonical path", {"changed_files": [{"path": "src/./a.py", "change": "modified"}], "diff_lines": 1}, "path_not_canonical"),
    ("double slash", {"changed_files": [{"path": "src//a.py", "change": "modified"}], "diff_lines": 1}, "path_not_canonical"),
    ("permission change", {"changed_files": [{"path": "src/run.sh", "change": "modified", "mode_changed": True}], "diff_lines": 1}, "permission_change"),
    ("too many files", {"changed_files": [{"path": f"src/f{i}.py", "change": "added"} for i in range(6)], "diff_lines": 1}, "too_many_files"),
    ("diff budget", {"changed_files": [{"path": "src/a.py", "change": "modified"}], "diff_lines": 201}, "diff_too_large"),
    ("new dependency", {"changed_files": [{"path": "src/a.py", "change": "modified"}], "diff_lines": 1, "new_dependencies": ["left-pad"]}, "new_dependency"),
    ("mixed: one bad path poisons the rest", {"changed_files": [{"path": "src/ok.py", "change": "modified"}, {"path": "../x", "change": "added"}], "diff_lines": 1}, "422"),
]


def test_q25_every_surgical_exit_is_quarantined_and_leaves_no_trace(api: Api):
    for label, manifest, kind in QUARANTINE_CASES:
        t = api.queued_task(title=label)
        c = api.claim("impl")
        api.start("impl", c)
        r = api.submit_impl(c, expect=None, scope_manifest=manifest)
        if kind == "422":  # structurally invalid: rejected at the door, run stays active and nothing is stored
            assert r.status_code == 422, label
            api.req("impl", "POST", api.p(f"/runs/{c['run_id']}/fail"), {**api.guard(c), "error_code": "x", "retryable": False})
            continue
        assert r.status_code == 409 and code(r) == "scope_violation", (label, r.text)
        kinds = {v["kind"] for v in r.json()["error"]["details"]["violations"]}
        assert kind in kinds, (label, kinds)
        task = api.get_task(t["id"])
        assert (task["status"], task["blocked_reason"]) == ("blocked", "scope_change_required"), label
        assert task["latest_report_id"] is None and task["current_snapshot_id"] is None, label
    # nothing was accepted anywhere: no snapshot/report/audit job; every run failed; the repo (relay data) is untouched
    assert api.count(Snapshot) == 0 and api.count(Report) == 0
    assert api.claim("aud", "audit", expect=204).status_code == 204
    quarantined = [e for e in api.events() if e["type"] == "run.quarantined"]
    assert len(quarantined) == len(QUARANTINE_CASES) - 1
    # control: a clean manifest of the same shape IS accepted (the checks are not just rejecting everything)
    t = api.queued_task(title="clean")
    c = api.claim("impl")
    api.start("impl", c)
    ok = api.submit_impl(c, scope_manifest={"changed_files": [
        {"path": "src/app.py", "change": "modified"}, {"path": "src/new.py", "change": "added"},
        {"path": "src/old.py", "change": "renamed", "renamed_from": "src/older.py"}], "diff_lines": 10})
    assert ok.status_code == 200 and api.get_task(t["id"])["status"] == "awaiting_review"


def test_q25_creative_mode_allows_binary_but_never_symlinks_or_git_internals(api: Api):
    t = api.queued_task(mode="creative", title="creative")
    c = api.claim("impl")
    api.start("impl", c)
    bad = api.submit_impl(c, expect=None, scope_manifest={"changed_files": [{"path": "src/.git/config", "change": "added"}], "diff_lines": 1})
    assert bad.status_code == 409 and api.get_task(t["id"])["blocked_reason"] == "scope_change_required"
    t2 = api.queued_task(mode="creative", title="creative2")
    c2 = api.claim("impl")
    api.start("impl", c2)
    ok = api.submit_impl(c2, scope_manifest={"changed_files": [{"path": "src/logo.png", "change": "added", "binary": True}], "diff_lines": 1})
    assert ok.status_code == 200 and api.get_task(t2["id"])["status"] == "awaiting_review"


# ====================================================================== Q13: loops


def test_q13_aba_blocks_with_evidence_and_does_not_fire_for_distinct_states(api: Api):
    t = api.queued_task()
    for n, v in enumerate(("A", "B", "A"), start=1):
        run_to_audit_fail(api, v, n)
    task = api.get_task(t["id"])
    assert (task["status"], task["blocked_reason"]) == ("blocked", "loop_detected")
    ev = [e for e in api.events() if e["data"].get("blocked_reason") == "loop_detected"][0]["data"]
    assert ev["loop"]["rule"] == "state_cycle_aba" and len(ev["loop"]["signatures"]) == 3
    assert ev["recommended_action"] and api.claim("impl", expect=204).status_code == 204  # no more work is issued
    # three DIFFERENT states + different invariants: plain iteration limit, not a loop
    t2 = api.queued_task(title="distinct")
    for n, v in enumerate(("X", "Y", "Z"), start=1):
        run_to_audit_fail(api, v, n + 10)
    task2 = api.get_task(t2["id"])
    assert (task2["status"], task2["blocked_reason"]) == ("blocked", "iteration_limit")


def test_q13_same_invariant_and_diff_twice_blocks_immediately(api: Api):
    t = api.queued_task()
    run_to_audit_fail(api, "same", 1)
    assert api.get_task(t["id"])["status"] == "changes_requested"
    run_to_audit_fail(api, "same", 1)  # identical code, identical blocking invariant
    task = api.get_task(t["id"])
    assert (task["status"], task["blocked_reason"]) == ("blocked", "loop_detected")
    ev = [e for e in api.events() if e["data"].get("blocked_reason") == "loop_detected"][0]["data"]
    assert ev["loop"]["rule"] == "same_invariant_same_diff" and ev["failed_review_count"] == 2
    # a revision cannot be used to bypass the loop block
    r = api.control(t["id"], "revise", expect=409, revision={"requirements": "try again"})
    assert code(r) == "budget_decision_required"


def test_q13_detector_unit_longer_cycles_and_no_false_positive():
    def r(inv: frozenset[str], tag: str) -> AuditRound:
        return AuditRound(inv, f"diff-{tag}", f"tree-{tag}")

    i1, i2, i3 = frozenset({"i1"}), frozenset({"i2"}), frozenset({"i3"})
    assert detect_loop([r(i1, "A"), r(i2, "B")], r(i3, "A")).rule == "state_cycle_aba"
    longer = detect_loop([r(i1, "A"), r(i2, "B"), r(i3, "C")], r(frozenset({"i4"}), "A"))
    assert longer is not None and longer.rule == "state_cycle_revisit" and longer.evidence["rounds_ago"] == 3
    assert detect_loop([r(i1, "A"), r(i2, "B"), r(i3, "C")], r(frozenset({"i4"}), "D")) is None
    assert detect_loop([], r(i1, "A")) is None
    assert detect_loop([r(i1, "A")], r(i2, "B")) is None


# ====================================================================== Q33: approval records


def test_q33_approval_flow_requires_recent_auth_session_and_exact_digest(api: Api):
    a = request_approval(api)
    assert a["status"] == "pending" and a["executor"] == "none" and a["requested_by"] == api.impl_id
    assert api.req("owner", "GET", api.p(f"/approval-requests/{a['id']}")).json()["status"] == "pending"
    # agents may ask, never decide
    for who in ("impl", "aud"):
        assert decide(api, api.project_id, a, who=who).status_code == 403
    # a stale password proof (> 5 min) cannot decide
    api.clock.advance(seconds=301)
    r = decide(api, api.project_id, a)
    assert r.status_code == 403 and code(r) == "recent_auth_required"
    assert reauth(api, "wrong password here").status_code == 401
    assert decide(api, api.project_id, a).status_code == 403  # a failed proof does not count
    assert reauth(api).status_code == 200
    # wrong digest -> denied, record untouched
    r = decide(api, api.project_id, a, digest=SHA_B)
    assert r.status_code == 409 and code(r) == "digest_mismatch"
    r = decide(api, api.project_id, a)
    assert r.status_code == 200 and r.json()["status"] == "approved" and r.json()["approved_by"] == api.owner_id
    # a second decision is not possible
    assert code(decide(api, api.project_id, a, "reject")) == "not_pending"
    assert [e["type"] for e in api.events() if e["type"].startswith("approval.")] == ["approval.requested", "approval.approved"]


def test_q33_decision_needs_a_browser_session_and_csrf(api: Api, env: Env):
    a = request_approval(api)
    # CSRF: a session cookie without the token is refused (cookie-only forgery)
    c = api.owner_client()
    r = c.post(api.p(f"/approval-requests/{a['id']}/decision"),
               json={"decision": "approve", "action_digest": a["action_digest"]}, headers={"Idempotency-Key": uid()})
    assert r.status_code == 403
    with api.db() as db:
        assert db.get(ApprovalRequest, a["id"]).status == "pending"  # type: ignore[union-attr]


def test_q33_expiry_denies_decision_and_consumption(api: Api):
    a = request_approval(api, expires_in_seconds=60)
    api.clock.advance(seconds=61)
    r = decide(api, api.project_id, a)
    assert r.status_code == 409 and code(r) == "approval_expired"
    assert api.req("owner", "GET", api.p(f"/approval-requests/{a['id']}")).json()["status"] == "expired"
    # approved, then it ages out before use
    b = request_approval(api, expires_in_seconds=120)
    assert decide(api, api.project_id, b).status_code == 200
    api.clock.advance(seconds=121)
    with write_session(api.app.state.engine) as ws:  # type: ignore[attr-defined]
        from nozo_relay.db.models import Project

        res = approvals_svc.consume(ws, api.clock, ws.get(Project, api.project_id), b["id"], b["action_digest"])
        assert not res.ok and res.reason == "approval_expired"
    with api.db() as db:
        row = db.get(ApprovalRequest, b["id"])
        assert row is not None and row.status == "expired" and row.use_count == 0


def test_q33_single_use_reuse_and_wrong_digest_are_denied(api: Api):
    from nozo_relay.db.models import Project

    a = request_approval(api)
    assert decide(api, api.project_id, a).status_code == 200
    with write_session(api.app.state.engine) as ws:  # type: ignore[attr-defined]
        project = ws.get(Project, api.project_id)
        assert not approvals_svc.consume(ws, api.clock, project, a["id"], SHA_B).ok  # other commit/digest
        first = approvals_svc.consume(ws, api.clock, project, a["id"], a["action_digest"])
        assert first.ok and first.request is not None and first.request.status == "used"
        again = approvals_svc.consume(ws, api.clock, project, a["id"], a["action_digest"])
        assert not again.ok and again.reason == "status_used"
        assert not approvals_svc.consume(ws, api.clock, project, uid(), a["action_digest"]).ok
    # pending and rejected records are never consumable
    p = request_approval(api, action={"destination": "pypi:x", "commit_digest": SHA_B})
    rej = request_approval(api, action={"destination": "pypi:y", "commit_digest": SHA_B})
    assert decide(api, api.project_id, rej, "reject").json()["status"] == "rejected"
    with write_session(api.app.state.engine) as ws:  # type: ignore[attr-defined]
        project = ws.get(Project, api.project_id)
        assert approvals_svc.consume(ws, api.clock, project, p["id"], p["action_digest"]).reason == "status_pending"
        assert approvals_svc.consume(ws, api.clock, project, rej["id"], rej["action_digest"]).reason == "status_rejected"


def test_q33_different_commit_means_a_different_digest(api: Api):
    a = request_approval(api, action={"destination": "pypi:nozo", "commit_digest": SHA_A})
    b = request_approval(api, action={"destination": "pypi:nozo", "commit_digest": SHA_B})
    c = request_approval(api, action={"destination": "pypi:other", "commit_digest": SHA_A})
    k = request_approval(api, kind="deploy", action={"destination": "pypi:nozo", "commit_digest": SHA_A})
    assert len({a["action_digest"], b["action_digest"], c["action_digest"], k["action_digest"]}) == 4
    assert decide(api, api.project_id, a, digest=b["action_digest"]).status_code == 409  # approving "B" with A's id
    for bad in (
        {"action": {"destination": "x"}},  # no commit/artifact digest
        {"kind": "rm -rf"},  # closed enum
        {"expires_in_seconds": 5},
        {"task_id": uid()},  # unknown task -> 404
    ):
        r = api.req("impl", "POST", api.p("/approval-requests"), appr_body(**bad))
        assert r.status_code in (404, 422), bad


def test_q33_task_binding_changes_make_the_record_stale(api: Api):
    t = api.queued_task(autonomous=False)
    a = request_approval(api, task_id=t["id"])
    b = request_approval(api, task_id=t["id"], action={"destination": "pypi:b", "commit_digest": SHA_B})
    assert decide(api, api.project_id, b).status_code == 200  # approved while the binding holds
    # a new task revision changes the bound object: pending cannot be approved, approved cannot be used
    api.control(t["id"], "revise", expect=200, revision={"requirements": "Changed goal."})
    r = decide(api, api.project_id, a)
    assert r.status_code == 409 and code(r) == "binding_changed"
    assert api.req("owner", "GET", api.p(f"/approval-requests/{a['id']}")).json()["status"] == "expired"
    from nozo_relay.db.models import Project

    with write_session(api.app.state.engine) as ws:  # type: ignore[attr-defined]
        res = approvals_svc.consume(ws, api.clock, ws.get(Project, api.project_id), b["id"], b["action_digest"])
        assert not res.ok and res.reason == "binding_changed"
    # policy revision changes bind too
    c = request_approval(api)
    put_policy(api, api.project_id, {"max_failed_reviews_cap": 2})
    assert code(decide(api, api.project_id, c)) == "binding_changed"


def test_q33_approved_record_has_no_executor_and_nothing_runs(api: Api):
    a = request_approval(api)
    assert api.req("owner", "POST", api.p(f"/approval-requests/{a['id']}/execute"), {"action_digest": a["action_digest"]}).status_code == 409  # not approved yet
    assert decide(api, api.project_id, a).status_code == 200
    before = api.count(Event)
    r = api.req("owner", "POST", api.p(f"/approval-requests/{a['id']}/execute"), {"action_digest": a["action_digest"]})
    assert r.status_code == 501 and code(r) == "no_executor"
    with api.db() as db:
        row = db.get(ApprovalRequest, a["id"])
        assert row is not None and row.status == "approved" and row.use_count == 0  # not even consumed
    assert api.count(Event) == before + 1
    assert api.events()[-1]["type"] == "approval.execution_denied"
    # structurally: no code path outside the approvals module touches publish/push, and no subprocess/network is imported there
    src = Path(approvals_svc.__file__).read_text()
    assert "subprocess" not in src and "socket" not in src and "httpx" not in src and "os.system" not in src
    assert api.req("impl", "POST", api.p(f"/approval-requests/{a['id']}/execute"), {"action_digest": a["action_digest"]}).status_code == 403


def test_q33_approval_isolation_limits_and_listing(api: Api, env: Env):
    b = new_project(api)
    a = request_approval(api)
    assert api.req("owner", "GET", pp(b, f"/approval-requests/{a['id']}")).status_code == 404
    assert decide(api, b, a).status_code == 404
    assert api.req("owner", "GET", pp(b, "/approval-requests")).json()["items"] == []
    assert [x["id"] for x in api.req("aud", "GET", api.p("/approval-requests?status=pending")).json()["items"]] == [a["id"]]
    assert api.req("owner", "GET", api.p("/approval-requests?status=bogus")).status_code == 422
    # secrets in a summary never reach the record
    s = request_approval(api, summary="deploy with token=SENTINEL_SECRET_abc123 now")
    assert "SENTINEL_SECRET" not in json.dumps(s)
    # pending cap
    cap = api.env.settings.approval_max_pending_per_project
    with write_session(api.app.state.engine) as ws:  # type: ignore[attr-defined]
        for i in range(cap):
            ws.add(ApprovalRequest(project_id=b, requested_by=api.impl_id, kind="push", action_digest=f"{i:064d}",
                                   scope_digest=SHA_A, status="pending", expires_at=api.clock.now_ms() + 10**6,
                                   created_at=api.clock.now_ms(), summary="x", action_json="{}"))
    r = api.req("impl", "POST", pp(b, "/approval-requests"), appr_body())
    assert r.status_code == 409 and code(r) == "too_many_pending"


# ====================================================================== sanitised logs


def test_logsafe_redacts_sentinels_keys_cookies_and_control_codes(caplog):
    key = "nzr_" + "0123456789abcdef" + "." + "A" * 43
    raw = (
        f"Authorization: Bearer {key}\nCookie: nozo_session=SESSIONVALUE; nozo_csrf=CSRFVALUE\n"
        f"password=hunter2hunter2 api_key: sk-live-1234567890abcdefghij SENTINEL_SECRET_xyz \x1b[31mred\x1b[0m\x00"
        "-----BEGIN PRIVATE KEY-----\nMIIBVgIBADANBg\n-----END PRIVATE KEY-----"
    )
    out = logsafe.redact(raw)
    for secret in (key, "SESSIONVALUE", "CSRFVALUE", "hunter2hunter2", "sk-live-1234567890abcdefghij", "SENTINEL_SECRET_xyz", "MIIBVgIBADANBg"):
        assert secret not in out, secret
    assert "\x1b" not in out and "\x00" not in out and logsafe.REDACTED in out
    assert logsafe.redact("my custom-sentinel-77 here", extra=["custom-sentinel-77"]) == f"my {logsafe.REDACTED} here"
    assert len(logsafe.redact("x" * 10_000)) < 2100  # bounded
    assert logsafe.redact("ordinary progress: 3 tests passed") == "ordinary progress: 3 tests passed"
    obj = logsafe.redact_obj({"ok": "fine", "password": "p", "nested": {"api_key": "k", "list": [f"Bearer {key}"]}})
    assert obj["password"] == logsafe.REDACTED and obj["nested"]["api_key"] == logsafe.REDACTED
    assert key not in json.dumps(obj) and obj["ok"] == "fine"
    # the installed record factory scrubs nozo_relay.* log records (also those of child loggers)
    logsafe.install()
    with caplog.at_level(logging.INFO):
        logging.getLogger("nozo_relay.t06.child").info("leaked %s and token=%s", key, "abc12345secret")
        logging.getLogger("other.lib").info("untouched %s", "token=visible")
    msgs = " | ".join(r.getMessage() for r in caplog.records)
    assert key not in msgs and "abc12345secret" not in msgs and "token=visible" in msgs


def test_run_failure_evidence_is_sanitised_before_it_reaches_the_event_log(api: Api):
    api.queued_task()
    c = api.claim("impl")
    api.start("impl", c)
    key = "nzr_" + "0123456789abcdef" + "." + "B" * 43
    r = api.req("impl", "POST", api.p(f"/runs/{c['run_id']}/fail"), {
        **api.guard(c), "error_code": "crash", "retryable": False,
        "evidence": f"stderr: Authorization: Bearer {key} password=SENTINEL_SECRET_pw\x1b[31m",
    })
    assert r.status_code == 200
    dump = json.dumps(api.events())
    assert key not in dump and "SENTINEL_SECRET_pw" not in dump and "\x1b" not in dump


# ====================================================================== retention


def test_retention_rules_nothing_is_auto_deleted_and_history_is_append_only(api: Api):
    assert RETENTION_RULES["events"]["rule"] == "keep_forever" and RETENTION_RULES["reports"]["rule"] == "keep_forever"
    assert RETENTION_RULES["backups"]["rule"] == "operator_managed" and RETENTION_RULES["projects"]["rule"] == "archive_only"
    assert not [k for k, v in RETENTION_RULES.items() if v["rule"] in ("ttl", "auto_delete")]
    api.queued_task()
    eng = api.app.state.engine  # type: ignore[attr-defined]
    for stmt in ("DELETE FROM events", "UPDATE events SET type='x'", "DELETE FROM task_revisions", "UPDATE task_revisions SET mode='creative'"):
        with pytest.raises(Exception, match="append-only"):
            with eng.begin() as conn:
                conn.exec_driver_sql(stmt)
    # the code base contains no deletion of retained history at all
    root = Path(approvals_svc.__file__).parents[1]
    offenders = [
        str(p.relative_to(root)) for p in root.rglob("*.py")
        if p.name != "models.py" and any(tok in p.read_text() for tok in ("DELETE FROM", ".delete(", "sa.delete(", "delete(Event"))
    ]
    assert offenders == []


# ====================================================================== Q24: backup / restore / migration


def _populate(api: Api) -> dict[str, Any]:
    b = new_project(api)
    cid, _ = make_principal(api, "coordinator", "coord")
    delegation_in(api, api.project_id, cid)
    t = api.queued_task(title="finished")
    c = api.claim("impl")
    api.start("impl", c)
    up = _upload(api, "impl", b"evidence bytes \x00\x01", **{"X-Run-Id": c["run_id"]})
    assert up.status_code == 201
    api.submit_impl(c, artifacts=[up.json()["id"]])
    a = api.claim("aud", "audit")
    api.start("aud", a)
    api.submit_audit(a, "PASS")
    request_approval(api, task_id=t["id"])
    task_in(api, b, title="beta queued")
    live = api.queued_task(title="in flight")
    lc = api.claim("impl")  # an ACTIVE lease at backup time
    api.start("impl", lc)
    return {"b": b, "done": t["id"], "live": live["id"], "artifact": up.json(), "live_claim": lc}


def _counts_of(path: Path) -> dict[str, int]:
    conn = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
    try:
        return backup_mod._counts(conn)
    finally:
        conn.close()


def _restored_settings(tmp_path: Path, target: Path) -> Settings:
    return Settings(_env_file=None, data_dir=target, insecure_dev_cookies=True, watchdog_interval_seconds=0)


def test_q24_backup_restore_drill_into_a_new_directory(api: Api, env: Env, tmp_path: Path):
    s = _populate(api)
    old_cookies = dict(api.clients["owner"].cookies)
    original_before = _counts_of(env.settings.db_path)
    dest = tmp_path / "backups" / "b1"
    manifest = backup_mod.create_backup(env.settings, dest, env.clock)
    assert manifest["complete"] and manifest["schema_version"] == SCHEMA_VERSION and len(manifest["artifacts"]) == 1
    assert manifest["table_counts"]["events"] == original_before["events"] and "bootstrap_credentials" not in json.dumps(manifest["db"])
    assert not (dest / "bootstrap_credentials.json").exists()
    assert stat.S_IMODE(dest.stat().st_mode) == 0o700 and stat.S_IMODE((dest / "relay.sqlite").stat().st_mode) == 0o600
    assert not list(dest.glob("*-wal")) and not list(dest.glob("*-shm"))  # one self-contained file
    assert backup_mod.verify_backup(dest)["db"]["sha256"] == manifest["db"]["sha256"]

    # the live system keeps working during/after the backup
    api.queued_task(title="after backup")
    target = tmp_path / "restored"
    report = backup_mod.restore_backup(dest, target, env.clock)
    assert report["runs_lost"] == 1 and report["sessions_revoked"] >= 1

    # Restore never touched the original: still the same data (+ the one task created after the backup)
    after = _counts_of(env.settings.db_path)
    assert after["tasks"] == original_before["tasks"] + 1 and after["events"] > original_before["events"]
    assert env.settings.db_path.exists() and env.settings.artifacts_dir.exists()
    assert api.req("owner", "GET", api.p("/tasks")).status_code == 200

    # The restored copy: history, counts, snapshots, artifacts intact...
    restored = _counts_of(target / "relay.sqlite")
    for table, n in original_before.items():
        if table == "events":
            # + run.lost/task events of the fenced lease + one system.restored per project (2 projects)
            assert restored[table] >= n + 2
        elif table == "runs":
            assert restored[table] == n
        else:
            assert restored[table] == n, table
    app2 = create_app(_restored_settings(tmp_path, target), env.clock)
    api2 = Api(dataclasses.replace(env, settings=app2.state.settings, app=app2))  # type: ignore[attr-defined]
    task = api2.get_task(s["done"])
    assert task["status"] == "completed" and task["latest_report_id"] and task["current_snapshot_id"]
    assert api2.req("owner", "GET", api2.p(f"/snapshots/{task['current_snapshot_id']}")).status_code == 200
    dl = api2.req("owner", "GET", api2.p(f"/artifacts/{s['artifact']['id']}"))
    assert dl.status_code == 200 and dl.content == b"evidence bytes \x00\x01"
    ev = api2.events(limit=200)
    assert ev[-1]["type"] == "system.restored" and ev[-1]["data"]["runs_lost"] == 1
    # ...sessions are revoked: the old browser cookie is dead, a fresh login works
    stale = api2.env.client()
    stale.cookies.update(old_cookies)
    assert stale.get("/api/v1/me").status_code == 401
    with api2.db() as db:
        assert db.execute(select(func.count()).select_from(SessionRow).where(SessionRow.revoked_at.is_(None))).scalar_one() == 1  # only api2's own new login
    # the lease that was ACTIVE when the backup ran is fenced in the copy (the old process must not resurrect it)
    live = api2.get_task(s["live"])
    assert live["status"] == "blocked" and live["blocked_reason"] == "recovery_required"
    lc = s["live_claim"]
    hb = api2.req("impl", "POST", pp(lc["project_id"], f"/runs/{lc['run_id']}/heartbeat"), api2.guard(lc))
    assert hb.status_code == 409
    # agent keys survive the restore (only sessions are revoked)
    assert api2.req("impl", "GET", "/api/v1/me").status_code == 200


def test_q24_restore_never_overwrites_and_rejects_tampered_or_incompatible_backups(api: Api, env: Env, tmp_path: Path):
    _populate(api)
    dest = tmp_path / "b"
    backup_mod.create_backup(env.settings, dest, env.clock)
    # destination rules: not the live dir, not a non-empty dir, not inside the backup
    with pytest.raises(backup_mod.BackupError):
        backup_mod.create_backup(env.settings, env.settings.data_dir, env.clock)
    with pytest.raises(backup_mod.BackupError):
        backup_mod.create_backup(env.settings, dest, env.clock)  # already holds a backup
    occupied = tmp_path / "occupied"
    occupied.mkdir()
    (occupied / "precious.txt").write_text("keep me")
    with pytest.raises(backup_mod.BackupError, match="not empty"):
        backup_mod.restore_backup(dest, occupied, env.clock)
    assert (occupied / "precious.txt").read_text() == "keep me" and sorted(p.name for p in occupied.iterdir()) == ["precious.txt"]
    with pytest.raises(backup_mod.BackupError):
        backup_mod.restore_backup(dest, dest / "inside", env.clock)
    with pytest.raises(backup_mod.BackupError):
        backup_mod.restore_backup(dest, env.settings.data_dir, env.clock)  # the live dir is not empty
    # tampering is detected before anything is written
    art = next((dest / "artifacts").rglob("*.*"), None) or next(p for p in (dest / "artifacts").rglob("*") if p.is_file())
    original = art.read_bytes()
    art.write_bytes(b"evil")
    with pytest.raises(backup_mod.BackupError, match="artifact"):
        backup_mod.verify_backup(dest)
    art.write_bytes(original)
    db_file = dest / "relay.sqlite"
    raw = bytearray(db_file.read_bytes())
    raw[-10] ^= 0xFF
    db_file.write_bytes(bytes(raw))
    with pytest.raises(backup_mod.BackupError, match="sha256"):
        backup_mod.restore_backup(dest, tmp_path / "never", env.clock)
    assert not (tmp_path / "never").exists()
    (dest / "manifest.json").unlink()
    with pytest.raises(backup_mod.BackupError, match="not a complete backup"):
        backup_mod.verify_backup(dest)


def test_q24_schema_check_refuses_unknown_versions_and_migrates_a_v2_copy(api: Api, env: Env, tmp_path: Path):
    _populate(api)
    # (1) a database from another build: restore is refused and creates nothing
    foreign = tmp_path / "foreign"
    foreign.mkdir()
    src = sqlite3.connect(env.settings.db_path)
    dst = sqlite3.connect(foreign / "relay.sqlite")
    src.backup(dst)
    dst.execute("UPDATE schema_version SET version = 99")
    dst.commit()
    dst.close()
    src.close()
    if env.settings.artifacts_dir.exists():  # T12/F05: an incomplete backup is refused before the schema check
        shutil.copytree(env.settings.artifacts_dir, foreign / "artifacts")
    fake = Settings(_env_file=None, data_dir=foreign, watchdog_interval_seconds=0)
    b99 = tmp_path / "b99"
    backup_mod.create_backup(fake, b99, env.clock)
    with pytest.raises(SchemaError, match="requires v"):
        backup_mod.restore_backup(b99, tmp_path / "r99", env.clock)
    assert not (tmp_path / "r99").exists()

    # (2) a v2 database (downgrade a copy by undoing the additive v3 columns)
    v2_dir = tmp_path / "v2data"
    v2_dir.mkdir()
    s_src = sqlite3.connect(env.settings.db_path)
    s_dst = sqlite3.connect(v2_dir / "relay.sqlite")
    s_src.backup(s_dst)
    s_src.close()
    for stmt in (
        "DROP INDEX ix_approvals_project_status",
        "ALTER TABLE projects DROP COLUMN last_claimed_at",
        "ALTER TABLE sessions DROP COLUMN reauth_at",
        "ALTER TABLE approval_requests DROP COLUMN summary",
        "ALTER TABLE approval_requests DROP COLUMN action_json",
        "ALTER TABLE approval_requests DROP COLUMN revision",
        "ALTER TABLE approval_requests DROP COLUMN decided_at",
        "ALTER TABLE approval_requests DROP COLUMN decision_reason",
        "UPDATE schema_version SET version = 2",
    ):
        s_dst.execute(stmt)
    s_dst.commit()
    s_dst.close()
    if env.settings.artifacts_dir.exists():
        shutil.copytree(env.settings.artifacts_dir, v2_dir / "artifacts")
    v2_settings = Settings(_env_file=None, data_dir=v2_dir, watchdog_interval_seconds=0)
    eng = create_sqlite_engine(v2_settings.db_path)
    with pytest.raises(SchemaError, match="incompatible schema version 2"):
        ensure_schema(eng, env.clock)  # the server refuses to start on it
    eng.dispose()
    b2 = tmp_path / "b2"
    backup_mod.create_backup(v2_settings, b2, env.clock)
    with pytest.raises(SchemaError, match="--migrate"):
        backup_mod.restore_backup(b2, tmp_path / "r2-nomigrate", env.clock)
    rep = backup_mod.restore_backup(b2, tmp_path / "r2", env.clock, migrate=True)
    assert rep["migrated_from"] == 2
    assert backup_mod._counts(sqlite3.connect(tmp_path / "r2" / "relay.sqlite"))["tasks"] >= 1
    eng2 = create_sqlite_engine(tmp_path / "r2" / "relay.sqlite")
    assert read_schema_version(eng2) == SCHEMA_VERSION and ensure_schema(eng2, env.clock) == SCHEMA_VERSION
    assert migrate_to_current(eng2) == (SCHEMA_VERSION, SCHEMA_VERSION)  # idempotent
    eng2.dispose()
    # the in-place path: v2 database -> migrate -> compatible; v1/unknown is refused
    eng3 = create_sqlite_engine(v2_settings.db_path)
    assert migrate_to_current(eng3, env.clock) == (2, SCHEMA_VERSION)
    assert ensure_schema(eng3, env.clock) == SCHEMA_VERSION
    with eng3.begin() as conn:
        conn.execute(text("UPDATE schema_version SET version = 1"))
    with pytest.raises(SchemaError, match="cannot migrate"):
        migrate_to_current(eng3)
    eng3.dispose()
    # the migrated copy really works as a server
    app = create_app(_restored_settings(tmp_path, tmp_path / "r2"), env.clock)
    api3 = Api(dataclasses.replace(env, settings=app.state.settings, app=app))  # type: ignore[attr-defined]
    assert api3.req("owner", "GET", "/api/v1/projects").status_code == 200


def test_q24_cli_backup_verify_restore(api: Api, env: Env, tmp_path: Path, monkeypatch, capsys):
    from nozo_relay.__main__ import main

    _populate(api)
    monkeypatch.chdir(tmp_path)  # no stray .env
    monkeypatch.setenv("NOZO_RELAY_DATA_DIR", str(env.settings.data_dir))
    dest, target = tmp_path / "cli-backup", tmp_path / "cli-restored"
    assert main(["backup", "--to", str(dest)]) == 0
    assert main(["verify-backup", "--from", str(dest)]) == 0
    assert main(["backup", "--to", str(dest)]) == 1  # refuses a non-empty destination
    assert main(["restore", "--from", str(dest), "--to-data-dir", str(target)]) == 0
    out = capsys.readouterr()
    assert "Restored into" in out.out and "bootstrap" not in out.out.lower().replace("bootstrap_credentials", "")
    assert main(["restore", "--from", str(dest), "--to-data-dir", str(target)]) == 1  # target now non-empty
    assert (target / "relay.sqlite").exists() and not (target / "bootstrap_credentials.json").exists()
    monkeypatch.setenv("NOZO_RELAY_DATA_DIR", str(target))
    assert main(["check"]) == 0  # the restored data dir passes the server's startup check


def test_migrate_cli_backs_up_first(api: Api, env: Env, tmp_path: Path, monkeypatch, capsys):
    from nozo_relay.__main__ import main

    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("NOZO_RELAY_DATA_DIR", str(env.settings.data_dir))
    api.app.state.engine.dispose()  # type: ignore[attr-defined]
    assert main(["migrate"]) == 0  # already current: still takes the pre-migrate backup, reports vN -> vN
    from nozo_relay.db.schema import SCHEMA_VERSION

    assert f"Schema v{SCHEMA_VERSION} -> v{SCHEMA_VERSION}" in capsys.readouterr().out
    backups = list((env.settings.data_dir / "backups").iterdir())
    assert len(backups) == 1 and (backups[0] / "manifest.json").exists()


def test_session_reauth_endpoint_is_session_only_and_rate_limited(api: Api):
    assert reauth(api).status_code == 200
    # a bearer key cannot use it (and an owner has no key): agents get 403
    assert api.req("impl", "POST", "/api/v1/auth/reauth", {"password": OWNER_PASSWORD}).status_code == 403
    for _ in range(api.env.settings.login_max_failures):
        assert reauth(api, "nope nope nope nope").status_code == 401
    assert reauth(api, OWNER_PASSWORD).status_code == 429  # lock-out also blocks the correct password for a while


def test_artifact_and_approval_paths_require_authentication(api: Api, env: Env):
    anon = env.client()
    for method, path in (
        ("POST", api.p("/approval-requests")), ("GET", api.p("/approval-requests")),
        ("POST", "/api/v1/jobs/claim"), ("PUT", api.p("/policy")), ("GET", api.p("/policy")),
        ("POST", api.p(f"/delegations/{uid()}/revoke")), ("GET", api.p(f"/snapshots/{uid()}")),
    ):
        assert anon.request(method, path, json={}, headers={"Idempotency-Key": uid()}).status_code == 401, (method, path)


def test_bootstrap_credentials_and_secrets_never_enter_a_backup(api: Api, env: Env, tmp_path: Path):
    dest = tmp_path / "sec"
    backup_mod.create_backup(env.settings, dest, env.clock)
    blob = b"".join(p.read_bytes() for p in dest.rglob("*") if p.is_file())
    for agent in env.creds["agents"]:
        assert agent["key"].encode() not in blob  # only digests are in the database
    assert OWNER_PASSWORD.encode() not in blob
    assert not any(p.name == "bootstrap_credentials.json" for p in dest.rglob("*"))
    assert os.path.exists(env.settings.data_dir / "bootstrap_credentials.json")
