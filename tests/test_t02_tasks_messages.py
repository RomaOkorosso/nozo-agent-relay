"""T02: tasks, messages, idempotency, ACL, version guards (Q01/Q02/Q06/Q15 + 403/404 + validation)."""

from __future__ import annotations

import dataclasses
import threading
from datetime import UTC, datetime, timedelta

from conftest import BASE_URL, Env
from fastapi.testclient import TestClient
from sqlalchemy import select

from api_helpers import SCOPE, Api, uid
from nozo_relay.auth.credentials import issue_credential
from nozo_relay.db.engine import write_session
from nozo_relay.db.models import Event, Job, Membership, Message, Principal, Task
from nozo_relay.main import create_app


def error_code(r) -> str:
    return r.json()["error"]["code"]


def make_principal(api: Api, kind: str, name: str, *, projects: list[str] | None = None) -> tuple[str, str]:
    """Register an identity + key the way the owner CLI would; returns (principal_id, key)."""
    with write_session(api.app.state.engine) as ws:
        p = Principal(display_name=name, kind=kind, active=True, created_at=api.clock.now_ms())
        ws.add(p)
        ws.flush()
        for pid in projects if projects is not None else [api.project_id]:
            ws.add(Membership(principal_id=p.id, project_id=pid, role=kind))
        key, _ = issue_credential(ws, api.clock, p.id)
    return p.id, key.full_key


def second_project(api: Api, slug: str = "other") -> dict:
    r = api.req("owner", "POST", "/api/v1/projects", {"slug": slug, "name": "Other"})
    assert r.status_code == 201, r.text
    return r.json()


# ----------------------------------------------------------------------------- idempotency (Q01/Q02)


def test_q01_same_key_same_body_one_task_same_response(api: Api):
    key = uid()
    body = api.task_body()
    r1 = api.req("owner", "POST", api.p("/tasks"), body, idem=key)
    r2 = api.req("owner", "POST", api.p("/tasks"), body, idem=key)
    assert r1.status_code == 201 and r2.status_code == 201
    assert r1.json() == r2.json()
    assert r2.headers["Idempotent-Replay"] == "true" and "Idempotent-Replay" not in r1.headers
    assert api.count(Task) == 1
    created = [e for e in api.events() if e["type"] == "task.created"]
    assert len(created) == 1  # the replay did not append a second event


def test_q02_same_key_different_body_conflict_without_mutation(api: Api):
    key = uid()
    assert api.req("owner", "POST", api.p("/tasks"), api.task_body(title="A"), idem=key).status_code == 201
    r = api.req("owner", "POST", api.p("/tasks"), api.task_body(title="B"), idem=key)
    assert r.status_code == 409 and error_code(r) == "idempotency_conflict"
    assert api.count(Task) == 1
    assert api.count(Task, Task.title == "B") == 0


def test_idempotency_key_required_and_must_be_uuid(api: Api):
    r = api.req("owner", "POST", api.p("/tasks"), api.task_body(), idem=False)
    assert r.status_code == 428 and error_code(r) == "idempotency_key_required"
    r = api.req("owner", "POST", api.p("/tasks"), api.task_body(), idem="not-a-uuid")
    assert r.status_code == 422 and error_code(r) == "invalid_idempotency_key"
    assert api.count(Task) == 0


def test_replay_response_lost_after_restart_still_one_task(env: Env, api: Api):
    """Crash between mutation and response: the retry (same key) after a restart yields ONE task."""
    key = uid()
    body = api.task_body()
    first = api.req("owner", "POST", api.p("/tasks"), body, idem=key)
    assert first.status_code == 201
    api2 = Api(dataclasses.replace(env, app=create_app(env.settings, env.clock)))
    again = api2.req("owner", "POST", api2.p("/tasks"), body, idem=key)
    assert again.status_code == 201 and again.json() == first.json()
    assert api2.count(Task) == 1


def test_replay_rechecks_authentication(api: Api):
    """A revoked/logged-out principal must not read a cached answer."""
    key = uid()
    assert api.req("owner", "POST", api.p("/tasks"), api.task_body(), idem=key).status_code == 201
    assert api.req("owner", "POST", "/api/v1/auth/logout", None).status_code == 200
    r = api.req("owner", "POST", api.p("/tasks"), api.task_body(), idem=key)
    assert r.status_code == 401


def test_replay_rechecks_acl(api: Api):
    """Cached success is not served once the principal lost access to the project."""
    cid, ckey = make_principal(api, "coordinator", "coord")
    key = uid()
    msg = {"client_message_id": "m1", "kind": "note", "body": "hello"}
    agent = api.client_for_key(ckey)
    assert api.req(agent, "POST", api.p("/messages"), msg, idem=key).status_code == 201
    with write_session(api.app.state.engine) as ws:
        ws.delete(ws.get(Membership, (cid, api.project_id)))
    r = api.req(agent, "POST", api.p("/messages"), msg, idem=key)
    assert r.status_code == 404


def test_concurrent_same_key_creates_one_task(api: Api):
    key = uid()
    body = api.task_body()
    barrier = threading.Barrier(4)
    results: list[int] = []

    def go() -> None:
        owner = TestClient(api.app, base_url=BASE_URL)  # type: ignore[arg-type]
        owner.cookies.update(api.clients["owner"].cookies)
        barrier.wait()
        r = api.req(owner, "POST", api.p("/tasks"), body, idem=key, headers={"X-CSRF-Token": api.csrf})
        results.append(r.status_code)

    threads = [threading.Thread(target=go) for _ in range(4)]
    [t.start() for t in threads]
    [t.join() for t in threads]
    assert results == [201] * 4
    assert api.count(Task) == 1


# ----------------------------------------------------------------------------- guards: CSRF / If-Match


def test_csrf_missing_blocks_owner_mutation(api: Api):
    r = api.clients["owner"].post(api.p("/tasks"), json=api.task_body(), headers={"Idempotency-Key": uid()})
    assert r.status_code == 403 and error_code(r) == "csrf_failed"
    assert api.count(Task) == 0


def test_if_match_missing_is_428_and_stale_is_412(api: Api):
    t = api.create_task()
    path = api.p(f"/tasks/{t['id']}/enqueue")
    r = api.req("owner", "POST", path)
    assert r.status_code == 428 and error_code(r) == "precondition_required"
    r = api.req("owner", "POST", path, if_match=t["version"] + 5)
    assert r.status_code == 412 and error_code(r) == "version_conflict"
    assert r.json()["error"]["details"]["current_version"] == t["version"]
    r = api.req("owner", "POST", path, if_match="abc")
    assert r.status_code == 422
    assert api.get_task(t["id"])["status"] == "draft"


def test_enqueue_creates_ready_implement_job_and_replays_once(api: Api):
    t = api.create_task()
    key = uid()
    path = api.p(f"/tasks/{t['id']}/enqueue")
    r1 = api.req("owner", "POST", path, if_match=t["version"], idem=key)
    r2 = api.req("owner", "POST", path, if_match=t["version"], idem=key)
    assert r1.status_code == r2.status_code == 200 and r1.json() == r2.json()
    assert r1.json()["status"] == "queued" and r1.json()["version"] == t["version"] + 1
    assert r1.headers["ETag"] == f'"{t["version"] + 1}"'
    with api.db() as s:
        jobs = s.execute(select(Job).where(Job.task_id == t["id"])).scalars().all()
    assert [(j.stage, j.status, j.sequence, j.assignee_id) for j in jobs] == [("implement", "ready", 1, api.impl_id)]
    # a fresh key with the now-stale version is rejected; with the current version it is a state conflict
    r = api.req("owner", "POST", path, if_match=t["version"])
    assert r.status_code == 412
    r = api.req("owner", "POST", path, if_match=r1.json()["version"])
    assert r.status_code == 409 and error_code(r) == "invalid_state"


def test_task_get_etag_and_detail(api: Api):
    t = api.create_task()
    r = api.req("owner", "GET", api.p(f"/tasks/{t['id']}"))
    assert r.headers["ETag"] == f'"{t["version"]}"'
    d = r.json()
    assert d["current_revision"]["revision"] == 1 and len(d["current_revision"]["policy_digest"]) == 64
    assert d["authority_tier"] == "P0" and d["assignees"] == {"implementer_id": api.impl_id, "auditor_id": api.aud_id}
    assert d["links"]["jobs"] == [] and d["status"] == "draft"


# ----------------------------------------------------------------------------- validation


def test_validation_unknown_fields_enums_and_limits(api: Api):
    def post(**over):
        return api.req("owner", "POST", api.p("/tasks"), api.task_body(**over))

    assert post(origin_principal_id=api.owner_id).status_code == 422
    assert post(effective_tier="P0").status_code == 422
    assert post(actor="owner", role="owner").status_code == 422
    assert post(mode="reckless").status_code == 422
    assert post(urgency="urgent").status_code == 422
    assert post(max_failed_reviews=4).status_code == 422
    assert post(title="").status_code == 422
    assert post(title="x" * 201).status_code == 422
    assert post(acceptance=[]).status_code == 422
    assert post(acceptance=["a"] * 31).status_code == 422
    assert post(requirements="x" * (32 * 1024 + 1)).status_code == 422
    assert post(scope={**SCOPE, "allowed_paths": []}).status_code == 422
    assert post(scope={**SCOPE, "allowed_paths": ["../etc/**"]}).status_code == 422
    assert post(scope={**SCOPE, "allowed_paths": ["/abs/**"]}).status_code == 422
    assert post(scope={**SCOPE, "extra": 1}).status_code == 422
    assert post(implementer_id="not-a-uuid").status_code == 422
    assert api.count(Task) == 0
    r = post(origin_principal_id=api.owner_id)
    assert api.owner_id not in r.text  # field names may be reported, submitted values never echoed


def test_body_over_limit_rejected(api: Api):
    big = "x" * (300 * 1024)
    r = api.req("owner", "POST", api.p("/messages"), {"client_message_id": "big", "kind": "note", "body": big})
    assert r.status_code == 413


def test_assignee_validation(api: Api):
    r = api.req("owner", "POST", api.p("/tasks"), api.task_body(implementer_id=api.aud_id))
    assert r.status_code == 422 and error_code(r) == "invalid_assignee"
    r = api.req("owner", "POST", api.p("/tasks"), api.task_body(auditor_id=uid()))
    assert r.status_code == 422 and error_code(r) == "invalid_assignee"
    r = api.req("owner", "POST", api.p("/tasks"), api.task_body(auditor_id=api.impl_id))
    assert r.status_code == 422


# ----------------------------------------------------------------------------- ACL / spoofing (Q15)


def test_q15_executors_cannot_create_enqueue_or_spoof(api: Api):
    # implementer and auditor may only post notes
    for who in ("impl", "aud"):
        r = api.req(who, "POST", api.p("/tasks"), api.task_body())
        assert r.status_code == 403, who
    assert api.count(Task) == 0
    t = api.create_task()
    r = api.req("impl", "POST", api.p(f"/tasks/{t['id']}/enqueue"), if_match=t["version"])
    assert r.status_code == 403
    # spoofing headers/fields has no effect: actor, tier and role are server-derived
    r = api.req("impl", "POST", api.p("/tasks"), api.task_body(), headers={"X-Actor": "owner", "X-Role": "owner", "X-Tier": "P0"})
    assert r.status_code == 403
    assert api.req("impl", "POST", "/api/v1/projects", {"slug": "evil", "name": "x"}).status_code == 403
    assert api.req("impl", "POST", "/api/v1/agents", {"display_name": "k", "kind": "implementer", "project_ids": [api.project_id]}).status_code == 403
    assert api.req("aud", "GET", "/api/v1/agents").status_code == 403
    assert api.req("impl", "PATCH", api.p(), {"name": "pwn"}, if_match=1).status_code == 403
    assert api.req("impl", "POST", "/api/v1/controls/emergency-stop", {"reason": "x"}).status_code == 403
    assert api.get_task(t["id"])["status"] == "draft"
    # there is no endpoint for key creation / approval / arbitrary status
    assert api.req("impl", "POST", "/api/v1/agents/x/keys", {}).status_code in (404, 405)
    assert api.req("impl", "PATCH", api.p(f"/tasks/{t['id']}"), {"status": "completed"}, if_match=1).status_code in (404, 405)


def test_unauthenticated_and_query_string_credentials_rejected(api: Api):
    anon = TestClient(api.app, base_url=BASE_URL)  # type: ignore[arg-type]
    assert anon.get(api.p("/tasks")).status_code == 401
    key = api.keys["impl"]
    assert anon.get(api.p("/tasks") + f"?access_token={key}&api_key={key}").status_code == 401


def test_non_member_gets_404_not_403_everywhere(api: Api):
    _, key = make_principal(api, "implementer", "outsider", projects=[])
    out = api.client_for_key(key)
    t = api.create_task()
    for method, path in [
        ("GET", api.p()), ("GET", api.p("/tasks")), ("GET", api.p(f"/tasks/{t['id']}")),
        ("GET", api.p("/messages")), ("GET", api.p("/events")), ("GET", api.p("/snapshot")),
    ]:
        r = api.req(out, method, path)
        assert r.status_code == 404 and error_code(r) == "not_found", (method, path)
    r = api.req(out, "POST", api.p("/messages"), {"client_message_id": "x", "kind": "note", "body": "hi"})
    assert r.status_code == 404
    assert api.req(out, "GET", "/api/v1/projects").json()["items"] == []


def test_cross_project_ids_are_404_without_data(api: Api):
    p2 = second_project(api)
    # task in project 2 is invisible through project 1 URL and vice versa
    r = api.req("owner", "POST", f"/api/v1/projects/{p2['id']}/tasks", api.task_body())
    # implementer/auditor are not members of project 2 -> assignee validation fails; owner still sees 422
    assert r.status_code == 422
    t = api.create_task()
    r = api.req("owner", "GET", f"/api/v1/projects/{p2['id']}/tasks/{t['id']}")
    assert r.status_code == 404
    # agents cannot even see project 2
    r = api.req("impl", "GET", f"/api/v1/projects/{p2['id']}")
    assert r.status_code == 404
    assert [p["slug"] for p in api.req("impl", "GET", "/api/v1/projects").json()["items"]] == ["default"]
    assert sorted(p["slug"] for p in api.req("owner", "GET", "/api/v1/projects").json()["items"]) == ["default", "other"]


# ----------------------------------------------------------------------------- coordinator + delegation


def _delegation(api: Api, cid: str, *, valid_for: timedelta = timedelta(hours=1), **ceiling):
    ceil = {"allowed_paths": ["src/**"], "max_changed_files": 5, "max_diff_lines": 200, **ceiling}
    until = datetime.fromtimestamp(api.clock.now_ms() / 1000, tz=UTC) + valid_for
    r = api.req(
        "owner", "POST", api.p("/delegations"),
        {"coordinator_id": cid, "allowed_actions": ["task.create", "task.enqueue", "task.control"],
         "scope_ceiling": ceil, "valid_until": until.isoformat()},
    )
    assert r.status_code == 201, r.text
    return r.json()


def test_coordinator_requires_valid_delegation_and_gets_p1_tier(api: Api):
    cid, ckey = make_principal(api, "coordinator", "coord")
    coord = api.client_for_key(ckey)
    # no delegation -> 403
    assert api.req(coord, "POST", api.p("/tasks"), api.task_body()).status_code == 403
    d = _delegation(api, cid)
    # within ceiling -> P1 draft; tier comes from the credential
    r = api.req(coord, "POST", api.p("/tasks"), api.task_body(autonomous=False, delegation_id=d["id"]))
    assert r.status_code == 201 and r.json()["authority_tier"] == "P1"
    task = r.json()
    # exceeding the ceiling (files, paths, autonomy) -> 403
    assert api.req(coord, "POST", api.p("/tasks"), api.task_body(autonomous=False, delegation_id=d["id"], scope={**SCOPE, "max_changed_files": 6})).status_code == 403
    assert api.req(coord, "POST", api.p("/tasks"), api.task_body(autonomous=False, delegation_id=d["id"], scope={**SCOPE, "allowed_paths": ["other/**"]})).status_code == 403
    assert api.req(coord, "POST", api.p("/tasks"), api.task_body(autonomous=True, delegation_id=d["id"])).status_code == 403
    # the coordinator can enqueue its own task, but cannot touch the owner's
    owner_task = api.create_task()
    assert api.req(coord, "POST", api.p(f"/tasks/{owner_task['id']}/enqueue"), if_match=owner_task["version"]).status_code == 403
    r = api.req(coord, "POST", api.p(f"/tasks/{task['id']}/enqueue"), if_match=task["version"])
    assert r.status_code == 200 and r.json()["status"] == "queued"
    # expiry kills the authority
    api.clock.advance(seconds=3601)
    t2 = api.task_body(autonomous=False, delegation_id=d["id"])
    assert api.req(coord, "POST", api.p("/tasks"), t2).status_code == 403
    # a coordinator cannot create delegations or keys
    assert api.req(coord, "POST", api.p("/delegations"), {}).status_code in (403, 422)


# ----------------------------------------------------------------------------- projects


def test_project_create_patch_and_version_guard(api: Api):
    r = api.req("owner", "POST", "/api/v1/projects", {"slug": "Bad_Slug", "name": "x"})
    assert r.status_code == 422
    p = second_project(api, "alpha")
    assert api.req("owner", "POST", "/api/v1/projects", {"slug": "alpha", "name": "dup"}).status_code == 409
    path = f"/api/v1/projects/{p['id']}"
    assert api.req("owner", "PATCH", path, {"name": "New"}).status_code == 428
    assert api.req("owner", "PATCH", path, {"name": "New"}, if_match=p["version"] + 1).status_code == 412
    r = api.req("owner", "PATCH", path, {"name": "New"}, if_match=p["version"])
    assert r.status_code == 200 and r.json()["name"] == "New" and r.json()["version"] == p["version"] + 1
    assert api.req("owner", "PATCH", path, {}, if_match=r.json()["version"]).status_code == 422
    assert api.req("owner", "GET", path).json()["name"] == "New"
    assert api.req("owner", "PATCH", path, {"slug": "x"}, if_match=r.json()["version"]).status_code == 422


# ----------------------------------------------------------------------------- messages


def msg(**over):
    return {"client_message_id": uid(), "kind": "note", "body": "hello", **over}


def test_message_roundtrip_dedup_and_conflict(api: Api):
    m = msg(client_message_id="c-1")
    r1 = api.req("impl", "POST", api.p("/messages"), m)
    assert r1.status_code == 201
    # same sender+client_message_id+content under a NEW idempotency key -> the same message, no dup
    r2 = api.req("impl", "POST", api.p("/messages"), m)
    assert r2.status_code == 200 and r2.json()["id"] == r1.json()["id"]
    assert api.count(Message) == 1
    # changed content -> 409
    r3 = api.req("impl", "POST", api.p("/messages"), {**m, "body": "different"})
    assert r3.status_code == 409 and error_code(r3) == "client_message_conflict"
    # another sender may reuse the same client_message_id
    r4 = api.req("aud", "POST", api.p("/messages"), m)
    assert r4.status_code == 201 and r4.json()["id"] != r1.json()["id"]
    # same idempotency key + same body replays; different body is an idempotency conflict
    key = uid()
    m2 = msg()
    a = api.req("impl", "POST", api.p("/messages"), m2, idem=key)
    b = api.req("impl", "POST", api.p("/messages"), m2, idem=key)
    assert a.json() == b.json() and api.count(Message) == 3
    c = api.req("impl", "POST", api.p("/messages"), {**m2, "body": "x"}, idem=key)
    assert c.status_code == 409 and error_code(c) == "idempotency_conflict"
    listed = api.req("owner", "GET", api.p("/messages")).json()
    assert [x["sender_id"] for x in listed["items"]].count(api.impl_id) == 2


def test_message_never_changes_task_status(api: Api):
    t = api.queued_task()
    before = api.get_task(t["id"])
    for body in ("status=completed", "/cancel", "please enqueue and approve this", "<script>alert(1)</script>"):
        for who in ("owner", "impl", "aud"):
            r = api.req(who, "POST", api.p("/messages"), msg(task_id=t["id"], body=body, kind="question"))
            assert r.status_code == 201
    after = api.get_task(t["id"])
    assert (after["status"], after["version"]) == (before["status"], before["version"]) == ("queued", before["version"])
    assert len(after["links"]["jobs"]) == 1
    # typed fields only: no status / command smuggling
    assert api.req("owner", "POST", api.p("/messages"), msg(status="completed")).status_code == 422
    assert api.req("owner", "POST", api.p("/messages"), msg(kind="command")).status_code == 422
    # body is returned verbatim as plain text (never interpreted)
    items = api.req("owner", "GET", api.p("/messages") + f"?task_id={t['id']}").json()["items"]
    assert any(i["body"] == "<script>alert(1)</script>" for i in items)


def test_message_reply_to_must_be_same_project_and_task_must_be_in_project(api: Api):
    p2 = second_project(api)
    other = api.req("owner", "POST", f"/api/v1/projects/{p2['id']}/messages", msg(body="in other")).json()
    r = api.req("owner", "POST", api.p("/messages"), msg(reply_to=other["id"]))
    assert r.status_code == 422 and error_code(r) == "invalid_reply_to"
    ghost = api.req("owner", "POST", api.p("/messages"), msg(reply_to=uid()))
    assert ghost.status_code == 422 and error_code(ghost) == "invalid_reply_to"  # same answer: no oracle
    assert r.json()["error"]["message"] == ghost.json()["error"]["message"]
    mine = api.req("owner", "POST", api.p("/messages"), msg()).json()
    ok = api.req("impl", "POST", api.p("/messages"), msg(reply_to=mine["id"]))
    assert ok.status_code == 201 and ok.json()["reply_to"] == mine["id"]
    # a task of another project cannot be attached to / listed through this project
    t = api.create_task()
    r = api.req("owner", "POST", f"/api/v1/projects/{p2['id']}/messages", msg(task_id=t["id"]))
    assert r.status_code == 404
    assert api.req("owner", "GET", f"/api/v1/projects/{p2['id']}/messages?task_id={t['id']}").status_code == 404
    assert api.count(Message) == 3


def test_message_size_limit(api: Api):
    assert api.req("owner", "POST", api.p("/messages"), msg(body="x" * 16 * 1024)).status_code == 201
    assert api.req("owner", "POST", api.p("/messages"), msg(body="x" * (16 * 1024 + 1))).status_code == 422
    assert api.req("owner", "POST", api.p("/messages"), msg(body="")).status_code == 422


# ----------------------------------------------------------------------------- lists / events / snapshot


def test_pagination_cursor_and_limits(api: Api):
    ids = []
    for i in range(5):
        ids.append(api.create_task(title=f"t{i}")["id"])
        api.clock.advance(ms=1)  # order is (created_at, id): distinct timestamps give creation order
    seen: list[str] = []
    cursor = None
    pages = 0
    while True:
        q = "?limit=2" + (f"&cursor={cursor}" if cursor else "")
        r = api.req("owner", "GET", api.p("/tasks") + q).json()
        seen += [t["id"] for t in r["items"]]
        pages += 1
        cursor = r["next_cursor"]
        if not cursor:
            break
    assert pages == 3 and seen == ids  # deterministic order, no duplicates / gaps
    assert api.req("owner", "GET", api.p("/tasks?limit=201")).status_code == 422
    assert api.req("owner", "GET", api.p("/tasks?limit=0")).status_code == 422
    assert api.req("owner", "GET", api.p("/tasks?cursor=garbage")).status_code == 422
    assert api.req("owner", "GET", api.p("/tasks?status=bogus")).status_code == 422
    assert len(api.req("owner", "GET", api.p("/tasks?status=draft")).json()["items"]) == 5
    assert api.req("owner", "GET", api.p("/tasks?status=queued")).json()["items"] == []


def test_q06_events_survive_restart_and_replay_by_seq(env: Env, api: Api):
    t = api.create_task()
    api.enqueue(t)
    evs = api.events()
    assert [e["type"] for e in evs] == ["task.created", "task.status_changed", "job.created"]
    assert all(e["schema_version"] == 1 and e["project_id"] == api.project_id for e in evs)
    seqs = [e["seq"] for e in evs]
    assert seqs == sorted(seqs) and len(set(seqs)) == 3
    assert [e["entity_version"] for e in evs if e["type"] != "job.created"] == [1, 2]
    # "crash" after commit and before any notification: a fresh process still serves the committed events
    api2 = Api(dataclasses.replace(env, app=create_app(env.settings, env.clock)))
    again = api2.events()
    assert [e["event_id"] for e in again] == [e["event_id"] for e in evs]
    tail = api2.events(after=seqs[0])
    assert [e["seq"] for e in tail] == seqs[1:]
    r = api2.req("owner", "GET", api2.p(f"/events?after_seq={seqs[0]}&limit=1")).json()
    assert len(r["events"]) == 1 and r["next_cursor"] == str(seqs[1]) and r["high_watermark"] == seqs[-1]
    assert api2.req("owner", "GET", api2.p("/events?limit=500")).status_code == 422
    # events never carry secrets
    assert api.keys["impl"] not in str(evs) and "password" not in str(evs).lower()


def test_events_are_scoped_to_project(api: Api):
    p2 = second_project(api)
    api.create_task()
    assert api.req("owner", "GET", f"/api/v1/projects/{p2['id']}/events").json()["events"][0]["type"] == "project.created"
    with api.db() as s:
        foreign = s.execute(select(Event).where(Event.project_id == p2["id"])).scalars().all()
    assert all(e.project_id == p2["id"] for e in foreign)
    assert api.req("impl", "GET", f"/api/v1/projects/{p2['id']}/events").status_code == 404


def test_snapshot_is_consistent_with_event_watermark(api: Api):
    t = api.queued_task()
    api.req("impl", "POST", api.p("/messages"), msg(task_id=t["id"]))
    snap = api.req("owner", "GET", api.p("/snapshot")).json()
    assert snap["high_watermark"] == api.events()[-1]["seq"]
    assert [x["id"] for x in snap["tasks"]] == [t["id"]] and snap["tasks"][0]["status"] == "queued"
    assert len(snap["messages"]) == 1 and len(snap["active_jobs"]) == 1 and snap["project"]["id"] == api.project_id
    # replay from the watermark yields nothing missing / duplicated
    assert api.events(after=snap["high_watermark"]) == []
    api.create_task()
    assert len(api.events(after=snap["high_watermark"])) == 1


def test_agents_endpoints_are_owner_only_and_secret_free(api: Api):
    r = api.req("owner", "GET", "/api/v1/agents")
    assert r.status_code == 200
    items = {a["display_name"]: a for a in r.json()["items"]}
    assert set(items) == {"test-implementer", "test-auditor", "default-supervisor"}
    assert items["test-implementer"]["availability"] == "available"
    assert api.keys["impl"] not in r.text and "secret" not in r.text.lower()
    r = api.req("owner", "POST", "/api/v1/agents", {"display_name": "impl-2", "kind": "implementer", "project_ids": [api.project_id]})
    assert r.status_code == 201 and "key" not in r.json()
    assert api.req("owner", "POST", "/api/v1/agents", {"display_name": "x", "kind": "owner", "project_ids": [api.project_id]}).status_code == 422
    assert api.req("owner", "POST", "/api/v1/agents", {"display_name": "x", "kind": "runner", "project_ids": [uid()]}).status_code == 404
    assert api.req("impl", "GET", "/api/v1/agents").status_code == 403
