"""Owner/coordinator force-complete (command=complete) for idle tasks."""

from __future__ import annotations

import pytest


def test_owner_completes_draft_and_queued(api):
    draft = api.create_task(title="complete draft")
    r = api.control(draft["id"], "complete", reason="done offline")
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["control"]["command"] == "complete"
    assert body["control"]["status"] == "confirmed"
    assert body["task"]["status"] == "completed"

    queued = api.queued_task(title="complete queued")
    r2 = api.control(queued["id"], "complete", reason="shipped")
    assert r2.status_code == 200, r2.text
    assert r2.json()["task"]["status"] == "completed"


def test_complete_rejects_terminal_and_active(api):
    t = api.create_task(title="once")
    assert api.control(t["id"], "complete", reason="first").status_code == 200
    again = api.control(t["id"], "complete", reason="again", expect=409)
    assert again.json()["error"]["code"] == "task_terminal"

    live = api.queued_task(title="running path")
    claim = api.claim("impl")
    assert claim["task_id"] == live["id"]
    blocked = api.control(live["id"], "complete", reason="nope", expect=409)
    assert blocked.json()["error"]["code"] == "invalid_state"


def test_implementer_cannot_complete(api):
    t = api.create_task(title="impl denied")
    r = api.req(
        "impl",
        "POST",
        api.p(f"/tasks/{t['id']}/controls"),
        {"command": "complete", "reason": "x"},
        if_match=t["version"],
    )
    assert r.status_code == 403


def test_coordinator_completes_own_delegated_task(api):
    from datetime import UTC, datetime, timedelta

    cid, key = api.make_principal("coordinator", "complete-coord")
    until = datetime.fromtimestamp(api.clock.now_ms() / 1000, UTC) + timedelta(hours=1)
    d = api.req(
        "owner",
        "POST",
        api.p("/delegations"),
        {
            "coordinator_id": cid,
            "allowed_actions": ["task.create", "task.enqueue", "task.control"],
            "scope_ceiling": {
                "allowed_paths": ["src/**"],
                "max_changed_files": 5,
                "max_diff_lines": 200,
                "allow_autonomous": True,
            },
            "valid_until": until.isoformat(),
        },
    )
    assert d.status_code == 201, d.text
    coord = api.client_for_key(key)
    made = api.req(
        coord,
        "POST",
        api.p("/tasks"),
        api.task_body(title="coord complete me", autonomous=True, delegation_id=d.json()["id"]),
    )
    assert made.status_code == 201, made.text
    task = made.json()
    done = api.req(
        coord,
        "POST",
        api.p(f"/tasks/{task['id']}/controls"),
        {"command": "complete", "reason": "coord closed"},
        if_match=task["version"],
    )
    assert done.status_code == 200, done.text
    assert done.json()["task"]["status"] == "completed"


def test_complete_idle_transition_table():
    from nozo_relay.domain import transitions

    transitions.check_task("complete_idle", "draft", "completed")
    transitions.check_task("complete_idle", "queued", "completed")
    with pytest.raises(transitions.IllegalTransition):
        transitions.check_task("complete_idle", "running", "completed")
    with pytest.raises(transitions.IllegalTransition):
        transitions.check_task("complete_idle", "draft", "cancelled")
