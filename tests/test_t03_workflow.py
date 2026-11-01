"""T03: jobs/runs/leases, reports, controls, fencing, loop detector (Q03-Q13, Q15-Q17, Q34, Q35)."""

from __future__ import annotations

import threading
from typing import Any

import pytest
from conftest import Env
from sqlalchemy import select

from api_helpers import Api, uid
from nozo_relay.db.models import Finding, Job, Report, Run, Snapshot, Task
from nozo_relay.domain import transitions
from nozo_relay.domain.fingerprints import (
    AuditRound,
    detect_loop,
    finding_fingerprint,
    invariant_id,
    normalize_reproduction,
)


def code(r) -> str:
    return r.json()["error"]["code"]


def statuses(api: Api, task_id: str) -> list[str]:
    return [e["data"]["status"] for e in api.events() if e["type"] == "task.status_changed" and e["task_id"] == task_id]


def parallel(*fns) -> list[Any]:
    barrier = threading.Barrier(len(fns))
    out: list[Any] = [None] * len(fns)

    def wrap(i: int, fn) -> None:  # noqa: ANN001
        barrier.wait()
        out[i] = fn()

    threads = [threading.Thread(target=wrap, args=(i, f)) for i, f in enumerate(fns)]
    [t.start() for t in threads]
    [t.join() for t in threads]
    return out


def to_reviewing(api: Api, **task_over: Any) -> tuple[dict, dict]:
    """task -> implementation accepted -> audit claimed+started. Returns (task, audit_claim)."""
    t = api.queued_task(**task_over)
    api.implement()
    a = api.claim("aud", "audit")
    api.start("aud", a)
    return t, a


# =============================================================================== domain units


def test_transition_table_rejects_illegal_moves():
    transitions.check_task("enqueue", "draft", "queued")
    for trigger, src, dst in [
        ("enqueue", "queued", "queued"), ("audit_pass", "running", "completed"),
        ("start", "queued", "running"), ("audit_fail", "reviewing", "completed"),
        ("cancel_idle", "completed", "cancelled"), ("resume", "completed", "queued"),
    ]:
        with pytest.raises(transitions.IllegalTransition):
            transitions.check_task(trigger, src, dst)
    transitions.check_job("ready", "leased")
    for src, dst in [("succeeded", "ready"), ("ready", "running"), ("lost", "leased"), ("cancelled", "running")]:
        with pytest.raises(transitions.IllegalTransition):
            transitions.check_job(src, dst)
    for src, dst in [("succeeded", "running"), ("lost", "running"), ("cancelled", "leased")]:
        with pytest.raises(transitions.IllegalTransition):
            transitions.check_run(src, dst)


def test_fingerprint_ignores_lines_uuids_timestamps_and_case():
    a = finding_fingerprint(project_id="p", lineage="l", invariant_key="inv", component="c",
                            reproduction="Fails at app.py:42 for 3f2b1c9e-1111-4222-8333-444455556666 at 2026-10-28T10:00:00Z")
    b = finding_fingerprint(project_id="p", lineage="l", invariant_key=" INV ", component="C",
                            reproduction="fails   at app.py:99 for aaaaaaaa-1111-4222-8333-444455556666 at 2027-01-01T00:00:00Z")
    assert a == b
    assert a != finding_fingerprint(project_id="p", lineage="l", invariant_key="inv2", component="c", reproduction="x")
    assert a != finding_fingerprint(project_id="p2", lineage="l", invariant_key="inv", component="c",
                                    reproduction="Fails at app.py:42 for 3f2b1c9e-1111-4222-8333-444455556666 at 2026-10-28T10:00:00Z")
    assert normalize_reproduction("Line 12: boom") == normalize_reproduction("line 99:   BOOM")


def test_loop_detector_rules():
    inv = frozenset({invariant_id("a", "c")})
    other = frozenset({invariant_id("b", "c")})
    r = lambda i, d, t="t": AuditRound(i, d, t)  # noqa: E731
    assert detect_loop([], r(inv, "d1")) is None
    assert detect_loop([r(inv, "d1")], r(inv, "d2")) is None  # fixed attempt changed the diff
    assert detect_loop([r(inv, "d1")], r(inv, "d1")).rule == "same_invariant_same_diff"
    assert detect_loop([r(other, "d1")], r(inv, "d1")) is None  # different invariant
    assert detect_loop([r(inv, "d1"), r(inv, "d2")], r(inv, "d3")).rule == "same_invariant_after_two_fixes"
    assert detect_loop([r(inv, "d1"), r(other, "d2")], r(inv, "d3")) is None
    assert detect_loop([r(inv, "A"), r(other, "B")], r(frozenset(), "A")).rule == "state_cycle_aba"
    assert detect_loop([r(inv, "A"), r(other, "A")], r(frozenset(), "B")) is None


# =============================================================================== success / fix cycles


def test_full_success_cycle_with_explained_history(api: Api):
    t = api.create_task()
    api.enqueue(t)
    c = api.claim("impl")
    assert (c["stage"], c["lease_epoch"], c["revision"], c["input_snapshot"]) == ("implement", 1, 1, None)
    assert c["task_input"]["scope"]["allowed_paths"] == ["src/**"] and c["lease_ttl_seconds"] == 90
    assert c["heartbeat_interval_seconds"] == 15
    assert api.get_task(t["id"])["status"] == "claimed"
    assert api.start("impl", c).json()["task_status"] == "running"
    r = api.submit_impl(c).json()
    assert r["task"]["status"] == "awaiting_review" and r["next_job"]["stage"] == "audit"
    a = api.claim("aud", "audit")
    assert a["input_snapshot"]["id"] == r["task"]["current_snapshot_id"] and a["revision"] == 1
    assert api.get_task(t["id"])["status"] == "reviewing"
    assert api.start("aud", a).json()["task_status"] == "reviewing"  # start does not change the task
    res = api.submit_audit(a, "PASS").json()
    assert res["task"]["status"] == "completed" and res["verdict"] == "PASS"

    final = api.get_task(t["id"])
    assert final["failed_review_count"] == 0 and final["blocked_reason"] is None
    assert [(j["stage"], j["status"]) for j in final["links"]["jobs"]] == [("implement", "succeeded"), ("audit", "succeeded")]
    assert statuses(api, t["id"]) == ["queued", "claimed", "running", "awaiting_review", "reviewing", "completed"]
    rep = api.req("owner", "GET", api.p(f"/reports/{res['report_id']}")).json()
    assert rep["snapshot"]["id"] == a["input_snapshot"]["id"] and rep["snapshot"]["verified_at"] is not None
    assert rep["verdict"] == "PASS" and rep["evidence_level"] == "INTEGRATION_FIXTURE"
    # nothing left to do and completed tasks are immutable
    assert api.claim("impl", expect=204).status_code == 204
    assert api.control(t["id"], "cancel").status_code == 409
    assert api.count(Run) == 2 and api.count(Report) == 2


def test_fix_cycle_fail_then_pass(api: Api):
    t = api.queued_task()
    api.implement(variant="v1")
    a1 = api.audit("FAIL")
    task = api.get_task(t["id"])
    assert (task["status"], task["failed_review_count"]) == ("changes_requested", 1)
    fix = api.claim("impl")
    assert fix["revision"] == 1 and fix["lease_epoch"] == 1  # new job, fresh epoch
    assert fix["run_id"] != a1["run_id"] and fix["input_snapshot"]["id"] == a1["input_snapshot"]["id"]
    assert fix["task_input"]["failed_review_count"] == 1
    api.start("impl", fix)
    api.submit_impl(fix, variant="v2")
    a2 = api.audit("PASS")
    assert a2["input_snapshot"]["id"] != a1["input_snapshot"]["id"]  # audits the NEW snapshot
    done = api.get_task(t["id"])
    assert done["status"] == "completed" and done["failed_review_count"] == 1
    assert statuses(api, t["id"]) == [
        "queued", "claimed", "running", "awaiting_review", "reviewing", "changes_requested",
        "claimed", "running", "awaiting_review", "reviewing", "completed",
    ]
    # finding is server-fingerprinted, lineage tracked
    with api.db() as s:
        f = s.execute(select(Finding)).scalar_one()
    assert len(f.fingerprint) == 64 and f.severity == "S1" and f.status == "open"


# =============================================================================== Q03 / Q04 claims


def test_q03_concurrent_claims_have_one_winner(api: Api):
    api.queued_task()
    clients = [api.client_for_key(api.keys["impl"]) for _ in range(6)]
    results = parallel(*[
        (lambda c=c: api.req(c, "POST", api.p("/jobs/claim"), {"stage": "implement", "claim_request_id": uid(), "runner_instance_id": "r"}))
        for c in clients
    ])
    assert sorted(r.status_code for r in results) == [200, 204, 204, 204, 204, 204]
    assert api.count(Run) == 1
    assert api.count(Run, Run.status.in_(["leased", "running", "stopping"])) == 1
    with api.db() as s:
        job = s.execute(select(Job)).scalar_one()
    assert (job.status, job.lease_epoch, job.delivery_count) == ("leased", 1, 1)


def test_q04_claim_replay_returns_same_run(api: Api):
    api.queued_task()
    key, cid = uid(), uid()
    body = {"stage": "implement", "claim_request_id": cid, "runner_instance_id": "r1"}
    r1 = api.req("impl", "POST", api.p("/jobs/claim"), body, idem=key)
    r2 = api.req("impl", "POST", api.p("/jobs/claim"), body, idem=key)  # lost response, same key
    r3 = api.req("impl", "POST", api.p("/jobs/claim"), body)  # same claim_request_id, new header key
    assert r1.status_code == r2.status_code == r3.status_code == 200
    assert r1.json() == r2.json() == r3.json()
    assert api.count(Run) == 1
    # same key, different request -> conflict, still one run
    other = api.req("impl", "POST", api.p("/jobs/claim"), {**body, "runner_instance_id": "r2"}, idem=key)
    assert other.status_code == 409 and code(other) == "idempotency_conflict"
    assert api.count(Run) == 1
    # the replayed receipt is only a receipt: start must still succeed for the process to spawn
    assert api.start("impl", r1.json()).status_code == 200


def test_claim_role_and_assignment_rules(api: Api):
    t = api.queued_task()
    # wrong role for the stage, and owner cannot pose as an implementer/auditor
    assert api.req("aud", "POST", api.p("/jobs/claim"), {"stage": "implement", "claim_request_id": uid(), "runner_instance_id": "r"}).status_code == 403
    assert api.req("impl", "POST", api.p("/jobs/claim"), {"stage": "audit", "claim_request_id": uid(), "runner_instance_id": "r"}).status_code == 403
    assert api.req("owner", "POST", api.p("/jobs/claim"), {"stage": "audit", "claim_request_id": uid(), "runner_instance_id": "r"}).status_code == 403
    assert api.req("owner", "POST", api.p("/jobs/claim"), {"stage": "implement", "claim_request_id": uid(), "runner_instance_id": "r"}).status_code == 403
    # another implementer in the project is not the assignee: nothing for them
    _, key2 = api.make_principal("implementer", "impl-2")
    other = api.client_for_key(key2)
    assert api.req(other, "POST", api.p("/jobs/claim"), {"stage": "implement", "claim_request_id": uid(), "runner_instance_id": "r"}).status_code == 204
    # unknown stage / extra fields
    assert api.req("impl", "POST", api.p("/jobs/claim"), {"stage": "ship", "claim_request_id": uid(), "runner_instance_id": "r"}).status_code == 422
    assert api.req("impl", "POST", api.p("/jobs/claim"), {"stage": "implement", "claim_request_id": uid(), "runner_instance_id": "r", "task_id": t["id"]}).status_code == 422
    assert api.get_task(t["id"])["status"] == "queued"


def test_claim_priority_tier_then_urgency_then_age(api: Api):
    low = api.queued_task(title="low", urgency="low")
    api.clock.advance(ms=5)
    normal = api.queued_task(title="normal")
    api.clock.advance(ms=5)
    high = api.queued_task(title="high", urgency="high")
    order = []
    for _ in range(3):
        c = api.claim("impl")
        order.append(c["task_id"])
        api.start("impl", c)
        api.submit_impl(c)  # free the implementer slot (audit jobs belong to the auditor)
    assert order == [high["id"], normal["id"], low["id"]]


# =============================================================================== Q05 / Q12 results


def test_q05_result_replay_yields_one_report_and_one_audit_job(api: Api):
    t = api.queued_task()
    c = api.claim("impl")
    api.start("impl", c)
    key = uid()
    r1 = api.submit_impl(c, idem=key)
    r2 = api.submit_impl(c, idem=key)  # response lost, same key
    r3 = api.submit_impl(c)  # new key, identical content (e.g. runner outbox resend)
    assert r1.json() == r2.json()
    assert r3.status_code == 200 and r3.json()["replayed"] is True and r3.json()["report_id"] == r1.json()["report_id"]
    assert api.count(Report) == 1 and api.count(Snapshot) == 1
    jobs = api.jobs(t["id"])
    assert sorted((j.stage, j.status) for j in jobs) == [("audit", "ready"), ("implement", "succeeded")]
    # a DIFFERENT result for the same run is refused, nothing changes
    r4 = api.submit_impl(c, expect=None, variant="v2")
    assert r4.status_code == 409 and code(r4) == "result_conflict"
    assert api.count(Report) == 1 and len(api.jobs(t["id"])) == 2


def test_q12_duplicate_fail_does_not_double_count(api: Api):
    t = api.queued_task()
    api.implement()
    a = api.claim("aud", "audit")
    api.start("aud", a)
    key = uid()
    first = api.submit_audit(a, "FAIL", idem=key)
    again_same_key = api.submit_audit(a, "FAIL", idem=key)
    again_new_key = api.submit_audit(a, "FAIL")
    assert first.json() == again_same_key.json() and again_new_key.json()["replayed"] is True
    conflicting = api.submit_audit(a, "FAIL", expect=None, findings=[api.finding(9)])
    assert conflicting.status_code == 409 and code(conflicting) == "result_conflict"
    task = api.get_task(t["id"])
    assert task["failed_review_count"] == 1 and task["status"] == "changes_requested"
    assert api.count(Report, Report.kind == "audit") == 1 and api.count(Finding) == 1
    assert sorted(j.stage for j in api.jobs(t["id"])) == ["audit", "implement", "implement"]  # exactly one fix job
    # a late duplicate with a stale run guard after the fix job exists changes nothing either
    assert api.get_task(t["id"])["failed_review_count"] == 1


def test_q11_three_fails_block_with_restart_between_and_no_fourth_job(api: Api):
    t = api.queued_task()
    cur = api
    for n in (1, 2, 3):
        cur.implement(variant=f"v{n}")
        cur.audit("FAIL", findings=[cur.finding(n)])
        if n == 1:
            cur = cur.restart()  # server restart between FAILs: the counter is durable
            assert cur.get_task(t["id"])["failed_review_count"] == 1
    task = cur.get_task(t["id"])
    assert (task["status"], task["blocked_reason"], task["failed_review_count"]) == ("blocked", "iteration_limit", 3)
    assert cur.claim("impl", expect=204).status_code == 204
    assert cur.claim("aud", "audit", expect=204).status_code == 204
    jobs = cur.jobs(t["id"])
    assert sorted(j.stage for j in jobs).count("implement") == 3 and not [j for j in jobs if j.status == "ready"]
    # no way around the budget: plain resume and revise are refused, nothing is issued
    assert cur.control(t["id"], "resume").status_code == 409
    assert code(cur.control(t["id"], "resume")) == "budget_decision_required"
    r = cur.control(t["id"], "revise", revision={"requirements": "try something else"})
    assert r.status_code == 409 and code(r) == "budget_decision_required"
    assert cur.claim("impl", expect=204).status_code == 204 and len(cur.jobs(t["id"])) == 6
    ev = [e for e in cur.events() if e["type"] == "task.status_changed" and e["data"].get("blocked_reason")][-1]
    assert ev["data"]["blocked_reason"] == "iteration_limit" and ev["data"]["failed_review_count"] == 3


def test_owner_limit_of_two_failed_reviews(api: Api):
    t = api.queued_task(max_failed_reviews=2)
    for n in (1, 2):
        api.implement(variant=f"v{n}")
        api.audit("FAIL", findings=[api.finding(n)])
    task = api.get_task(t["id"])
    assert (task["status"], task["blocked_reason"], task["failed_review_count"]) == ("blocked", "iteration_limit", 2)
    assert api.claim("impl", expect=204).status_code == 204


# =============================================================================== Q13 loop detector


def test_q13_same_invariant_and_diff_twice_blocks_immediately(api: Api):
    t = api.queued_task()
    api.implement(variant="same")
    api.audit("FAIL", findings=[api.finding(1, reproduction="step at a.py:10")])
    api.implement(variant="same")  # fix attempt produced the identical diff
    api.audit("FAIL", findings=[api.finding(1, reproduction="step at a.py:99")])  # different line number, same defect
    task = api.get_task(t["id"])
    assert (task["status"], task["blocked_reason"], task["failed_review_count"]) == ("blocked", "loop_detected", 2)
    ev = [e for e in api.events() if e["data"].get("blocked_reason") == "loop_detected"][0]["data"]
    assert ev["loop"]["rule"] == "same_invariant_same_diff" and ev["loop"]["diff_hash"]
    assert "recommended_action" in ev
    assert api.claim("impl", expect=204).status_code == 204
    # fingerprint ignored the changed line number: one lineage for both findings
    with api.db() as s:
        fs = s.execute(select(Finding)).scalars().all()
    assert len(fs) == 2 and fs[0].fingerprint == fs[1].fingerprint and fs[0].lineage_id == fs[1].lineage_id


def test_q13_same_invariant_after_two_fix_attempts_blocks_even_if_diff_changes(api: Api):
    t = api.queued_task()
    for n, v in enumerate(("v1", "v2", "v3"), start=1):
        api.implement(variant=v)
        api.audit("FAIL", findings=[api.finding(1)])
        if n < 3:
            assert api.get_task(t["id"])["status"] == "changes_requested"
    task = api.get_task(t["id"])
    assert (task["status"], task["blocked_reason"]) == ("blocked", "loop_detected")  # beats iteration_limit
    ev = [e for e in api.events() if e["data"].get("blocked_reason") == "loop_detected"][0]["data"]
    assert ev["loop"]["rule"] == "same_invariant_after_two_fixes"


def test_q13_aba_state_cycle_blocks(api: Api):
    t = api.queued_task()
    for n, v in enumerate(("A", "B", "A"), start=1):
        api.implement(variant=v)
        api.audit("FAIL", findings=[api.finding(n)])  # different invariants each time
    task = api.get_task(t["id"])
    assert (task["status"], task["blocked_reason"]) == ("blocked", "loop_detected")
    ev = [e for e in api.events() if e["data"].get("blocked_reason") == "loop_detected"][0]["data"]
    assert ev["loop"]["rule"] == "state_cycle_aba"


# =============================================================================== Q15 spoof / self review


def test_q15_executor_cannot_spoof_approve_or_review_itself(api: Api):
    t = api.queued_task()
    c = api.claim("impl")
    api.start("impl", c)
    # implementer may not use audit routes or another principal's run
    r = api.req("impl", "POST", api.p(f"/runs/{c['run_id']}/audit-result"), api.audit_payload({**c, "input_snapshot": {"id": uid()}}, "PASS"))
    assert r.status_code == 409 and code(r) == "wrong_stage"
    # auditor cannot drive the implementer's run (404: no existence leak)
    assert api.req("aud", "POST", api.p(f"/runs/{c['run_id']}/implementation-result"), api.impl_payload(c)).status_code == 404
    assert api.req("aud", "POST", api.p(f"/runs/{c['run_id']}/heartbeat"), api.guard(c)).status_code == 404
    assert api.req("aud", "POST", api.p(f"/runs/{c['run_id']}/start"), api.guard(c)).status_code == 404
    # nobody but the owner / a delegated coordinator controls tasks
    for who in ("impl", "aud"):
        assert api.req(who, "POST", api.p(f"/tasks/{t['id']}/controls"), {"command": "cancel", "reason": "x"}, if_match=3).status_code == 403
    assert api.req("impl", "POST", api.p("/controls"), {"command": "pause", "reason": "x"}).status_code == 403
    # executors cannot act as supervisors either (no forged stop receipts)
    assert api.req("impl", "POST", api.p(f"/runs/{c['run_id']}/stopped"), {"control_id": uid(), "target_epoch": 1, "process_tree_absent": True}).status_code == 403
    assert api.req("impl", "POST", api.p(f"/runs/{c['run_id']}/reconcile"), {"process_tree_absent": True, "workspace_quarantined": True}).status_code == 403
    assert api.req("impl", "POST", api.p(f"/jobs/{uid()}/dispatch"), if_match=1).status_code == 403
    # self-review: even if the auditor slot were forced onto the implementer principal, claim refuses
    api.submit_impl(c)
    with api.app.state.engine.begin() as conn:  # type: ignore[attr-defined]
        conn.exec_driver_sql("UPDATE tasks SET implementer_id = ?", (api.aud_id,))
    r = api.claim("aud", "audit", expect=None)
    assert r.status_code == 403 and code(r) == "self_review_forbidden"
    assert api.get_task(t["id"])["status"] == "awaiting_review"
    assert api.count(Run, Run.status == "leased") == 0


# =============================================================================== Q16 / Q17 audit binding


def test_q16_wrong_snapshot_revision_epoch_or_policy_rejected(api: Api):
    t, a = to_reviewing(api)
    other = api.create_task(title="other")
    api.enqueue(other)
    api.implement()  # snapshot of another task
    with api.db() as s:
        foreign = s.execute(select(Snapshot).where(Snapshot.task_id == other["id"])).scalar_one().id
    cases = [
        ({"snapshot_id": uid()}, "snapshot_mismatch"),
        ({"snapshot_id": foreign}, "snapshot_mismatch"),
        ({"revision": 2}, "revision_mismatch"),
        ({"lease_epoch": 2}, "stale_epoch"),
        ({"policy_digest": "0" * 64}, "policy_digest_mismatch"),
    ]
    for over, expected in cases:
        r = api.submit_audit(a, "PASS", expect=None, **over)
        assert r.status_code == 409 and code(r) == expected, (over, r.text)
    assert api.get_task(t["id"])["status"] == "reviewing" and api.count(Report, Report.kind == "audit") == 0
    assert api.submit_audit(a, "PASS").json()["task"]["status"] == "completed"


def test_q16_new_revision_requires_a_new_audit(api: Api):
    t, a = to_reviewing(api)
    r = api.control(t["id"], "revise", expect=202, revision={"requirements": "Different goal."})
    assert r.json()["task"]["status"] == "stop_requested"
    # the in-flight audit of revision 1 can no longer close anything
    stale = api.submit_audit(a, "PASS", expect=None)
    assert stale.status_code == 409 and code(stale) == "stale_epoch"
    api.make_runner()
    api.stopped(a, r.json()["control"])
    task = api.get_task(t["id"])
    assert (task["status"], task["revision"], task["failed_review_count"]) == ("queued", 2, 0)
    old_digest = a["policy_digest"]
    c2 = api.claim("impl")
    assert c2["revision"] == 2 and c2["policy_digest"] != old_digest
    api.start("impl", c2)
    api.submit_impl(c2, variant="rev2")
    a2 = api.claim("aud", "audit")
    assert a2["revision"] == 2 and a2["input_snapshot"]["id"] != a["input_snapshot"]["id"]
    api.start("aud", a2)
    # revision-1 snapshot / digest cannot be smuggled into the revision-2 audit
    assert api.submit_audit(a2, "PASS", expect=None, snapshot_id=a["input_snapshot"]["id"]).status_code == 409
    assert api.submit_audit(a2, "PASS", expect=None, revision=1, policy_digest=old_digest).status_code == 409
    assert api.submit_audit(a2, "PASS").json()["task"]["status"] == "completed"
    audits = [r_ for r_ in api.req("owner", "GET", api.p(f"/tasks/{t['id']}")).json()["links"]["reports"] if r_["kind"] == "audit"]
    assert [(r_["revision"], r_["verdict"]) for r_ in audits] == [(2, "PASS")]


def test_idle_revise_cancels_pending_audit_job(api: Api):
    t = api.queued_task()
    api.implement()  # awaiting_review, audit job ready
    r = api.control(t["id"], "revise", expect=200, revision={"acceptance": ["new acceptance"]})
    assert r.json()["task"]["status"] == "queued" and r.json()["task"]["revision"] == 2
    jobs = sorted(api.jobs(t["id"]), key=lambda j: (j.revision, j.stage))
    assert [(j.revision, j.stage, j.status) for j in jobs] == [(1, "audit", "cancelled"), (1, "implement", "succeeded"), (2, "implement", "ready")]
    assert api.claim("aud", "audit", expect=204).status_code == 204  # stale audit is gone


def test_q17_pass_with_not_run_required_check_is_rejected(api: Api):
    t, a = to_reviewing(api)
    bad = [{"id": "c1", "command_label": "pytest", "status": "pass"}, {"id": "c2", "command_label": "e2e", "status": "not_run"}]
    r = api.submit_audit(a, "PASS", expect=None, checks=bad)
    assert r.status_code == 422 and code(r) == "pass_requires_evidence"
    assert r.json()["error"]["details"]["checks"] == [{"id": "c2", "status": "not_run"}]
    for checks in ([], [{"id": "c1", "command_label": "pytest", "status": "not_verified"}],
                   [{"id": "c1", "command_label": "pytest", "status": "fail"}]):
        assert api.submit_audit(a, "PASS", expect=None, checks=checks).status_code == 422
    assert api.submit_audit(a, "PASS", expect=None, evidence_level="DESIGN").status_code == 422
    assert api.submit_audit(a, "PASS", expect=None, findings=[api.finding(1)]).status_code == 422
    assert api.get_task(t["id"])["status"] == "reviewing" and api.count(Report, Report.kind == "audit") == 0
    # a non-required check may be not_run: allowed
    ok = api.submit_audit(a, "PASS", expect=None, checks=[
        {"id": "c1", "command_label": "pytest", "status": "pass"},
        {"id": "c2", "command_label": "optional", "status": "not_run", "required": False}])
    assert ok.status_code == 200 and ok.json()["task"]["status"] == "completed"


def test_inconclusive_blocks_without_counting_and_fail_needs_evidence(api: Api):
    t, a = to_reviewing(api)
    assert api.submit_audit(a, "FAIL", expect=None, findings=[]).status_code == 422  # no reproducible defect
    assert api.submit_audit(a, "FAIL", expect=None, findings=[api.finding(1, severity="S2")]).status_code == 422
    assert api.submit_audit(a, "INCONCLUSIVE", expect=None, limitations=[]).status_code == 422
    r = api.submit_audit(a, "INCONCLUSIVE")
    task = r.json()["task"]
    assert (task["status"], task["blocked_reason"], task["failed_review_count"]) == ("blocked", "verification_unavailable", 0)
    assert api.claim("aud", "audit", expect=204).status_code == 204
    # explicit resume re-issues an audit job on the SAME snapshot
    assert api.control(t["id"], "resume").status_code == 200
    a2 = api.claim("aud", "audit")
    assert a2["input_snapshot"]["id"] == a["input_snapshot"]["id"] and a2["run_id"] != a["run_id"]


# =============================================================================== Q07 / Q09 / Q10 / Q35 controls


def test_q07_stale_run_result_after_cancel_is_rejected(api: Api):
    t = api.queued_task()
    c = api.claim("impl")
    api.start("impl", c)
    r = api.control(t["id"], "cancel", expect=202)
    ctl = r.json()["control"]
    assert ctl["status"] == "stopping" and r.json()["task"]["status"] == "stop_requested"
    res = api.submit_impl(c, expect=None)
    assert res.status_code == 409 and code(res) == "stale_epoch"
    assert api.get_task(t["id"])["status"] == "stop_requested" and api.count(Report) == 0
    api.make_runner()
    assert api.stopped(c, ctl).json()["task"]["status"] == "cancelled"
    res = api.submit_impl(c, expect=None)
    assert res.status_code == 409 and api.count(Report) == 0
    assert api.get_task(t["id"])["status"] == "cancelled"
    assert api.req("owner", "GET", api.p(f"/controls/{ctl['id']}")).json()["status"] == "confirmed"
    assert api.claim("impl", expect=204).status_code == 204  # cancelled work is never re-issued
    assert api.count(Job, Job.status == "ready") == 0


def test_q09_pause_fences_old_lease_and_resume_does_not_revive_it(api: Api):
    t = api.queued_task()
    c = api.claim("impl")
    api.start("impl", c)
    r = api.control(t["id"], "pause", expect=202)
    ctl = r.json()["control"]
    hb = api.heartbeat("impl", c).json()  # runner learns about the stop through the heartbeat
    assert hb["status"] == "stopping" and hb["pending_control"] == {
        "control_id": ctl["id"], "command": "pause", "target_epoch": c["lease_epoch"]}
    assert api.submit_impl(c, expect=None).status_code == 409
    # only a registered supervisor (not the lease holder) can confirm
    assert api.req("impl", "POST", api.p(f"/runs/{c['run_id']}/stopped"), {"control_id": ctl["id"], "target_epoch": 1, "process_tree_absent": True}).status_code == 403
    api.make_runner()
    assert api.stopped(c, ctl, expect=None, target_epoch=7).status_code == 409  # wrong epoch
    assert api.stopped(c, ctl).json()["task"]["status"] == "paused"
    assert api.claim("impl", expect=204).status_code == 204  # paused work is not issued
    assert api.control(t["id"], "resume").status_code == 200
    new = api.claim("impl")
    assert new["run_id"] != c["run_id"] and new["job_id"] != c["job_id"]
    assert api.heartbeat("impl", c, expect=None).status_code == 409  # old lease stays dead
    assert api.submit_impl(c, expect=None).status_code == 409
    assert api.start("impl", new).status_code == 200


def test_q10_stop_with_absent_runner_is_unknown_not_stopped(api: Api):
    t = api.queued_task()
    c = api.claim("impl")
    api.start("impl", c)
    ctl = api.control(t["id"], "cancel", expect=202).json()["control"]
    api.clock.advance(seconds=91)  # runner vanished: no heartbeat, no receipt
    api.claim("impl", expect=204)  # any lifecycle call runs the lease sweep
    task = api.get_task(t["id"])
    assert (task["status"], task["blocked_reason"]) == ("blocked", "stop_unknown")
    assert api.req("owner", "GET", api.p(f"/controls/{ctl['id']}")).json()["status"] == "unknown"
    assert api.count(Run, Run.status == "lost") == 1
    stop_events = [e for e in api.events() if e["type"] == "task.status_changed" and e["data"]["status"] == "cancelled"]
    assert stop_events == []  # never claimed a physical stop we did not observe
    assert any(e["type"] == "control.unknown" or e["data"].get("quarantine_required") for e in api.events())
    # no automatic re-issue, even for resume
    assert api.control(t["id"], "resume").status_code == 409
    api.make_runner()
    r = api.req("runner", "POST", api.p(f"/runs/{c['run_id']}/reconcile"), {"process_tree_absent": True, "workspace_quarantined": False})
    assert r.status_code == 200 and r.json()["outcome"] == "still_blocked"
    r = api.req("runner", "POST", api.p(f"/runs/{c['run_id']}/reconcile"), {"process_tree_absent": True, "workspace_quarantined": True})
    assert r.json()["outcome"] == "paused_ready_to_resume" and api.get_task(t["id"])["status"] == "paused"


def test_q10_runner_alive_but_never_confirms_hits_stop_deadline(api: Api):
    t = api.queued_task()
    c = api.claim("impl")
    api.start("impl", c)
    ctl = api.control(t["id"], "pause", expect=202).json()["control"]
    api.clock.advance(seconds=30)
    api.heartbeat("impl", c)
    api.clock.advance(seconds=31)  # 61s > deadline although heartbeats keep the lease alive
    api.heartbeat("impl", c)
    assert api.req("owner", "GET", api.p(f"/controls/{ctl['id']}")).json()["status"] == "unknown"
    assert api.get_task(t["id"])["blocked_reason"] == "stop_unknown"
    # a late but real supervisor receipt resolves it (task -> paused), still no revival of the lease
    api.make_runner()
    assert api.stopped(c, ctl).json()["task"]["status"] == "paused"


def test_stopped_receipt_with_process_still_present_marks_unknown(api: Api):
    t = api.queued_task()
    c = api.claim("impl")
    api.start("impl", c)
    ctl = api.control(t["id"], "cancel", expect=202).json()["control"]
    api.make_runner()
    r = api.stopped(c, ctl, absent=False)
    assert r.json()["outcome"] == "unknown"
    task = api.get_task(t["id"])
    assert (task["status"], task["blocked_reason"]) == ("blocked", "stop_unknown")


def test_q08_lease_expiry_blocks_without_second_writer_until_reconcile(api: Api):
    t = api.queued_task()
    c = api.claim("impl")
    api.start("impl", c)
    api.clock.advance(seconds=89)
    assert api.heartbeat("impl", c).status_code == 200  # heartbeat renews the full TTL
    api.clock.advance(seconds=89)
    assert api.heartbeat("impl", c).status_code == 200
    api.clock.advance(seconds=91)  # silent for > TTL
    r = api.heartbeat("impl", c, expect=None)
    assert r.status_code == 409 and code(r) == "run_not_active"
    task = api.get_task(t["id"])
    assert (task["status"], task["blocked_reason"]) == ("blocked", "recovery_required")
    assert api.submit_impl(c, expect=None).status_code == 409
    assert api.claim("impl", expect=204).status_code == 204  # NO second writer
    assert api.count(Job, Job.status == "ready") == 0 and api.count(Run, Run.status.in_(["leased", "running"])) == 0
    r = api.control(t["id"], "resume")
    assert r.status_code == 409 and code(r) == "reconcile_required"
    # a revision cannot sidestep the lost run either
    assert code(api.control(t["id"], "revise", revision={"requirements": "x"})) == "reconcile_required"
    api.make_runner()
    assert api.req("runner", "POST", api.p(f"/runs/{c['run_id']}/reconcile"), {"process_tree_absent": True, "workspace_quarantined": True}).status_code == 200
    assert api.get_task(t["id"])["status"] == "paused"
    assert api.claim("impl", expect=204).status_code == 204  # reconcile alone does not re-issue
    assert api.control(t["id"], "resume").status_code == 200
    new = api.claim("impl")
    assert new["run_id"] != c["run_id"]
    with api.db() as s:
        assert s.execute(select(Job.runtime_retry_count).where(Job.id == new["job_id"])).scalar_one() == 1
    assert api.submit_impl(c, expect=None).status_code == 409  # the lost run never revives
    assert api.start("impl", new).status_code == 200


def test_restart_reconciliation_marks_expired_leases_lost_without_reissue(api: Api):
    t = api.queued_task()
    c = api.claim("impl")
    api.start("impl", c)
    api.clock.advance(seconds=120)
    api2 = api.restart()  # startup recovery runs before any request
    with api2.db() as s:
        assert s.execute(select(Run.status).where(Run.id == c["run_id"])).scalar_one() == "lost"
    task = api2.get_task(t["id"])
    assert (task["status"], task["blocked_reason"]) == ("blocked", "recovery_required")
    assert api2.claim("impl", expect=204).status_code == 204
    # leases that are still valid survive a restart untouched
    t2 = api2.queued_task(title="second")
    c2 = api2.claim("impl")
    api2.start("impl", c2)
    api3 = api2.restart()
    assert api3.heartbeat("impl", c2).status_code == 200
    assert api3.get_task(t2["id"])["status"] == "running"


def test_q34_paused_project_issues_no_work_and_restart_keeps_the_pause(api: Api):
    r = api.req("owner", "POST", api.p("/controls"), {"command": "pause", "reason": "maintenance"})
    assert r.status_code == 200 and r.json()["project"]["paused"] is True
    hi = api.queued_task(title="urgent", urgency="high")
    r = api.claim("impl", expect=None)
    assert r.status_code == 409 and code(r) == "project_paused" and r.json()["error"]["retryable"] is True
    api2 = api.restart()
    assert api2.req("owner", "GET", api2.p()).json()["paused"] is True
    assert api2.claim("impl", expect=None).status_code == 409
    assert api2.get_task(hi["id"])["status"] == "queued" and api2.count(Run) == 0
    # explicit resume only
    api2.req("owner", "POST", api2.p("/controls"), {"command": "resume", "reason": "done"})
    assert api2.claim("impl")["task_id"] == hi["id"]


def test_project_pause_stops_active_runs_and_emergency_stop_hits_every_project(api: Api):
    t = api.queued_task()
    c = api.claim("impl")
    api.start("impl", c)
    p2 = api.req("owner", "POST", "/api/v1/projects", {"slug": "second", "name": "Second"}).json()
    r = api.req("owner", "POST", "/api/v1/controls/emergency-stop", {"reason": "panic"})
    assert r.status_code == 202
    body = r.json()
    assert {p["id"] for p in body["projects"]} == {api.project_id, p2["id"]} and all(p["paused"] for p in body["projects"])
    by_project = {c_["project_id"]: c_ for c_ in body["controls"]}
    assert by_project[api.project_id]["status"] == "stopping" and by_project[p2["id"]]["status"] == "confirmed"
    assert by_project[api.project_id]["command"] == "emergency_stop"
    assert api.get_task(t["id"])["status"] == "stop_requested"
    assert api.submit_impl(c, expect=None).status_code == 409
    assert api.claim("impl", expect=None).status_code == 409
    api.make_runner()
    ctl = api.heartbeat("impl", c).json()["pending_control"]
    api.stopped(c, {"id": ctl["control_id"]})
    assert api.get_task(t["id"])["status"] == "paused"
    parent = api.req("owner", "GET", api.p(f"/controls/{by_project[api.project_id]['id']}")).json()
    assert parent["status"] == "confirmed"  # parent settles once every child is confirmed
    # resume is explicit: project first, which also resumes the paused task
    assert api.req("owner", "POST", api.p("/controls"), {"command": "resume", "reason": "ok"}).status_code == 200
    assert api.get_task(t["id"])["status"] == "queued"
    assert api.claim("impl")["run_id"] != c["run_id"]
    assert api.req("aud", "POST", "/api/v1/controls/emergency-stop", {"reason": "x"}).status_code == 403


def test_q35_cancel_vs_result_serializes_to_one_outcome(api: Api):
    outcomes = set()
    api.make_runner()
    for _ in range(6):
        t = api.queued_task()
        c = api.claim("impl")
        api.start("impl", c)
        version = api.get_task(t["id"])["version"]
        impl = api.client_for_key(api.keys["impl"])
        res, ctl = parallel(
            lambda: api.req(impl, "POST", api.p(f"/runs/{c['run_id']}/implementation-result"), api.impl_payload(c)),
            lambda: api.req(api.owner_client(), "POST", api.p(f"/tasks/{t['id']}/controls"),
                            {"command": "cancel", "reason": "race"}, if_match=version, headers={"X-CSRF-Token": api.csrf}),
        )
        task = api.get_task(t["id"])
        reports = api.count(Report, Report.task_id == t["id"])
        if res.status_code == 200:
            # result won: the audit job existed, cancel then ran against an idle task (or lost on version)
            assert ctl.status_code in (200, 412) and reports == 1
            assert task["status"] in ("cancelled", "awaiting_review")
            outcomes.add("result_first")
        else:
            assert res.status_code == 409 and ctl.status_code == 202 and reports == 0
            assert task["status"] == "stop_requested"
            outcomes.add("cancel_first")
        # clean slate for the next iteration: cancel whatever is left
        if task["status"] == "stop_requested":
            api.stopped(c, ctl.json()["control"])
        elif task["status"] == "awaiting_review":
            api.control(t["id"], "cancel", expect=200)
        assert api.get_task(t["id"])["status"] == "cancelled"
        assert api.count(Run, Run.status.in_(["leased", "running", "stopping"])) == 0
    assert outcomes  # invariants held for every serialisation observed (which one wins may vary)


def test_q35_revoke_vs_heartbeat_and_revise_vs_pass(api: Api):
    # revoke vs heartbeat
    t = api.queued_task()
    c = api.claim("impl")
    api.start("impl", c)
    cred = next(a["credential_id"] for a in api.env.creds["agents"] if a["principal_id"] == api.impl_id)
    impl = api.client_for_key(api.keys["impl"])
    hb, rv = parallel(
        lambda: api.req(impl, "POST", api.p(f"/runs/{c['run_id']}/heartbeat"), api.guard(c)),
        lambda: api.req("owner", "POST", f"/api/v1/agents/{api.impl_id}/keys/{cred}/revoke", None, headers={"X-CSRF-Token": api.csrf}),
    )
    assert rv.status_code == 200 and rv.json()["fenced_runs"] == 1
    assert hb.status_code in (200, 401, 409)
    assert api.req(impl, "POST", api.p(f"/runs/{c['run_id']}/heartbeat"), api.guard(c)).status_code == 401
    task = api.get_task(t["id"])
    assert (task["status"], task["blocked_reason"]) == ("blocked", "auth_required")
    assert api.count(Run, Run.status.in_(["leased", "running", "stopping"])) == 0


def test_q35_revise_vs_audit_pass_has_one_outcome(api: Api):
    t, a = to_reviewing(api)
    version = api.get_task(t["id"])["version"]
    aud = api.client_for_key(api.keys["aud"])
    res, rev = parallel(
        lambda: api.req(aud, "POST", api.p(f"/runs/{a['run_id']}/audit-result"), api.audit_payload(a, "PASS")),
        lambda: api.req(api.owner_client(), "POST", api.p(f"/tasks/{t['id']}/controls"),
                        {"command": "revise", "reason": "race", "revision": {"requirements": "New goal"}},
                        if_match=version, headers={"X-CSRF-Token": api.csrf}),
    )
    task = api.get_task(t["id"])
    if res.status_code == 200:
        assert task["status"] == "completed" and task["revision"] == 1 and rev.status_code in (409, 412)
    else:
        assert rev.status_code == 202 and res.status_code == 409
        assert task["status"] == "stop_requested" and api.count(Report, Report.kind == "audit") == 0


# =============================================================================== dispatch / heartbeat / fail / scope


def test_non_autonomous_jobs_need_a_one_shot_dispatch_for_every_stage(api: Api):
    t = api.queued_task(autonomous=False)
    assert api.claim("impl", expect=204).status_code == 204
    job = api.get_task(t["id"])["links"]["jobs"][0]
    assert job["dispatch_authorized"] is False
    path = api.p(f"/jobs/{job['id']}/dispatch")
    ver = api.get_task(t["id"])["version"]
    assert api.req("owner", "POST", path).status_code == 428
    assert api.req("owner", "POST", path, if_match=ver + 3).status_code == 412
    r = api.req("owner", "POST", path, if_match=ver)
    assert r.status_code == 200 and r.json()["dispatch_authorized"] is True
    assert api.req("owner", "POST", path, if_match=r.json()["task_version"]).status_code == 409  # one-shot
    api.implement()
    assert api.claim("aud", "audit", expect=204).status_code == 204  # new job => new dispatch needed
    audit_job = [j for j in api.get_task(t["id"])["links"]["jobs"] if j["stage"] == "audit"][0]
    ver = api.get_task(t["id"])["version"]
    assert api.req("owner", "POST", api.p(f"/jobs/{audit_job['id']}/dispatch"), if_match=ver).status_code == 200
    assert api.claim("aud", "audit")["job_id"] == audit_job["id"]
    # autonomous tasks never need it
    t2 = api.queued_task(title="auto")
    j2 = api.get_task(t2["id"])["links"]["jobs"][0]
    r = api.req("owner", "POST", api.p(f"/jobs/{j2['id']}/dispatch"), if_match=api.get_task(t2["id"])["version"])
    assert r.status_code == 409 and code(r) == "dispatch_not_required"


def test_runtime_failure_has_own_budget_and_never_counts_as_review_fail(api: Api):
    t = api.queued_task()
    for attempt in (1, 2):
        c = api.claim("impl")
        api.start("impl", c)
        r = api.req("impl", "POST", api.p(f"/runs/{c['run_id']}/fail"), {**api.guard(c), "error_code": "provider_5xx", "retryable": True, "evidence": "boom"})
        assert r.status_code == 200 and r.json()["outcome"] == "retry_scheduled"
        task = api.get_task(t["id"])
        assert (task["status"], task["failed_review_count"]) == ("queued", 0)
    c = api.claim("impl")
    api.start("impl", c)
    r = api.req("impl", "POST", api.p(f"/runs/{c['run_id']}/fail"), {**api.guard(c), "error_code": "provider_5xx", "retryable": True})
    assert r.json()["outcome"] == "blocked"
    task = api.get_task(t["id"])
    assert (task["status"], task["blocked_reason"], task["failed_review_count"]) == ("blocked", "runtime_failure", 0)
    assert api.claim("impl", expect=204).status_code == 204
    assert code(api.control(t["id"], "resume")) == "runtime_retry_limit"  # resetting by new jobs is impossible
    with api.db() as s:
        assert sorted(s.execute(select(Job.runtime_retry_count)).scalars().all()) == [0, 1, 2]


def test_fail_error_codes_map_to_specific_blockers(api: Api):
    for err, reason in (("auth_required", "auth_required"), ("quota", "quota"), ("anything", "runtime_failure")):
        t = api.queued_task(title=err)
        c = api.claim("impl")
        api.start("impl", c)
        r = api.req("impl", "POST", api.p(f"/runs/{c['run_id']}/fail"), {**api.guard(c), "error_code": err, "retryable": False})
        assert r.status_code == 200
        assert api.get_task(t["id"])["blocked_reason"] == reason
    bad = api.req("impl", "POST", api.p(f"/runs/{uid()}/fail"), {"lease_epoch": 1, "revision": 1, "policy_digest": "0" * 64, "error_code": "x", "retryable": False})
    assert bad.status_code == 404


def test_start_and_heartbeat_guards(api: Api):
    t = api.queued_task()
    c = api.claim("impl")
    for over in ({"lease_epoch": 9}, {"revision": 2}, {"policy_digest": "f" * 64}):
        assert api.start("impl", c, expect=None, **over).status_code == 409
        assert api.heartbeat("impl", c, expect=None, **over).status_code == 409
    assert api.req("impl", "POST", api.p(f"/runs/{c['run_id']}/start"), {**api.guard(c), "extra": 1}).status_code == 422
    assert api.req("impl", "POST", api.p(f"/runs/{c['run_id']}/start"), {"lease_epoch": 0, "revision": 1, "policy_digest": c["policy_digest"]}).status_code == 422
    assert api.get_task(t["id"])["status"] == "claimed"
    assert api.submit_impl(c, expect=None).status_code == 409  # cannot report before start
    api.start("impl", c)
    assert api.start("impl", c).status_code == 200  # idempotent
    assert statuses(api, t["id"]).count("running") == 1
    # leased-but-never-started runs expire like any other lease
    t2 = api.queued_task(title="never started")
    c2 = api.claim("impl", runner="r2")
    api.clock.advance(seconds=91)
    assert api.start("impl", c2, expect=None).status_code == 409
    assert api.get_task(t2["id"])["blocked_reason"] == "recovery_required"


def test_scope_violation_is_quarantined_not_accepted(api: Api):
    t = api.queued_task()
    c = api.claim("impl")
    api.start("impl", c)
    bad_manifest = {"changed_files": [{"path": "src/app.py", "change": "modified"}, {"path": "src/secret/key.pem", "change": "added"}],
                    "diff_lines": 10, "new_dependencies": []}
    r = api.submit_impl(c, expect=None, scope_manifest=bad_manifest)
    assert r.status_code == 409 and code(r) == "scope_violation"
    assert {"kind": "path_not_allowed", "detail": "src/secret/key.pem"} in r.json()["error"]["details"]["violations"]
    task = api.get_task(t["id"])
    assert (task["status"], task["blocked_reason"]) == ("blocked", "scope_change_required")
    assert api.count(Report) == 0 and api.count(Snapshot) == 0 and not [j for j in api.jobs(t["id"]) if j.stage == "audit"]
    assert api.claim("aud", "audit", expect=204).status_code == 204
    assert api.count(Run, Run.status == "failed") == 1
    # same quarantine for traversal-ish renames, binaries (surgical), symlinks, size and new dependencies
    for manifest in (
        {"changed_files": [{"path": "src/a.py", "change": "renamed", "renamed_from": "etc/passwd"}], "diff_lines": 1},
        {"changed_files": [{"path": "src/a.bin", "change": "added", "binary": True}], "diff_lines": 1},
        {"changed_files": [{"path": "src/link", "change": "added", "symlink": True}], "diff_lines": 1},
        {"changed_files": [{"path": "src/a.py", "change": "modified"}], "diff_lines": 201},
        {"changed_files": [{"path": "src/a.py", "change": "modified"}], "diff_lines": 1, "new_dependencies": ["left-pad"]},
        {"changed_files": [{"path": f"src/f{i}.py", "change": "added"} for i in range(6)], "diff_lines": 1},
        {"changed_files": [{"path": ".env.local", "change": "added"}], "diff_lines": 1},
    ):
        t2 = api.queued_task(title="x")
        c2 = api.claim("impl")
        api.start("impl", c2)
        assert api.submit_impl(c2, expect=None, scope_manifest=manifest).status_code == 409, manifest
        assert api.get_task(t2["id"])["blocked_reason"] == "scope_change_required"
    assert api.req("impl", "POST", api.p(f"/runs/{c['run_id']}/implementation-result"), {**api.impl_payload(c), "scope_manifest": {"changed_files": [{"path": "../x", "change": "added"}], "diff_lines": 1}}).status_code == 422


# =============================================================================== controls: reassign / revise / resume


def test_reassign_idle_task_moves_the_job_to_the_new_assignee(api: Api):
    t = api.queued_task()
    impl2, key2 = api.make_principal("implementer", "impl-2")
    r = api.control(t["id"], "reassign", expect=200, implementer_id=impl2)
    assert r.json()["task"]["assignees"]["implementer_id"] == impl2
    assert api.claim("impl", expect=204).status_code == 204  # old assignee gets nothing
    other = api.client_for_key(key2)
    got = api.req(other, "POST", api.p("/jobs/claim"), {"stage": "implement", "claim_request_id": uid(), "runner_instance_id": "r"})
    assert got.status_code == 200
    assert sorted((j.sequence, j.status) for j in api.jobs(t["id"])) == [(1, "cancelled"), (2, "leased")]
    # invalid assignee kinds are refused
    t2 = api.queued_task(title="b")
    assert api.control(t2["id"], "reassign", implementer_id=api.aud_id).status_code == 422
    assert api.control(t2["id"], "reassign", auditor_id=impl2).status_code == 422


def test_reassign_active_run_stops_first_then_issues_to_new_assignee(api: Api):
    t = api.queued_task()
    c = api.claim("impl")
    api.start("impl", c)
    impl2, key2 = api.make_principal("implementer", "impl-2")
    r = api.control(t["id"], "reassign", expect=202, implementer_id=impl2)
    assert api.req("impl", "POST", api.p("/jobs/claim"), {"stage": "implement", "claim_request_id": uid(), "runner_instance_id": "r"}).status_code == 204
    other = api.client_for_key(key2)
    # no new job before the old child is confirmed gone
    assert api.req(other, "POST", api.p("/jobs/claim"), {"stage": "implement", "claim_request_id": uid(), "runner_instance_id": "r"}).status_code == 204
    api.make_runner()
    api.stopped(c, r.json()["control"])
    task = api.get_task(t["id"])
    assert task["status"] == "queued" and task["assignees"]["implementer_id"] == impl2
    assert api.req(other, "POST", api.p("/jobs/claim"), {"stage": "implement", "claim_request_id": uid(), "runner_instance_id": "r"}).status_code == 200
    assert api.submit_impl(c, expect=None).status_code == 409


def test_coordinator_authority_is_rechecked_before_creating_a_new_job(api: Api):
    from datetime import UTC, datetime, timedelta

    cid, ckey = api.make_principal("coordinator", "coord")
    coord = api.client_for_key(ckey)
    until = (datetime.fromtimestamp(api.clock.now_ms() / 1000, tz=UTC) + timedelta(seconds=30)).isoformat()
    d = api.req("owner", "POST", api.p("/delegations"), {
        "coordinator_id": cid, "allowed_actions": ["task.create", "task.enqueue", "task.control"],
        "scope_ceiling": {"allowed_paths": ["src/**"], "max_changed_files": 5, "max_diff_lines": 200, "allow_autonomous": True},
        "valid_until": until}).json()
    task = api.req(coord, "POST", api.p("/tasks"), api.task_body(delegation_id=d["id"])).json()
    task = api.req(coord, "POST", api.p(f"/tasks/{task['id']}/enqueue"), if_match=task["version"]).json()
    c = api.claim("impl")
    api.start("impl", c)
    v = api.get_task(task["id"])["version"]
    controls = api.p(f"/tasks/{task['id']}/controls")
    # a coordinator can neither widen the scope nor change mode/autonomy
    wide = {"command": "revise", "reason": "x", "revision": {"scope": {**api.task_body()["scope"], "max_changed_files": 4, "allowed_paths": ["src/**", "docs/**"]}}}
    assert api.req(coord, "POST", controls, wide, if_match=v).status_code == 403
    mode = {"command": "revise", "reason": "x", "revision": {"mode": "creative"}}
    assert api.req(coord, "POST", controls, mode, if_match=v).status_code == 403
    narrow = {"command": "revise", "reason": "narrow", "revision": {"scope": {**api.task_body()["scope"], "max_changed_files": 2}}}
    r = api.req(coord, "POST", controls, narrow, if_match=v)
    assert r.status_code == 202
    api.clock.advance(seconds=31)  # the delegation expires while the old run is still stopping
    api.make_runner()
    api.stopped(c, r.json()["control"])
    final = api.get_task(task["id"])
    # expired authority: the pending revise is NOT applied and no new job is created
    assert (final["status"], final["revision"]) == ("paused", 1)
    assert api.count(Job, Job.status == "ready") == 0
    assert any(e["type"] == "control.authority_expired" for e in api.events())
    # and the coordinator can no longer drive the task at all
    assert api.req(coord, "POST", controls, {"command": "resume", "reason": "x"}, if_match=final["version"]).status_code == 403


def test_resume_cancel_and_terminal_rules(api: Api):
    t = api.queued_task()
    assert api.control(t["id"], "resume").status_code == 409  # not paused
    assert api.control(t["id"], "pause", expect=200).json()["task"]["status"] == "paused"
    assert api.control(t["id"], "pause").status_code == 409  # already paused
    assert api.count(Job, Job.status == "ready") == 0
    assert api.claim("impl", expect=204).status_code == 204
    assert api.control(t["id"], "resume", expect=200).json()["task"]["status"] == "queued"
    assert api.claim("impl")["task_id"] == t["id"]
    d = api.create_task(title="draft")
    assert api.control(d["id"], "cancel", expect=200).json()["task"]["status"] == "cancelled"
    assert code(api.control(d["id"], "pause")) == "task_terminal"
    assert api.control(d["id"], "revise", revision={"requirements": "x"}).status_code == 409
    # unknown / unsupported commands never reach the state machine
    v = api.get_task(t["id"])["version"]
    for body in ({"command": "emergency_stop", "reason": "x"}, {"command": "complete", "reason": "x"}, {"command": "pause"}):
        assert api.req("owner", "POST", api.p(f"/tasks/{t['id']}/controls"), body, if_match=v).status_code == 422
    assert api.req("owner", "POST", api.p(f"/tasks/{t['id']}/controls"), {"command": "pause", "reason": "x"}).status_code == 428
    assert api.req("owner", "POST", api.p(f"/tasks/{t['id']}/controls"), {"command": "pause", "reason": "x"}, if_match=v + 9).status_code == 412


def test_cancel_escalates_a_pending_pause(api: Api):
    t = api.queued_task()
    c = api.claim("impl")
    api.start("impl", c)
    pause = api.control(t["id"], "pause", expect=202).json()["control"]
    assert api.control(t["id"], "reassign", implementer_id=api.impl_id).status_code in (409, 422)  # stop in progress
    cancel = api.control(t["id"], "cancel", expect=202).json()["control"]
    api.make_runner()
    assert api.heartbeat("impl", c).json()["pending_control"]["command"] == "cancel"
    api.stopped(c, cancel)
    assert api.get_task(t["id"])["status"] == "cancelled"
    assert api.req("owner", "GET", api.p(f"/controls/{pause['id']}")).json()["status"] == "confirmed"


def test_cross_project_lifecycle_calls_are_404(api: Api):
    p2 = api.req("owner", "POST", "/api/v1/projects", {"slug": "second", "name": "Second"}).json()
    t = api.queued_task()
    other = f"/api/v1/projects/{p2['id']}"
    assert api.req("owner", "POST", f"{other}/tasks/{t['id']}/controls", {"command": "cancel", "reason": "x"}, if_match=1).status_code == 404
    assert api.req("owner", "POST", f"{other}/jobs/claim", {"stage": "implement", "claim_request_id": uid(), "runner_instance_id": "r"}).status_code == 403
    assert api.req("impl", "POST", f"{other}/jobs/claim", {"stage": "implement", "claim_request_id": uid(), "runner_instance_id": "r"}).status_code == 404
    c = api.claim("impl")
    assert api.req("owner", "POST", f"{other}/runs/{c['run_id']}/start", api.guard(c)).status_code == 404
    assert api.req("owner", "GET", f"{other}/reports/{uid()}").status_code == 404


# =============================================================================== restart durability


def test_state_machine_survives_restarts_midway(api: Api):
    t = api.queued_task()
    c = api.claim("impl")
    api2 = api.restart()
    api2.start("impl", c)
    api3 = api2.restart()
    api3.submit_impl(c)
    a = api3.restart().claim("aud", "audit")
    api4 = api3.restart()
    api4.start("aud", a)
    assert api4.submit_audit(a, "PASS").json()["task"]["status"] == "completed"
    assert statuses(api4, t["id"]) == ["queued", "claimed", "running", "awaiting_review", "reviewing", "completed"]
    assert api4.count(Task, Task.status == "completed") == 1
