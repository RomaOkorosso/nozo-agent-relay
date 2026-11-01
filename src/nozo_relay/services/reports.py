"""Validated implementation / audit results, report persistence, verdict -> transition mapping.

The server (not the reporter) derives the next task status from verdict + policy. PASS needs real
evidence bound to ``revision + snapshot_id + policy_digest``; FAIL counts exactly once per audit
run; the loop detector blocks repeated invariant/diff cycles (06_EXECUTION_PROTOCOL).
"""

from __future__ import annotations

import json
from typing import Any

from sqlalchemy import literal_column, select
from sqlalchemy.orm import Session

from nozo_relay.api.errors import RelayError
from nozo_relay.api.schemas import AuditResult, Check, FindingIn, ImplementationResult
from nozo_relay.auth.context import PrincipalContext
from nozo_relay.clock import Clock, ms_to_rfc3339
from nozo_relay.config import Settings
from nozo_relay.db.models import Artifact, Finding, Job, Project, Report, Run, Snapshot, Task, new_id
from nozo_relay.domain.enums import (
    BlockedReason,
    CheckStatus,
    EvidenceLevel,
    FindingSeverity,
    JobStage,
    JobStatus,
    ReportKind,
    RunStatus,
    TaskStatus,
    Verdict,
)
from nozo_relay.domain.fingerprints import (
    AuditRound,
    detect_loop,
    digest_of,
    finding_fingerprint,
    invariant_id,
)
from nozo_relay.services.common import (
    create_job,
    get_revision,
    set_job_status,
    set_run_status,
    set_task_status,
)
from nozo_relay.services.events import append_event
from nozo_relay.services.jobs import check_guard, conflict, load_owned_run
from nozo_relay.services.scope import path_matches, scope_violations  # noqa: F401 - re-exported
from nozo_relay.services.snapshots import mark_verified, store_snapshot
from nozo_relay.services.tasks import task_to_dict

BLOCKING = (FindingSeverity.S0, FindingSeverity.S1)


# ------------------------------------------------------------------ scope manifest


# ------------------------------------------------------------------ helpers


def _require_artifacts(ws: Session, project_id: str, ids: list[str]) -> None:
    wanted = set(ids)
    if not wanted:
        return
    found = set(
        ws.execute(select(Artifact.id).where(Artifact.project_id == project_id, Artifact.id.in_(wanted)))
        .scalars()
        .all()
    )
    if found != wanted:
        raise RelayError(422, "unknown_artifact", "evidence references an unknown artifact")


def _checks_json(checks: list[Check]) -> str:
    return json.dumps([c.model_dump(mode="json") for c in checks], sort_keys=True, separators=(",", ":"))


def _existing_report(ws: Session, run: Run, report_hash: str) -> Report | None:
    existing = ws.execute(select(Report).where(Report.run_id == run.id)).scalar_one_or_none()
    if existing is None:
        return None
    if existing.report_hash != report_hash:
        raise conflict("result_conflict", "A different result was already accepted for this run")
    return existing


def report_to_dict(ws: Session, report: Report) -> dict[str, Any]:
    findings = ws.execute(
        select(Finding).where(Finding.report_id == report.id).order_by(literal_column("findings.rowid"))
    ).scalars().all()
    snap = ws.get(Snapshot, report.snapshot_id) if report.snapshot_id else None
    return {
        "id": report.id,
        "task_id": report.task_id,
        "revision": report.revision,
        "run_id": report.run_id,
        "kind": report.kind,
        "verdict": report.verdict,
        "summary": report.summary,
        "checks": json.loads(report.checks_json),
        "blockers": json.loads(report.blockers_json),
        "evidence_level": report.evidence_level,
        "report_hash": report.report_hash,
        "created_at": ms_to_rfc3339(report.created_at),
        "snapshot": (
            {
                "id": snap.id,
                "revision": snap.revision,
                "tree_hash": snap.tree_hash,
                "diff_hash": snap.diff_hash,
                "verified_at": ms_to_rfc3339(snap.verified_at) if snap.verified_at else None,
            }
            if snap
            else None
        ),
        "findings": [
            {
                "id": f.id,
                "lineage_id": f.lineage_id,
                "fingerprint": f.fingerprint,
                "severity": f.severity,
                "status": f.status,
                "component": f.component,
                "invariant_key": f.invariant_key,
                "repro": json.loads(f.repro_json),
            }
            for f in findings
        ],
    }


def _receipt(ws: Session, report: Report, task: Task, *, replayed: bool = False) -> dict[str, Any]:
    next_job = ws.execute(
        select(Job.id, Job.stage)
        .where(Job.task_id == task.id, Job.status == JobStatus.READY.value)
        .limit(1)
    ).first()
    return {
        "report_id": report.id,
        "run_id": report.run_id,
        "kind": report.kind,
        "verdict": report.verdict,
        "replayed": replayed,
        "next_job": {"id": next_job[0], "stage": next_job[1]} if next_job else None,
        "task": task_to_dict(ws, task),
    }


# ------------------------------------------------------------------ implementation result


def submit_implementation_result(
    ws: Session,
    clock: Clock,
    principal: PrincipalContext,
    project: Project,
    run_id: str,
    dto: ImplementationResult,
) -> tuple[int, dict[str, Any]]:
    run, job, task = load_owned_run(ws, project, principal, run_id)
    if job.stage != JobStage.IMPLEMENT.value:
        raise conflict("wrong_stage", "This run is not an implementation run")
    report_hash = digest_of({"kind": ReportKind.IMPLEMENTATION.value, "run_id": run.id, "body": dto.model_dump(mode="json")})
    existing = _existing_report(ws, run, report_hash)
    if existing is not None:
        return 200, _receipt(ws, existing, task, replayed=True)
    check_guard(ws, clock, run, job, task, dto, statuses={RunStatus.RUNNING})
    _require_artifacts(ws, project.id, [*dto.artifacts, *(a for c in dto.checks for a in c.evidence_artifact_ids)])

    rev = get_revision(ws, task, job.revision)
    problems = scope_violations(json.loads(rev.scope_json), rev.mode, dto.scope_manifest)
    if problems:
        # Quarantine: output is NOT accepted, nothing is bound to a report/snapshot, task blocked.
        set_run_status(run, RunStatus.FAILED, clock, error_code="scope_violation")
        set_job_status(job, JobStatus.FAILED)
        task.resume_stage = JobStage.IMPLEMENT.value
        ws.flush()
        append_event(
            ws, clock, type="run.quarantined", project_id=project.id, task_id=task.id,
            entity_version=task.version, actor_id=principal.id,
            payload={"run_id": run.id, "violations": problems[:20]},
        )
        set_task_status(
            ws, clock, task, "runtime_fail", TaskStatus.BLOCKED, actor_id=principal.id,
            blocked_reason=BlockedReason.SCOPE_CHANGE_REQUIRED, payload={"run_id": run.id},
        )
        return 409, {
            "error": {
                "code": "scope_violation",
                "message": "Output is outside the task scope and was quarantined; owner revision required",
                "retryable": False,
                "details": {"violations": problems[:20], "task_status": task.status},
            }
        }

    snap = store_snapshot(ws, task, job.revision, principal.id, dto.snapshot)
    report = Report(
        task_id=task.id,
        revision=job.revision,
        run_id=run.id,
        snapshot_id=snap.id,
        kind=ReportKind.IMPLEMENTATION.value,
        verdict=None,
        summary=dto.summary,
        checks_json=_checks_json(dto.checks),
        blockers_json="[]",
        evidence_level="self_reported",
        report_hash=report_hash,
        created_at=clock.now_ms(),
    )
    ws.add(report)
    set_run_status(run, RunStatus.SUCCEEDED, clock)
    job.output_snapshot_id = snap.id
    set_job_status(job, JobStatus.SUCCEEDED)
    ws.flush()
    append_event(
        ws, clock, type="report.created", project_id=project.id, task_id=task.id,
        entity_version=task.version, actor_id=principal.id,
        payload={"report_id": report.id, "kind": report.kind, "snapshot_id": snap.id, "run_id": run.id},
    )
    set_task_status(
        ws, clock, task, "implementation_result", TaskStatus.AWAITING_REVIEW, actor_id=principal.id,
        payload={"report_id": report.id, "snapshot_id": snap.id},
    )
    create_job(ws, clock, task, rev, JobStage.AUDIT, input_snapshot_id=snap.id, actor_id=principal.id)
    return 200, _receipt(ws, report, task)


# ------------------------------------------------------------------ audit result


def _validate_audit_content(dto: AuditResult) -> None:
    required = [c for c in dto.checks if c.required]
    blocking = [f for f in dto.findings if f.severity in BLOCKING]
    if dto.verdict is Verdict.PASS:
        if dto.evidence_level is EvidenceLevel.DESIGN:
            raise RelayError(422, "pass_requires_evidence", "PASS needs evidence above DESIGN level")
        if not required:
            raise RelayError(
                422, "pass_requires_evidence", "PASS requires at least one required check with evidence"
            )
        bad = [{"id": c.id, "status": c.status.value} for c in required if c.status is not CheckStatus.PASS]
        if bad:
            raise RelayError(
                422,
                "pass_requires_evidence",
                "PASS is rejected while a required check is not_run / not_verified / failed",
                details={"checks": bad[:20]},
            )
        if blocking:
            raise RelayError(422, "pass_with_blocking_findings", "PASS cannot carry S0/S1 findings")
    elif dto.verdict is Verdict.FAIL:
        if not blocking:
            raise RelayError(
                422,
                "fail_requires_blocking_finding",
                "FAIL needs at least one reproducible S0/S1 finding; use INCONCLUSIVE without evidence",
            )
    else:
        if not dto.limitations:
            raise RelayError(422, "inconclusive_requires_limitations", "INCONCLUSIVE must list limitations")


def _audit_history(ws: Session, task: Task, revision: int) -> list[AuditRound]:
    """Previous accepted FAIL rounds of this revision, oldest first."""
    rows = ws.execute(
        select(Report.id, Snapshot.diff_hash, Snapshot.tree_hash)
        .join(Snapshot, Snapshot.id == Report.snapshot_id)
        .where(
            Report.task_id == task.id,
            Report.kind == ReportKind.AUDIT.value,
            Report.verdict == Verdict.FAIL.value,
            Report.revision == revision,
        )
        .order_by(literal_column("reports.rowid"))
    ).all()
    rounds: list[AuditRound] = []
    for report_id, diff_hash, tree_hash in rows:
        invs = frozenset(
            invariant_id(k, c)
            for k, c in ws.execute(
                select(Finding.invariant_key, Finding.component).where(
                    Finding.report_id == report_id, Finding.severity.in_([s.value for s in BLOCKING])
                )
            ).all()
        )
        rounds.append(AuditRound(invs, diff_hash, tree_hash))
    return rounds


def _insert_findings(
    ws: Session, task: Task, report: Report, findings: list[FindingIn]
) -> list[Finding]:
    rows: list[Finding] = []
    seen: set[str] = set()
    for f in findings:
        fp = finding_fingerprint(
            project_id=task.project_id,
            lineage=task.id,
            invariant_key=f.invariant_key,
            component=f.component,
            reproduction=f.reproduction,
            error_class=f.error_class,
        )
        if fp in seen:  # UNIQUE(report_id, fingerprint): server-computed, model cannot dodge it
            continue
        seen.add(fp)
        prior = ws.execute(
            select(Finding.lineage_id)
            .where(Finding.task_id == task.id, Finding.fingerprint == fp)
            .order_by(literal_column("findings.rowid"))
            .limit(1)
        ).scalar()
        rows.append(
            Finding(
                report_id=report.id,
                task_id=task.id,
                lineage_id=prior or new_id(),
                fingerprint=fp,
                severity=f.severity.value,
                status="open",
                component=f.component,
                invariant_key=f.invariant_key,
                repro_json=json.dumps(
                    {
                        "reproduction": f.reproduction,
                        "expected": f.expected,
                        "actual": f.actual,
                        "error_class": f.error_class,
                    },
                    sort_keys=True,
                ),
                evidence_json=json.dumps(f.evidence_artifact_ids),
            )
        )
    ws.add_all(rows)
    ws.flush()
    return rows


def submit_audit_result(
    ws: Session,
    clock: Clock,
    settings: Settings,  # noqa: ARG001 - reserved for policy knobs
    principal: PrincipalContext,
    project: Project,
    run_id: str,
    dto: AuditResult,
) -> tuple[int, dict[str, Any]]:
    run, job, task = load_owned_run(ws, project, principal, run_id)
    if job.stage != JobStage.AUDIT.value:
        raise conflict("wrong_stage", "This run is not an audit run")
    report_hash = digest_of({"kind": ReportKind.AUDIT.value, "run_id": run.id, "body": dto.model_dump(mode="json")})
    existing = _existing_report(ws, run, report_hash)
    if existing is not None:  # duplicate FAIL/PASS: no second report, no second count
        return 200, _receipt(ws, existing, task, replayed=True)
    check_guard(ws, clock, run, job, task, dto, statuses={RunStatus.RUNNING})
    if task.status != TaskStatus.REVIEWING.value:
        raise conflict("task_not_reviewing", f"Task is {task.status}", status=task.status)
    snap = ws.get(Snapshot, dto.snapshot_id)
    if (
        dto.snapshot_id != job.input_snapshot_id
        or snap is None
        or snap.project_id != project.id
        or snap.task_id != task.id
        or snap.revision != job.revision
    ):
        raise conflict("snapshot_mismatch", "Audit result is not bound to the snapshot this job audits")
    _validate_audit_content(dto)
    _require_artifacts(
        ws,
        project.id,
        [*(a for c in dto.checks for a in c.evidence_artifact_ids), *(a for f in dto.findings for a in f.evidence_artifact_ids)],
    )

    blocking = [f for f in dto.findings if f.severity in BLOCKING]
    blockers: list[Any]
    if dto.verdict is Verdict.FAIL:
        blockers = [{"invariant_key": f.invariant_key, "component": f.component, "severity": f.severity.value} for f in blocking]
    elif dto.verdict is Verdict.INCONCLUSIVE:
        blockers = list(dto.limitations)
    else:
        blockers = []
    report = Report(
        task_id=task.id,
        revision=job.revision,
        run_id=run.id,
        snapshot_id=snap.id,
        kind=ReportKind.AUDIT.value,
        verdict=dto.verdict.value,
        summary=dto.summary or dto.verdict.value,
        checks_json=_checks_json(dto.checks),
        blockers_json=json.dumps(blockers, sort_keys=True),
        evidence_level=dto.evidence_level.value,
        report_hash=report_hash,
        created_at=clock.now_ms(),
    )
    ws.add(report)
    ws.flush()
    _insert_findings(ws, task, report, dto.findings)
    set_run_status(run, RunStatus.SUCCEEDED, clock)  # an audit that FAILs still executed successfully
    set_job_status(job, JobStatus.SUCCEEDED)
    ws.flush()
    append_event(
        ws, clock, type="report.created", project_id=project.id, task_id=task.id,
        entity_version=task.version, actor_id=principal.id,
        payload={
            "report_id": report.id, "kind": report.kind, "verdict": report.verdict,
            "snapshot_id": snap.id, "run_id": run.id,
        },
    )
    rev = get_revision(ws, task, job.revision)

    if dto.verdict is Verdict.PASS:
        mark_verified(snap, clock)
        set_task_status(
            ws, clock, task, "audit_pass", TaskStatus.COMPLETED, actor_id=principal.id,
            payload={"report_id": report.id, "snapshot_id": snap.id, "revision": job.revision},
        )
    elif dto.verdict is Verdict.INCONCLUSIVE:
        task.resume_stage = JobStage.AUDIT.value
        set_task_status(
            ws, clock, task, "audit_inconclusive", TaskStatus.BLOCKED, actor_id=principal.id,
            blocked_reason=BlockedReason.VERIFICATION_UNAVAILABLE,
            payload={"report_id": report.id, "limitations": list(dto.limitations)[:10]},
        )
    else:
        # The only place failed_review_count grows: first accepted FAIL of this audit run.
        task.failed_review_count += 1
        history = _audit_history(ws, task, job.revision)
        # history now includes the report just inserted (FAIL, flushed); drop it from the "previous" list.
        current = history[-1] if history else AuditRound(frozenset(), snap.diff_hash, snap.tree_hash)
        previous = history[:-1]
        loop = detect_loop(previous, current)
        task.resume_stage = JobStage.IMPLEMENT.value
        if loop is not None:
            set_task_status(
                ws, clock, task, "audit_fail", TaskStatus.BLOCKED, actor_id=principal.id,
                blocked_reason=BlockedReason.LOOP_DETECTED,
                payload={
                    "report_id": report.id,
                    "failed_review_count": task.failed_review_count,
                    "loop": {"rule": loop.rule, **loop.evidence},
                    "recommended_action": "owner review: change approach or give an explicit budget decision",
                },
            )
        elif task.failed_review_count >= task.max_failed_reviews:
            set_task_status(
                ws, clock, task, "audit_fail", TaskStatus.BLOCKED, actor_id=principal.id,
                blocked_reason=BlockedReason.ITERATION_LIMIT,
                payload={
                    "report_id": report.id,
                    "failed_review_count": task.failed_review_count,
                    "max_failed_reviews": task.max_failed_reviews,
                    "recommended_action": "owner budget decision required",
                },
            )
        else:
            set_task_status(
                ws, clock, task, "audit_fail", TaskStatus.CHANGES_REQUESTED, actor_id=principal.id,
                payload={"report_id": report.id, "failed_review_count": task.failed_review_count},
            )
            create_job(ws, clock, task, rev, JobStage.IMPLEMENT, input_snapshot_id=snap.id, actor_id=principal.id)
    return 200, _receipt(ws, report, task)
