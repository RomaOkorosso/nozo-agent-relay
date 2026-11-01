"""Jobs and runs: claim (BEGIN IMMEDIATE), start, heartbeat, fail, dispatch, lease fencing.

Claim safety (03_DATA_MODEL transactional invariant 1): the caller opens the transaction with
``write_session`` (``BEGIN IMMEDIATE``); eligibility check, job update, run insert and event commit
atomically. Only then may a runner start a child process. A stale lease (old epoch / revision /
policy digest / non-active run) is never accepted for any lifecycle call.
"""

from __future__ import annotations

from typing import Any

from sqlalchemy import case, func, select
from sqlalchemy.orm import Session

from nozo_relay.api.errors import RelayError
from nozo_relay.api.schemas import ClaimRequest, RunFail, RunGuard
from nozo_relay.auth.context import PrincipalContext
from nozo_relay.clock import Clock, ms_to_rfc3339
from nozo_relay.config import Settings
from nozo_relay.logsafe import redact
from nozo_relay.db.models import Control, Job, Membership, Principal, Project, Run, Task
from nozo_relay.domain.enums import (
    BlockedReason,
    ControlStatus,
    JobStage,
    JobStatus,
    MembershipRole,
    PrincipalKind,
    RunStatus,
    TaskStatus,
)
from nozo_relay.services import acl
from nozo_relay.services import policy as policy_svc
from nozo_relay.services.common import (
    create_job,
    get_revision,
    idle_status_for,
    set_job_status,
    set_run_status,
    set_task_status,
    touch_task,
)
from nozo_relay.services.events import append_event
from nozo_relay.services.snapshots import input_snapshot_of, snapshot_to_dict
from nozo_relay.services.tasks import check_version, task_to_dict

_STAGE_ROLE = {
    JobStage.IMPLEMENT: (PrincipalKind.IMPLEMENTER, MembershipRole.IMPLEMENTER),
    JobStage.AUDIT: (PrincipalKind.AUDITOR, MembershipRole.AUDITOR),
}
_CLAIMABLE_TASK_STATUS = {
    JobStage.IMPLEMENT: (TaskStatus.QUEUED.value, TaskStatus.CHANGES_REQUESTED.value),
    JobStage.AUDIT: (TaskStatus.AWAITING_REVIEW.value,),
}
_TIER_RANK = case((Task.effective_tier == "P0", 0), (Task.effective_tier == "P1", 1), else_=2)
_URGENCY_RANK = case((Task.urgency == "high", 0), (Task.urgency == "normal", 1), else_=2)


def conflict(code: str, message: str, **details: Any) -> RelayError:
    return RelayError(409, code, message, details=details or None)


# ------------------------------------------------------------------ run loading & guards


def load_owned_run(
    ws: Session, project: Project, principal: PrincipalContext, run_id: str
) -> tuple[Run, Job, Task]:
    """Run of this project owned by the calling credential's principal, else 404 (no leak)."""
    run, job = acl.get_run_of(ws, project, run_id)
    if run.principal_id != principal.id:
        raise acl.not_found()
    task = ws.get(Task, job.task_id)
    assert task is not None
    return run, job, task


def check_guard(
    ws: Session,
    clock: Clock,
    run: Run,
    job: Job,
    task: Task,
    guard: RunGuard,
    *,
    statuses: set[RunStatus],
    allow_fenced: bool = False,
    check_lease: bool = True,
) -> None:
    """Fencing: epoch + revision + policy digest + run state + lease expiry (06_EXECUTION_PROTOCOL)."""
    if guard.lease_epoch != run.lease_epoch or (not allow_fenced and job.lease_epoch != run.lease_epoch):
        raise conflict(
            "stale_epoch", "Lease epoch is stale", presented=guard.lease_epoch, current=job.lease_epoch
        )
    if guard.revision != job.revision or task.current_revision != job.revision:
        raise conflict("revision_mismatch", "Task revision changed; this run is stale")
    rev = get_revision(ws, task, job.revision)
    if guard.policy_digest != run.policy_digest or run.policy_digest != rev.policy_digest:
        raise conflict("policy_digest_mismatch", "Policy digest does not match the run")
    if RunStatus(run.status) not in statuses:
        raise conflict("run_not_active", f"Run is {run.status}", status=run.status)
    if check_lease and clock.now_ms() >= run.lease_expires_at:
        raise conflict("lease_expired", "Lease expired; the run is lost until reconciled")


# ------------------------------------------------------------------ claim


def _claim_body(
    ws: Session, settings: Settings, task: Task, job: Job, run: Run
) -> dict[str, Any]:
    import json

    rev = get_revision(ws, task, job.revision)
    snap = input_snapshot_of(ws, job)
    return {
        "job_id": job.id,
        "task_id": task.id,
        "project_id": task.project_id,
        "stage": job.stage,
        "revision": job.revision,
        "run_id": run.id,
        "lease_epoch": run.lease_epoch,
        "lease_expires_at": ms_to_rfc3339(run.lease_expires_at),
        "policy_digest": run.policy_digest,
        "heartbeat_interval_seconds": settings.heartbeat_interval_seconds,
        "lease_ttl_seconds": settings.lease_ttl_seconds,
        "task_input": {
            "title": task.title,
            "requirements": json.loads(rev.requirements_json),
            "acceptance": json.loads(rev.acceptance_json),
            "mode": rev.mode,
            "autonomous": bool(rev.autonomous),
            "scope": json.loads(rev.scope_json),
            "failed_review_count": task.failed_review_count,
            "max_failed_reviews": task.max_failed_reviews,
        },
        "input_snapshot": snapshot_to_dict(snap) if snap else None,
    }


def _stage_principal_ok(principal: PrincipalContext, role: str, stage: JobStage) -> bool:
    kind, member_role = _STAGE_ROLE[stage]
    return principal.kind is kind and role == member_role.value


def _next_claim_stamp(ws: Session, now: int) -> int:
    """Strictly increasing round-robin stamp (BEGIN IMMEDIATE makes read-then-write safe)."""
    last = ws.execute(select(func.max(Project.last_claimed_at))).scalar()
    return now if last is None or now > last else last + 1


def _pick_candidate(
    ws: Session, principal: PrincipalContext, stage: JobStage, project_ids: list[str]
) -> tuple[Job, Task, Project] | None:
    """Best eligible job: tier, then urgency, then the project served least recently, then FIFO.

    Paused / disabled projects are excluded in SQL (never offered). Jobs whose revision policy
    digest no longer matches the project's current policy are skipped (stale policy never runs).
    """
    if not project_ids:
        return None
    rows = ws.execute(
        select(Job, Task, Project)
        .join(Task, Task.id == Job.task_id)
        .join(Project, Project.id == Job.project_id)
        .where(
            Job.project_id.in_(project_ids),
            Project.enabled.is_(True),
            Project.paused.is_(False),
            Job.status == JobStatus.READY.value,
            Job.assignee_id == principal.id,
            Job.stage == stage.value,
            Job.dispatch_authorized.is_(True),
            Task.status.in_(_CLAIMABLE_TASK_STATUS[stage]),
        )
        .order_by(
            _TIER_RANK, _URGENCY_RANK, func.coalesce(Project.last_claimed_at, 0), Job.ready_at, Job.id
        )
        .limit(25)
    ).all()
    stale: list[str] = []
    for job, task, project in rows:
        if policy_svc.revision_policy_is_current(project, get_revision(ws, task, job.revision)):
            return job, task, project
        stale.append(task.id)
    if stale:
        raise conflict(
            "policy_stale",
            "Project policy changed after these tasks were revised; the owner must revise them",
            task_ids=stale[:10],
        )
    return None


def resolve_supervisor(ws: Session, project: Project, requested: str | None) -> str:
    """The supervisor (runner principal) a new run is bound to, verified server-side (T12/F02).

    ``requested`` must be an ACTIVE runner-kind principal holding the runner membership of ``project``.
    When omitted it is accepted only if the project has exactly one such runner (deterministic, never a guess
    between several); otherwise the claim is refused. The result is stored once on the run and never changes.
    """
    rows = ws.execute(
        select(Principal.id)
        .join(Membership, Membership.principal_id == Principal.id)
        .where(
            Membership.project_id == project.id,
            Membership.role == MembershipRole.RUNNER.value,
            Principal.kind == PrincipalKind.RUNNER.value,
            Principal.active.is_(True),
        )
        .order_by(Principal.id)
    ).scalars().all()
    if requested is None:
        if len(rows) == 1:
            return rows[0]
        raise RelayError(
            422, "supervisor_required",
            "supervisor_principal_id is required (the project has no unique active supervisor)",
        )
    if requested not in rows:
        raise RelayError(
            422, "supervisor_invalid",
            "supervisor_principal_id is not an active runner principal of this project",
        )
    return requested


def _lease(
    ws: Session,
    clock: Clock,
    settings: Settings,
    principal: PrincipalContext,
    stage: JobStage,
    runner_instance_id: str,
    supervisor_principal_id: str | None,
    job: Job,
    task: Task,
    project: Project,
) -> dict[str, Any]:
    supervisor_id = resolve_supervisor(ws, project, supervisor_principal_id)
    if stage is JobStage.AUDIT:
        snap = input_snapshot_of(ws, job)
        if task.implementer_id == principal.id or (snap is not None and snap.created_by == principal.id):
            raise RelayError(403, "self_review_forbidden", "An implementer cannot audit its own work")
        if snap is None:
            raise conflict("missing_snapshot", "Audit job has no input snapshot")

    rev = get_revision(ws, task, job.revision)
    now = clock.now_ms()
    set_job_status(job, JobStatus.LEASED)
    job.lease_epoch += 1
    job.delivery_count += 1
    project.last_claimed_at = _next_claim_stamp(ws, now)
    run = Run(
        job_id=job.id,
        principal_id=principal.id,
        runner_instance_id=runner_instance_id,
        supervisor_principal_id=supervisor_id,
        lease_epoch=job.lease_epoch,
        lease_expires_at=now + settings.lease_ttl_seconds * 1000,
        status=RunStatus.LEASED.value,
        heartbeat_at=now,
        policy_digest=rev.policy_digest,
    )
    ws.add(run)
    ws.flush()
    append_event(
        ws,
        clock,
        type="job.claimed",
        project_id=project.id,
        task_id=task.id,
        entity_version=task.version,
        actor_id=principal.id,
        payload={
            "job_id": job.id,
            "run_id": run.id,
            "stage": job.stage,
            "lease_epoch": run.lease_epoch,
            "revision": job.revision,
        },
    )
    trigger = "claim_implement" if stage is JobStage.IMPLEMENT else "claim_audit"
    to = TaskStatus.CLAIMED if stage is JobStage.IMPLEMENT else TaskStatus.REVIEWING
    set_task_status(ws, clock, task, trigger, to, actor_id=principal.id, payload={"run_id": run.id})
    return _claim_body(ws, settings, task, job, run)


def claim(
    ws: Session,
    clock: Clock,
    settings: Settings,
    principal: PrincipalContext,
    project: Project,
    dto: ClaimRequest,
) -> dict[str, Any] | None:
    """Atomic lease inside one project. ``None`` means no eligible work (HTTP 204)."""
    role = acl.project_role(principal, project)
    kind, _ = _STAGE_ROLE[dto.stage]
    if not _stage_principal_ok(principal, role, dto.stage):
        raise acl.forbidden(f"Only {kind.value} principals may claim {dto.stage.value} jobs")
    if not project.enabled or project.paused:
        raise RelayError(
            409,
            "project_paused",
            "Project is paused or disabled; no work is issued",
            retryable=True,
        )
    picked = _pick_candidate(ws, principal, dto.stage, [project.id])
    if picked is None:
        return None
    job, task, project = picked
    return _lease(ws, clock, settings, principal, dto.stage, dto.runner_instance_id, dto.supervisor_principal_id, job, task, project)


def claim_any(
    ws: Session,
    clock: Clock,
    settings: Settings,
    principal: PrincipalContext,
    dto: ClaimRequest,
) -> dict[str, Any] | None:
    """Cross-project claim over every project where the caller holds the stage role.

    Only the caller's own memberships are considered, so another project's queue is never
    visible. Equal tier + urgency are served round-robin across projects (least recently served first).
    """
    kind, member_role = _STAGE_ROLE[dto.stage]
    if principal.kind is not kind:
        raise acl.forbidden(f"Only {kind.value} principals may claim {dto.stage.value} jobs")
    ids = sorted(pid for pid, role in principal.project_roles.items() if role == member_role.value)
    picked = _pick_candidate(ws, principal, dto.stage, ids)
    if picked is None:
        return None
    job, task, project = picked
    return _lease(ws, clock, settings, principal, dto.stage, dto.runner_instance_id, dto.supervisor_principal_id, job, task, project)


# ------------------------------------------------------------------ start / heartbeat


def start_run(
    ws: Session,
    clock: Clock,
    principal: PrincipalContext,
    project: Project,
    run_id: str,
    guard: RunGuard,
) -> dict[str, Any]:
    run, job, task = load_owned_run(ws, project, principal, run_id)
    check_guard(ws, clock, run, job, task, guard, statuses={RunStatus.LEASED, RunStatus.RUNNING})
    if project.paused or not project.enabled:
        raise conflict("project_paused", "Project is paused; do not spawn work")
    if run.status == RunStatus.LEASED.value:
        set_run_status(run, RunStatus.RUNNING, clock)
        run.started_at = clock.now_ms()
        set_job_status(job, JobStatus.RUNNING)
        if job.stage == JobStage.IMPLEMENT.value:
            set_task_status(
                ws, clock, task, "start", TaskStatus.RUNNING, actor_id=principal.id, payload={"run_id": run.id}
            )
        else:  # audit: task stays `reviewing`; start only records that the process began
            touch_task(clock, task)
            append_event(
                ws,
                clock,
                type="run.started",
                project_id=project.id,
                task_id=task.id,
                entity_version=task.version,
                actor_id=principal.id,
                payload={"run_id": run.id, "stage": job.stage},
            )
    return {
        "run_id": run.id,
        "status": run.status,
        "lease_epoch": run.lease_epoch,
        "lease_expires_at": ms_to_rfc3339(run.lease_expires_at),
        "started_at": ms_to_rfc3339(run.started_at) if run.started_at else None,
        "task_status": task.status,
    }


def heartbeat(
    ws: Session,
    clock: Clock,
    settings: Settings,
    principal: PrincipalContext,
    project: Project,
    run_id: str,
    guard: RunGuard,
) -> dict[str, Any]:
    run, job, task = load_owned_run(ws, project, principal, run_id)
    check_guard(
        ws,
        clock,
        run,
        job,
        task,
        guard,
        statuses={RunStatus.LEASED, RunStatus.RUNNING, RunStatus.STOPPING},
        allow_fenced=True,
    )
    now = clock.now_ms()
    run.heartbeat_at = now
    run.lease_expires_at = now + settings.lease_ttl_seconds * 1000
    pending: dict[str, Any] | None = None
    if run.status == RunStatus.STOPPING.value:
        ctl = ws.execute(
            select(Control)
            .where(
                Control.target_run_id == run.id,
                Control.status.in_([ControlStatus.REQUESTED.value, ControlStatus.STOPPING.value]),
            )
            .order_by(Control.requested_at.desc(), Control.id.desc())
            .limit(1)
        ).scalar_one_or_none()
        if ctl is not None:
            pending = {
                "control_id": ctl.id,
                # the task's *desired* control wins (a cancel may escalate an earlier pause)
                "command": task.desired_control or ctl.command,
                "target_epoch": ctl.target_epoch,
            }
    return {
        "run_id": run.id,
        "status": run.status,
        "lease_epoch": run.lease_epoch,
        "lease_expires_at": ms_to_rfc3339(run.lease_expires_at),
        "pending_control": pending,
    }


# ------------------------------------------------------------------ fail (runtime failure)


def _blocked_reason_for(error_code: str) -> BlockedReason:
    if error_code in ("auth_required", "unauthenticated", "expired_login"):
        return BlockedReason.AUTH_REQUIRED
    if error_code in ("quota", "rate_limited", "quota_exceeded"):
        return BlockedReason.QUOTA
    if error_code == "scope_violation":  # T07: supervisor quarantined out-of-scope output (never applied)
        return BlockedReason.SCOPE_CHANGE_REQUIRED
    return BlockedReason.RUNTIME_FAILURE


def fail_run(
    ws: Session,
    clock: Clock,
    settings: Settings,
    principal: PrincipalContext,
    project: Project,
    run_id: str,
    dto: RunFail,
) -> dict[str, Any]:
    """Technical failure: never counts as a failed review; has its own retry budget."""
    run, job, task = load_owned_run(ws, project, principal, run_id)
    check_guard(ws, clock, run, job, task, dto, statuses={RunStatus.LEASED, RunStatus.RUNNING})
    stage = JobStage(job.stage)
    set_run_status(run, RunStatus.FAILED, clock, error_code=dto.error_code)
    set_job_status(job, JobStatus.FAILED)
    task.resume_stage = stage.value
    evidence = redact(dto.evidence or "", max_len=500)
    retry = (
        dto.retryable
        and job.runtime_retry_count < policy_svc.runtime_retry_limit(project, settings)
        and not project.paused
        and project.enabled
    )
    ws.flush()
    append_event(
        ws,
        clock,
        type="run.failed",
        project_id=project.id,
        task_id=task.id,
        entity_version=task.version,
        actor_id=principal.id,
        payload={
            "run_id": run.id,
            "job_id": job.id,
            "error_code": dto.error_code,
            "retryable": dto.retryable,
            "evidence": evidence,
            "will_retry": retry,
        },
    )
    if retry:
        to = idle_status_for(task, stage)
        set_task_status(
            ws, clock, task, "runtime_fail", to, actor_id=principal.id,
            payload={"run_id": run.id, "retry": job.runtime_retry_count + 1},
        )
        rev = get_revision(ws, task)
        create_job(
            ws, clock, task, rev, stage,
            input_snapshot_id=job.input_snapshot_id,
            runtime_retry_count=job.runtime_retry_count + 1,
            actor_id=principal.id,
        )
        outcome = "retry_scheduled"
    else:
        set_task_status(
            ws, clock, task, "runtime_fail", TaskStatus.BLOCKED, actor_id=principal.id,
            blocked_reason=_blocked_reason_for(dto.error_code), payload={"run_id": run.id},
        )
        outcome = "blocked"
    return {"run_id": run.id, "status": run.status, "outcome": outcome, "task": task_to_dict(ws, task)}


# ------------------------------------------------------------------ dispatch


def dispatch_job(
    ws: Session,
    clock: Clock,
    principal: PrincipalContext,
    project: Project,
    job_id: str,
    expected_task_version: int,
) -> dict[str, Any]:
    acl.require_owner(principal, project)
    job = acl.get_job(ws, project, job_id)
    task = ws.get(Task, job.task_id)
    assert task is not None
    check_version(task.version, expected_task_version, "task")
    rev = get_revision(ws, task, job.revision)
    if job.status != JobStatus.READY.value:
        raise conflict("invalid_state", f"Only ready jobs can be dispatched (status={job.status})")
    if rev.autonomous:
        raise conflict("dispatch_not_required", "Task is autonomous; jobs are authorised automatically")
    if job.dispatch_authorized:
        raise conflict("already_dispatched", "Job was already dispatched (admission is one-shot)")
    job.dispatch_authorized = True
    touch_task(clock, task)
    append_event(
        ws,
        clock,
        type="job.dispatched",
        project_id=project.id,
        task_id=task.id,
        entity_version=task.version,
        actor_id=principal.id,
        payload={"job_id": job.id, "stage": job.stage},
    )
    return {"job_id": job.id, "dispatch_authorized": True, "task_version": task.version}
