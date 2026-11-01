"""Controls: pause / resume / cancel / complete / reassign / revise / emergency-stop, fencing and stop receipts.

A control that touches an active run first FENCES it (job.lease_epoch += 1, run+job -> stopping,
task -> stop_requested) so the old holder can no longer submit results or start work. The task only
reaches paused/cancelled/queued/... after a registered supervisor confirms the process tree is gone
(``stopped``). If the runner never confirms the control becomes ``unknown`` and the task
``blocked(stop_unknown)``: we never claim a physical stop we did not observe.
"""

from __future__ import annotations

import json
from typing import Any

from sqlalchemy import literal_column, select
from sqlalchemy.orm import Session

from nozo_relay.api.errors import RelayError
from nozo_relay.api.schemas import (
    ControlCreate,
    ReassignControl,
    ReconcileReceipt,
    ReviseControl,
    StoppedReceipt,
)
from nozo_relay.auth.context import PrincipalContext
from nozo_relay.clock import Clock, ms_to_rfc3339
from nozo_relay.config import Settings
from nozo_relay.db.models import Control, Job, Project, Run, Task, TaskRevision
from nozo_relay.domain.enums import (
    TERMINAL_TASK_STATUSES,
    BlockedReason,
    ControlCommand,
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
    active_job_and_run,
    cancel_ready_jobs,
    create_job,
    get_revision,
    idle_status_for,
    parent_control_refresh,
    set_job_status,
    set_run_status,
    set_task_status,
    stage_of_task,
    touch_task,
)
from nozo_relay.services.events import append_event
from nozo_relay.services.tasks import (
    check_actor_may_drive,
    check_version,
    task_to_dict,
    validate_assignee,
    write_revision,
)

OPEN_CONTROL = (ControlStatus.REQUESTED.value, ControlStatus.STOPPING.value)
_IDLE_PAUSABLE = (TaskStatus.QUEUED.value, TaskStatus.CHANGES_REQUESTED.value, TaskStatus.AWAITING_REVIEW.value)
_ACTIVE_TASK = (TaskStatus.CLAIMED.value, TaskStatus.RUNNING.value, TaskStatus.REVIEWING.value)


def conflict(code: str, message: str, **details: Any) -> RelayError:
    return RelayError(409, code, message, details=details or None)


def control_to_dict(c: Control) -> dict[str, Any]:
    return {
        "id": c.id,
        "project_id": c.project_id,
        "task_id": c.task_id,
        "command": c.command,
        "status": c.status,
        "requested_by": c.requested_by,
        "target_run_id": c.target_run_id,
        "target_epoch": c.target_epoch,
        "reason": c.reason,
        "requested_at": ms_to_rfc3339(c.requested_at),
        "confirmed_at": ms_to_rfc3339(c.confirmed_at) if c.confirmed_at else None,
    }


def get_control(ws: Session, project: Project, control_id: str) -> Control:
    c = ws.get(Control, control_id)
    if c is None or c.project_id != project.id:
        raise acl.not_found()
    return c


def _new_control(
    ws: Session,
    clock: Clock,
    project_id: str,
    task_id: str | None,
    command: ControlCommand,
    requested_by: str,
    reason: str,
    payload: dict[str, Any],
    *,
    run: Run | None = None,
    status: ControlStatus = ControlStatus.REQUESTED,
) -> Control:
    now = clock.now_ms()
    ctl = Control(
        project_id=project_id,
        task_id=task_id,
        command=command.value,
        requested_by=requested_by,
        target_run_id=run.id if run else None,
        target_epoch=run.lease_epoch if run else None,
        status=status.value,
        payload_json=json.dumps(payload, sort_keys=True),
        reason=reason,
        requested_at=now,
        confirmed_at=now if status is ControlStatus.CONFIRMED else None,
    )
    ws.add(ctl)
    ws.flush()
    append_event(
        ws, clock, type="control.requested", project_id=project_id, task_id=task_id,
        actor_id=requested_by,
        payload={"control_id": ctl.id, "command": ctl.command, "status": ctl.status, "run_id": ctl.target_run_id},
    )
    return ctl


def _parent_of(ctl: Control) -> str | None:
    return json.loads(ctl.payload_json).get("parent_control_id")


# ------------------------------------------------------------------ fencing / stop request


def _request_stop(
    ws: Session,
    clock: Clock,
    task: Task,
    job: Job,
    run: Run,
    project: Project,
    command: ControlCommand,
    requested_by: str,
    reason: str,
    payload: dict[str, Any],
) -> Control:
    ctl = _new_control(
        ws, clock, project.id, task.id, command, requested_by, reason, payload,
        run=run, status=ControlStatus.STOPPING,
    )
    job.lease_epoch += 1  # fencing epoch: the old holder is stale from this commit on
    set_job_status(job, JobStatus.STOPPING)
    set_run_status(run, RunStatus.STOPPING, clock)
    task.desired_control = command.value
    task.resume_stage = job.stage
    set_task_status(
        ws, clock, task, "stop_request", TaskStatus.STOP_REQUESTED, actor_id=requested_by,
        payload={"control_id": ctl.id, "command": command.value, "run_id": run.id, "target_epoch": run.lease_epoch},
    )
    return ctl


# ------------------------------------------------------------------ per-task commands


def _default_input_snapshot(ws: Session, task: Task, stage: JobStage) -> str | None:
    if stage is JobStage.AUDIT:
        return ws.execute(
            select(Job.output_snapshot_id)
            .where(
                Job.task_id == task.id,
                Job.revision == task.current_revision,
                Job.stage == JobStage.IMPLEMENT.value,
                Job.status == JobStatus.SUCCEEDED.value,
            )
            .order_by(literal_column("jobs.rowid").desc())
            .limit(1)
        ).scalar()
    if task.failed_review_count > 0:
        return ws.execute(
            select(Job.input_snapshot_id)
            .where(
                Job.task_id == task.id,
                Job.revision == task.current_revision,
                Job.stage == JobStage.AUDIT.value,
            )
            .order_by(literal_column("jobs.rowid").desc())
            .limit(1)
        ).scalar()
    return None


def _retry_count_for_resume(
    ws: Session, settings: Settings, project: Project, task: Task, stage: JobStage
) -> int:
    last = ws.execute(
        select(Job)
        .where(Job.task_id == task.id, Job.revision == task.current_revision, Job.stage == stage.value)
        .order_by(literal_column("jobs.rowid").desc())
        .limit(1)
    ).scalar_one_or_none()
    if last is None:
        return 0
    count = last.runtime_retry_count + (1 if last.status in (JobStatus.FAILED.value, JobStatus.LOST.value) else 0)
    limit = policy_svc.runtime_retry_limit(project, settings)
    if count > limit:
        raise conflict(
            "runtime_retry_limit",
            "Technical retry limit reached; the owner must revise the task",
            limit=limit,
        )
    return count


def _do_pause(ws, clock, actor_id, project, task, command, reason, payload, ar) -> Control:  # noqa: ANN001
    if task.status == TaskStatus.STOP_REQUESTED.value:
        raise conflict("stop_in_progress", "A stop is already in progress for this task")
    if task.status == TaskStatus.PAUSED.value:
        raise conflict("invalid_state", "Task is already paused")
    if ar is not None:
        return _request_stop(ws, clock, task, ar[0], ar[1], project, command, actor_id, reason, payload)
    if task.status not in _IDLE_PAUSABLE:
        raise conflict("invalid_state", f"Cannot pause a task in status {task.status}")
    stage = stage_of_task(task)
    cancel_ready_jobs(ws, clock, task, actor_id=actor_id)
    task.resume_stage = stage.value
    ctl = _new_control(
        ws, clock, project.id, task.id, command, actor_id, reason, payload, status=ControlStatus.CONFIRMED
    )
    set_task_status(ws, clock, task, "pause_idle", TaskStatus.PAUSED, actor_id=actor_id, payload={"control_id": ctl.id})
    return ctl


def _do_cancel(ws, clock, actor_id, project, task, command, reason, payload, ar) -> Control:  # noqa: ANN001
    if task.status == TaskStatus.STOP_REQUESTED.value:
        if ar is None:
            raise conflict("invalid_state", "Task is stopping without an active run")
        run = ar[1]
        ctl = _new_control(
            ws, clock, project.id, task.id, command, actor_id, reason, payload,
            run=run, status=ControlStatus.STOPPING,
        )
        task.desired_control = ControlCommand.CANCEL.value  # cancel escalates any earlier intent
        touch_task(clock, task)
        return ctl
    if ar is not None:
        return _request_stop(ws, clock, task, ar[0], ar[1], project, command, actor_id, reason, payload)
    cancel_ready_jobs(ws, clock, task, actor_id=actor_id)
    ctl = _new_control(
        ws, clock, project.id, task.id, command, actor_id, reason, payload, status=ControlStatus.CONFIRMED
    )
    set_task_status(ws, clock, task, "cancel_idle", TaskStatus.CANCELLED, actor_id=actor_id, payload={"control_id": ctl.id})
    return ctl


def _do_complete(ws, clock, actor_id, project, task, command, reason, payload, ar) -> Control:  # noqa: ANN001
    """Mark idle work completed (owner/coordinator). Does not replace auditor audit_pass for active runs.

    Active / stopping tasks must be paused or cancelled first — force-complete never invents a stop receipt.
    """
    if ar is not None or task.status == TaskStatus.STOP_REQUESTED.value:
        raise conflict(
            "invalid_state",
            "Cannot force-complete a task with an active or stopping run; pause/cancel first, then complete",
            status=task.status,
        )
    if task.status not in (
        TaskStatus.DRAFT.value,
        TaskStatus.QUEUED.value,
        TaskStatus.CHANGES_REQUESTED.value,
        TaskStatus.AWAITING_REVIEW.value,
        TaskStatus.PAUSED.value,
        TaskStatus.BLOCKED.value,
    ):
        raise conflict("invalid_state", f"Cannot force-complete a task in status {task.status}")
    cancel_ready_jobs(ws, clock, task, actor_id=actor_id)
    ctl = _new_control(
        ws, clock, project.id, task.id, command, actor_id, reason, payload, status=ControlStatus.CONFIRMED
    )
    set_task_status(
        ws, clock, task, "complete_idle", TaskStatus.COMPLETED, actor_id=actor_id, payload={"control_id": ctl.id}
    )
    return ctl


def _do_resume(ws, clock, settings, actor_id, project, task, command, reason, payload) -> Control:  # noqa: ANN001
    if task.status not in (TaskStatus.PAUSED.value, TaskStatus.BLOCKED.value):
        raise conflict("invalid_state", f"Only paused or blocked tasks can be resumed (status={task.status})")
    if project.paused or not project.enabled:
        raise conflict("project_paused", "Project is paused; resume the project first")
    if task.status == TaskStatus.BLOCKED.value:
        reason_code = task.blocked_reason
        if reason_code in (BlockedReason.ITERATION_LIMIT.value, BlockedReason.LOOP_DETECTED.value):
            raise conflict(
                "budget_decision_required",
                "The failed-review budget is exhausted; an explicit owner budget decision is required",
                blocked_reason=reason_code,
            )
        if reason_code in (BlockedReason.RECOVERY_REQUIRED.value, BlockedReason.STOP_UNKNOWN.value):
            raise conflict(
                "reconcile_required",
                "The previous run must be reconciled by its supervisor before work is re-issued",
                blocked_reason=reason_code,
            )
        if reason_code == BlockedReason.SCOPE_CHANGE_REQUIRED.value:
            raise conflict("revision_required", "Scope change needs an owner revision, not a plain resume")
    stage = JobStage(task.resume_stage or JobStage.IMPLEMENT.value)
    retries = _retry_count_for_resume(ws, settings, project, task, stage)
    to = idle_status_for(task, stage)
    ctl = _new_control(
        ws, clock, project.id, task.id, command, actor_id, reason, payload, status=ControlStatus.CONFIRMED
    )
    task.resume_stage = None
    set_task_status(ws, clock, task, "resume", to, actor_id=actor_id, payload={"control_id": ctl.id, "stage": stage.value})
    create_job(
        ws, clock, task, get_revision(ws, task), stage,
        input_snapshot_id=_default_input_snapshot(ws, task, stage),
        runtime_retry_count=retries, actor_id=actor_id,
    )
    return ctl


def _reassign_payload(ws: Session, project: Project, task: Task, dto: ReassignControl) -> dict[str, Any]:
    impl = dto.implementer_id or task.implementer_id
    aud = dto.auditor_id or task.auditor_id
    if dto.implementer_id:
        validate_assignee(ws, project, dto.implementer_id, PrincipalKind.IMPLEMENTER, MembershipRole.IMPLEMENTER, "implementer_id")
    if dto.auditor_id:
        validate_assignee(ws, project, dto.auditor_id, PrincipalKind.AUDITOR, MembershipRole.AUDITOR, "auditor_id")
    if impl == aud:
        raise RelayError(403, "self_review_forbidden", "Implementer and auditor must be different principals")
    return {"implementer_id": dto.implementer_id, "auditor_id": dto.auditor_id}


def _apply_reassign(
    ws: Session, clock: Clock, task: Task, payload: dict[str, Any], actor_id: str,
    *, stage: JobStage | None, to_status: TaskStatus | None,
) -> None:
    """Change assignees; re-issue the current stage's job when ITS assignee changed (or a stop happened)."""
    old_impl, old_aud = task.implementer_id, task.auditor_id
    if payload.get("implementer_id"):
        task.implementer_id = payload["implementer_id"]
    if payload.get("auditor_id"):
        task.auditor_id = payload["auditor_id"]
    reissue = stage is not None
    if stage is None and task.status in _IDLE_PAUSABLE:
        stage = stage_of_task(task)
        changed = (stage is JobStage.IMPLEMENT and task.implementer_id != old_impl) or (
            stage is JobStage.AUDIT and task.auditor_id != old_aud
        )
        if changed:
            cancel_ready_jobs(ws, clock, task, actor_id=actor_id)
            reissue = True
    ws.flush()
    if reissue and stage is not None:
        if to_status is not None:
            set_task_status(
                ws, clock, task, "stop_confirmed", to_status, actor_id=actor_id,
                payload={"reassigned": True, "stage": stage.value},
            )
        else:
            touch_task(clock, task)
        create_job(
            ws, clock, task, get_revision(ws, task), stage,
            input_snapshot_id=_default_input_snapshot(ws, task, stage), actor_id=actor_id,
        )
    else:
        touch_task(clock, task)
    append_event(
        ws, clock, type="task.reassigned", project_id=task.project_id, task_id=task.id,
        entity_version=task.version, actor_id=actor_id,
        payload={"implementer_id": task.implementer_id, "auditor_id": task.auditor_id},
    )


def _check_revise_authority(
    ws: Session, clock: Clock, actor: PrincipalContext, project: Project, task: Task, dto: ReviseControl
) -> None:
    """Coordinators may only refine requirements/acceptance/scope WITHIN current scope and ceiling."""
    p = dto.revision
    if actor.kind is not PrincipalKind.COORDINATOR:
        return
    if p.mode is not None or p.autonomous is not None:
        raise acl.forbidden("Only the owner can change mode or autonomy")
    if p.scope is not None:
        rev1 = get_revision(ws, task, 1)
        d = acl.load_delegation(ws, clock, project, actor.id, rev1.delegation_id, "task.control")
        new_scope = p.scope.model_dump(mode="json")
        current = json.loads(get_revision(ws, task).scope_json)
        if not acl.scope_within(new_scope, current) or not acl.scope_within(new_scope, acl.delegation_ceiling(d)):
            raise acl.forbidden("Scope expansion requires an owner revision")


def _apply_revise(
    ws: Session, clock: Clock, project: Project, task: Task, payload: dict[str, Any], actor_id: str,
    *, to_status: TaskStatus | None,
) -> None:
    current = get_revision(ws, task)
    merged = {
        "requirements": payload.get("requirements") or json.loads(current.requirements_json),
        "acceptance": payload.get("acceptance") or json.loads(current.acceptance_json),
        "mode": payload.get("mode") or current.mode,
        "autonomous": current.autonomous if payload.get("autonomous") is None else payload["autonomous"],
        "scope": payload.get("scope") or json.loads(current.scope_json),
    }
    cancel_ready_jobs(ws, clock, task, actor_id=actor_id)  # stale audit/implement of the old revision
    task.current_revision += 1
    rev = write_revision(ws, clock, task, project, merged, created_by=actor_id, delegation_id=current.delegation_id)
    status = TaskStatus(task.status)
    if to_status is not None:
        target = to_status
        trigger = "stop_confirmed"
    elif status in (TaskStatus.DRAFT, TaskStatus.PAUSED):
        target, trigger = status, "revise_idle"
    else:
        target, trigger = TaskStatus.QUEUED, "revise_idle"
    task.resume_stage = JobStage.IMPLEMENT.value if target is TaskStatus.PAUSED else None
    set_task_status(
        ws, clock, task, trigger, target, actor_id=actor_id,
        payload={"revision": rev.revision, "policy_digest": rev.policy_digest},
    )
    append_event(
        ws, clock, type="task.revision_created", project_id=task.project_id, task_id=task.id,
        entity_version=task.version, actor_id=actor_id,
        payload={"revision": rev.revision, "policy_digest": rev.policy_digest},
    )
    if target is TaskStatus.QUEUED:
        create_job(ws, clock, task, rev, JobStage.IMPLEMENT, input_snapshot_id=None, actor_id=actor_id)


def _do_reassign_or_revise(
    ws, clock, actor, project, task, dto, command, reason, ar  # noqa: ANN001
) -> Control:
    if task.status == TaskStatus.STOP_REQUESTED.value:
        raise conflict("stop_in_progress", "A stop is already in progress for this task")
    if command is ControlCommand.REASSIGN:
        payload = _reassign_payload(ws, project, task, dto)
    else:
        _check_revise_authority(ws, clock, actor, project, task, dto)
        if task.status == TaskStatus.BLOCKED.value and task.blocked_reason in (
            BlockedReason.ITERATION_LIMIT.value, BlockedReason.LOOP_DETECTED.value,
        ):
            raise conflict("budget_decision_required", "Revising cannot bypass the failed-review budget")
        if task.status == TaskStatus.BLOCKED.value and task.blocked_reason in (
            BlockedReason.RECOVERY_REQUIRED.value, BlockedReason.STOP_UNKNOWN.value,
        ):
            raise conflict("reconcile_required", "Reconcile the lost run first")
        payload = dto.revision.model_dump(mode="json", exclude_none=True)
        cur = get_revision(ws, task)
        policy_svc.enforce_task_policy(
            project,
            scope=payload.get("scope") or json.loads(cur.scope_json),
            autonomous=bool(cur.autonomous if payload.get("autonomous") is None else payload["autonomous"]),
        )
    if ar is not None:
        return _request_stop(ws, clock, task, ar[0], ar[1], project, command, actor.id, reason, payload)
    ctl = _new_control(ws, clock, project.id, task.id, command, actor.id, reason, payload, status=ControlStatus.CONFIRMED)
    if command is ControlCommand.REASSIGN:
        _apply_reassign(ws, clock, task, payload, actor.id, stage=None, to_status=None)
    else:
        _apply_revise(ws, clock, project, task, payload, actor.id, to_status=None)
    return ctl


def apply_task_command(
    ws: Session,
    clock: Clock,
    settings: Settings,
    actor: PrincipalContext,
    project: Project,
    task: Task,
    command: ControlCommand,
    reason: str,
    dto: Any = None,
    *,
    payload: dict[str, Any] | None = None,
) -> Control:
    """Execute one typed command. Callers have already authorised the actor and checked versions."""
    if TaskStatus(task.status) in TERMINAL_TASK_STATUSES:
        raise conflict("task_terminal", "Completed or cancelled tasks cannot change; create a new task")
    ar = active_job_and_run(ws, task)
    payload = payload or {}
    if command is ControlCommand.PAUSE:
        return _do_pause(ws, clock, actor.id, project, task, command, reason, payload, ar)
    if command is ControlCommand.CANCEL:
        return _do_cancel(ws, clock, actor.id, project, task, command, reason, payload, ar)
    if command is ControlCommand.COMPLETE:
        return _do_complete(ws, clock, actor.id, project, task, command, reason, payload, ar)
    if command is ControlCommand.RESUME:
        return _do_resume(ws, clock, settings, actor.id, project, task, command, reason, payload)
    if command in (ControlCommand.REASSIGN, ControlCommand.REVISE):
        return _do_reassign_or_revise(ws, clock, actor, project, task, dto, command, reason, ar)
    raise conflict("unsupported_command", "Unsupported command")


def request_task_control(
    ws: Session,
    clock: Clock,
    settings: Settings,
    principal: PrincipalContext,
    project: Project,
    task: Task,
    dto: ControlCreate,
    expected_version: int,
) -> tuple[int, dict[str, Any]]:
    check_actor_may_drive(ws, clock, principal, project, task, "task.control")
    acl.require_enabled(project)
    check_version(task.version, expected_version, "task")
    ctl = apply_task_command(
        ws, clock, settings, principal, project, task, ControlCommand(dto.command), dto.reason, dto
    )
    status = 202 if ctl.status in OPEN_CONTROL else 200
    return status, {"control": control_to_dict(ctl), "task": task_to_dict(ws, task)}


# ------------------------------------------------------------------ project-level / emergency


_PROJECT_PAUSABLE = (*_IDLE_PAUSABLE, *_ACTIVE_TASK)


def project_control(
    ws: Session,
    clock: Clock,
    settings: Settings,
    principal: PrincipalContext,
    project: Project,
    command: str,
    reason: str,
    *,
    emergency: bool = False,
) -> tuple[int, dict[str, Any]]:
    """Pause/resume every task of a project (owner). Emergency stop is the same path, all projects."""
    parent = _new_control(
        ws, clock, project.id, None,
        ControlCommand.EMERGENCY_STOP if emergency else ControlCommand(command),
        principal.id, reason, {},
    )
    skipped: list[dict[str, str]] = []
    children: list[Control] = []
    if command == "pause":
        project.paused = True
        project.version += 1
        tasks = ws.execute(
            select(Task).where(Task.project_id == project.id, Task.status.in_(_PROJECT_PAUSABLE))
            .order_by(Task.created_at, Task.id)
        ).scalars().all()
        for t in tasks:
            children.append(
                apply_task_command(
                    ws, clock, settings, principal, project, t, ControlCommand.PAUSE, reason,
                    payload={"parent_control_id": parent.id, "origin": "emergency_stop" if emergency else "project_pause"},
                )
            )
    else:
        project.paused = False
        project.version += 1
        tasks = ws.execute(
            select(Task).where(Task.project_id == project.id, Task.status == TaskStatus.PAUSED.value)
            .order_by(Task.created_at, Task.id)
        ).scalars().all()
        for t in tasks:
            try:
                children.append(
                    apply_task_command(
                        ws, clock, settings, principal, project, t, ControlCommand.RESUME, reason,
                        payload={"parent_control_id": parent.id},
                    )
                )
            except RelayError as exc:
                skipped.append({"task_id": t.id, "code": exc.code})
    append_event(
        ws, clock, type="project.updated", project_id=project.id, entity_version=project.version,
        actor_id=principal.id, payload={"paused": project.paused, "control_id": parent.id, "emergency": emergency},
    )
    parent_control_refresh(ws, clock, parent.id)
    ws.flush()
    ws.refresh(parent)
    pending = parent.status in OPEN_CONTROL
    body = {
        "control": control_to_dict(parent),
        "task_controls": [control_to_dict(c) for c in children],
        "skipped": skipped,
        "project": {"id": project.id, "paused": project.paused, "version": project.version},
    }
    return (202 if pending or emergency else 200), body


def emergency_stop(
    ws: Session, clock: Clock, settings: Settings, principal: PrincipalContext, reason: str
) -> dict[str, Any]:
    if not principal.is_owner:
        raise acl.forbidden("Owner privileges required")
    projects = ws.execute(select(Project).order_by(Project.slug)).scalars().all()
    results = []
    for p in projects:
        _, body = project_control(ws, clock, settings, principal, p, "pause", reason, emergency=True)
        results.append(body)
    return {"controls": [r["control"] for r in results], "projects": [r["project"] for r in results]}


# ------------------------------------------------------------------ supervisor receipts


def require_supervisor(principal: PrincipalContext, project: Project) -> None:
    role = acl.project_role(principal, project)
    if principal.kind is not PrincipalKind.RUNNER or role != MembershipRole.RUNNER.value:
        raise acl.forbidden("A registered supervisor (runner) credential is required")


def require_run_supervisor(principal: PrincipalContext, run: Run) -> None:
    """Only the supervisor bound to the run at claim may confirm its stop / reconcile it (T12/F02).

    404 (not 403): a runner that never owned the run must not learn that it exists. Legacy rows without a bound
    supervisor can never be confirmed by anyone (fail closed); the owner must resolve those out of band.
    """
    if run.supervisor_principal_id is None or run.supervisor_principal_id != principal.id:
        raise acl.not_found()


def _authority_still_valid(
    ws: Session, clock: Clock, project: Project, task: Task, ctl: Control
) -> bool:
    """Re-check requester authority before creating a new job from a pending reassign/revise."""
    from nozo_relay.db.models import Principal

    requester = ws.get(Principal, ctl.requested_by)
    if requester is None or not requester.active:
        return False
    if requester.kind == PrincipalKind.OWNER.value:
        return True
    if requester.kind == PrincipalKind.COORDINATOR.value:
        try:
            rev1 = get_revision(ws, task, 1)
            acl.load_delegation(ws, clock, project, requester.id, rev1.delegation_id, "task.control")
        except RelayError:
            return False
        return True
    return False


def _latest_control(ws: Session, run: Run, command: str) -> Control | None:
    return ws.execute(
        select(Control)
        .where(Control.target_run_id == run.id, Control.command == command)
        .order_by(literal_column("controls.rowid").desc())
        .limit(1)
    ).scalar_one_or_none()


def _finalize_stop(
    ws: Session, clock: Clock, project: Project, task: Task, job: Job, run: Run, actor_id: str
) -> None:
    desired = task.desired_control or ControlCommand.PAUSE.value
    stage = JobStage(job.stage)
    if desired == ControlCommand.CANCEL.value:
        set_task_status(ws, clock, task, "stop_confirmed", TaskStatus.CANCELLED, actor_id=actor_id, payload={"run_id": run.id})
        return
    if desired in (ControlCommand.REASSIGN.value, ControlCommand.REVISE.value):
        ctl = _latest_control(ws, run, desired)
        if ctl is not None and _authority_still_valid(ws, clock, project, task, ctl):
            payload = json.loads(ctl.payload_json)
            if desired == ControlCommand.REASSIGN.value:
                to = idle_status_for(task, stage)
                _apply_reassign(ws, clock, task, payload, ctl.requested_by, stage=stage, to_status=to)
            else:
                _apply_revise(ws, clock, project, task, payload, ctl.requested_by, to_status=TaskStatus.QUEUED)
            return
        append_event(
            ws, clock, type="control.authority_expired", project_id=project.id, task_id=task.id,
            actor_id=actor_id, payload={"control_id": ctl.id if ctl else None, "command": desired},
        )
    task.resume_stage = stage.value
    set_task_status(ws, clock, task, "stop_confirmed", TaskStatus.PAUSED, actor_id=actor_id, payload={"run_id": run.id})


def confirm_stopped(
    ws: Session,
    clock: Clock,
    principal: PrincipalContext,
    project: Project,
    run_id: str,
    dto: StoppedReceipt,
) -> dict[str, Any]:
    require_supervisor(principal, project)
    run, job = acl.get_run_of(ws, project, run_id)
    require_run_supervisor(principal, run)
    task = ws.get(Task, job.task_id)
    assert task is not None
    ctl = ws.get(Control, dto.control_id)
    if ctl is None or ctl.project_id != project.id or ctl.target_run_id != run.id:
        raise acl.not_found()
    if dto.target_epoch != run.lease_epoch or ctl.target_epoch != run.lease_epoch:
        raise conflict("stale_epoch", "Receipt targets a different lease epoch")
    if run.status != RunStatus.STOPPING.value:
        raise conflict("run_not_stopping", f"Run is {run.status}; use reconcile for lost runs", status=run.status)
    if ctl.status not in (*OPEN_CONTROL, ControlStatus.UNKNOWN.value):
        raise conflict("control_closed", f"Control is already {ctl.status}")

    open_controls = ws.execute(
        select(Control).where(Control.target_run_id == run.id, Control.status.in_([*OPEN_CONTROL, ControlStatus.UNKNOWN.value]))
    ).scalars().all()

    if not dto.process_tree_absent:
        for c in open_controls:
            c.status = ControlStatus.UNKNOWN.value
        if task.status == TaskStatus.STOP_REQUESTED.value:
            task.resume_stage = job.stage
            set_task_status(
                ws, clock, task, "stop_unknown", TaskStatus.BLOCKED, actor_id=principal.id,
                blocked_reason=BlockedReason.STOP_UNKNOWN, payload={"run_id": run.id, "reason": "process_tree_present"},
            )
        append_event(
            ws, clock, type="control.unknown", project_id=project.id, task_id=task.id, actor_id=principal.id,
            payload={"control_id": ctl.id, "run_id": run.id, "quarantine_required": True},
        )
        for c in open_controls:
            if (parent := _parent_of(c)):
                parent_control_refresh(ws, clock, parent)
        return {"control": control_to_dict(ctl), "task": task_to_dict(ws, task), "outcome": "unknown"}

    now = clock.now_ms()
    set_run_status(run, RunStatus.CANCELLED, clock)
    set_job_status(job, JobStatus.CANCELLED)
    for c in open_controls:
        c.status = ControlStatus.CONFIRMED.value
        c.confirmed_at = now
        run.control_ack_id = c.id
    ws.flush()
    append_event(
        ws, clock, type="control.confirmed", project_id=project.id, task_id=task.id, actor_id=principal.id,
        payload={"control_id": ctl.id, "run_id": run.id, "receipt": dto.receipt[:500]},
    )
    if task.status == TaskStatus.STOP_REQUESTED.value:
        _finalize_stop(ws, clock, project, task, job, run, principal.id)
    elif task.status == TaskStatus.BLOCKED.value and task.blocked_reason == BlockedReason.STOP_UNKNOWN.value:
        set_task_status(ws, clock, task, "reconcile", TaskStatus.PAUSED, actor_id=principal.id, payload={"run_id": run.id})
    for c in open_controls:
        if (parent := _parent_of(c)):
            parent_control_refresh(ws, clock, parent)
    ws.refresh(ctl)
    return {"control": control_to_dict(ctl), "task": task_to_dict(ws, task), "outcome": "confirmed"}


def reconcile_run(
    ws: Session,
    clock: Clock,
    principal: PrincipalContext,
    project: Project,
    run_id: str,
    dto: ReconcileReceipt,
) -> dict[str, Any]:
    """A lost run never revives: reconcile only unblocks the TASK (-> paused) after cleanup is proven."""
    require_supervisor(principal, project)
    run, job = acl.get_run_of(ws, project, run_id)
    require_run_supervisor(principal, run)
    task = ws.get(Task, job.task_id)
    assert task is not None
    if run.status != RunStatus.LOST.value:
        raise conflict("run_not_lost", f"Run is {run.status}; only lost runs are reconciled", status=run.status)
    if task.status != TaskStatus.BLOCKED.value or task.blocked_reason not in (
        BlockedReason.RECOVERY_REQUIRED.value, BlockedReason.STOP_UNKNOWN.value,
    ):
        raise conflict("not_reconcilable", "Task is not waiting for reconciliation", status=task.status)
    if dto.process_tree_absent and dto.workspace_quarantined:
        set_task_status(
            ws, clock, task, "reconcile", TaskStatus.PAUSED, actor_id=principal.id,
            payload={"run_id": run.id, "receipt": dto.receipt[:500]},
        )
        outcome = "paused_ready_to_resume"
    else:
        append_event(
            ws, clock, type="run.reconcile_incomplete", project_id=project.id, task_id=task.id,
            actor_id=principal.id,
            payload={"run_id": run.id, "process_tree_absent": dto.process_tree_absent,
                     "workspace_quarantined": dto.workspace_quarantined},
        )
        outcome = "still_blocked"
    append_event(
        ws, clock, type="run.reconciled", project_id=project.id, task_id=task.id, actor_id=principal.id,
        payload={"run_id": run.id, "outcome": outcome},
    )
    return {"run_id": run.id, "outcome": outcome, "task": task_to_dict(ws, task)}


def revision_row(ws: Session, task: Task) -> TaskRevision:  # re-exported for views
    return get_revision(ws, task)
