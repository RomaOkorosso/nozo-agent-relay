"""Shared transactional helpers: guarded status changes, job creation, run/job finalisation.

Task, job and run statuses are only ever changed through these functions, inside one service
transaction (03_DATA_MODEL: no independent status edits).
"""

from __future__ import annotations

import json
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from nozo_relay.clock import Clock
from nozo_relay.db.models import Control, Job, Project, Run, Task, TaskRevision
from nozo_relay.domain import transitions
from nozo_relay.domain.enums import (
    ACTIVE_RUN_STATUSES,
    BlockedReason,
    ControlStatus,
    JobStage,
    JobStatus,
    RunStatus,
    TaskStatus,
)
from nozo_relay.services.events import append_event


def get_revision(ws: Session, task: Task, revision: int | None = None) -> TaskRevision:
    rev = ws.get(TaskRevision, (task.id, revision if revision is not None else task.current_revision))
    assert rev is not None, "task without its current revision"
    return rev


def touch_task(clock: Clock, task: Task) -> None:
    task.version += 1
    task.updated_at = clock.now_ms()


def set_task_status(
    ws: Session,
    clock: Clock,
    task: Task,
    trigger: str,
    to: TaskStatus,
    *,
    actor_id: str | None,
    blocked_reason: BlockedReason | None = None,
    payload: dict[str, Any] | None = None,
    event_type: str = "task.status_changed",
) -> None:
    """Guarded transition + version bump + event (one place so history explains every change)."""
    transitions.check_task(trigger, task.status, to.value)
    if (to is TaskStatus.BLOCKED) != (blocked_reason is not None):
        raise transitions.IllegalTransition("blocked_reason is required iff status is blocked")
    previous = task.status
    task.status = to.value
    task.blocked_reason = blocked_reason.value if blocked_reason else None
    if previous == TaskStatus.STOP_REQUESTED.value:
        task.desired_control = None
    touch_task(clock, task)
    data: dict[str, Any] = {"status": to.value, "from": previous, "trigger": trigger}
    if blocked_reason is not None:
        data["blocked_reason"] = blocked_reason.value
    if payload:
        data.update(payload)
    append_event(
        ws,
        clock,
        type=event_type,
        project_id=task.project_id,
        task_id=task.id,
        entity_version=task.version,
        actor_id=actor_id,
        payload=data,
    )


def set_job_status(job: Job, to: JobStatus) -> None:
    transitions.check_job(job.status, to.value)
    job.status = to.value


def set_run_status(run: Run, to: RunStatus, clock: Clock, *, error_code: str | None = None) -> None:
    transitions.check_run(run.status, to.value)
    run.status = to.value
    if to not in (RunStatus.LEASED, RunStatus.RUNNING, RunStatus.STOPPING):
        run.finished_at = clock.now_ms()
    if error_code is not None:
        run.error_code = error_code


def create_job(
    ws: Session,
    clock: Clock,
    task: Task,
    revision: TaskRevision,
    stage: JobStage,
    *,
    input_snapshot_id: str | None,
    runtime_retry_count: int = 0,
    actor_id: str | None = None,
) -> Job:
    """Insert a ready job. The caller must have closed the task's previous active job (flushed)."""
    assignee = task.implementer_id if stage is JobStage.IMPLEMENT else task.auditor_id
    assert assignee is not None
    seq = ws.execute(
        select(func.coalesce(func.max(Job.sequence), 0)).where(
            Job.task_id == task.id, Job.revision == revision.revision, Job.stage == stage.value
        )
    ).scalar_one()
    now = clock.now_ms()
    job = Job(
        task_id=task.id,
        project_id=task.project_id,
        revision=revision.revision,
        stage=stage.value,
        sequence=seq + 1,
        status=JobStatus.READY.value,
        assignee_id=assignee,
        input_snapshot_id=input_snapshot_id,
        # autonomous=true is applied by the server from the revision policy; otherwise the
        # owner must dispatch each new audit/fix job explicitly.
        dispatch_authorized=bool(revision.autonomous),
        runtime_retry_count=runtime_retry_count,
        ready_at=now,
        created_at=now,
    )
    ws.add(job)
    ws.flush()
    append_event(
        ws,
        clock,
        type="job.created",
        project_id=task.project_id,
        task_id=task.id,
        entity_version=task.version,
        actor_id=actor_id,
        payload={
            "job_id": job.id,
            "stage": job.stage,
            "sequence": job.sequence,
            "revision": job.revision,
            "dispatch_authorized": job.dispatch_authorized,
        },
    )
    return job


def cancel_ready_jobs(ws: Session, clock: Clock, task: Task, *, actor_id: str | None) -> int:
    jobs = (
        ws.execute(select(Job).where(Job.task_id == task.id, Job.status == JobStatus.READY.value))
        .scalars()
        .all()
    )
    for job in jobs:
        set_job_status(job, JobStatus.CANCELLED)
        append_event(
            ws,
            clock,
            type="job.cancelled",
            project_id=task.project_id,
            task_id=task.id,
            entity_version=task.version,
            actor_id=actor_id,
            payload={"job_id": job.id, "stage": job.stage},
        )
    ws.flush()
    return len(jobs)


def active_job_and_run(ws: Session, task: Task) -> tuple[Job, Run] | None:
    row = ws.execute(
        select(Job, Run)
        .join(Run, Run.job_id == Job.id)
        .where(Job.task_id == task.id, Run.status.in_([s.value for s in ACTIVE_RUN_STATUSES]))
    ).first()
    return (row[0], row[1]) if row else None


def stage_of_task(task: Task) -> JobStage:
    """Stage a task is currently in (used for resume_stage bookkeeping)."""
    if task.status in (TaskStatus.AWAITING_REVIEW.value, TaskStatus.REVIEWING.value):
        return JobStage.AUDIT
    if task.status in (TaskStatus.PAUSED.value, TaskStatus.BLOCKED.value) and task.resume_stage:
        return JobStage(task.resume_stage)
    return JobStage.IMPLEMENT


def idle_status_for(task: Task, stage: JobStage) -> TaskStatus:
    if stage is JobStage.AUDIT:
        return TaskStatus.AWAITING_REVIEW
    return TaskStatus.CHANGES_REQUESTED if task.failed_review_count > 0 else TaskStatus.QUEUED


def parent_control_refresh(ws: Session, clock: Clock, parent_id: str) -> None:
    """Project-level control becomes confirmed/unknown once every child control settled."""
    parent = ws.get(Control, parent_id)
    if parent is None or parent.status in (ControlStatus.CONFIRMED.value, ControlStatus.UNKNOWN.value):
        return
    children = (
        ws.execute(select(Control).where(Control.payload_json.like(f'%"{parent_id}"%')))
        .scalars()
        .all()
    )
    children = [c for c in children if json.loads(c.payload_json).get("parent_control_id") == parent_id]
    if any(c.status in (ControlStatus.REQUESTED.value, ControlStatus.STOPPING.value) for c in children):
        parent.status = ControlStatus.STOPPING.value
        return
    if any(c.status == ControlStatus.UNKNOWN.value for c in children):
        parent.status = ControlStatus.UNKNOWN.value
    else:
        parent.status = ControlStatus.CONFIRMED.value
        parent.confirmed_at = clock.now_ms()


def project_by_id(ws: Session, project_id: str) -> Project:
    project = ws.get(Project, project_id)
    assert project is not None
    return project
