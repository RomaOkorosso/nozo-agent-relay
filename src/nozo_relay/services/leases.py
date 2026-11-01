"""Lease expiry, stop deadlines and restart reconciliation.

* Lease expiry -> run ``lost``, job ``lost``, task ``blocked(recovery_required)``. NO new job is
  issued: the old child may still be alive, so re-issuing waits for supervisor reconcile + an
  explicit resume (06_EXECUTION_PROTOCOL "Lease и повторы").
* A fenced (stopping) run whose runner never confirms -> control ``unknown``, task
  ``blocked(stop_unknown)``; never a fictitious "stopped" (Q10).
* The same function runs at server start (restart recovery), lazily before lifecycle requests and
  from the background watchdog, so behaviour is identical on every path.
"""

from __future__ import annotations

import logging

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from nozo_relay.clock import Clock
from nozo_relay.config import Settings
from nozo_relay.db.models import Control, Job, Run, Task
from nozo_relay.domain.enums import (
    ACTIVE_RUN_STATUSES,
    BlockedReason,
    ControlStatus,
    JobStatus,
    RunStatus,
    TaskStatus,
)
from nozo_relay.services.common import parent_control_refresh, set_job_status, set_run_status, set_task_status
from nozo_relay.services.events import append_event

log = logging.getLogger("nozo_relay.leases")
_ACTIVE = [s.value for s in ACTIVE_RUN_STATUSES]
_OPEN = [ControlStatus.REQUESTED.value, ControlStatus.STOPPING.value]


def needs_sweep(db: Session, clock: Clock, settings: Settings) -> bool:
    """Cheap read-only probe so the write lock is only taken when there is something to do."""
    now = clock.now_ms()
    expired = db.execute(
        select(func.count()).select_from(Run).where(Run.status.in_(_ACTIVE), Run.lease_expires_at <= now)
    ).scalar_one()
    if expired:
        return True
    overdue = db.execute(
        select(func.count())
        .select_from(Control)
        .where(
            Control.status.in_(_OPEN),
            Control.target_run_id.is_not(None),
            Control.requested_at + settings.stop_confirm_deadline_seconds * 1000 <= now,
        )
    ).scalar_one()
    return bool(overdue)


def lose_run(
    ws: Session, clock: Clock, run: Run, *, reason: str, blocked: BlockedReason
) -> bool:
    """Run/job -> lost; open controls -> unknown; task -> blocked. Returns True if a stop was pending.

    Never creates a replacement job: re-issue needs supervisor reconcile + explicit resume.
    """
    import json

    job = ws.get(Job, run.job_id)
    task = ws.get(Task, job.task_id)
    assert job is not None and task is not None
    set_run_status(run, RunStatus.LOST, clock, error_code=reason)
    set_job_status(job, JobStatus.LOST)
    ctls = ws.execute(
        select(Control).where(Control.target_run_id == run.id, Control.status.in_(_OPEN))
    ).scalars().all()
    for c in ctls:
        c.status = ControlStatus.UNKNOWN.value
    ws.flush()
    append_event(
        ws, clock, type="run.lost", project_id=task.project_id, task_id=task.id,
        entity_version=task.version,
        payload={"run_id": run.id, "job_id": job.id, "lease_epoch": run.lease_epoch, "reason": reason},
    )
    task.resume_stage = job.stage
    was_stop = task.status == TaskStatus.STOP_REQUESTED.value
    if was_stop:
        set_task_status(
            ws, clock, task, "stop_unknown", TaskStatus.BLOCKED, actor_id=None,
            blocked_reason=BlockedReason.STOP_UNKNOWN,
            payload={"run_id": run.id, "quarantine_required": True},
        )
    elif task.status in (TaskStatus.CLAIMED.value, TaskStatus.RUNNING.value, TaskStatus.REVIEWING.value):
        set_task_status(
            ws, clock, task, "lease_lost", TaskStatus.BLOCKED, actor_id=None,
            blocked_reason=blocked, payload={"run_id": run.id, "quarantine_required": True},
        )
    for c in ctls:
        parent = json.loads(c.payload_json).get("parent_control_id")
        if parent:
            parent_control_refresh(ws, clock, parent)
    return was_stop


def sweep(ws: Session, clock: Clock, settings: Settings) -> dict[str, int]:
    """Mark expired leases lost and overdue stops unknown. Returns counters (for logs/tests)."""
    import json

    now = clock.now_ms()
    lost = unknown = 0

    expired = ws.execute(
        select(Run).where(Run.status.in_(_ACTIVE), Run.lease_expires_at <= now).order_by(Run.lease_expires_at, Run.id)
    ).scalars().all()
    for run in expired:
        was_stop = lose_run(ws, clock, run, reason="lease_expired", blocked=BlockedReason.RECOVERY_REQUIRED)
        lost += 1
        unknown += int(was_stop)

    overdue = ws.execute(
        select(Control).where(
            Control.status.in_(_OPEN),
            Control.target_run_id.is_not(None),
            Control.requested_at + settings.stop_confirm_deadline_seconds * 1000 <= now,
        )
    ).scalars().all()
    for c in overdue:
        run = ws.get(Run, c.target_run_id)
        task = ws.get(Task, c.task_id) if c.task_id else None
        if run is None or run.status != RunStatus.STOPPING.value or task is None:
            continue
        c.status = ControlStatus.UNKNOWN.value
        unknown += 1
        append_event(
            ws, clock, type="control.unknown", project_id=c.project_id, task_id=task.id,
            payload={"control_id": c.id, "run_id": run.id, "reason": "stop_not_confirmed",
                     "quarantine_required": True},
        )
        if task.status == TaskStatus.STOP_REQUESTED.value:
            set_task_status(
                ws, clock, task, "stop_unknown", TaskStatus.BLOCKED, actor_id=None,
                blocked_reason=BlockedReason.STOP_UNKNOWN, payload={"run_id": run.id},
            )
        parent = json.loads(c.payload_json).get("parent_control_id")
        if parent:
            parent_control_refresh(ws, clock, parent)
    if lost or unknown:
        log.warning("lease sweep: lost=%d stop_unknown=%d", lost, unknown)
    return {"lost": lost, "stop_unknown": unknown}
