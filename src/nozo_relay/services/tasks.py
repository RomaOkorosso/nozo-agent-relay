"""Tasks: create draft, read, list, enqueue, and the optimistic ``If-Match`` version guard."""

from __future__ import annotations

import json
from typing import Any

from sqlalchemy import literal_column, select
from sqlalchemy.orm import Session

from nozo_relay.api.errors import RelayError
from nozo_relay.api.schemas import TaskCreate
from nozo_relay.auth.context import PrincipalContext
from nozo_relay.clock import Clock, ms_to_rfc3339
from nozo_relay.db.models import Job, Principal, Project, Report, Snapshot, Task, TaskRevision, Membership
from nozo_relay.domain.enums import (
    JobStage,
    JobStatus,
    MembershipRole,
    PrincipalKind,
    TaskStatus,
)
from nozo_relay.domain.fingerprints import policy_digest
from nozo_relay.services import acl
from nozo_relay.services.common import create_job, get_revision, set_task_status
from nozo_relay.services.events import append_event
from nozo_relay.services.pagination import clamp_limit, decode_cursor, encode_cursor


def parse_if_match(raw: str | None) -> int:
    if raw is None or not raw.strip():
        raise RelayError(428, "precondition_required", 'If-Match header is required (e.g. If-Match: "3")')
    value = raw.strip()
    if value.startswith("W/"):
        value = value[2:]
    value = value.strip('"')
    if not value.isdigit():
        raise RelayError(422, "invalid_if_match", "If-Match must be a quoted integer version")
    return int(value)


def check_version(current: int, expected: int, what: str = "resource") -> None:
    if current != expected:
        raise RelayError(
            412,
            "version_conflict",
            f"{what} was modified (current version {current}); re-read and retry",
            details={"current_version": current},
        )


def compute_policy_digest(project: Project, rev: dict[str, Any]) -> str:
    return policy_digest(
        project_id=project.id,
        policy_revision=project.policy_revision,
        project_policy=json.loads(project.policy_json),
        mode=rev["mode"],
        autonomous=rev["autonomous"],
        scope=rev["scope"],
        requirements=rev["requirements"],
        acceptance=rev["acceptance"],
    )


# ------------------------------------------------------------------ validation


def validate_assignee(
    ws: Session, project: Project, principal_id: str, kind: PrincipalKind, role: MembershipRole, label: str
) -> Principal:
    p = ws.get(Principal, principal_id)
    m = ws.get(Membership, (principal_id, project.id)) if p else None
    if p is None or not p.active or p.kind != kind.value or m is None or m.role != role.value:
        raise RelayError(
            422,
            "invalid_assignee",
            f"{label} must be an active {kind.value} member of this project",
            details={"field": label},
        )
    return p


def validate_assignees(
    ws: Session, project: Project, implementer_id: str, auditor_id: str
) -> None:
    validate_assignee(ws, project, implementer_id, PrincipalKind.IMPLEMENTER, MembershipRole.IMPLEMENTER, "implementer_id")
    validate_assignee(ws, project, auditor_id, PrincipalKind.AUDITOR, MembershipRole.AUDITOR, "auditor_id")
    if implementer_id == auditor_id:
        raise RelayError(
            403, "self_review_forbidden", "Implementer and auditor must be different principals"
        )


# ------------------------------------------------------------------ views


def task_to_dict(ws: Session, task: Task, rev: TaskRevision | None = None) -> dict[str, Any]:
    rev = rev or get_revision(ws, task)
    latest_report = ws.execute(
        select(Report.id).where(Report.task_id == task.id).order_by(literal_column("reports.rowid").desc()).limit(1)
    ).scalar()
    current_snapshot = ws.execute(
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
    return {
        "id": task.id,
        "project_id": task.project_id,
        "status": task.status,
        "version": task.version,
        "revision": task.current_revision,
        "title": task.title,
        "authority_tier": task.effective_tier,
        "urgency": task.urgency,
        "mode": rev.mode,
        "autonomous": bool(rev.autonomous),
        "failed_review_count": task.failed_review_count,
        "max_failed_reviews": task.max_failed_reviews,
        "assignees": {"implementer_id": task.implementer_id, "auditor_id": task.auditor_id},
        "timestamps": {
            "created_at": ms_to_rfc3339(task.created_at),
            "updated_at": ms_to_rfc3339(task.updated_at),
        },
        "blocked_reason": task.blocked_reason,
        "latest_report_id": latest_report,
        "current_snapshot_id": current_snapshot,
    }


def revision_to_dict(rev: TaskRevision) -> dict[str, Any]:
    return {
        "revision": rev.revision,
        "requirements": json.loads(rev.requirements_json),
        "acceptance": json.loads(rev.acceptance_json),
        "mode": rev.mode,
        "autonomous": bool(rev.autonomous),
        "scope": json.loads(rev.scope_json),
        "policy_digest": rev.policy_digest,
        "delegation_id": rev.delegation_id,
        "created_at": ms_to_rfc3339(rev.created_at),
    }


def task_detail(ws: Session, task: Task) -> dict[str, Any]:
    rev = get_revision(ws, task)
    out = task_to_dict(ws, task, rev)
    out["current_revision"] = revision_to_dict(rev)
    jobs = ws.execute(
        select(Job).where(Job.task_id == task.id).order_by(literal_column("jobs.rowid"))
    ).scalars().all()
    reports = ws.execute(
        select(Report).where(Report.task_id == task.id).order_by(literal_column("reports.rowid"))
    ).scalars().all()
    out["links"] = {
        "jobs": [
            {
                "id": j.id,
                "stage": j.stage,
                "sequence": j.sequence,
                "revision": j.revision,
                "status": j.status,
                "dispatch_authorized": j.dispatch_authorized,
                "input_snapshot_id": j.input_snapshot_id,
                "output_snapshot_id": j.output_snapshot_id,
            }
            for j in jobs
        ],
        "reports": [
            {"id": r.id, "kind": r.kind, "verdict": r.verdict, "revision": r.revision, "snapshot_id": r.snapshot_id}
            for r in reports
        ],
    }
    return out


def list_tasks(
    ws: Session, project: Project, *, status: str | None, limit: int | None, cursor: str | None
) -> dict[str, Any]:
    lim = clamp_limit(limit)
    q = select(Task).where(Task.project_id == project.id)
    if status is not None:
        try:
            q = q.where(Task.status == TaskStatus(status).value)
        except ValueError:
            raise RelayError(422, "invalid_status", "Unknown task status filter") from None
    after = decode_cursor(cursor, 2)
    if after:
        q = q.where((Task.created_at > after[0]) | ((Task.created_at == after[0]) & (Task.id > after[1])))
    rows = ws.execute(q.order_by(Task.created_at, Task.id).limit(lim + 1)).scalars().all()
    more = len(rows) > lim
    rows = rows[:lim]
    return {
        "items": [task_to_dict(ws, t) for t in rows],
        "next_cursor": encode_cursor([rows[-1].created_at, rows[-1].id]) if more and rows else None,
    }


# ------------------------------------------------------------------ commands


def create_task(
    ws: Session, clock: Clock, principal: PrincipalContext, project: Project, dto: TaskCreate
) -> Task:
    """Draft task + revision 1. Actor and tier come from the credential, never the payload."""
    role = acl.require_roles(principal, project, MembershipRole.OWNER, MembershipRole.COORDINATOR)
    acl.require_enabled(project)
    scope = dto.scope.model_dump(mode="json")
    delegation_id: str | None = None
    if principal.kind is PrincipalKind.COORDINATOR:
        d = acl.load_delegation(ws, clock, project, principal.id, dto.delegation_id, "task.create")
        ceiling = acl.delegation_ceiling(d)
        if not acl.scope_within(scope, ceiling):
            raise acl.forbidden("Task scope exceeds the delegated scope ceiling")
        if dto.autonomous and not ceiling.get("allow_autonomous"):
            raise acl.forbidden("Delegation does not allow autonomous tasks")
        delegation_id = d.id
    elif role == MembershipRole.OWNER.value and dto.delegation_id is not None:
        raise RelayError(422, "delegation_not_applicable", "delegation_id is only used by coordinators")

    from nozo_relay.services.policy import enforce_task_policy  # local: policy imports this module

    enforce_task_policy(
        project, scope=scope, autonomous=dto.autonomous, max_failed_reviews=dto.max_failed_reviews
    )
    validate_assignees(ws, project, dto.implementer_id, dto.auditor_id)

    now = clock.now_ms()
    rev_fields = {
        "requirements": dto.requirements,
        "acceptance": list(dto.acceptance),
        "mode": dto.mode.value,
        "autonomous": dto.autonomous,
        "scope": scope,
    }
    task = Task(
        project_id=project.id,
        title=dto.title,
        status=TaskStatus.DRAFT.value,
        version=1,
        current_revision=1,
        origin_principal_id=principal.id,
        effective_tier=principal.tier.value,
        urgency=dto.urgency.value,
        implementer_id=dto.implementer_id,
        auditor_id=dto.auditor_id,
        failed_review_count=0,
        max_failed_reviews=dto.max_failed_reviews,
        created_at=now,
        updated_at=now,
    )
    ws.add(task)
    ws.flush()
    write_revision(ws, clock, task, project, rev_fields, created_by=principal.id, delegation_id=delegation_id)
    append_event(
        ws,
        clock,
        type="task.created",
        project_id=project.id,
        task_id=task.id,
        entity_version=task.version,
        actor_id=principal.id,
        payload={"status": task.status, "title": task.title, "revision": 1, "tier": task.effective_tier},
    )
    return task


def write_revision(
    ws: Session,
    clock: Clock,
    task: Task,
    project: Project,
    fields: dict[str, Any],
    *,
    created_by: str,
    delegation_id: str | None,
) -> TaskRevision:
    rev = TaskRevision(
        task_id=task.id,
        revision=task.current_revision,
        requirements_json=json.dumps(fields["requirements"]),
        acceptance_json=json.dumps(fields["acceptance"]),
        mode=fields["mode"],
        autonomous=fields["autonomous"],
        scope_json=json.dumps(fields["scope"], sort_keys=True),
        base_snapshot_id=None,
        policy_digest=compute_policy_digest(project, fields),
        delegation_id=delegation_id,
        created_by=created_by,
        created_at=clock.now_ms(),
    )
    ws.add(rev)
    ws.flush()
    return rev


def check_actor_may_drive(
    ws: Session, clock: Clock, principal: PrincipalContext, project: Project, task: Task, action: str
) -> None:
    """Owner, or a coordinator acting within a still-valid delegation on a task it originated."""
    if principal.is_owner:
        acl.require_owner(principal, project)
        return
    if principal.kind is PrincipalKind.COORDINATOR and acl.project_role(principal, project) == "coordinator":
        if task.origin_principal_id != principal.id:
            raise acl.forbidden("Coordinators can only drive tasks they created")
        rev = get_revision(ws, task, 1)
        acl.load_delegation(ws, clock, project, principal.id, rev.delegation_id, action)
        return
    raise acl.forbidden()


def enqueue_task(
    ws: Session, clock: Clock, principal: PrincipalContext, project: Project, task: Task, expected_version: int
) -> Task:
    check_actor_may_drive(ws, clock, principal, project, task, "task.enqueue")
    acl.require_enabled(project)
    check_version(task.version, expected_version, "task")
    if task.status != TaskStatus.DRAFT.value:
        raise RelayError(409, "invalid_state", f"Only draft tasks can be enqueued (status={task.status})")
    rev = get_revision(ws, task)
    # Guards of the lifecycle table: requirements/acceptance/scope/assignees are valid.
    if not json.loads(rev.acceptance_json) or not json.loads(rev.scope_json).get("allowed_paths"):
        raise RelayError(422, "task_incomplete", "Task requires acceptance criteria and a scope allowlist")
    validate_assignees(ws, project, task.implementer_id or "", task.auditor_id or "")
    set_task_status(
        ws, clock, task, "enqueue", TaskStatus.QUEUED, actor_id=principal.id, payload={"revision": rev.revision}
    )
    create_job(ws, clock, task, rev, JobStage.IMPLEMENT, input_snapshot_id=None, actor_id=principal.id)
    return task


def snapshot_of_task(ws: Session, snapshot_id: str) -> Snapshot | None:
    return ws.get(Snapshot, snapshot_id)
