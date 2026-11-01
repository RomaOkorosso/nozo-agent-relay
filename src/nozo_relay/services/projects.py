"""Projects: create / list / patch, delegation grants, and the consistent UI snapshot."""

from __future__ import annotations

import json
from datetime import datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from nozo_relay.api.errors import RelayError
from nozo_relay.api.schemas import DelegationCreate, ProjectCreate
from nozo_relay.auth.context import PrincipalContext
from nozo_relay.clock import Clock, ms_to_rfc3339
from nozo_relay.db.models import (
    Control,
    Delegation,
    Job,
    Membership,
    Message,
    Principal,
    Project,
    Run,
    Task,
)
from nozo_relay.domain.enums import ACTIVE_JOB_STATUSES, MembershipRole, PrincipalKind
from nozo_relay.services import events as ev
from nozo_relay.services.events import append_event


def project_to_dict(p: Project) -> dict[str, Any]:
    return {
        "id": p.id,
        "slug": p.slug,
        "name": p.name,
        "enabled": p.enabled,
        "paused": p.paused,
        "version": p.version,
        "policy_revision": p.policy_revision,
        "created_at": ms_to_rfc3339(p.created_at),
    }


def create_project(ws: Session, clock: Clock, owner: PrincipalContext, dto: ProjectCreate) -> Project:
    now = clock.now_ms()
    project = Project(slug=dto.slug, name=dto.name, created_at=now)
    ws.add(project)
    try:
        ws.flush()
    except IntegrityError:
        ws.rollback()
        raise RelayError(409, "slug_taken", "A project with this slug already exists") from None
    ws.add(Membership(principal_id=owner.id, project_id=project.id, role=MembershipRole.OWNER.value))
    ws.flush()
    append_event(
        ws,
        clock,
        type="project.created",
        project_id=project.id,
        entity_version=project.version,
        actor_id=owner.id,
        payload={"slug": project.slug, "name": project.name},
    )
    return project


def list_projects(ws: Session, principal: PrincipalContext) -> list[Project]:
    from nozo_relay.services import acl

    acl.deny_runner_content_read(principal)
    ids = list(principal.project_roles)
    if not ids:
        return []
    return list(
        ws.execute(select(Project).where(Project.id.in_(ids)).order_by(Project.slug)).scalars().all()
    )


def create_delegation(
    ws: Session, clock: Clock, owner: PrincipalContext, project: Project, dto: DelegationCreate
) -> Delegation:
    coord = ws.get(Principal, dto.coordinator_id)
    member = ws.get(Membership, (dto.coordinator_id, project.id))
    if (
        coord is None
        or not coord.active
        or coord.kind != PrincipalKind.COORDINATOR.value
        or member is None
        or member.role != MembershipRole.COORDINATOR.value
    ):
        raise RelayError(422, "invalid_coordinator", "coordinator_id is not a coordinator member of this project")
    valid_until = int(dto.valid_until.timestamp() * 1000)
    if valid_until <= clock.now_ms():
        raise RelayError(422, "invalid_valid_until", "valid_until must be in the future")
    # A delegation can never be wider than the project's own policy ceiling.
    from nozo_relay.services import acl
    from nozo_relay.services.policy import effective_policy

    pol = effective_policy(project)
    ceiling = dto.scope_ceiling.model_dump(mode="json")
    if pol.scope_ceiling is not None and not acl.scope_within(ceiling, pol.scope_ceiling.model_dump(mode="json")):
        raise RelayError(422, "policy_violation", "scope_ceiling exceeds the project scope ceiling")
    if dto.scope_ceiling.allow_autonomous and not pol.allow_autonomous:
        raise RelayError(422, "policy_violation", "Project policy forbids autonomous delegation")
    d = Delegation(
        project_id=project.id,
        coordinator_id=dto.coordinator_id,
        owner_id=owner.id,
        allowed_actions_json=json.dumps(sorted(set(dto.allowed_actions))),
        scope_ceiling_json=json.dumps(dto.scope_ceiling.model_dump(mode="json"), sort_keys=True),
        valid_until=valid_until,
        created_at=clock.now_ms(),
    )
    ws.add(d)
    ws.flush()
    append_event(
        ws,
        clock,
        type="delegation.created",
        project_id=project.id,
        actor_id=owner.id,
        payload={"delegation_id": d.id, "coordinator_id": d.coordinator_id, "actions": dto.allowed_actions},
    )
    return d


def revoke_delegation(
    ws: Session, clock: Clock, owner: PrincipalContext, project: Project, delegation_id: str, reason: str
) -> dict[str, Any]:
    """Owner-only, idempotent. Takes effect for the very next coordinator request (checked per call)."""
    d = ws.get(Delegation, delegation_id)
    if d is None or d.project_id != project.id:
        raise RelayError(404, "not_found", "Resource not found")
    if d.revoked_at is None:
        d.revoked_at = clock.now_ms()
        ws.flush()
        append_event(
            ws, clock, type="delegation.revoked", project_id=project.id, actor_id=owner.id,
            payload={"delegation_id": d.id, "coordinator_id": d.coordinator_id, "reason": reason[:200]},
        )
    return delegation_to_dict(d)


def list_delegations(ws: Session, project: Project) -> list[dict[str, Any]]:
    rows = ws.execute(
        select(Delegation).where(Delegation.project_id == project.id).order_by(Delegation.created_at, Delegation.id)
    ).scalars().all()
    return [delegation_to_dict(d) for d in rows]


def delegation_to_dict(d: Delegation) -> dict[str, Any]:
    return {
        "id": d.id,
        "project_id": d.project_id,
        "coordinator_id": d.coordinator_id,
        "allowed_actions": json.loads(d.allowed_actions_json),
        "scope_ceiling": json.loads(d.scope_ceiling_json),
        "valid_until": ms_to_rfc3339(d.valid_until),
        "revoked": d.revoked_at is not None,
        "revoked_at": ms_to_rfc3339(d.revoked_at) if d.revoked_at is not None else None,
    }


def project_state_snapshot(ws: Session, project: Project) -> dict[str, Any]:
    """Consistent UI state + ``high_watermark`` from ONE read transaction.

    The watermark is read first inside the same snapshot as the rest, so a client can replay
    ``seq > high_watermark`` from the durable log without gap or duplicate.
    """
    from nozo_relay.services.tasks import task_to_dict  # local import: tasks imports this module

    watermark = ev.high_watermark(ws, project.id)
    tasks = ws.execute(
        select(Task).where(Task.project_id == project.id).order_by(Task.created_at, Task.id).limit(200)
    ).scalars().all()
    messages = ws.execute(
        select(Message)
        .where(Message.project_id == project.id)
        .order_by(Message.created_at.desc(), Message.id.desc())
        .limit(50)
    ).scalars().all()
    active_jobs = ws.execute(
        select(Job).where(
            Job.project_id == project.id, Job.status.in_([s.value for s in ACTIVE_JOB_STATUSES])
        )
    ).scalars().all()
    runs = ws.execute(
        select(Run)
        .join(Job, Job.id == Run.job_id)
        .where(Job.project_id == project.id, Run.status.in_(["leased", "running", "stopping"]))
    ).scalars().all()
    pending_controls = ws.execute(
        select(Control).where(
            Control.project_id == project.id, Control.status.in_(["requested", "stopping", "unknown"])
        )
    ).scalars().all()
    from nozo_relay.services.messages import message_to_dict
    from nozo_relay.services.controls import control_to_dict

    return {
        "high_watermark": watermark,
        "project": project_to_dict(project),
        "tasks": [task_to_dict(ws, t) for t in tasks],
        "messages": [message_to_dict(m) for m in reversed(messages)],
        "active_jobs": [
            {
                "id": j.id,
                "task_id": j.task_id,
                "stage": j.stage,
                "status": j.status,
                "assignee_id": j.assignee_id,
                "dispatch_authorized": j.dispatch_authorized,
            }
            for j in active_jobs
        ],
        "active_runs": [
            {
                "id": r.id,
                "job_id": r.job_id,
                "status": r.status,
                "lease_epoch": r.lease_epoch,
                "lease_expires_at": ms_to_rfc3339(r.lease_expires_at),
            }
            for r in runs
        ],
        "pending_controls": [control_to_dict(c) for c in pending_controls],
    }


def valid_until_to_dt(ms: int) -> datetime:  # pragma: no cover - convenience for tests
    from datetime import UTC

    return datetime.fromtimestamp(ms / 1000, tz=UTC)
