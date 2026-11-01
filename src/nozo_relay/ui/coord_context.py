"""View helpers: what the current principal may do in the owner panel templates."""

from __future__ import annotations

import json
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from nozo_relay.auth.context import PrincipalContext
from nozo_relay.clock import Clock
from nozo_relay.db.models import Delegation, Project, Task
from nozo_relay.domain.enums import PrincipalKind
from nozo_relay.services import projects as projects_svc


def can_post_chat(principal: PrincipalContext) -> bool:
    """Any project member except runners may post typed chat notes (server ACL agrees)."""
    return principal.kind is not PrincipalKind.RUNNER


def active_delegation_for(
    db: Session, clock: Clock, principal: PrincipalContext, project: Project
) -> dict[str, Any] | None:
    if principal.kind is not PrincipalKind.COORDINATOR:
        return None
    now = clock.now_ms()
    rows = db.execute(
        select(Delegation)
        .where(
            Delegation.project_id == project.id,
            Delegation.coordinator_id == principal.id,
            Delegation.revoked_at.is_(None),
            Delegation.valid_until > now,
        )
        .order_by(Delegation.created_at.desc())
    ).scalars().all()
    for d in rows:
        actions = set(json.loads(d.allowed_actions_json))
        if "task.create" in actions or "message.create" in actions or "task.control" in actions:
            return projects_svc.delegation_to_dict(d)
    return None


def can_create_task(principal: PrincipalContext, delegation: dict[str, Any] | None) -> bool:
    if principal.is_owner:
        return True
    if principal.kind is not PrincipalKind.COORDINATOR or delegation is None:
        return False
    return "task.create" in set(delegation.get("allowed_actions") or [])


def can_drive_task(principal: PrincipalContext, task: Task, delegation: dict[str, Any] | None) -> bool:
    if principal.is_owner:
        return True
    if principal.kind is not PrincipalKind.COORDINATOR:
        return False
    if task.origin_principal_id != principal.id:
        return False
    if delegation is None:
        return False
    return "task.control" in set(delegation.get("allowed_actions") or []) or "task.enqueue" in set(
        delegation.get("allowed_actions") or []
    )
