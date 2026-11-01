"""Project policy (owner-only), failure budget and scope-ceiling formalisation.

The policy JSON is part of every task revision's ``policy_digest``. Changing the policy therefore
makes jobs of older revisions *stale*: ``claim`` refuses to lease them until the owner creates a new
revision (``revise``), exactly like a scope change (06_EXECUTION_PROTOCOL: stale policy never runs).
"""

from __future__ import annotations

import json
from typing import Any

from sqlalchemy.orm import Session

from nozo_relay.api.errors import RelayError
from nozo_relay.api.schemas import PolicyUpdate, ProjectPolicy
from nozo_relay.auth.context import PrincipalContext
from nozo_relay.clock import Clock
from nozo_relay.config import Settings
from nozo_relay.db.models import Project, TaskRevision
from nozo_relay.services import acl
from nozo_relay.services.events import append_event
from nozo_relay.services.tasks import check_version


def effective_policy(project: Project) -> ProjectPolicy:
    return ProjectPolicy.model_validate(json.loads(project.policy_json or "{}"))


def policy_to_dict(project: Project) -> dict[str, Any]:
    return {
        "project_id": project.id,
        "policy_revision": project.policy_revision,
        "policy": effective_policy(project).model_dump(mode="json"),
        "version": project.version,
    }


def revision_policy_is_current(project: Project, rev: TaskRevision) -> bool:
    """True iff the revision's stored digest equals the digest under the project's CURRENT policy."""
    from nozo_relay.services.tasks import compute_policy_digest

    return compute_policy_digest(
        project,
        {
            "mode": rev.mode,
            "autonomous": bool(rev.autonomous),
            "scope": json.loads(rev.scope_json),
            "requirements": json.loads(rev.requirements_json),
            "acceptance": json.loads(rev.acceptance_json),
        },
    ) == rev.policy_digest


def runtime_retry_limit(project: Project, settings: Settings) -> int:
    limit = effective_policy(project).runtime_retry_limit
    return settings.runtime_retry_limit if limit is None else limit


def update_policy(
    ws: Session,
    clock: Clock,
    principal: PrincipalContext,
    project: Project,
    dto: PolicyUpdate,
    expected_version: int,
) -> dict[str, Any]:
    """Owner-only. Bumps ``policy_revision``; never touches existing (immutable) revisions."""
    acl.require_owner(principal, project)
    check_version(project.version, expected_version, "project")
    new = dto.policy.model_dump(mode="json")
    if new == effective_policy(project).model_dump(mode="json"):
        return policy_to_dict(project)  # no-op: no revision bump, no event
    project.policy_json = json.dumps(new, sort_keys=True, separators=(",", ":"))
    project.policy_revision += 1
    project.version += 1
    append_event(
        ws, clock, type="project.policy_changed", project_id=project.id, entity_version=project.version,
        actor_id=principal.id,
        payload={"policy_revision": project.policy_revision, "reason": dto.reason[:200]},
    )
    return policy_to_dict(project)


def enforce_task_policy(
    project: Project, *, scope: dict[str, Any], autonomous: bool, max_failed_reviews: int | None = None
) -> None:
    """Project-wide limits that apply to every actor (the owner cannot create a task above own ceiling)."""
    pol = effective_policy(project)
    if max_failed_reviews is not None and max_failed_reviews > pol.max_failed_reviews_cap:
        raise RelayError(
            422, "policy_violation", "max_failed_reviews exceeds the project failure budget",
            details={"cap": pol.max_failed_reviews_cap},
        )
    if autonomous and not pol.allow_autonomous:
        raise RelayError(422, "policy_violation", "Project policy forbids autonomous tasks")
    if pol.scope_ceiling is not None and not acl.scope_within(scope, pol.scope_ceiling.model_dump(mode="json")):
        raise RelayError(422, "policy_violation", "Task scope exceeds the project scope ceiling")
