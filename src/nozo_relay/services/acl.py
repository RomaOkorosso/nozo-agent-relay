"""Project-scoped access control.

* Membership is required for any project resource; knowing a UUID grants nothing.
* Inaccessible resources answer 404 (not 403) so existence never leaks across projects.
* Actor, role and authority tier always come from the authenticated principal, never from input.
"""

from __future__ import annotations

import json
from typing import Any

from sqlalchemy.orm import Session

from nozo_relay.api.errors import RelayError
from nozo_relay.auth.context import PrincipalContext
from nozo_relay.clock import Clock
from nozo_relay.db.models import Delegation, Job, Project, Run, Task
from nozo_relay.domain.enums import MembershipRole, PrincipalKind
from nozo_relay.services.scope import glob_covers

NOT_FOUND = "Resource not found"


def not_found() -> RelayError:
    return RelayError(404, "not_found", NOT_FOUND)


def forbidden(message: str = "Action is not permitted for this principal") -> RelayError:
    return RelayError(403, "forbidden", message)


def deny_runner_content_read(principal: PrincipalContext) -> None:
    """Supervisors (runner kind) get lifecycle receipts for their own runs only - never project content (T12/F03).

    Content = messages, task details, reports, artifacts, events, snapshots, WS project streams, MCP tools.
    403 for an authenticated runner (it already knows the project exists through its membership).
    """
    if principal.kind is PrincipalKind.RUNNER:
        raise forbidden("Supervisor (runner) credentials cannot access project content")


require_not_runner_for_content = deny_runner_content_read


def get_project(
    ws: Session, principal: PrincipalContext, project_id: str, *, allow_runner: bool = False
) -> Project:
    """Project visible to the principal, else 404.

    Runner-kind principals are refused (403) unless the caller is a lifecycle-receipt endpoint that explicitly
    passes ``allow_runner=True`` (stopped / reconcile).
    """
    if not principal.is_member(project_id):
        raise not_found()
    if not allow_runner:
        deny_runner_content_read(principal)
    project = ws.get(Project, project_id)
    if project is None:
        raise not_found()
    return project


def project_role(principal: PrincipalContext, project: Project) -> str:
    role = principal.role_in(project.id)
    if role is None:
        raise not_found()
    return role


def require_roles(principal: PrincipalContext, project: Project, *roles: MembershipRole) -> str:
    role = project_role(principal, project)
    if role not in {r.value for r in roles}:
        raise forbidden()
    return role


def require_owner(principal: PrincipalContext, project: Project) -> None:
    if not (principal.is_owner and project_role(principal, project) == MembershipRole.OWNER.value):
        raise forbidden("Owner privileges required")


def require_enabled(project: Project) -> None:
    if not project.enabled:
        raise RelayError(409, "project_disabled", "Project is disabled")


def get_task(ws: Session, project: Project, task_id: str) -> Task:
    task = ws.get(Task, task_id)
    if task is None or task.project_id != project.id:
        raise not_found()
    return task


def get_job(ws: Session, project: Project, job_id: str) -> Job:
    job = ws.get(Job, job_id)
    if job is None or job.project_id != project.id:
        raise not_found()
    return job


def get_run_of(ws: Session, project: Project, run_id: str) -> tuple[Run, Job]:
    run = ws.get(Run, run_id)
    if run is None:
        raise not_found()
    job = ws.get(Job, run.job_id)
    if job is None or job.project_id != project.id:
        raise not_found()
    return run, job


# ------------------------------------------------------------------ delegations


def load_delegation(
    ws: Session,
    clock: Clock,
    project: Project,
    coordinator_id: str,
    delegation_id: str | None,
    action: str,
) -> Delegation:
    """A currently valid delegation of ``coordinator_id`` for ``action``; else 403."""
    if delegation_id is None:
        raise forbidden("A valid delegation_id is required for coordinators")
    d = ws.get(Delegation, delegation_id)
    if (
        d is None
        or d.project_id != project.id
        or d.coordinator_id != coordinator_id
        or d.revoked_at is not None
        or d.valid_until <= clock.now_ms()
        or action not in json.loads(d.allowed_actions_json)
    ):
        raise forbidden("Delegation is missing, expired, revoked or does not allow this action")
    return d


def delegation_ceiling(d: Delegation) -> dict[str, Any]:
    return json.loads(d.scope_ceiling_json)


def is_coordinator(principal: PrincipalContext) -> bool:
    return principal.kind is PrincipalKind.COORDINATOR


# ------------------------------------------------------------------ scope arithmetic


def scope_within(scope: dict[str, Any], ceiling: dict[str, Any]) -> bool:
    """True iff ``scope`` does not exceed ``ceiling`` (paths, file/line budgets, dependencies).

    Every allowed glob of the scope must be PROVEN to be covered by some single allowed glob of the ceiling
    (``scope.glob_covers``: exact language inclusion with the manifest-enforcement semantics). Not proven -> False.
    """
    if scope["max_changed_files"] > ceiling["max_changed_files"]:
        return False
    if scope["max_diff_lines"] > ceiling["max_diff_lines"]:
        return False
    if scope.get("allow_new_dependencies") and not ceiling.get("allow_new_dependencies"):
        return False
    ceil_globs = list(ceiling["allowed_paths"])
    for pattern in scope["allowed_paths"]:
        if not any(glob_covers(pattern, c) for c in ceil_globs):
            return False
    return True
