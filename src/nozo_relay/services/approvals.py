"""Approval-request RECORDS (M1). The relay has no publish/push/deploy executor, by design.

An approval is a one-shot, expiring, digest-bound record::

    action_digest = H(kind, project_id, task_id, task revision, destination, commit/artifact digest, max cost)
    scope_digest  = H(task revision, revision policy digest, latest implementation snapshot, project policy_revision)

* the owner decides with a *recent* password proof (session only, never an agent key);
* the decision must quote the exact ``action_digest``;
* anything that changes the bound object (new revision / new snapshot-commit / policy change) makes the
  record stale (``binding_changed``) - it can never be approved or consumed afterwards;
* ``consume`` is single-use (``max_uses``); a used / expired / rejected / stale record is denied;
* even a perfectly valid approved record only ever reaches ``execute``, which refuses
  (``501 no_executor``): there is nothing that could run a publish.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

from sqlalchemy import func, literal_column, select
from sqlalchemy.orm import Session

from nozo_relay.api.errors import RelayError
from nozo_relay.api.schemas import ApprovalDecision, ApprovalRequestCreate
from nozo_relay.auth.context import PrincipalContext
from nozo_relay.auth.sessions import is_recent_auth
from nozo_relay.clock import Clock, ms_to_rfc3339
from nozo_relay.config import Settings
from nozo_relay.db.models import ApprovalRequest, Job, Project, Task
from nozo_relay.domain.enums import ApprovalStatus, JobStage, JobStatus
from nozo_relay.domain.fingerprints import digest_of
from nozo_relay.logsafe import redact
from nozo_relay.services import acl
from nozo_relay.services.common import get_revision
from nozo_relay.services.events import append_event


def _task_binding(ws: Session, task: Task) -> dict[str, Any]:
    rev = get_revision(ws, task)
    snap = ws.execute(
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
    snapshot: dict[str, Any] | None = None
    if snap:
        from nozo_relay.db.models import Snapshot

        s = ws.get(Snapshot, snap)
        if s is not None:
            snapshot = {"id": s.id, "head_commit": s.head_commit, "tree_hash": s.tree_hash, "diff_hash": s.diff_hash}
    return {"revision": rev.revision, "policy_digest": rev.policy_digest, "snapshot": snapshot}


def compute_action_digest(
    project_id: str, kind: str, task_id: str | None, revision: int | None, action: dict[str, Any]
) -> str:
    return digest_of(
        {"kind": kind, "project_id": project_id, "task_id": task_id, "revision": revision, "action": action}
    )


def compute_scope_digest(ws: Session, project: Project, task: Task | None) -> str:
    return digest_of(
        {
            "project_id": project.id,
            "policy_revision": project.policy_revision,
            "task": _task_binding(ws, task) if task is not None else None,
        }
    )


def approval_to_dict(a: ApprovalRequest) -> dict[str, Any]:
    return {
        "id": a.id,
        "project_id": a.project_id,
        "task_id": a.task_id,
        "revision": a.revision,
        "kind": a.kind,
        "summary": a.summary,
        "action": json.loads(a.action_json),
        "action_digest": a.action_digest,
        "scope_digest": a.scope_digest,
        "status": a.status,
        "requested_by": a.requested_by,
        "approved_by": a.approved_by,
        "max_uses": a.max_uses,
        "use_count": a.use_count,
        "expires_at": ms_to_rfc3339(a.expires_at),
        "created_at": ms_to_rfc3339(a.created_at),
        "decided_at": ms_to_rfc3339(a.decided_at) if a.decided_at is not None else None,
        "decision_reason": a.decision_reason,
        "executor": "none",  # M1: records only, nothing can execute an approved action
    }


def _error(http_status: int, code: str, message: str, **details: Any) -> tuple[int, dict[str, Any]]:
    return http_status, {"error": {"code": code, "message": message, "retryable": False, "details": details or None}}


def get_request(ws: Session, project: Project, approval_id: str) -> ApprovalRequest:
    a = ws.get(ApprovalRequest, approval_id)
    if a is None or a.project_id != project.id:
        raise acl.not_found()
    return a


def list_requests(ws: Session, project: Project, *, status: str | None = None) -> list[dict[str, Any]]:
    q = select(ApprovalRequest).where(ApprovalRequest.project_id == project.id)
    if status is not None:
        try:
            q = q.where(ApprovalRequest.status == ApprovalStatus(status).value)
        except ValueError:
            raise RelayError(422, "invalid_status", "Unknown approval status filter") from None
    rows = ws.execute(q.order_by(ApprovalRequest.created_at, ApprovalRequest.id).limit(200)).scalars().all()
    return [approval_to_dict(a) for a in rows]


def create_request(
    ws: Session,
    clock: Clock,
    settings: Settings,
    principal: PrincipalContext,
    project: Project,
    dto: ApprovalRequestCreate,
) -> ApprovalRequest:
    """Any project member may *ask*; nobody but the owner can decide (and nobody can execute)."""
    acl.project_role(principal, project)
    acl.require_enabled(project)
    task: Task | None = None
    if dto.task_id is not None:
        task = ws.get(Task, dto.task_id)
        if task is None or task.project_id != project.id:
            raise acl.not_found()
    pending = ws.execute(
        select(func.count()).select_from(ApprovalRequest).where(
            ApprovalRequest.project_id == project.id, ApprovalRequest.status == ApprovalStatus.PENDING.value
        )
    ).scalar_one()
    if pending >= settings.approval_max_pending_per_project:
        raise RelayError(409, "too_many_pending", "Too many pending approval requests in this project")
    ttl = min(dto.expires_in_seconds, settings.approval_max_ttl_seconds)
    action = dto.action.model_dump(mode="json")
    revision = task.current_revision if task is not None else None
    now = clock.now_ms()
    a = ApprovalRequest(
        project_id=project.id,
        task_id=task.id if task else None,
        requested_by=principal.id,
        kind=dto.kind,
        action_digest=compute_action_digest(project.id, dto.kind, dto.task_id, revision, action),
        scope_digest=compute_scope_digest(ws, project, task),
        status=ApprovalStatus.PENDING.value,
        expires_at=now + ttl * 1000,
        max_uses=1,
        use_count=0,
        created_at=now,
        summary=redact(dto.summary, max_len=2000),
        action_json=json.dumps(action, sort_keys=True, separators=(",", ":")),
        revision=revision,
    )
    ws.add(a)
    ws.flush()
    append_event(
        ws, clock, type="approval.requested", project_id=project.id, task_id=a.task_id,
        actor_id=principal.id,
        payload={"approval_id": a.id, "kind": a.kind, "action_digest": a.action_digest},
    )
    return a


def _expire(ws: Session, clock: Clock, a: ApprovalRequest, reason: str, actor_id: str | None) -> None:
    a.status = ApprovalStatus.EXPIRED.value
    a.decided_at = clock.now_ms()
    a.decision_reason = reason
    ws.flush()
    append_event(
        ws, clock, type="approval.expired", project_id=a.project_id, task_id=a.task_id, actor_id=actor_id,
        payload={"approval_id": a.id, "reason": reason},
    )


def _revalidate(ws: Session, clock: Clock, project: Project, a: ApprovalRequest, actor_id: str | None) -> tuple[int, dict[str, Any]] | None:
    """Time + binding checks shared by decision, consume and execute. Mutates (marks expired)."""
    if clock.now_ms() >= a.expires_at:
        _expire(ws, clock, a, "expired", actor_id)
        return _error(409, "approval_expired", "The approval request expired")
    task = ws.get(Task, a.task_id) if a.task_id else None
    if compute_scope_digest(ws, project, task) != a.scope_digest:
        _expire(ws, clock, a, "binding_changed", actor_id)
        return _error(
            409, "binding_changed",
            "The task revision, commit/snapshot or project policy changed after the request; request again",
        )
    return None


def decide(
    ws: Session,
    clock: Clock,
    settings: Settings,
    principal: PrincipalContext,
    project: Project,
    approval_id: str,
    dto: ApprovalDecision,
) -> tuple[int, dict[str, Any]]:
    """Owner decision: browser session + recent password proof + exact action_digest."""
    acl.require_owner(principal, project)
    if principal.auth_method != "session":
        raise RelayError(403, "session_required", "Approval decisions require an owner browser session")
    if not is_recent_auth(principal.reauth_at, clock, settings):
        raise RelayError(
            403, "recent_auth_required", "Re-enter the owner password (POST /auth/reauth) to decide",
            details={"max_age_seconds": settings.recent_auth_seconds},
        )
    a = get_request(ws, project, approval_id)
    if a.status != ApprovalStatus.PENDING.value:
        return _error(409, "not_pending", f"Approval request is {a.status}", status=a.status)
    if dto.action_digest != a.action_digest:
        return _error(409, "digest_mismatch", "action_digest does not match this request")
    if (bad := _revalidate(ws, clock, project, a, principal.id)) is not None:
        return bad
    now = clock.now_ms()
    a.status = ApprovalStatus.APPROVED.value if dto.decision == "approve" else ApprovalStatus.REJECTED.value
    a.approved_by = principal.id if dto.decision == "approve" else None
    a.decided_at = now
    a.decision_reason = redact(dto.reason, max_len=1000) or None
    ws.flush()
    append_event(
        ws, clock, type=f"approval.{a.status}", project_id=project.id, task_id=a.task_id, actor_id=principal.id,
        payload={"approval_id": a.id, "kind": a.kind, "action_digest": a.action_digest},
    )
    return 200, approval_to_dict(a)


@dataclass(frozen=True)
class ConsumeResult:
    ok: bool
    reason: str | None
    request: ApprovalRequest | None


def consume(
    ws: Session, clock: Clock, project: Project, approval_id: str, action_digest: str
) -> ConsumeResult:
    """Single use of an approved record (for a FUTURE constrained executor). Never executes anything.

    Denied (and nothing consumed) when: unknown, wrong digest, not approved (pending / rejected / used /
    expired), expired by time, bound object changed, or ``use_count`` already reached ``max_uses``.
    """
    a = ws.get(ApprovalRequest, approval_id)
    if a is None or a.project_id != project.id:
        return ConsumeResult(False, "not_found", None)
    if action_digest != a.action_digest:
        return ConsumeResult(False, "digest_mismatch", a)
    if a.status != ApprovalStatus.APPROVED.value:
        return ConsumeResult(False, f"status_{a.status}", a)
    if a.use_count >= a.max_uses:
        a.status = ApprovalStatus.USED.value
        return ConsumeResult(False, "already_used", a)
    if (bad := _revalidate(ws, clock, project, a, None)) is not None:
        return ConsumeResult(False, bad[1]["error"]["code"], a)
    a.use_count += 1
    if a.use_count >= a.max_uses:
        a.status = ApprovalStatus.USED.value
    ws.flush()
    append_event(
        ws, clock, type="approval.consumed", project_id=project.id, task_id=a.task_id,
        payload={"approval_id": a.id, "use_count": a.use_count},
    )
    return ConsumeResult(True, None, a)


def execute(
    ws: Session, clock: Clock, project: Project, principal: PrincipalContext, approval_id: str, action_digest: str
) -> tuple[int, dict[str, Any]]:
    """There is NO executor. Valid or not, nothing runs and nothing is consumed."""
    acl.require_owner(principal, project)
    a = get_request(ws, project, approval_id)
    if action_digest != a.action_digest:
        return _error(409, "digest_mismatch", "action_digest does not match this request")
    if a.status != ApprovalStatus.APPROVED.value:
        return _error(409, "not_approved", f"Approval request is {a.status}", status=a.status)
    if (bad := _revalidate(ws, clock, project, a, principal.id)) is not None:
        return bad
    append_event(
        ws, clock, type="approval.execution_denied", project_id=project.id, task_id=a.task_id,
        actor_id=principal.id, payload={"approval_id": a.id, "reason": "no_executor"},
    )
    return _error(
        501, "no_executor",
        "This relay has no publish/push/deploy executor; the approval record is not an action",
        approval_id=a.id,
    )
