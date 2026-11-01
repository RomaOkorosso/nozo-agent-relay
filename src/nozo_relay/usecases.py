"""Transport-neutral use cases shared by REST routes and the MCP facade (T10).

Both transports call exactly these functions, so ACL order, idempotency scope
(principal + operation + key), guards, events and cached results are identical by construction:
a retry through the *other* transport replays the stored answer instead of creating a duplicate.

Order inside every mutation (unchanged from the original REST routes):
ACL -> role gate -> idempotency replay -> version/lease guards -> mutation + event + cached result,
all in ONE ``BEGIN IMMEDIATE`` transaction.

Nothing here takes ``actor``/``tier``/``role`` from input: they come from ``PrincipalContext``.
"""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Any

from sqlalchemy import Engine
from sqlalchemy.orm import Session, sessionmaker

from nozo_relay.api.errors import RelayError
from nozo_relay.api.schemas import ApprovalRequestCreate, MessageCreate, TaskCreate
from nozo_relay.auth.context import PrincipalContext
from nozo_relay.clock import Clock
from nozo_relay.config import Settings
from nozo_relay.db.engine import make_session_factory, write_session
from nozo_relay.db.models import Report, Task
from nozo_relay.services import acl, leases
from nozo_relay.services import approvals as approvals_svc
from nozo_relay.services import controls as controls_svc
from nozo_relay.services import events as ev
from nozo_relay.services import messages as msg_svc
from nozo_relay.services import projects as projects_svc
from nozo_relay.services import tasks as tasks_svc
from nozo_relay.services.idempotency import Idempotent, request_digest
from nozo_relay.services.pagination import clamp_limit, decode_cursor, encode_cursor
from nozo_relay.services.reports import report_to_dict


@dataclass(frozen=True)
class Ctx:
    """Everything a use case needs; built from the FastAPI app or from a stdio process."""

    engine: Engine
    session_factory: sessionmaker[Session]
    clock: Clock
    settings: Settings

    @classmethod
    def from_app(cls, app: Any) -> Ctx:
        st = app.state
        return cls(st.engine, st.session_factory, st.clock, st.settings)

    @classmethod
    def from_engine(cls, engine: Engine, clock: Clock, settings: Settings) -> Ctx:
        return cls(engine, make_session_factory(engine), clock, settings)

    @contextmanager
    def read(self) -> Iterator[Session]:
        db = self.session_factory()
        try:
            yield db
        finally:
            db.rollback()
            db.close()


@dataclass(frozen=True)
class Outcome:
    """Result of a mutation: HTTP-style status, JSON body, replay flag and entity version."""

    status: int
    body: dict[str, Any]
    replayed: bool = False
    version: int | None = None  # ETag source for fresh responses


def maintenance(ctx: Ctx) -> None:
    """Lazily expire leases / overdue stops before lifecycle calls (cheap read probe first)."""
    with ctx.read() as db:
        due = leases.needs_sweep(db, ctx.clock, ctx.settings)
    if due:
        with write_session(ctx.engine) as ws:
            leases.sweep(ws, ctx.clock, ctx.settings)


def _replayed(hit: Any) -> Outcome:
    return Outcome(hit.status, hit.body, replayed=True)


# ------------------------------------------------------------------ mutations


def create_task(ctx: Ctx, principal: PrincipalContext, project_id: str, body: TaskCreate, key: str) -> Outcome:
    with write_session(ctx.engine) as ws:
        project = acl.get_project(ws, principal, project_id)
        # Role gate BEFORE the idempotency lookup so a demoted principal never reads a cached answer.
        acl.require_roles(principal, project, acl.MembershipRole.OWNER, acl.MembershipRole.COORDINATOR)
        op = Idempotent(
            ws, ctx.clock, principal.id, "task.create", key,
            request_digest("task.create", ids={"project_id": project.id}, body=body.model_dump(mode="json")),
        )
        if (hit := op.replay()) is not None:
            return _replayed(hit)
        task = tasks_svc.create_task(ws, ctx.clock, principal, project, body)
        out = op.finish(201, tasks_svc.task_detail(ws, task))
    return Outcome(out.status, out.body, version=out.body["version"])


def enqueue_task(
    ctx: Ctx, principal: PrincipalContext, project_id: str, task_id: str, key: str, if_match: int
) -> Outcome:
    with write_session(ctx.engine) as ws:
        project = acl.get_project(ws, principal, project_id)
        task = acl.get_task(ws, project, task_id)
        tasks_svc.check_actor_may_drive(ws, ctx.clock, principal, project, task, "task.enqueue")
        op = Idempotent(
            ws, ctx.clock, principal.id, "task.enqueue", key,
            request_digest(
                "task.enqueue", ids={"project_id": project.id, "task_id": task.id}, guards={"if_match": if_match}
            ),
        )
        if (hit := op.replay()) is not None:
            return _replayed(hit)
        tasks_svc.enqueue_task(ws, ctx.clock, principal, project, task, if_match)
        out = op.finish(200, tasks_svc.task_detail(ws, task))
    return Outcome(out.status, out.body, version=out.body["version"])


def control_task(
    ctx: Ctx, principal: PrincipalContext, project_id: str, task_id: str, body: Any, key: str, if_match: int
) -> Outcome:
    """``body`` is a validated ``ControlCreate`` variant (pause/resume/cancel/reassign/revise)."""
    maintenance(ctx)
    with write_session(ctx.engine) as ws:
        project = acl.get_project(ws, principal, project_id)
        task = acl.get_task(ws, project, task_id)
        tasks_svc.check_actor_may_drive(ws, ctx.clock, principal, project, task, "task.control")
        op = Idempotent(
            ws, ctx.clock, principal.id, "task.control", key,
            request_digest(
                "task.control", ids={"project_id": project.id, "task_id": task.id},
                body=body.model_dump(mode="json"), guards={"if_match": if_match},
            ),
        )
        if (hit := op.replay()) is not None:
            return _replayed(hit)
        status, out_body = controls_svc.request_task_control(
            ws, ctx.clock, ctx.settings, principal, project, task, body, if_match
        )
        out = op.finish(status, out_body)
    return Outcome(out.status, out.body, version=out.body["task"]["version"])


def post_message(ctx: Ctx, principal: PrincipalContext, project_id: str, body: MessageCreate, key: str) -> Outcome:
    with write_session(ctx.engine) as ws:
        project = acl.get_project(ws, principal, project_id)
        op = Idempotent(
            ws, ctx.clock, principal.id, "message.create", key,
            request_digest("message.create", ids={"project_id": project.id}, body=body.model_dump(mode="json")),
        )
        if (hit := op.replay()) is not None:
            return _replayed(hit)
        msg, created = msg_svc.create_message(ws, ctx.clock, principal, project, body)
        out = op.finish(201 if created else 200, msg_svc.message_to_dict(msg))
    return Outcome(out.status, out.body)


def request_approval(
    ctx: Ctx, principal: PrincipalContext, project_id: str, body: ApprovalRequestCreate, key: str
) -> Outcome:
    """Creates a PENDING record only. Deciding it is an owner-only, recent-auth, session-only action."""
    with write_session(ctx.engine) as ws:
        project = acl.get_project(ws, principal, project_id)
        op = Idempotent(
            ws, ctx.clock, principal.id, "approval.request", key,
            request_digest("approval.request", ids={"project_id": project.id}, body=body.model_dump(mode="json")),
        )
        if (hit := op.replay()) is not None:
            return _replayed(hit)
        a = approvals_svc.create_request(ws, ctx.clock, ctx.settings, principal, project, body)
        out = op.finish(201, approvals_svc.approval_to_dict(a))
    return Outcome(out.status, out.body)


# ------------------------------------------------------------------ reads


def list_projects(ctx: Ctx, principal: PrincipalContext, limit: int | None, cursor: str | None) -> dict[str, Any]:
    lim = clamp_limit(limit)
    after = decode_cursor(cursor, 1)
    offset = after[0] if after else 0
    if not isinstance(offset, int) or offset < 0:
        raise RelayError(422, "invalid_cursor", "Malformed cursor")
    with ctx.read() as db:
        rows = [projects_svc.project_to_dict(p) for p in projects_svc.list_projects(db, principal)]
    page = rows[offset : offset + lim]
    more = offset + lim < len(rows)
    return {"items": page, "next_cursor": encode_cursor([offset + lim]) if more else None}


def get_task(ctx: Ctx, principal: PrincipalContext, project_id: str, task_id: str) -> dict[str, Any]:
    with ctx.read() as db:
        project = acl.get_project(db, principal, project_id)
        task = acl.get_task(db, project, task_id)
        return tasks_svc.task_detail(db, task)


def list_tasks(
    ctx: Ctx, principal: PrincipalContext, project_id: str, status: str | None, limit: int | None, cursor: str | None
) -> dict[str, Any]:
    with ctx.read() as db:
        project = acl.get_project(db, principal, project_id)
        return tasks_svc.list_tasks(db, project, status=status, limit=limit, cursor=cursor)


def get_report(ctx: Ctx, principal: PrincipalContext, project_id: str, report_id: str) -> dict[str, Any]:
    with ctx.read() as db:
        project = acl.get_project(db, principal, project_id)
        report = db.get(Report, report_id)
        task = db.get(Task, report.task_id) if report else None
        if report is None or task is None or task.project_id != project.id:
            raise RelayError(404, "not_found", acl.NOT_FOUND)
        return report_to_dict(db, report)


def get_events(
    ctx: Ctx, principal: PrincipalContext, project_id: str, after_seq: int, limit: int | None
) -> dict[str, Any]:
    with ctx.read() as db:
        project = acl.get_project(db, principal, project_id)
        lim = clamp_limit(limit)
        watermark = ev.high_watermark(db, project.id)
        rows, next_seq = ev.list_events(db, project.id, after_seq=after_seq, limit=lim)
        return {
            "events": [ev.event_to_dict(e) for e in rows],
            "next_cursor": str(next_seq) if next_seq is not None else None,
            "high_watermark": watermark,
        }
