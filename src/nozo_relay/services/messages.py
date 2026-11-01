"""Messages: typed notes only. A message can never change a task's status or enqueue work."""

from __future__ import annotations

from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from nozo_relay.api.errors import RelayError
from nozo_relay.api.schemas import MessageCreate
from nozo_relay.auth.context import PrincipalContext
from nozo_relay.clock import Clock, ms_to_rfc3339
from nozo_relay.db.models import Message, Project, Task
from nozo_relay.services import acl
from nozo_relay.services.events import append_event
from nozo_relay.services.pagination import clamp_limit, decode_cursor, encode_cursor


def message_to_dict(m: Message) -> dict[str, Any]:
    return {
        "id": m.id,
        "project_id": m.project_id,
        "task_id": m.task_id,
        "sender_id": m.sender_id,
        "client_message_id": m.client_message_id,
        "kind": m.kind,
        "body": m.body,  # plain text: clients must render it as text, never as HTML
        "reply_to": m.reply_to,
        "created_at": ms_to_rfc3339(m.created_at),
    }


def _same_content(m: Message, dto: MessageCreate) -> bool:
    return (
        m.project_id is not None
        and m.kind == dto.kind.value
        and m.body == dto.body
        and m.task_id == dto.task_id
        and m.reply_to == dto.reply_to
    )


def create_message(
    ws: Session, clock: Clock, principal: PrincipalContext, project: Project, dto: MessageCreate
) -> tuple[Message, bool]:
    """Returns (message, created). UNIQUE(sender_id, client_message_id) makes retries safe."""
    acl.project_role(principal, project)  # any member may post a typed note
    existing = ws.execute(
        select(Message).where(
            Message.sender_id == principal.id, Message.client_message_id == dto.client_message_id
        )
    ).scalar_one_or_none()
    if existing is not None:
        if existing.project_id == project.id and _same_content(existing, dto):
            return existing, False
        raise RelayError(
            409, "client_message_conflict", "client_message_id was already used with different content"
        )

    task: Task | None = None
    if dto.task_id is not None:
        task = ws.get(Task, dto.task_id)
        if task is None or task.project_id != project.id:
            raise acl.not_found()
    if dto.reply_to is not None:
        parent = ws.get(Message, dto.reply_to)
        # Same error for "missing" and "other project": no existence oracle across projects.
        if parent is None or parent.project_id != project.id:
            raise RelayError(422, "invalid_reply_to", "reply_to must reference a message in this project")

    msg = Message(
        project_id=project.id,
        task_id=dto.task_id,
        sender_id=principal.id,
        client_message_id=dto.client_message_id,
        kind=dto.kind.value,
        body=dto.body,
        reply_to=dto.reply_to,
        created_at=clock.now_ms(),
    )
    ws.add(msg)
    ws.flush()
    append_event(
        ws,
        clock,
        type="message.created",
        project_id=project.id,
        task_id=dto.task_id,
        actor_id=principal.id,
        payload={"message_id": msg.id, "kind": msg.kind, "reply_to": msg.reply_to},
    )
    return msg, True


def list_messages(
    ws: Session, project: Project, *, task_id: str | None, limit: int | None, cursor: str | None
) -> dict[str, Any]:
    lim = clamp_limit(limit)
    q = select(Message).where(Message.project_id == project.id)
    if task_id is not None:
        q = q.where(Message.task_id == task_id)
    after = decode_cursor(cursor, 2)
    if after:
        q = q.where(
            (Message.created_at > after[0]) | ((Message.created_at == after[0]) & (Message.id > after[1]))
        )
    rows = ws.execute(q.order_by(Message.created_at, Message.id).limit(lim + 1)).scalars().all()
    more = len(rows) > lim
    rows = rows[:lim]
    return {
        "items": [message_to_dict(m) for m in rows],
        "next_cursor": encode_cursor([rows[-1].created_at, rows[-1].id]) if more and rows else None,
    }
