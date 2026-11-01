"""Append-only durable event log. Events are written in the same transaction as the mutation."""

from __future__ import annotations

import json
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from nozo_relay.clock import Clock, ms_to_rfc3339
from nozo_relay.db.models import Event, new_id

SCHEMA_VERSION = 1


def append_event(
    ws: Session,
    clock: Clock,
    *,
    type: str,  # noqa: A002
    project_id: str | None = None,
    task_id: str | None = None,
    entity_version: int | None = None,
    actor_id: str | None = None,
    correlation_id: str | None = None,
    causation_event_id: str | None = None,
    payload: dict[str, Any] | None = None,
) -> Event:
    """Insert one event and flush so ``seq`` is available. Payloads must never carry secrets."""
    event = Event(
        event_id=new_id(),
        project_id=project_id,
        task_id=task_id,
        entity_version=entity_version,
        type=type,
        actor_id=actor_id,
        correlation_id=correlation_id or task_id or project_id or new_id(),
        causation_event_id=causation_event_id,
        payload_json=json.dumps(payload or {}, sort_keys=True, separators=(",", ":")),
        created_at=clock.now_ms(),
    )
    ws.add(event)
    ws.flush()
    if project_id is not None:
        # Remembered until COMMIT; ``write_session`` then wakes WebSocket subscribers (best effort).
        ws.info.setdefault("event_projects", set()).add(project_id)
    return event


def event_to_dict(event: Event) -> dict[str, Any]:
    """Wire format of 04_API_CONTRACTS (WebSocket frame / REST replay item)."""
    return {
        "schema_version": SCHEMA_VERSION,
        "event_id": event.event_id,
        "seq": event.seq,
        "project_id": event.project_id,
        "task_id": event.task_id,
        "type": event.type,
        "entity_version": event.entity_version,
        "actor_id": event.actor_id,
        "correlation_id": event.correlation_id,
        "occurred_at": ms_to_rfc3339(event.created_at),
        "data": json.loads(event.payload_json),
    }


def high_watermark(ws: Session, project_id: str) -> int:
    return ws.execute(
        select(func.coalesce(func.max(Event.seq), 0)).where(Event.project_id == project_id)
    ).scalar_one()


def list_events(
    ws: Session, project_id: str, *, after_seq: int, limit: int
) -> tuple[list[Event], int | None]:
    """Events with seq > after_seq (ascending). Second item: next cursor if more remain."""
    rows = (
        ws.execute(
            select(Event)
            .where(Event.project_id == project_id, Event.seq > after_seq)
            .order_by(Event.seq)
            .limit(limit + 1)
        )
        .scalars()
        .all()
    )
    more = len(rows) > limit
    rows = rows[:limit]
    return list(rows), (rows[-1].seq if more and rows else None)
