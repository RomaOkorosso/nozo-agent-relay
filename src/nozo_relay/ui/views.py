"""Read-side view models for the owner panel. Pure data (dicts); templates only format.

Everything user-supplied (titles, message bodies, summaries) is passed through as plain text and is
escaped by Jinja autoescaping — there is no HTML/Markdown rendering path.
"""

from __future__ import annotations

import json
from typing import Any

from sqlalchemy import func, literal_column, select
from sqlalchemy.orm import Session

from nozo_relay.api.errors import RelayError
from nozo_relay.clock import Clock
from nozo_relay.config import Settings
from nozo_relay.db.models import (
    Control,
    Event,
    Job,
    Membership,
    Message,
    Principal,
    Project,
    Report,
    Run,
    Snapshot,
    Task,
)
from nozo_relay.domain.enums import ACTIVE_RUN_STATUSES, TaskStatus
from nozo_relay.services import events as ev
from nozo_relay.services.controls import control_to_dict
from nozo_relay.services.pagination import decode_cursor, encode_cursor
from nozo_relay.services.reports import report_to_dict
from nozo_relay.services.tasks import revision_to_dict
from nozo_relay.services.common import get_revision
from nozo_relay.ui import labels as L

CHAT_PAGE = 30
TASK_LIMIT = 100
TIMELINE_LIMIT = 150
SNIPPET = 90

ACTIVE_COUNT = (TaskStatus.CLAIMED, TaskStatus.RUNNING, TaskStatus.REVIEWING, TaskStatus.STOP_REQUESTED)


def principals(db: Session, project_id: str) -> dict[str, dict[str, str]]:
    rows = db.execute(
        select(Principal.id, Principal.display_name, Principal.kind, Principal.active)
        .join(Membership, Membership.principal_id == Principal.id)
        .where(Membership.project_id == project_id)
    ).all()
    return {
        pid: {"id": pid, "name": name, "kind": kind, "kind_ru": L.label(L.KIND_RU, kind), "active": active}
        for pid, name, kind, active in rows
    }


def _who(people: dict[str, dict[str, str]], db: Session, pid: str | None) -> dict[str, str]:
    if pid is None:
        return {"id": "", "name": "система", "kind": "system", "kind_ru": "Система"}
    if pid in people:
        return people[pid]
    p = db.get(Principal, pid)  # no longer a member (kept for history)
    if p is None:
        return {"id": pid, "name": "неизвестно", "kind": "unknown", "kind_ru": "—"}
    return {"id": pid, "name": p.display_name, "kind": p.kind, "kind_ru": L.label(L.KIND_RU, p.kind)}


def snippet(text: str, n: int = SNIPPET) -> str:
    flat = " ".join(text.split())
    return flat if len(flat) <= n else flat[: n - 1] + "…"


def _run_dict(run: Run) -> dict[str, Any]:
    return {
        "id": run.id, "status": run.status, "lease_epoch": run.lease_epoch,
        "lease_expires_at": run.lease_expires_at, "started_at": run.started_at,
        "heartbeat_at": run.heartbeat_at,
    }


def active_runs_by_task(db: Session, project_id: str) -> dict[str, dict[str, Any]]:
    rows = db.execute(
        select(Run, Job.task_id)
        .join(Job, Job.id == Run.job_id)
        .where(Job.project_id == project_id, Run.status.in_([s.value for s in ACTIVE_RUN_STATUSES]))
        .order_by(Run.lease_epoch)
    ).all()
    return {task_id: _run_dict(run) for run, task_id in rows}


def high_watermark(db: Session, project_id: str) -> int:
    return ev.high_watermark(db, project_id)


# ---------------------------------------------------------------- project / task list


def counters(db: Session, project_id: str) -> dict[str, int]:
    rows = dict(
        db.execute(
            select(Task.status, func.count()).where(Task.project_id == project_id).group_by(Task.status)
        ).all()
    )
    get = lambda *names: sum(rows.get(n.value, 0) for n in names)  # noqa: E731
    return {
        "queued": get(TaskStatus.QUEUED),
        "active": get(*ACTIVE_COUNT),
        "review": get(TaskStatus.AWAITING_REVIEW),
        "attention": get(TaskStatus.BLOCKED, TaskStatus.CHANGES_REQUESTED, TaskStatus.PAUSED),
        "done": get(TaskStatus.COMPLETED, TaskStatus.CANCELLED),
        "total": sum(rows.values()),
    }


def pending_controls(db: Session, project_id: str) -> list[dict[str, Any]]:
    """Open or unresolved controls, with the honest display state."""
    rows = db.execute(
        select(Control)
        .where(Control.project_id == project_id, Control.status.in_(["requested", "stopping", "unknown"]))
        .order_by(Control.requested_at.desc())
        .limit(20)
    ).scalars().all()
    titles = dict(
        db.execute(select(Task.id, Task.title).where(Task.project_id == project_id)).all()
    )
    out = []
    for c in rows:
        d = control_to_dict(c)
        d["view"] = L.control_view(d)
        d["task_title"] = titles.get(c.task_id) if c.task_id else None
        d["requested_at_ms"] = c.requested_at
        out.append(d)
    return out


def task_cards(db: Session, settings: Settings, clock: Clock, project: Project) -> list[dict[str, Any]]:
    people = principals(db, project.id)
    runs = active_runs_by_task(db, project.id)
    tasks = db.execute(
        select(Task)
        .where(Task.project_id == project.id)
        .order_by(Task.updated_at.desc(), Task.id)
        .limit(TASK_LIMIT)
    ).scalars().all()
    now = clock.now_ms()
    cards = []
    for t in tasks:
        activity = L.activity_view(runs.get(t.id), now, settings.heartbeat_interval_seconds)
        cards.append(task_card(t, people, activity))
    return cards


def task_card(t: Task, people: dict[str, dict[str, str]], activity: dict[str, Any]) -> dict[str, Any]:
    impl = people.get(t.implementer_id or "", {}).get("name", "—")
    aud = people.get(t.auditor_id or "", {}).get("name", "—")
    return {
        "id": t.id, "title": t.title, "status": t.status, "version": t.version,
        "status_ru": L.label(L.TASK_STATUS_RU, t.status), "tone": L.TASK_TONE.get(t.status, "muted"),
        "urgency": t.urgency, "urgency_ru": L.label(L.URGENCY_RU, t.urgency), "tier": t.effective_tier,
        "implementer": impl, "auditor": aud, "revision": t.current_revision,
        "failed_reviews": f"{t.failed_review_count}/{t.max_failed_reviews}",
        "failed_review_count": t.failed_review_count,
        "blocked_reason": t.blocked_reason,
        "blocked_ru": L.label(L.BLOCKED_RU, t.blocked_reason) if t.blocked_reason else None,
        "updated_at": t.updated_at, "activity": activity,
    }


def project_page(db: Session, settings: Settings, clock: Clock, project: Project) -> dict[str, Any]:
    hw = high_watermark(db, project.id)  # BEFORE the state reads: replay(hw) can only re-send, never skip
    return {
        "project": project,
        "hw": hw,
        "counters": counters(db, project.id),
        "controls": pending_controls(db, project.id),
        "tasks": task_cards(db, settings, clock, project),
        "people": principals(db, project.id),
    }


# ---------------------------------------------------------------- chat


def chat_page(
    db: Session,
    project: Project,
    *,
    task_id: str | None = None,
    author_id: str | None = None,
    before: str | None = None,
    limit: int = CHAT_PAGE,
) -> dict[str, Any]:
    """Newest ``limit`` messages (older than ``before``), returned oldest-first for display."""
    limit = max(1, min(limit, 100))
    people = principals(db, project.id)
    q = select(Message).where(Message.project_id == project.id)
    if task_id:
        q = q.where(Message.task_id == task_id)
    if author_id:
        q = q.where(Message.sender_id == author_id)
    cur = decode_cursor(before, 2)
    if cur:
        q = q.where((Message.created_at < cur[0]) | ((Message.created_at == cur[0]) & (Message.id < cur[1])))
    rows = db.execute(q.order_by(Message.created_at.desc(), Message.id.desc()).limit(limit + 1)).scalars().all()
    has_more = len(rows) > limit
    rows = list(reversed(rows[:limit]))
    titles = dict(db.execute(select(Task.id, Task.title).where(Task.project_id == project.id)).all())
    parents = {}
    parent_ids = {m.reply_to for m in rows if m.reply_to}
    if parent_ids:
        for pm in db.execute(select(Message).where(Message.id.in_(parent_ids))).scalars():
            parents[pm.id] = pm
    items = []
    for m in rows:
        who = _who(people, db, m.sender_id)
        parent = parents.get(m.reply_to) if m.reply_to else None
        items.append({
            "id": m.id, "key": f"{m.created_at:015d}|{m.id}", "author": who,
            "kind": m.kind, "kind_ru": L.label(L.MESSAGE_KIND_RU, m.kind),
            "body": m.body, "created_at": m.created_at,
            "task_id": m.task_id, "task_title": titles.get(m.task_id) if m.task_id else None,
            "reply_to": (
                {"id": parent.id, "author": _who(people, db, parent.sender_id)["name"], "snippet": snippet(parent.body)}
                if parent else ({"id": m.reply_to, "author": "?", "snippet": ""} if m.reply_to else None)
            ),
        })
    older = encode_cursor([rows[0].created_at, rows[0].id]) if has_more and rows else None
    return {"messages": items, "older_cursor": older, "has_more": has_more, "people": people}


# ---------------------------------------------------------------- task detail


def _event_detail(db: Session, people: dict, e: Event, payload: dict[str, Any]) -> dict[str, Any]:
    out: dict[str, Any] = {"text": "", "report_id": None}
    t = e.type
    if t == "task.status_changed":
        frm = L.label(L.TASK_STATUS_RU, payload.get("from"), "")
        to = L.label(L.TASK_STATUS_RU, payload.get("status"), "")
        out["text"] = f"{frm} → {to}" if frm else to
        if payload.get("blocked_reason"):
            out["text"] += f" ({L.label(L.BLOCKED_RU, payload['blocked_reason'])})"
        out["report_id"] = payload.get("report_id")
    elif t == "message.created":
        m = db.get(Message, payload.get("message_id")) if payload.get("message_id") else None
        if m is not None:
            out["text"] = f"{_who(people, db, m.sender_id)['name']}: {snippet(m.body)}"
    elif t == "report.created":
        out["report_id"] = payload.get("report_id")
        verdict = payload.get("verdict")
        out["text"] = L.label(L.REPORT_KIND_RU, payload.get("kind"), "")
        if verdict:
            out["text"] += f" — {L.label(L.VERDICT_RU, verdict)}"
    elif t.startswith("control."):
        out["text"] = L.label(L.CONTROL_CMD_RU, payload.get("command"), "")
    return out


def timeline(db: Session, project: Project, task: Task, people: dict) -> list[dict[str, Any]]:
    rows = db.execute(
        select(Event)
        .where(Event.project_id == project.id, Event.task_id == task.id)
        .order_by(Event.seq.desc())
        .limit(TIMELINE_LIMIT)
    ).scalars().all()
    out = []
    for e in rows:  # newest first
        payload = json.loads(e.payload_json)
        d = _event_detail(db, people, e, payload)
        out.append({
            "seq": e.seq, "type": e.type, "label": L.label(L.EVENT_RU, e.type),
            "at": e.created_at, "actor": _who(people, db, e.actor_id)["name"] if e.actor_id else "система",
            "text": d["text"], "report_id": d["report_id"],
        })
    return out


def reports_of(db: Session, task: Task) -> list[dict[str, Any]]:
    rows = db.execute(
        select(Report).where(Report.task_id == task.id).order_by(literal_column("reports.rowid").desc())
    ).scalars().all()
    out = []
    for r in rows:
        d = report_to_dict(db, r)
        d["kind_ru"] = L.label(L.REPORT_KIND_RU, d["kind"])
        d["verdict_ru"] = L.label(L.VERDICT_RU, d["verdict"], "—") if d["verdict"] else None
        d["verdict_tone"] = L.VERDICT_TONE.get(d["verdict"] or "", "muted")
        d["check_groups"] = L.group_checks(d["checks"])
        d["created_ms"] = r.created_at
        out.append(d)
    return out


def task_controls(db: Session, task: Task) -> list[dict[str, Any]]:
    rows = db.execute(
        select(Control).where(Control.task_id == task.id).order_by(Control.requested_at.desc()).limit(8)
    ).scalars().all()
    out = []
    for c in rows:
        d = control_to_dict(c)
        d["view"] = L.control_view(d)
        d["requested_at_ms"] = c.requested_at
        out.append(d)
    return out


def task_page(db: Session, settings: Settings, clock: Clock, project: Project, task: Task) -> dict[str, Any]:
    hw = high_watermark(db, project.id)
    people = principals(db, project.id)
    run = active_runs_by_task(db, project.id).get(task.id)
    rev = revision_to_dict(get_revision(db, task))
    snap = None
    snap_row = None
    from nozo_relay.services.tasks import task_to_dict

    sid = task_to_dict(db, task)["current_snapshot_id"]
    if sid:
        snap_row = db.get(Snapshot, sid)
    if snap_row is not None:
        snap = {
            "id": snap_row.id, "head": snap_row.head_commit[:12], "tree": snap_row.tree_hash[:12],
            "diff": snap_row.diff_hash[:12], "verified_at": snap_row.verified_at,
        }
    activity = L.activity_view(run, clock.now_ms(), settings.heartbeat_interval_seconds)
    card = task_card(task, people, activity)
    return {
        "project": project, "task": task, "card": card, "hw": hw, "people": people,
        "revision": rev, "snapshot": snap, "timeline": timeline(db, project, task, people),
        "reports": reports_of(db, task), "controls": task_controls(db, task),
        "created_at": task.created_at, "mode_ru": L.label(L.MODE_RU, rev["mode"]),
        "agents": agent_choices(people),
    }


def agent_choices(people: dict[str, dict[str, str]]) -> dict[str, list[dict[str, str]]]:
    return {
        "implementers": [p for p in people.values() if p["kind"] == "implementer" and p["active"]],
        "auditors": [p for p in people.values() if p["kind"] == "auditor" and p["active"]],
    }


def require_task(db: Session, project: Project, task_id: str) -> Task:
    task = db.get(Task, task_id)
    if task is None or task.project_id != project.id:
        raise RelayError(404, "not_found", "Resource not found")
    return task


def allowed_actions(status: str) -> dict[str, bool]:
    """Which control buttons to offer. Presentation only: the API re-validates every command."""
    s = status
    terminal = s in ("completed", "cancelled")
    idle_completable = s in ("draft", "queued", "changes_requested", "awaiting_review", "paused", "blocked")
    return {
        "enqueue": s == "draft",
        "pause": s in ("queued", "claimed", "running", "awaiting_review", "reviewing", "changes_requested"),
        "resume": s in ("paused", "blocked"),
        "complete": idle_completable,
        "cancel": not terminal,
        "reassign": not terminal and s != "stop_requested",
        "stopping": s == "stop_requested",
    }
