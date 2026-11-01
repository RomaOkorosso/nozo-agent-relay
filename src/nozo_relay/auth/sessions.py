"""Server-side sessions. The cookie carries an opaque random id; only its SHA-256 is stored."""

from __future__ import annotations

import secrets
from dataclasses import dataclass

from sqlalchemy import select, update
from sqlalchemy.orm import Session

from nozo_relay.auth.keys import constant_time_equal, digest_secret
from nozo_relay.clock import Clock
from nozo_relay.config import Settings
from nozo_relay.db.models import SessionRow

TOUCH_GRANULARITY_MS = 30_000  # avoid a DB write on every request


@dataclass(frozen=True)
class IssuedSession:
    session_id: str  # opaque cookie value, shown once
    csrf_token: str
    id_digest: str
    idle_expires_at: int
    absolute_expires_at: int

    def __repr__(self) -> str:
        return "IssuedSession(<redacted>)"


def hash_session_id(session_id: str) -> str:
    return digest_secret(session_id)


def create_session(db: Session, clock: Clock, settings: Settings, owner_id: str) -> IssuedSession:
    now = clock.now_ms()
    session_id = secrets.token_urlsafe(32)
    csrf = secrets.token_urlsafe(32)
    absolute = now + settings.session_absolute_seconds * 1000
    idle = min(now + settings.session_idle_seconds * 1000, absolute)
    db.add(
        SessionRow(
            id_digest=hash_session_id(session_id),
            owner_id=owner_id,
            csrf_digest=digest_secret(csrf),
            created_at=now,
            reauth_at=now,
            idle_expires_at=idle,
            absolute_expires_at=absolute,
        )
    )
    db.flush()
    return IssuedSession(session_id, csrf, hash_session_id(session_id), idle, absolute)


def get_session(
    db: Session, clock: Clock, settings: Settings, session_id: str, *, touch: bool = True
) -> SessionRow | None:
    """Return the live session or None (unknown / revoked / idle- or absolute-expired)."""
    if not session_id or len(session_id) > 256:
        return None
    row = db.get(SessionRow, hash_session_id(session_id))
    if row is None or row.revoked_at is not None:
        return None
    now = clock.now_ms()
    if now >= row.absolute_expires_at or now >= row.idle_expires_at:
        return None
    if touch:
        new_idle = min(now + settings.session_idle_seconds * 1000, row.absolute_expires_at)
        if new_idle - row.idle_expires_at >= TOUCH_GRANULARITY_MS:
            db.execute(
                update(SessionRow)
                .where(SessionRow.id_digest == row.id_digest)
                .values(idle_expires_at=new_idle)
            )
            row.idle_expires_at = new_idle
    return row


def verify_csrf(row: SessionRow, presented: str | None) -> bool:
    if not presented:
        return False
    return constant_time_equal(digest_secret(presented), row.csrf_digest)


def revoke_session(db: Session, clock: Clock, session_id: str) -> bool:
    return revoke_session_digest(db, clock, hash_session_id(session_id))


def revoke_session_digest(db: Session, clock: Clock, id_digest: str) -> bool:
    res = db.execute(
        update(SessionRow)
        .where(SessionRow.id_digest == id_digest, SessionRow.revoked_at.is_(None))
        .values(revoked_at=clock.now_ms())
    )
    return (res.rowcount or 0) > 0


def revoke_all_for_owner(db: Session, clock: Clock, owner_id: str) -> int:
    res = db.execute(
        update(SessionRow)
        .where(SessionRow.owner_id == owner_id, SessionRow.revoked_at.is_(None))
        .values(revoked_at=clock.now_ms())
    )
    return res.rowcount or 0


def live_session_count(db: Session, clock: Clock, owner_id: str) -> int:
    now = clock.now_ms()
    rows = db.execute(
        select(SessionRow.id_digest).where(
            SessionRow.owner_id == owner_id,
            SessionRow.revoked_at.is_(None),
            SessionRow.idle_expires_at > now,
            SessionRow.absolute_expires_at > now,
        )
    ).all()
    return len(rows)


def mark_reauthenticated(db: Session, clock: Clock, id_digest: str) -> int:
    """Record a fresh password proof on this session (enables owner sensitive decisions)."""
    now = clock.now_ms()
    db.execute(update(SessionRow).where(SessionRow.id_digest == id_digest).values(reauth_at=now))
    return now


def is_recent_auth(reauth_at: int | None, clock: Clock, settings: Settings) -> bool:
    if reauth_at is None:
        return False
    age = clock.now_ms() - reauth_at
    return 0 <= age <= settings.recent_auth_seconds * 1000
