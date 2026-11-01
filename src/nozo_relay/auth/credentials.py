"""Credential lifecycle: issue / authenticate / revoke agent keys."""

from __future__ import annotations

from sqlalchemy import select, update
from sqlalchemy.orm import Session

from nozo_relay.auth.context import PrincipalContext
from nozo_relay.auth.keys import (
    DUMMY_DIGEST,
    GeneratedKey,
    generate_key,
    parse_key,
    verify_secret,
)
from nozo_relay.clock import Clock
from nozo_relay.db.models import Credential, Membership, Principal
from nozo_relay.domain.enums import PrincipalKind

LAST_USED_GRANULARITY_MS = 60_000


def issue_credential(
    db: Session, clock: Clock, principal_id: str, *, expires_at: int | None = None
) -> tuple[GeneratedKey, Credential]:
    key = generate_key()
    cred = Credential(
        principal_id=principal_id,
        key_prefix=key.prefix,
        secret_digest=key.digest,
        created_at=clock.now_ms(),
        expires_at=expires_at,
    )
    db.add(cred)
    db.flush()
    return key, cred


def revoke_credential(db: Session, clock: Clock, credential_id: str) -> bool:
    res = db.execute(
        update(Credential)
        .where(Credential.id == credential_id, Credential.revoked_at.is_(None))
        .values(revoked_at=clock.now_ms())
    )
    return (res.rowcount or 0) > 0


def load_project_roles(db: Session, principal_id: str) -> dict[str, str]:
    rows = db.execute(
        select(Membership.project_id, Membership.role).where(Membership.principal_id == principal_id)
    ).all()
    return {pid: role for pid, role in rows}


def authenticate_key(db: Session, clock: Clock, raw_key: str) -> PrincipalContext | None:
    """Return the principal for a valid, unrevoked, unexpired key; otherwise None."""
    parsed = parse_key(raw_key)
    if parsed is None:
        verify_secret("x", DUMMY_DIGEST)
        return None
    prefix, secret = parsed
    cred = db.execute(select(Credential).where(Credential.key_prefix == prefix)).scalar_one_or_none()
    if cred is None:
        verify_secret(secret, DUMMY_DIGEST)  # uniform timing
        return None
    if not verify_secret(secret, cred.secret_digest):
        return None
    now = clock.now_ms()
    if cred.revoked_at is not None or (cred.expires_at is not None and cred.expires_at <= now):
        return None
    principal = db.get(Principal, cred.principal_id)
    if principal is None or not principal.active:
        return None
    if cred.last_used_at is None or now - cred.last_used_at >= LAST_USED_GRANULARITY_MS:
        # Never upgrade this (deferred, read) transaction to a write: under concurrency SQLite fails
        # the upgrade immediately. The caller records the touch in its own best-effort write.
        db.info["touch_credential"] = (cred.id, now)
    return PrincipalContext(
        id=principal.id,
        kind=PrincipalKind(principal.kind),
        display_name=principal.display_name,
        project_roles=load_project_roles(db, principal.id),
        auth_method="key",
        credential_id=cred.id,
    )
