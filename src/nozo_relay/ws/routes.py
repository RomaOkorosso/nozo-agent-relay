"""``WS /ws/v1/projects/{project_id}?after_seq=N`` — authenticated BEFORE ``accept``.

Credentials: HttpOnly session cookie (browser; ``Origin`` is mandatory and must be allow-listed) or
``Authorization: Bearer`` (CLI). Nothing is ever read from the query string; unknown query parameters
are refused so that nobody builds URLs with secrets in them.
"""

from __future__ import annotations

import asyncio
import logging

from fastapi import APIRouter, WebSocket
from sqlalchemy.orm import Session

from nozo_relay.auth.credentials import authenticate_key, load_project_roles
from nozo_relay.auth.sessions import get_session
from nozo_relay.domain.enums import PrincipalKind
from nozo_relay.db.models import Credential, Membership, Principal, SessionRow
from nozo_relay.ws.hub import (
    CLOSE_POLICY,
    CLOSE_TRY_LATER,
    Connection,
    Hub,
    Identity,
)

log = logging.getLogger("nozo_relay.ws")
router = APIRouter()

ALLOWED_QUERY = frozenset({"after_seq"})


class _WsTransport:
    def __init__(self, ws: WebSocket) -> None:
        self._ws = ws

    async def send_text(self, text: str) -> None:
        await self._ws.send_text(text)

    async def receive_text(self) -> str:
        return await self._ws.receive_text()

    async def close(self, code: int, reason: str) -> None:
        await self._ws.close(code=code, reason=reason[:100])


def _authenticate(ws: WebSocket, project_id: str) -> tuple[Identity | None, str]:
    """Sync (runs in a worker thread). Returns (identity, reason-if-rejected)."""
    app = ws.app
    settings, clock = app.state.settings, app.state.clock
    origin = ws.headers.get("origin")
    if origin is not None and not settings.origin_permitted(origin):
        return None, "origin_not_allowed"

    authz = ws.headers.get("authorization")
    cookie = ws.cookies.get(settings.session_cookie_name)
    with app.state.session_factory() as db:
        try:
            if authz is not None:
                scheme, _, token = authz.partition(" ")
                if scheme.lower() != "bearer" or not token.strip():
                    return None, "invalid_authorization"
                ctx = authenticate_key(db, clock, token)
                if ctx is None or not ctx.is_member(project_id):
                    return None, "unauthenticated"
                if ctx.kind is PrincipalKind.RUNNER:  # T12/F03: project chat/events are not supervisor data
                    return None, "forbidden"
                return Identity(ctx.id, project_id, credential_id=ctx.credential_id), ""
            if not cookie:
                return None, "unauthenticated"
            if origin is None:  # a cookie-authenticated socket must come from a page we served
                return None, "origin_required"
            row = get_session(db, clock, settings, cookie, touch=False)
            if row is None:
                return None, "unauthenticated"
            principal = db.get(Principal, row.owner_id)
            if principal is None or not principal.active:
                return None, "unauthenticated"
            if project_id not in load_project_roles(db, principal.id):
                return None, "unauthenticated"  # same answer as "no such project"
            return Identity(principal.id, project_id, session_digest=row.id_digest), ""
        finally:
            db.rollback()


def revalidate_identity(app, identity: Identity) -> str | None:  # noqa: ANN001
    """None while still authorised, otherwise a short machine reason (sync, worker thread)."""
    settings, clock = app.state.settings, app.state.clock
    now = clock.now_ms()
    with app.state.session_factory() as db:  # type: Session
        try:
            if identity.session_digest is not None:
                row = db.get(SessionRow, identity.session_digest)
                if row is None or row.revoked_at is not None:
                    return "session_revoked"
                if now >= row.absolute_expires_at or now >= row.idle_expires_at:
                    return "session_expired"
            if identity.credential_id is not None:
                cred = db.get(Credential, identity.credential_id)
                if cred is None or cred.revoked_at is not None:
                    return "credential_revoked"
                if cred.expires_at is not None and cred.expires_at <= now:
                    return "credential_expired"
            principal = db.get(Principal, identity.principal_id)
            if principal is None or not principal.active:
                return "principal_inactive"
            if db.get(Membership, (identity.principal_id, identity.project_id)) is None:
                return "membership_lost"
            return None
        finally:
            db.rollback()


@router.websocket("/ws/v1/projects/{project_id}")
async def project_events(websocket: WebSocket, project_id: str) -> None:
    app = websocket.app
    hub: Hub = app.state.hub

    async def reject(reason: str, code: int = CLOSE_POLICY) -> None:
        # Not accepted yet => the client sees an HTTP 403 handshake failure and no frames.
        await websocket.close(code=code, reason=reason)

    # Defense in depth: public Funnel must not accept WS even if middleware is bypassed.
    from nozo_relay.api.external_surface import is_external_public_request

    if is_external_public_request(websocket, app.state.settings):
        await reject("not_found")
        return

    params = websocket.query_params
    if any(k not in ALLOWED_QUERY for k in params.keys()):
        await reject("unsupported_query_parameter")
        return
    raw = params.get("after_seq", "0")
    if not raw.isdigit() or len(raw) > 18:
        await reject("invalid_after_seq")
        return
    after_seq = int(raw)

    identity, why = await asyncio.to_thread(_authenticate, websocket, project_id)
    if identity is None:
        await reject(why)
        return
    if hub.count_for_principal(identity.principal_id) >= app.state.settings.ws_max_connections_per_principal:
        await reject("too_many_connections", CLOSE_TRY_LATER)
        return

    await websocket.accept()

    async def revalidate() -> str | None:
        return await asyncio.to_thread(revalidate_identity, app, identity)

    conn = Connection(hub, identity, after_seq, _WsTransport(websocket), revalidate)
    hub.register(conn)
    try:
        await conn.run()
    finally:
        hub.unregister(conn)
