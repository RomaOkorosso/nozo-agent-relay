"""ASGI gateway in front of the MCP SDK app: Origin check -> Bearer auth -> principal context.

Order matters: an invalid Origin is refused BEFORE any credential is looked at (DNS-rebinding /
browser-driven requests never reach token verification). Credentials come only from the
``Authorization: Bearer`` header (never query string, never a cookie). Owners are refused: the MCP
facade is for agents/coordinators and never carries owner authority.

Errors use the relay's uniform shape ``{error:{code,message,request_id,retryable,details}}`` and a
``WWW-Authenticate`` challenge (with ``resource_metadata`` when OAuth discovery is enabled).
"""

from __future__ import annotations

import asyncio
import uuid
from collections.abc import Awaitable, Callable
from contextvars import ContextVar
from dataclasses import dataclass

from sqlalchemy.exc import OperationalError
from starlette.datastructures import Headers
from starlette.responses import JSONResponse
from starlette.types import ASGIApp, Receive, Scope, Send

from nozo_relay.auth.context import PrincipalContext
from nozo_relay.auth.credentials import authenticate_key
from nozo_relay.auth.keys import KEY_SCHEME
from nozo_relay.config import Settings
from nozo_relay.db.engine import write_session
from nozo_relay.db.models import Credential
from nozo_relay.domain.enums import PrincipalKind
from nozo_relay.usecases import Ctx

from .oauth import BASE_SCOPES, RelayOAuthProvider, principal_context_for


@dataclass(frozen=True, slots=True)
class McpAuth:
    """Who is calling and what the credential allows. Authority itself always comes from ACL."""

    principal: PrincipalContext
    scopes: frozenset[str]
    method: str  # "key" | "oauth" | "stdio"


current_auth: ContextVar[McpAuth | None] = ContextVar("nozo_mcp_auth", default=None)


def _touch(ctx: Ctx, credential_id: str, now: int) -> None:
    try:
        with write_session(ctx.engine) as ws:
            cred = ws.get(Credential, credential_id)
            if cred is not None and (cred.last_used_at is None or cred.last_used_at < now):
                cred.last_used_at = now
    except OperationalError:
        pass  # informational only


def authenticate_agent_key(ctx: Ctx, raw_key: str) -> McpAuth | None:
    with ctx.read() as db:
        principal = authenticate_key(db, ctx.clock, raw_key)
        touch = db.info.pop("touch_credential", None)
    if principal is None:
        return None
    if touch is not None:
        _touch(ctx, touch[0], touch[1])
    return McpAuth(principal, frozenset(BASE_SCOPES), "key")


async def authenticate_bearer(
    ctx: Ctx, oauth: RelayOAuthProvider | None, token: str
) -> McpAuth | None:
    """Agent key (``nzr_...``) or, when enabled, an OAuth access token bound to this resource."""
    if token.startswith(f"{KEY_SCHEME}_"):
        return await asyncio.to_thread(authenticate_agent_key, ctx, token)
    if oauth is None:
        return None
    at = await oauth.load_access_token(token)
    if at is None or at.subject is None:
        return None
    if (at.resource or "").rstrip("/") != ctx.settings.mcp_resource:
        return None  # wrong audience
    principal = await asyncio.to_thread(principal_context_for, ctx, at.subject)
    if principal is None:
        return None
    return McpAuth(principal, frozenset(at.scopes), "oauth")


class McpGateway:
    def __init__(
        self,
        inner: ASGIApp | None,
        ctx_factory: Callable[[], Ctx],
        oauth: RelayOAuthProvider | None,
        *,
        resource_metadata_url: str | None = None,
    ) -> None:
        self.inner = inner
        self.ctx_factory = ctx_factory
        self.oauth = oauth
        self.resource_metadata_url = resource_metadata_url

    @staticmethod
    def _error(
        status: int, code: str, message: str, *, challenge: str | None = None, retryable: bool = False
    ) -> JSONResponse:
        rid = str(uuid.uuid4())
        headers = {"X-Request-Id": rid}
        if challenge:
            headers["WWW-Authenticate"] = challenge
        return JSONResponse(
            {"error": {"code": code, "message": message, "request_id": rid, "retryable": retryable, "details": None}},
            status_code=status,
            headers=headers,
        )

    def _challenge(self, error: str | None = None) -> str:
        parts = ['realm="nozo-relay-mcp"']
        if error:
            parts.append(f'error="{error}"')
        if self.resource_metadata_url:
            parts.append(f'resource_metadata="{self.resource_metadata_url}"')
        return "Bearer " + ", ".join(parts)

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            return
        ctx = self.ctx_factory()
        settings: Settings = ctx.settings
        headers = Headers(scope=scope)

        origin = headers.get("origin")
        if origin is not None and origin.rstrip("/") not in settings.origin_allowlist:
            await self._error(403, "origin_not_allowed", "Origin is not allowed")(scope, receive, send)
            return

        if scope["method"] != "POST":
            # Stateless JSON transport: no standalone SSE stream (GET) and no session to DELETE.
            resp = self._error(405, "method_not_allowed", "Only POST is supported on this MCP endpoint")
            resp.headers["Allow"] = "POST"
            await resp(scope, receive, send)
            return

        authz = headers.get("authorization")
        if authz is None:
            await self._error(401, "unauthenticated", "Authentication required", challenge=self._challenge())(
                scope, receive, send
            )
            return
        scheme, _, token = authz.partition(" ")
        if scheme.lower() != "bearer" or not token.strip():
            await self._error(
                401, "unauthenticated", "Invalid Authorization header", challenge=self._challenge("invalid_request")
            )(scope, receive, send)
            return
        try:
            auth = await authenticate_bearer(ctx, self.oauth, token.strip())
        except OperationalError:
            await self._error(503, "database_busy", "Database is busy; retry shortly", retryable=True)(
                scope, receive, send
            )
            return
        if auth is None:
            await self._error(
                401, "unauthenticated", "Invalid, expired or revoked credential",
                challenge=self._challenge("invalid_token"),
            )(scope, receive, send)
            return
        if auth.principal.kind is PrincipalKind.OWNER:
            await self._error(403, "owner_not_allowed", "The MCP facade does not accept owner credentials")(
                scope, receive, send
            )
            return
        if auth.principal.kind is PrincipalKind.RUNNER:  # T12/F03: supervisors get lifecycle receipts only, never chat/tools
            await self._error(403, "runner_not_allowed", "The MCP facade does not accept supervisor (runner) credentials")(
                scope, receive, send
            )
            return

        inner = self.inner
        if inner is None:  # app lifespan not running (e.g. TestClient used without a context manager)
            await self._error(503, "unavailable", "MCP transport is not started", retryable=True)(scope, receive, send)
            return
        marker = current_auth.set(auth)
        try:
            await inner(scope, receive, send)
        finally:
            current_auth.reset(marker)


PrincipalSource = Callable[[], Awaitable[McpAuth | None]]


async def http_principal_source() -> McpAuth | None:
    """Principal for the current HTTP request (set by the gateway); None => fail closed."""
    return current_auth.get()
