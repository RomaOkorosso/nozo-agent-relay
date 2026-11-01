"""Optional public HTTPS surface (e.g. Tailscale Funnel): coordinator UI/API only.

Same ``*.ts.net`` Host is used by private Serve and public Funnel. We treat a request as
*public* only when the Host is listed in ``external_public_hosts`` **and** Tailscale did
not attach an identity header (``Tailscale-User-Login``). Serve from a logged-in tailnet
peer keeps the full owner panel; Funnel visitors get the coordinator allowlist.

WebSocket is **not** on the public allowlist (free tunnels drop WS; Funnel stays HTTP-only).
This middleware is pure ASGI so both HTTP and WebSocket are gated **before** accept.
"""

from __future__ import annotations

from collections.abc import MutableMapping
from typing import Any

from starlette.types import ASGIApp, Receive, Scope, Send

from nozo_relay.config import Settings

# Paths a public coordinator browser may touch. Everything else is 404 on Funnel.
# WebSocket paths are intentionally absent — see ASGI websocket branch.
_ALLOW_PREFIXES = (
    "/login",
    "/login/claim/",
    "/static/",
    "/projects",
    "/ui/",
    "/api/v1/auth/login",
    "/api/v1/auth/logout",
    "/api/v1/me",
    "/api/v1/projects/",
    "/api/v1/health/",
    "/healthz",
    "/readyz",
)

_ALLOW_EXACT = frozenset({"/", "/favicon.ico", "/healthz", "/readyz", "/login", "/projects", "/ui/session"})

_DENY_PREFIXES = (
    "/api/v1/agents",
    "/api/v1/controls/emergency-stop",
    "/api/v1/oauth/",
    "/oauth/",
    "/mcp",
    "/authorize",
    "/token",
    "/register",
    "/revoke",
    "/.well-known/",
)

_NOT_FOUND_BODY = (
    b'{"error":{"code":"not_found","message":"Not Found","request_id":null,'
    b'"retryable":false,"details":null}}'
)


def host_without_port(host: str) -> str:
    h = host.strip().lower()
    if h.startswith("["):
        end = h.find("]")
        return h[1:end] if end > 0 else h
    return h.rsplit(":", 1)[0] if h.count(":") == 1 else h


def header_map(scope: Scope) -> dict[str, str]:
    out: dict[str, str] = {}
    for key, value in scope.get("headers") or []:
        out[key.decode("latin-1").lower()] = value.decode("latin-1")
    return out


def is_listed_public_host(host_header: str | None, settings: Settings) -> bool:
    if not host_header:
        return False
    if not settings.external_public_hosts and not settings.external_public_host_suffixes:
        return False
    return settings.host_is_external_public(host_without_port(host_header))


def is_tailnet_identity_headers(headers: MutableMapping[str, str]) -> bool:
    """True when Tailscale Serve attached a peer identity (not a naked Funnel visitor)."""
    return bool(headers.get("tailscale-user-login") or headers.get("tailscale-user-name"))


def is_external_public_headers(headers: MutableMapping[str, str], settings: Settings) -> bool:
    if not is_listed_public_host(headers.get("host"), settings):
        return False
    if is_tailnet_identity_headers(headers):
        return False
    return True


def is_tailnet_identity(request: Any) -> bool:
    return bool(request.headers.get("tailscale-user-login") or request.headers.get("tailscale-user-name"))


def is_external_public_request(request: Any, settings: Settings) -> bool:
    if not is_listed_public_host(request.headers.get("host"), settings):
        return False
    if is_tailnet_identity(request):
        return False
    return True


def path_allowed(path: str) -> bool:
    if path in _ALLOW_EXACT:
        return True
    if any(path.startswith(p) for p in _DENY_PREFIXES):
        return False
    return any(path == p.rstrip("/") or path.startswith(p) for p in _ALLOW_PREFIXES)


class ExternalSurfaceMiddleware:
    """ASGI middleware: HTTP path allowlist + deny all WebSocket on public Funnel."""

    def __init__(self, app: ASGIApp, settings: Settings) -> None:
        self.app = app
        self.settings = settings

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] not in ("http", "websocket"):
            await self.app(scope, receive, send)
            return

        headers = header_map(scope)
        if not is_external_public_headers(headers, self.settings):
            await self.app(scope, receive, send)
            return

        path = scope.get("path") or ""

        if scope["type"] == "websocket":
            # Public Funnel contract: no WS (allowlist intentionally omits /ws/).
            await send(
                {
                    "type": "websocket.http.response.start",
                    "status": 403,
                    "headers": [(b"content-type", b"application/json")],
                }
            )
            await send({"type": "websocket.http.response.body", "body": _NOT_FOUND_BODY})
            return

        if not path_allowed(path):
            await send(
                {
                    "type": "http.response.start",
                    "status": 404,
                    "headers": [
                        (b"content-type", b"application/json"),
                        (b"content-length", str(len(_NOT_FOUND_BODY)).encode("ascii")),
                    ],
                }
            )
            await send({"type": "http.response.body", "body": _NOT_FOUND_BODY})
            return

        state = scope.setdefault("state", {})
        state["external_surface"] = True
        await self.app(scope, receive, send)
