"""FastAPI dependencies: DB session, authentication (Bearer key or session cookie), CSRF."""

from __future__ import annotations

from collections.abc import Iterator
from typing import Annotated

from fastapi import Depends, Request
from sqlalchemy.exc import OperationalError
from sqlalchemy.orm import Session

from nozo_relay.auth.context import PrincipalContext
from nozo_relay.auth.credentials import authenticate_key, load_project_roles
from nozo_relay.auth.ratelimit import LoginRateLimiter
from nozo_relay.auth.sessions import get_session, verify_csrf
from nozo_relay.api.errors import RelayError
from nozo_relay.clock import Clock
from nozo_relay.config import Settings
from nozo_relay.db.engine import write_session
from nozo_relay.db.models import Credential, Principal
from nozo_relay.domain.enums import PrincipalKind

SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})


def get_settings(request: Request) -> Settings:
    return request.app.state.settings


def get_clock(request: Request) -> Clock:
    return request.app.state.clock


def get_login_limiter(request: Request) -> LoginRateLimiter:
    return request.app.state.login_limiter


def get_db(request: Request) -> Iterator[Session]:
    session: Session = request.app.state.session_factory()
    try:
        yield session
    finally:
        session.rollback()  # anything not explicitly committed is discarded
        session.close()


SettingsDep = Annotated[Settings, Depends(get_settings)]
ClockDep = Annotated[Clock, Depends(get_clock)]
DbDep = Annotated[Session, Depends(get_db)]
LimiterDep = Annotated[LoginRateLimiter, Depends(get_login_limiter)]


def _unauthenticated(message: str = "Authentication required") -> RelayError:
    return RelayError(
        401, "unauthenticated", message, headers={"WWW-Authenticate": 'Bearer realm="nozo-relay"'}
    )


def _origin_matches_request_host(origin: str, request: Request) -> bool:
    """True when Origin is the same host:port the browser is talking to (same-origin form POST).

    TrustedHost already rejected unknown Hosts; this only repairs allowlist drift for
    loopback/Tailscale HTML form login without opening arbitrary Origins.
    """
    from urllib.parse import urlparse

    from nozo_relay.api.external_surface import host_without_port

    parsed = urlparse(origin)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        return False
    req_host = host_without_port(request.headers.get("host") or "")
    origin_host = parsed.hostname.lower().strip("[]")
    if origin_host != req_host:
        return False
    # Port: Origin may omit default ports; Host header usually includes non-defaults.
    host_hdr = (request.headers.get("host") or "").lower()
    if ":" in host_hdr and not host_hdr.startswith("["):
        req_port = host_hdr.rsplit(":", 1)[-1]
    elif host_hdr.startswith("[") and "]:" in host_hdr:
        req_port = host_hdr.rsplit("]:", 1)[-1]
    else:
        req_port = "443" if (request.headers.get("x-forwarded-proto") or request.url.scheme) == "https" else "80"
    origin_port = str(parsed.port) if parsed.port else ("443" if parsed.scheme == "https" else "80")
    return origin_port == req_port


def check_origin(request: Request, settings: Settings) -> None:
    origin = request.headers.get("origin")
    if origin is None:
        return
    # Opaque Origin:null is NOT trusted by destination Host alone (SA-07).
    # Opt-in local-dev only: allow_opaque_origin + loopback bind.
    if origin.strip().lower() == "null":
        if settings.allow_opaque_origin and settings.host in {"127.0.0.1", "localhost", "::1"}:
            return
        raise RelayError(403, "origin_not_allowed", "Origin is not allowed")
    if settings.origin_permitted(origin):
        return
    if _origin_matches_request_host(origin, request):
        return
    raise RelayError(403, "origin_not_allowed", "Origin is not allowed")


def _touch_credential(request: Request, db: Session) -> None:
    """Best-effort ``last_used_at`` update in its own short write transaction."""
    due = db.info.pop("touch_credential", None)
    if due is None:
        return
    cred_id, now = due
    try:
        with write_session(request.app.state.engine) as ws:
            cred = ws.get(Credential, cred_id)
            if cred is not None and (cred.last_used_at is None or cred.last_used_at < now):
                cred.last_used_at = now
    except OperationalError:
        pass  # purely informational; never fail a request because of it


def authenticate(
    request: Request, db: DbDep, settings: SettingsDep, clock: ClockDep
) -> PrincipalContext:
    """Bearer relay key, else HttpOnly session cookie (+ CSRF/Origin on mutations).

    Credentials are never read from the query string.
    """
    authz = request.headers.get("authorization")
    if authz is not None:
        scheme, _, token = authz.partition(" ")
        if scheme.lower() != "bearer" or not token.strip():
            raise _unauthenticated("Invalid Authorization header")
        ctx = authenticate_key(db, clock, token)
        if ctx is None:
            raise _unauthenticated("Invalid or revoked credential")
        if getattr(request.state, "external_surface", False) and ctx.kind is not PrincipalKind.COORDINATOR:
            raise RelayError(403, "forbidden", "Only coordinator credentials are allowed on the public surface")
        db.commit()
        _touch_credential(request, db)
        return ctx

    cookie = request.cookies.get(settings.session_cookie_name)
    if not cookie:
        raise _unauthenticated()
    row = get_session(db, clock, settings, cookie)
    if row is None:
        raise _unauthenticated("Session expired or revoked")
    principal = db.get(Principal, row.owner_id)
    if principal is None or not principal.active:
        raise _unauthenticated("Session expired or revoked")

    if request.method not in SAFE_METHODS:
        check_origin(request, settings)
        if not verify_csrf(row, request.headers.get(settings.csrf_header_name)):
            raise RelayError(403, "csrf_failed", "Missing or invalid CSRF token")

    ctx = PrincipalContext(
        id=principal.id,
        kind=PrincipalKind(principal.kind),
        display_name=principal.display_name,
        project_roles=load_project_roles(db, principal.id),
        auth_method="session",
        session_id_digest=row.id_digest,
        reauth_at=row.reauth_at if row.reauth_at is not None else row.created_at,
    )
    if getattr(request.state, "external_surface", False) and ctx.kind is not PrincipalKind.COORDINATOR:
        raise RelayError(403, "forbidden", "Only coordinator sessions are allowed on the public surface")
    db.commit()
    return ctx


CurrentPrincipal = Annotated[PrincipalContext, Depends(authenticate)]


def require_owner(principal: CurrentPrincipal) -> PrincipalContext:
    if not principal.is_owner:
        raise RelayError(403, "forbidden", "Owner privileges required")
    return principal


OwnerPrincipal = Annotated[PrincipalContext, Depends(require_owner)]


def require_session(principal: CurrentPrincipal) -> PrincipalContext:
    if principal.auth_method != "session":
        raise RelayError(403, "session_required", "This action requires a browser session")
    return principal


SessionPrincipal = Annotated[PrincipalContext, Depends(require_session)]
