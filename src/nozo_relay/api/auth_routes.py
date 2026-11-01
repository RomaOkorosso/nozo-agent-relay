"""Owner login/logout (cookie session + CSRF) and /me."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from fastapi import APIRouter, Request, Response
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from nozo_relay.api.deps import (
    ClockDep,
    CurrentPrincipal,
    DbDep,
    LimiterDep,
    SessionPrincipal,
    SettingsDep,
    check_origin,
)
from nozo_relay.api.errors import RelayError
from nozo_relay.auth.passwords import hash_password, needs_rehash, verify_password
from nozo_relay.auth.ratelimit import LoginRateLimiter
from nozo_relay.auth.sessions import create_session, mark_reauthenticated, revoke_session_digest
from nozo_relay.clock import Clock, ms_to_rfc3339
from nozo_relay.config import Settings
from nozo_relay.db.models import Membership, Principal, Project
from nozo_relay.domain.enums import AuthorityTier, PrincipalKind

router = APIRouter(prefix="/api/v1", tags=["auth"])

# Static, conservative M0 action hints derived from the 05_SECURITY matrix (not authorization).
_ACTIONS_BY_ROLE: dict[str, list[str]] = {
    "owner": ["project.read", "task.create", "task.control", "key.manage", "emergency_stop"],
    "coordinator": ["project.read", "task.create_delegated", "task.control_delegated"],
    "implementer": ["project.read", "job.claim_implement", "message.post"],
    "auditor": ["project.read", "job.claim_audit", "message.post"],
    "runner": ["run.lifecycle"],
}


class LoginRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    username: str = Field(min_length=1, max_length=64)
    password: str = Field(min_length=1, max_length=1024)


class PrincipalOut(BaseModel):
    id: str
    display_name: str
    kind: str
    authority_tier: str


class LoginResponse(BaseModel):
    principal: PrincipalOut
    csrf_token: str
    csrf_header: str
    idle_expires_at: str
    absolute_expires_at: str


@dataclass(frozen=True)
class IssuedBrowserLogin:
    principal: Principal
    session_id: str
    csrf_token: str
    idle_expires_at: int
    absolute_expires_at: int


def _client_key(request: Request, username: str) -> str:
    ip = request.client.host if request.client else "unknown"
    return f"{ip}|{username.lower()}"


_LOGIN_KINDS = frozenset({PrincipalKind.OWNER.value, PrincipalKind.COORDINATOR.value})


def authenticate_browser_login(
    *,
    request: Request,
    db: Session,
    settings: Settings,
    clock: Clock,
    limiter: LoginRateLimiter,
    username: str,
    password: str,
) -> IssuedBrowserLogin:
    """Validate owner/coordinator password and create a session (shared by JSON + HTML form login)."""
    key = _client_key(request, username)
    wait = limiter.retry_after_seconds(key)
    if wait:
        raise RelayError(
            429,
            "rate_limited",
            "Too many failed logins; try again later",
            retryable=True,
            details={"retry_after_seconds": wait},
            headers={"Retry-After": str(wait)},
        )

    principal = db.execute(
        select(Principal).where(Principal.username == username, Principal.kind.in_(_LOGIN_KINDS))
    ).scalar_one_or_none()
    ok = verify_password(principal.password_hash if principal else None, password)
    if not ok or principal is None or not principal.active:
        limiter.record_failure(key)
        raise RelayError(401, "invalid_credentials", "Invalid username or password")
    limiter.record_success(key)

    # Public Funnel (or other external Host): owner must not obtain a session there.
    if getattr(request.state, "external_surface", False) and principal.kind != PrincipalKind.COORDINATOR.value:
        raise RelayError(403, "forbidden", "Owner login is not available on the public coordinator surface")

    if principal.password_hash and needs_rehash(principal.password_hash):
        principal.password_hash = hash_password(password)

    issued = create_session(db, clock, settings, principal.id)
    db.commit()
    return IssuedBrowserLogin(
        principal=principal,
        session_id=issued.session_id,
        csrf_token=issued.csrf_token,
        idle_expires_at=issued.idle_expires_at,
        absolute_expires_at=issued.absolute_expires_at,
    )


def cookie_secure_for_request(request: Request, settings: Settings) -> bool:
    """Secure cookies on HTTPS/Tailscale Host; plain cookies only on loopback HTTP.

    One Relay process serves both ``http://127.0.0.1:8765`` (owner laptop) and
    ``https://*.ts.net`` (Serve/Funnel). A global Secure flag breaks one of them.
    """
    from nozo_relay.api.external_surface import host_without_port

    proto = (request.headers.get("x-forwarded-proto") or request.url.scheme or "").lower()
    if proto == "https":
        return True
    host = host_without_port(request.headers.get("host") or "")
    if host.endswith(".ts.net") or host in {h.lower() for h in settings.allowed_hosts}:
        return True
    if settings.host_is_external_public(host):
        return True
    # Loopback plain HTTP — only when bound to loopback (enforced by Settings).
    return False if settings.insecure_dev_cookies or host in {"127.0.0.1", "localhost", "::1"} else settings.cookie_secure


def attach_session_cookies(
    response: Response,
    settings: Settings,
    issued: IssuedBrowserLogin,
    *,
    request: Request | None = None,
) -> None:
    secure = cookie_secure_for_request(request, settings) if request is not None else settings.cookie_secure
    cookie_common: dict[str, Any] = {
        "max_age": settings.session_absolute_seconds,
        "path": "/",
        "secure": secure,
        # Lax: top-level navigations (HTML form login → redirect) keep the session on flaky browsers.
        "samesite": "lax",
    }
    response.set_cookie(settings.session_cookie_name, issued.session_id, httponly=True, **cookie_common)
    response.set_cookie(settings.csrf_cookie_name, issued.csrf_token, httponly=False, **cookie_common)
    response.headers["Cache-Control"] = "no-store"


@router.post("/auth/login", response_model=LoginResponse)
def login(
    body: LoginRequest,
    request: Request,
    response: Response,
    db: DbDep,
    settings: SettingsDep,
    clock: ClockDep,
    limiter: LimiterDep,
) -> LoginResponse:
    check_origin(request, settings)
    issued = authenticate_browser_login(
        request=request,
        db=db,
        settings=settings,
        clock=clock,
        limiter=limiter,
        username=body.username,
        password=body.password,
    )
    attach_session_cookies(response, settings, issued, request=request)
    kind = PrincipalKind(issued.principal.kind)
    tier = AuthorityTier.P0 if kind is PrincipalKind.OWNER else AuthorityTier.P1
    return LoginResponse(
        principal=PrincipalOut(
            id=issued.principal.id,
            display_name=issued.principal.display_name,
            kind=issued.principal.kind,
            authority_tier=tier.value,
        ),
        csrf_token=issued.csrf_token,
        csrf_header=settings.csrf_header_name,
        idle_expires_at=ms_to_rfc3339(issued.idle_expires_at),
        absolute_expires_at=ms_to_rfc3339(issued.absolute_expires_at),
    )


@router.post("/auth/logout")
def logout(
    request: Request,
    response: Response,
    principal: SessionPrincipal,
    db: DbDep,
    settings: SettingsDep,
    clock: ClockDep,
) -> dict[str, str]:
    # CSRF + Origin were already enforced by the authenticate dependency (cookie mutation).
    assert principal.session_id_digest is not None
    revoke_session_digest(db, clock, principal.session_id_digest)
    db.commit()
    request.app.state.hub.close_session(principal.session_id_digest)  # drop this session's sockets now
    secure = cookie_secure_for_request(request, settings)
    response.delete_cookie(
        settings.session_cookie_name, path="/", secure=secure, httponly=True, samesite="lax"
    )
    response.delete_cookie(
        settings.csrf_cookie_name, path="/", secure=secure, samesite="lax"
    )
    return {"status": "logged_out"}


class ReauthRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    password: str = Field(min_length=1, max_length=1024)


@router.post("/auth/reauth")
def reauth(
    body: ReauthRequest,
    principal: SessionPrincipal,
    db: DbDep,
    clock: ClockDep,
    limiter: LimiterDep,
) -> dict[str, Any]:
    """Prove the password again on this session (owner sensitive decisions need it within 5 min).

    Session + CSRF + Origin are enforced by the authenticate dependency. Failures share the login
    rate limiter (keyed by principal) so this endpoint is not a password oracle.
    """
    key = f"reauth|{principal.id}"
    wait = limiter.retry_after_seconds(key)
    if wait:
        raise RelayError(
            429, "rate_limited", "Too many failed attempts; try again later", retryable=True,
            details={"retry_after_seconds": wait}, headers={"Retry-After": str(wait)},
        )
    row = db.get(Principal, principal.id)
    if row is None or not row.active or not verify_password(row.password_hash, body.password):
        limiter.record_failure(key)
        raise RelayError(401, "invalid_credentials", "Invalid password")
    limiter.record_success(key)
    assert principal.session_id_digest is not None
    at = mark_reauthenticated(db, clock, principal.session_id_digest)
    db.commit()
    return {"reauthenticated_at": ms_to_rfc3339(at)}


@router.get("/me")
def me(principal: CurrentPrincipal, db: DbDep) -> dict[str, Any]:
    rows = db.execute(
        select(Project.id, Project.slug, Project.name, Membership.role, Membership.scopes_json)
        .join(Membership, Membership.project_id == Project.id)
        .where(Membership.principal_id == principal.id)
        .order_by(Project.slug)
    ).all()
    memberships = [
        {
            "project_id": pid,
            "slug": slug,
            "name": name,
            "role": role,
            "permitted_actions": _ACTIONS_BY_ROLE.get(role, []),
        }
        for pid, slug, name, role, _scopes in rows
    ]
    return {
        "principal": {
            "id": principal.id,
            "display_name": principal.display_name,
            "kind": principal.kind.value,
            "authority_tier": principal.tier.value,
        },
        "auth_method": principal.auth_method,
        "memberships": memberships,
    }
