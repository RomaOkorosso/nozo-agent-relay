"""Owner consent page for MCP OAuth (``/oauth/consent``).

Called after ``/authorize``; requires an owner browser session + recent password proof,
then binds the pending request to a coordinator principal via ``RelayOAuthProvider.grant()``.
"""

from __future__ import annotations

from typing import Any
from urllib.parse import quote, urlencode

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse, RedirectResponse, Response
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import select

from nozo_relay.api.deps import ClockDep, DbDep, SessionPrincipal, SettingsDep, check_origin
from nozo_relay.api.errors import RelayError
from nozo_relay.auth.sessions import is_recent_auth
from nozo_relay.db.models import Principal, Project
from nozo_relay.domain.enums import PrincipalKind
from mcp.server.auth.provider import AuthorizeError

from nozo_relay.mcp.oauth import BASE_SCOPES, CONSENT_PATH
from nozo_relay.ui import routes as ui_routes

router = APIRouter(tags=["oauth-consent"], include_in_schema=False)


def _oauth(request: Request):
    mcp = getattr(request.app.state, "mcp", None)
    oauth = getattr(mcp, "oauth", None) if mcp is not None else None
    if oauth is None:
        raise RelayError(404, "not_found", "MCP OAuth is not enabled")
    return oauth


def _safe_next(request_id: str) -> str:
    return f"{CONSENT_PATH}?{urlencode({'request_id': request_id})}"


@router.get(CONSENT_PATH, response_class=HTMLResponse)
def consent_page(
    request: Request,
    db: DbDep,
    settings: SettingsDep,
    clock: ClockDep,
) -> Response:
    request_id = (request.query_params.get("request_id") or "").strip()
    if not request_id:
        raise RelayError(400, "invalid_request", "request_id is required")

    principal = ui_routes._session_principal(request, db, settings, clock, touch=True)
    if principal is None:
        return RedirectResponse(f"/login?next={quote(_safe_next(request_id), safe='')}", status_code=303)

    if principal.kind is not PrincipalKind.OWNER:
        raise RelayError(403, "forbidden", "Only the owner can grant MCP OAuth access")

    oauth = _oauth(request)
    pending = oauth.peek_pending(request_id)
    if pending is None:
        return ui_routes._render(
            request,
            "oauth_consent.html",
            {
                "principal": principal,
                "error": "Запрос авторизации не найден или истёк. Начните подключение заново из ChatGPT.",
                "pending": None,
                "coordinators": [],
                "projects": [],
                "recent_auth": False,
                "request_id": request_id,
            },
            status=410,
        )

    coordinators = list(
        db.execute(
            select(Principal)
            .where(Principal.kind == PrincipalKind.COORDINATOR.value, Principal.active.is_(True))
            .order_by(Principal.display_name)
        ).scalars()
    )
    projects = list(db.execute(select(Project).order_by(Project.name)).scalars())
    recent = is_recent_auth(principal.reauth_at, clock, settings)
    client_name = getattr(pending.client, "client_name", None) or pending.client.client_id or "MCP client"
    scopes = list(pending.params.scopes or [BASE_SCOPES[0]])
    return ui_routes._render(
        request,
        "oauth_consent.html",
        {
            "principal": principal,
            "error": None,
            "pending": {
                "client_name": client_name,
                "client_id": pending.client.client_id,
                "redirect_uri": str(pending.params.redirect_uri),
                "resource": pending.params.resource,
                "scopes": scopes,
            },
            "coordinators": [{"id": c.id, "display_name": c.display_name} for c in coordinators],
            "projects": [{"id": p.id, "name": p.name, "slug": p.slug} for p in projects],
            "recent_auth": recent,
            "recent_auth_seconds": settings.recent_auth_seconds,
            "request_id": request_id,
            "base_scopes": list(BASE_SCOPES),
        },
    )


class ConsentBody(BaseModel):
    model_config = ConfigDict(extra="forbid")

    request_id: str = Field(min_length=8, max_length=128)
    principal_id: str = Field(min_length=8, max_length=64)
    scopes: list[str] | None = None
    project_ids: list[str] | None = None


@router.post("/api/v1/oauth/consent")
def consent_grant(
    body: ConsentBody,
    request: Request,
    principal: SessionPrincipal,
    settings: SettingsDep,
    clock: ClockDep,
) -> dict[str, Any]:
    """Owner grants a pending OAuth request to a coordinator. Returns the client redirect URL."""
    check_origin(request, settings)
    if principal.kind is not PrincipalKind.OWNER:
        raise RelayError(403, "forbidden", "Only the owner can grant MCP OAuth access")
    if principal.auth_method != "session":
        raise RelayError(403, "session_required", "OAuth consent requires an owner browser session")
    if not is_recent_auth(principal.reauth_at, clock, settings):
        raise RelayError(
            403,
            "recent_auth_required",
            "Re-enter the owner password (POST /api/v1/auth/reauth) to grant MCP access",
            details={"max_age_seconds": settings.recent_auth_seconds},
        )

    oauth = _oauth(request)
    try:
        redirect = oauth.grant(
            body.request_id,
            body.principal_id,
            scopes=body.scopes,
            project_ids=body.project_ids,
        )
    except AuthorizeError as e:
        raise RelayError(400, e.error, e.error_description or "authorization denied") from e
    return {"redirect_url": redirect}
