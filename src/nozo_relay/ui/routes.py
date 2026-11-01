"""Owner panel: server-rendered Jinja2 pages + HTML fragments for live regions.

* Authentication is the HttpOnly session cookie only (no Bearer, no tokens in JS). Pages redirect to
  ``/login``; fragments answer 401 JSON so the script can redirect. Mutations are done by the page
  script against the normal ``/api/v1`` endpoints with ``X-CSRF-Token`` (see static/app.js).
* Fragments are read-only GETs and are the same templates the page includes, so there is a single
  rendering path and a reconnect/refresh is idempotent (no duplicated rows).
"""

from __future__ import annotations

from pathlib import Path
from typing import Annotated, Any

from fastapi import APIRouter, Depends, Form, Query, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, Response
from fastapi.templating import Jinja2Templates
from sqlalchemy import select
from sqlalchemy.orm import Session

from nozo_relay.api.auth_routes import IssuedBrowserLogin, attach_session_cookies, authenticate_browser_login
from nozo_relay.api.deps import ClockDep, DbDep, LimiterDep, SettingsDep, check_origin
from nozo_relay.api.errors import RelayError
from nozo_relay.auth.claim_tokens import consume_claim_token
from nozo_relay.auth.context import PrincipalContext
from nozo_relay.auth.credentials import load_project_roles
from nozo_relay.auth.sessions import create_session, get_session
from nozo_relay.db.models import Membership, Principal, Project
from nozo_relay.domain.enums import PrincipalKind
from nozo_relay.services import acl
from nozo_relay.ui import coord_context, labels as L
from nozo_relay.ui import views

HERE = Path(__file__).parent
TEMPLATES_DIR = HERE / "templates"
STATIC_DIR = HERE / "static"

templates = Jinja2Templates(directory=str(TEMPLATES_DIR))
templates.env.globals.update(L=L, snippet=views.snippet)
templates.env.filters.update(utc=L.fmt_utc, iso=L.fmt_iso, age=L.human_age)

router = APIRouter(tags=["ui"], include_in_schema=False)

HTML_HEADERS = {"Cache-Control": "no-store"}


class UiAuthRedirect(Exception):
    pass


def _session_principal(request: Request, db: Session, settings, clock, *, touch: bool) -> PrincipalContext | None:
    cookie = request.cookies.get(settings.session_cookie_name)
    if not cookie:
        return None
    row = get_session(db, clock, settings, cookie, touch=touch)
    if row is None:
        return None
    p = db.get(Principal, row.owner_id)
    if p is None or not p.active:
        return None
    kind = PrincipalKind(p.kind)
    if getattr(request.state, "external_surface", False) and kind is not PrincipalKind.COORDINATOR:
        return None
    if touch:
        db.commit()
    return PrincipalContext(
        id=p.id, kind=kind, display_name=p.display_name,
        project_roles=load_project_roles(db, p.id), auth_method="session", session_id_digest=row.id_digest,
        reauth_at=row.reauth_at if row.reauth_at is not None else row.created_at,
    )


def page_principal(request: Request, db: DbDep, settings: SettingsDep, clock: ClockDep) -> PrincipalContext:
    p = _session_principal(request, db, settings, clock, touch=True)
    if p is None:
        raise UiAuthRedirect
    return p


def fragment_principal(request: Request, db: DbDep, settings: SettingsDep, clock: ClockDep) -> PrincipalContext:
    # No idle extension: a tab that only polls must not keep a session alive forever.
    p = _session_principal(request, db, settings, clock, touch=False)
    if p is None:
        raise RelayError(401, "unauthenticated", "Session expired or revoked")
    return p


PagePrincipal = Annotated[PrincipalContext, Depends(page_principal)]
FragPrincipal = Annotated[PrincipalContext, Depends(fragment_principal)]


def install_ui_handlers(app) -> None:  # noqa: ANN001
    @app.exception_handler(UiAuthRedirect)
    async def _redirect(_request: Request, _exc: UiAuthRedirect) -> Response:
        return RedirectResponse("/login", status_code=303, headers=HTML_HEADERS)


def _render(request: Request, name: str, ctx: dict[str, Any], status: int = 200) -> HTMLResponse:
    settings = request.app.state.settings
    ctx = {
        "csrf_cookie": settings.csrf_cookie_name,
        "csrf_header": settings.csrf_header_name,
        **ctx,
    }
    return templates.TemplateResponse(request, name, ctx, status_code=status, headers=HTML_HEADERS)


def _error_page(request: Request, exc: RelayError) -> HTMLResponse:
    status = 404 if exc.status_code == 404 else exc.status_code
    return _render(request, "error.html", {"status": status, "message": "Страница не найдена" if status == 404 else exc.message}, status)


def _project_or_404(db: Session, principal: PrincipalContext, project_id: str) -> Project:
    return acl.get_project(db, principal, project_id)


# ------------------------------------------------------------------ pages


@router.get("/")
def index(request: Request, db: DbDep, settings: SettingsDep, clock: ClockDep) -> Response:
    p = _session_principal(request, db, settings, clock, touch=False)
    return RedirectResponse("/projects" if p else "/login", status_code=303, headers=HTML_HEADERS)


@router.get("/login")
def login_page(request: Request, db: DbDep, settings: SettingsDep, clock: ClockDep) -> Response:
    if _session_principal(request, db, settings, clock, touch=False) is not None:
        return RedirectResponse("/projects", status_code=303, headers=HTML_HEADERS)
    return _render(request, "login.html", {"error": None})


@router.post("/login")
def login_form(
    request: Request,
    db: DbDep,
    settings: SettingsDep,
    clock: ClockDep,
    limiter: LimiterDep,
    username: Annotated[str, Form(min_length=1, max_length=64)],
    password: Annotated[str, Form(min_length=1, max_length=1024)],
) -> Response:
    """Classic HTML form login (no JS fetch) — more reliable through free tunnels / remote browsers."""
    try:
        check_origin(request, settings)
        issued = authenticate_browser_login(
            request=request,
            db=db,
            settings=settings,
            clock=clock,
            limiter=limiter,
            username=username.strip(),
            password=password,
        )
    except RelayError as exc:
        if exc.status_code == 429:
            msg = "Слишком много неудачных попыток. Повторите позже."
        elif exc.status_code == 401:
            msg = "Неверный логин или пароль."
        elif exc.code == "origin_not_allowed":
            msg = (
                "Origin не разрешён. Используйте обычный браузер (не Cursor Simple Browser) "
                "на http://127.0.0.1:8765/login или https://roma-gv628rc.tailbfec94.ts.net/login"
            )
        elif exc.code == "forbidden":
            msg = "Вход владельца на публичной поверхности запрещён. Используйте локальный адрес или Tailscale Serve."
        else:
            msg = exc.message or "Ошибка входа."
        return _render(request, "login.html", {"error": msg, "username": username}, status=exc.status_code)

    response = RedirectResponse("/projects", status_code=303, headers=HTML_HEADERS)
    attach_session_cookies(response, settings, issued, request=request)
    return response


@router.get("/login/claim/{token}")
def login_claim(
    token: str,
    request: Request,
    db: DbDep,
    settings: SettingsDep,
    clock: ClockDep,
) -> Response:
    """Single-use GET login for coordinators when free tunnels drop POST /login."""
    principal_id = consume_claim_token(settings.data_dir, clock, token)
    if principal_id is None:
        return _render(
            request,
            "login.html",
            {"error": "Ссылка входа недействительна или уже использована. Нужна новая claim-ссылка."},
            status=401,
        )
    principal = db.get(Principal, principal_id)
    if (
        principal is None
        or not principal.active
        or principal.kind != PrincipalKind.COORDINATOR.value
    ):
        return _render(request, "login.html", {"error": "Координатор недоступен."}, status=403)
    if getattr(request.state, "external_surface", False) and principal.kind != PrincipalKind.COORDINATOR.value:
        return _render(request, "login.html", {"error": "Forbidden."}, status=403)

    raw = create_session(db, clock, settings, principal.id)
    db.commit()
    issued = IssuedBrowserLogin(
        principal=principal,
        session_id=raw.session_id,
        csrf_token=raw.csrf_token,
        idle_expires_at=raw.idle_expires_at,
        absolute_expires_at=raw.absolute_expires_at,
    )
    response = RedirectResponse("/projects", status_code=303, headers=HTML_HEADERS)
    attach_session_cookies(response, settings, issued, request=request)
    return response


@router.get("/projects")
def projects_page(request: Request, principal: PagePrincipal, db: DbDep) -> Response:
    rows = db.execute(
        select(Project)
        .join(Membership, Membership.project_id == Project.id)
        .where(Membership.principal_id == principal.id)
        .order_by(Project.slug)
    ).scalars().all()
    items = [{"project": p, "counters": views.counters(db, p.id)} for p in rows]
    return _render(request, "projects.html", {"principal": principal, "items": items})


@router.get("/projects/{project_id}")
def project_page(
    request: Request, project_id: str, principal: PagePrincipal, db: DbDep, settings: SettingsDep, clock: ClockDep
) -> Response:
    try:
        project = _project_or_404(db, principal, project_id)
    except RelayError as exc:
        return _error_page(request, exc)
    data = views.project_page(db, settings, clock, project)
    chat = views.chat_page(db, project)
    delegation = coord_context.active_delegation_for(db, clock, principal, project)
    return _render(
        request, "project.html",
        {
            "principal": principal,
            "is_owner": principal.is_owner,
            "can_post_chat": coord_context.can_post_chat(principal),
            "can_create_task": coord_context.can_create_task(principal, delegation),
            "active_delegation": delegation,
            "chat": chat,
            "agents": views.agent_choices(data["people"]),
            "author_filter": "",
            "task_filter": "",
            **data,
        },
    )


@router.get("/projects/{project_id}/tasks/{task_id}")
def task_page(
    request: Request, project_id: str, task_id: str, principal: PagePrincipal, db: DbDep, settings: SettingsDep,
    clock: ClockDep,
) -> Response:
    try:
        project = _project_or_404(db, principal, project_id)
        task = views.require_task(db, project, task_id)
    except RelayError as exc:
        return _error_page(request, exc)
    data = views.task_page(db, settings, clock, project, task)
    chat = views.chat_page(db, project, task_id=task.id)
    delegation = coord_context.active_delegation_for(db, clock, principal, project)
    return _render(
        request, "task.html",
        {
            "principal": principal,
            "is_owner": principal.is_owner,
            "can_post_chat": coord_context.can_post_chat(principal),
            "can_drive": coord_context.can_drive_task(principal, task, delegation),
            "active_delegation": delegation,
            "chat": chat,
            "actions": views.allowed_actions(task.status),
            **data,
        },
    )


# ------------------------------------------------------------------ fragments (live regions)


def _frag(request: Request, name: str, ctx: dict[str, Any]) -> HTMLResponse:
    return templates.TemplateResponse(request, name, ctx, headers=HTML_HEADERS)


@router.get("/ui/projects/{project_id}/summary")
def frag_summary(
    request: Request, project_id: str, principal: FragPrincipal, db: DbDep, settings: SettingsDep, clock: ClockDep
) -> Response:
    project = _project_or_404(db, principal, project_id)
    data = views.project_page(db, settings, clock, project)
    return _frag(request, "_summary.html", data)


@router.get("/ui/projects/{project_id}/tasks")
def frag_tasks(
    request: Request, project_id: str, principal: FragPrincipal, db: DbDep, settings: SettingsDep, clock: ClockDep
) -> Response:
    project = _project_or_404(db, principal, project_id)
    return _frag(request, "_tasks.html", {"project": project, "tasks": views.task_cards(db, settings, clock, project),
                                          "hw": views.high_watermark(db, project.id)})


@router.get("/ui/projects/{project_id}/chat")
def frag_chat(
    request: Request,
    project_id: str,
    principal: FragPrincipal,
    db: DbDep,
    task_id: Annotated[str | None, Query(max_length=64)] = None,
    author_id: Annotated[str | None, Query(max_length=64)] = None,
    before: Annotated[str | None, Query(max_length=200)] = None,
    limit: Annotated[int, Query(ge=1, le=100)] = views.CHAT_PAGE,
) -> Response:
    project = _project_or_404(db, principal, project_id)
    if task_id:
        views.require_task(db, project, task_id)
    chat = views.chat_page(db, project, task_id=task_id or None, author_id=author_id or None, before=before, limit=limit)
    return _frag(request, "_chat_fragment.html", {"chat": chat, "project": project})


@router.get("/ui/projects/{project_id}/tasks/{task_id}/{part}")
def frag_task_part(
    request: Request,
    project_id: str,
    task_id: str,
    part: str,
    principal: FragPrincipal,
    db: DbDep,
    settings: SettingsDep,
    clock: ClockDep,
) -> Response:
    templates_by_part = {"state": "_task_state.html", "actions": "_task_actions.html",
                         "timeline": "_timeline.html", "reports": "_reports.html"}
    if part not in templates_by_part:
        raise RelayError(404, "not_found", "Resource not found")
    project = _project_or_404(db, principal, project_id)
    task = views.require_task(db, project, task_id)
    data = views.task_page(db, settings, clock, project, task)
    delegation = coord_context.active_delegation_for(db, clock, principal, project)
    return _frag(
        request, templates_by_part[part],
        {
            "is_owner": principal.is_owner,
            "can_drive": coord_context.can_drive_task(principal, task, delegation),
            "actions": views.allowed_actions(task.status),
            **data,
        },
    )


@router.get("/ui/session")
def session_probe(principal: FragPrincipal) -> JSONResponse:
    """Cheap liveness probe for the polling fallback (200 while the session is valid)."""
    return JSONResponse({"ok": True}, headers=HTML_HEADERS)
