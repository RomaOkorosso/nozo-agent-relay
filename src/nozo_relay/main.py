"""FastAPI application factory and bind helpers."""

from __future__ import annotations

import asyncio
import logging
import re
from collections.abc import AsyncIterator
from contextlib import AsyncExitStack, asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.staticfiles import StaticFiles
from starlette.middleware.trustedhost import TrustedHostMiddleware

from nozo_relay import __version__, logsafe
from nozo_relay.api import agents, approvals, artifacts, auth_routes, health, projects, runs, tasks
from nozo_relay.api.errors import error_response, install_error_handlers, new_request_id
from nozo_relay.auth.ratelimit import LoginRateLimiter
from nozo_relay.clock import Clock, SystemClock
from nozo_relay.config import Settings, SettingsError, is_loopback_host
from nozo_relay.db.engine import create_engine_from_settings, make_session_factory
from nozo_relay.db.engine import add_commit_listener, write_session
from nozo_relay.db.schema import ensure_schema
from nozo_relay.mcp.install import install_mcp
from nozo_relay.services import leases
from nozo_relay.ui import routes as ui_routes
from nozo_relay.ws.hub import Hub
from nozo_relay.ws.routes import router as ws_router

_ARTIFACT_PATH = re.compile(r"/api/v1/projects/[^/]+/artifacts")
_HOST_RE = re.compile(r"[A-Za-z0-9.\-\[\]:]{1,255}")
CSP = "default-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'; object-src 'none'"


def bind_address(settings: Settings) -> tuple[str, int]:
    """Validated (host, port). Refuses non-loopback unless explicitly allowed."""
    validate_bind(settings)
    return settings.host, settings.port


def validate_bind(settings: Settings) -> None:
    if not is_loopback_host(settings.host):
        if not settings.allow_non_loopback_bind:
            raise SettingsError(f"refusing non-loopback bind {settings.host!r}")
        if settings.insecure_dev_cookies:
            raise SettingsError("insecure_dev_cookies requires a loopback bind")


def create_app(settings: Settings | None = None, clock: Clock | None = None) -> FastAPI:
    settings = settings or Settings()
    validate_bind(settings)
    clock = clock or SystemClock()
    logsafe.install()  # secrets never reach nozo_relay.* log records

    # Fail fast: incompatible schema/runtime must prevent startup.
    engine = create_engine_from_settings(settings)
    try:
        ensure_schema(engine, clock, require_wal_fix=settings.sqlite_require_wal_fix)
    except BaseException:
        engine.dispose()
        raise

    # Restart reconciliation: expired leases -> lost + blocked(recovery_required). Nothing is
    # re-issued automatically; a supervisor must reconcile and the owner must resume explicitly.
    try:
        with write_session(engine) as ws:
            leases.sweep(ws, clock, settings)
    except BaseException:
        engine.dispose()
        raise

    async def _watchdog() -> None:
        interval = settings.watchdog_interval_seconds
        while True:
            await asyncio.sleep(interval)
            try:
                await asyncio.to_thread(_sweep_once)
            except Exception:  # noqa: BLE001 - the watchdog must never die
                logging.getLogger("nozo_relay.leases").exception("watchdog sweep failed")

    def _sweep_once() -> None:
        with make_session_factory(engine)() as db:
            due = leases.needs_sweep(db, clock, settings)
            db.rollback()
        if due:
            with write_session(engine) as ws:
                leases.sweep(ws, clock, settings)

    @asynccontextmanager
    async def lifespan(_app: FastAPI) -> AsyncIterator[None]:
        task = asyncio.create_task(_watchdog()) if settings.watchdog_interval_seconds > 0 else None
        try:
            async with AsyncExitStack() as stack:
                if app.state.mcp is not None:  # SDK session manager must run for /mcp to serve
                    await stack.enter_async_context(app.state.mcp.lifespan())
                yield
        finally:
            if task is not None:
                task.cancel()
            app.state.hub.close_all("server_shutdown")
            await asyncio.sleep(0)  # let connection tasks observe the close request
            engine.dispose()

    app = FastAPI(
        title="Nozo Agent Relay",
        version=__version__,
        lifespan=lifespan,
        docs_url=None,
        redoc_url=None,
        openapi_url=None,  # no unauthenticated schema surface in M0
    )
    app.state.settings = settings
    app.state.clock = clock
    app.state.engine = engine
    app.state.session_factory = make_session_factory(engine)
    hub = Hub(settings, clock, app.state.session_factory)
    app.state.hub = hub
    # Wake WebSocket subscribers after every committed write that appended events. This is only an
    # acceleration: the hub also scans the durable log periodically (crash between commit and notify).
    add_commit_listener(engine, hub.notify)
    app.state.login_limiter = LoginRateLimiter(
        clock,
        max_failures=settings.login_max_failures,
        window_s=settings.login_window_seconds,
        lockout_s=settings.login_lockout_seconds,
    )

    install_error_handlers(app)

    @app.middleware("http")
    async def _common(request: Request, call_next):  # noqa: ANN001, ANN202
        request.state.request_id = new_request_id()
        declared = request.headers.get("content-length")
        if declared is not None:
            limit = settings.max_body_bytes
            if request.method == "POST" and _ARTIFACT_PATH.fullmatch(request.url.path):
                limit = settings.artifact_max_bytes  # binary upload; still capped, auth runs before reading
            try:
                too_big = int(declared) > limit
            except ValueError:
                too_big = True
            if too_big:
                return error_response(request, 413, "payload_too_large", "Request body too large")
        response = await call_next(request)
        response.headers.setdefault("X-Request-Id", request.state.request_id)
        # Older mobile WebKit does not let 'self' cover ws(s); name this (already allow-listed) host.
        host = request.headers.get("host", "")
        response.headers["Content-Security-Policy"] = (
            f"{CSP}; connect-src 'self' ws://{host} wss://{host}" if host and _HOST_RE.fullmatch(host) else CSP
        )
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        # same-origin (not no-referrer): browsers send Origin:null on POST when
        # Referrer-Policy is no-referrer, which breaks HTML form login Origin checks (RELAY-04).
        response.headers["Referrer-Policy"] = "same-origin"
        response.headers.setdefault("Cache-Control", "no-store")
        return response

    # Inner relative to TrustedHost: public Host → coordinator-only path allowlist.
    from nozo_relay.api.cors import GatewayCorsMiddleware
    from nozo_relay.api.external_surface import ExternalSurfaceMiddleware

    if settings.external_public_hosts or settings.external_public_host_suffixes:
        app.add_middleware(ExternalSurfaceMiddleware, settings=settings)

    # CORS for github.io gateway (and allowed_origins). Inside TrustedHost so Host is valid.
    app.add_middleware(GatewayCorsMiddleware, settings=settings)

    # Added last => outermost: unknown Host headers are rejected before anything else runs.
    app.add_middleware(TrustedHostMiddleware, allowed_hosts=settings.host_allowlist)

    app.include_router(health.router)
    app.include_router(auth_routes.router)
    app.include_router(projects.router)
    app.include_router(tasks.router)
    app.include_router(runs.router)
    app.include_router(agents.router)
    app.include_router(approvals.router)
    app.include_router(artifacts.router)
    app.include_router(ws_router)
    app.include_router(ui_routes.router)
    ui_routes.install_ui_handlers(app)
    app.mount("/static", StaticFiles(directory=str(ui_routes.STATIC_DIR)), name="static")
    app.state.mcp = install_mcp(app)  # None when disabled / SDK missing
    if app.state.mcp is not None and settings.mcp_oauth_enabled:
        from nozo_relay.mcp.consent import router as oauth_consent_router

        app.include_router(oauth_consent_router)
    return app


def serve(settings: Settings | None = None) -> None:
    import uvicorn

    settings = settings or Settings()
    host, port = bind_address(settings)
    app = create_app(settings)
    # Single worker: SQLite single-writer design. Proxy headers trusted from loopback only.
    uvicorn.run(app, host=host, port=port, workers=1, forwarded_allow_ips="127.0.0.1", server_header=False)


def app_factory() -> FastAPI:
    """For ``uvicorn nozo_relay.main:app_factory --factory`` (settings come from env/.env)."""
    return create_app(Settings())
