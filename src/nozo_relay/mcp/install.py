"""Wire the MCP facade into the FastAPI app (same listener, same DB, same use cases).

The SDK is an OPTIONAL dependency (``uv sync --extra mcp``; also in the dev group). When it is
missing (or ``mcp_enabled=False``) nothing is registered and ``/mcp`` answers 404 — never a fake PASS.
"""

from __future__ import annotations

import logging
from collections.abc import AsyncIterator
from contextlib import AbstractAsyncContextManager, asynccontextmanager
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any
from urllib.parse import urlsplit

from fastapi import FastAPI
from starlette.routing import Route

from nozo_relay.usecases import Ctx

if TYPE_CHECKING:
    from .oauth import RelayOAuthProvider

log = logging.getLogger("nozo_relay.mcp")
MCP_PATH = "/mcp"


@dataclass
class McpRuntime:
    server: Any
    session_manager_run: Any
    oauth: RelayOAuthProvider | None
    protocol_note: str

    def lifespan(self) -> AbstractAsyncContextManager[Any]:
        return self.session_manager_run()


def sdk_available() -> bool:
    try:
        import mcp.server.mcpserver  # noqa: F401
    except ImportError:
        return False
    return True


def install_mcp(app: FastAPI) -> McpRuntime | None:
    settings = app.state.settings
    if not settings.mcp_enabled:
        return None
    if not sdk_available():
        log.warning("MCP SDK not installed (uv sync --extra mcp); /mcp is not served")
        return None

    from mcp.server.auth.routes import build_resource_metadata_url, create_auth_routes, create_protected_resource_routes
    from mcp.server.auth.settings import ClientRegistrationOptions, RevocationOptions
    from mcp.server.transport_security import TransportSecuritySettings
    from pydantic import AnyHttpUrl

    from .gateway import McpGateway, http_principal_source
    from .oauth import BASE_SCOPES, RelayOAuthProvider
    from .server import build_mcp_server

    def ctx_factory() -> Ctx:
        return Ctx.from_app(app)

    path = urlsplit(settings.mcp_resource).path or MCP_PATH
    ctx = ctx_factory()
    server = build_mcp_server(ctx, http_principal_source)

    hosts: list[str] = []
    for h in settings.host_allowlist:
        hosts += [h, f"{h}:{settings.port}"]
    security = TransportSecuritySettings(
        enable_dns_rebinding_protection=True,
        allowed_hosts=sorted(set(hosts)),
        allowed_origins=sorted(settings.origin_allowlist),
    )
    def build_inner() -> Any:
        # Stateless + JSON responses: every HTTP request is authenticated on its own (revocation is
        # immediate, no per-session identity to go stale) and tool calls never need a server->client channel.
        return server.streamable_http_app(
            streamable_http_path=path,
            json_response=True,
            stateless_http=True,
            transport_security=security,
            host=settings.host,
        )

    oauth: RelayOAuthProvider | None = None
    extra_routes: list[Route] = []
    resource_metadata_url: str | None = None
    if settings.mcp_oauth_enabled:
        oauth = RelayOAuthProvider(ctx, settings)
        resource = AnyHttpUrl(settings.mcp_resource)
        issuer = AnyHttpUrl(settings.mcp_oauth_issuer)
        resource_metadata_url = str(build_resource_metadata_url(resource))
        extra_routes += create_protected_resource_routes(
            resource_url=resource, authorization_servers=[issuer], scopes_supported=list(BASE_SCOPES),
            resource_name="Nozo Agent Relay MCP",
        )
        # ChatGPT requires public-client ``none`` + RFC 9207 iss advertisement (stable redirect URI).
        # SDK build_metadata omits both; we replace the AS metadata route after create_auth_routes.
        from mcp.server.auth.handlers.metadata import MetadataHandler
        from mcp.server.auth.routes import AUTHORIZATION_PATH, TOKEN_PATH, REGISTRATION_PATH, REVOCATION_PATH
        from mcp.server.auth.routes import build_metadata, cors_middleware
        from mcp.shared.auth import OAuthMetadata

        reg_opts = ClientRegistrationOptions(
            enabled=True, valid_scopes=list(BASE_SCOPES), default_scopes=[BASE_SCOPES[0]]
        )
        rev_opts = RevocationOptions(enabled=True)
        auth_routes = create_auth_routes(
            provider=oauth,
            issuer_url=issuer,
            client_registration_options=reg_opts,
            revocation_options=rev_opts,
        )
        meta = build_metadata(issuer, None, reg_opts, rev_opts, supports_identity_assertion=False)
        methods = list(meta.token_endpoint_auth_methods_supported or [])
        if "none" not in methods:
            methods = ["none", *methods]
        enhanced = OAuthMetadata.model_validate(
            {
                **meta.model_dump(mode="json"),
                "token_endpoint_auth_methods_supported": methods,
                "authorization_response_iss_parameter_supported": True,
                # CIMD not implemented here — ChatGPT uses DCR via registration_endpoint.
                "client_id_metadata_document_supported": False,
            }
        )
        # Drop stock metadata route, keep authorize/token/register/revoke.
        kept = [
            r for r in auth_routes
            if getattr(r, "path", None) != "/.well-known/oauth-authorization-server"
        ]
        kept.insert(
            0,
            Route(
                "/.well-known/oauth-authorization-server",
                endpoint=cors_middleware(MetadataHandler(enhanced).handle, ["GET", "OPTIONS"]),
                methods=["GET", "OPTIONS"],
            ),
        )
        extra_routes += kept
        _ = (AUTHORIZATION_PATH, TOKEN_PATH, REGISTRATION_PATH, REVOCATION_PATH)  # documented surface

    gateway = McpGateway(None, ctx_factory, oauth, resource_metadata_url=resource_metadata_url)
    # Register the exact MCP path on the FastAPI router (a root Mount would also swallow unknown paths
    # and change their 404 shape). Discovery/AS routes are public by design (RFC 9728/8414).
    app.router.routes.append(Route(path, endpoint=gateway))
    app.router.routes.extend(extra_routes)

    @asynccontextmanager
    async def run() -> AsyncIterator[None]:
        # A fresh SDK app/session manager per app lifespan (the manager's run() is single-use).
        inner = build_inner()
        async with inner.router.lifespan_context(inner):
            gateway.inner = inner
            try:
                yield
            finally:
                gateway.inner = None

    return McpRuntime(server, run, oauth, "stateless-json")
