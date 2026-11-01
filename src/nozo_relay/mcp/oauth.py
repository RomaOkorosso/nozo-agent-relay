"""OAuth compatibility SCAFFOLDING for the MCP facade (T10).

Status: ``probe_pass`` for local discovery/PKCE/revoke/rotation tests; ``not_verified`` for ChatGPT
(real connector behaviour is T11). Disabled by default (``mcp_oauth_enabled=False``).

What this is: a thin ``OAuthAuthorizationServerProvider`` for the *supported* MCP SDK. The SDK owns
the protocol surface (RFC 8414 AS metadata, RFC 9728 protected-resource metadata, RFC 7591
registration, ``/authorize``, ``/token``, ``/revoke``, S256-only PKCE verification, redirect-URI
exact matching). This module only supplies policy and storage; it contains NO hand-written crypto
(random values come from ``secrets``; verification is the SDK's).

Policy implemented here:

* Redirect URIs: exact match against ``mcp_oauth_redirect_uris`` (registration is refused otherwise).
* Audience (RFC 8707): ``resource`` is REQUIRED on /authorize and must equal ``mcp_resource``; every
  token is stamped with that resource and the gateway re-checks it per request.
* Scopes: ``relay:read``, ``relay:write``, ``relay:control`` plus optional ``project:<uuid>`` limits.
* Principal mapping: consent binds a token to ONE relay *coordinator* principal chosen by the owner.
  A token can never map to an owner (the owner's authority is never delegated through OAuth).
* Tokens: opaque random values; only SHA-256 digests are kept (in memory). Short access TTL, refresh
  rotation with reuse detection (reuse revokes the whole grant family), revocation endpoint enabled.
* Single-use authorization codes; re-presenting a used code revokes tokens minted from it.

Durable storage is NOT implemented (state is in-process, so a restart revokes every OAuth grant:
fails closed). The SDK's CORS ``*`` on /token,/register,/revoke is retained (public OAuth endpoints,
no cookies; see KNOWN_LIMITATIONS). Owner consent is served at ``/oauth/consent``.
"""

from __future__ import annotations

import hashlib
import re
import secrets
import time
import uuid
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from mcp.server.auth.provider import (
    AccessToken,
    AuthorizationCode,
    AuthorizationParams,
    AuthorizeError,
    RefreshToken,
    RegistrationError,
    TokenError,
    construct_redirect_uri,
)
from mcp.shared.auth import OAuthClientInformationFull, OAuthToken

from nozo_relay.auth.context import PrincipalContext
from nozo_relay.auth.credentials import load_project_roles
from nozo_relay.config import Settings
from nozo_relay.db.models import Principal
from nozo_relay.domain.enums import PrincipalKind
from nozo_relay.usecases import Ctx

SCOPE_READ = "relay:read"
SCOPE_WRITE = "relay:write"
SCOPE_CONTROL = "relay:control"
BASE_SCOPES = (SCOPE_READ, SCOPE_WRITE, SCOPE_CONTROL)
PROJECT_SCOPE_PREFIX = "project:"
_PROJECT_SCOPE = re.compile(r"^project:[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
_ALLOWED_GRANTS = {"authorization_code", "refresh_token"}
CONSENT_PATH = "/oauth/consent"


def valid_scope(scope: str) -> bool:
    return scope in BASE_SCOPES or bool(_PROJECT_SCOPE.match(scope))


def _digest(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def principal_context_for(ctx: Ctx, principal_id: str) -> PrincipalContext | None:
    """Fresh PrincipalContext for an OAuth subject; None if inactive/unknown/owner (never owner)."""
    with ctx.read() as db:
        p = db.get(Principal, principal_id)
        if p is None or not p.active or p.kind != PrincipalKind.COORDINATOR.value:
            return None
        return PrincipalContext(
            id=p.id,
            kind=PrincipalKind(p.kind),
            display_name=p.display_name,
            project_roles=load_project_roles(db, p.id),
            auth_method="key",  # a bearer credential, not a browser session
        )


@dataclass
class _Pending:
    client: OAuthClientInformationFull
    params: AuthorizationParams
    created_at: float


@dataclass
class _Family:
    id: str
    principal_id: str
    client_id: str
    revoked: bool = False


class RelayAuthorizationCode(AuthorizationCode):
    family_id: str
    principal_id: str


class RelayRefreshToken(RefreshToken):
    family_id: str


class RelayAccessToken(AccessToken):
    family_id: str


@dataclass
class RelayOAuthProvider:
    ctx: Ctx
    settings: Settings
    now: Callable[[], float] = time.time
    clients: dict[str, OAuthClientInformationFull] = field(default_factory=dict)
    _pending: dict[str, _Pending] = field(default_factory=dict)
    _codes: dict[str, RelayAuthorizationCode] = field(default_factory=dict)
    _used_codes: dict[str, str] = field(default_factory=dict)  # code digest -> family id
    _access: dict[str, RelayAccessToken] = field(default_factory=dict)
    _refresh: dict[str, RelayRefreshToken] = field(default_factory=dict)
    _used_refresh: dict[str, str] = field(default_factory=dict)  # refresh digest -> family id
    _families: dict[str, _Family] = field(default_factory=dict)

    # ------------------------------------------------------------------ clients
    async def get_client(self, client_id: str) -> OAuthClientInformationFull | None:
        return self.clients.get(client_id)

    async def register_client(self, client_info: OAuthClientInformationFull) -> None:
        allowed = set(self.settings.mcp_oauth_redirect_uris)
        uris = [str(u) for u in (client_info.redirect_uris or [])]
        if not uris or any(u not in allowed for u in uris):
            raise RegistrationError("invalid_redirect_uri", "redirect URI is not on the exact-match allowlist")
        if not set(client_info.grant_types) <= _ALLOWED_GRANTS:
            raise RegistrationError("invalid_client_metadata", "unsupported grant type")
        if client_info.scope and not all(s in BASE_SCOPES for s in client_info.scope.split()):
            raise RegistrationError("invalid_client_metadata", "unsupported scope")
        if client_info.client_id is None:
            raise RegistrationError("invalid_client_metadata", "client_id missing")
        self.clients[client_info.client_id] = client_info

    # ------------------------------------------------------------------ authorize
    def accepted_resources(self) -> frozenset[str]:
        """Canonical MCP audience plus optional aliases (e.g. tunnel-rewritten resource URLs)."""
        values = {self.settings.mcp_resource.rstrip("/")}
        values.update(u.rstrip("/") for u in self.settings.mcp_oauth_accepted_resources)
        return frozenset(values)

    def peek_pending(self, request_id: str) -> _Pending | None:
        pending = self._pending.get(request_id)
        if pending is None:
            return None
        if self.now() - pending.created_at > self.settings.mcp_oauth_code_ttl_seconds * 5:
            return None
        return pending

    async def authorize(self, client: OAuthClientInformationFull, params: AuthorizationParams) -> str:
        if params.resource is None or params.resource.rstrip("/") not in self.accepted_resources():
            raise AuthorizeError("invalid_target", "resource must be the Relay MCP resource URL")
        scopes = params.scopes or [SCOPE_READ]
        if not all(s in BASE_SCOPES for s in scopes):  # project limits are set by the owner at consent
            raise AuthorizeError("invalid_scope", "unsupported scope")
        self._gc()
        request_id = secrets.token_urlsafe(32)
        self._pending[request_id] = _Pending(client, params.model_copy(update={"scopes": scopes}), self.now())
        return f"{self.settings.mcp_oauth_issuer}{CONSENT_PATH}?request_id={request_id}"

    def grant(
        self,
        request_id: str,
        principal_id: str,
        *,
        scopes: list[str] | None = None,
        project_ids: list[str] | None = None,
    ) -> str:
        """Owner consent hook: bind a pending request to a coordinator principal; returns the redirect URL.

        Call only after owner session + recent-auth. Scopes can only be narrowed, never widened;
        ``project_ids`` (chosen by the OWNER at consent, never by the client) adds ``project:<uuid>``
        limits so the token only sees those projects. Owner/inactive/non-coordinator principals are
        refused. The redirect includes RFC 9207 ``iss`` matching ``mcp_oauth_issuer``.
        """
        pending = self._pending.pop(request_id, None)
        if pending is None or self.now() - pending.created_at > self.settings.mcp_oauth_code_ttl_seconds * 5:
            raise AuthorizeError("access_denied", "unknown or expired authorization request")
        if principal_context_for(self.ctx, principal_id) is None:
            raise AuthorizeError("access_denied", "principal cannot be granted MCP access")
        requested = list(pending.params.scopes or [SCOPE_READ])
        granted = requested if scopes is None else [s for s in scopes if s in requested]
        if not granted:
            raise AuthorizeError("invalid_scope", "no scope granted")
        granted = granted + [f"{PROJECT_SCOPE_PREFIX}{str(uuid.UUID(p))}" for p in (project_ids or [])]
        family = _Family(secrets.token_hex(16), principal_id, pending.client.client_id or "")
        self._families[family.id] = family
        code = secrets.token_urlsafe(32)
        self._codes[_digest(code)] = RelayAuthorizationCode(
            code=_digest(code),
            scopes=granted,
            expires_at=self.now() + self.settings.mcp_oauth_code_ttl_seconds,
            client_id=family.client_id,
            code_challenge=pending.params.code_challenge,
            redirect_uri=pending.params.redirect_uri,
            redirect_uri_provided_explicitly=pending.params.redirect_uri_provided_explicitly,
            resource=self.settings.mcp_resource,
            subject=principal_id,
            family_id=family.id,
            principal_id=principal_id,
        )
        return construct_redirect_uri(
            str(pending.params.redirect_uri),
            code=code,
            state=pending.params.state,
            iss=self.settings.mcp_oauth_issuer,
        )

    # ------------------------------------------------------------------ code / tokens
    async def load_authorization_code(
        self, client: OAuthClientInformationFull, authorization_code: str
    ) -> RelayAuthorizationCode | None:
        d = _digest(authorization_code)
        if d in self._used_codes:  # replay of a redeemed code: revoke what it produced (RFC 6749 §4.1.2)
            self._revoke_family(self._used_codes[d])
            return None
        code = self._codes.get(d)
        if code is None or code.client_id != client.client_id:
            return None
        return code

    async def exchange_authorization_code(
        self, client: OAuthClientInformationFull, authorization_code: RelayAuthorizationCode
    ) -> OAuthToken:
        self._codes.pop(authorization_code.code, None)
        self._used_codes[authorization_code.code] = authorization_code.family_id
        if self._families[authorization_code.family_id].revoked:
            raise TokenError("invalid_grant", "grant was revoked")
        return self._issue(authorization_code.family_id, authorization_code.scopes)

    def _issue(self, family_id: str, scopes: list[str]) -> OAuthToken:
        fam = self._families[family_id]
        now = self.now()
        access, refresh = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
        at_ttl, rt_ttl = self.settings.mcp_oauth_access_ttl_seconds, self.settings.mcp_oauth_refresh_ttl_seconds
        self._access[_digest(access)] = RelayAccessToken(
            token=_digest(access), client_id=fam.client_id, scopes=list(scopes), expires_at=int(now + at_ttl),
            resource=self.settings.mcp_resource, subject=fam.principal_id,
            claims={"iss": self.settings.mcp_oauth_issuer, "family": fam.id}, family_id=fam.id,
        )
        self._refresh[_digest(refresh)] = RelayRefreshToken(
            token=_digest(refresh), client_id=fam.client_id, scopes=list(scopes), expires_at=int(now + rt_ttl),
            resource=self.settings.mcp_resource, subject=fam.principal_id, family_id=fam.id,
        )
        return OAuthToken(
            access_token=access, token_type="Bearer", expires_in=at_ttl, scope=" ".join(scopes), refresh_token=refresh
        )

    async def load_refresh_token(self, client: OAuthClientInformationFull, refresh_token: str) -> RelayRefreshToken | None:
        d = _digest(refresh_token)
        if d in self._used_refresh:  # reuse of a rotated token => the family is compromised
            self._revoke_family(self._used_refresh[d])
            return None
        rt = self._refresh.get(d)
        if rt is None or rt.client_id != client.client_id or self._families[rt.family_id].revoked:
            return None
        return rt

    async def exchange_refresh_token(
        self, client: OAuthClientInformationFull, refresh_token: RelayRefreshToken, scopes: list[str]
    ) -> OAuthToken:
        self._refresh.pop(refresh_token.token, None)
        self._used_refresh[refresh_token.token] = refresh_token.family_id
        # Old access tokens of the family die with the rotation.
        for k in [k for k, v in self._access.items() if v.family_id == refresh_token.family_id]:
            del self._access[k]
        if principal_context_for(self.ctx, self._families[refresh_token.family_id].principal_id) is None:
            self._revoke_family(refresh_token.family_id)
            raise TokenError("invalid_grant", "principal is no longer eligible")
        return self._issue(refresh_token.family_id, scopes or refresh_token.scopes)

    async def load_access_token(self, token: str) -> RelayAccessToken | None:
        at = self._access.get(_digest(token))
        if at is None or at.expires_at is None or at.expires_at <= self.now():
            return None
        if self._families[at.family_id].revoked:
            return None
        return at

    async def revoke_token(self, token: Any) -> None:
        family_id = getattr(token, "family_id", None)
        if family_id is not None:
            self._revoke_family(family_id)

    # ------------------------------------------------------------------ internals
    def _revoke_family(self, family_id: str) -> None:
        fam = self._families.get(family_id)
        if fam is not None:
            fam.revoked = True
        for table in (self._access, self._refresh):
            for k in [k for k, v in table.items() if v.family_id == family_id]:
                del table[k]

    def revoke_principal(self, principal_id: str) -> int:
        """Revoke every OAuth grant of a principal (owner action: delegation/credential revocation)."""
        ids = [f.id for f in self._families.values() if f.principal_id == principal_id and not f.revoked]
        for fid in ids:
            self._revoke_family(fid)
        return len(ids)

    def _gc(self) -> None:
        cutoff = self.now() - self.settings.mcp_oauth_code_ttl_seconds * 5
        for k in [k for k, v in self._pending.items() if v.created_at < cutoff]:
            del self._pending[k]
