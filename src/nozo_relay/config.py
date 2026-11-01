"""Runtime settings (env prefix ``NOZO_RELAY_``, optional ``.env``)."""

from __future__ import annotations

import ipaddress
from pathlib import Path
from typing import Self

from pydantic import Field, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

LOOPBACK_NAMES = frozenset({"localhost"})


def is_loopback_host(host: str) -> bool:
    """True only for loopback names / addresses (never for 0.0.0.0 or ::)."""
    h = host.strip().strip("[]").lower()
    if h in LOOPBACK_NAMES:
        return True
    try:
        return ipaddress.ip_address(h).is_loopback
    except ValueError:
        return False


class SettingsError(ValueError):
    pass


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="NOZO_RELAY_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # Storage
    data_dir: Path = Field(default=Path("data"))
    sqlite_path: Path | None = None  # default: <data_dir>/relay.sqlite

    # Network. Backend stays on loopback; remote access goes through an HTTPS proxy.
    host: str = "127.0.0.1"
    port: int = Field(default=8765, ge=1, le=65535)
    allow_non_loopback_bind: bool = False
    allowed_origins: list[str] = Field(default_factory=list)  # extra browser origins (HTTPS proxy)
    allowed_hosts: list[str] = Field(default_factory=list)  # extra Host values (HTTPS proxy)
    # Public Hostnames (e.g. Funnel) that get the coordinator-only surface. Empty = disabled.
    # Owner Tailscale Serve can share the same DNS name only if Funnel is off; prefer listing the
    # Funnel hostname here and keeping Serve private when both are used carefully.
    external_public_hosts: list[str] = Field(default_factory=list)
    # Suffix match for ephemeral free tunnels (Cloudflare quick tunnel → *.trycloudflare.com).
    external_public_host_suffixes: list[str] = Field(default_factory=list)
    # Browser Origins for the static GitHub Pages gateway (CORS). Not Relay Host values.
    cors_origin_suffixes: list[str] = Field(default_factory=lambda: [".github.io"])

    # Sessions (05_SECURITY: idle 30 min, absolute 12 h)
    session_idle_seconds: int = Field(default=30 * 60, gt=0)
    session_absolute_seconds: int = Field(default=12 * 3600, gt=0)
    session_cookie_name: str = "nozo_session"
    csrf_cookie_name: str = "nozo_csrf"
    csrf_header_name: str = "X-CSRF-Token"
    # Plain-HTTP cookies (no Secure flag) are allowed ONLY when bound to loopback.
    insecure_dev_cookies: bool = False
    # Opt-in: accept browser Origin:null on loopback only (IDE Simple Browser). Off by default (SA-07).
    allow_opaque_origin: bool = False

    # Owner sensitive decisions (approvals) need a password proof this recent (05_SECURITY: 5 min)
    recent_auth_seconds: int = Field(default=300, gt=0)

    # Artifacts (04_API_CONTRACTS: <= 10 MiB each). Bytes live under <data_dir>/artifacts, server-chosen keys.
    artifact_max_bytes: int = Field(default=10 * 1024 * 1024, gt=0)
    artifact_project_quota_bytes: int = Field(default=1024 * 1024 * 1024, gt=0)

    # Approvals (records only; the relay has no publish executor)
    approval_max_ttl_seconds: int = Field(default=24 * 3600, gt=0)
    approval_max_pending_per_project: int = Field(default=50, ge=1)

    # Limits
    max_body_bytes: int = 256 * 1024
    login_max_failures: int = Field(default=5, ge=1)
    login_window_seconds: int = Field(default=300, gt=0)
    login_lockout_seconds: int = Field(default=60, gt=0)

    # Lease / execution protocol (06_EXECUTION_PROTOCOL defaults; fake clock in tests)
    lease_ttl_seconds: int = Field(default=90, gt=0)
    heartbeat_interval_seconds: int = Field(default=15, gt=0)
    watchdog_interval_seconds: float = Field(default=5.0, ge=0)  # 0 disables the background sweep
    stop_confirm_deadline_seconds: int = Field(default=60, gt=0)
    runtime_retry_limit: int = Field(default=2, ge=0)

    # WebSocket (04_API_CONTRACTS): heartbeat 20 s, per-consumer queue 1000 events / 2 MiB
    ws_heartbeat_seconds: float = Field(default=20.0, gt=0)
    ws_scan_interval_seconds: float = Field(default=1.0, gt=0)  # DB scan safety net behind the signal
    ws_auth_recheck_seconds: float = Field(default=5.0, gt=0)  # session/key/membership re-validation
    ws_queue_max_events: int = Field(default=1000, ge=1)
    ws_queue_max_bytes: int = Field(default=2 * 1024 * 1024, ge=1024)
    ws_send_timeout_seconds: float = Field(default=10.0, gt=0)
    ws_batch_size: int = Field(default=200, ge=1, le=1000)
    ws_max_connections_per_principal: int = Field(default=20, ge=1)

    # MCP facade (T10). Streamable HTTP at /mcp on the SAME loopback listener; Bearer agent key.
    mcp_enabled: bool = True  # also skipped (with a warning) when the optional `mcp` SDK is not installed
    mcp_resource_url: str | None = None  # canonical audience; default http://<host>:<port>/mcp
    # OAuth scaffolding (RFC 9728 discovery, RFC 8414 AS metadata, PKCE S256, RFC 8707 resource,
    # revocation, refresh rotation). OFF by default; NOT verified against ChatGPT (T11).
    mcp_oauth_enabled: bool = False
    mcp_oauth_issuer_url: str | None = None  # default: origin of the MCP resource URL
    mcp_oauth_redirect_uris: list[str] = Field(default_factory=list)  # exact-match allowlist, no wildcards
    # Extra RFC 8707 resource values accepted on /authorize (e.g. tunnel-rewritten MCP URLs).
    mcp_oauth_accepted_resources: list[str] = Field(default_factory=list)
    mcp_oauth_access_ttl_seconds: int = Field(default=900, ge=60, le=3600)
    mcp_oauth_refresh_ttl_seconds: int = Field(default=24 * 3600, ge=300, le=7 * 24 * 3600)
    mcp_oauth_code_ttl_seconds: int = Field(default=120, ge=30, le=600)

    # SQLite
    sqlite_busy_timeout_ms: int = 5000
    sqlite_require_wal_fix: bool = False  # reject SQLite builds with the WAL-reset bug

    @model_validator(mode="after")
    def _validate(self) -> Self:
        if self.session_idle_seconds > self.session_absolute_seconds:
            raise ValueError("session_idle_seconds must be <= session_absolute_seconds")
        loopback = is_loopback_host(self.host)
        if not loopback and not self.allow_non_loopback_bind:
            raise ValueError(
                f"host {self.host!r} is not loopback; refusing to bind "
                "(set NOZO_RELAY_ALLOW_NON_LOOPBACK_BIND=1 only behind HTTPS)"
            )
        if self.insecure_dev_cookies and not loopback:
            raise ValueError("insecure_dev_cookies is only allowed when bound to loopback")
        if self.allow_opaque_origin and not loopback:
            raise ValueError("allow_opaque_origin is only allowed when bound to loopback")
        if "*" in self.allowed_origins or any("*" in h for h in self.allowed_hosts):
            raise ValueError("wildcard origins/hosts are not allowed")
        if any("*" in u for u in self.mcp_oauth_redirect_uris):
            raise ValueError("wildcard OAuth redirect URIs are not allowed")
        return self

    @property
    def mcp_resource(self) -> str:
        """Canonical MCP resource URL = the OAuth audience (RFC 8707) for tokens bound to this relay."""
        if self.mcp_resource_url:
            return self.mcp_resource_url.rstrip("/")
        host = f"[{self.host.strip('[]')}]" if ":" in self.host else self.host
        return f"http://{host}:{self.port}/mcp"

    @property
    def mcp_oauth_issuer(self) -> str:
        if self.mcp_oauth_issuer_url:
            return self.mcp_oauth_issuer_url.rstrip("/")
        from urllib.parse import urlsplit

        parts = urlsplit(self.mcp_resource)
        return f"{parts.scheme}://{parts.netloc}"

    @property
    def db_path(self) -> Path:
        return (self.sqlite_path or (self.data_dir / "relay.sqlite")).expanduser()

    @property
    def artifacts_dir(self) -> Path:
        return (self.data_dir / "artifacts").expanduser()

    @property
    def runner_state_dir(self) -> Path:
        """Supervisor state (receipts, outbox, disposable workspaces). Never exposed to a child."""
        return (self.data_dir / "runner").expanduser()

    @property
    def cookie_secure(self) -> bool:
        return not self.insecure_dev_cookies

    @property
    def database_url(self) -> str:
        return f"sqlite:///{self.db_path}"

    @property
    def origin_allowlist(self) -> frozenset[str]:
        origins = {f"http://{h}:{self.port}" for h in ("127.0.0.1", "localhost", "[::1]")}
        origins.add(f"http://{self.host}:{self.port}")
        origins.update(o.rstrip("/") for o in self.allowed_origins)
        return frozenset(origins)

    def origin_permitted(self, origin: str) -> bool:
        """Exact allowlist, external public Host as Origin, or CORS gateway suffixes (e.g. github.io)."""
        o = origin.rstrip("/")
        if o in self.origin_allowlist:
            return True
        if not o.startswith("https://"):
            return False
        host = o.removeprefix("https://").split("/", 1)[0].split(":", 1)[0].lower()
        if self.host_is_external_public(host):
            return True
        return self.cors_origin_allowed_host(host)

    def cors_origin_allowed_host(self, host: str) -> bool:
        h = host.strip().lower()
        for suf in self.cors_origin_suffixes:
            s = suf.lower() if suf.startswith(".") else f".{suf.lower()}"
            if h.endswith(s) and len(h) > len(s):
                return True
        return False

    def host_is_external_public(self, host: str) -> bool:
        h = host.strip().lower()
        if h in {x.lower() for x in self.external_public_hosts}:
            return True
        for suf in self.external_public_host_suffixes:
            s = suf.lower() if suf.startswith(".") else f".{suf.lower()}"
            if h.endswith(s) and len(h) > len(s):
                return True
        return False

    @property
    def host_allowlist(self) -> list[str]:
        hosts = {"127.0.0.1", "localhost", "[::1]", "::1", self.host.strip("[]")}
        hosts.update(self.allowed_hosts)
        hosts.update(h.strip().lower() for h in self.external_public_hosts)
        # Starlette TrustedHostMiddleware accepts ``*.example.com`` patterns.
        for suf in self.external_public_host_suffixes:
            s = suf.lstrip(".").lower()
            hosts.add(f"*.{s}")
        return sorted(hosts)
