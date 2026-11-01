"""One-time login claim tokens (GET redeem) for flaky free tunnels that drop POSTs."""

from __future__ import annotations

import json
import re
import secrets
from dataclasses import dataclass
from pathlib import Path

from nozo_relay.clock import Clock

_TOKEN_RE = re.compile(r"^[A-Za-z0-9_-]{20,64}$")
DEFAULT_TTL_SECONDS = 600


@dataclass(frozen=True)
class ClaimToken:
    token: str
    principal_id: str
    expires_at_ms: int


def claims_dir(data_dir: Path) -> Path:
    d = (data_dir / "clients" / "claims").expanduser()
    d.mkdir(parents=True, exist_ok=True)
    d.chmod(0o700)
    return d


def mint_claim_token(
    data_dir: Path,
    clock: Clock,
    *,
    principal_id: str,
    ttl_seconds: int = DEFAULT_TTL_SECONDS,
) -> ClaimToken:
    token = secrets.token_urlsafe(24)
    expires = clock.now_ms() + max(60, ttl_seconds) * 1000
    path = claims_dir(data_dir) / f"{token}.json"
    path.write_text(
        json.dumps({"principal_id": principal_id, "expires_at_ms": expires}, indent=2) + "\n",
        encoding="utf-8",
    )
    path.chmod(0o600)
    return ClaimToken(token=token, principal_id=principal_id, expires_at_ms=expires)


def consume_claim_token(data_dir: Path, clock: Clock, token: str) -> str | None:
    """Return principal_id if token is valid; delete it (single-use). None if invalid/expired."""
    if not _TOKEN_RE.match(token or ""):
        return None
    path = claims_dir(data_dir) / f"{token}.json"
    if not path.is_file():
        return None
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
        principal_id = str(raw["principal_id"])
        expires_at_ms = int(raw["expires_at_ms"])
    except (OSError, KeyError, TypeError, ValueError, json.JSONDecodeError):
        try:
            path.unlink(missing_ok=True)
        except OSError:
            pass
        return None
    try:
        path.unlink(missing_ok=True)
    except OSError:
        return None
    if clock.now_ms() >= expires_at_ms:
        return None
    return principal_id
