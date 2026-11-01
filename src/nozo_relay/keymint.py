"""Owner CLI helper: mint an additional API key for a registered non-owner agent (e.g. a coordinator).

``POST /api/v1/agents`` only creates the identity + memberships; keys are never minted over HTTP. This
local, owner-only command closes that gap. The key is written ONCE to a new ``0600`` file (``O_EXCL``)
under ``<data_dir>/minted_keys/`` and is never printed or logged; the database keeps only the digest.
It cannot create or elevate owners: owner principals are refused.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from pathlib import Path

from sqlalchemy import select

from nozo_relay.auth.credentials import issue_credential
from nozo_relay.clock import Clock, SystemClock, ms_to_rfc3339
from nozo_relay.config import Settings
from nozo_relay.db.engine import create_engine_from_settings, write_session
from nozo_relay.db.models import Credential, Principal
from nozo_relay.domain.enums import PrincipalKind
from nozo_relay.services.events import append_event

MINTED_DIR = "minted_keys"


@dataclass(frozen=True)
class MintResult:
    path: Path
    principal_id: str
    credential_id: str
    kind: str


def mint_key(settings: Settings, agent: str, *, clock: Clock | None = None, expires_in_days: int | None = None) -> MintResult:
    """``agent`` is a principal id or an exact display name. Refuses owners and unknown/ambiguous names."""
    clock = clock or SystemClock()
    settings.data_dir.mkdir(parents=True, exist_ok=True)
    out_dir = settings.data_dir / MINTED_DIR
    out_dir.mkdir(mode=0o700, exist_ok=True)
    os.chmod(out_dir, 0o700)
    engine = create_engine_from_settings(settings)
    try:
        # 1) issue the credential and COMMIT (leaving the ``with`` block commits). Nothing touches the disk yet, so a
        #    failing commit can never leave a key file that belongs to a rolled-back credential (T12/F06).
        with write_session(engine) as ws:
            rows = list(ws.execute(select(Principal).where(Principal.id == agent, Principal.active.is_(True))).scalars())
            if not rows:
                rows = list(ws.execute(select(Principal).where(Principal.display_name == agent, Principal.active.is_(True))).scalars())
            if not rows:
                raise ValueError(f"no active agent with id or name {agent!r}")
            if len(rows) > 1:
                raise ValueError(f"name {agent!r} is ambiguous; use the principal id")
            p = rows[0]
            if p.kind == PrincipalKind.OWNER.value:
                raise ValueError("refusing to mint a key for an owner principal")
            expires_at = clock.now_ms() + expires_in_days * 86_400_000 if expires_in_days else None
            key, cred = issue_credential(ws, clock, p.id, expires_at=expires_at)
            principal_id, display_name, kind, credential_id = p.id, p.display_name, p.kind, cred.id
            full_key = key.full_key
            append_event(ws, clock, type="credential.minted", payload={"agent_id": p.id, "credential_id": cred.id, "via": "owner_cli"})
        # 2) the credential is durable: now write the one-time key file. If that fails the credential is revoked
        #    (an unrecoverable key must not stay valid) and no partial file is left behind.
        path = out_dir / f"{principal_id}-{credential_id}.json"
        payload = {
            "principal_id": principal_id, "display_name": display_name, "kind": kind,
            "credential_id": credential_id, "key": full_key,
            "created_at": ms_to_rfc3339(clock.now_ms()),
            "expires_at": ms_to_rfc3339(expires_at) if expires_at else None,
        }
        try:
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            try:
                with os.fdopen(fd, "w", encoding="utf-8") as fh:
                    json.dump(payload, fh, indent=2, sort_keys=True)
                    fh.flush()
                    os.fsync(fh.fileno())
            except BaseException:
                path.unlink(missing_ok=True)
                raise
        except BaseException:
            _revoke_quietly(engine, clock, credential_id)
            raise
        return MintResult(path=path, principal_id=principal_id, credential_id=credential_id, kind=kind)
    finally:
        engine.dispose()


def _revoke_quietly(engine, clock: Clock, credential_id: str) -> None:  # noqa: ANN001
    try:
        with write_session(engine) as ws:
            cred = ws.get(Credential, credential_id)
            if cred is not None and cred.revoked_at is None:
                cred.revoked_at = clock.now_ms()
    except Exception:  # noqa: BLE001 - best effort; the original error is what the caller needs to see
        pass
