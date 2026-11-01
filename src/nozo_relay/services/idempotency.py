"""Idempotency: lookup/store in the SAME transaction as the mutation (06_EXECUTION_PROTOCOL).

Scope = principal + operation + key. The digest covers canonical body, resource ids and semantic
guard fields, never tokens. Same key + same digest -> the stored response/status; same key +
different digest -> 409 ``idempotency_conflict``. Authentication/ACL are enforced by the caller
*before* ``replay()``, so a revoked principal can never read a cached answer.
"""

from __future__ import annotations

import json
import uuid
from dataclasses import dataclass
from typing import Any

from sqlalchemy.orm import Session

from nozo_relay.api.errors import RelayError
from nozo_relay.clock import Clock
from nozo_relay.db.models import Idempotency
from nozo_relay.domain.fingerprints import digest_of


@dataclass(frozen=True)
class Replay:
    status: int
    body: dict[str, Any]
    replayed: bool = False


def parse_key(raw: str | None) -> str:
    if raw is None or not raw.strip():
        raise RelayError(428, "idempotency_key_required", "Idempotency-Key header is required")
    try:
        parsed = uuid.UUID(raw.strip())
    except ValueError:
        raise RelayError(422, "invalid_idempotency_key", "Idempotency-Key must be a UUID") from None
    return str(parsed)


def request_digest(
    operation: str,
    *,
    ids: dict[str, Any] | None = None,
    body: Any = None,
    guards: dict[str, Any] | None = None,
) -> str:
    return digest_of({"op": operation, "ids": ids or {}, "body": body, "guards": guards or {}})


class Idempotent:
    """One idempotent mutation attempt bound to the caller's open write transaction."""

    def __init__(
        self,
        ws: Session,
        clock: Clock,
        principal_id: str,
        operation: str,
        key: str,
        digest: str,
    ) -> None:
        self.ws = ws
        self.clock = clock
        self.principal_id = principal_id
        self.operation = operation
        self.key = key
        self.digest = digest

    def replay(self) -> Replay | None:
        row = self.ws.get(Idempotency, (self.principal_id, self.operation, self.key))
        if row is None:
            return None
        if row.request_digest != self.digest:
            raise RelayError(
                409,
                "idempotency_conflict",
                "Idempotency-Key was already used with a different request",
            )
        return Replay(row.response_status, json.loads(row.response_json), replayed=True)

    def finish(self, status: int, body: dict[str, Any]) -> Replay:
        self.store(self.operation, self.key, self.digest, status, body)
        return Replay(status, body)

    def store(self, operation: str, key: str, digest: str, status: int, body: dict[str, Any]) -> None:
        self.ws.add(
            Idempotency(
                principal_id=self.principal_id,
                operation=operation,
                key=key,
                request_digest=digest,
                response_status=status,
                response_json=json.dumps(body, sort_keys=True, separators=(",", ":")),
                created_at=self.clock.now_ms(),
            )
        )
        self.ws.flush()
