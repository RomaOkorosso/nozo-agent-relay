"""Opaque cursors: ``{items, next_cursor}`` lists with limit default 50 / max 200."""

from __future__ import annotations

import base64
import json
from typing import Any

from nozo_relay.api.errors import RelayError

DEFAULT_LIMIT = 50
MAX_LIMIT = 200


def clamp_limit(limit: int | None) -> int:
    if limit is None:
        return DEFAULT_LIMIT
    if limit < 1 or limit > MAX_LIMIT:
        raise RelayError(422, "invalid_limit", f"limit must be between 1 and {MAX_LIMIT}")
    return limit


def encode_cursor(payload: list[Any]) -> str:
    raw = json.dumps(payload, separators=(",", ":")).encode()
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def decode_cursor(cursor: str | None, arity: int) -> list[Any] | None:
    if not cursor:
        return None
    try:
        padded = cursor + "=" * (-len(cursor) % 4)
        value = json.loads(base64.urlsafe_b64decode(padded.encode()))
    except Exception:  # noqa: BLE001 - any malformed cursor is a client error
        raise RelayError(422, "invalid_cursor", "Malformed cursor") from None
    if not isinstance(value, list) or len(value) != arity:
        raise RelayError(422, "invalid_cursor", "Malformed cursor")
    return value
