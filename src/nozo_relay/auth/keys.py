"""Relay agent keys: ``nzr_<prefix>.<secret>``.

The prefix is a public lookup id (stored plaintext, UNIQUE). The secret is >= 32 CSPRNG bytes;
only its SHA-256 digest is stored (the secret is high-entropy, so a fast hash is appropriate).
"""

from __future__ import annotations

import hashlib
import hmac
import re
import secrets
from dataclasses import dataclass

KEY_SCHEME = "nzr"
SECRET_BYTES = 32
PREFIX_BYTES = 8

_KEY_RE = re.compile(rf"^{KEY_SCHEME}_([0-9a-f]{{{PREFIX_BYTES * 2}}})\.([A-Za-z0-9_-]{{43,128}})$")


@dataclass(frozen=True)
class GeneratedKey:
    prefix: str
    secret: str
    digest: str

    @property
    def full_key(self) -> str:
        """Shown to the owner exactly once; never persisted."""
        return f"{KEY_SCHEME}_{self.prefix}.{self.secret}"

    def __repr__(self) -> str:  # never leak the secret via logs/tracebacks
        return f"GeneratedKey(prefix={self.prefix!r}, secret=<redacted>)"


def digest_secret(secret: str) -> str:
    return hashlib.sha256(secret.encode("utf-8")).hexdigest()


def generate_key() -> GeneratedKey:
    prefix = secrets.token_hex(PREFIX_BYTES)
    secret = secrets.token_urlsafe(SECRET_BYTES)
    return GeneratedKey(prefix=prefix, secret=secret, digest=digest_secret(secret))


def parse_key(raw: str) -> tuple[str, str] | None:
    """Split a presented key into (prefix, secret); None if malformed."""
    m = _KEY_RE.match(raw.strip())
    if not m:
        return None
    return m.group(1), m.group(2)


def verify_secret(secret: str, stored_digest: str) -> bool:
    return hmac.compare_digest(digest_secret(secret), stored_digest)


# Used to keep timing uniform when the prefix is unknown.
DUMMY_DIGEST = digest_secret("nozo-relay-dummy-key-secret")


def constant_time_equal(a: str, b: str) -> bool:
    return hmac.compare_digest(a.encode("utf-8"), b.encode("utf-8"))
