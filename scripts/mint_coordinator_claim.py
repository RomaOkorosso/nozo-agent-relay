#!/usr/bin/env python3
"""Mint a one-time GET claim URL for chatgpt_coordinator (free tunnels often drop POST /login)."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from nozo_relay.auth.claim_tokens import DEFAULT_TTL_SECONDS, mint_claim_token  # noqa: E402
from nozo_relay.clock import SystemClock  # noqa: E402
from nozo_relay.config import Settings  # noqa: E402
from nozo_relay.db.engine import create_engine_from_settings, write_session  # noqa: E402
from nozo_relay.db.models import Principal  # noqa: E402
from nozo_relay.domain.enums import PrincipalKind  # noqa: E402
from sqlalchemy import select  # noqa: E402


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--username", default="chatgpt_coordinator")
    p.add_argument("--ttl", type=int, default=DEFAULT_TTL_SECONDS)
    p.add_argument("--public-url-file", default="/tmp/nozo-public-url.txt")
    args = p.parse_args()

    settings = Settings()
    clock = SystemClock()
    with write_session(create_engine_from_settings(settings)) as ws:
        row = ws.execute(
            select(Principal).where(
                Principal.username == args.username,
                Principal.kind == PrincipalKind.COORDINATOR.value,
                Principal.active.is_(True),
            )
        ).scalar_one_or_none()
        if row is None:
            print(f"active coordinator {args.username!r} not found", file=sys.stderr)
            return 2
        principal_id = row.id

    claim = mint_claim_token(settings.data_dir, clock, principal_id=principal_id, ttl_seconds=args.ttl)
    base = ""
    url_file = Path(args.public_url_file)
    if url_file.is_file():
        base = url_file.read_text(encoding="utf-8").strip().rstrip("/")
    if not base:
        base = f"http://127.0.0.1:{settings.port}"
    claim_url = f"{base}/login/claim/{claim.token}"
    out = settings.data_dir / "clients" / "chatgpt_coordinator_claim.json"
    out.write_text(
        json.dumps(
            {
                "claim_url": claim_url,
                "expires_at_ms": claim.expires_at_ms,
                "ttl_seconds": args.ttl,
                "username": args.username,
                "note": "Single-use GET. Do not reuse. Prefer this over password form on free tunnels.",
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    out.chmod(0o600)
    print(claim_url)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
