#!/usr/bin/env python3
"""Set username/password for the chatgpt coordinator principal (browser login).

Writes once to data/clients/chatgpt_coordinator_login.json (0600). Does not print the password.
"""

from __future__ import annotations

import argparse
import json
import secrets
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from nozo_relay.auth.passwords import hash_password  # noqa: E402
from nozo_relay.config import Settings  # noqa: E402
from nozo_relay.db.engine import create_engine_from_settings, write_session  # noqa: E402
from nozo_relay.db.models import Principal  # noqa: E402
from nozo_relay.domain.enums import PrincipalKind  # noqa: E402
from sqlalchemy import select  # noqa: E402

DEFAULT_USERNAME = "chatgpt_coordinator"
COORD_DISPLAY = "chatgpt-coordinator"


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--username", default=DEFAULT_USERNAME)
    p.add_argument("--password", default="", help="If empty, a strong password is generated")
    p.add_argument("--principal-name", default=COORD_DISPLAY, help="display_name match")
    args = p.parse_args()

    settings = Settings()
    password = args.password or ("nzr-" + secrets.token_urlsafe(18))
    digest = hash_password(password)

    with write_session(create_engine_from_settings(settings)) as ws:
        row = ws.execute(
            select(Principal).where(
                Principal.kind == PrincipalKind.COORDINATOR.value,
                Principal.display_name == args.principal_name,
            )
        ).scalar_one_or_none()
        if row is None:
            print(f"coordinator principal {args.principal_name!r} not found", file=sys.stderr)
            return 2
        # username unique among login principals
        clash = ws.execute(
            select(Principal).where(Principal.username == args.username, Principal.id != row.id)
        ).scalar_one_or_none()
        if clash is not None:
            print(f"username {args.username!r} already taken", file=sys.stderr)
            return 2
        row.username = args.username
        row.password_hash = digest
        principal_id = row.id

    out = settings.data_dir / "clients" / "chatgpt_coordinator_login.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "username": args.username,
        "password": password,
        "principal_id": principal_id,
        "display_name": args.principal_name,
        "login_url_local": f"http://127.0.0.1:{settings.port}/login",
        "note": "Coordinator browser session only. Never put this password in JS or URL query strings.",
    }
    out.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    out.chmod(0o600)
    print(f"wrote {out} (0600); username={args.username}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
