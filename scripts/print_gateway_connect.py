#!/usr/bin/env python3
"""Print GitHub Pages gateway connect hints (Relay URL + where the Bearer key lives)."""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_PUBLIC = Path("/tmp/nozo-public-url.txt")
DEFAULT_CREDS = ROOT / "data" / "clients" / "chatgpt_credentials.json"


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument(
        "--pages-url",
        default=os.environ.get("NOZO_GATEWAY_PAGES_URL", "https://romaokorosso.github.io/nozo-agent-relay/"),
        help="GitHub Pages URL of the gateway (set NOZO_GATEWAY_PAGES_URL)",
    )
    p.add_argument("--public-url-file", type=Path, default=DEFAULT_PUBLIC)
    p.add_argument("--creds", type=Path, default=DEFAULT_CREDS)
    p.add_argument("--print-key", action="store_true", help="Also print the coordinator Bearer key")
    args = p.parse_args()

    relay = ""
    if args.public_url_file.is_file():
        relay = args.public_url_file.read_text(encoding="utf-8").strip()
    pages = args.pages_url.rstrip("/") + "/"
    if relay:
        pages_with_relay = f"{pages}?relay={relay}"
    else:
        pages_with_relay = pages

    print(f"GATEWAY_PAGES={pages}")
    print(f"GATEWAY_OPEN={pages_with_relay}")
    print(f"RELAY_BASE={relay or '(none — start a tunnel; see /tmp/nozo-public-url.txt)'}")
    print(f"BEARER_FILE={args.creds}")
    if args.print_key:
        if not args.creds.is_file():
            print("key missing", file=sys.stderr)
            return 2
        data = json.loads(args.creds.read_text(encoding="utf-8"))
        key = data.get("key")
        if not key:
            print("no key field", file=sys.stderr)
            return 2
        print(f"BEARER_KEY={key}")
    else:
        print("BEARER_KEY=(pass --print-key to show; never commit)")
    print("Paste Relay URL + Bearer into the gateway form (sessionStorage only).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
