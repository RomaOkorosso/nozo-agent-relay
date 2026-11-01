"""Gateway static pointer + Pages assets."""

from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
GW = ROOT / "gateway"


def test_pointer_json_has_https_relay_no_secrets():
    doc = json.loads((GW / "pointer.json").read_text(encoding="utf-8"))
    assert doc["relay_base"].startswith("https://")
    assert "ts.net" in doc["relay_base"] or "github.io" not in doc["relay_base"]
    blob = json.dumps(doc)
    assert "nzr_" not in blob
    assert "password" not in blob.lower()
    assert "sk-" not in blob


def test_gateway_js_has_states_and_pointer_and_msg_idempotency():
    js = (GW / "app.js").read_text(encoding="utf-8")
    for needle in (
        "pointer.json",
        "recovering",
        "STORE_PENDING_MSG",
        "STORE_DRAFT_MSG",
        "classifyFetchFailure",
        "подтверждено сервером",
        "требуется вход",
    ):
        assert needle in js, needle
    html = (GW / "index.html").read_text(encoding="utf-8")
    assert "conn-chip" in html
    assert "viewport-fit=cover" in html
