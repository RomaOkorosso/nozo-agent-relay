"""GitHub Pages gateway: CORS preflight + coordinator-only Bearer on public Host."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from conftest import OWNER_PASSWORD, Env, make_settings
from nozo_relay.auth.credentials import issue_credential
from nozo_relay.bootstrap import bootstrap, credentials_path
from nozo_relay.clock import FakeClock
from nozo_relay.db.engine import create_engine_from_settings, write_session
from nozo_relay.db.models import Membership, Principal, Project
from nozo_relay.domain.enums import MembershipRole, PrincipalKind
from nozo_relay.main import create_app

GW_ORIGIN = "https://roma.github.io"
PUB = "https://public.example.test"


@pytest.fixture
def gw_env(tmp_path: Path) -> Env:
    clock = FakeClock()
    s = make_settings(
        tmp_path,
        external_public_hosts=["public.example.test"],
        allowed_hosts=["public.example.test"],
        allowed_origins=["https://public.example.test"],
        cors_origin_suffixes=[".github.io"],
    )
    bootstrap(s, owner_password=OWNER_PASSWORD, clock=clock)
    app = create_app(s, clock)
    creds = json.loads(credentials_path(s).read_text())
    with write_session(create_engine_from_settings(s)) as ws:
        project = ws.execute(select(Project)).scalar_one()
        coord = Principal(
            kind=PrincipalKind.COORDINATOR.value,
            display_name="gw-coord",
            username="gw_coord",
            password_hash=None,
            active=True,
            created_at=clock.now_ms(),
        )
        ws.add(coord)
        ws.flush()
        ws.add(
            Membership(
                principal_id=coord.id,
                project_id=project.id,
                role=MembershipRole.COORDINATOR.value,
                scopes_json="[]",
            )
        )
        coord_key, _ = issue_credential(ws, clock, coord.id)
        owner = ws.execute(select(Principal).where(Principal.username == "owner")).scalar_one()
        owner_key, _ = issue_credential(ws, clock, owner.id)
        coord_id = coord.id
    env = Env(settings=s, clock=clock, creds=creds, app=app)
    env.coord_key = coord_key.full_key  # type: ignore[attr-defined]
    env.owner_key = owner_key.full_key  # type: ignore[attr-defined]
    env.coord_id = coord_id  # type: ignore[attr-defined]
    return env


def test_cors_preflight_from_github_io(gw_env: Env):
    with TestClient(gw_env.app, base_url=PUB) as c:
        r = c.options(
            "/api/v1/me",
            headers={
                "Origin": GW_ORIGIN,
                "Access-Control-Request-Method": "GET",
                "Access-Control-Request-Headers": "authorization,content-type",
            },
        )
        assert r.status_code == 204
        assert r.headers["access-control-allow-origin"] == GW_ORIGIN
        assert "authorization" in r.headers["access-control-allow-headers"].lower()
        assert "GET" in r.headers["access-control-allow-methods"]


def test_cors_rejects_unknown_origin(gw_env: Env):
    with TestClient(gw_env.app, base_url=PUB) as c:
        r = c.options(
            "/api/v1/me",
            headers={"Origin": "https://evil.example", "Access-Control-Request-Method": "GET"},
        )
        # Preflight answered locally without reflecting Allow-Origin for evil.
        assert r.status_code == 204
        assert r.headers.get("access-control-allow-origin") is None


def test_bearer_coordinator_ok_owner_denied_on_public_host(gw_env: Env):
    with TestClient(gw_env.app, base_url=PUB) as c:
        ok = c.get(
            "/api/v1/me",
            headers={"Authorization": f"Bearer {gw_env.coord_key}", "Origin": GW_ORIGIN},  # type: ignore[attr-defined]
        )
        assert ok.status_code == 200, ok.text
        assert ok.json()["principal"]["kind"] == "coordinator"
        assert ok.headers.get("access-control-allow-origin") == GW_ORIGIN

        bad = c.get(
            "/api/v1/me",
            headers={"Authorization": f"Bearer {gw_env.owner_key}", "Origin": GW_ORIGIN},  # type: ignore[attr-defined]
        )
        assert bad.status_code == 403, bad.text
        assert bad.json()["error"]["code"] == "forbidden"


def test_gateway_static_files_present():
    root = Path(__file__).resolve().parents[1] / "gateway"
    for name in ("index.html", "app.js", "app.css", "config.example.json", "README.md"):
        assert (root / name).is_file(), name
    html = (root / "index.html").read_text(encoding="utf-8")
    assert "connect-form" in html and "Relay base URL" in html
