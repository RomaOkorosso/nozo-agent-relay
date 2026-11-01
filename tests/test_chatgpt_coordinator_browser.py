"""Coordinator browser login + chat post + public-surface gates (no Funnel required)."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from conftest import OWNER_PASSWORD, Env, login, make_settings
from nozo_relay.api.schemas import DelegationCreate, ScopeCeiling
from nozo_relay.auth.context import PrincipalContext
from nozo_relay.auth.passwords import hash_password
from nozo_relay.bootstrap import bootstrap, credentials_path
from nozo_relay.clock import FakeClock
from nozo_relay.db.engine import create_engine_from_settings, write_session
from nozo_relay.db.models import Membership, Principal, Project
from nozo_relay.domain.enums import MembershipRole, PrincipalKind
from nozo_relay.main import create_app
from nozo_relay.services import projects as projects_svc

COORD_USER = "chatgpt_coordinator"
COORD_PASS = "coord horse battery staple test"


@pytest.fixture
def coord_env(tmp_path: Path) -> Env:
    clock = FakeClock()
    s = make_settings(
        tmp_path,
        external_public_hosts=["public.example.test"],
        allowed_hosts=["public.example.test"],
        allowed_origins=["https://public.example.test", "http://127.0.0.1:8765"],
    )
    bootstrap(s, owner_password=OWNER_PASSWORD, clock=clock)
    app = create_app(s, clock)
    creds = json.loads(credentials_path(s).read_text())
    with write_session(create_engine_from_settings(s)) as ws:
        owner = ws.execute(select(Principal).where(Principal.username == "owner")).scalar_one()
        project = ws.execute(select(Project)).scalar_one()
        coord = Principal(
            kind=PrincipalKind.COORDINATOR.value,
            display_name="chatgpt-coordinator",
            username=COORD_USER,
            password_hash=hash_password(COORD_PASS),
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
        ws.flush()
        owner_ctx = PrincipalContext(
            id=owner.id,
            kind=PrincipalKind.OWNER,
            display_name="Owner",
            project_roles={project.id: "owner"},
            auth_method="session",
        )
        dto = DelegationCreate(
            coordinator_id=coord.id,
            allowed_actions=["task.create", "task.enqueue", "task.control"],
            scope_ceiling=ScopeCeiling(
                allowed_paths=["web/**", "docs/**", "tests/**"],
                max_changed_files=50,
                max_diff_lines=2000,
                allow_new_dependencies=False,
                allow_autonomous=True,
            ),
            valid_until=datetime.fromtimestamp((clock.now_ms() / 1000) + 86400 * 30, tz=UTC),
        )
        projects_svc.create_delegation(ws, clock, owner_ctx, project, dto)
        coord_id, project_id = coord.id, project.id
    env = Env(settings=s, clock=clock, creds=creds, app=app)
    env.coord_id = coord_id  # type: ignore[attr-defined]
    env.project_id = project_id  # type: ignore[attr-defined]
    return env


def test_coordinator_html_form_login_on_public_host(coord_env: Env):
    """Classic POST /login must work on external Host (ChatGPT remote browser path)."""
    app = coord_env.app
    pub_origin = "https://public.example.test"
    with TestClient(app, base_url=pub_origin) as pub:
        page = pub.get("/login")
        assert page.status_code == 200 and 'method="post"' in page.text and 'action="/login"' in page.text
        bad = pub.post("/login", data={"username": COORD_USER, "password": "wrong password value"}, follow_redirects=False)
        assert bad.status_code == 401 and "Неверный логин или пароль" in bad.text
        ok = pub.post(
            "/login",
            data={"username": COORD_USER, "password": COORD_PASS},
            follow_redirects=False,
        )
        assert ok.status_code == 303 and ok.headers["location"] == "/projects"
        assert "nozo_session" in ok.cookies


def test_coordinator_claim_token_get_login(coord_env: Env):
    """One-time GET claim bypasses flaky tunnel POSTs."""
    from nozo_relay.auth.claim_tokens import mint_claim_token

    app = coord_env.app
    coord_id = coord_env.coord_id  # type: ignore[attr-defined]
    claim = mint_claim_token(coord_env.settings.data_dir, coord_env.clock, principal_id=coord_id, ttl_seconds=120)
    pub_origin = "https://public.example.test"
    with TestClient(app, base_url=pub_origin) as pub:
        dead = pub.get("/login/claim/not-a-real-token-value-xxxxx", follow_redirects=False)
        assert dead.status_code == 401
        ok = pub.get(f"/login/claim/{claim.token}", follow_redirects=False)
        assert ok.status_code == 303 and ok.headers["location"] == "/projects"
        assert "nozo_session" in ok.cookies
        # single-use
        again = pub.get(f"/login/claim/{claim.token}", follow_redirects=False)
        assert again.status_code == 401


def test_coordinator_login_chat_and_owner_denied_on_public_host(coord_env: Env):
    app = coord_env.app
    project_id = coord_env.project_id  # type: ignore[attr-defined]
    origin = "http://127.0.0.1:8765"

    with TestClient(app, base_url=origin) as c:
        r = login(c, password=COORD_PASS, username=COORD_USER)
        assert r.status_code == 200, r.text
        assert r.json()["principal"]["kind"] == "coordinator"
        assert "nozo_session" in c.cookies

        me = c.get("/api/v1/me")
        assert me.status_code == 200
        assert me.json()["principal"]["kind"] == "coordinator"

        assert c.get(f"/api/v1/projects/{project_id}/delegations").status_code == 403

        page = c.get(f"/projects/{project_id}")
        assert page.status_code == 200
        assert 'data-kind="message"' in page.text

        msg = c.post(
            f"/api/v1/projects/{project_id}/messages",
            json={
                "client_message_id": "00000000-0000-4000-8000-000000000001",
                "kind": "note",
                "body": "hello from coordinator browser",
            },
            headers={
                "X-CSRF-Token": r.json()["csrf_token"],
                "Origin": origin,
                "Idempotency-Key": "11111111-1111-4111-8111-111111111111",
            },
        )
        assert msg.status_code in (200, 201), msg.text

    pub_origin = "https://public.example.test"
    with TestClient(app, base_url=pub_origin) as pub:
        bad = pub.post("/api/v1/auth/login", json={"username": "owner", "password": OWNER_PASSWORD})
        assert bad.status_code == 403

        ok = pub.post("/api/v1/auth/login", json={"username": COORD_USER, "password": COORD_PASS})
        assert ok.status_code == 200, ok.text

        assert pub.get("/mcp").status_code == 404
        assert pub.get("/api/v1/agents").status_code == 404
        assert pub.get("/login").status_code == 200

        # Same Host via Tailscale Serve (identity header) → full surface, owner login OK
        owner_ok = pub.post(
            "/api/v1/auth/login",
            json={"username": "owner", "password": OWNER_PASSWORD},
            headers={"Tailscale-User-Login": "roma@example.com"},
        )
        assert owner_ok.status_code == 200, owner_ok.text
        assert pub.get("/api/v1/agents", headers={"Tailscale-User-Login": "roma@example.com"}).status_code != 404
