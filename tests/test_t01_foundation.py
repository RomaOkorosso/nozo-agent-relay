"""T01 foundation + auth tests (Q20/Q21/Q22 slices, schema, bind)."""

from __future__ import annotations

import stat
import uuid
from pathlib import Path

import pytest
from conftest import BASE_URL, OWNER_PASSWORD, Env, login, make_settings
from fastapi.testclient import TestClient
from sqlalchemy import select, text
from sqlalchemy.exc import DatabaseError, IntegrityError

from nozo_relay.auth.credentials import revoke_credential
from nozo_relay.auth.keys import generate_key, parse_key, verify_secret
from nozo_relay.auth.passwords import hash_password, verify_password
from nozo_relay.clock import FakeClock, SystemClock
from nozo_relay.config import Settings, SettingsError
from nozo_relay.db.engine import create_sqlite_engine, make_session_factory, pragma_value
from nozo_relay.db.models import Base, Credential, Event, Job, M0_TABLES, Principal, Project
from nozo_relay.db.schema import SCHEMA_VERSION, SchemaError, ensure_schema, read_schema_version
from nozo_relay.main import bind_address, create_app

M0_REQUIRED = {
    "principals", "credentials", "sessions", "projects", "memberships", "tasks", "task_revisions",
    "jobs", "runs", "snapshots", "reports", "findings", "messages", "events", "idempotency",
    "controls", "artifacts", "capabilities", "repo_bindings", "delegations", "approval_requests",
}  # fmt: skip


# ----------------------------------------------------------------------------- schema / DB


def test_migrate_empty_db_creates_m0_schema_and_is_idempotent(tmp_path: Path):
    engine = create_sqlite_engine(tmp_path / "x" / "relay.sqlite")
    clock = FakeClock()
    assert read_schema_version(engine) is None
    assert ensure_schema(engine, clock) == SCHEMA_VERSION
    from sqlalchemy import inspect

    tables = set(inspect(engine).get_table_names())
    assert M0_REQUIRED <= tables and "schema_version" in tables
    assert M0_REQUIRED == set(M0_TABLES)
    assert read_schema_version(engine) == SCHEMA_VERSION
    # second run: no-op, no error
    assert ensure_schema(engine, clock) == SCHEMA_VERSION
    engine.dispose()


def test_sqlite_pragmas(tmp_path: Path):
    engine = create_sqlite_engine(tmp_path / "relay.sqlite")
    ensure_schema(engine)
    assert str(pragma_value(engine, "journal_mode")).lower() == "wal"
    assert pragma_value(engine, "synchronous") == 2  # FULL
    assert pragma_value(engine, "foreign_keys") == 1
    assert pragma_value(engine, "busy_timeout") == 5000
    engine.dispose()


def test_incompatible_schema_version_rejected(tmp_path: Path):
    engine = create_sqlite_engine(tmp_path / "relay.sqlite")
    ensure_schema(engine)
    with engine.begin() as c:
        c.execute(text("UPDATE schema_version SET version = 999"))
    with pytest.raises(SchemaError, match="incompatible schema version"):
        ensure_schema(engine)
    engine.dispose()


def test_foreign_database_without_version_rejected(tmp_path: Path):
    engine = create_sqlite_engine(tmp_path / "relay.sqlite")
    with engine.begin() as c:
        c.execute(text("CREATE TABLE something_else (id INTEGER PRIMARY KEY)"))
    with pytest.raises(SchemaError, match="no schema_version"):
        ensure_schema(engine)
    engine.dispose()


def test_app_startup_refuses_incompatible_schema(env: Env):
    from nozo_relay.db.engine import create_engine_from_settings

    engine = create_engine_from_settings(env.settings)
    with engine.begin() as c:
        c.execute(text("UPDATE schema_version SET version = 0"))
    engine.dispose()
    with pytest.raises(SchemaError):
        create_app(env.settings, env.clock)


def test_foreign_keys_enforced_and_project_isolation(tmp_path: Path):
    engine = create_sqlite_engine(tmp_path / "relay.sqlite")
    ensure_schema(engine)
    factory = make_session_factory(engine)
    with factory() as db:
        db.add(
            Job(
                task_id=str(uuid.uuid4()), project_id=str(uuid.uuid4()), revision=1, stage="implement",
                sequence=1, assignee_id=str(uuid.uuid4()), ready_at=1, created_at=1,
            )  # fmt: skip
        )
        with pytest.raises(IntegrityError):
            db.commit()
    engine.dispose()


def test_events_are_append_only(tmp_path: Path):
    engine = create_sqlite_engine(tmp_path / "relay.sqlite")
    ensure_schema(engine)
    factory = make_session_factory(engine)
    with factory() as db:
        db.add(
            Event(type="t", correlation_id=str(uuid.uuid4()), payload_json="{}", created_at=1)
        )
        db.commit()
        with pytest.raises(DatabaseError, match="append-only"):
            db.execute(text("UPDATE events SET type = 'x'"))
        db.rollback()
        with pytest.raises(DatabaseError, match="append-only"):
            db.execute(text("DELETE FROM events"))
    engine.dispose()


def test_enum_check_constraint_rejects_unknown_value(tmp_path: Path):
    engine = create_sqlite_engine(tmp_path / "relay.sqlite")
    ensure_schema(engine)
    factory = make_session_factory(engine)
    with factory() as db:
        db.add(Principal(display_name="x", kind="root", active=True, created_at=1))
        with pytest.raises(IntegrityError):
            db.commit()
    engine.dispose()


# ----------------------------------------------------------------------------- crypto primitives


def test_argon2id_hash_and_verify():
    h = hash_password("a long enough password")
    assert h.startswith("$argon2id$")
    assert verify_password(h, "a long enough password")
    assert not verify_password(h, "wrong password!!")
    assert not verify_password(None, "anything at all")
    with pytest.raises(ValueError):
        hash_password("short")


def test_key_generation_digest_and_constant_time_verify():
    k = generate_key()
    assert len(k.secret) >= 43  # >= 32 random bytes, urlsafe-encoded
    assert k.full_key.startswith(f"nzr_{k.prefix}.")
    assert parse_key(k.full_key) == (k.prefix, k.secret)
    assert parse_key("garbage") is None
    assert parse_key(f"nzr_{k.prefix}.short") is None
    assert k.secret not in repr(k)
    assert verify_secret(k.secret, k.digest)
    assert not verify_secret(k.secret + "x", k.digest)
    assert generate_key().secret != k.secret


def test_fake_clock_and_system_clock():
    c = FakeClock(1000)
    c.advance(seconds=2)
    assert c.now_ms() == 3000
    assert SystemClock().now_ms() > 1_700_000_000_000


# ----------------------------------------------------------------------------- auth: login/logout


def test_login_wrong_password_uniform_error(client: TestClient):
    r = login(client, "wrong password here")
    assert r.status_code == 401
    err = r.json()["error"]
    assert set(err) == {"code", "message", "request_id", "retryable", "details"}
    assert err["code"] == "invalid_credentials"
    assert err["request_id"] == r.headers["X-Request-Id"]
    # unknown user looks identical
    r2 = login(client, OWNER_PASSWORD, username="nobody")
    assert r2.status_code == 401 and r2.json()["error"]["code"] == "invalid_credentials"
    assert "set-cookie" not in r.headers


def test_login_me_logout_flow(client: TestClient, env: Env):
    assert client.get("/api/v1/me").status_code == 401

    r = login(client)
    assert r.status_code == 200
    body = r.json()
    assert body["principal"]["kind"] == "owner" and body["principal"]["authority_tier"] == "P0"
    csrf = body["csrf_token"]

    cookie_hdrs = [v for k, v in r.headers.multi_items() if k == "set-cookie"]
    session_cookie = next(c for c in cookie_hdrs if c.startswith(env.settings.session_cookie_name))
    assert "HttpOnly" in session_cookie and "SameSite=lax" in session_cookie.replace("Lax", "lax")
    assert "Secure" not in session_cookie  # insecure dev profile on loopback only

    me = client.get("/api/v1/me")
    assert me.status_code == 200
    assert me.json()["principal"]["id"] == env.creds["owner"]["principal_id"]
    assert me.json()["auth_method"] == "session"
    assert me.json()["memberships"][0]["role"] == "owner"

    # mutation without CSRF is rejected and does not revoke the session
    r = client.post("/api/v1/auth/logout")
    assert r.status_code == 403 and r.json()["error"]["code"] == "csrf_failed"
    r = client.post("/api/v1/auth/logout", headers={env.settings.csrf_header_name: "wrong"})
    assert r.status_code == 403
    assert client.get("/api/v1/me").status_code == 200

    # cross-origin mutation is rejected even with a valid token
    r = client.post(
        "/api/v1/auth/logout",
        headers={env.settings.csrf_header_name: csrf, "Origin": "https://evil.example"},
    )
    assert r.status_code == 403 and r.json()["error"]["code"] == "origin_not_allowed"

    r = client.post("/api/v1/auth/logout", headers={env.settings.csrf_header_name: csrf})
    assert r.status_code == 200
    assert client.get("/api/v1/me").status_code == 401


def test_revoked_session_cookie_cannot_be_replayed(client: TestClient, env: Env):
    r = login(client)
    csrf = r.json()["csrf_token"]
    stolen = client.cookies.get(env.settings.session_cookie_name)
    client.post("/api/v1/auth/logout", headers={env.settings.csrf_header_name: csrf})
    with env.client() as other:
        other.cookies.set(env.settings.session_cookie_name, stolen)
        assert other.get("/api/v1/me").status_code == 401


def test_session_idle_and_absolute_expiry(client: TestClient, env: Env):
    login(client)
    env.clock.advance(seconds=29 * 60)
    assert client.get("/api/v1/me").status_code == 200  # activity extends idle window
    env.clock.advance(seconds=29 * 60)
    assert client.get("/api/v1/me").status_code == 200
    env.clock.advance(seconds=31 * 60)  # idle > 30 min
    assert client.get("/api/v1/me").status_code == 401

    login(client)
    for _ in range(25):  # keep active, but absolute limit (12h) must still cut it off
        env.clock.advance(seconds=29 * 60)
        if client.get("/api/v1/me").status_code != 200:
            break
    else:
        pytest.fail("session outlived absolute expiry")
    assert client.get("/api/v1/me").status_code == 401


def test_login_rate_limit(client: TestClient, env: Env):
    for _ in range(env.settings.login_max_failures):
        assert login(client, "bad password value").status_code == 401
    r = login(client, OWNER_PASSWORD)  # even the right password is throttled
    assert r.status_code == 429 and r.headers["Retry-After"]
    assert r.json()["error"]["retryable"] is True
    env.clock.advance(seconds=env.settings.login_lockout_seconds + 1)
    assert login(client, OWNER_PASSWORD).status_code == 200


def test_login_rejects_unknown_fields_and_foreign_origin(client: TestClient):
    r = client.post("/api/v1/auth/login", json={"username": "owner", "password": "x", "role": "owner"})
    assert r.status_code == 422 and r.json()["error"]["code"] == "validation_error"
    r = client.post(
        "/api/v1/auth/login",
        json={"username": "owner", "password": OWNER_PASSWORD},
        headers={"Origin": "https://evil.example"},
    )
    assert r.status_code == 403


# ----------------------------------------------------------------------------- auth: agent keys


def _agent_key(env: Env, name: str) -> dict:
    return next(a for a in env.creds["agents"] if a["name"] == name)


def test_two_agents_have_distinct_scoped_keys(client: TestClient, env: Env):
    impl, aud = _agent_key(env, "test-implementer"), _agent_key(env, "test-auditor")
    assert impl["key"] != aud["key"] and impl["principal_id"] != aud["principal_id"]

    for agent, kind in ((impl, "implementer"), (aud, "auditor")):
        r = client.get("/api/v1/me", headers={"Authorization": f"Bearer {agent['key']}"})
        assert r.status_code == 200
        p = r.json()["principal"]
        assert p["id"] == agent["principal_id"] and p["kind"] == kind and p["authority_tier"] == "P2"
        assert r.json()["memberships"][0]["role"] == kind
    assert client.cookies.get(env.settings.session_cookie_name) is None


def test_agent_key_rejections(client: TestClient, env: Env):
    key = _agent_key(env, "test-implementer")["key"]
    assert client.get("/api/v1/me", headers={"Authorization": "Bearer nzr_bad"}).status_code == 401
    assert client.get("/api/v1/me", headers={"Authorization": f"Basic {key}"}).status_code == 401
    tampered = key[:-1] + ("A" if key[-1] != "A" else "B")
    r = client.get("/api/v1/me", headers={"Authorization": f"Bearer {tampered}"})
    assert r.status_code == 401 and "WWW-Authenticate" in r.headers
    # credentials in the query string are never accepted
    assert client.get("/api/v1/me", params={"key": key, "access_token": key}).status_code == 401
    # agent keys cannot use the browser-only logout
    r = client.post("/api/v1/auth/logout", headers={"Authorization": f"Bearer {key}"})
    assert r.status_code == 403 and r.json()["error"]["code"] == "session_required"


def test_credential_revoke_takes_effect_immediately(client: TestClient, env: Env):
    agent = _agent_key(env, "test-auditor")
    h = {"Authorization": f"Bearer {agent['key']}"}
    assert client.get("/api/v1/me", headers=h).status_code == 200
    factory = env.app.state.session_factory  # type: ignore[attr-defined]
    with factory() as db:
        assert revoke_credential(db, env.clock, agent["credential_id"])
        assert not revoke_credential(db, env.clock, agent["credential_id"])
        db.commit()
    assert client.get("/api/v1/me", headers=h).status_code == 401


def test_deactivated_principal_loses_access(client: TestClient, env: Env):
    agent = _agent_key(env, "test-implementer")
    factory = env.app.state.session_factory  # type: ignore[attr-defined]
    with factory() as db:
        db.get(Principal, agent["principal_id"]).active = False
        db.commit()
    r = client.get("/api/v1/me", headers={"Authorization": f"Bearer {agent['key']}"})
    assert r.status_code == 401


# ----------------------------------------------------------------------------- secrets at rest


def test_no_plaintext_secret_in_db(client: TestClient, env: Env):
    r = login(client)
    csrf = r.json()["csrf_token"]
    session_id = client.cookies.get(env.settings.session_cookie_name)
    keys = [a["key"] for a in env.creds["agents"]] + [env.creds["runner"]["key"]]
    secrets_ = [OWNER_PASSWORD, csrf, session_id, *keys, *(parse_key(k)[1] for k in keys)]  # type: ignore[index]
    assert all(secrets_)

    env.app.state.engine.dispose()  # type: ignore[attr-defined]  # checkpoint WAL on close
    db_files = [p for p in env.settings.data_dir.iterdir() if p.name.startswith("relay.sqlite")]
    assert db_files
    for f in db_files:
        blob = f.read_bytes()
        for s in secrets_:
            assert s.encode() not in blob, f"plaintext secret found in {f.name}"

    # what *is* stored: digests / hashes
    import sqlite3

    con = sqlite3.connect(env.settings.db_path)
    try:
        (pw_hash,) = con.execute("SELECT password_hash FROM principals WHERE kind='owner'").fetchone()
        assert pw_hash.startswith("$argon2id$")
        digests = [d for (d,) in con.execute("SELECT secret_digest FROM credentials")]
        assert len(digests) == 3 and all(len(d) == 64 for d in digests)
        (sid,) = con.execute("SELECT id_digest FROM sessions").fetchone()
        assert len(sid) == 64 and sid != session_id
    finally:
        con.close()


def test_bootstrap_credentials_written_once_private_and_gitignored(env: Env):
    from nozo_relay.bootstrap import BootstrapError, bootstrap, credentials_path

    path = credentials_path(env.settings)
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert stat.S_IMODE(env.settings.data_dir.stat().st_mode) == 0o700
    assert env.creds["owner"]["password"] is None  # operator-supplied password is not echoed
    assert len(env.creds["agents"]) == 2
    with pytest.raises(BootstrapError):
        bootstrap(env.settings, owner_password=OWNER_PASSWORD, clock=env.clock)

    root = Path(__file__).resolve().parents[1]
    ignore = (root / ".gitignore").read_text().splitlines()
    for pattern in ("bootstrap_credentials.json", "data/", "*.sqlite*", ".env", ".venv", "workspaces/"):
        assert pattern in ignore


def test_bootstrap_default_project_and_memberships(env: Env):
    factory = env.app.state.session_factory  # type: ignore[attr-defined]
    with factory() as db:
        proj = db.execute(select(Project)).scalar_one()
        assert proj.slug == "default" and proj.id == env.creds["project"]["id"]
        roles = dict(
            db.execute(text("SELECT p.display_name, m.role FROM memberships m JOIN principals p "
                            "ON p.id = m.principal_id")).all()
        )  # fmt: skip
        assert roles == {
            "Owner": "owner", "test-implementer": "implementer", "test-auditor": "auditor",
            "default-supervisor": "runner",  # T12/F02: default supervisor identity bound to runs at claim
        }
        assert db.execute(select(Credential)).all().__len__() == 3


def test_generated_owner_password_is_written_to_file_only(tmp_path: Path, capsys):
    from nozo_relay.bootstrap import bootstrap, credentials_path
    import json

    s = make_settings(tmp_path)
    bootstrap(s)
    data = json.loads(credentials_path(s).read_text())
    assert len(data["owner"]["password"]) >= 20
    out = capsys.readouterr()
    assert data["owner"]["password"] not in out.out + out.err


# ----------------------------------------------------------------------------- health


def test_health_live_and_ready(client: TestClient):
    live = client.get("/api/v1/health/live")
    assert live.status_code == 200 and live.json() == {"status": "live"}
    ready = client.get("/api/v1/health/ready")
    assert ready.status_code == 200
    assert ready.json() == {"status": "ready", "db": "ok", "schema_version": SCHEMA_VERSION}


def test_health_ready_503_when_schema_incompatible(client: TestClient, env: Env):
    with env.app.state.engine.begin() as c:  # type: ignore[attr-defined]
        c.execute(text("UPDATE schema_version SET version = 42"))
    r = client.get("/api/v1/health/ready")
    assert r.status_code == 503
    assert r.json()["error"]["code"] == "not_ready"
    assert client.get("/api/v1/health/live").status_code == 200


def test_security_headers_and_no_openapi_surface(client: TestClient):
    r = client.get("/api/v1/health/live")
    assert "frame-ancestors 'none'" in r.headers["Content-Security-Policy"]
    assert r.headers["X-Content-Type-Options"] == "nosniff"
    assert "access-control-allow-origin" not in r.headers
    for path in ("/docs", "/openapi.json", "/redoc"):
        assert client.get(path).status_code == 404


def test_unknown_route_uses_error_shape_and_oversize_body_rejected(client: TestClient):
    r = client.get("/api/v1/nope")
    assert r.status_code == 404 and r.json()["error"]["code"] == "not_found"
    r = client.post("/api/v1/auth/login", content=b"x" * (256 * 1024 + 1))
    assert r.status_code == 413 and r.json()["error"]["code"] == "payload_too_large"


def test_unexpected_host_header_rejected(env: Env):
    with TestClient(env.app, base_url="http://evil.example") as c:  # type: ignore[arg-type]
        assert c.get("/api/v1/health/live").status_code == 400


# ----------------------------------------------------------------------------- bind / settings


def test_default_bind_is_loopback_8765(tmp_path: Path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    s = Settings(_env_file=None)
    assert (s.host, s.port) == ("127.0.0.1", 8765)
    assert bind_address(s) == ("127.0.0.1", 8765)
    assert s.session_idle_seconds == 1800 and s.session_absolute_seconds == 43200
    assert s.cookie_secure is True  # secure by default
    assert s.db_path == s.data_dir / "relay.sqlite"
    assert BASE_URL.startswith("http://127.0.0.1:8765")


@pytest.mark.parametrize("host", ["0.0.0.0", "192.168.1.5", "::", "example.com"])
def test_non_loopback_bind_refused(host: str):
    with pytest.raises(ValueError, match="not loopback"):
        Settings(_env_file=None, host=host)


def test_insecure_cookies_never_with_remote_bind():
    with pytest.raises(ValueError, match="loopback"):
        Settings(_env_file=None, host="0.0.0.0", allow_non_loopback_bind=True, insecure_dev_cookies=True)
    ok = Settings(_env_file=None, host="0.0.0.0", allow_non_loopback_bind=True)
    assert ok.cookie_secure is True


def test_insecure_cookie_flag_defaults_off_and_secure_cookie_set(tmp_path: Path):
    s = Settings(_env_file=None, data_dir=tmp_path / "d")
    assert s.insecure_dev_cookies is False
    bootstrap_settings = make_settings(tmp_path / "b", insecure_dev_cookies=False)
    from nozo_relay.bootstrap import bootstrap

    bootstrap(bootstrap_settings, owner_password=OWNER_PASSWORD)
    with TestClient(create_app(bootstrap_settings), base_url="https://127.0.0.1:8765") as c:
        r = login(c)
        assert r.status_code == 200
        cookie = next(v for k, v in r.headers.multi_items() if k == "set-cookie")
        assert "Secure" in cookie and "HttpOnly" in cookie


def test_wildcard_origins_rejected():
    with pytest.raises(ValueError):
        Settings(_env_file=None, allowed_origins=["*"])


def test_session_timeouts_must_be_consistent():
    with pytest.raises(ValueError):
        Settings(_env_file=None, session_idle_seconds=100, session_absolute_seconds=50)


def test_settings_error_exported():
    assert issubclass(SettingsError, ValueError)
    assert Base.metadata.tables  # models importable
