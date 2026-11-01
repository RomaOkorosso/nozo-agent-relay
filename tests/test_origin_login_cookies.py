"""Loopback Origin login + per-request Secure cookie flag."""

from __future__ import annotations

from fastapi.testclient import TestClient

from conftest import OWNER_PASSWORD, Env


def test_html_login_accepts_loopback_origin(env: Env):
    with TestClient(env.app, base_url="http://127.0.0.1:8765") as c:
        r = c.post(
            "/login",
            data={"username": "owner", "password": OWNER_PASSWORD},
            headers={"Origin": "http://127.0.0.1:8765"},
            follow_redirects=False,
        )
        assert r.status_code == 303, r.text
        assert "Origin не разрешён" not in r.text
        set_cookie = " ".join(v for k, v in r.headers.multi_items() if k.lower() == "set-cookie").lower()
        assert "nozo_session" in set_cookie and "httponly" in set_cookie
        # Loopback HTTP must not force Secure (otherwise the browser drops the cookie).
        assert "secure" not in set_cookie.split("nozo_session", 1)[-1].split(",", 1)[0]


def test_html_login_rejects_foreign_origin(env: Env):
    with TestClient(env.app, base_url="http://127.0.0.1:8765") as c:
        r = c.post(
            "/login",
            data={"username": "owner", "password": OWNER_PASSWORD},
            headers={"Origin": "https://evil.example"},
            follow_redirects=False,
        )
        assert r.status_code == 403
        assert "Origin не разрешён" in r.text or "origin" in r.text.lower()


def test_html_login_rejects_opaque_null_origin_by_default(env: Env):
    """SA-07: Origin:null is not trusted via destination Host (opt-in only)."""
    with TestClient(env.app, base_url="http://127.0.0.1:8765") as c:
        r = c.post(
            "/login",
            data={"username": "owner", "password": OWNER_PASSWORD},
            headers={"Origin": "null"},
            follow_redirects=False,
        )
        assert r.status_code == 403
        assert "Origin не разрешён" in r.text or "origin" in r.text.lower()


def test_cookie_secure_false_on_loopback_true_on_ts_host(env: Env):
    from starlette.requests import Request

    from nozo_relay.api.auth_routes import cookie_secure_for_request

    scope_loop = {
        "type": "http",
        "asgi": {"version": "3.0"},
        "http_version": "1.1",
        "method": "GET",
        "scheme": "http",
        "path": "/",
        "raw_path": b"/",
        "query_string": b"",
        "headers": [(b"host", b"127.0.0.1:8765")],
        "client": ("127.0.0.1", 123),
        "server": ("127.0.0.1", 8765),
    }
    assert cookie_secure_for_request(Request(scope_loop), env.settings) is False

    host = "roma-gv628rc.tailbfec94.ts.net"
    env.settings.allowed_hosts = [host]
    scope_ts = {
        **scope_loop,
        "headers": [(b"host", host.encode()), (b"x-forwarded-proto", b"https")],
        "scheme": "http",
    }
    assert cookie_secure_for_request(Request(scope_ts), env.settings) is True
