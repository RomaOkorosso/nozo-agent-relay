"""T11: regression of the phone/owner panel capabilities + coordinator-delegation helper + receipt honesty.

SCOPE (read this before quoting these tests):
* Everything here is LOCAL: Starlette TestClient over loopback, no Tailscale, no phone, no mobile network,
  no ChatGPT. It re-checks login, tasks, chat, reports, controls and the offline indicator contract at the
  server/markup level. It does NOT prove behaviour on a real mobile browser or a real network (Q32 stays
  BLOCKED_EXTERNAL) and it does NOT prove ChatGPT web/mobile (Q30/Q31 stay NOT_VERIFIED).
* The real-Chrome 360x800 emulation smoke lives in ``test_t04_browser_smoke.py`` (skipped without Playwright).
"""

from __future__ import annotations

import json
import os
import re
import stat
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from sqlalchemy import select

from api_helpers import Api, uid
from conftest import BASE_URL, OWNER_PASSWORD, Env, login
from nozo_relay import __main__ as cli
from nozo_relay.db.models import ApprovalRequest, Credential, Principal
from nozo_relay.ui import routes as ui_routes

ROOT = Path(__file__).resolve().parent.parent
STATIC = Path(ui_routes.STATIC_DIR)
T11 = ROOT / "evidence" / "t11"


def html(api: Api, path: str, who: str = "owner"):
    return api.clients[who].get(path)


# ============================================================================ login / session
def test_phone_login_form_session_cookie_and_gate(env: Env):
    anon = env.client()
    page = anon.get("/login")
    assert page.status_code == 200 and 'id="login-form"' in page.text and "Войти" in page.text
    assert 'name="viewport" content="width=device-width, initial-scale=1' in page.text
    # wrong password: no session, no cookie
    bad = anon.post("/api/v1/auth/login", json={"username": "owner", "password": "wrong password value"})
    assert bad.status_code == 401 and not anon.cookies
    # correct login: HttpOnly session cookie; the CSRF token is the only readable one
    ok = login(anon)
    assert ok.status_code == 200 and ok.json()["csrf_token"]
    set_cookie = " ".join(v for k, v in ok.headers.multi_items() if k.lower() == "set-cookie").lower()
    assert "httponly" in set_cookie and "samesite" in set_cookie
    assert anon.get("/projects").status_code == 200
    # logout kills the session for pages and fragments
    out = anon.post("/api/v1/auth/logout", headers={"X-CSRF-Token": ok.json()["csrf_token"], "Idempotency-Key": uid()})
    assert out.status_code in (200, 204)
    assert anon.get("/projects", follow_redirects=False).status_code == 303
    assert anon.get("/ui/session").status_code == 401


def test_session_revocation_is_rejected_on_the_next_request(api: Api, env: Env):
    from nozo_relay.auth.sessions import revoke_all_for_owner
    from nozo_relay.db.engine import write_session

    assert html(api, "/projects").status_code == 200
    with write_session(api.app.state.engine) as ws:  # type: ignore[attr-defined]
        revoke_all_for_owner(ws, api.clock, api.owner_id)
    r = api.clients["owner"].get(f"/projects/{api.project_id}", follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"] == "/login"
    assert api.clients["owner"].get(f"/ui/projects/{api.project_id}/tasks").status_code == 401
    # a foreign/forged cookie is just as dead
    stranger = env.client()
    stranger.cookies.set(env.settings.session_cookie_name, "forged-session-value")
    assert stranger.get(f"/ui/projects/{api.project_id}/tasks").status_code == 401


# ============================================================================ tasks
def test_phone_task_flow_create_enqueue_and_list_without_leaking_secrets(api: Api):
    page = html(api, f"/projects/{api.project_id}").text
    assert 'data-kind="task-create"' in page and "Новая задача" in page and "Задачи" in page
    t = api.create_task(title="Телефонная задача")
    lst = html(api, f"/ui/projects/{api.project_id}/tasks").text
    assert "Телефонная задача" in lst and "Черновик" in lst and f"/projects/{api.project_id}/tasks/{t['id']}" in lst
    api.enqueue(t)
    lst = html(api, f"/ui/projects/{api.project_id}/tasks").text
    assert "Телефонная задача" in lst and "Черновик" not in lst
    detail = html(api, f"/projects/{api.project_id}/tasks/{t['id']}")
    assert detail.status_code == 200 and "Требования" in detail.text and "Критерии приёмки" in detail.text
    for body in (page, lst, detail.text):
        assert "nzr_" not in body and api.keys["impl"] not in body and api.keys["aud"] not in body
    # idempotent create from a flaky phone connection: same key -> same task, not a duplicate
    key = uid()
    a = api.req("owner", "POST", api.p("/tasks"), api.task_body(title="Повтор"), idem=key)
    b = api.req("owner", "POST", api.p("/tasks"), api.task_body(title="Повтор"), idem=key)
    assert a.status_code == b.status_code == 201 and a.json()["id"] == b.json()["id"]
    assert b.headers.get("Idempotent-Replay") == "true"


# ============================================================================ chat
def test_phone_chat_post_render_and_escape(api: Api):
    t = api.create_task()
    evil = "<script>alert(1)</script> **x**"
    for who, text in (("owner", "Вопрос с телефона"), ("impl", evil)):
        r = api.req(who, "POST", api.p("/messages"), {"client_message_id": uid(), "kind": "note", "body": text, "task_id": t["id"]})
        assert r.status_code == 201, r.text
        api.clock.advance(ms=5)
    chat = html(api, f"/ui/projects/{api.project_id}/chat").text
    assert "Вопрос с телефона" in chat and "&lt;script&gt;" in chat and "<script>alert" not in chat
    # a message never changes task state (shown to the owner on the task page)
    assert api.get_task(t["id"])["status"] == "draft"
    assert "не меняет scope, не даёт approval и не запускает агента" in html(api, f"/projects/{api.project_id}/tasks/{t['id']}").text
    # same client_message_id retried after a lost response -> one message
    cid = uid()
    body = {"client_message_id": cid, "kind": "note", "body": "retry me"}
    r1 = api.req("owner", "POST", api.p("/messages"), body)
    r2 = api.req("owner", "POST", api.p("/messages"), body)
    assert r1.status_code == 201 and r2.status_code in (200, 201) and r1.json()["id"] == r2.json()["id"]
    ids = re.findall(r'data-msg-id="([^"]+)"', html(api, f"/ui/projects/{api.project_id}/chat").text)
    assert len(ids) == len(set(ids))


# ============================================================================ reports
def test_phone_reports_render_separate_groups_and_no_fake_pass(api: Api):
    t = api.queued_task(title="Отчёты")
    api.implement(t["id"])
    api.audit("INCONCLUSIVE")
    rep = html(api, f"/ui/projects/{api.project_id}/tasks/{t['id']}/reports").text
    assert "Отчёт реализации" in rep and "Отчёт аудита" in rep
    assert "Не определено" in rep and "Не запускалось" in rep and "Уровень доказательств" in rep
    assert api.get_task(t["id"])["status"] != "completed"  # INCONCLUSIVE never completes a task
    timeline = html(api, f"/ui/projects/{api.project_id}/tasks/{t['id']}/timeline").text
    assert "Отчёт получен" in timeline


# ============================================================================ controls
def test_phone_controls_stop_is_requested_never_stopped_without_receipt(api: Api):
    page = html(api, f"/projects/{api.project_id}").text
    for needle in ("Аварийная остановка", "Пауза проекта", 'data-act="emergency-stop"'):
        assert needle in page, needle
    t = api.queued_task()
    c = api.claim("impl")
    api.start("impl", c)
    r = api.control(t["id"], "pause", expect=202)
    assert r.json()["control"]["confirmed_at"] is None
    state = html(api, f"/ui/projects/{api.project_id}/tasks/{t['id']}/state").text
    assert "Запрошено" in state and "Остановлено" not in state
    # agent keys get no controls in the UI and are refused by the API regardless of markup
    assert html(api, f"/ui/projects/{api.project_id}/tasks/{t['id']}/actions", who="impl").status_code == 401  # panel is session-only
    t2 = api.create_task()
    assert api.req("impl", "POST", api.p(f"/tasks/{t2['id']}/controls"), {"command": "cancel", "reason": "x"}, if_match=t2["version"]).status_code == 403


# ============================================================================ offline indicator
def test_offline_indicator_contract_markup_script_and_css(api: Api):
    page = html(api, f"/projects/{api.project_id}").text
    assert 'id="connbar"' in page and 'id="conn-label"' in page and 'id="conn-sync"' in page and "Синхр.:" in page
    js = (STATIC / "app.js").read_text()
    css = (STATIC / "app.css").read_text()
    for state, label in (("connected", "Онлайн (WebSocket)"), ("reconnecting", "Переподключение…"),
                         ("polling", "Опрос каждые 10 с"), ("offline", "Нет сети")):
        assert state in js and label in js, state
        assert f'.connbar[data-state="{state}"]' in css, state
    # commands fail visibly offline; nothing is queued, stored or served from a service worker
    assert "НЕ поставлена в очередь" in js and "if (!online())" in js
    for banned in ("localStorage", "sessionStorage", "indexedDB", "navigator.serviceWorker", "Bearer", "nzr_"):
        assert banned not in js, banned
    # reconnect resumes from the durable cursor and de-duplicates
    assert "after_seq=" in js and "frame.seq <= ws.lastSeq || ws.seen.has(frame.event_id)" in js


def test_phone_layout_contract_viewport_tap_targets_no_os_surface(api: Api):
    css = (STATIC / "app.css").read_text()
    assert "--tap: 44px" in css and "@media (min-width: 900px)" in css and css.count("min-height: var(--tap)") >= 5
    # the panel is a control/chat surface only: no terminal/shell/file-browser/remote-desktop routes
    paths = {getattr(r, "path", "") for r in api.app.routes}  # type: ignore[attr-defined]
    for p in paths:
        assert not re.search(r"/(terminal|shell|exec|files?|fs|vnc|rdp|desktop)(/|$)", p), p
    # no public/funnel assumption: the default listener is loopback
    assert api.env.settings.host == "127.0.0.1"


# ============================================================================ coordinator delegation helper
def _register_coordinator(api: Api, name: str = "chatgpt-coordinator") -> str:
    r = api.req("owner", "POST", "/api/v1/agents", {"display_name": name, "kind": "coordinator", "project_ids": [api.project_id]})
    assert r.status_code == 201, r.text
    return r.json()["id"]


def test_mint_key_cli_writes_once_0600_never_prints_and_enables_a_narrow_coordinator(
    api: Api, env: Env, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
):
    monkeypatch.setenv("NOZO_RELAY_DATA_DIR", str(env.settings.data_dir))
    monkeypatch.setenv("NOZO_RELAY_INSECURE_DEV_COOKIES", "1")
    monkeypatch.setattr("nozo_relay.keymint.SystemClock", lambda: env.clock)  # tests run on the fake clock
    cid = _register_coordinator(api)

    # owner principals can never get a key through this helper; unknown names are refused
    assert cli.main(["mint-key", "--agent", "owner"]) == 1
    assert cli.main(["mint-key", "--agent", "does-not-exist"]) == 1
    capsys.readouterr()

    assert cli.main(["mint-key", "--agent", cid, "--expires-in-days", "30"]) == 0
    out = capsys.readouterr()
    files = list((env.settings.data_dir / "minted_keys").glob("*.json"))
    assert len(files) == 1
    mode = stat.S_IMODE(os.stat(files[0]).st_mode)
    assert mode == 0o600 and stat.S_IMODE(os.stat(files[0].parent).st_mode) == 0o700
    doc = json.loads(files[0].read_text())
    key = doc["key"]
    assert key.startswith("nzr_") and doc["principal_id"] == cid and doc["kind"] == "coordinator" and doc["expires_at"]
    assert key not in out.out and key not in out.err  # printed nowhere
    with api.db() as s:
        cred = s.execute(select(Credential).where(Credential.principal_id == cid)).scalar_one()
        assert key not in (cred.secret_digest or "") and cred.expires_at is not None

    coord = api.client_for_key(key)
    me = api.req(coord, "GET", "/api/v1/me").json()
    assert me["principal"]["kind"] == "coordinator" and me["principal"]["id"] == cid

    # without a delegation the coordinator can create nothing
    r = api.req(coord, "POST", api.p("/tasks"), api.task_body(autonomous=False))
    assert r.status_code in (403, 422), r.text

    # narrow delegation: task.create + task.enqueue only (NO task.control), expires, scope ceiling
    until = (datetime.fromtimestamp(api.clock.now_ms() / 1000, tz=UTC) + timedelta(hours=1)).isoformat()
    d = api.req("owner", "POST", api.p("/delegations"), {
        "coordinator_id": cid, "allowed_actions": ["task.create", "task.enqueue"],
        "scope_ceiling": {"allowed_paths": ["src/**"], "max_changed_files": 5, "max_diff_lines": 200}, "valid_until": until,
    })
    assert d.status_code == 201, d.text
    did = d.json()["id"]
    made = api.req(coord, "POST", api.p("/tasks"), api.task_body(autonomous=False, delegation_id=did, title="Из ChatGPT (локальный прокси)"))
    assert made.status_code == 201, made.text
    t = made.json()
    assert api.req(coord, "POST", api.p(f"/tasks/{t['id']}/enqueue"), if_match=t["version"]).status_code == 200
    ctl = api.req(coord, "POST", api.p(f"/tasks/{t['id']}/controls"), {"command": "cancel", "reason": "x"}, if_match=api.get_task(t["id"])["version"])
    assert ctl.status_code == 403, "delegation without task.control must not allow controls"

    # exceeding the ceiling (autonomous) is refused
    over = api.req(coord, "POST", api.p("/tasks"), api.task_body(autonomous=True, delegation_id=did))
    assert over.status_code in (403, 422), over.text

    # revocation ends the coordinator's authority immediately
    rv = api.req("owner", "POST", api.p(f"/delegations/{did}/revoke"), {"reason": "test"})
    assert rv.status_code == 200, rv.text
    after = api.req(coord, "POST", api.p("/tasks"), api.task_body(autonomous=False, delegation_id=did, title="after revoke"))
    assert after.status_code in (403, 409, 422), after.text


def test_coordinator_cannot_approve_publish_or_administer(api: Api, env: Env, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("NOZO_RELAY_DATA_DIR", str(env.settings.data_dir))
    cid = _register_coordinator(api)
    assert cli.main(["mint-key", "--agent", cid]) == 0
    key = json.loads(next((env.settings.data_dir / "minted_keys").glob("*.json")).read_text())["key"]
    coord = api.client_for_key(key)

    # it may only REQUEST approval ...
    ar = api.req(coord, "POST", api.p("/approval-requests"), {
        "kind": "publish", "summary": "ship it",
        "action": {"destination": "pypi", "artifact_digest": "b" * 64},
    })
    assert ar.status_code == 201, ar.text
    aid, digest = ar.json()["id"], ar.json()["action_digest"]
    # ... never decide / execute it
    dec = api.req(coord, "POST", api.p(f"/approval-requests/{aid}/decision"), {"decision": "approve", "action_digest": digest, "reason": "me"})
    assert dec.status_code == 403
    ex = api.req(coord, "POST", api.p(f"/approval-requests/{aid}/execute"), {"action_digest": digest})
    assert ex.status_code in (403, 501)
    with api.db() as s:
        assert s.get(ApprovalRequest, aid).status == "pending"
    # nor administer: agents, keys, delegations, policy, emergency stop, reauth
    attempts: list[tuple[str, str, Any]] = [
        ("POST", "/api/v1/agents", {"display_name": "evil", "kind": "coordinator", "project_ids": [api.project_id]}),
        ("POST", api.p("/delegations"), {"coordinator_id": cid, "allowed_actions": ["task.create"], "scope_ceiling": {"allowed_paths": ["**"]},
                                         "valid_until": "2099-01-01T00:00:00+00:00"}),
        ("PUT", api.p("/policy"), {}),
        ("POST", "/api/v1/controls/emergency-stop", {"reason": "x"}),
        ("POST", "/api/v1/auth/reauth", {"password": OWNER_PASSWORD}),
    ]
    for method, path, body in attempts:
        r = api.req(coord, method, path, body, if_match='"1"' if method == "PUT" else None)
        assert r.status_code in (401, 403, 404, 422, 428), (method, path, r.status_code)
        assert r.status_code != 200 and r.status_code != 201, (method, path)
    # and the coordinator key cannot open the owner panel
    assert coord.get("/ui/session").status_code == 401
    with api.db() as s:
        assert s.execute(select(Principal).where(Principal.display_name == "evil")).first() is None


# ============================================================================ receipts honesty (T11 evidence)
RECEIPTS = ("PHONE_UI.json", "CHATGPT_WEB.json", "CHATGPT_MOBILE.json")


def _receipt(name: str) -> dict[str, Any]:
    path = T11 / name
    assert path.is_file(), f"missing receipt {path}"
    return json.loads(path.read_text())


def test_t11_receipts_exist_and_do_not_overclaim():
    phone = _receipt("PHONE_UI.json")
    assert phone["capability"] == "PHONE_UI"
    assert phone["levels"]["local_browser"]["status"] == "probe_pass"
    assert phone["levels"]["local_browser"]["emulated"] is True
    assert phone["levels"]["real_mobile"]["status"] == "BLOCKED_EXTERNAL"
    assert phone["levels"]["real_mobile"]["verified"] is False and "Tailscale" in phone["levels"]["real_mobile"]["reason"]
    for rel in phone["levels"]["local_browser"]["evidence_files"]:
        assert (ROOT / rel).is_file(), rel
    assert phone["q32"] == "BLOCKED_EXTERNAL"
    for name, cap in (("CHATGPT_WEB.json", "CHATGPT_WEB"), ("CHATGPT_MOBILE.json", "CHATGPT_MOBILE")):
        r = _receipt(name)
        assert r["capability"] == cap and r["status"] == "NOT_VERIFIED" and r["verified"] is False
        assert r["real_invocation_performed"] is False
        assert r["reason"] and r["owner_actions"]
    assert _receipt("CHATGPT_WEB.json")["qxx"] == ["Q30"] and set(_receipt("CHATGPT_MOBILE.json")["qxx"]) == {"Q31"}
    # no receipt may contain secret-looking material
    for name in RECEIPTS:
        text = (T11 / name).read_text()
        assert not re.search(r"nzr_[A-Za-z0-9_-]{8,}", text) and not re.search(r"Bearer\s+[A-Za-z0-9_.~+/=-]{16,}", text)


def test_t11_receipts_match_the_local_host_facts():
    """If Tailscale appears on the machine running the audit, the recorded host probe is stale: skip (not pass)."""
    import shutil

    phone = _receipt("PHONE_UI.json")
    if shutil.which("tailscale"):
        pytest.skip("tailscale is now installed: re-probe and refresh evidence/t11/PHONE_UI.json (still no real-device test => still BLOCKED_EXTERNAL)")
    assert phone["host_probe"]["tailscale_binary"] is None
