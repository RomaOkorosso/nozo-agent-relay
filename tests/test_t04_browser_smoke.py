"""Real-browser smoke of the owner panel (Chrome via Playwright) against a real uvicorn server.

Optional: skipped when ``playwright`` or Chrome is unavailable. Run with
``uv run --with playwright pytest tests/test_t04_browser_smoke.py`` (nothing is added to the project
dependencies). Screenshots + console logs (no secrets) go to ``evidence/t04/``.

This is LOCAL browser evidence only (emulated 360x800 touch viewport on this laptop). It is NOT the Q32
real-phone test, which needs the owner's device and a private HTTPS route.
"""

from __future__ import annotations

import json
import socket
import threading
import time
from pathlib import Path

import pytest

sync_api = pytest.importorskip("playwright.sync_api")
import uvicorn  # noqa: E402

from api_helpers import Api, uid  # noqa: E402
from conftest import OWNER_PASSWORD, Env, make_settings  # noqa: E402
from nozo_relay.auth.sessions import revoke_all_for_owner  # noqa: E402
from nozo_relay.bootstrap import bootstrap, credentials_path  # noqa: E402
from nozo_relay.clock import SystemClock  # noqa: E402
from nozo_relay.db.engine import write_session  # noqa: E402
from nozo_relay.main import create_app  # noqa: E402

EVIDENCE = Path(__file__).resolve().parent.parent / "evidence" / "t04"


class LiveUi:
    def __init__(self, tmp_path: Path) -> None:
        with socket.socket() as s:
            s.bind(("127.0.0.1", 0))
            self.port = s.getsockname()[1]
        settings = make_settings(
            tmp_path, port=self.port, ws_scan_interval_seconds=0.3, ws_auth_recheck_seconds=0.3,
            ws_heartbeat_seconds=5, watchdog_interval_seconds=0,
        )
        clock = SystemClock()
        bootstrap(settings, owner_password=OWNER_PASSWORD, clock=clock)
        creds = json.loads(credentials_path(settings).read_text())
        self.app = create_app(settings, clock)
        self.api = Api(Env(settings=settings, clock=clock, creds=creds, app=self.app))  # type: ignore[arg-type]
        self.server = uvicorn.Server(uvicorn.Config(self.app, host="127.0.0.1", port=self.port, log_level="warning"))
        self.thread = threading.Thread(target=self.server.run, daemon=True)
        self.thread.start()
        end = time.monotonic() + 15
        while not self.server.started:
            assert time.monotonic() < end, "uvicorn did not start"
            time.sleep(0.05)
        self.url = f"http://127.0.0.1:{self.port}"

    def close(self) -> None:
        self.server.should_exit = True
        self.thread.join(timeout=10)


@pytest.fixture(scope="module")
def browser():
    with sync_api.sync_playwright() as p:
        try:
            b = p.chromium.launch(channel="chrome", headless=True)
        except Exception as exc:  # noqa: BLE001
            pytest.skip(f"Chrome not available for Playwright: {exc}")
        yield b
        b.close()


@pytest.fixture
def live(tmp_path: Path):
    lv = LiveUi(tmp_path)
    try:
        yield lv
    finally:
        lv.close()


def shot(page, name: str) -> None:  # noqa: ANN001
    EVIDENCE.mkdir(parents=True, exist_ok=True)
    page.screenshot(path=str(EVIDENCE / f"{name}.png"))


class Console:
    def __init__(self, page) -> None:  # noqa: ANN001
        self.lines: list[str] = []
        page.on("console", lambda m: self.lines.append(f"{m.type}: {m.text}") if m.type in ("error", "warning") else None)
        page.on("pageerror", lambda e: self.lines.append(f"pageerror: {e}"))

    def errors(self) -> list[str]:
        return list(self.lines)

    def save(self, name: str) -> None:
        EVIDENCE.mkdir(parents=True, exist_ok=True)
        (EVIDENCE / f"{name}.console.log").write_text("\n".join(self.lines) + "\n")


def login_ui(page, lv: LiveUi) -> None:  # noqa: ANN001
    page.goto(lv.url + "/login")
    page.fill("input[name=username]", "owner")
    page.fill("input[name=password]", OWNER_PASSWORD)
    page.click("#login-form button[type=submit]")
    page.wait_for_url("**/projects")


def wait_state(page, state: str, timeout: int = 8000) -> None:  # noqa: ANN001
    page.wait_for_selector(f'#connbar[data-state="{state}"]', timeout=timeout)


def no_horizontal_scroll(page) -> None:  # noqa: ANN001
    over = page.evaluate("() => [document.documentElement.scrollWidth, window.innerWidth]")
    assert over[0] <= over[1], f"horizontal scroll: scrollWidth={over[0]} innerWidth={over[1]}"


def small_targets(page) -> list[str]:  # noqa: ANN001
    return page.evaluate(
        """() => {
          const sel = 'button, a.btn, a.crumb, a.brand, a.card-link, input:not([type=checkbox]):not([type=hidden]), select, textarea, summary, .tab';
          const bad = [];
          for (const el of document.querySelectorAll(sel)) {
            const r = el.getBoundingClientRect();
            if (r.width === 0 || r.height === 0) continue;      // hidden / collapsed
            if (r.height < 43.5) bad.push(el.tagName + '.' + el.className + ' h=' + r.height.toFixed(1) + ' "' + (el.textContent || '').trim().slice(0, 20) + '"');
          }
          return bad;
        }"""
    )


def test_phone_360x800_full_flow_ws_reconnect_stop_and_revocation(browser, live: LiveUi):
    lv, api = live, live.api
    ctx = browser.new_context(viewport={"width": 360, "height": 800}, device_scale_factor=2, is_mobile=True,
                              has_touch=True, locale="ru-RU", timezone_id="Asia/Dubai")
    page = ctx.new_page()
    con = Console(page)
    login_ui(page, lv)
    no_horizontal_scroll(page)
    shot(page, "01-phone-projects")

    page.click("a.card-link")
    page.wait_for_url(f"**/projects/{api.project_id}")
    wait_state(page, "connected")
    assert page.inner_text("#conn-sync") != "—"  # last-synced timestamp is shown
    no_horizontal_scroll(page)
    assert small_targets(page) == []
    shot(page, "02-phone-project-tasks")

    # create + enqueue a task through the UI (CSRF + Idempotency-Key headers added by the script)
    page.click("button.tab[data-tab=manage]")
    page.fill("form[data-kind=task-create] [name=title]", "Мобильная задача")
    page.fill("form[data-kind=task-create] [name=requirements]", "Сделать панель удобной на телефоне")
    page.fill("form[data-kind=task-create] [name=acceptance]", "кнопки ≥44px\nнет горизонтального скролла")
    page.check("form[data-kind=task-create] [name=enqueue]")
    assert small_targets(page) == []
    shot(page, "03-phone-create-task")
    page.click("form[data-kind=task-create] button[type=submit]")
    page.wait_for_url("**/tasks/*")
    task_id = page.url.rsplit("/", 1)[1]
    wait_state(page, "connected")
    assert "В очереди" in page.inner_text(".task-state")
    no_horizontal_scroll(page)
    shot(page, "04-phone-task-queued")

    # chat: send a note from the phone; it appears exactly once; markup is shown as text
    page.click("button.tab[data-tab=chat]")
    page.fill("form.composer [name=body]", "Привет <b>агент</b>, уточнение")
    page.click("form.composer button[type=submit]")
    page.wait_for_selector("li.msg")
    time.sleep(0.8)  # the WS echo of the same event must not duplicate the row
    assert page.locator("li.msg").count() == 1
    assert "<b>агент</b>" in page.locator("li.msg .msg-body").first.inner_text()
    assert page.locator("li.msg .msg-body b").count() == 0
    no_horizontal_scroll(page)
    shot(page, "05-phone-chat")

    # a second (desktop) browser context sees it live, then the phone drops offline during updates
    desk = browser.new_context(viewport={"width": 1280, "height": 800}, locale="ru-RU")
    desk.add_cookies([{"name": c.name, "value": c.value, "url": lv.url} for c in api.clients["owner"].cookies.jar])
    dpage = desk.new_page()
    dpage.goto(f"{lv.url}/projects/{api.project_id}/tasks/{task_id}")
    wait_state(dpage, "connected")
    dcon = Console(dpage)
    dpage.fill("form.composer [name=body]", "С десктопа")
    dpage.click("form.composer button[type=submit]")
    page.wait_for_function("() => document.querySelectorAll('li.msg').length === 2", timeout=5000)

    ctx.set_offline(True)
    wait_state(page, "offline")
    page.fill("form.composer [name=body]", "Не должно уйти")
    page.click("form.composer button[type=submit]")
    page.wait_for_selector("#toast:not([hidden])")
    assert "Нет сети" in page.inner_text("#toast")  # refused, NOT queued for later
    for i in range(3):  # continuous updates while the phone is away
        api.req("owner", "POST", api.p("/messages"), {"client_message_id": uid(), "kind": "note", "body": f"пока вас нет {i}", "task_id": task_id})
    shot(page, "06-phone-offline")
    assert page.locator("li.msg").count() == 2
    ctx.set_offline(False)
    wait_state(page, "connected", 15000)
    page.wait_for_function("() => document.querySelectorAll('li.msg').length === 5", timeout=8000)
    time.sleep(1.0)
    assert page.locator("li.msg").count() == 5  # replay: all events once, no duplicates
    bodies = page.locator("li.msg .msg-body").all_inner_texts()
    assert len(set(bodies)) == 5 and "Не должно уйти" not in bodies
    shot(page, "07-phone-reconnected")

    # stop flow: 202 shows REQUESTED, never "Остановлено", until the runner's receipt arrives
    page.click("button.tab[data-tab=state]")
    claim = api.claim("impl")
    api.start("impl", claim)
    page.wait_for_selector('[data-activity="running"], [data-activity="claimed_only"]')
    page.wait_for_selector('[data-activity="running"]', timeout=8000)
    shot(page, "08-phone-running")
    page.click('button[data-act="control"][data-command="pause"]')
    page.wait_for_selector('[data-control-state="requested"]', timeout=8000)
    assert "ЗАПРОШЕНО" in page.inner_text("#toast") or "Запрошено" in page.inner_text(".task-state")
    assert "Остановлено" not in page.inner_text("main")
    shot(page, "09-phone-stop-requested")
    ctl = api.req("owner", "GET", api.p(f"/tasks/{task_id}")).json()
    runner_key = api.make_runner()
    with api.db() as s:
        from nozo_relay.db.models import Control
        from sqlalchemy import select

        control = s.execute(select(Control).where(Control.task_id == task_id)).scalars().first()
        control_dict = {"id": control.id}
    api.stopped(claim, control_dict)
    page.wait_for_selector('[data-control-state="confirmed"]', timeout=8000)
    assert "Остановлено" in page.inner_text(".task-state")
    shot(page, "10-phone-stop-confirmed")
    _ = (ctl, runner_key)

    # nothing secret in the page/storage; HttpOnly cookie not readable by script
    assert page.evaluate("() => localStorage.length + sessionStorage.length") == 0
    cookie_js = page.evaluate("() => document.cookie")
    assert "nozo_session" not in cookie_js and "nozo_csrf" in cookie_js
    html = page.content()
    assert api.keys["impl"] not in html and "nzr_" not in html

    assert con.errors() == [], con.errors()
    assert dcon.errors() == [], dcon.errors()
    con.save("phone-360x800")

    # session revoked server-side -> socket closed (4401) -> the page goes to the login screen
    with write_session(lv.app.state.engine) as ws:  # type: ignore[attr-defined]
        revoke_all_for_owner(ws, lv.app.state.clock, api.owner_id)  # type: ignore[attr-defined]
    page.wait_for_url("**/login", timeout=10000)
    shot(page, "11-phone-session-revoked-login")
    ctx.close()
    desk.close()


def test_desktop_layout_shows_tasks_and_chat_side_by_side(browser, live: LiveUi):
    lv, api = live, live.api
    api.queued_task(title="Десктоп")
    ctx = browser.new_context(viewport={"width": 1280, "height": 800}, locale="ru-RU")
    page = ctx.new_page()
    con = Console(page)
    login_ui(page, lv)
    page.goto(f"{lv.url}/projects/{api.project_id}")
    wait_state(page, "connected")
    assert page.locator("#tab-tasks").is_visible() and page.locator("#tab-chat").is_visible()
    assert not page.locator("nav.bottomnav").is_visible()
    no_horizontal_scroll(page)
    shot(page, "20-desktop-project")
    assert con.errors() == [], con.errors()
    con.save("desktop-1280x800")
    ctx.close()


def test_polling_fallback_when_websocket_is_unavailable(browser, live: LiveUi):
    lv, api = live, live.api
    ctx = browser.new_context(viewport={"width": 360, "height": 800}, is_mobile=True, has_touch=True, locale="ru-RU")
    ctx.add_init_script("window.WebSocket = function () { throw new Error('ws blocked'); };")
    page = ctx.new_page()
    login_ui(page, lv)
    page.goto(f"{lv.url}/projects/{api.project_id}")
    wait_state(page, "polling", 20000)  # degraded, and labelled as such (not shown as WebSocket)
    assert "WebSocket недоступен" in page.inner_text("#conn-label")
    api.queued_task(title="Появилась при опросе")
    page.wait_for_selector("text=Появилась при опросе", timeout=20000)
    shot(page, "30-phone-polling-fallback")
    ctx.close()
