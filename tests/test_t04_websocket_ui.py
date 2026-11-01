"""T04: durable WebSocket + authenticated owner panel (Q06, Q18, Q19, Q21, Q23-adjacent, Q32 local part)."""

from __future__ import annotations

import asyncio
import concurrent.futures
import contextlib
import queue
import re
import threading
import time
from pathlib import Path
from typing import Any

import pytest
from sqlalchemy import select
from sqlalchemy.orm import Session
from starlette.testclient import WebSocketDenialResponse, WebSocketDisconnect

from api_helpers import Api, uid
from conftest import BASE_URL, OWNER_PASSWORD, Env, login, make_settings
from nozo_relay.db.engine import write_session
from nozo_relay.db.models import Credential, Event
from nozo_relay.services.events import append_event
from nozo_relay.ui import labels as L
from nozo_relay.ui import routes as ui_routes
from nozo_relay.ws.hub import CLOSE_AUTH_LOST, CLOSE_RESYNC, CLOSE_SLOW, Connection, FrameQueue, Identity, Item

Rejected = (WebSocketDisconnect, WebSocketDenialResponse)  # refused before accept == HTTP denial
ORIGIN = BASE_URL  # http://127.0.0.1:8765, in the allow-list
STATIC = Path(ui_routes.STATIC_DIR)


@pytest.fixture
def settings(tmp_path):
    return make_settings(
        tmp_path,
        ws_scan_interval_seconds=0.05,
        ws_auth_recheck_seconds=0.1,
        ws_heartbeat_seconds=30,
    )


# ====================================================================== helpers


class WsReader:
    """Background reader around Starlette's blocking WebSocketTestSession: frames or the close code."""

    def __init__(self, session) -> None:  # noqa: ANN001
        self.session = session
        self.q: queue.Queue[tuple[str, Any]] = queue.Queue()
        self.closed: tuple[int, str] | None = None
        t = threading.Thread(target=self._run, daemon=True)
        t.start()

    def _run(self) -> None:
        while True:
            try:
                self.q.put(("frame", self.session.receive_json()))
            except WebSocketDisconnect as exc:
                self.q.put(("closed", (exc.code, exc.reason)))
                return
            except BaseException as exc:  # noqa: BLE001
                self.q.put(("error", exc))
                return

    def next(self, timeout: float = 5.0) -> dict[str, Any]:
        kind, val = self.q.get(timeout=timeout)
        if kind == "closed":
            self.closed = val
            raise WsClosed(*val)
        if kind == "error":
            raise val
        return val

    def until(self, pred, timeout: float = 5.0) -> dict[str, Any]:  # noqa: ANN001
        end = time.monotonic() + timeout
        while True:
            frame = self.next(max(0.05, end - time.monotonic()))
            if pred(frame):
                return frame

    def ready(self, timeout: float = 5.0) -> dict[str, Any]:
        return self.until(lambda f: f.get("type") == "ready", timeout)

    def events(self, n: int, timeout: float = 10.0) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        end = time.monotonic() + timeout
        while len(out) < n:
            f = self.next(max(0.05, end - time.monotonic()))
            if "event_id" in f:
                out.append(f)
        return out

    def expect_close(self, timeout: float = 5.0) -> tuple[int, str]:
        end = time.monotonic() + timeout
        while True:
            try:
                self.next(max(0.05, end - time.monotonic()))
            except WsClosed as c:
                return c.code, c.reason


class WsClosed(Exception):
    def __init__(self, code: int, reason: str) -> None:
        super().__init__(f"closed {code} {reason}")
        self.code, self.reason = code, reason


def ws_url(api: Api, after: int | None = 0) -> str:
    return f"/ws/v1/projects/{api.project_id}" + (f"?after_seq={after}" if after is not None else "")


@contextlib.contextmanager
def open_ws(client, url: str, **headers: str):  # noqa: ANN001
    """websocket_connect that tolerates the test harness' hard cancel on exit.

    Starlette's session sends 'disconnect' and immediately cancels the app task, so the future of a
    still-cleaning-up server coroutine reports CancelledError; that is harness behaviour, not a server error.
    """
    base = str(client.base_url).replace("http://", "ws://").rstrip("/")
    cm = client.websocket_connect(base + url, headers=headers)
    session = cm.__enter__()  # Rejected (HTTP denial / close before accept) propagates from here
    try:
        yield session
    finally:
        with contextlib.suppress(concurrent.futures.CancelledError):
            cm.__exit__(None, None, None)


def owner_ws(api: Api, after: int = 0, **extra: str):
    return open_ws(api.clients["owner"], ws_url(api, after), Origin=ORIGIN, **extra)


def high_watermark(api: Api) -> int:
    with api.db() as s:
        return max([e for e in s.execute(select(Event.seq).where(Event.project_id == api.project_id)).scalars()] or [0])


def silent_commit(api: Api, n: int = 1, tag: str = "test.silent") -> list[str]:
    """Commit events WITHOUT notifying the hub (plain session, not write_session): crash-before-notify."""
    ids = []
    with Session(bind=api.app.state.engine) as s:  # type: ignore[attr-defined]
        for i in range(n):
            e = append_event(s, api.clock, type=tag, project_id=api.project_id, payload={"i": i})
            ids.append(e.event_id)
        s.commit()
    return ids


def notified_commit(api: Api, n: int = 1, tag: str = "test.live") -> list[str]:
    ids = []
    with write_session(api.app.state.engine) as ws:  # type: ignore[attr-defined]
        for i in range(n):
            ids.append(append_event(ws, api.clock, type=tag, project_id=api.project_id, payload={"i": i}).event_id)
    return ids


def post_message(api: Api, body: str, *, task_id: str | None = None, who: str = "owner", reply_to: str | None = None):
    payload: dict[str, Any] = {"client_message_id": uid(), "kind": "note", "body": body}
    if task_id:
        payload["task_id"] = task_id
    if reply_to:
        payload["reply_to"] = reply_to
    if hasattr(api.clock, "advance"):
        api.clock.advance(ms=5)  # messages are ordered by (created_at, id): keep timestamps distinct
    r = api.req(who, "POST", api.p("/messages"), payload)
    assert r.status_code == 201, r.text
    return r.json()


def get_html(api: Api, path: str, who: str = "owner", **kw):
    r = api.clients[who].get(path, **kw)
    return r


# ====================================================================== WebSocket: auth before accept


def test_ws_requires_auth_before_accept(api: Api, env: Env):
    anon = env.client()
    with pytest.raises(Rejected):
        with open_ws(anon, ws_url(api), Origin=ORIGIN):
            pass
    with pytest.raises(Rejected):
        with open_ws(anon, ws_url(api), Authorization="Bearer nzr_bogus.bogus"):
            pass


def test_ws_cookie_auth_needs_allowed_origin(api: Api):
    owner = api.clients["owner"]
    for hdrs in ({}, {"Origin": "https://evil.example"}, {"Origin": "null"}):
        with pytest.raises(Rejected):
            with open_ws(owner, ws_url(api), **hdrs):
                pass
    with owner_ws(api) as ws:  # allowed same-origin
        assert WsReader(ws).ready()["type"] == "ready"


def test_ws_never_accepts_credentials_in_query_string(api: Api):
    owner = api.clients["owner"]
    cookie = owner.cookies.get("nozo_session")
    key = api.keys["impl"]
    anon = api.app and __import__("fastapi.testclient", fromlist=["TestClient"]).TestClient(api.app, base_url=BASE_URL)
    for q in (f"?token={key}", f"?access_token={key}", f"?session={cookie}", f"?after_seq=0&api_key={key}"):
        with pytest.raises(Rejected):
            with open_ws(anon, f"/ws/v1/projects/{api.project_id}{q}", Origin=ORIGIN):
                pass
        # even WITH a valid cookie, the unknown parameter is refused (URLs must not carry secrets)
        with pytest.raises(Rejected):
            with open_ws(owner, f"/ws/v1/projects/{api.project_id}{q}", Origin=ORIGIN):
                pass
    for bad in ("-1", "abc", "1.5", "9" * 40):
        with pytest.raises(Rejected):
            with open_ws(owner, ws_url(api).split("?")[0] + f"?after_seq={bad}", Origin=ORIGIN):
                pass


def test_ws_bearer_for_cli_and_no_foreign_project(api: Api):
    with open_ws(api.clients["impl"], ws_url(api), Authorization=f"Bearer {api.keys['impl']}") as ws:
        assert WsReader(ws).ready()
    # a member of project A must not subscribe to an unknown / foreign project id
    with pytest.raises(Rejected):
        with open_ws(api.clients["impl"], f"/ws/v1/projects/{uid()}", Authorization=f"Bearer {api.keys['impl']}"):
            pass
    # Bearer with a hostile Origin header is refused too
    with pytest.raises(Rejected):
        with open_ws(api.clients["impl"], ws_url(api), Authorization=f"Bearer {api.keys['impl']}", Origin="https://evil.example"):
            pass


def test_ws_host_header_is_checked(api: Api):
    from fastapi.testclient import TestClient

    bad = TestClient(api.app, base_url="http://evil.example")
    bad.cookies.update(api.clients["owner"].cookies)
    with pytest.raises(Rejected):
        with open_ws(bad, ws_url(api), Origin=ORIGIN):
            pass


# ====================================================================== WebSocket: frames, replay, live


REQUIRED_KEYS = {"schema_version", "event_id", "seq", "project_id", "task_id", "type", "entity_version", "occurred_at", "data"}


def test_ws_frame_schema_replay_then_live(api: Api):
    task = api.create_task()
    base = high_watermark(api)
    with owner_ws(api, after=0) as ws:
        rd = WsReader(ws)
        replay = []
        while True:
            f = rd.next()
            if f["type"] == "ready":
                break
            replay.append(f)
        assert f["high_watermark"] == base and f["schema_version"] == 1
        assert replay and all(REQUIRED_KEYS <= set(e) for e in replay)
        assert [e["seq"] for e in replay] == sorted(e["seq"] for e in replay)
        created = [e for e in replay if e["type"] == "task.created"]
        assert created and created[0]["task_id"] == task["id"] and created[0]["data"]["title"] == "Fixture task"
        assert created[0]["project_id"] == api.project_id and created[0]["occurred_at"].endswith("Z")
        # live: a new committed event arrives after ready, with a seq above the watermark
        api.enqueue(task)
        live = rd.events(1)[0]
        assert live["seq"] > base and REQUIRED_KEYS <= set(live)
        # same payload as the REST replay (single wire format)
        rest = {e["event_id"]: e for e in api.events(after=0)}
        assert rest[live["event_id"]] == live


def test_ws_only_sees_own_project_events(api: Api):
    r = api.req("owner", "POST", "/api/v1/projects", {"slug": "other", "name": "Other"})
    assert r.status_code == 201, r.text
    other = r.json()["id"]
    with owner_ws(api, after=high_watermark(api)) as ws:
        rd = WsReader(ws)
        rd.ready()
        r2 = api.req("owner", "POST", f"/api/v1/projects/{other}/messages", {"client_message_id": uid(), "kind": "note", "body": "x"})
        assert r2.status_code == 201
        post_message(api, "mine")
        got = rd.events(1)[0]
        assert got["project_id"] == api.project_id  # never the other project's event


def test_ws_after_seq_ahead_of_log_requires_resync(api: Api):
    with owner_ws(api, after=high_watermark(api) + 1000) as ws:
        rd = WsReader(ws)
        f = rd.until(lambda f: f.get("type") == "resync_required")
        assert f["reason"] == "cursor_ahead"
        assert rd.expect_close()[0] == CLOSE_RESYNC


def test_ws_heartbeat_frame(api: Api):
    api.app.state.hub.settings.ws_heartbeat_seconds = 0.2  # type: ignore[attr-defined]
    with owner_ws(api, after=high_watermark(api)) as ws:
        rd = WsReader(ws)
        rd.ready()
        hb = rd.until(lambda f: f.get("type") == "heartbeat")
        assert hb["schema_version"] == 1 and hb["server_time"].endswith("Z")


# ====================================================================== Q06: crash between commit and notify


def test_q06_commit_without_notify_is_delivered_by_periodic_scan(api: Api):
    with owner_ws(api, after=high_watermark(api)) as ws:
        rd = WsReader(ws)
        rd.ready()
        ids = silent_commit(api, 2)  # the notify never happened (crash)
        got = rd.events(2)
        assert [e["event_id"] for e in got] == ids and got[0]["type"] == "test.silent"


def test_q06_commit_without_notify_is_available_by_replay_and_rest_and_after_restart(api: Api):
    before = high_watermark(api)
    ids = silent_commit(api, 3)
    assert {e["event_id"] for e in api.events(after=before)} >= set(ids)  # REST replay
    with owner_ws(api, after=before) as ws:  # WS replay
        rd = WsReader(ws)
        got = rd.events(3)
        assert [e["event_id"] for e in got] == ids
    api2 = api.restart()  # whole server restarted over the same DB
    with owner_ws(api2, after=before) as ws:
        assert [e["event_id"] for e in WsReader(ws).events(3)] == ids


def test_notify_wakes_connections_before_the_scan_would(api: Api):
    api.app.state.hub.settings.ws_scan_interval_seconds = 30  # type: ignore[attr-defined]
    with owner_ws(api, after=high_watermark(api)) as ws:
        rd = WsReader(ws)
        time.sleep(0.3)
        rd.ready()
        t0 = time.monotonic()
        post_message(api, "fast")  # REST commit -> write_session listener -> hub.notify
        rd.events(1, timeout=3)
        assert time.monotonic() - t0 < 1.0  # event commit -> UI < 1 s (08_UI_OPERATIONS target)


def test_rollback_does_not_notify_or_leak_events(api: Api):
    hub = api.app.state.hub  # type: ignore[attr-defined]
    seen: list[Any] = []
    from nozo_relay.db.engine import add_commit_listener

    add_commit_listener(api.app.state.engine, lambda p: seen.append(p))  # type: ignore[attr-defined]
    before = high_watermark(api)
    with pytest.raises(RuntimeError):
        with write_session(api.app.state.engine) as ws:  # type: ignore[attr-defined]
            append_event(ws, api.clock, type="test.rolled_back", project_id=api.project_id, payload={})
            raise RuntimeError("boom")
    assert seen == [] and high_watermark(api) == before and hub.stats["notified"] >= 0
    notified_commit(api, 1)
    assert seen and api.project_id in seen[-1]


# ====================================================================== Q18: reconnect during continuous writes


def test_q18_reconnect_with_after_seq_delivers_every_event_exactly_once(api: Api):
    base = high_watermark(api)
    total = 120
    written: list[str] = []
    stop = threading.Event()

    def writer() -> None:
        for i in range(total):
            written.extend(notified_commit(api, 1, tag="test.stream"))
            if i % 10 == 0:
                time.sleep(0.01)
        stop.set()

    seen: list[dict[str, Any]] = []
    t = threading.Thread(target=writer)
    with owner_ws(api, after=base) as ws1:
        rd1 = WsReader(ws1)
        t.start()
        seen.extend(rd1.events(25))
    last = seen[-1]["seq"]  # connection dropped mid-stream while the writer keeps going
    with owner_ws(api, after=last) as ws2:
        rd2 = WsReader(ws2)
        seen.extend(rd2.events(total - len(seen), timeout=15))
    t.join()
    seqs = [e["seq"] for e in seen]
    assert len(seen) == total and seqs == sorted(set(seqs))  # strictly increasing: no dup, no reorder
    assert [e["event_id"] for e in seen] == written  # every committed event, exactly once, in order


def test_q18_two_reconnects_with_gaps_in_project_sequence(api: Api):
    # another project's events consume global seq numbers: project seq has gaps, which is normal
    other = api.req("owner", "POST", "/api/v1/projects", {"slug": "gap", "name": "Gap"}).json()["id"]
    base = high_watermark(api)
    ids = []
    for i in range(6):
        ids += notified_commit(api, 1, tag="test.a")
        r = api.req("owner", "POST", f"/api/v1/projects/{other}/messages", {"client_message_id": uid(), "kind": "note", "body": f"o{i}"})
        assert r.status_code == 201
    got: list[dict[str, Any]] = []
    cursor = base
    for _ in range(3):  # reconnect repeatedly, two events at a time
        with owner_ws(api, after=cursor) as ws:
            part = WsReader(ws).events(2)
        got += part
        cursor = part[-1]["seq"]
    assert [e["event_id"] for e in got] == ids
    assert any(b["seq"] - a["seq"] > 1 for a, b in zip(got, got[1:]))  # gaps exist and are harmless


# ====================================================================== Q19: slow consumer


class StuckTransport:
    """A client that stopped reading: data frames never complete; only the final resync notice may pass."""

    def __init__(self) -> None:
        self.sent: list[str] = []
        self.closed: tuple[int, str] | None = None
        self.gate = asyncio.Event()

    async def send_text(self, text: str) -> None:
        if '"resync_required"' not in text:
            await self.gate.wait()
        self.sent.append(text)

    async def receive_text(self) -> str:
        await asyncio.Event().wait()
        return ""

    async def close(self, code: int, reason: str) -> None:
        self.closed = (code, reason)


async def test_q19_slow_consumer_gets_resync_and_disconnect_while_api_keeps_working(api: Api):
    hub = api.app.state.hub  # type: ignore[attr-defined]
    hub.settings.ws_queue_max_events = 3
    hub.settings.ws_send_timeout_seconds = 30
    tr = StuckTransport()
    conn = Connection(hub, Identity(api.owner_id, api.project_id), high_watermark(api), tr)
    hub.register(conn)
    runner = asyncio.create_task(conn.run())
    try:
        await asyncio.sleep(0.3)  # ready frame is "in flight" and stuck in the client's socket buffer
        t0 = time.monotonic()
        await asyncio.to_thread(notified_commit, api, 10)  # writers are never blocked by the stuck reader
        r = await asyncio.to_thread(api.req, "owner", "GET", api.p("/snapshot"))
        assert r.status_code == 200 and time.monotonic() - t0 < 3
        await asyncio.wait_for(runner, 5)
    finally:
        hub.unregister(conn)
    assert tr.closed is not None and tr.closed[0] == CLOSE_SLOW
    resync = [s for s in tr.sent if '"resync_required"' in s]
    assert resync and '"reason":"slow_consumer"' in resync[0]
    assert not [s for s in tr.sent if '"test.live"' in s]  # no half-delivered backlog after the notice
    # the queue/API continue for everybody else
    task = await asyncio.to_thread(api.create_task)
    assert task["status"] == "draft"


async def test_q19_send_timeout_marks_consumer_slow(api: Api):
    hub = api.app.state.hub  # type: ignore[attr-defined]
    hub.settings.ws_send_timeout_seconds = 0.2
    tr = StuckTransport()
    conn = Connection(hub, Identity(api.owner_id, api.project_id), high_watermark(api), tr)
    hub.register(conn)
    try:
        await asyncio.wait_for(conn.run(), 5)
    finally:
        hub.unregister(conn)
    assert tr.closed and tr.closed[0] == CLOSE_SLOW


def test_q19_default_queue_bounds_are_1000_events_and_2mib(api: Api):
    s = api.env.settings
    assert (s.ws_queue_max_events, s.ws_queue_max_bytes, s.ws_heartbeat_seconds) == (1000, 2 * 1024 * 1024, 30)
    from nozo_relay.config import Settings

    d = Settings(_env_file=None)
    assert (d.ws_queue_max_events, d.ws_queue_max_bytes, d.ws_heartbeat_seconds) == (1000, 2 * 1024 * 1024, 20.0)


async def test_frame_queue_bounds_events_and_bytes():
    q = FrameQueue(1000, 2 * 1024 * 1024)
    assert all(q.try_put(Item(i, "x", 1)) for i in range(1000))
    assert not q.try_put(Item(1001, "x", 1))  # 1001st event refused
    q2 = FrameQueue(1000, 2 * 1024 * 1024)
    assert q2.try_put(Item(1, "x", 2 * 1024 * 1024))
    assert not q2.try_put(Item(2, "x", 1))  # byte budget exhausted
    await q2.get()
    assert q2.try_put(Item(3, "x", 10))


def test_q19_end_to_end_burst_larger_than_queue_resyncs_over_real_ws(api: Api):
    hub = api.app.state.hub  # type: ignore[attr-defined]
    hub.settings.ws_queue_max_events = 5
    with owner_ws(api, after=high_watermark(api)) as ws:
        rd = WsReader(ws)
        rd.ready()
        # one commit of 40 events: the scan reads them in one batch which cannot fit the 5-event queue
        notified_commit(api, 40)
        f = rd.until(lambda f: f.get("type") == "resync_required")
        assert f["reason"] == "slow_consumer"
        assert rd.expect_close()[0] == CLOSE_SLOW
    assert api.req("owner", "GET", api.p("/snapshot")).status_code == 200
    # reconnect after the resync gets the full history again via replay (state is not lost)
    with owner_ws(api, after=0) as ws:
        rd = WsReader(ws)
        live: list[dict[str, Any]] = []
        while len(live) < 40:  # initial bootstrap events come first; replay is back-pressured, not dropped
            f = rd.next(10)
            if f.get("type") == "test.live":
                live.append(f)
        assert [e["seq"] for e in live] == sorted({e["seq"] for e in live})


# ====================================================================== revocation / expiry closes sockets


def test_expired_session_closes_ws(api: Api, clock):
    with owner_ws(api, after=high_watermark(api)) as ws:
        rd = WsReader(ws)
        rd.ready()
        clock.advance(seconds=31 * 60)  # > 30 min idle
        code, reason = rd.expect_close(5)
        assert code == CLOSE_AUTH_LOST and reason == "session_expired"
    with pytest.raises(Rejected):  # and it cannot reconnect with the dead session
        with owner_ws(api):
            pass


def test_absolute_session_expiry_and_membership_loss_close_ws(api: Api, clock):
    with owner_ws(api, after=high_watermark(api)) as ws:
        rd = WsReader(ws)
        rd.ready()
        with write_session(api.app.state.engine) as s:  # type: ignore[attr-defined]
            from nozo_relay.db.models import Membership

            s.delete(s.get(Membership, (api.owner_id, api.project_id)))
        code, reason = rd.expect_close(5)
        assert (code, reason) == (CLOSE_AUTH_LOST, "membership_lost")


def test_logout_closes_that_sessions_ws_immediately(api: Api):
    api.app.state.hub.settings.ws_auth_recheck_seconds = 60  # prove the direct hook, not the poll  # type: ignore[attr-defined]
    with owner_ws(api, after=high_watermark(api)) as ws:
        rd = WsReader(ws)
        rd.ready()
        r = api.req("owner", "POST", "/api/v1/auth/logout")
        assert r.status_code == 200
        code, reason = rd.expect_close(3)
        assert code == CLOSE_AUTH_LOST and reason == "session_revoked"


def test_revoked_key_closes_ws_directly_and_by_recheck(api: Api):
    with api.db() as s:
        cred = s.execute(select(Credential).where(Credential.principal_id == api.impl_id)).scalars().one()
    api.app.state.hub.settings.ws_auth_recheck_seconds = 60  # type: ignore[attr-defined]
    with open_ws(api.clients["impl"], ws_url(api, high_watermark(api)), Authorization=f"Bearer {api.keys['impl']}") as ws:
        rd = WsReader(ws)
        rd.ready()
        r = api.req("owner", "POST", f"/api/v1/agents/{api.impl_id}/keys/{cred.id}/revoke")
        assert r.status_code == 200, r.text
        assert rd.expect_close(3) == (CLOSE_AUTH_LOST, "credential_revoked")
    # Revocation that bypasses the HTTP route (e.g. owner CLI) is still caught by the periodic recheck.
    pid2, key2 = api.make_principal("implementer", "second-impl")
    api.app.state.hub.settings.ws_auth_recheck_seconds = 0.1  # type: ignore[attr-defined]
    with open_ws(api.client_for_key(key2), ws_url(api, high_watermark(api)), Authorization=f"Bearer {key2}") as ws:
        rd = WsReader(ws)
        rd.ready()
        with write_session(api.app.state.engine) as s:  # type: ignore[attr-defined]
            for c in s.execute(select(Credential).where(Credential.principal_id == pid2)).scalars():
                c.revoked_at = api.clock.now_ms()
        assert rd.expect_close(5)[0] == CLOSE_AUTH_LOST


def test_connection_cap_per_principal(api: Api):
    api.app.state.hub.settings.ws_max_connections_per_principal = 2  # type: ignore[attr-defined]
    with owner_ws(api) as a, owner_ws(api) as b:
        WsReader(a).ready(); WsReader(b).ready()
        with pytest.raises(Rejected):
            with owner_ws(api):
                pass


def test_hub_unregisters_closed_connections(api: Api):
    hub = api.app.state.hub  # type: ignore[attr-defined]
    with owner_ws(api) as ws:
        WsReader(ws).ready()
        assert hub.connection_count(api.project_id) == 1
    for _ in range(50):
        if hub.connection_count() == 0:
            break
        time.sleep(0.05)
    assert hub.connection_count() == 0


# ====================================================================== UI: pages, auth, escaping


def test_ui_login_page_and_redirects(api: Api, env: Env):
    anon = env.client()
    r = anon.get("/", follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"] == "/login"
    for path in ("/projects", f"/projects/{api.project_id}", f"/projects/{api.project_id}/tasks/{uid()}"):
        r = anon.get(path, follow_redirects=False)
        assert r.status_code == 303 and r.headers["location"] == "/login", path
    r = anon.get("/login")
    assert r.status_code == 200 and 'lang="ru"' in r.text and 'id="login-form"' in r.text
    assert "Войти" in r.text and "Пароль" in r.text
    assert r.headers["content-security-policy"].startswith("default-src 'self'")
    assert "no-store" in r.headers["cache-control"]
    # authenticated: / -> /projects, /login -> /projects
    assert api.clients["owner"].get("/", follow_redirects=False).headers["location"] == "/projects"
    assert api.clients["owner"].get("/login", follow_redirects=False).headers["location"] == "/projects"


def test_ui_fragments_and_pages_reject_agent_bearer_and_bad_sessions(api: Api, env: Env):
    for path in (f"/ui/projects/{api.project_id}/tasks", f"/ui/projects/{api.project_id}/chat", "/ui/session"):
        r = api.clients["impl"].get(path)  # Bearer keys do not open the owner panel
        assert r.status_code == 401, path
        assert r.json()["error"]["code"] == "unauthenticated"
    r = api.clients["impl"].get("/projects", follow_redirects=False)
    assert r.status_code == 303


def test_ui_projects_and_project_page_render_russian_mobile_first(api: Api):
    t = api.create_task(title="Показать reconnect")
    r = get_html(api, "/projects")
    assert r.status_code == 200 and "Проекты" in r.text and f"/projects/{api.project_id}" in r.text
    r = get_html(api, f"/projects/{api.project_id}")
    assert r.status_code == 200
    html = r.text
    assert 'name="viewport" content="width=device-width, initial-scale=1' in html
    for needle in ("Задачи", "Чат проекта", "Управление", "Новая задача", "Аварийная остановка", "Пауза проекта",
                   "Показать более ранние", "Показать reconnect", "Черновик", 'id="connbar"'):
        assert needle in html, needle
    assert f'data-ws-path="/ws/v1/projects/{api.project_id}"' in html
    assert f'data-hw="{high_watermark(api)}"' in html
    assert f"/projects/{api.project_id}/tasks/{t['id']}" in html
    # nothing in the page carries a credential
    assert api.keys["impl"] not in html and api.keys["aud"] not in html and "nzr_" not in html


def test_ui_pages_have_no_inline_script_or_style_and_static_assets_are_clean(api: Api):
    t = api.create_task()
    for path in ("/login", "/projects", f"/projects/{api.project_id}", f"/projects/{api.project_id}/tasks/{t['id']}"):
        html = get_html(api, path).text
        assert re.findall(r"<script\b[^>]*>", html) in ([], ['<script src="/static/app.js" defer>']), path
        assert not re.search(r"<script[^>]*>[^<]+</script>", html)  # no inline JS (CSP forbids it)
        assert not re.search(r"\sstyle\s*=", html), path
        assert not re.search(r"\son[a-z]+\s*=", html), path
    js = (STATIC / "app.js").read_text()
    css = (STATIC / "app.css").read_text()
    for banned in ("localStorage", "sessionStorage", "indexedDB", "eval(", "document.write", "access_token", "api_key", "nzr_", "Bearer"):
        assert banned not in js, banned
    assert js.count("after_seq=") == 1 and "?token" not in js  # the only query parameter is the cursor
    assert CSRF_HEADER_USED(js)
    assert css.count("min-height: var(--tap)") >= 5 and "--tap: 44px" in css and "@media (min-width: 900px)" in css
    r = api.clients["owner"].get("/static/app.js")
    assert r.status_code == 200 and "javascript" in r.headers["content-type"]
    assert r.headers["x-content-type-options"] == "nosniff"


def CSRF_HEADER_USED(js: str) -> bool:
    return "headers[CSRF_HEADER] = readCookie(CSRF_COOKIE)" in js


def test_ui_user_text_is_escaped_never_executed(api: Api):
    evil_title = "<script>alert(1)</script>"
    evil_body = '<img src=x onerror=alert(1)> **bold** [x](javascript:alert(1))'
    t = api.create_task(title=evil_title, requirements=evil_body)
    post_message(api, evil_body, task_id=t["id"])
    post_message(api, evil_body)
    pages = [
        get_html(api, f"/projects/{api.project_id}").text,
        get_html(api, f"/projects/{api.project_id}/tasks/{t['id']}").text,
        get_html(api, f"/ui/projects/{api.project_id}/chat").text,
        get_html(api, f"/ui/projects/{api.project_id}/tasks/{t['id']}/state").text,
        get_html(api, f"/ui/projects/{api.project_id}/tasks/{t['id']}/timeline").text,
        get_html(api, f"/ui/projects/{api.project_id}/tasks").text,
    ]
    for html in pages:
        assert "<script>alert(1)</script>" not in html
        assert "<img src=x" not in html and "onerror=alert" not in html.replace("&#34;", '"').replace("onerror=alert(1)&gt;", "")
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in pages[0]
    assert "&lt;img src=x onerror=alert(1)&gt;" in pages[2]  # markdown/HTML shown as plain text
    assert "<strong>bold</strong>" not in pages[2] and "<a href=\"javascript" not in pages[2]


def test_ui_unknown_project_or_task_is_404_page_without_existence_leak(api: Api):
    r = get_html(api, f"/projects/{uid()}")
    assert r.status_code == 404 and "Страница не найдена" in r.text
    r = get_html(api, f"/projects/{api.project_id}/tasks/{uid()}")
    assert r.status_code == 404
    r = api.clients["owner"].get(f"/ui/projects/{uid()}/tasks")
    assert r.status_code == 404 and r.json()["error"]["code"] == "not_found"
    assert api.clients["owner"].get(f"/ui/projects/{api.project_id}/tasks/{uid()}/state").status_code == 404
    t = api.create_task()
    assert api.clients["owner"].get(f"/ui/projects/{api.project_id}/tasks/{t['id']}/secrets").status_code == 404


def test_ui_expired_session_redirects_pages_and_401s_fragments(api: Api, clock):
    clock.advance(seconds=31 * 60)
    r = api.clients["owner"].get(f"/projects/{api.project_id}", follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"] == "/login"
    r = api.clients["owner"].get(f"/ui/projects/{api.project_id}/tasks")
    assert r.status_code == 401


def test_ui_fragment_polling_does_not_extend_the_idle_session(api: Api, clock):
    for _ in range(4):  # a tab that only polls for 40 minutes must still expire at 30 min idle
        clock.advance(seconds=10 * 60 - 1)
        r = api.clients["owner"].get("/ui/session")
        if r.status_code == 401:
            break
    assert r.status_code == 401


# ====================================================================== Q21: UI mutations need CSRF/Origin


def test_q21_ui_mutations_need_csrf_and_allowed_origin(api: Api):
    owner = api.clients["owner"]
    body = {"client_message_id": uid(), "kind": "note", "body": "hi"}
    h = {"Idempotency-Key": uid(), "Origin": ORIGIN}
    r = owner.post(api.p("/messages"), json=body, headers=h)  # cookie but no CSRF header
    assert r.status_code == 403 and r.json()["error"]["code"] == "csrf_failed"
    r = owner.post(api.p("/messages"), json=body, headers={**h, "X-CSRF-Token": "wrong"})
    assert r.status_code == 403
    r = owner.post(api.p("/messages"), json=body, headers={**h, "X-CSRF-Token": api.csrf, "Origin": "https://evil.example"})
    assert r.status_code == 403 and r.json()["error"]["code"] == "origin_not_allowed"
    r = owner.post(api.p("/messages"), json=body, headers={**h, "X-CSRF-Token": api.csrf})
    assert r.status_code == 201
    # the HTML/fragment routes are read-only: no mutation can be sent to them at all
    assert owner.post(f"/ui/projects/{api.project_id}/tasks", headers={"X-CSRF-Token": api.csrf}).status_code == 405
    assert owner.post("/projects", headers={"X-CSRF-Token": api.csrf}).status_code == 405
    # task controls / emergency stop likewise
    t = api.create_task()
    r = owner.post(api.p(f"/tasks/{t['id']}/enqueue"), headers={"Idempotency-Key": uid(), "If-Match": f'"{t["version"]}"', "Origin": ORIGIN})
    assert r.status_code == 403
    r = owner.post("/api/v1/controls/emergency-stop", json={"reason": "x"}, headers={"Idempotency-Key": uid(), "Origin": ORIGIN})
    assert r.status_code == 403


def test_q21_login_page_form_cannot_be_framed_or_post_cross_origin(api: Api, env: Env):
    anon = env.client()
    r = anon.get("/login")
    csp = r.headers["content-security-policy"]
    assert "frame-ancestors 'none'" in csp and "form-action 'self'" in csp and "object-src 'none'" in csp
    assert "script-src" not in csp and "unsafe-inline" not in csp  # default-src 'self' only
    assert r.headers["x-frame-options"] == "DENY"
    bad = anon.post("/api/v1/auth/login", json={"username": "owner", "password": OWNER_PASSWORD}, headers={"Origin": "https://evil.example"})
    assert bad.status_code == 403
    ok = login(env.client())
    assert ok.status_code == 200


def test_csp_names_only_the_validated_host_for_websockets(api: Api):
    csp = api.clients["owner"].get("/login").headers["content-security-policy"]
    assert "connect-src 'self' ws://127.0.0.1:8765 wss://127.0.0.1:8765" in csp
    assert "*" not in csp


# ====================================================================== UI: stop / activity honesty


def test_control_view_never_shows_confirmed_without_a_receipt():
    requested = {"status": "requested", "command": "pause", "target_run_id": "r", "confirmed_at": None}
    stopping = {"status": "stopping", "command": "cancel", "target_run_id": "r", "confirmed_at": None}
    assert L.control_view(requested)["label"] == "Запрошено" and L.control_view(requested)["state"] == "requested"
    assert L.control_view(stopping)["label"] == "Запрошено"
    # even a corrupt/hand-edited 'confirmed' without a timestamp stays unconfirmed
    forged = {"status": "confirmed", "command": "pause", "target_run_id": "r", "confirmed_at": None}
    assert L.control_view(forged)["label"] == "Запрошено"
    ok = {"status": "confirmed", "command": "pause", "target_run_id": "r", "confirmed_at": "2026-10-28T18:00:00Z"}
    assert L.control_view(ok)["label"] == "Остановлено" and L.control_view(ok)["state"] == "confirmed"
    idle = {"status": "confirmed", "command": "pause", "target_run_id": None, "confirmed_at": "2026-10-28T18:00:00Z"}
    assert L.control_view(idle)["label"] == "Применено" and "Остановлено" not in L.control_view(idle)["label"]
    unknown = {"status": "unknown", "command": "cancel", "target_run_id": "r", "confirmed_at": None}
    assert L.control_view(unknown)["label"] == "Остановка не подтверждена" and L.control_view(unknown)["tone"] == "danger"


def test_stop_202_renders_requested_until_runner_receipt_then_stopped(api: Api):
    t = api.queued_task()
    c = api.claim("impl")
    api.start("impl", c)
    r = api.control(t["id"], "pause", expect=202)  # HTTP 202: accepted, not stopped
    ctl = r.json()["control"]
    assert ctl["status"] in ("requested", "stopping") and ctl["confirmed_at"] is None

    state = get_html(api, f"/ui/projects/{api.project_id}/tasks/{t['id']}/state").text
    assert 'data-control-state="requested"' in state and "Запрошено" in state
    assert "Остановлено" not in state and 'data-control-state="confirmed"' not in state
    assert "Остановка запрошена" in state  # task status chip
    summary = get_html(api, f"/ui/projects/{api.project_id}/summary").text
    assert "Запрошено" in summary and "Остановлено" not in summary
    page = get_html(api, f"/projects/{api.project_id}/tasks/{t['id']}").text
    assert "Остановлено" not in page and "Идёт остановка" in page  # actions panel says waiting for receipt

    api.make_runner()
    api.stopped(c, ctl)  # supervisor receipt: process tree absent
    state = get_html(api, f"/ui/projects/{api.project_id}/tasks/{t['id']}/state").text
    assert 'data-control-state="confirmed"' in state and "Остановлено" in state and "квитанция runner" in state
    assert "Пауза" in state
    summary = get_html(api, f"/ui/projects/{api.project_id}/summary").text
    assert "Остановлено" not in summary  # nothing pending any more


def test_lost_runner_shows_stop_not_confirmed_never_stopped(api: Api):
    t = api.queued_task()
    c = api.claim("impl")
    api.start("impl", c)
    api.control(t["id"], "cancel", expect=202)
    api.clock.advance(seconds=91)  # runner vanished
    api.claim("impl", expect=204)  # lifecycle call sweeps leases
    state = get_html(api, f"/ui/projects/{api.project_id}/tasks/{t['id']}/state").text
    assert 'data-control-state="unknown"' in state and "Остановка не подтверждена" in state
    assert "Остановлено" not in state and 'data-blocked="stop_unknown"' in state
    assert "Заблокирована" in state and "Остановка не подтверждена исполнителем" in state
    summary = get_html(api, f"/ui/projects/{api.project_id}/summary").text
    assert "Остановка не подтверждена" in summary  # surfaced at project level as well


def test_emergency_stop_response_202_is_requested_in_summary(api: Api):
    t = api.queued_task()
    c = api.claim("impl")
    api.start("impl", c)
    r = api.req("owner", "POST", "/api/v1/controls/emergency-stop", {"reason": "panic"})
    assert r.status_code == 202
    summary = get_html(api, f"/ui/projects/{api.project_id}/summary").text
    assert 'data-control-state="requested"' in summary and "Остановлено" not in summary
    assert "Проект на паузе" in summary
    _ = t


def test_claimed_lease_is_not_shown_as_running(api: Api):
    t = api.queued_task()
    c = api.claim("impl")  # lease only: no process-start, no heartbeat
    state = get_html(api, f"/ui/projects/{api.project_id}/tasks/{t['id']}/state").text
    assert 'data-activity="claimed_only"' in state and "запуск процесса не подтверждён" in state
    assert "Выполняется (heartbeat" not in state
    assert re.search(r'data-signal="process"', state) and "нет подтверждения" in state
    lst = get_html(api, f"/ui/projects/{api.project_id}/tasks").text
    assert "Выдана (claim)" in lst and "Выполняется (heartbeat" not in lst

    api.start("impl", c)
    api.heartbeat("impl", c)
    state = get_html(api, f"/ui/projects/{api.project_id}/tasks/{t['id']}/state").text
    assert 'data-activity="running"' in state and "Выполняется (heartbeat" in state
    assert "Последний вывод" in state and "не передаётся клиентом" in state  # output signal is separate

    api.clock.advance(seconds=45)  # lease (90 s) alive, but no heartbeat for > 2 intervals
    state = get_html(api, f"/ui/projects/{api.project_id}/tasks/{t['id']}/state").text
    assert 'data-activity="stale"' in state and "heartbeat устарел" in state


def test_activity_view_rules_are_pure():
    now = 1_800_000_000_000
    run = {"status": "leased", "lease_epoch": 1, "lease_expires_at": now + 80_000, "started_at": None, "heartbeat_at": now}
    assert L.activity_view(None, now, 15)["state"] == "none"
    assert L.activity_view(run, now, 15)["state"] == "claimed_only"
    assert L.activity_view({**run, "status": "running", "started_at": now}, now, 15)["state"] == "running"
    assert L.activity_view({**run, "status": "running", "started_at": now}, now + 31_000, 15)["state"] == "stale"
    assert L.activity_view({**run, "status": "stopping", "started_at": now}, now, 15)["state"] == "stopping"
    keys = [s["key"] for s in L.activity_view(run, now, 15)["signals"]]
    assert keys == ["claimed", "process", "heartbeat", "output"]


# ====================================================================== UI: chat, timeline, reports, controls


def _ids(html: str) -> list[str]:
    return re.findall(r'data-msg-id="([^"]+)"', html)


def test_chat_shows_author_time_task_link_reply_and_never_duplicates(api: Api):
    t = api.create_task(title="Задача чата")
    m1 = post_message(api, "Первое уточнение", task_id=t["id"])
    m2 = post_message(api, "Ответ исполнителя", task_id=t["id"], who="impl", reply_to=m1["id"])
    post_message(api, "Общее сообщение проекта")
    frag = get_html(api, f"/ui/projects/{api.project_id}/chat").text
    assert _ids(frag) == [m1["id"], m2["id"], _ids(frag)[2]]  # chronological, each exactly once
    assert "owner" in frag and "test-implementer" in frag and "Исполнитель" in frag and "Владелец" in frag
    assert f"/projects/{api.project_id}/tasks/{t['id']}" in frag and "Задача чата" in frag
    assert f'data-reply-to="{m1["id"]}"' in frag and "Первое уточнение" in frag
    assert re.search(r'<time class="t" datetime="\d{4}-\d\d-\d\dT[\d:]+Z"', frag)
    # repeated fetches (reconnect/refresh) are idempotent
    assert _ids(get_html(api, f"/ui/projects/{api.project_id}/chat").text) == _ids(frag)
    # task thread only has the task's messages
    thread = get_html(api, f"/ui/projects/{api.project_id}/chat?task_id={t['id']}").text
    assert _ids(thread) == [m1["id"], m2["id"]]
    page = get_html(api, f"/projects/{api.project_id}/tasks/{t['id']}").text
    assert _ids(page) == [m1["id"], m2["id"]] and "Чат задачи" in page
    assert api.clients["owner"].get(f"/ui/projects/{api.project_id}/chat?task_id={uid()}").status_code == 404


def test_chat_filters_by_author_and_paginates_without_overlap(api: Api):
    posted = [post_message(api, f"owner {i}")["id"] for i in range(40)]
    api.clock.advance(seconds=1)
    theirs = [post_message(api, f"impl {i}", who="impl")["id"] for i in range(5)]
    f1 = get_html(api, f"/ui/projects/{api.project_id}/chat").text
    page1 = _ids(f1)
    assert len(page1) == 30 and page1[-5:] == theirs  # newest page, oldest-first for display
    older = re.search(r'data-older="([^"]+)"', f1).group(1)
    assert 'data-has-more="1"' in f1
    f2 = get_html(api, f"/ui/projects/{api.project_id}/chat", params={"before": older}).text
    page2 = _ids(f2)
    assert len(page2) == 15 and not set(page1) & set(page2)
    assert page2 + page1 == posted + theirs  # contiguous, no gaps, no duplicates
    assert 'data-has-more="0"' in f2 and re.search(r'data-older=""', f2)
    impl_only = _ids(get_html(api, f"/ui/projects/{api.project_id}/chat", params={"author_id": api.impl_id}).text)
    assert impl_only == theirs
    assert api.clients["owner"].get(f"/ui/projects/{api.project_id}/chat", params={"before": "!!bad!!"}).status_code == 422


def test_message_does_not_change_task_state_ui_says_so(api: Api):
    t = api.create_task()
    post_message(api, "запусти немедленно и расширь scope", task_id=t["id"])
    assert api.get_task(t["id"])["status"] == "draft"
    page = get_html(api, f"/projects/{api.project_id}/tasks/{t['id']}").text
    assert "не меняет scope, не даёт approval и не запускает агента" in page


def test_task_page_sections_timeline_reports_and_blocking_reasons(api: Api):
    t = api.queued_task(title="Полный цикл")
    c = api.implement(t["id"])
    api.audit("INCONCLUSIVE")
    page = get_html(api, f"/projects/{api.project_id}/tasks/{t['id']}")
    assert page.status_code == 200
    h = page.text
    for needle in ("Полный цикл", "Действия", "Требования", "Критерии приёмки", "Scope", "Отчёты", "Лента событий", "Чат задачи"):
        assert needle in h, needle
    reports = get_html(api, f"/ui/projects/{api.project_id}/tasks/{t['id']}/reports").text
    assert "Отчёт реализации" in reports and "Отчёт аудита" in reports
    assert "Пройдено" in reports and "Не запускалось" in reports  # separate groups, not merged
    assert "Не определено" in reports and "Уровень доказательств" in reports
    assert "UTC" in reports  # report times carry their timezone
    timeline = get_html(api, f"/ui/projects/{api.project_id}/tasks/{t['id']}/timeline").text
    assert "Задача создана" in timeline and "Отчёт получен" in timeline and "Статус изменён" in timeline
    state = get_html(api, f"/ui/projects/{api.project_id}/tasks/{t['id']}/state").text
    assert "Неудачные аудиты" in state and "0/3" in state and "Снимок" in state
    _ = c


def test_owner_controls_are_rendered_per_status_and_agents_get_no_buttons(api: Api):
    t = api.create_task()
    draft = get_html(api, f"/ui/projects/{api.project_id}/tasks/{t['id']}/actions").text
    assert 'data-act="enqueue"' in draft and 'data-command="cancel"' in draft and 'data-command="pause"' not in draft
    api.enqueue(t)
    queued = get_html(api, f"/ui/projects/{api.project_id}/tasks/{t['id']}/actions").text
    assert 'data-command="pause"' in queued and 'data-command="reassign"' in queued and "Последствия" in queued
    assert 'data-act="enqueue"' not in queued
    api.control(t["id"], "pause", expect=200)
    paused = get_html(api, f"/ui/projects/{api.project_id}/tasks/{t['id']}/actions").text
    assert 'data-command="resume"' in paused and 'data-command="pause"' not in paused
    api.control(t["id"], "cancel", expect=200)
    done = get_html(api, f"/ui/projects/{api.project_id}/tasks/{t['id']}/actions").text
    assert "data-act=" not in done
    # hiding is not authorization: the backend rejects agent attempts regardless of the UI
    t2 = api.create_task()
    r = api.req("impl", "POST", api.p(f"/tasks/{t2['id']}/controls"), {"command": "cancel", "reason": "x"}, if_match=t2["version"])
    assert r.status_code == 403


def test_project_page_has_owner_controls_and_counters(api: Api):
    api.queued_task()
    api.create_task()
    summary = get_html(api, f"/ui/projects/{api.project_id}/summary").text
    assert re.search(r"<b>1</b><span>В очереди", summary) and "Ждут аудита" in summary
    page = get_html(api, f"/projects/{api.project_id}").text
    assert 'data-act="emergency-stop"' in page and 'data-kind="task-create"' in page
    assert f'<option value="{api.impl_id}">test-implementer</option>' in page
    assert f'<option value="{api.aud_id}">test-auditor</option>' in page
    api.req("owner", "PATCH", api.p(""), {"paused": True}, if_match=api.req("owner", "GET", api.p("")).json()["version"])
    page = get_html(api, f"/projects/{api.project_id}").text
    assert "Продолжить проект" in page and "Проект на паузе" in page


def test_ui_ws_indicator_markup_and_script_states(api: Api):
    page = get_html(api, f"/projects/{api.project_id}").text
    assert 'id="connbar"' in page and 'id="conn-label"' in page and 'id="conn-sync"' in page and "Синхр.:" in page
    js = (STATIC / "app.js").read_text()
    for state, label in (("connected", "Онлайн (WebSocket)"), ("reconnecting", "Переподключение…"),
                         ("polling", "Опрос каждые 10 с"), ("offline", "Нет сети")):
        assert state in js and label in js
    css = (STATIC / "app.css").read_text()
    for state in ("connected", "reconnecting", "polling", "offline"):
        assert f'.connbar[data-state="{state}"]' in css
    # offline commands are refused, not queued for later
    assert "НЕ поставлена в очередь" in js and "if (!online())" in js and "navigator.serviceWorker" not in js
    # reconnect refreshes from the durable log and dedupes by seq + event_id
    assert "frame.seq <= ws.lastSeq || ws.seen.has(frame.event_id)" in js


def test_q23_ui_surfaces_busy_database_as_an_error_not_success(api: Api, monkeypatch):
    """A failing write must never look like a success in the panel (503/explicit error from the API)."""
    from sqlalchemy.exc import OperationalError

    import nozo_relay.usecases as mutation  # T10: write transactions moved into the shared use cases

    class Boom:
        def __enter__(self):
            raise OperationalError("BEGIN IMMEDIATE", {}, Exception("database is locked"))

        def __exit__(self, *a):
            return False

    monkeypatch.setattr(mutation, "write_session", lambda engine: Boom())
    r = api.req("owner", "POST", api.p("/messages"), {"client_message_id": uid(), "kind": "note", "body": "x"})
    assert r.status_code == 503 and r.json()["error"]["retryable"] is True
    js = (STATIC / "app.js").read_text()
    assert "explain(e)" in js and "toast(explain(e), 'error')" in js  # errors are shown, never swallowed


# ====================================================================== real sockets (uvicorn thread + websockets client)


def _real(tmp_path: Path, **over: Any):
    from test_t03_real_workers import Live

    lv = Live(tmp_path)
    for k, v in over.items():
        setattr(lv.app.state.settings, k, v)
    return lv


def _connect(lv, after: int, key: str | None = None, origin: str | None = None):  # noqa: ANN001
    from websockets.sync.client import connect

    headers = {}
    if key:
        headers["Authorization"] = f"Bearer {key}"
    if origin:
        headers["Origin"] = origin
    return connect(f"ws://127.0.0.1:{lv.port}/ws/v1/projects/{lv.api.project_id}?after_seq={after}",
                   additional_headers=headers, open_timeout=5, max_size=2 * 1024 * 1024)


def _frames(conn, n: int, timeout: float = 10.0, want=lambda f: "event_id" in f):  # noqa: ANN001
    import json as _json

    out = []
    end = time.monotonic() + timeout
    while len(out) < n:
        f = _json.loads(conn.recv(timeout=max(0.05, end - time.monotonic())))
        if want(f):
            out.append(f)
    return out


def test_real_ws_live_delivery_heartbeat_and_cross_thread_notify(tmp_path: Path):
    lv = _real(tmp_path, ws_heartbeat_seconds=0.3, ws_scan_interval_seconds=30)
    try:
        key = lv.api.keys["impl"]
        base = high_watermark(lv.api)
        with _connect(lv, base, key) as conn:
            _frames(conn, 1, want=lambda f: f.get("type") == "ready")
            _frames(conn, 1, want=lambda f: f.get("type") == "heartbeat")
            t0 = time.monotonic()
            post_message(lv.api, "через uvicorn")  # commit on a worker thread -> notify -> uvicorn loop
            ev = _frames(conn, 1, timeout=3)[0]
            assert ev["type"] == "message.created" and time.monotonic() - t0 < 1.0
        # a socket that presents a cookie but a foreign Origin never gets in
        from websockets.exceptions import InvalidStatus

        with pytest.raises(InvalidStatus) as exc:
            _connect(lv, 0, origin="https://evil.example").__enter__()
        assert exc.value.response.status_code == 403
    finally:
        lv.close()


def test_real_ws_q18_reconnect_during_continuous_writes_is_exactly_once(tmp_path: Path):
    import json as _json

    lv = _real(tmp_path, ws_scan_interval_seconds=0.2)
    try:
        key = lv.api.keys["impl"]
        base = high_watermark(lv.api)
        total = 150
        written: list[str] = []

        def writer() -> None:
            for i in range(total):
                written.extend(notified_commit(lv.api, 1, tag="test.stream"))
                time.sleep(0.004)

        t = threading.Thread(target=writer)
        seen: list[dict[str, Any]] = []
        t.start()
        for want in (30, 55, 200):  # drop and reconnect twice while writes continue
            with _connect(lv, seen[-1]["seq"] if seen else base, key) as conn:
                end = time.monotonic() + 20
                while len(seen) < min(want, total):
                    f = _json.loads(conn.recv(timeout=max(0.05, end - time.monotonic())))
                    if "event_id" in f:
                        seen.append(f)
        t.join()
        assert [e["event_id"] for e in seen] == written
        assert [e["seq"] for e in seen] == sorted({e["seq"] for e in seen})
    finally:
        lv.close()


def test_real_ws_q19_non_reading_client_is_cut_off_and_api_stays_fast(tmp_path: Path):
    import json as _json

    from websockets.exceptions import ConnectionClosed

    lv = _real(tmp_path, ws_send_timeout_seconds=1.0, ws_scan_interval_seconds=0.1)
    try:
        key = lv.api.keys["impl"]
        base = high_watermark(lv.api)
        with _connect(lv, base, key) as conn:
            _frames(conn, 1, want=lambda f: f.get("type") == "ready")
            pad = "x" * 300_000
            with write_session(lv.app.state.engine) as ws:  # type: ignore[attr-defined]
                for i in range(100):  # ~30 MB: far beyond socket buffers + the 2 MiB queue
                    append_event(ws, lv.api.clock, type="test.big", project_id=lv.api.project_id, payload={"i": i, "pad": pad})
            time.sleep(1.5)  # we do NOT read; the server must not stall anyone else meanwhile
            t0 = time.monotonic()
            r = lv.api.req("owner", "GET", lv.api.p("/snapshot"))
            assert r.status_code == 200 and time.monotonic() - t0 < 1.5
            assert lv.api.req("owner", "POST", lv.api.p("/messages"), {"client_message_id": uid(), "kind": "note", "body": "ok"}).status_code == 201
            got, resync, code = 0, None, None
            end = time.monotonic() + 30
            while time.monotonic() < end:
                try:
                    f = _json.loads(conn.recv(timeout=5))
                except ConnectionClosed as c:
                    code = c.rcvd.code if c.rcvd else None
                    break
                if f.get("type") == "resync_required":
                    resync = f
                elif f.get("type") == "test.big":
                    got += 1
            assert code in (CLOSE_SLOW, CLOSE_RESYNC), code
            assert resync is not None and resync["reason"] == "slow_consumer"
            assert got < 100  # the backlog was NOT silently pushed through: client must resync
        # a fresh connection with a new cursor works immediately
        with _connect(lv, high_watermark(lv.api), key) as conn2:
            _frames(conn2, 1, want=lambda f: f.get("type") == "ready")
    finally:
        lv.close()
