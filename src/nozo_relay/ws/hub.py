"""WebSocket hub: per-project connection registry + durable event delivery.

Design (04_API_CONTRACTS "WebSocket", 03_DATA_MODEL invariant "events are the source of truth"):

* Events are read from the **database**, never taken from an in-memory payload. ``Hub.notify`` only
  wakes connections sooner; a periodic scan (``ws_scan_interval_seconds``) catches events whose
  commit was not followed by a notification (crash/commit-without-notify, closed loop, ...).
* Each connection owns a cursor (``last seq`` handed to its queue). Frames are queued strictly in
  ascending ``seq`` order so every event is delivered at most once per connection (dedup by seq);
  gaps in the project sequence are normal (the sequence is global).
* Catch-up (replay of ``seq > after_seq``) is back-pressured and bounded by the watermark taken at
  connect time; afterwards the connection is *live* and a consumer that falls behind the bounded queue
  (1000 events / 2 MiB by default) receives ``resync_required`` and is disconnected. A slow consumer
  never blocks writers: writers only call ``notify`` (non-blocking, thread-safe).
* Liveness: heartbeat frame every ``ws_heartbeat_seconds`` of silence. Authorisation (session /
  credential / membership) is re-validated periodically and can be revoked immediately.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import logging
import threading
from collections import deque
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from typing import Any, Protocol

from sqlalchemy import func, select
from sqlalchemy.orm import Session, sessionmaker

from nozo_relay.clock import Clock, ms_to_rfc3339
from nozo_relay.config import Settings
from nozo_relay.db.models import Event
from nozo_relay.services.events import SCHEMA_VERSION, event_to_dict

log = logging.getLogger("nozo_relay.ws")

# Application close codes (4000-4999 are free for applications).
CLOSE_NORMAL = 1000
CLOSE_GOING_AWAY = 1001
CLOSE_POLICY = 1008
CLOSE_TRY_LATER = 1013
CLOSE_AUTH_LOST = 4401  # session expired / revoked, key revoked, membership lost
CLOSE_RESYNC = 4410  # client must reload a snapshot and reconnect with a fresh cursor
CLOSE_SLOW = 4411


class Transport(Protocol):
    async def send_text(self, text: str) -> None: ...

    async def receive_text(self) -> str: ...  # raises on disconnect

    async def close(self, code: int, reason: str) -> None: ...


@dataclass(frozen=True, slots=True)
class Identity:
    """Who a connection acts for. Only digests/ids are kept, never a raw cookie or key."""

    principal_id: str
    project_id: str
    session_digest: str | None = None
    credential_id: str | None = None


@dataclass(frozen=True, slots=True)
class Item:
    seq: int
    text: str
    size: int


def _dumps(obj: dict[str, Any]) -> str:
    return json.dumps(obj, separators=(",", ":"), ensure_ascii=False)


class FrameQueue:
    """Bounded FIFO accounted in events and bytes. Single consumer, loop-affine."""

    def __init__(self, max_events: int, max_bytes: int) -> None:
        self.max_events = max_events
        self.max_bytes = max_bytes
        self._items: deque[Item] = deque()
        self.bytes = 0
        self._not_empty = asyncio.Event()
        self._room = asyncio.Event()
        self._room.set()

    def __len__(self) -> int:
        return len(self._items)

    def _fits(self, size: int) -> bool:
        return len(self._items) + 1 <= self.max_events and self.bytes + size <= self.max_bytes

    def try_put(self, item: Item) -> bool:
        """Non-blocking put. False (nothing queued) when a bound would be exceeded."""
        if not self._fits(item.size):
            return False
        self._append(item)
        return True

    def _append(self, item: Item) -> None:
        self._items.append(item)
        self.bytes += item.size
        self._not_empty.set()
        if not self._fits(0):
            self._room.clear()

    async def put_wait(self, item: Item) -> None:
        """Back-pressured put (catch-up phase). An oversize single item is admitted to an empty queue."""
        while not self._fits(item.size) and self._items:
            self._room.clear()
            await self._room.wait()
        self._append(item)

    async def get(self) -> Item:
        while not self._items:
            self._not_empty.clear()
            await self._not_empty.wait()
        item = self._items.popleft()
        self.bytes -= item.size
        if not self._items:
            self._not_empty.clear()
        if self._fits(0):
            self._room.set()
        return item

    def clear(self) -> None:
        self._items.clear()
        self.bytes = 0
        self._not_empty.clear()
        self._room.set()


@dataclass(slots=True)
class _Stop:
    code: int
    reason: str
    frame: dict[str, Any] | None = None


class Connection:
    """One authenticated subscriber of one project. Lives on the event loop that created it."""

    def __init__(
        self,
        hub: Hub,
        identity: Identity,
        after_seq: int,
        transport: Transport,
        revalidate: Callable[[], Awaitable[str | None]] | None = None,
    ) -> None:
        self.hub = hub
        self.identity = identity
        self.after_seq = after_seq
        self.transport = transport
        self._revalidate = revalidate
        s = hub.settings
        self.queue = FrameQueue(s.ws_queue_max_events, s.ws_queue_max_bytes)
        self.loop = asyncio.get_running_loop()
        self.wake = asyncio.Event()
        self._stop: _Stop | None = None
        self._stopped = asyncio.Event()
        self.cursor = after_seq  # highest seq handed to the queue
        self.sent_events = 0
        self.live = False

    # ------------------------------------------------------------ thread-safe controls
    def poke(self) -> None:
        """Wake the pump (safe from any thread; a closed loop is ignored)."""
        with contextlib.suppress(RuntimeError):
            self.loop.call_soon_threadsafe(self.wake.set)

    def request_close(self, code: int, reason: str) -> None:
        with contextlib.suppress(RuntimeError):
            self.loop.call_soon_threadsafe(self._set_stop, code, reason, None)

    def _set_stop(self, code: int, reason: str, frame: dict[str, Any] | None) -> None:
        if self._stop is None:
            self._stop = _Stop(code, reason, frame)
            self._stopped.set()

    # ------------------------------------------------------------ coroutines
    async def run(self) -> None:
        """Serve until the client leaves or the connection is closed by policy."""
        tasks = [
            asyncio.create_task(self._pump(), name="ws-pump"),
            asyncio.create_task(self._sender(), name="ws-sender"),
            asyncio.create_task(self._receiver(), name="ws-receiver"),
            asyncio.create_task(self._auth_watch(), name="ws-auth"),
            asyncio.create_task(self._stopped.wait(), name="ws-stop"),
        ]
        try:
            await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
        finally:
            for t in tasks:
                t.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)
            for t in tasks:  # surface programming errors in logs, never to the client
                if t.done() and not t.cancelled() and t.exception():
                    log.error("ws task %s failed", t.get_name(), exc_info=t.exception())
            stop = self._stop or _Stop(CLOSE_NORMAL, "bye")
            self.queue.clear()
            if stop.frame is not None:
                with contextlib.suppress(Exception):
                    await asyncio.wait_for(self.transport.send_text(_dumps(stop.frame)), 2.0)
            with contextlib.suppress(Exception):
                await asyncio.wait_for(self.transport.close(stop.code, stop.reason), 2.0)

    def _resync(self, reason: str, code: int = CLOSE_RESYNC) -> None:
        self.queue.clear()
        self._set_stop(
            code,
            reason,
            {
                "schema_version": SCHEMA_VERSION,
                "type": "resync_required",
                "reason": reason,
                "high_watermark": self.cursor,
            },
        )

    async def _pump(self) -> None:
        hub, pid, batch = self.hub, self.identity.project_id, self.hub.settings.ws_batch_size
        watermark = await hub.run_db(hub.watermark, pid)
        if self.after_seq > watermark:
            # Client is ahead of this server's log (restored DB / wrong server): force a new snapshot.
            self._resync("cursor_ahead")
            return
        # Catch-up: back-pressured replay of the durable log up to the connect-time watermark.
        while self.cursor < watermark:
            items = await hub.run_db(hub.fetch, pid, self.cursor, batch)
            if not items:
                break
            for it in items:
                await self.queue.put_wait(it)
                self.cursor = it.seq
        ready = _dumps(
            {"schema_version": SCHEMA_VERSION, "type": "ready", "project_id": pid,
             "high_watermark": max(watermark, self.cursor), "server_time": ms_to_rfc3339(hub.clock.now_ms())}
        )
        await self.queue.put_wait(Item(0, ready, len(ready)))
        self.live = True
        interval = hub.settings.ws_scan_interval_seconds
        while True:
            self.wake.clear()  # clear BEFORE reading: a notify during the read re-arms it
            while True:
                items = await hub.run_db(hub.fetch, pid, self.cursor, batch)
                for it in items:
                    if not self.queue.try_put(it):
                        self._resync("slow_consumer", CLOSE_SLOW)
                        return
                    self.cursor = it.seq
                if len(items) < batch:
                    break
            with contextlib.suppress(TimeoutError):
                await asyncio.wait_for(self.wake.wait(), interval)

    async def _sender(self) -> None:
        s = self.hub.settings
        while True:
            seq = 0
            try:
                item = await asyncio.wait_for(self.queue.get(), s.ws_heartbeat_seconds)
            except TimeoutError:
                text = _dumps(
                    {"schema_version": SCHEMA_VERSION, "type": "heartbeat",
                     "server_time": ms_to_rfc3339(self.hub.clock.now_ms())}
                )
            else:
                text, seq = item.text, item.seq
            try:
                await asyncio.wait_for(self.transport.send_text(text), s.ws_send_timeout_seconds)
            except TimeoutError:
                self._resync("slow_consumer", CLOSE_SLOW)
                return
            if seq > 0:
                self.sent_events += 1

    async def _receiver(self) -> None:
        """Clients send nothing meaningful; reading detects disconnects. Oversize frames are refused."""
        while True:
            try:
                text = await self.transport.receive_text()
            except Exception:  # noqa: BLE001 - any receive failure == the client is gone
                return
            if len(text) > 4096:
                self._set_stop(1009, "frame too large", None)
                return

    async def _auth_watch(self) -> None:
        if self._revalidate is None:
            await asyncio.Event().wait()
        interval = self.hub.settings.ws_auth_recheck_seconds
        while True:
            await asyncio.sleep(interval)
            try:
                lost = await self._revalidate()  # type: ignore[misc]
            except Exception:  # noqa: BLE001 - DB busy: keep the connection, retry next tick
                log.warning("ws auth recheck failed", exc_info=True)
                continue
            if lost is not None:
                self._set_stop(CLOSE_AUTH_LOST, lost, None)
                return


class Hub:
    """Registry of live connections + DB access used by them."""

    def __init__(
        self, settings: Settings, clock: Clock, session_factory: sessionmaker[Session]
    ) -> None:
        self.settings = settings
        self.clock = clock
        self._factory = session_factory
        self._lock = threading.Lock()
        self._conns: dict[str, set[Connection]] = {}
        self.stats = {"notified": 0, "resync": 0, "connections_total": 0}

    # ------------------------------------------------------------ registry
    def register(self, conn: Connection) -> None:
        with self._lock:
            self._conns.setdefault(conn.identity.project_id, set()).add(conn)
            self.stats["connections_total"] += 1

    def unregister(self, conn: Connection) -> None:
        with self._lock:
            group = self._conns.get(conn.identity.project_id)
            if group is not None:
                group.discard(conn)
                if not group:
                    del self._conns[conn.identity.project_id]

    def connection_count(self, project_id: str | None = None) -> int:
        with self._lock:
            if project_id is not None:
                return len(self._conns.get(project_id, ()))
            return sum(len(g) for g in self._conns.values())

    def count_for_principal(self, principal_id: str) -> int:
        with self._lock:
            return sum(1 for g in self._conns.values() for c in g if c.identity.principal_id == principal_id)

    def _snapshot_conns(self) -> list[Connection]:
        with self._lock:
            return [c for g in self._conns.values() for c in g]

    # ------------------------------------------------------------ signals (any thread)
    def notify(self, project_ids: frozenset[str] | set[str] | None = None) -> None:
        """Wake subscribers of the given projects (None = all). Never blocks, never raises."""
        self.stats["notified"] += 1
        with self._lock:
            targets = [
                c
                for pid, g in self._conns.items()
                if project_ids is None or pid in project_ids
                for c in g
            ]
        for c in targets:
            c.poke()

    def close_session(self, session_digest: str, reason: str = "session_revoked") -> int:
        return self._close_where(lambda c: c.identity.session_digest == session_digest, reason)

    def close_credential(self, credential_id: str, reason: str = "credential_revoked") -> int:
        return self._close_where(lambda c: c.identity.credential_id == credential_id, reason)

    def close_principal(self, principal_id: str, reason: str = "principal_revoked") -> int:
        return self._close_where(lambda c: c.identity.principal_id == principal_id, reason)

    def close_all(self, reason: str = "server_shutdown") -> int:
        return self._close_where(lambda c: True, reason, CLOSE_GOING_AWAY)

    def _close_where(
        self, pred: Callable[[Connection], bool], reason: str, code: int = CLOSE_AUTH_LOST
    ) -> int:
        victims = [c for c in self._snapshot_conns() if pred(c)]
        for c in victims:
            c.request_close(code, reason)
        return len(victims)

    # ------------------------------------------------------------ DB access (worker thread)
    async def run_db(self, fn: Callable[..., Any], *args: Any) -> Any:
        return await asyncio.to_thread(fn, *args)

    def watermark(self, project_id: str) -> int:
        with self._factory() as db:
            try:
                return db.execute(
                    select(func.coalesce(func.max(Event.seq), 0)).where(Event.project_id == project_id)
                ).scalar_one()
            finally:
                db.rollback()

    def fetch(self, project_id: str, after_seq: int, limit: int) -> list[Item]:
        """Committed events ``seq > after_seq`` (ascending), pre-serialised for the wire."""
        with self._factory() as db:
            try:
                rows = (
                    db.execute(
                        select(Event)
                        .where(Event.project_id == project_id, Event.seq > after_seq)
                        .order_by(Event.seq)
                        .limit(limit)
                    )
                    .scalars()
                    .all()
                )
                out = []
                for e in rows:
                    text = _dumps(event_to_dict(e))
                    out.append(Item(e.seq, text, len(text.encode("utf-8"))))
                return out
            finally:
                db.rollback()
