"""SQLite engine: WAL, synchronous=FULL, busy_timeout, foreign_keys=ON, single-writer friendly."""

from __future__ import annotations

import os
import sqlite3
from collections.abc import Iterator
from collections.abc import Callable
from contextlib import contextmanager
from pathlib import Path
from weakref import WeakKeyDictionary

from sqlalchemy import Engine, create_engine, event
from sqlalchemy.orm import Session, sessionmaker

from nozo_relay.config import Settings

DEFAULT_BUSY_TIMEOUT_MS = 5000


def _apply_pragmas(dbapi_conn: sqlite3.Connection, busy_timeout_ms: int) -> None:
    # Autocommit at the driver level: SQLAlchemy emits BEGIN itself (see "begin" listener),
    # which avoids pysqlite's legacy implicit transaction handling.
    dbapi_conn.isolation_level = None
    cur = dbapi_conn.cursor()
    try:
        cur.execute("PRAGMA journal_mode=WAL")
        cur.execute("PRAGMA synchronous=FULL")
        cur.execute(f"PRAGMA busy_timeout={int(busy_timeout_ms)}")
        cur.execute("PRAGMA foreign_keys=ON")
    finally:
        cur.close()


def create_sqlite_engine(
    db_path: Path | str, *, busy_timeout_ms: int = DEFAULT_BUSY_TIMEOUT_MS
) -> Engine:
    path = Path(db_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    engine = create_engine(
        f"sqlite:///{path}",
        connect_args={"check_same_thread": False, "timeout": busy_timeout_ms / 1000},
        pool_pre_ping=False,
    )

    @event.listens_for(engine, "connect")
    def _on_connect(dbapi_conn: sqlite3.Connection, _record: object) -> None:
        _apply_pragmas(dbapi_conn, busy_timeout_ms)

    @event.listens_for(engine, "begin")
    def _on_begin(conn) -> None:  # noqa: ANN001
        # Writers may request IMMEDIATE via execution_options(sqlite_begin="IMMEDIATE") so that
        # claim-style transactions take the write lock up front (03_DATA_MODEL invariant 1).
        mode = conn.get_execution_options().get("sqlite_begin", "DEFERRED")
        if mode not in {"DEFERRED", "IMMEDIATE"}:
            raise ValueError(f"invalid sqlite_begin mode: {mode!r}")
        conn.exec_driver_sql(f"BEGIN {mode}")

    if path.exists():
        _secure_file(path)
    return engine


def _secure_file(path: Path) -> None:
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass


def create_engine_from_settings(settings: Settings) -> Engine:
    settings.data_dir.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(settings.data_dir, 0o700)
    except OSError:
        pass
    engine = create_sqlite_engine(settings.db_path, busy_timeout_ms=settings.sqlite_busy_timeout_ms)
    with engine.connect() as conn:  # materialise the file so it can be chmod-ed
        conn.exec_driver_sql("SELECT 1")
    _secure_file(settings.db_path)
    return engine


def make_session_factory(engine: Engine) -> sessionmaker[Session]:
    return sessionmaker(bind=engine, expire_on_commit=False, autoflush=False)


# Post-commit listeners per engine. They receive the project ids whose events were committed by a
# write transaction. They are only an acceleration signal: consumers must also scan the durable log.
CommitListener = Callable[[frozenset[str]], None]
_COMMIT_LISTENERS: WeakKeyDictionary[Engine, list[CommitListener]] = WeakKeyDictionary()
EVENT_PROJECTS_KEY = "event_projects"


def add_commit_listener(engine: Engine, listener: CommitListener) -> None:
    _COMMIT_LISTENERS.setdefault(engine, []).append(listener)


def _fire_commit_listeners(engine: Engine, projects: frozenset[str]) -> None:
    for listener in list(_COMMIT_LISTENERS.get(engine, ())):
        try:
            listener(projects)
        except Exception:  # noqa: BLE001 - a notification failure must never fail a committed write
            pass


@contextmanager
def write_session(engine: Engine) -> Iterator[Session]:
    """Session whose transaction starts with BEGIN IMMEDIATE (single-writer friendly).

    After a successful COMMIT the commit listeners are told which projects got new events
    (``append_event`` records them in ``session.info``). A rollback never notifies.
    """
    bound = engine.execution_options(sqlite_begin="IMMEDIATE")
    with Session(bind=bound, expire_on_commit=False, autoflush=False) as session:
        try:
            yield session
            session.commit()
        except BaseException:
            session.rollback()
            raise
        projects = session.info.pop(EVENT_PROJECTS_KEY, None)
    if projects:
        _fire_commit_listeners(engine, frozenset(projects))


def pragma_value(engine: Engine, name: str) -> object:
    with engine.connect() as conn:
        return conn.exec_driver_sql(f"PRAGMA {name}").scalar()
