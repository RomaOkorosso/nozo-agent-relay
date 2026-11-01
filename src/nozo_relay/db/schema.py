"""Schema creation and version gate. Incompatible schema/runtime is rejected, never auto-migrated."""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass

from sqlalchemy import Engine, inspect, select, text
from sqlalchemy.orm import Session

from nozo_relay.clock import Clock, SystemClock
from nozo_relay.db.models import Base, SchemaVersion

# v2: BlockedReason CHECK widened (recovery_required, scope_change_required, ...). Pre-release:
# no migration path from v1 (re-bootstrap a fresh database).
# v3 (T06): additive columns only (projects.last_claimed_at, sessions.reauth_at, approval_requests.
# summary/action_json/revision/decided_at/decision_reason) + one index. ``migrate_to_current`` upgrades
# a v2 database in place (after the caller took a backup); v1 still needs a re-bootstrap.
# v4 (T07): additive ``repo_bindings`` columns only (created_at, registered_by, baseline_policy,
# approved_tree_hash, approved_at, quarantined_at). ``migrate_to_current`` upgrades v2/v3 in place; each
# ADD COLUMN is skipped when the column already exists, so the step is idempotent.
# v5 (T12/F02): additive ``runs.supervisor_principal_id`` (FK principals, nullable for old rows). ``migrate_to_current``
# upgrades v2/v3/v4 in place; the ADD COLUMN is skipped when the column already exists.
# v6: widen ``controls.command`` CHECK to include ``complete`` (owner/coordinator force-complete of
# idle tasks). Controls table rebuild only; ``tasks.desired_control`` CHECK unchanged on migrated DBs
# (idle complete never sets desired_control). Fresh installs get both CHECKs from the enum.
SCHEMA_VERSION = 6
_V3_ADDITIONS: tuple[str, ...] = (
    "ALTER TABLE projects ADD COLUMN last_claimed_at BIGINT",
    "ALTER TABLE sessions ADD COLUMN reauth_at BIGINT",
    "ALTER TABLE approval_requests ADD COLUMN summary TEXT NOT NULL DEFAULT ''",
    "ALTER TABLE approval_requests ADD COLUMN action_json TEXT NOT NULL DEFAULT '{}'",
    "ALTER TABLE approval_requests ADD COLUMN revision INTEGER",
    "ALTER TABLE approval_requests ADD COLUMN decided_at BIGINT",
    "ALTER TABLE approval_requests ADD COLUMN decision_reason TEXT",
    "CREATE INDEX IF NOT EXISTS ix_approvals_project_status ON approval_requests (project_id, status)",
)
_V4_ADDITIONS: tuple[tuple[str, str, str], ...] = (
    ("repo_bindings", "created_at", "BIGINT"),
    ("repo_bindings", "registered_by", "VARCHAR(36)"),
    ("repo_bindings", "baseline_policy", "VARCHAR(24) NOT NULL DEFAULT 'clean'"),
    ("repo_bindings", "approved_tree_hash", "VARCHAR(64)"),
    ("repo_bindings", "approved_at", "BIGINT"),
    ("repo_bindings", "quarantined_at", "BIGINT"),
)
_V5_ADDITIONS: tuple[tuple[str, str, str], ...] = (
    ("runs", "supervisor_principal_id", "VARCHAR(36) REFERENCES principals(id)"),
)
MIN_SQLITE_VERSION = (3, 35, 0)  # RETURNING, reliable ALTER/partial index behaviour


class SchemaError(RuntimeError):
    """Raised when the database or SQLite runtime is not compatible."""


@dataclass(frozen=True)
class SqliteRuntime:
    version: str
    wal_reset_bug_fixed: bool


def sqlite_runtime() -> SqliteRuntime:
    v = sqlite3.sqlite_version_info
    # WAL-reset corruption bug: present 3.7.0 .. 3.51.2; fixed in 3.44.6, 3.50.7, 3.51.3.
    fixed = v >= (3, 51, 3) or (3, 50, 7) <= v < (3, 51, 0) or (3, 44, 6) <= v < (3, 45, 0)
    return SqliteRuntime(version=sqlite3.sqlite_version, wal_reset_bug_fixed=fixed)


def check_sqlite_runtime(*, require_wal_fix: bool = False) -> SqliteRuntime:
    if sqlite3.sqlite_version_info < MIN_SQLITE_VERSION:
        raise SchemaError(
            f"SQLite {sqlite3.sqlite_version} is too old (need >= "
            f"{'.'.join(map(str, MIN_SQLITE_VERSION))})"
        )
    rt = sqlite_runtime()
    if require_wal_fix and not rt.wal_reset_bug_fixed:
        raise SchemaError(f"SQLite {rt.version} lacks the WAL-reset bug fix (need 3.44.6/3.50.7/3.51.3+)")
    return rt


def read_schema_version(engine: Engine) -> int | None:
    """Return stored version, or None if the schema_version table does not exist."""
    if "schema_version" not in inspect(engine).get_table_names():
        return None
    with Session(engine) as s:
        row = s.execute(select(SchemaVersion.version).where(SchemaVersion.id == 1)).scalar()
    return row


def ensure_schema(
    engine: Engine, clock: Clock | None = None, *, require_wal_fix: bool = False
) -> int:
    """Create the schema on an empty DB; verify version otherwise. Idempotent."""
    check_sqlite_runtime(require_wal_fix=require_wal_fix)
    clock = clock or SystemClock()
    tables = set(inspect(engine).get_table_names())
    if not tables:
        # Single transaction: either the whole schema + version exists, or nothing.
        with engine.begin() as conn:
            Base.metadata.create_all(conn)
            conn.execute(
                text("INSERT INTO schema_version (id, version, applied_at) VALUES (1, :v, :t)"),
                {"v": SCHEMA_VERSION, "t": clock.now_ms()},
            )
        return SCHEMA_VERSION

    if "schema_version" not in tables:
        raise SchemaError("database has tables but no schema_version; refusing to touch it")
    found = read_schema_version(engine)
    if found != SCHEMA_VERSION:
        raise SchemaError(
            f"incompatible schema version {found!r}; this build requires {SCHEMA_VERSION}. "
            "Back up the database and run a migration with the runner stopped."
        )
    missing = {t.name for t in Base.metadata.sorted_tables} - tables
    if missing:
        raise SchemaError(f"schema version ok but tables missing: {sorted(missing)}")
    return found


def _has_column(conn, table: str, column: str) -> bool:  # noqa: ANN001
    return any(r[1] == column for r in conn.execute(text(f"PRAGMA table_info({table})")).fetchall())


_V6_CONTROL_COMMANDS = (
    "pause",
    "resume",
    "cancel",
    "reassign",
    "revise",
    "complete",
    "emergency_stop",
)


def _widen_control_command_checks(conn) -> None:  # noqa: ANN001
    """Rebuild ``controls.command`` CHECK so ``complete`` is accepted (SQLite cannot ALTER CHECK).

    Idle force-complete never writes ``tasks.desired_control='complete'``, so the tasks CHECK is left
    unchanged (avoiding a heavy rebuild under live FKs). Fresh DBs created by ``ensure_schema`` still
    get both CHECKs from the current ``ControlCommand`` enum.
    """
    cmds = ",".join(f"'{c}'" for c in _V6_CONTROL_COMMANDS)
    # Disable FK checks for the duration of this connection (table swap).
    conn.execute(text("PRAGMA foreign_keys=OFF"))
    row = conn.execute(text("SELECT sql FROM sqlite_master WHERE type='table' AND name='controls'")).scalar()
    if row and "'complete'" in row:
        return
    conn.execute(
        text(
            f"""
            CREATE TABLE controls__v6 (
                id VARCHAR(36) NOT NULL,
                project_id VARCHAR(36) NOT NULL,
                task_id VARCHAR(36),
                command VARCHAR(16) NOT NULL,
                requested_by VARCHAR(36) NOT NULL,
                target_run_id VARCHAR(36),
                target_epoch INTEGER,
                status VARCHAR(16) NOT NULL,
                payload_json TEXT NOT NULL,
                reason TEXT NOT NULL,
                requested_at BIGINT NOT NULL,
                confirmed_at BIGINT,
                PRIMARY KEY (id),
                CONSTRAINT fk_controls_task_project FOREIGN KEY(task_id, project_id) REFERENCES tasks (id, project_id),
                CONSTRAINT ck_command_enum CHECK (command IN ({cmds})),
                CONSTRAINT ck_status_enum CHECK (status IN ('requested','stopping','confirmed','unknown')),
                CONSTRAINT ck_payload_json_json CHECK (json_valid(payload_json)),
                FOREIGN KEY(project_id) REFERENCES projects (id),
                FOREIGN KEY(requested_by) REFERENCES principals (id),
                FOREIGN KEY(target_run_id) REFERENCES runs (id)
            )
            """
        )
    )
    conn.execute(
        text(
            "INSERT INTO controls__v6 SELECT id, project_id, task_id, command, requested_by, "
            "target_run_id, target_epoch, status, payload_json, reason, requested_at, confirmed_at FROM controls"
        )
    )
    conn.execute(text("DROP TABLE controls"))
    conn.execute(text("ALTER TABLE controls__v6 RENAME TO controls"))
    conn.execute(text("CREATE INDEX IF NOT EXISTS ix_controls_project_id ON controls (project_id)"))


def migrate_to_current(engine: Engine, clock: Clock | None = None) -> tuple[int, int]:
    """In-place migration v2/v3/v4/v5 -> v6. Returns (from, to). Run with the server stopped, after a backup.

    Only a v2–v5 database is accepted; anything else is refused (never guess). Atomic: one transaction.
    """
    clock = clock or SystemClock()
    found = read_schema_version(engine)
    if found == SCHEMA_VERSION:
        return found, found
    if found not in (2, 3, 4, 5):
        raise SchemaError(f"cannot migrate schema {found!r}; only v2/v3/v4/v5 -> v{SCHEMA_VERSION} is supported")
    with engine.begin() as conn:
        if found == 2:
            for stmt in _V3_ADDITIONS:
                if stmt.startswith("ALTER TABLE"):
                    _, _, table, _, _, column, *_ = stmt.split()
                    if _has_column(conn, table, column):
                        continue
                conn.execute(text(stmt))
        if found in (2, 3, 4):
            for table, column, ddl in _V4_ADDITIONS:
                if not _has_column(conn, table, column):
                    conn.execute(text(f"ALTER TABLE {table} ADD COLUMN {column} {ddl}"))
            for table, column, ddl in _V5_ADDITIONS:
                if not _has_column(conn, table, column):
                    conn.execute(text(f"ALTER TABLE {table} ADD COLUMN {column} {ddl}"))
        _widen_control_command_checks(conn)
        conn.execute(
            text("UPDATE schema_version SET version = :v, applied_at = :t WHERE id = 1"),
            {"v": SCHEMA_VERSION, "t": clock.now_ms()},
        )
    return found, SCHEMA_VERSION
