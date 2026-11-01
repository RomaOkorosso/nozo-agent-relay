"""Backup / restore / schema-checked migration (Q24). CLI only: ``python -m nozo_relay backup|restore``.

Backup = SQLite *online backup API* (consistent while the server runs) + referenced artifact files +
``manifest.json`` (sha256 of every file, table counts, schema version, last event seq). The manifest is
written last: a directory without it is not a backup.

Restore ALWAYS goes to a NEW (or empty) directory and never deletes or overwrites anything. The restored
copy gets: every session revoked, every active run marked lost (``recovery_required``), and one
``system.restored`` event. The original data dir and the backup stay untouched.

Not included on purpose: ``bootstrap_credentials.json`` (secrets) and ``.env``. The DB holds only
hashes/digests (password hashes, key digests, session digests), but it is still sensitive: files are
created 0600 in 0700 directories.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import sqlite3
from pathlib import Path
from typing import Any

from nozo_relay import __version__
from nozo_relay.clock import Clock, SystemClock, ms_to_rfc3339
from nozo_relay.config import Settings
from nozo_relay.db.schema import SCHEMA_VERSION, SchemaError

BACKUP_FORMAT = 1
MANIFEST = "manifest.json"
DB_NAME = "relay.sqlite"
EXCLUDED = ["bootstrap_credentials.json", ".env"]


class BackupError(RuntimeError):
    pass


# ------------------------------------------------------------------ helpers


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _private_dir(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)
    os.chmod(path, 0o700)


def _require_empty_target(path: Path, what: str) -> None:
    if path.exists():
        if not path.is_dir():
            raise BackupError(f"{what} {path} exists and is not a directory")
        if any(path.iterdir()):
            raise BackupError(f"{what} {path} is not empty; refusing to touch it (choose a NEW directory)")


def _copy_private(src: Path, dst: Path) -> None:
    _private_dir(dst.parent)
    tmp = dst.with_name(f".{dst.name}.tmp")
    shutil.copyfile(src, tmp)
    os.chmod(tmp, 0o600)
    with open(tmp, "rb") as fh:
        os.fsync(fh.fileno())
    os.replace(tmp, dst)


def _tables(conn: sqlite3.Connection) -> list[str]:
    rows = conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name"
    ).fetchall()
    return [r[0] for r in rows]


def _counts(conn: sqlite3.Connection) -> dict[str, int]:
    return {t: conn.execute(f'SELECT COUNT(*) FROM "{t}"').fetchone()[0] for t in _tables(conn)}


def _schema_version(conn: sqlite3.Connection) -> int | None:
    if "schema_version" not in _tables(conn):
        return None
    row = conn.execute("SELECT version FROM schema_version WHERE id = 1").fetchone()
    return None if row is None else int(row[0])


def _integrity(conn: sqlite3.Connection) -> None:
    res = conn.execute("PRAGMA integrity_check").fetchall()
    if res != [("ok",)]:
        raise BackupError(f"SQLite integrity_check failed: {res[:3]}")
    fk = conn.execute("PRAGMA foreign_key_check").fetchall()
    if fk:
        raise BackupError(f"foreign_key_check failed: {len(fk)} violation(s), first={fk[0]}")


def _open_readonly(path: Path) -> sqlite3.Connection:
    return sqlite3.connect(f"file:{path}?mode=ro&immutable=1", uri=True)


# ------------------------------------------------------------------ create


def create_backup(settings: Settings, dest: Path, clock: Clock | None = None) -> dict[str, Any]:
    clock = clock or SystemClock()
    dest = Path(dest).expanduser().resolve()
    src_db = settings.db_path.resolve()
    if not src_db.exists():
        raise BackupError(f"database {src_db} does not exist")
    if dest == settings.data_dir.expanduser().resolve() or src_db.parent == dest:
        raise BackupError("backup destination must not be the live data directory")
    _require_empty_target(dest, "backup destination")
    _private_dir(dest)
    db_copy = dest / DB_NAME

    src = sqlite3.connect(str(src_db), timeout=30)
    dst = sqlite3.connect(str(db_copy))
    try:
        src.backup(dst)  # online backup API: consistent snapshot even while the server writes
        dst.execute("PRAGMA journal_mode=DELETE")  # one self-contained file, no -wal/-shm sidecars
    finally:
        dst.close()
        src.close()
    os.chmod(db_copy, 0o600)

    conn = _open_readonly(db_copy)
    try:
        _integrity(conn)
        version = _schema_version(conn)
        if version is None:
            raise BackupError("source database has no schema_version; not a Nozo relay database")
        counts = _counts(conn)
        last_seq = conn.execute("SELECT COALESCE(MAX(seq), 0) FROM events").fetchone()[0]
        art_rows = conn.execute("SELECT id, project_id, storage_key, sha256, size_bytes FROM artifacts ORDER BY id").fetchall()
    finally:
        conn.close()

    art_root = settings.artifacts_dir.resolve()
    artifacts: list[dict[str, Any]] = []
    problems: list[str] = []
    for art_id, project_id, key, sha, size in art_rows:
        src_file = (art_root / key).resolve()
        if art_root not in src_file.parents or not src_file.is_file() or src_file.is_symlink():
            problems.append(f"artifact {art_id}: file missing or unsafe")
            continue
        if _sha256_file(src_file) != sha:
            problems.append(f"artifact {art_id}: sha256 mismatch (not copied)")
            continue
        _copy_private(src_file, dest / "artifacts" / key)
        artifacts.append({"id": art_id, "project_id": project_id, "storage_key": key, "sha256": sha, "size_bytes": size})

    manifest = {
        "format": BACKUP_FORMAT,
        "created_at": clock.now_ms(),
        "created_at_rfc3339": ms_to_rfc3339(clock.now_ms()),
        "app_version": __version__,
        "schema_version": version,
        "sqlite_version": sqlite3.sqlite_version,
        "db": {"file": DB_NAME, "sha256": _sha256_file(db_copy), "size_bytes": db_copy.stat().st_size},
        "table_counts": counts,
        "last_event_seq": last_seq,
        "artifacts": artifacts,
        "complete": not problems,
        "problems": problems,
        "excluded": EXCLUDED,
        "contains": "hashes/digests only (no plaintext keys or passwords); still treat as sensitive",
    }
    tmp = dest / f".{MANIFEST}.tmp"
    tmp.write_text(json.dumps(manifest, indent=2, sort_keys=True), encoding="utf-8")
    os.chmod(tmp, 0o600)
    os.replace(tmp, dest / MANIFEST)
    return manifest


# ------------------------------------------------------------------ verify


def verify_backup(backup_dir: Path) -> dict[str, Any]:
    """Raise ``BackupError`` unless every file matches the manifest and the DB is sound."""
    root = Path(backup_dir).expanduser().resolve()
    mf = root / MANIFEST
    if not mf.is_file():
        raise BackupError(f"{root} has no {MANIFEST}: not a complete backup")
    try:
        manifest = json.loads(mf.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise BackupError(f"unreadable manifest: {exc}") from None
    if manifest.get("format") != BACKUP_FORMAT:
        raise BackupError(f"unsupported backup format {manifest.get('format')!r}")
    # T12/F05: a backup that knew it was incomplete (missing/corrupt artifact at creation time) never restores.
    if manifest.get("complete") is not True:
        raise BackupError("backup manifest says complete=false: refusing (an artifact was missing or unsafe at backup time)")
    if manifest.get("problems"):
        raise BackupError(f"backup manifest lists problems: {list(manifest['problems'])[:3]}")
    db = root / manifest["db"]["file"]
    if not db.is_file() or _sha256_file(db) != manifest["db"]["sha256"]:
        raise BackupError("database file is missing or its sha256 differs from the manifest")
    conn = _open_readonly(db)
    try:
        _integrity(conn)
        if _schema_version(conn) != manifest["schema_version"]:
            raise BackupError("schema_version inside the database differs from the manifest")
        if _counts(conn) != manifest["table_counts"]:
            raise BackupError("table counts differ from the manifest")
        # Every artifact row in the DB must have its bytes in the backup (no omitted artifact left row-only).
        db_arts = {
            r[0]: (r[1], r[2], r[3], r[4])
            for r in conn.execute("SELECT id, project_id, storage_key, sha256, size_bytes FROM artifacts")
        }
    finally:
        conn.close()
    listed = manifest["artifacts"]
    if len(db_arts) != len(listed) or {a["id"] for a in listed} != set(db_arts):
        raise BackupError(
            f"database has {len(db_arts)} artifact row(s) but the manifest lists {len(listed)}: backup is incomplete"
        )
    for a in listed:
        if db_arts[a["id"]][1:3] != (a["storage_key"], a["sha256"]):
            raise BackupError(f"artifact {a['id']}: database row differs from the manifest")
    art_root = root / "artifacts"
    for a in manifest["artifacts"]:
        f = (art_root / a["storage_key"]).resolve()
        if (
            art_root.resolve() not in f.parents
            or not f.is_file()
            or f.stat().st_size != a["size_bytes"]
            or _sha256_file(f) != a["sha256"]
        ):
            raise BackupError(f"artifact {a['id']} is missing or differs from the manifest")
    return manifest


# ------------------------------------------------------------------ restore


def restore_backup(
    backup_dir: Path,
    target_data_dir: Path,
    clock: Clock | None = None,
    *,
    migrate: bool = False,
) -> dict[str, Any]:
    """Restore into a NEW (or empty) data directory. Never deletes or overwrites anything."""
    clock = clock or SystemClock()
    root = Path(backup_dir).expanduser().resolve()
    target = Path(target_data_dir).expanduser().resolve()
    if target == root or root in target.parents or target in root.parents:
        raise BackupError("restore target must be a separate directory from the backup")
    _require_empty_target(target, "restore target")
    manifest = verify_backup(root)

    found = manifest["schema_version"]
    if found != SCHEMA_VERSION and not (migrate and found in (2, 3, 4, 5)):
        raise SchemaError(
            f"backup has schema v{found}; this build requires v{SCHEMA_VERSION}. "
            + ("Use --migrate to upgrade the restored COPY (v2/v3/v4/v5 only)." if found in (2, 3, 4, 5) else "Restore with a matching build.")
        )

    _private_dir(target)
    db_out = target / DB_NAME
    src = _open_readonly(root / manifest["db"]["file"])
    dst = sqlite3.connect(str(db_out))
    try:
        src.backup(dst)
    finally:
        dst.close()
        src.close()
    os.chmod(db_out, 0o600)

    for a in manifest["artifacts"]:
        _copy_private(root / "artifacts" / a["storage_key"], target / "artifacts" / a["storage_key"])
        if _sha256_file(target / "artifacts" / a["storage_key"]) != a["sha256"]:
            raise BackupError(f"artifact {a['id']} changed while copying")

    check = sqlite3.connect(str(db_out))
    try:
        _integrity(check)
        restored_counts = _counts(check)
    finally:
        check.close()
    if restored_counts != manifest["table_counts"]:
        raise BackupError("restored table counts differ from the manifest")

    from nozo_relay.db.engine import create_sqlite_engine
    from nozo_relay.db.schema import ensure_schema, migrate_to_current

    engine = create_sqlite_engine(db_out)
    try:
        if found != SCHEMA_VERSION:
            migrate_to_current(engine, clock)
        ensure_schema(engine, clock)  # the schema check (Q24): wrong/unknown version never starts
        report = _quarantine_restored_state(engine, clock, manifest)
    finally:
        engine.dispose()
    report.update(
        {
            "target": str(target),
            "backup_created_at": manifest["created_at_rfc3339"],
            "table_counts": manifest["table_counts"],
            "migrated_from": found if found != SCHEMA_VERSION else None,
        }
    )
    return report


def _quarantine_restored_state(engine: Any, clock: Clock, manifest: dict[str, Any]) -> dict[str, Any]:
    """Old processes may still hold leases/sessions of the ORIGINAL instance: fence them in the copy."""
    from sqlalchemy import select, update

    from nozo_relay.db.engine import write_session
    from nozo_relay.db.models import Project, Run, SessionRow
    from nozo_relay.domain.enums import ACTIVE_RUN_STATUSES, BlockedReason
    from nozo_relay.services.events import append_event
    from nozo_relay.services.leases import lose_run

    with write_session(engine) as ws:
        revoked = ws.execute(
            update(SessionRow).where(SessionRow.revoked_at.is_(None)).values(revoked_at=clock.now_ms())
        ).rowcount or 0
        runs = ws.execute(
            select(Run).where(Run.status.in_([s.value for s in ACTIVE_RUN_STATUSES])).order_by(Run.id)
        ).scalars().all()
        for run in runs:
            lose_run(ws, clock, run, reason="restored_from_backup", blocked=BlockedReason.RECOVERY_REQUIRED)
        for pid in ws.execute(select(Project.id).order_by(Project.slug)).scalars().all():
            append_event(
                ws, clock, type="system.restored", project_id=pid,
                payload={
                    "backup_created_at": manifest["created_at_rfc3339"],
                    "sessions_revoked": revoked,
                    "runs_lost": len(runs),
                },
            )
    return {"sessions_revoked": revoked, "runs_lost": len(runs)}
