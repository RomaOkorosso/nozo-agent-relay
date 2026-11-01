"""Synthetic snapshot fixtures for M0 (no real repository).

A snapshot is an immutable (project, task, revision, tree_hash, diff_hash, manifest) record that an
audit is bound to. M0 fixtures derive hashes deterministically from a seed so the two test agents
can exercise the whole protocol without touching a repo.
"""

from __future__ import annotations

import json
from typing import Any

from sqlalchemy.orm import Session

from nozo_relay.api.schemas import SnapshotIn
from nozo_relay.clock import Clock, ms_to_rfc3339
from nozo_relay.db.models import Job, Snapshot
from nozo_relay.domain.fingerprints import sha256_hex


def fixture_snapshot_payload(task_id: str, revision: int, variant: str, *, files: list[str] | None = None) -> dict[str, Any]:
    """Deterministic fixture snapshot body (used by the test worker and tests)."""
    seed = f"{task_id}|{revision}|{variant}"
    return {
        "base_commit": sha256_hex(f"base|{task_id}|{revision}")[:40],
        "head_commit": sha256_hex(f"head|{seed}")[:40],
        "tree_hash": sha256_hex(f"tree|{seed}"),
        "diff_hash": sha256_hex(f"diff|{seed}"),
        "manifest": {"fixture": True, "variant": variant, "files": sorted(files or [])},
    }


def store_snapshot(
    ws: Session, task: Any, revision: int, created_by: str, data: SnapshotIn
) -> Snapshot:
    snap = Snapshot(
        project_id=task.project_id,
        task_id=task.id,
        revision=revision,
        base_commit=data.base_commit,
        head_commit=data.head_commit,
        tree_hash=data.tree_hash,
        diff_hash=data.diff_hash,
        manifest_json=json.dumps(data.manifest, sort_keys=True, separators=(",", ":")),
        created_by=created_by,
    )
    ws.add(snap)
    ws.flush()
    return snap


def snapshot_to_dict(snap: Snapshot) -> dict[str, Any]:
    return {
        "id": snap.id,
        "project_id": snap.project_id,
        "task_id": snap.task_id,
        "revision": snap.revision,
        "base_commit": snap.base_commit,
        "head_commit": snap.head_commit,
        "tree_hash": snap.tree_hash,
        "diff_hash": snap.diff_hash,
        "manifest": json.loads(snap.manifest_json),
        "verified_at": ms_to_rfc3339(snap.verified_at) if snap.verified_at else None,
    }


def mark_verified(snap: Snapshot, clock: Clock) -> None:
    """Content stays immutable; only the verification timestamp is set when an audit PASSes."""
    if snap.verified_at is None:
        snap.verified_at = clock.now_ms()


def input_snapshot_of(ws: Session, job: Job) -> Snapshot | None:
    return ws.get(Snapshot, job.input_snapshot_id) if job.input_snapshot_id else None
