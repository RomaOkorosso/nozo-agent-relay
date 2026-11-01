"""Artifacts: opaque ids, server-chosen storage keys, project ACL, integrity-checked reads.

* The caller never supplies a path or a media type that is trusted: the key is ``<id[:2]>/<id>`` under
  ``<data_dir>/artifacts`` (0700/0600), the stored media type is sniffed from the bytes, and downloads
  are ALWAYS ``application/octet-stream`` + ``Content-Disposition: attachment`` (HTML never runs on the
  panel origin).
* Reads re-hash the bytes (sha256 + size from the DB); a mismatch is an error, never silently served.
* An artifact of another project answers 404, exactly like an unknown id.
"""

from __future__ import annotations

import hashlib
import os
import uuid
from pathlib import Path
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from nozo_relay.api.errors import RelayError
from nozo_relay.auth.context import PrincipalContext
from nozo_relay.clock import Clock, ms_to_rfc3339
from nozo_relay.config import Settings
from nozo_relay.db.models import Artifact, Job, Project, Run, Task
from nozo_relay.services import acl
from nozo_relay.services.events import append_event


def sniff_media_type(data: bytes) -> str:
    if data.startswith(b"\x89PNG\r\n\x1a\n"):
        return "image/png"
    if data.startswith(b"%PDF-"):
        return "application/pdf"
    if data.startswith((b"PK\x03\x04", b"PK\x05\x06")):
        return "application/zip"
    if data.startswith(b"\x1f\x8b"):
        return "application/gzip"
    if data.startswith(b"\xff\xd8\xff"):
        return "image/jpeg"
    if b"\x00" not in data[:8192]:
        try:
            data[:8192].decode("utf-8", errors="strict")
            return "text/plain"
        except UnicodeDecodeError:
            pass
    return "application/octet-stream"


def artifact_to_dict(a: Artifact) -> dict[str, Any]:
    return {
        "id": a.id,
        "project_id": a.project_id,
        "task_id": a.task_id,
        "run_id": a.run_id,
        "sha256": a.sha256,
        "size_bytes": a.size_bytes,
        "media_type": a.media_type,
        "created_at": ms_to_rfc3339(a.created_at),
    }


def _root(settings: Settings) -> Path:
    root = settings.artifacts_dir
    root.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(root, 0o700)
    except OSError:
        pass
    return root


def _path_for(settings: Settings, storage_key: str) -> Path:
    root = _root(settings).resolve()
    path = (root / storage_key).resolve()
    if root not in path.parents:  # defence in depth: keys are server-made, but never trust the row
        raise RelayError(500, "artifact_path_invalid", "Artifact storage key is invalid")
    return path


def _write_atomic(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(path.parent, 0o700)
    except OSError:
        pass
    tmp = path.with_name(f".{path.name}.{uuid.uuid4().hex}.tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, path)
    except BaseException:
        tmp.unlink(missing_ok=True)
        raise


def store_artifact(
    ws: Session,
    clock: Clock,
    settings: Settings,
    principal: PrincipalContext,
    project: Project,
    data: bytes,
    *,
    task_id: str | None,
    run_id: str | None,
) -> Artifact:
    acl.project_role(principal, project)
    acl.require_enabled(project)
    if not data:
        raise RelayError(422, "empty_artifact", "Artifact body is empty")
    if len(data) > settings.artifact_max_bytes:
        raise RelayError(413, "payload_too_large", "Artifact exceeds the per-file limit")
    if task_id is not None:
        task = ws.get(Task, task_id)
        if task is None or task.project_id != project.id:
            raise acl.not_found()
    if run_id is not None:
        run = ws.get(Run, run_id)
        job = ws.get(Job, run.job_id) if run is not None else None
        if run is None or job is None or job.project_id != project.id:
            raise acl.not_found()
        if not principal.is_owner and run.principal_id != principal.id:
            raise acl.not_found()
    used = ws.execute(
        select(func.coalesce(func.sum(Artifact.size_bytes), 0)).where(Artifact.project_id == project.id)
    ).scalar_one()
    if used + len(data) > settings.artifact_project_quota_bytes:
        raise RelayError(409, "quota_exceeded", "Project artifact quota exceeded")
    art_id = str(uuid.uuid4())
    key = f"{art_id[:2]}/{art_id}"
    art = Artifact(
        id=art_id,
        project_id=project.id,
        task_id=task_id,
        run_id=run_id,
        storage_key=key,
        sha256=hashlib.sha256(data).hexdigest(),
        size_bytes=len(data),
        media_type=sniff_media_type(data),
        created_at=clock.now_ms(),
    )
    ws.add(art)
    ws.flush()
    _write_atomic(_path_for(settings, key), data)
    append_event(
        ws, clock, type="artifact.created", project_id=project.id, task_id=task_id, actor_id=principal.id,
        payload={"artifact_id": art.id, "sha256": art.sha256, "size_bytes": art.size_bytes},
    )
    return art


def get_artifact(ws: Session, project: Project, artifact_id: str) -> Artifact:
    a = ws.get(Artifact, artifact_id)
    if a is None or a.project_id != project.id:
        raise acl.not_found()
    return a


def read_bytes(settings: Settings, art: Artifact) -> bytes:
    path = _path_for(settings, art.storage_key)
    try:
        # O_NOFOLLOW: a swapped-in symlink is refused instead of followed.
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    except FileNotFoundError:
        raise RelayError(500, "artifact_missing", "Artifact bytes are missing") from None
    except OSError:
        raise RelayError(500, "artifact_unreadable", "Artifact bytes are unreadable") from None
    with os.fdopen(fd, "rb") as fh:
        data = fh.read(art.size_bytes + 1)
    if len(data) != art.size_bytes or hashlib.sha256(data).hexdigest() != art.sha256:
        raise RelayError(500, "artifact_corrupt", "Artifact integrity check failed")
    return data
