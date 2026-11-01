"""Repo bindings: the OWNER-configured link between a project and a canonical repository on this host.

Hard rules (03_DATA_MODEL ``repo_bindings``, 07_ADAPTERS "Git и снимки"):

* ``canonical_root`` is set only here, by the local owner procedure (``python -m nozo_relay repo-bind``).
  No HTTP endpoint, task payload, task revision, message or agent report can create or change it; the API's
  strict models reject unknown fields and ``reject_path_fields`` rejects path-like keys at the runner boundary.
* Registration verifies that the root is a plain git repository directory (not a symlink, not a worktree
  pointer file), records its identity (root commit) and refuses roots that contain or sit inside the relay's
  own data directory.
* A dirty tree is never reset. Either the baseline is clean, or the owner explicitly approves the CURRENT tree
  (``approve_dirty_snapshot``): the approval is bound to the tree hash and stops matching as soon as the tree
  changes again.
* ``active_lock_run`` / ``lock_epoch`` allow exactly one writer per binding; quarantine blocks new runs until
  the owner clears it.
"""

from __future__ import annotations

import os
from collections.abc import Callable, Iterable, Mapping
from contextlib import AbstractContextManager
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any, Protocol

from sqlalchemy import select, update
from sqlalchemy.orm import Session

from nozo_relay.clock import Clock
from nozo_relay.db.models import Project, RepoBinding
from nozo_relay.runner import snapshots

PATH_LIKE_KEYS = frozenset(
    {
        "repo", "repo_path", "repo_root", "repo_dir", "repository", "repository_path", "canonical_root", "root", "root_path",
        "path", "paths", "cwd", "workdir", "working_dir", "work_dir", "workspace", "workspace_path", "directory", "dir",
        "folder", "binding_path", "mount", "mounts", "volume", "volumes", "home", "state_dir", "data_dir", "env", "environment",
        "argv", "command", "cmd", "shell", "executable", "binary",
    }
)


class RepoBindingError(ValueError):
    pass


class BindingLocked(RuntimeError):
    """Another run holds the writer lock of this binding (one writable binding per run)."""


class PathInPayload(ValueError):
    """A task/API payload tried to smuggle a filesystem path / command into the runner."""


def reject_path_fields(payload: Any, *, _where: str = "$") -> None:
    """Recursively refuse path/command-like keys in data that originates from the API or a model."""
    if isinstance(payload, Mapping):
        for key, value in payload.items():
            if str(key).lower() in PATH_LIKE_KEYS:
                raise PathInPayload(f"payload field {_where}.{key} is not accepted: repository paths and commands come from the owner binding only")
            reject_path_fields(value, _where=f"{_where}.{key}")
    elif isinstance(payload, (list, tuple)):
        for i, item in enumerate(payload):
            reject_path_fields(item, _where=f"{_where}[{i}]")


@dataclass(frozen=True)
class BindingInfo:
    id: str
    project_id: str
    canonical_root: Path
    repo_identity: str
    baseline_policy: str = "clean"
    approved_tree_hash: str | None = None
    quarantine_reason: str | None = None
    active_lock_run: str | None = None
    lock_epoch: int = 0


class BindingRegistry(Protocol):
    def get(self, binding_id: str) -> BindingInfo: ...
    def acquire_lock(self, binding_id: str, run_id: str) -> int: ...
    def release_lock(self, binding_id: str, run_id: str) -> None: ...
    def quarantine(self, binding_id: str, reason: str) -> None: ...


def _info(b: RepoBinding) -> BindingInfo:
    return BindingInfo(
        id=b.id, project_id=b.project_id, canonical_root=Path(b.canonical_root), repo_identity=b.repo_identity,
        baseline_policy=b.baseline_policy, approved_tree_hash=b.approved_tree_hash, quarantine_reason=b.quarantine_reason,
        active_lock_run=b.active_lock_run, lock_epoch=b.lock_epoch,
    )


# --------------------------------------------------------------------------------------------- owner operations
def register_binding(
    ws: Session, clock: Clock, *, project: str, canonical_root: str | os.PathLike[str], actor_id: str | None = None,
    protected_dirs: Iterable[Path] = (),
) -> RepoBinding:
    """Owner-only (local CLI). ``project`` is a slug or id."""
    raw = Path(canonical_root).expanduser()
    if not raw.is_absolute():
        raise RepoBindingError("canonical_root must be an absolute path")
    if raw.is_symlink():
        raise RepoBindingError("canonical_root must not be a symlink")
    root = raw.resolve(strict=True)
    if root == Path(root.anchor) or root == Path.home().resolve():
        raise RepoBindingError("refusing to bind a filesystem root or the user's home directory")
    if not (root / ".git").is_dir() or (root / ".git").is_symlink():
        raise RepoBindingError("canonical_root must be a plain git repository (a .git DIRECTORY, not a worktree/gitlink file)")
    for d in protected_dirs:
        p = Path(d).resolve()
        if root == p or root in p.parents or p in root.parents:
            raise RepoBindingError(f"canonical_root overlaps the relay's own data directory {p}")
    row = ws.execute(select(Project).where((Project.slug == project) | (Project.id == project))).scalar_one_or_none()
    if row is None:
        raise RepoBindingError(f"unknown project {project!r}")
    if ws.execute(select(RepoBinding).where(RepoBinding.project_id == row.id)).scalar_one_or_none():
        raise RepoBindingError("project already has a repo binding (one writable binding per project)")
    try:
        identity = snapshots.repo_identity(root)
    except snapshots.SnapshotError as exc:
        raise RepoBindingError(f"not a usable git repository: {exc}") from exc
    b = RepoBinding(
        project_id=row.id, canonical_root=str(root), repo_identity=identity, lock_epoch=0,
        created_at=clock.now_ms(), registered_by=actor_id, baseline_policy="clean",
    )
    ws.add(b)
    ws.flush()
    row.repo_binding_id = b.id
    return b


def approve_dirty_snapshot(ws: Session, clock: Clock, *, binding_id: str) -> str:
    """Owner explicitly saves the CURRENT dirty tree as the baseline. Returns the approved tree hash."""
    b = _get(ws, binding_id)
    tree = snapshots.worktree_tree_hash(Path(b.canonical_root))
    b.baseline_policy = "saved_dirty_snapshot"
    b.approved_tree_hash = tree
    b.approved_at = clock.now_ms()
    return tree


def clear_quarantine(ws: Session, *, binding_id: str) -> None:
    b = _get(ws, binding_id)
    b.quarantine_reason = None
    b.quarantined_at = None


def _get(ws: Session, binding_id: str) -> RepoBinding:
    b = ws.get(RepoBinding, binding_id)
    if b is None:
        raise RepoBindingError(f"unknown binding {binding_id!r}")
    return b


def binding_for_project(ws: Session, project_id: str) -> RepoBinding | None:
    return ws.execute(select(RepoBinding).where(RepoBinding.project_id == project_id)).scalar_one_or_none()


# --------------------------------------------------------------------------------------------- registries
class DbBindingRegistry:
    """Registry over the relay database. ``session_scope`` yields a committed-on-exit write session."""

    def __init__(self, session_scope: Callable[[], AbstractContextManager[Session]], clock: Clock) -> None:
        self._scope = session_scope
        self._clock = clock

    def get(self, binding_id: str) -> BindingInfo:
        with self._scope() as ws:
            return _info(_get(ws, binding_id))

    def acquire_lock(self, binding_id: str, run_id: str) -> int:
        with self._scope() as ws:
            res = ws.execute(
                update(RepoBinding)
                .where(RepoBinding.id == binding_id, RepoBinding.active_lock_run.is_(None), RepoBinding.quarantine_reason.is_(None))
                .values(active_lock_run=run_id, lock_epoch=RepoBinding.lock_epoch + 1)
            )
            if res.rowcount != 1:  # type: ignore[attr-defined]
                raise BindingLocked(f"binding {binding_id} is locked or quarantined")
            return _get(ws, binding_id).lock_epoch

    def release_lock(self, binding_id: str, run_id: str) -> None:
        with self._scope() as ws:
            ws.execute(
                update(RepoBinding).where(RepoBinding.id == binding_id, RepoBinding.active_lock_run == run_id)
                .values(active_lock_run=None)
            )

    def quarantine(self, binding_id: str, reason: str) -> None:
        with self._scope() as ws:
            b = _get(ws, binding_id)
            b.quarantine_reason = reason[:500]
            b.quarantined_at = self._clock.now_ms()


class StaticBindingRegistry:
    """In-memory registry (tests, and a supervisor started without a database)."""

    def __init__(self, bindings: Iterable[BindingInfo] = ()) -> None:
        self._b = {b.id: b for b in bindings}

    def add(self, info: BindingInfo) -> None:
        self._b[info.id] = info

    def get(self, binding_id: str) -> BindingInfo:
        try:
            return self._b[binding_id]
        except KeyError as exc:
            raise RepoBindingError(f"unknown binding {binding_id!r}") from exc

    def acquire_lock(self, binding_id: str, run_id: str) -> int:
        b = self.get(binding_id)
        if b.active_lock_run or b.quarantine_reason:
            raise BindingLocked(f"binding {binding_id} is locked or quarantined")
        self._b[binding_id] = replace(b, active_lock_run=run_id, lock_epoch=b.lock_epoch + 1)
        return self._b[binding_id].lock_epoch

    def release_lock(self, binding_id: str, run_id: str) -> None:
        b = self.get(binding_id)
        if b.active_lock_run == run_id:
            self._b[binding_id] = replace(b, active_lock_run=None)

    def quarantine(self, binding_id: str, reason: str) -> None:
        self._b[binding_id] = replace(self.get(binding_id), quarantine_reason=reason)
