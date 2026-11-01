"""One-time local bootstrap: owner + two test agents + default project + memberships.

Secrets (agent keys, and the owner password when generated) are written exactly once to
``<data_dir>/bootstrap_credentials.json`` (mode 0600, O_EXCL, gitignored) and never logged or
printed. Only digests/hashes reach the database.
"""

from __future__ import annotations

import json
import os
import secrets
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from nozo_relay.auth.credentials import issue_credential
from nozo_relay.auth.passwords import hash_password
from nozo_relay.clock import Clock, SystemClock, ms_to_rfc3339
from nozo_relay.config import Settings
from nozo_relay.db.engine import create_engine_from_settings, make_session_factory
from nozo_relay.db.models import Membership, Principal, Project
from nozo_relay.db.schema import ensure_schema
from nozo_relay.domain.enums import MembershipRole, PrincipalKind

CREDENTIALS_FILENAME = "bootstrap_credentials.json"
DEFAULT_PROJECT_SLUG = "default"


class BootstrapError(RuntimeError):
    pass


@dataclass(frozen=True)
class BootstrapResult:
    credentials_path: Path
    owner_id: str
    owner_username: str
    project_id: str
    agent_ids: dict[str, str]
    password_generated: bool


def credentials_path(settings: Settings) -> Path:
    return settings.data_dir / CREDENTIALS_FILENAME


def _write_once(path: Path, payload: dict[str, Any]) -> None:
    data = json.dumps(payload, indent=2, sort_keys=True).encode("utf-8")
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
            fh.flush()
            os.fsync(fh.fileno())
    except BaseException:
        path.unlink(missing_ok=True)
        raise


def bootstrap(
    settings: Settings,
    *,
    owner_username: str = "owner",
    owner_password: str | None = None,
    clock: Clock | None = None,
) -> BootstrapResult:
    clock = clock or SystemClock()
    settings.data_dir.mkdir(parents=True, exist_ok=True)
    os.chmod(settings.data_dir, 0o700)
    cred_path = credentials_path(settings)
    if cred_path.exists():
        raise BootstrapError(f"{cred_path.name} already exists; bootstrap is one-time")

    password_generated = owner_password is None
    password = owner_password or secrets.token_urlsafe(18)
    password_hash = hash_password(password)  # validates strength before touching the DB

    engine = create_engine_from_settings(settings)
    try:
        ensure_schema(engine, clock, require_wal_fix=settings.sqlite_require_wal_fix)
        factory = make_session_factory(engine)
        with factory() as db:
            if db.execute(select(func.count()).select_from(Principal)).scalar_one() > 0:
                raise BootstrapError("database already contains principals; bootstrap is one-time")
            result, payload = _populate(db, clock, owner_username, password_hash, password, password_generated)
            db.commit()
    finally:
        engine.dispose()

    try:
        _write_once(cred_path, payload)
    except OSError as exc:  # DB committed but secrets unrecoverable: tell the operator clearly
        raise BootstrapError(
            f"database initialised but could not write {cred_path}: {exc}. "
            "Delete the database and re-run bootstrap."
        ) from exc
    return BootstrapResult(credentials_path=cred_path, **result)


def _populate(
    db: Session,
    clock: Clock,
    username: str,
    password_hash: str,
    password: str,
    password_generated: bool,
) -> tuple[dict[str, Any], dict[str, Any]]:
    now = clock.now_ms()
    owner = Principal(
        display_name="Owner",
        kind=PrincipalKind.OWNER.value,
        active=True,
        created_at=now,
        username=username,
        password_hash=password_hash,
    )
    project = Project(slug=DEFAULT_PROJECT_SLUG, name="Default project", created_at=now)
    db.add_all([owner, project])
    db.flush()
    db.add(Membership(principal_id=owner.id, project_id=project.id, role=MembershipRole.OWNER.value))

    agents_payload: list[dict[str, str]] = []
    agent_ids: dict[str, str] = {}
    for name, kind, role in (
        ("test-implementer", PrincipalKind.IMPLEMENTER, MembershipRole.IMPLEMENTER),
        ("test-auditor", PrincipalKind.AUDITOR, MembershipRole.AUDITOR),
    ):
        agent = Principal(display_name=name, kind=kind.value, active=True, created_at=now)
        db.add(agent)
        db.flush()
        db.add(Membership(principal_id=agent.id, project_id=project.id, role=role.value))
        key, cred = issue_credential(db, clock, agent.id)
        agent_ids[name] = agent.id
        agents_payload.append(
            {
                "name": name,
                "principal_id": agent.id,
                "kind": kind.value,
                "credential_id": cred.id,
                "key": key.full_key,
            }
        )

    # T12/F02: a default supervisor identity. Runs are bound to a runner principal at claim time; the
    # supervisor process authenticates with this key to confirm stops / reconcile its own runs.
    runner = Principal(display_name="default-supervisor", kind=PrincipalKind.RUNNER.value, active=True, created_at=now)
    db.add(runner)
    db.flush()
    db.add(Membership(principal_id=runner.id, project_id=project.id, role=MembershipRole.RUNNER.value))
    runner_key, runner_cred = issue_credential(db, clock, runner.id)
    agent_ids["default-supervisor"] = runner.id
    runner_payload = {
        "name": "default-supervisor",
        "principal_id": runner.id,
        "kind": PrincipalKind.RUNNER.value,
        "credential_id": runner_cred.id,
        "key": runner_key.full_key,
    }

    payload: dict[str, Any] = {
        "note": "Shown once. Store in a private keyring/config; never commit. Delete after copying.",
        "created_at": ms_to_rfc3339(now),
        "owner": {
            "principal_id": owner.id,
            "username": username,
            "password": password if password_generated else None,
        },
        "project": {"id": project.id, "slug": project.slug},
        "agents": agents_payload,
        "runner": runner_payload,
    }
    return (
        {
            "owner_id": owner.id,
            "owner_username": username,
            "project_id": project.id,
            "agent_ids": agent_ids,
            "password_generated": password_generated,
        },
        payload,
    )
