"""Agent identities: list / register (owner). Key minting stays in the local owner CLI, never HTTP."""

from __future__ import annotations

from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from nozo_relay.api.errors import RelayError
from nozo_relay.api.schemas import AgentRegister
from nozo_relay.auth.context import PrincipalContext
from nozo_relay.auth.credentials import revoke_credential
from nozo_relay.clock import Clock, ms_to_rfc3339
from nozo_relay.db.models import Capability, Credential, Membership, Principal, Run
from nozo_relay.domain.enums import ACTIVE_RUN_STATUSES, BlockedReason, MembershipRole, PrincipalKind
from nozo_relay.services import acl
from nozo_relay.services.events import append_event
from nozo_relay.services.leases import lose_run


def _require_owner(principal: PrincipalContext) -> None:
    if not principal.is_owner:
        raise acl.forbidden("Owner privileges required")


def agent_to_dict(ws: Session, p: Principal) -> dict[str, Any]:
    memberships = ws.execute(
        select(Membership.project_id, Membership.role).where(Membership.principal_id == p.id).order_by(Membership.project_id)
    ).all()
    caps = ws.execute(select(Capability).where(Capability.principal_id == p.id).order_by(Capability.capability)).scalars().all()
    last_hb = ws.execute(select(func.max(Run.heartbeat_at)).where(Run.principal_id == p.id)).scalar()
    busy = ws.execute(
        select(func.count()).select_from(Run).where(
            Run.principal_id == p.id, Run.status.in_([s.value for s in ACTIVE_RUN_STATUSES])
        )
    ).scalar_one()
    live_keys = ws.execute(
        select(func.count()).select_from(Credential).where(Credential.principal_id == p.id, Credential.revoked_at.is_(None))
    ).scalar_one()
    availability = "inactive" if not p.active or not live_keys else ("busy" if busy else "available")
    return {
        "id": p.id,
        "display_name": p.display_name,
        "kind": p.kind,
        "active": p.active,
        "memberships": [{"project_id": pid, "role": role} for pid, role in memberships],
        "capabilities": [
            {"capability": c.capability, "status": c.status, "client_version": c.client_version}
            for c in caps
        ],
        "last_heartbeat_at": ms_to_rfc3339(last_hb) if last_hb else None,
        "availability": availability,
        "active_keys": live_keys,
    }


def list_agents(ws: Session, principal: PrincipalContext) -> list[dict[str, Any]]:
    _require_owner(principal)
    rows = ws.execute(
        select(Principal).where(Principal.kind != PrincipalKind.OWNER.value).order_by(Principal.display_name, Principal.id)
    ).scalars().all()
    return [agent_to_dict(ws, p) for p in rows]


def register_agent(
    ws: Session, clock: Clock, principal: PrincipalContext, dto: AgentRegister
) -> dict[str, Any]:
    """Create the identity and memberships only. A key is minted separately by the owner CLI."""
    _require_owner(principal)
    for pid in dto.project_ids:
        if not principal.is_member(pid):
            raise acl.not_found()
    p = Principal(display_name=dto.display_name, kind=dto.kind, active=True, created_at=clock.now_ms())
    ws.add(p)
    ws.flush()
    role = MembershipRole(dto.kind).value
    for pid in sorted(set(dto.project_ids)):
        ws.add(Membership(principal_id=p.id, project_id=pid, role=role))
    ws.flush()
    append_event(
        ws, clock, type="agent.registered", actor_id=principal.id,
        payload={"agent_id": p.id, "kind": p.kind, "projects": sorted(set(dto.project_ids))},
    )
    return agent_to_dict(ws, p)


def revoke_key(
    ws: Session, clock: Clock, principal: PrincipalContext, agent_id: str, key_id: str
) -> dict[str, Any]:
    """Revoke a credential and fence the agent's active runs (they become lost, task blocked)."""
    _require_owner(principal)
    cred = ws.get(Credential, key_id)
    if cred is None or cred.principal_id != agent_id:
        raise acl.not_found()
    revoked = revoke_credential(ws, clock, key_id)
    fenced = 0
    runs = ws.execute(
        select(Run).where(Run.principal_id == agent_id, Run.status.in_([s.value for s in ACTIVE_RUN_STATUSES]))
    ).scalars().all()
    for run in runs:
        lose_run(ws, clock, run, reason="credential_revoked", blocked=BlockedReason.AUTH_REQUIRED)
        fenced += 1
    append_event(
        ws, clock, type="credential.revoked", actor_id=principal.id,
        payload={"agent_id": agent_id, "credential_id": key_id, "fenced_runs": fenced},
    )
    return {"credential_id": key_id, "revoked": bool(revoked) or cred.revoked_at is not None, "fenced_runs": fenced}
