"""Owner-only agent identity routes. Keys are minted by the local owner CLI, never over HTTP."""

from __future__ import annotations

from fastapi import APIRouter, Request
from fastapi.responses import Response

from nozo_relay.api.deps import CurrentPrincipal, DbDep
from nozo_relay.api.mutation import IdemKey, clock_of, replay_response, respond, unit_of_work
from nozo_relay.api.schemas import AgentRegister
from nozo_relay.services import agents as svc
from nozo_relay.services.idempotency import Idempotent, request_digest

router = APIRouter(prefix="/api/v1", tags=["agents"])


@router.get("/agents")
def list_agents(principal: CurrentPrincipal, db: DbDep) -> dict:
    return {"items": svc.list_agents(db, principal), "next_cursor": None}


@router.post("/agents")
def register_agent(request: Request, body: AgentRegister, principal: CurrentPrincipal, key: IdemKey) -> Response:
    clock = clock_of(request)
    if not principal.is_owner:
        from nozo_relay.services import acl

        raise acl.forbidden("Owner privileges required")
    with unit_of_work(request) as ws:
        op = Idempotent(
            ws, clock, principal.id, "agent.register", key,
            request_digest("agent.register", body=body.model_dump(mode="json")),
        )
        if (hit := op.replay()) is not None:
            return replay_response(request, hit)
        out = op.finish(201, svc.register_agent(ws, clock, principal, body))
    return respond(request, out.status, out.body)


@router.post("/agents/{agent_id}/keys/{key_id}/revoke")
def revoke_key(
    request: Request, agent_id: str, key_id: str, principal: CurrentPrincipal, key: IdemKey
) -> Response:
    clock = clock_of(request)
    if not principal.is_owner:
        from nozo_relay.services import acl

        raise acl.forbidden("Owner privileges required")
    with unit_of_work(request) as ws:
        op = Idempotent(
            ws, clock, principal.id, "agent.revoke_key", key,
            request_digest("agent.revoke_key", ids={"agent_id": agent_id, "key_id": key_id}),
        )
        if (hit := op.replay()) is not None:
            return replay_response(request, hit)
        out = op.finish(200, svc.revoke_key(ws, clock, principal, agent_id, key_id))
    request.app.state.hub.close_credential(key_id)  # committed: close its sockets without waiting
    return respond(request, out.status, out.body)
