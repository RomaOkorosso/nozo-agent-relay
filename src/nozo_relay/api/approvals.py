"""Approval-request records (M1): create (any member), list/read, owner decision, execute stub (501)."""

from __future__ import annotations

from fastapi import APIRouter, Query, Request
from fastapi.responses import Response

from nozo_relay.api.deps import CurrentPrincipal, DbDep
from nozo_relay.api.mutation import IdemKey, clock_of, replay_response, respond, settings_of, unit_of_work
from nozo_relay.api.schemas import ApprovalDecision, ApprovalExecute, ApprovalRequestCreate
from nozo_relay import usecases as uc
from nozo_relay.services import acl
from nozo_relay.services import approvals as svc
from nozo_relay.services.idempotency import Idempotent, request_digest

router = APIRouter(prefix="/api/v1", tags=["approvals"])


@router.post("/projects/{project_id}/approval-requests")
def create_approval_request(
    request: Request, project_id: str, body: ApprovalRequestCreate, principal: CurrentPrincipal, key: IdemKey
) -> Response:
    out = uc.request_approval(uc.Ctx.from_app(request.app), principal, project_id, body, key)
    return respond(request, out.status, out.body, replayed=out.replayed)


@router.get("/projects/{project_id}/approval-requests")
def list_approval_requests(
    project_id: str, principal: CurrentPrincipal, db: DbDep, status: str | None = Query(default=None)
) -> dict:
    project = acl.get_project(db, principal, project_id)
    return {"items": svc.list_requests(db, project, status=status), "next_cursor": None}


@router.get("/projects/{project_id}/approval-requests/{approval_id}")
def get_approval_request(project_id: str, approval_id: str, principal: CurrentPrincipal, db: DbDep) -> dict:
    project = acl.get_project(db, principal, project_id)
    return svc.approval_to_dict(svc.get_request(db, project, approval_id))


@router.post("/projects/{project_id}/approval-requests/{approval_id}/decision")
def decide_approval_request(
    request: Request, project_id: str, approval_id: str, body: ApprovalDecision,
    principal: CurrentPrincipal, key: IdemKey,
) -> Response:
    clock = clock_of(request)
    settings = settings_of(request)
    with unit_of_work(request) as ws:
        project = acl.get_project(ws, principal, project_id)
        acl.require_owner(principal, project)
        op = Idempotent(
            ws, clock, principal.id, "approval.decision", key,
            request_digest("approval.decision", ids={"project_id": project.id, "approval_id": approval_id},
                           body=body.model_dump(mode="json")),
        )
        if (hit := op.replay()) is not None:
            return replay_response(request, hit)
        status, payload = svc.decide(ws, clock, settings, principal, project, approval_id, body)
        out = op.finish(status, payload)
    return respond(request, out.status, out.body)


@router.post("/projects/{project_id}/approval-requests/{approval_id}/execute")
def execute_approval_request(
    request: Request, project_id: str, approval_id: str, body: ApprovalExecute,
    principal: CurrentPrincipal, key: IdemKey,
) -> Response:
    """Always refuses: even an approved record has no executor in M0-M2."""
    clock = clock_of(request)
    with unit_of_work(request) as ws:
        project = acl.get_project(ws, principal, project_id)
        acl.require_owner(principal, project)
        status, payload = svc.execute(ws, clock, project, principal, approval_id, body.action_digest)
    return respond(request, status, payload)
