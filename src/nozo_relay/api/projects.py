"""Projects, delegations, events replay, consistent UI snapshot, reports."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Query, Request
from fastapi.responses import JSONResponse, Response

from nozo_relay.api.deps import CurrentPrincipal, DbDep
from nozo_relay.api.errors import RelayError
from nozo_relay.api.mutation import (
    IdemKey,
    IfMatch,
    clock_of,
    replay_response,
    respond,
    settings_of,
    unit_of_work,
)
from nozo_relay.api.schemas import DelegationCreate, DelegationRevoke, PolicyUpdate, ProjectCreate, ProjectPatch
from nozo_relay.db.models import Snapshot
from nozo_relay import usecases as uc
from nozo_relay.services import acl
from nozo_relay.services import controls as controls_svc
from nozo_relay.services import policy as policy_svc
from nozo_relay.services import snapshots as snap_svc
from nozo_relay.services import projects as svc
from nozo_relay.services.events import append_event
from nozo_relay.services.idempotency import Idempotent, request_digest
from nozo_relay.services.tasks import check_version

router = APIRouter(prefix="/api/v1", tags=["projects"])


@router.get("/projects")
def list_projects(principal: CurrentPrincipal, db: DbDep) -> dict:
    items = [svc.project_to_dict(p) for p in svc.list_projects(db, principal)]
    return {"items": items, "next_cursor": None}


@router.post("/projects")
def create_project(request: Request, body: ProjectCreate, principal: CurrentPrincipal, key: IdemKey) -> Response:
    if not principal.is_owner:
        raise acl.forbidden("Owner privileges required")
    clock = clock_of(request)
    with unit_of_work(request) as ws:
        op = Idempotent(
            ws, clock, principal.id, "project.create", key,
            request_digest("project.create", body=body.model_dump(mode="json")),
        )
        if (hit := op.replay()) is not None:
            return replay_response(request, hit)
        project = svc.create_project(ws, clock, principal, body)
        out = op.finish(201, svc.project_to_dict(project))
    return respond(request, out.status, out.body, etag=out.body["version"], location=f"/api/v1/projects/{out.body['id']}")


@router.get("/projects/{project_id}")
def get_project(project_id: str, principal: CurrentPrincipal, db: DbDep) -> Response:
    project = acl.get_project(db, principal, project_id)
    return JSONResponse(svc.project_to_dict(project), headers={"ETag": f'"{project.version}"'})


@router.patch("/projects/{project_id}")
def patch_project(
    request: Request,
    project_id: str,
    body: ProjectPatch,
    principal: CurrentPrincipal,
    key: IdemKey,
    if_match: IfMatch,
) -> Response:
    clock = clock_of(request)
    settings = settings_of(request)
    with unit_of_work(request) as ws:
        project = acl.get_project(ws, principal, project_id)
        acl.require_owner(principal, project)
        op = Idempotent(
            ws, clock, principal.id, "project.patch", key,
            request_digest("project.patch", ids={"project_id": project.id}, body=body.model_dump(mode="json"),
                           guards={"if_match": if_match}),
        )
        if (hit := op.replay()) is not None:
            return replay_response(request, hit)
        check_version(project.version, if_match, "project")
        control = None
        status = 200
        if body.name is not None and body.name != project.name:
            project.name = body.name
            project.version += 1
            append_event(
                ws, clock, type="project.updated", project_id=project.id, entity_version=project.version,
                actor_id=principal.id, payload={"name": project.name},
            )
        if body.paused is not None and body.paused != project.paused:
            status, ctl_body = controls_svc.project_control(
                ws, clock, settings, principal, project, "pause" if body.paused else "resume",
                "project settings change",
            )
            control = ctl_body["control"]
        out_body = svc.project_to_dict(project)
        if control is not None:
            out_body["control"] = control
        out = op.finish(status, out_body)
    return respond(request, out.status, out.body, etag=out.body["version"])


@router.post("/projects/{project_id}/delegations")
def create_delegation(
    request: Request, project_id: str, body: DelegationCreate, principal: CurrentPrincipal, key: IdemKey
) -> Response:
    clock = clock_of(request)
    with unit_of_work(request) as ws:
        project = acl.get_project(ws, principal, project_id)
        acl.require_owner(principal, project)
        op = Idempotent(
            ws, clock, principal.id, "delegation.create", key,
            request_digest("delegation.create", ids={"project_id": project.id}, body=body.model_dump(mode="json")),
        )
        if (hit := op.replay()) is not None:
            return replay_response(request, hit)
        d = svc.create_delegation(ws, clock, principal, project, body)
        out = op.finish(201, svc.delegation_to_dict(d))
    return respond(request, out.status, out.body)


@router.get("/projects/{project_id}/delegations")
def list_delegations(project_id: str, principal: CurrentPrincipal, db: DbDep) -> dict:
    project = acl.get_project(db, principal, project_id)
    acl.require_owner(principal, project)
    return {"items": svc.list_delegations(db, project), "next_cursor": None}


@router.post("/projects/{project_id}/delegations/{delegation_id}/revoke")
def revoke_delegation(
    request: Request, project_id: str, delegation_id: str, body: DelegationRevoke,
    principal: CurrentPrincipal, key: IdemKey,
) -> Response:
    clock = clock_of(request)
    with unit_of_work(request) as ws:
        project = acl.get_project(ws, principal, project_id)
        acl.require_owner(principal, project)
        op = Idempotent(
            ws, clock, principal.id, "delegation.revoke", key,
            request_digest("delegation.revoke", ids={"project_id": project.id, "delegation_id": delegation_id},
                           body=body.model_dump(mode="json")),
        )
        if (hit := op.replay()) is not None:
            return replay_response(request, hit)
        out = op.finish(200, svc.revoke_delegation(ws, clock, principal, project, delegation_id, body.reason))
    return respond(request, out.status, out.body)


@router.get("/projects/{project_id}/policy")
def get_policy(project_id: str, principal: CurrentPrincipal, db: DbDep) -> Response:
    project = acl.get_project(db, principal, project_id)
    return JSONResponse(policy_svc.policy_to_dict(project), headers={"ETag": f'"{project.version}"'})


@router.put("/projects/{project_id}/policy")
def put_policy(
    request: Request, project_id: str, body: PolicyUpdate, principal: CurrentPrincipal,
    key: IdemKey, if_match: IfMatch,
) -> Response:
    """Owner-only. Mutable policy racing with a claim is serialised by BEGIN IMMEDIATE."""
    clock = clock_of(request)
    with unit_of_work(request) as ws:
        project = acl.get_project(ws, principal, project_id)
        acl.require_owner(principal, project)
        op = Idempotent(
            ws, clock, principal.id, "project.policy", key,
            request_digest("project.policy", ids={"project_id": project.id}, body=body.model_dump(mode="json"),
                           guards={"if_match": if_match}),
        )
        if (hit := op.replay()) is not None:
            return replay_response(request, hit)
        out = op.finish(200, policy_svc.update_policy(ws, clock, principal, project, body, if_match))
    return respond(request, out.status, out.body, etag=out.body["version"])


@router.get("/projects/{project_id}/snapshots/{snapshot_id}")
def get_snapshot_record(project_id: str, snapshot_id: str, principal: CurrentPrincipal, db: DbDep) -> dict:
    """Immutable snapshot record; another project's id answers 404 exactly like an unknown id."""
    project = acl.get_project(db, principal, project_id)
    snap = db.get(Snapshot, snapshot_id)
    if snap is None or snap.project_id != project.id:
        raise RelayError(404, "not_found", acl.NOT_FOUND)
    return snap_svc.snapshot_to_dict(snap)


@router.get("/projects/{project_id}/events")
def get_events(
    request: Request,
    project_id: str,
    principal: CurrentPrincipal,
    after_seq: Annotated[int, Query(ge=0)] = 0,
    limit: Annotated[int | None, Query()] = None,
) -> dict:
    return uc.get_events(uc.Ctx.from_app(request.app), principal, project_id, after_seq, limit)


@router.get("/projects/{project_id}/snapshot")
def get_snapshot(project_id: str, principal: CurrentPrincipal, db: DbDep) -> dict:
    project = acl.get_project(db, principal, project_id)
    return svc.project_state_snapshot(db, project)


@router.get("/projects/{project_id}/reports/{report_id}")
def get_report(request: Request, project_id: str, report_id: str, principal: CurrentPrincipal) -> dict:
    return uc.get_report(uc.Ctx.from_app(request.app), principal, project_id, report_id)
