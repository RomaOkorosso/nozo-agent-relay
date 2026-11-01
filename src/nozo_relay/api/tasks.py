"""Tasks, messages and task controls."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Query, Request
from fastapi.responses import JSONResponse, Response

from nozo_relay.api.deps import CurrentPrincipal, DbDep
from nozo_relay.api.mutation import (
    IdemKey,
    IfMatch,
    OptIfMatch,
    clock_of,
    maintenance,
    replay_response,
    respond,
    settings_of,
    unit_of_work,
)
from nozo_relay.api.schemas import (
    ControlCreate,
    EmergencyStop,
    MessageCreate,
    ProjectControlCreate,
    TaskCreate,
)
from nozo_relay import usecases as uc
from nozo_relay.services import acl
from nozo_relay.services import controls as controls_svc
from nozo_relay.services import messages as msg_svc
from nozo_relay.services import tasks as svc
from nozo_relay.services.idempotency import Idempotent, request_digest
from nozo_relay.services.tasks import check_version

router = APIRouter(prefix="/api/v1", tags=["tasks"])


@router.get("/projects/{project_id}/tasks")
def list_tasks(
    project_id: str,
    principal: CurrentPrincipal,
    db: DbDep,
    status: Annotated[str | None, Query()] = None,
    limit: Annotated[int | None, Query()] = None,
    cursor: Annotated[str | None, Query()] = None,
) -> dict:
    project = acl.get_project(db, principal, project_id)
    return svc.list_tasks(db, project, status=status, limit=limit, cursor=cursor)


@router.post("/projects/{project_id}/tasks")
def create_task(
    request: Request, project_id: str, body: TaskCreate, principal: CurrentPrincipal, key: IdemKey
) -> Response:
    out = uc.create_task(uc.Ctx.from_app(request.app), principal, project_id, body, key)
    if out.replayed:
        return respond(request, out.status, out.body, replayed=True)
    return respond(
        request, out.status, out.body, etag=out.version,
        location=f"/api/v1/projects/{project_id}/tasks/{out.body['id']}",
    )


@router.get("/projects/{project_id}/tasks/{task_id}")
def get_task(project_id: str, task_id: str, principal: CurrentPrincipal, db: DbDep) -> Response:
    project = acl.get_project(db, principal, project_id)
    task = acl.get_task(db, project, task_id)
    return JSONResponse(svc.task_detail(db, task), headers={"ETag": f'"{task.version}"'})


@router.post("/projects/{project_id}/tasks/{task_id}/enqueue")
def enqueue_task(
    request: Request,
    project_id: str,
    task_id: str,
    principal: CurrentPrincipal,
    key: IdemKey,
    if_match: IfMatch,
) -> Response:
    out = uc.enqueue_task(uc.Ctx.from_app(request.app), principal, project_id, task_id, key, if_match)
    if out.replayed:
        return respond(request, out.status, out.body, replayed=True)
    return respond(request, out.status, out.body, etag=out.version)


# ------------------------------------------------------------------ controls


@router.post("/projects/{project_id}/tasks/{task_id}/controls")
def task_control(
    request: Request,
    project_id: str,
    task_id: str,
    body: ControlCreate,
    principal: CurrentPrincipal,
    key: IdemKey,
    if_match: IfMatch,
) -> Response:
    out = uc.control_task(uc.Ctx.from_app(request.app), principal, project_id, task_id, body, key, if_match)
    if out.replayed:
        return respond(request, out.status, out.body, replayed=True)
    return respond(request, out.status, out.body, etag=out.version)


@router.get("/projects/{project_id}/controls/{control_id}")
def get_control(project_id: str, control_id: str, principal: CurrentPrincipal, db: DbDep) -> dict:
    project = acl.get_project(db, principal, project_id)
    return controls_svc.control_to_dict(controls_svc.get_control(db, project, control_id))


@router.post("/projects/{project_id}/controls")
def project_control(
    request: Request,
    project_id: str,
    body: ProjectControlCreate,
    principal: CurrentPrincipal,
    key: IdemKey,
    if_match: OptIfMatch = None,
) -> Response:
    """Owner pause/resume of all tasks. ``If-Match`` (project version) is optional on this P0 path."""
    maintenance(request)
    clock = clock_of(request)
    settings = settings_of(request)
    with unit_of_work(request) as ws:
        project = acl.get_project(ws, principal, project_id)
        acl.require_owner(principal, project)
        op = Idempotent(
            ws, clock, principal.id, "project.control", key,
            request_digest("project.control", ids={"project_id": project.id}, body=body.model_dump(mode="json"),
                           guards={"if_match": if_match}),
        )
        if (hit := op.replay()) is not None:
            return replay_response(request, hit)
        if if_match is not None:
            check_version(project.version, if_match, "project")
        status, out_body = controls_svc.project_control(
            ws, clock, settings, principal, project, body.command, body.reason
        )
        out = op.finish(status, out_body)
    return respond(request, out.status, out.body)


@router.post("/controls/emergency-stop")
def emergency_stop(request: Request, body: EmergencyStop, principal: CurrentPrincipal, key: IdemKey) -> Response:
    """P0 priority path: pauses every project, fences every active run, no queue involved."""
    maintenance(request)
    clock = clock_of(request)
    settings = settings_of(request)
    if not principal.is_owner:
        raise acl.forbidden("Owner privileges required")
    with unit_of_work(request) as ws:
        op = Idempotent(
            ws, clock, principal.id, "control.emergency_stop", key,
            request_digest("control.emergency_stop", body=body.model_dump(mode="json")),
        )
        if (hit := op.replay()) is not None:
            return replay_response(request, hit)
        out_body = controls_svc.emergency_stop(ws, clock, settings, principal, body.reason)
        out = op.finish(202, out_body)
    return respond(request, out.status, out.body)


# ------------------------------------------------------------------ messages


@router.get("/projects/{project_id}/messages")
def list_messages(
    project_id: str,
    principal: CurrentPrincipal,
    db: DbDep,
    task_id: Annotated[str | None, Query()] = None,
    limit: Annotated[int | None, Query()] = None,
    cursor: Annotated[str | None, Query()] = None,
) -> dict:
    project = acl.get_project(db, principal, project_id)
    if task_id is not None:
        acl.get_task(db, project, task_id)  # 404 for foreign/unknown tasks: no existence oracle
    return msg_svc.list_messages(db, project, task_id=task_id, limit=limit, cursor=cursor)


@router.post("/projects/{project_id}/messages")
def create_message(
    request: Request, project_id: str, body: MessageCreate, principal: CurrentPrincipal, key: IdemKey
) -> Response:
    out = uc.post_message(uc.Ctx.from_app(request.app), principal, project_id, body, key)
    return respond(request, out.status, out.body, replayed=out.replayed)
