"""Runner/agent lifecycle: claim, start, heartbeat, results, fail, supervisor receipts, dispatch.

Run guards (lease_epoch + revision + policy_digest) replace ``If-Match`` on these endpoints. A
credential alone is not enough: only the principal that claimed a run may drive it, and only while
its epoch is current.
"""

from __future__ import annotations

from fastapi import APIRouter, Request
from fastapi.responses import Response

from nozo_relay.api.deps import CurrentPrincipal
from nozo_relay.api.mutation import (
    IdemKey,
    IfMatch,
    clock_of,
    maintenance,
    replay_response,
    respond,
    settings_of,
    unit_of_work,
)
from nozo_relay.api.schemas import (
    AuditResult,
    ClaimRequest,
    ImplementationResult,
    ReconcileReceipt,
    RunFail,
    RunGuard,
    StoppedReceipt,
)
from nozo_relay.services import acl
from nozo_relay.services import controls as controls_svc
from nozo_relay.services import jobs as jobs_svc
from nozo_relay.services import reports as reports_svc
from nozo_relay.services.idempotency import Idempotent, request_digest

router = APIRouter(prefix="/api/v1", tags=["runs"])


def _digest(op: str, project_id: str, body, **ids) -> str:  # noqa: ANN001
    return request_digest(op, ids={"project_id": project_id, **ids}, body=body.model_dump(mode="json"))


@router.post("/projects/{project_id}/jobs/claim")
def claim(
    request: Request, project_id: str, body: ClaimRequest, principal: CurrentPrincipal, key: IdemKey
) -> Response:
    """Atomic lease (BEGIN IMMEDIATE). 204 = no eligible work. Replays return the SAME run."""
    maintenance(request)
    clock = clock_of(request)
    settings = settings_of(request)
    digest = _digest("job.claim", project_id, body)
    with unit_of_work(request) as ws:
        project = acl.get_project(ws, principal, project_id)
        op = Idempotent(ws, clock, principal.id, "job.claim", key, digest)
        # claim_request_id is a second replay handle: a retry with a fresh header key still maps to one run.
        alias = Idempotent(ws, clock, principal.id, "job.claim_request", body.claim_request_id, digest)
        if (hit := op.replay()) is not None:
            return replay_response(request, hit)
        if (hit := alias.replay()) is not None:
            op.store("job.claim", key, digest, hit.status, hit.body)
            return replay_response(request, hit)
        result = jobs_svc.claim(ws, clock, settings, principal, project, body)
        if result is None:
            return Response(status_code=204, headers={"X-Request-Id": request.state.request_id})
        out = op.finish(200, result)
        alias.store("job.claim_request", body.claim_request_id, digest, 200, result)
    return respond(request, out.status, out.body)


@router.post("/jobs/claim")
def claim_any(request: Request, body: ClaimRequest, principal: CurrentPrincipal, key: IdemKey) -> Response:
    """Cross-project claim: tier, urgency, then round-robin across the caller's projects.

    Paused/disabled projects are never offered. The lease body names ``project_id``; every later call
    (start/heartbeat/result) stays project-scoped. 204 = no eligible work anywhere.
    """
    maintenance(request)
    clock = clock_of(request)
    settings = settings_of(request)
    digest = request_digest("job.claim_any", body=body.model_dump(mode="json"))
    with unit_of_work(request) as ws:
        op = Idempotent(ws, clock, principal.id, "job.claim_any", key, digest)
        alias = Idempotent(ws, clock, principal.id, "job.claim_any_request", body.claim_request_id, digest)
        if (hit := op.replay()) is not None:
            return replay_response(request, hit)
        if (hit := alias.replay()) is not None:
            op.store("job.claim_any", key, digest, hit.status, hit.body)
            return replay_response(request, hit)
        result = jobs_svc.claim_any(ws, clock, settings, principal, body)
        if result is None:
            return Response(status_code=204, headers={"X-Request-Id": request.state.request_id})
        out = op.finish(200, result)
        alias.store("job.claim_any_request", body.claim_request_id, digest, 200, result)
    return respond(request, out.status, out.body)


@router.post("/projects/{project_id}/runs/{run_id}/start")
def start_run(
    request: Request, project_id: str, run_id: str, body: RunGuard, principal: CurrentPrincipal, key: IdemKey
) -> Response:
    maintenance(request)
    clock = clock_of(request)
    with unit_of_work(request) as ws:
        project = acl.get_project(ws, principal, project_id)
        op = Idempotent(ws, clock, principal.id, "run.start", key, _digest("run.start", project.id, body, run_id=run_id))
        if (hit := op.replay()) is not None:
            return replay_response(request, hit)
        out = op.finish(200, jobs_svc.start_run(ws, clock, principal, project, run_id, body))
    return respond(request, out.status, out.body)


@router.post("/projects/{project_id}/runs/{run_id}/heartbeat")
def heartbeat(
    request: Request, project_id: str, run_id: str, body: RunGuard, principal: CurrentPrincipal, key: IdemKey
) -> Response:
    """Naturally idempotent lease renewal: the key is validated but the response is not cached."""
    maintenance(request)
    clock = clock_of(request)
    settings = settings_of(request)
    with unit_of_work(request) as ws:
        project = acl.get_project(ws, principal, project_id)
        result = jobs_svc.heartbeat(ws, clock, settings, principal, project, run_id, body)
    return respond(request, 200, result)


@router.post("/projects/{project_id}/runs/{run_id}/implementation-result")
def implementation_result(
    request: Request, project_id: str, run_id: str, body: ImplementationResult, principal: CurrentPrincipal, key: IdemKey
) -> Response:
    maintenance(request)
    clock = clock_of(request)
    with unit_of_work(request) as ws:
        project = acl.get_project(ws, principal, project_id)
        op = Idempotent(
            ws, clock, principal.id, "run.implementation_result", key,
            _digest("run.implementation_result", project.id, body, run_id=run_id),
        )
        if (hit := op.replay()) is not None:
            return replay_response(request, hit)
        status, out_body = reports_svc.submit_implementation_result(ws, clock, principal, project, run_id, body)
        out = op.finish(status, out_body)
    return respond(request, out.status, out.body)


@router.post("/projects/{project_id}/runs/{run_id}/audit-result")
def audit_result(
    request: Request, project_id: str, run_id: str, body: AuditResult, principal: CurrentPrincipal, key: IdemKey
) -> Response:
    maintenance(request)
    clock = clock_of(request)
    settings = settings_of(request)
    with unit_of_work(request) as ws:
        project = acl.get_project(ws, principal, project_id)
        op = Idempotent(
            ws, clock, principal.id, "run.audit_result", key,
            _digest("run.audit_result", project.id, body, run_id=run_id),
        )
        if (hit := op.replay()) is not None:
            return replay_response(request, hit)
        status, out_body = reports_svc.submit_audit_result(ws, clock, settings, principal, project, run_id, body)
        out = op.finish(status, out_body)
    return respond(request, out.status, out.body)


@router.post("/projects/{project_id}/runs/{run_id}/fail")
def fail_run(
    request: Request, project_id: str, run_id: str, body: RunFail, principal: CurrentPrincipal, key: IdemKey
) -> Response:
    maintenance(request)
    clock = clock_of(request)
    settings = settings_of(request)
    with unit_of_work(request) as ws:
        project = acl.get_project(ws, principal, project_id)
        op = Idempotent(ws, clock, principal.id, "run.fail", key, _digest("run.fail", project.id, body, run_id=run_id))
        if (hit := op.replay()) is not None:
            return replay_response(request, hit)
        out = op.finish(200, jobs_svc.fail_run(ws, clock, settings, principal, project, run_id, body))
    return respond(request, out.status, out.body)


@router.post("/projects/{project_id}/runs/{run_id}/stopped")
def stopped(
    request: Request, project_id: str, run_id: str, body: StoppedReceipt, principal: CurrentPrincipal, key: IdemKey
) -> Response:
    """Registered supervisor receipt (runner credential, NOT the run's lease)."""
    maintenance(request)
    clock = clock_of(request)
    with unit_of_work(request) as ws:
        project = acl.get_project(ws, principal, project_id, allow_runner=True)
        controls_svc.require_supervisor(principal, project)
        op = Idempotent(ws, clock, principal.id, "run.stopped", key, _digest("run.stopped", project.id, body, run_id=run_id))
        if (hit := op.replay()) is not None:
            return replay_response(request, hit)
        out = op.finish(200, controls_svc.confirm_stopped(ws, clock, principal, project, run_id, body))
    return respond(request, out.status, out.body)


@router.post("/projects/{project_id}/runs/{run_id}/reconcile")
def reconcile(
    request: Request, project_id: str, run_id: str, body: ReconcileReceipt, principal: CurrentPrincipal, key: IdemKey
) -> Response:
    maintenance(request)
    clock = clock_of(request)
    with unit_of_work(request) as ws:
        project = acl.get_project(ws, principal, project_id, allow_runner=True)
        controls_svc.require_supervisor(principal, project)
        op = Idempotent(ws, clock, principal.id, "run.reconcile", key, _digest("run.reconcile", project.id, body, run_id=run_id))
        if (hit := op.replay()) is not None:
            return replay_response(request, hit)
        out = op.finish(200, controls_svc.reconcile_run(ws, clock, principal, project, run_id, body))
    return respond(request, out.status, out.body)


@router.post("/projects/{project_id}/jobs/{job_id}/dispatch")
def dispatch(
    request: Request, project_id: str, job_id: str, principal: CurrentPrincipal, key: IdemKey, if_match: IfMatch
) -> Response:
    """One-shot owner admission of a ready job when ``autonomous=false``."""
    clock = clock_of(request)
    with unit_of_work(request) as ws:
        project = acl.get_project(ws, principal, project_id)
        acl.require_owner(principal, project)
        op = Idempotent(
            ws, clock, principal.id, "job.dispatch", key,
            request_digest("job.dispatch", ids={"project_id": project.id, "job_id": job_id}, guards={"if_match": if_match}),
        )
        if (hit := op.replay()) is not None:
            return replay_response(request, hit)
        out = op.finish(200, jobs_svc.dispatch_job(ws, clock, principal, project, job_id, if_match))
    return respond(request, out.status, out.body, etag=out.body["task_version"])
