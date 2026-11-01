"""POST/GET /projects/{p}/artifacts - raw bytes in, opaque id out; always served as an attachment."""

from __future__ import annotations

import hashlib

from fastapi import APIRouter, Request
from fastapi.responses import Response
from starlette.concurrency import run_in_threadpool

from nozo_relay.api.deps import CurrentPrincipal, DbDep
from nozo_relay.api.errors import RelayError
from nozo_relay.api.mutation import IdemKey, clock_of, replay_response, respond, settings_of, unit_of_work
from nozo_relay.api.schemas import _canon_uuid
from nozo_relay.services import acl
from nozo_relay.services import artifacts as svc
from nozo_relay.services.idempotency import Idempotent, request_digest

router = APIRouter(prefix="/api/v1", tags=["artifacts"])


def _opt_uuid(request: Request, header: str) -> str | None:
    raw = request.headers.get(header)
    if raw is None:
        return None
    try:
        return _canon_uuid(raw.strip())
    except ValueError:
        raise RelayError(422, "invalid_header", f"{header} must be a UUID") from None


async def _read_capped(request: Request, limit: int) -> bytes:
    buf = bytearray()
    async for chunk in request.stream():
        buf += chunk
        if len(buf) > limit:
            raise RelayError(413, "payload_too_large", "Artifact exceeds the per-file limit")
    return bytes(buf)


@router.post("/projects/{project_id}/artifacts")
async def upload_artifact(
    request: Request, project_id: str, principal: CurrentPrincipal, key: IdemKey
) -> Response:
    """Body = the raw bytes (Content-Type is NOT trusted). Optional ``X-Task-Id`` / ``X-Run-Id``."""
    settings = settings_of(request)
    task_id = _opt_uuid(request, "x-task-id")
    run_id = _opt_uuid(request, "x-run-id")
    data = await _read_capped(request, settings.artifact_max_bytes)
    clock = clock_of(request)

    def work() -> Response:
        with unit_of_work(request) as ws:
            project = acl.get_project(ws, principal, project_id)
            op = Idempotent(
                ws, clock, principal.id, "artifact.upload", key,
                request_digest(
                    "artifact.upload",
                    ids={"project_id": project.id, "task_id": task_id, "run_id": run_id},
                    body={"sha256": hashlib.sha256(data).hexdigest(), "size": len(data)},
                ),
            )
            if (hit := op.replay()) is not None:
                return replay_response(request, hit)
            art = svc.store_artifact(ws, clock, settings, principal, project, data, task_id=task_id, run_id=run_id)
            out = op.finish(201, svc.artifact_to_dict(art))
        return respond(request, out.status, out.body, location=f"/api/v1/projects/{project_id}/artifacts/{out.body['id']}")

    return await run_in_threadpool(work)


@router.get("/projects/{project_id}/artifacts/{artifact_id}")
def download_artifact(
    request: Request, project_id: str, artifact_id: str, principal: CurrentPrincipal, db: DbDep
) -> Response:
    project = acl.get_project(db, principal, project_id)
    art = svc.get_artifact(db, project, artifact_id)
    data = svc.read_bytes(settings_of(request), art)
    return Response(
        content=data,
        media_type="application/octet-stream",  # never the stored/declared type
        headers={
            "Content-Disposition": f'attachment; filename="artifact-{art.id}.bin"',
            "X-Artifact-Sha256": art.sha256,
            "X-Artifact-Media-Type-Sniffed": art.media_type,
            "Content-Security-Policy": "sandbox; default-src 'none'",
        },
    )
