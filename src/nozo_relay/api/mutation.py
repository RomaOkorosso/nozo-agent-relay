"""Shared route plumbing: write transactions, guard headers, response helpers, lazy lease sweep.

Mutation pipeline (03_DATA_MODEL invariant 2):
authenticate (dependency) -> ACL -> idempotency lookup -> version/lease guards -> mutation + event
+ cached result, all in ONE ``BEGIN IMMEDIATE`` transaction committed before the response is sent.
"""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from typing import Annotated, Any

from fastapi import Depends, Request
from fastapi.responses import JSONResponse, Response
from sqlalchemy.orm import Session

from nozo_relay.api.errors import RelayError, request_id_of
from nozo_relay.clock import Clock
from nozo_relay.config import Settings
from nozo_relay.db.engine import write_session
from nozo_relay.services import idempotency
from nozo_relay.services.tasks import parse_if_match


def idempotency_key(request: Request) -> str:
    return idempotency.parse_key(request.headers.get("idempotency-key"))


def required_if_match(request: Request) -> int:
    return parse_if_match(request.headers.get("if-match"))


def optional_if_match(request: Request) -> int | None:
    raw = request.headers.get("if-match")
    return parse_if_match(raw) if raw is not None else None


IdemKey = Annotated[str, Depends(idempotency_key)]
IfMatch = Annotated[int, Depends(required_if_match)]
OptIfMatch = Annotated[int | None, Depends(optional_if_match)]


@contextmanager
def unit_of_work(request: Request) -> Iterator[Session]:
    """``BEGIN IMMEDIATE`` session; commits on success, rolls back on any exception."""
    with write_session(request.app.state.engine) as ws:
        yield ws


def clock_of(request: Request) -> Clock:
    return request.app.state.clock


def settings_of(request: Request) -> Settings:
    return request.app.state.settings


def maintenance(request: Request) -> None:
    """Lazily expire leases / overdue stops before lifecycle calls (cheap read probe first)."""
    from nozo_relay import usecases

    usecases.maintenance(usecases.Ctx.from_app(request.app))


def respond(
    request: Request,
    status: int,
    body: dict[str, Any],
    *,
    etag: int | None = None,
    replayed: bool = False,
    location: str | None = None,
) -> Response:
    headers = {"X-Request-Id": request_id_of(request)}
    if etag is not None:
        headers["ETag"] = f'"{etag}"'
    if replayed:
        headers["Idempotent-Replay"] = "true"
    if location:
        headers["Location"] = location
    # Errors that were deliberately committed (e.g. quarantine) keep the uniform error shape.
    if status >= 400 and "error" in body:
        body = {"error": {**body["error"], "request_id": request_id_of(request)}}
    return JSONResponse(body, status_code=status, headers=headers)


def replay_response(request: Request, replay: idempotency.Replay) -> Response:
    return respond(request, replay.status, replay.body, replayed=replay.replayed)


def require_or_raise(condition: bool, error: RelayError) -> None:
    if not condition:
        raise error
