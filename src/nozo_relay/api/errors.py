"""Uniform error shape: {error:{code,message,request_id,retryable,details}} (04_API_CONTRACTS)."""

from __future__ import annotations

import logging
import sqlite3
import uuid
from typing import Any

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict
from sqlalchemy.exc import OperationalError
from starlette.exceptions import HTTPException as StarletteHTTPException

log = logging.getLogger("nozo_relay.api")

_STATUS_CODES = {
    400: "bad_request",
    401: "unauthenticated",
    403: "forbidden",
    404: "not_found",
    405: "method_not_allowed",
    409: "conflict",
    412: "precondition_failed",
    413: "payload_too_large",
    422: "validation_error",
    428: "precondition_required",
    429: "rate_limited",
    503: "unavailable",
}


class ErrorBody(BaseModel):
    model_config = ConfigDict(extra="forbid")

    code: str
    message: str
    request_id: str
    retryable: bool = False
    details: dict[str, Any] | None = None


class ErrorResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    error: ErrorBody


class RelayError(Exception):
    def __init__(
        self,
        status_code: int,
        code: str,
        message: str,
        *,
        retryable: bool = False,
        details: dict[str, Any] | None = None,
        headers: dict[str, str] | None = None,
    ) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.code = code
        self.message = message
        self.retryable = retryable
        self.details = details
        self.headers = headers


def new_request_id() -> str:
    return str(uuid.uuid4())


def request_id_of(request: Request) -> str:
    rid = getattr(request.state, "request_id", None)
    if rid is None:
        rid = new_request_id()
        request.state.request_id = rid
    return rid


def error_response(
    request: Request,
    status_code: int,
    code: str,
    message: str,
    *,
    retryable: bool = False,
    details: dict[str, Any] | None = None,
    headers: dict[str, str] | None = None,
) -> JSONResponse:
    rid = request_id_of(request)
    body = ErrorResponse(
        error=ErrorBody(
            code=code, message=message, request_id=rid, retryable=retryable, details=details
        )
    )
    hdrs = {"X-Request-Id": rid, **(headers or {})}
    return JSONResponse(body.model_dump(), status_code=status_code, headers=hdrs)


_FULL_MARKERS = ("disk is full", "sqlite_full", "errno 28", "no space left", "enospc")


def is_disk_full(exc: BaseException) -> bool:
    """SQLITE_FULL / ENOSPC anywhere in the exception chain (SQLAlchemy wrapper, raw sqlite3, OSError)."""
    seen: set[int] = set()
    cur: BaseException | None = exc
    while cur is not None and id(cur) not in seen:
        seen.add(id(cur))
        orig = getattr(cur, "orig", None)
        if isinstance(orig, BaseException) and is_disk_full(orig):
            return True
        if isinstance(cur, OSError) and cur.errno == 28:
            return True
        if getattr(cur, "sqlite_errorname", "") == "SQLITE_FULL":
            return True
        if any(m in str(cur).lower() for m in _FULL_MARKERS):
            return True
        cur = cur.__cause__ or cur.__context__
    return False


def _storage_full(request: Request) -> JSONResponse:
    log.error("storage full request_id=%s", request_id_of(request))
    return error_response(
        request, 503, "storage_full",
        "Storage is full; the write was not applied. Free disk space and retry (same Idempotency-Key is safe)",
        retryable=True, headers={"Retry-After": "30"},
    )


def install_error_handlers(app: FastAPI) -> None:
    @app.exception_handler(RelayError)
    async def _relay(request: Request, exc: RelayError) -> JSONResponse:
        return error_response(
            request,
            exc.status_code,
            exc.code,
            exc.message,
            retryable=exc.retryable,
            details=exc.details,
            headers=exc.headers,
        )

    @app.exception_handler(StarletteHTTPException)
    async def _http(request: Request, exc: StarletteHTTPException) -> JSONResponse:
        code = _STATUS_CODES.get(exc.status_code, "http_error")
        message = exc.detail if isinstance(exc.detail, str) else code
        return error_response(
            request,
            exc.status_code,
            code,
            message,
            retryable=exc.status_code == 503,
            headers=dict(exc.headers) if exc.headers else None,
        )

    @app.exception_handler(RequestValidationError)
    async def _validation(request: Request, exc: RequestValidationError) -> JSONResponse:
        # Only location/type/message: never echo submitted input (may contain secrets).
        issues = [
            {"loc": [str(p) for p in e.get("loc", ())], "type": e.get("type"), "msg": e.get("msg")}
            for e in exc.errors()
        ]
        return error_response(
            request, 422, "validation_error", "Request validation failed", details={"issues": issues}
        )

    @app.exception_handler(OperationalError)
    async def _db_operational(request: Request, exc: OperationalError) -> JSONResponse:
        if is_disk_full(exc):
            return _storage_full(request)
        text = str(getattr(exc, "orig", exc)).lower()
        if "locked" in text or "busy" in text:
            # Bounded retry already happened (busy_timeout); never report silent success.
            log.warning("sqlite busy request_id=%s", request_id_of(request))
            return error_response(
                request, 503, "database_busy", "Database is busy; retry shortly",
                retryable=True, headers={"Retry-After": "1"},
            )
        log.exception("database error request_id=%s", request_id_of(request))
        return error_response(request, 500, "internal_error", "Internal server error")

    @app.exception_handler(sqlite3.OperationalError)
    async def _raw_sqlite(request: Request, exc: sqlite3.OperationalError) -> JSONResponse:
        # Raw driver error that bypassed the SQLAlchemy wrapper.
        if is_disk_full(exc):
            return _storage_full(request)
        text = str(exc).lower()
        if "locked" in text or "busy" in text:
            return error_response(
                request, 503, "database_busy", "Database is busy; retry shortly",
                retryable=True, headers={"Retry-After": "1"},
            )
        log.exception("database error request_id=%s", request_id_of(request))
        return error_response(request, 500, "internal_error", "Internal server error")

    @app.exception_handler(Exception)
    async def _unhandled(request: Request, exc: Exception) -> JSONResponse:
        if is_disk_full(exc):
            return _storage_full(request)
        log.exception("unhandled error request_id=%s", request_id_of(request))
        return error_response(request, 500, "internal_error", "Internal server error")
