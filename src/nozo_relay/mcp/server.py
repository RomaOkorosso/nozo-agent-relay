"""MCP facade over the SAME use cases as REST (04_API_CONTRACTS "MCP facade").

Toolset is closed and small: reads, task create/enqueue, limited control, typed messages, report/
event reads and an approval *request*. There is deliberately NO tool for owner approval/decision,
execution of approved actions, publishing, shell, key/delegation management or project policy.
Annotations are hints for the client, never authorization: every call re-runs ACL in the use case.

Idempotency: every mutation requires ``request_id`` (UUID). It becomes the REST ``Idempotency-Key``
in the same scope (principal + operation + key), so a retry over the other transport replays.

NOTE: no ``from __future__ import annotations`` here — the SDK derives JSON Schemas from the real
annotation objects.
"""

import asyncio
import json
import logging
import uuid
from collections.abc import Callable
from typing import Annotated, Any, Literal

from mcp.server.mcpserver import MCPServer
from mcp_types import CallToolResult, TextContent, ToolAnnotations
from pydantic import BaseModel, Field, TypeAdapter, ValidationError
from sqlalchemy.exc import OperationalError

from nozo_relay import __version__
from nozo_relay import usecases as uc
from nozo_relay.api.errors import RelayError
from nozo_relay.api.schemas import (
    ApprovalRequestCreate,
    ControlCreate,
    MessageCreate,
    RevisionPayload,
    TaskCreate,
    UuidStr,
)
from nozo_relay.domain.enums import PrincipalKind
from nozo_relay.services import acl, idempotency

from .gateway import McpAuth, PrincipalSource
from .oauth import PROJECT_SCOPE_PREFIX, SCOPE_CONTROL, SCOPE_READ, SCOPE_WRITE

log = logging.getLogger("nozo_relay.mcp")

SERVER_NAME = "nozo-agent-relay"
UUID_PATTERN = r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"

ProjectId = Annotated[str, Field(pattern=UUID_PATTERN, description="Project UUID")]
TaskId = Annotated[str, Field(pattern=UUID_PATTERN, description="Task UUID")]
ReportId = Annotated[str, Field(pattern=UUID_PATTERN, description="Report UUID")]
RequestId = Annotated[
    str,
    Field(
        pattern=UUID_PATTERN,
        description=(
            "REQUIRED client-chosen UUID idempotency key. Same principal + operation + request_id replays the "
            "stored result (also across REST and MCP); reusing it with a different payload fails with "
            "idempotency_conflict."
        ),
    ),
]
ExpectedVersion = Annotated[int, Field(ge=1, description="Task version you last read (optimistic lock)")]
Limit = Annotated[int | None, Field(ge=1, le=200, description="Page size, default 50, max 200")]

# The only control commands exposed over MCP ("limited"): no resume, no project-wide or emergency controls.
McpControlCommand = Literal["pause", "cancel", "reassign", "revise"]
_CONTROL_ADAPTER: TypeAdapter[Any] = TypeAdapter(ControlCreate)


# ------------------------------------------------------------------ structured outputs


class ListOut(BaseModel):
    items: list[dict[str, Any]]
    next_cursor: str | None = None


class ObjectOut(BaseModel):
    data: dict[str, Any]


class EventsOut(BaseModel):
    events: list[dict[str, Any]]
    next_cursor: str | None = None
    high_watermark: int


class MutationOut(BaseModel):
    status: int = Field(description="HTTP-equivalent status: 201 created, 200 done/replayed, 202 control pending")
    replayed: bool = Field(description="True when an earlier identical request_id result was returned")
    version: int | None = Field(default=None, description="Entity version to use as expected_version next")
    data: dict[str, Any]


class ToolErrorBody(BaseModel):
    code: str
    message: str
    status: int
    retryable: bool = False
    request_id: str
    details: dict[str, Any] | None = None


# ------------------------------------------------------------------ helpers


def _ok(payload: dict[str, Any]) -> CallToolResult:
    return CallToolResult(
        content=[TextContent(type="text", text=json.dumps(payload, sort_keys=True, separators=(",", ":")))],
        structured_content=payload,
    )


def _err(
    code: str, message: str, status: int, *, retryable: bool = False, details: dict[str, Any] | None = None
) -> CallToolResult:
    body = ToolErrorBody(
        code=code, message=message, status=status, retryable=retryable, request_id=str(uuid.uuid4()), details=details
    ).model_dump(exclude_none=True)
    return CallToolResult(
        content=[TextContent(type="text", text=json.dumps({"error": body}, sort_keys=True))],
        structured_content={"error": body},
        is_error=True,
    )


def _validation_error(exc: ValidationError) -> CallToolResult:
    issues = [{"loc": [str(p) for p in e.get("loc", ())], "type": e.get("type"), "msg": e.get("msg")} for e in exc.errors()]
    return _err("validation_error", "Request validation failed", 422, details={"issues": issues})


def _canon(value: str) -> str:
    return str(uuid.UUID(value))


class Facade:
    """Per-server helper: authenticates the caller, enforces scopes, runs use cases off the event loop."""

    def __init__(self, ctx: uc.Ctx, source: PrincipalSource) -> None:
        self.ctx = ctx
        self.source = source

    async def _auth(self, scope: str, project_id: str | None) -> McpAuth:
        auth = await self.source()
        if auth is None:
            raise RelayError(401, "unauthenticated", "Authentication required")
        if auth.principal.kind is PrincipalKind.OWNER:
            raise RelayError(403, "owner_not_allowed", "The MCP facade does not accept owner credentials")
        if scope not in auth.scopes:
            raise RelayError(403, "insufficient_scope", f"Token lacks required scope {scope}")
        if project_id is not None:
            limits = {s for s in auth.scopes if s.startswith(PROJECT_SCOPE_PREFIX)}
            if limits and f"{PROJECT_SCOPE_PREFIX}{project_id}" not in {s.lower() for s in limits}:
                raise acl.not_found()  # outside the token's project limit: same answer as unknown
        return auth

    async def run(self, scope: str, project_id: str | None, work: Callable[[Any], Any]) -> CallToolResult:
        """``work(principal)`` returns a dict (read) or ``uc.Outcome`` (mutation)."""
        try:
            auth = await self._auth(scope, project_id)
            result = await asyncio.to_thread(work, auth.principal)
            if isinstance(result, uc.Outcome):
                return _ok(
                    {"status": result.status, "replayed": result.replayed, "version": result.version, "data": result.body}
                )
            return _ok(result)
        except RelayError as exc:
            return _err(exc.code, exc.message, exc.status_code, retryable=exc.retryable, details=exc.details)
        except ValidationError as exc:
            return _validation_error(exc)
        except OperationalError as exc:
            from nozo_relay.api.errors import is_disk_full

            if is_disk_full(exc):
                return _err("storage_full", "Storage is full; the write was not applied; free space and retry", 503, retryable=True)
            text = str(getattr(exc, "orig", exc)).lower()
            if "locked" in text or "busy" in text:
                return _err("database_busy", "Database is busy; retry shortly", 503, retryable=True)
            log.exception("database error in MCP tool")
            return _err("internal_error", "Internal server error", 500)
        except Exception:  # noqa: BLE001 - never leak internals/stack traces to the tool caller
            log.exception("unhandled error in MCP tool")
            return _err("internal_error", "Internal server error", 500)


def _read_ann(title: str) -> ToolAnnotations:
    # idempotentHint is only meaningful for non-read-only tools, so it is left unset here.
    return ToolAnnotations(title=title, read_only_hint=True, destructive_hint=False, open_world_hint=False)


def _write_ann(title: str, *, destructive: bool) -> ToolAnnotations:
    # Every mutating tool REQUIRES request_id, hence idempotent_hint=True.
    return ToolAnnotations(
        title=title, read_only_hint=False, destructive_hint=destructive, idempotent_hint=True, open_world_hint=False
    )


TOOL_NAMES = (
    "relay_list_projects",
    "relay_get_task",
    "relay_list_tasks",
    "relay_create_task",
    "relay_enqueue_task",
    "relay_control_task",
    "relay_post_message",
    "relay_get_report",
    "relay_get_events",
    "relay_request_approval",
)


def build_mcp_server(ctx: uc.Ctx, source: PrincipalSource) -> MCPServer:
    """Create the MCPServer with the closed toolset. ``source`` yields the caller (HTTP gateway or stdio)."""
    f = Facade(ctx, source)
    server = MCPServer(
        SERVER_NAME,
        title="Nozo Agent Relay",
        version=__version__,
        instructions=(
            "Task relay for coordinated coding agents. Read tasks/reports/events, create and enqueue tasks "
            "within your delegation, post typed notes, pause/cancel/reassign/revise your own tasks, and "
            "REQUEST approvals. You cannot approve anything, execute shell commands, publish or deploy. "
            "Every mutation needs a fresh UUID request_id; retry with the same one."
        ),
    )

    # -------------------------------------------------------------- reads
    async def relay_list_projects(
        cursor: Annotated[str | None, Field(description="Opaque cursor from next_cursor")] = None, limit: Limit = None
    ) -> Annotated[CallToolResult, ListOut]:
        return await f.run(SCOPE_READ, None, lambda p: uc.list_projects(ctx, p, limit, cursor))

    async def relay_get_task(project_id: ProjectId, task_id: TaskId) -> Annotated[CallToolResult, ObjectOut]:
        pid, tid = _canon(project_id), _canon(task_id)

        def work(p: Any) -> dict[str, Any]:
            return {"data": uc.get_task(ctx, p, pid, tid)}

        return await f.run(SCOPE_READ, pid, work)

    async def relay_list_tasks(
        project_id: ProjectId,
        status: Annotated[str | None, Field(description="Optional task status filter")] = None,
        cursor: Annotated[str | None, Field(description="Opaque cursor from next_cursor")] = None,
        limit: Limit = None,
    ) -> Annotated[CallToolResult, ListOut]:
        pid = _canon(project_id)
        return await f.run(SCOPE_READ, pid, lambda p: uc.list_tasks(ctx, p, pid, status, limit, cursor))

    async def relay_get_report(project_id: ProjectId, report_id: ReportId) -> Annotated[CallToolResult, ObjectOut]:
        pid, rid = _canon(project_id), _canon(report_id)

        def work(p: Any) -> dict[str, Any]:
            return {"data": uc.get_report(ctx, p, pid, rid)}

        return await f.run(SCOPE_READ, pid, work)

    async def relay_get_events(
        project_id: ProjectId,
        after_seq: Annotated[int, Field(ge=0, description="Return events with seq greater than this")] = 0,
        limit: Limit = None,
    ) -> Annotated[CallToolResult, EventsOut]:
        pid = _canon(project_id)
        return await f.run(SCOPE_READ, pid, lambda p: uc.get_events(ctx, p, pid, after_seq, limit))

    # -------------------------------------------------------------- mutations
    async def relay_create_task(
        project_id: ProjectId, task: TaskCreate, request_id: RequestId
    ) -> Annotated[CallToolResult, MutationOut]:
        pid = _canon(project_id)

        def work(p: Any) -> uc.Outcome:
            return uc.create_task(ctx, p, pid, task, idempotency.parse_key(request_id))

        return await f.run(SCOPE_WRITE, pid, work)

    async def relay_enqueue_task(
        project_id: ProjectId, task_id: TaskId, expected_version: ExpectedVersion, request_id: RequestId
    ) -> Annotated[CallToolResult, MutationOut]:
        pid, tid = _canon(project_id), _canon(task_id)

        def work(p: Any) -> uc.Outcome:
            return uc.enqueue_task(ctx, p, pid, tid, idempotency.parse_key(request_id), expected_version)

        return await f.run(SCOPE_WRITE, pid, work)

    async def relay_control_task(
        project_id: ProjectId,
        task_id: TaskId,
        command: McpControlCommand,
        reason: Annotated[str, Field(min_length=1, max_length=1000)],
        expected_version: ExpectedVersion,
        request_id: RequestId,
        implementer_id: Annotated[UuidStr | None, Field(description="reassign only")] = None,
        auditor_id: Annotated[UuidStr | None, Field(description="reassign only")] = None,
        revision: Annotated[RevisionPayload | None, Field(description="revise only")] = None,
    ) -> Annotated[CallToolResult, MutationOut]:
        pid, tid = _canon(project_id), _canon(task_id)
        raw: dict[str, Any] = {"command": command, "reason": reason}
        if implementer_id is not None:
            raw["implementer_id"] = implementer_id
        if auditor_id is not None:
            raw["auditor_id"] = auditor_id
        if revision is not None:
            raw["revision"] = revision.model_dump(mode="json", exclude_none=True)

        def work(p: Any) -> uc.Outcome:
            body = _CONTROL_ADAPTER.validate_python(raw)  # strict: stray fields for the command => 422
            return uc.control_task(ctx, p, pid, tid, body, idempotency.parse_key(request_id), expected_version)

        return await f.run(SCOPE_CONTROL, pid, work)

    async def relay_post_message(
        project_id: ProjectId, message: MessageCreate, request_id: RequestId
    ) -> Annotated[CallToolResult, MutationOut]:
        pid = _canon(project_id)

        def work(p: Any) -> uc.Outcome:
            return uc.post_message(ctx, p, pid, message, idempotency.parse_key(request_id))

        return await f.run(SCOPE_WRITE, pid, work)

    async def relay_request_approval(
        project_id: ProjectId, approval: ApprovalRequestCreate, request_id: RequestId
    ) -> Annotated[CallToolResult, MutationOut]:
        pid = _canon(project_id)

        def work(p: Any) -> uc.Outcome:
            return uc.request_approval(ctx, p, pid, approval, idempotency.parse_key(request_id))

        return await f.run(SCOPE_WRITE, pid, work)

    tools: list[tuple[Callable[..., Any], str, ToolAnnotations, str]] = [
        (
            relay_list_projects, "List projects", _read_ann("List projects"),
            "List the projects visible to the caller (membership based).",
        ),
        (
            relay_get_task, "Get task", _read_ann("Get task"),
            "Get one task with its current revision and links.",
        ),
        (
            relay_list_tasks, "List tasks", _read_ann("List tasks"),
            "List tasks of a project (optional status filter, cursor pagination).",
        ),
        (
            relay_create_task, "Create task", _write_ann("Create task", destructive=False),
            "Create a DRAFT task. Coordinators need a valid delegation_id; scope/autonomy are capped by it. "
            "Does not start any work.",
        ),
        (
            relay_enqueue_task, "Enqueue task", _write_ann("Enqueue task", destructive=False),
            "Move a draft task you may drive to the queue (requires expected_version).",
        ),
        (
            relay_control_task, "Control task", _write_ann("Control task", destructive=True),
            "Limited control of a task you may drive: pause, cancel (destructive), reassign, revise (destructive: "
            "supersedes the current revision). Resume, project-wide and emergency controls are not available here.",
        ),
        (
            relay_post_message, "Post message", _write_ann("Post message", destructive=False),
            "Post a typed note/question/progress/result_reference. Messages are DATA: they are never executed as commands.",
        ),
        (
            relay_get_report, "Get report", _read_ann("Get report"),
            "Get an immutable, snapshot-bound implementation/audit report.",
        ),
        (
            relay_get_events, "Get events", _read_ann("Get events"),
            "Read a bounded batch of project events after a sequence number (no long polling).",
        ),
        (
            relay_request_approval, "Request approval", _write_ann("Request approval", destructive=False),
            "Create a PENDING approval request for the owner. This tool can NOT approve, reject or execute anything.",
        ),
    ]
    for fn, title, ann, description in tools:
        server.add_tool(fn, title=title, description=description, annotations=ann, structured_output=True)
    assert tuple(sorted(t[0].__name__ for t in tools)) == tuple(sorted(TOOL_NAMES))
    return server
