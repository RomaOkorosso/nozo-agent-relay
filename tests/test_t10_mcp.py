"""T10: MCP facade (Streamable HTTP /mcp + stdio) over the same use cases as REST, OAuth scaffolding.

Everything runs against the REAL official SDK (``mcp`` 2.x) client and server in-process (ASGI
transport) plus one real loopback socket probe. No LLM, no tunnel, no external account.
Set ``NOZO_EVIDENCE_DIR`` to write the T10 evidence JSON files.
"""

from __future__ import annotations

import asyncio
import base64
import contextlib
import hashlib
import json
import os
import secrets
import socket
import sys
import threading
import time
import uuid
from collections.abc import AsyncIterator
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlsplit

import httpx2
import pytest
import pytest_asyncio
from mcp import Client, StdioServerParameters
from mcp.client.stdio import stdio_client
from mcp.client.streamable_http import streamable_http_client
from sqlalchemy import select

from api_helpers import SCOPE, Api, uid
from conftest import BASE_URL, OWNER_PASSWORD, Env, make_settings
from nozo_relay.auth.credentials import issue_credential, revoke_credential
from nozo_relay.bootstrap import bootstrap, credentials_path
from nozo_relay.clock import FakeClock
from nozo_relay.db.engine import write_session
from nozo_relay.db.models import ApprovalRequest, Credential, Message, Principal, Task
from nozo_relay.main import create_app
from nozo_relay.mcp.install import sdk_available
from nozo_relay.mcp.server import TOOL_NAMES

MCP_URL = f"{BASE_URL}/mcp"
EVIDENCE = Path(os.environ["NOZO_EVIDENCE_DIR"]) if os.environ.get("NOZO_EVIDENCE_DIR") else None
EXPECTED_TOOLS = set(TOOL_NAMES)
FORBIDDEN_WORDS = ("shell", "exec", "sudo", "publish", "deploy", "approve", "decide", "decision", "key", "delegat", "policy")


def write_evidence(name: str, doc: dict[str, Any]) -> None:
    if EVIDENCE is not None:
        EVIDENCE.mkdir(parents=True, exist_ok=True)
        (EVIDENCE / name).write_text(json.dumps(doc, indent=2, sort_keys=True) + "\n")


# ------------------------------------------------------------------------------------------------ harness
class Harness:
    def __init__(self, api: Api) -> None:
        self.api = api
        self.app = api.app

    def http(self, key: str | None = None, headers: dict[str, str] | None = None) -> httpx2.AsyncClient:
        h = dict(headers or {})
        if key is not None:
            h["Authorization"] = f"Bearer {key}"
        return httpx2.AsyncClient(transport=httpx2.ASGITransport(app=self.app), base_url=BASE_URL, headers=h)

    @contextlib.asynccontextmanager
    async def client(self, key: str, *, mode: str = "legacy", headers: dict[str, str] | None = None) -> AsyncIterator[Client]:
        async with self.http(key, headers) as hc:
            async with Client(streamable_http_client(MCP_URL, http_client=hc), mode=mode) as c:
                yield c

    async def call(self, key: str, tool: str, args: dict[str, Any], *, mode: str = "legacy"):
        async with self.client(key, mode=mode) as c:
            return await c.call_tool(tool, args)


async def _lifespan_harness(api: Api) -> AsyncIterator[Harness]:
    """Run the app lifespan (starts the SDK session manager behind /mcp) inside ONE dedicated task:
    anyio cancel scopes must be entered and exited by the same task, unlike pytest-asyncio fixtures."""
    started, stop = asyncio.Event(), asyncio.Event()

    async def runner() -> None:
        async with api.app.router.lifespan_context(api.app):  # type: ignore[attr-defined]
            started.set()
            await stop.wait()

    task = asyncio.create_task(runner())
    waiter = asyncio.create_task(started.wait())
    await asyncio.wait({task, waiter}, return_when=asyncio.FIRST_COMPLETED)
    if task.done():
        task.result()
    yield Harness(api)
    stop.set()
    await task


@pytest_asyncio.fixture
async def mcp(api: Api) -> AsyncIterator[Harness]:
    async for h in _lifespan_harness(api):
        yield h


def delegation(api: Api, cid: str, *, valid_for: timedelta = timedelta(hours=1), actions=None) -> dict[str, Any]:
    until = datetime.fromtimestamp(api.clock.now_ms() / 1000, tz=UTC) + valid_for
    r = api.req(
        "owner", "POST", api.p("/delegations"),
        {
            "coordinator_id": cid,
            "allowed_actions": actions or ["task.create", "task.enqueue", "task.control"],
            "scope_ceiling": {"allowed_paths": ["src/**"], "max_changed_files": 5, "max_diff_lines": 200},
            "valid_until": until.isoformat(),
        },
    )
    assert r.status_code == 201, r.text
    return r.json()


@pytest.fixture
def coord(api: Api) -> dict[str, Any]:
    cid, key = api.make_principal("coordinator", "coord")
    return {"id": cid, "key": key, "delegation": delegation(api, cid)}


def tbody(api: Api, coord: dict[str, Any], **over: Any) -> dict[str, Any]:
    return api.task_body(autonomous=False, delegation_id=coord["delegation"]["id"], **over)


def err(result) -> dict[str, Any]:
    assert result.is_error, result
    return result.structured_content["error"]


def ok(result) -> dict[str, Any]:
    assert not result.is_error, result
    return result.structured_content


def credential_id(api: Api, key: str) -> str:
    prefix = key.split("_", 1)[1].split(".", 1)[0]
    with api.db() as s:
        return s.execute(select(Credential.id).where(Credential.key_prefix == prefix)).scalar_one()


def revoke(api: Api, key: str) -> None:
    with write_session(api.app.state.engine) as ws:  # type: ignore[attr-defined]
        assert revoke_credential(ws, api.clock, credential_id(api, key))


# ------------------------------------------------------------------------------------------------ catalog
async def test_toolset_is_closed_and_has_no_owner_or_execution_tools(mcp: Harness, coord):
    async with mcp.client(coord["key"]) as c:
        tools = (await c.list_tools()).tools
    names = {t.name for t in tools}
    assert names == EXPECTED_TOOLS
    for n in names:
        assert not any(w in n for w in FORBIDDEN_WORDS), n
    # the approval tool REQUESTS only; its description says so and there is no decision/execute sibling
    approval = next(t for t in tools if t.name == "relay_request_approval")
    assert "can not approve" in approval.description.lower()
    control = next(t for t in tools if t.name == "relay_control_task")
    assert set(control.input_schema["properties"]["command"]["enum"]) == {"pause", "cancel", "complete", "reassign", "revise"}
    for t in tools:  # every tool publishes input AND output JSON Schema
        assert t.input_schema["type"] == "object" and t.output_schema is not None, t.name


async def test_annotations_are_accurate(mcp: Harness, coord):
    async with mcp.client(coord["key"]) as c:
        tools = {t.name: t for t in (await c.list_tools()).tools}
    reads = {"relay_list_projects", "relay_get_task", "relay_list_tasks", "relay_get_report", "relay_get_events"}
    for n, t in tools.items():
        a = t.annotations
        assert a is not None and a.open_world_hint is False, n
        required = set(t.input_schema.get("required", []))
        if n in reads:
            assert a.read_only_hint is True and a.destructive_hint is False and a.idempotent_hint is not True, n
            assert "request_id" not in t.input_schema["properties"], n
        else:
            # every mutation REQUIRES request_id => idempotentHint is truthful; none is read-only
            assert a.read_only_hint is False and a.idempotent_hint is True, n
            assert "request_id" in required, n
    # cancel/revise are the potentially destructive ones
    assert tools["relay_control_task"].annotations.destructive_hint is True
    for n in ("relay_create_task", "relay_enqueue_task", "relay_post_message", "relay_request_approval"):
        assert tools[n].annotations.destructive_hint is False


# ------------------------------------------------------------------------------------------------ negotiation
async def test_protocol_negotiation_and_unsupported_version(mcp: Harness, coord):
    from mcp_types import LATEST_PROTOCOL_VERSION
    from mcp_types.version import HANDSHAKE_PROTOCOL_VERSIONS, MODERN_PROTOCOL_VERSIONS

    results: dict[str, Any] = {}
    async with mcp.client(coord["key"], mode="legacy") as c:
        results["legacy_initialize"] = c.protocol_version
        assert c.server_info is not None and c.server_info.name == "nozo-agent-relay"
    async with mcp.client(coord["key"], mode="auto") as c:
        results["auto_discover"] = c.protocol_version
        assert (await c.call_tool("relay_list_projects", {})).is_error is False
    assert results["legacy_initialize"] in HANDSHAKE_PROTOCOL_VERSIONS
    assert results["auto_discover"] in MODERN_PROTOCOL_VERSIONS == (LATEST_PROTOCOL_VERSION,)

    # unsupported modern version: HTTP 400 + JSON-RPC -32022 naming the supported set (no silent downgrade)
    meta = {"io.modelcontextprotocol/protocolVersion": "1999-01-01", "io.modelcontextprotocol/clientCapabilities": {}}
    async with mcp.http(coord["key"]) as hc:
        r = await hc.post(
            "/mcp",
            headers={**ACCEPT, "MCP-Protocol-Version": "1999-01-01", "Mcp-Method": "tools/list"},
            json={"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {"_meta": meta}},
        )
        results["unsupported_modern_version_status"] = r.status_code
        results["unsupported_modern_version_body"] = r.json()
        assert r.status_code == 400
        assert r.json()["error"]["code"] == -32022 and r.json()["error"]["data"]["supported"] == list(MODERN_PROTOCOL_VERSIONS)
        assert r.json()["error"]["data"]["requested"] == "1999-01-01"
        # legacy initialize offering an unknown version: the server counter-offers one it supports
        # (spec: the client then decides to continue or disconnect); it never echoes the unknown one.
        r = await hc.post(
            "/mcp", headers=ACCEPT,
            json={"jsonrpc": "2.0", "id": 1, "method": "initialize",
                  "params": {"protocolVersion": "1999-01-01", "capabilities": {}, "clientInfo": {"name": "probe", "version": "0"}}},
        )
        counter = r.json()["result"]["protocolVersion"]
        results["initialize_unknown_version_counter_offer"] = counter
        assert r.status_code == 200 and counter in HANDSHAKE_PROTOCOL_VERSIONS and counter != "1999-01-01"
        # a modern-era header on a request without the envelope is rejected, not guessed at
        r = await hc.post("/mcp", headers={**ACCEPT, "MCP-Protocol-Version": "2026-07-28"}, json=RPC)
        assert r.status_code == 400 and "error" in r.json()
    write_evidence(
        "protocol_negotiation.json",
        {
            "sdk": "mcp 2.3.0 (mcp-types 2.3.0)",
            "transport": "streamable-http, stateless, JSON responses, in-process ASGI",
            "negotiated": results,
            "sdk_handshake_versions": list(HANDSHAKE_PROTOCOL_VERSIONS),
            "sdk_modern_versions": list(MODERN_PROTOCOL_VERSIONS),
            "client_modes": {"legacy": "initialize handshake", "auto": "server/discover with fallback to initialize"},
        },
    )


# ------------------------------------------------------------------------------------------------ reads
async def test_read_tools_return_structured_data_scoped_by_acl(mcp: Harness, api: Api, coord):
    owner_task = api.create_task()
    async with mcp.client(coord["key"]) as c:
        projects = ok(await c.call_tool("relay_list_projects", {}))
        assert [p["id"] for p in projects["items"]] == [api.project_id]
        t = ok(await c.call_tool("relay_get_task", {"project_id": api.project_id, "task_id": owner_task["id"]}))
        assert t["data"]["id"] == owner_task["id"] and t["data"]["version"] == owner_task["version"]
        lst = ok(await c.call_tool("relay_list_tasks", {"project_id": api.project_id, "limit": 1}))
        assert [x["id"] for x in lst["items"]] == [owner_task["id"]]
        assert ok(await c.call_tool("relay_list_tasks", {"project_id": api.project_id, "status": "queued"}))["items"] == []
        ev = ok(await c.call_tool("relay_get_events", {"project_id": api.project_id, "after_seq": 0, "limit": 5}))
        assert ev["events"] and ev["high_watermark"] >= ev["events"][-1]["seq"]
        # unknown / foreign project -> same 404 as REST (no existence oracle)
        e = err(await c.call_tool("relay_get_task", {"project_id": uid(), "task_id": owner_task["id"]}))
        assert e["code"] == "not_found" and e["status"] == 404
        bad = await c.call_tool("relay_list_tasks", {"project_id": api.project_id, "status": "nope"})
        assert err(bad)["code"] == "invalid_status"
        assert err(await c.call_tool("relay_list_tasks", {"project_id": api.project_id, "cursor": "!!"}))["code"] == "invalid_cursor"


async def test_get_report_returns_snapshot_bound_report_and_hides_foreign_ids(mcp: Harness, api: Api, coord):
    api.queued_task()
    api.implement()
    task_id = api.audit("PASS")["task_id"]
    task = api.get_task(task_id)
    rid = task["latest_report_id"]
    assert rid
    async with mcp.client(coord["key"]) as c:
        rep = ok(await c.call_tool("relay_get_report", {"project_id": api.project_id, "report_id": rid}))
        assert rep["data"]["id"] == rid
        rest = api.req("impl", "GET", api.p(f"/reports/{rid}")).json()
        assert rep["data"] == rest  # byte-for-byte the REST representation
        assert err(await c.call_tool("relay_get_report", {"project_id": api.project_id, "report_id": uid()}))["code"] == "not_found"


# ------------------------------------------------------------------------------------------------ mutations
async def test_create_enqueue_control_message_and_approval_request_via_mcp(mcp: Harness, api: Api, coord):
    key = coord["key"]
    async with mcp.client(key) as c:
        created = ok(await c.call_tool(
            "relay_create_task",
            {"project_id": api.project_id, "task": tbody(api, coord), "request_id": uid()},
        ))
        assert created["status"] == 201 and created["replayed"] is False
        task = created["data"]
        assert task["status"] == "draft" and task["authority_tier"] == "P1"  # tier from the credential
        # state visible through REST == same use case
        assert api.get_task(task["id"])["id"] == task["id"]

        enq = ok(await c.call_tool(
            "relay_enqueue_task",
            {"project_id": api.project_id, "task_id": task["id"], "expected_version": created["version"], "request_id": uid()},
        ))
        assert enq["data"]["status"] == "queued" and enq["version"] > created["version"]
        stale = err(await c.call_tool(
            "relay_enqueue_task",
            {"project_id": api.project_id, "task_id": task["id"], "expected_version": created["version"], "request_id": uid()},
        ))
        assert stale["code"] in {"stale_version", "precondition_failed", "version_conflict"} or stale["status"] == 412

        ctl = ok(await c.call_tool(
            "relay_control_task",
            {"project_id": api.project_id, "task_id": task["id"], "command": "pause", "reason": "hold on",
             "expected_version": enq["version"], "request_id": uid()},
        ))
        assert ctl["status"] in {200, 202} and "task" in ctl["data"]

        msg = ok(await c.call_tool(
            "relay_post_message",
            {"project_id": api.project_id, "request_id": uid(),
             "message": {"client_message_id": "m-1", "kind": "note", "body": "rm -rf / (this is only text)", "task_id": task["id"]}},
        ))
        assert msg["status"] == 201
        with api.db() as s:
            m = s.execute(select(Message)).scalars().all()
            assert any(x.body == "rm -rf / (this is only text)" for x in m)  # stored as inert data

        appr = ok(await c.call_tool(
            "relay_request_approval",
            {"project_id": api.project_id, "request_id": uid(),
             "approval": {"kind": "push", "summary": "push the branch", "action": {"destination": "origin/main", "commit_digest": "a" * 64}}},
        ))
        assert appr["status"] == 201 and appr["data"]["status"] == "pending"


async def test_revise_and_cancel_and_reassign_controls(mcp: Harness, api: Api, coord):
    key = coord["key"]
    async with mcp.client(key) as c:
        t = ok(await c.call_tool("relay_create_task", {"project_id": api.project_id, "task": tbody(api, coord), "request_id": uid()}))
        v = t["version"]
        rev = ok(await c.call_tool("relay_control_task", {
            "project_id": api.project_id, "task_id": t["data"]["id"], "command": "revise", "reason": "narrow scope",
            "expected_version": v, "request_id": uid(),
            "revision": {"requirements": "Only touch src/app.py"},
        }))
        assert rev["status"] in {200, 202}
        v2 = rev["version"]
        # stray fields for a command are rejected (strict discriminated union), not ignored
        bad = err(await c.call_tool("relay_control_task", {
            "project_id": api.project_id, "task_id": t["data"]["id"], "command": "pause", "reason": "x",
            "expected_version": v2, "request_id": uid(), "implementer_id": api.impl_id,
        }))
        assert bad["code"] == "validation_error" and bad["status"] == 422
        # resume is NOT part of the MCP command enum -> rejected by the schema before any use case runs
        res = await c.call_tool("relay_control_task", {
            "project_id": api.project_id, "task_id": t["data"]["id"], "command": "resume", "reason": "x",
            "expected_version": v2, "request_id": uid(),
        })
        assert res.is_error
        can = ok(await c.call_tool("relay_control_task", {
            "project_id": api.project_id, "task_id": t["data"]["id"], "command": "cancel", "reason": "stop",
            "expected_version": v2, "request_id": uid(),
        }))
        assert can["data"]["task"]["status"] == "cancelled" or can["status"] == 202


# ------------------------------------------------------------------------------------------------ denies
async def test_denies_roles_without_authority_and_foreign_resources(mcp: Harness, api: Api, coord):
    owner_task = api.create_task()
    impl, aud = api.keys["impl"], api.keys["aud"]
    # implementer/auditor cannot create or drive tasks
    for key in (impl, aud):
        e = err(await mcp.call(key, "relay_create_task", {"project_id": api.project_id, "task": api.task_body(), "request_id": uid()}))
        assert e["code"] == "forbidden" and e["status"] == 403
        e = err(await mcp.call(key, "relay_enqueue_task", {
            "project_id": api.project_id, "task_id": owner_task["id"], "expected_version": owner_task["version"], "request_id": uid()}))
        assert e["status"] == 403
    # coordinator without a delegation, and on a task it did not create
    e = err(await mcp.call(coord["key"], "relay_create_task", {"project_id": api.project_id, "task": api.task_body(autonomous=False), "request_id": uid()}))
    assert e["status"] == 403
    e = err(await mcp.call(coord["key"], "relay_enqueue_task", {
        "project_id": api.project_id, "task_id": owner_task["id"], "expected_version": owner_task["version"], "request_id": uid()}))
    assert e["status"] == 403
    e = err(await mcp.call(coord["key"], "relay_control_task", {
        "project_id": api.project_id, "task_id": owner_task["id"], "command": "cancel", "reason": "no",
        "expected_version": owner_task["version"], "request_id": uid()}))
    assert e["status"] == 403
    assert api.get_task(owner_task["id"])["status"] == "draft"
    # exceeding the delegation ceiling (autonomous) is refused exactly like REST
    e = err(await mcp.call(coord["key"], "relay_create_task", {
        "project_id": api.project_id, "task": api.task_body(autonomous=True, delegation_id=coord["delegation"]["id"]), "request_id": uid()}))
    assert e["status"] == 403
    # request_id must be a UUID
    r = await mcp.call(coord["key"], "relay_create_task", {"project_id": api.project_id, "task": tbody(api, coord), "request_id": "not-a-uuid"})
    assert r.is_error
    assert api.count(Task) == 1


async def test_no_task_is_created_when_delegation_is_revoked_or_expired(mcp: Harness, api: Api, coord):
    r = api.req("owner", "POST", api.p(f"/delegations/{coord['delegation']['id']}/revoke"), {"reason": "test"})
    assert r.status_code == 200, r.text
    e = err(await mcp.call(coord["key"], "relay_create_task", {"project_id": api.project_id, "task": tbody(api, coord), "request_id": uid()}))
    assert e["status"] == 403
    assert api.count(Task) == 0


async def test_member_of_other_project_sees_nothing(mcp: Harness, api: Api, coord):
    # a principal with no membership in the project
    with write_session(api.app.state.engine) as ws:  # type: ignore[attr-defined]
        p = Principal(display_name="stranger", kind="coordinator", active=True, created_at=api.clock.now_ms())
        ws.add(p)
        ws.flush()
        key, _ = issue_credential(ws, api.clock, p.id)
    task = api.create_task()
    e = err(await mcp.call(key.full_key, "relay_get_task", {"project_id": api.project_id, "task_id": task["id"]}))
    assert e["code"] == "not_found"
    assert ok(await mcp.call(key.full_key, "relay_list_projects", {}))["items"] == []


async def test_coordinator_cannot_approve_anything(mcp: Harness, api: Api, coord):
    key = coord["key"]
    res = ok(await mcp.call(key, "relay_request_approval", {
        "project_id": api.project_id, "request_id": uid(),
        "approval": {"kind": "publish", "summary": "ship it", "action": {"destination": "pypi", "artifact_digest": "b" * 64}},
    }))
    aid, digest = res["data"]["id"], res["data"]["action_digest"]
    assert res["data"]["status"] == "pending"
    # no approve/decide/execute tool exists, and an unknown tool name is rejected
    async with mcp.client(key) as c:
        for ghost in ("relay_approve", "relay_decide_approval", "relay_execute_approval", "relay_publish", "relay_shell"):
            r = await c.call_tool(ghost, {"project_id": api.project_id})
            assert r.is_error, ghost
    # the same credential over REST is denied too (defence in depth)
    body = {"decision": "approve", "action_digest": digest, "reason": "me"}
    r = api.req(api.client_for_key(key), "POST", api.p(f"/approval-requests/{aid}/decision"), body)
    assert r.status_code == 403
    with api.db() as s:
        assert s.get(ApprovalRequest, aid).status == "pending"


async def test_owner_credentials_are_refused_by_the_facade(mcp: Harness, api: Api):
    with write_session(api.app.state.engine) as ws:  # type: ignore[attr-defined]
        key, _ = issue_credential(ws, api.clock, api.owner_id)  # hypothetical owner key
    async with mcp.http(key.full_key) as hc:
        r = await hc.post("/mcp", json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
                          headers={"Accept": "application/json, text/event-stream"})
    assert r.status_code == 403 and r.json()["error"]["code"] == "owner_not_allowed"


# ------------------------------------------------------------------------------------------------ idempotency parity
async def test_idempotency_parity_rest_then_mcp_and_mcp_then_rest(mcp: Harness, api: Api, coord):
    key = coord["key"]
    agent = api.client_for_key(key)
    # --- REST first, MCP retry with the same key replays (no duplicate)
    k1 = uid()
    body = tbody(api, coord)
    r = api.req(agent, "POST", api.p("/tasks"), body, idem=k1)
    assert r.status_code == 201
    m = ok(await mcp.call(key, "relay_create_task", {"project_id": api.project_id, "task": body, "request_id": k1}))
    assert m["replayed"] is True and m["status"] == 201 and m["data"] == r.json()
    assert api.count(Task) == 1
    # --- MCP first, REST retry with the same key replays (header + same body)
    k2 = uid()
    body2 = tbody(api, coord, title="Second")
    m2 = ok(await mcp.call(key, "relay_create_task", {"project_id": api.project_id, "task": body2, "request_id": k2}))
    assert m2["replayed"] is False
    r2 = api.req(agent, "POST", api.p("/tasks"), body2, idem=k2)
    assert r2.status_code == 201 and r2.headers.get("Idempotent-Replay") == "true" and r2.json() == m2["data"]
    assert api.count(Task) == 2
    # --- same key + different payload over the other transport -> conflict, nothing created
    c = err(await mcp.call(key, "relay_create_task", {"project_id": api.project_id, "task": tbody(api, coord, title="Other"), "request_id": k2}))
    assert c["code"] == "idempotency_conflict" and c["status"] == 409
    assert api.count(Task) == 2
    # --- enqueue parity (If-Match <-> expected_version)
    t = r.json()
    k3 = uid()
    re_ = api.req(agent, "POST", api.p(f"/tasks/{t['id']}/enqueue"), idem=k3, if_match=t["version"])
    assert re_.status_code == 200
    me = ok(await mcp.call(key, "relay_enqueue_task", {"project_id": api.project_id, "task_id": t["id"], "expected_version": t["version"], "request_id": k3}))
    assert me["replayed"] is True and me["data"] == re_.json()
    assert len(api.jobs(t["id"])) == 1
    # --- control parity
    k4 = uid()
    cur = api.get_task(t["id"])
    rc = api.req(agent, "POST", api.p(f"/tasks/{t['id']}/controls"), {"command": "pause", "reason": "p"}, idem=k4, if_match=cur["version"])
    assert rc.status_code in (200, 202)
    mc = ok(await mcp.call(key, "relay_control_task", {
        "project_id": api.project_id, "task_id": t["id"], "command": "pause", "reason": "p",
        "expected_version": cur["version"], "request_id": k4}))
    assert mc["replayed"] is True and mc["data"] == rc.json()
    # --- message parity
    k5 = uid()
    mb = {"client_message_id": "same", "kind": "note", "body": "hello"}
    rm = api.req(agent, "POST", api.p("/messages"), mb, idem=k5)
    mm = ok(await mcp.call(key, "relay_post_message", {"project_id": api.project_id, "message": mb, "request_id": k5}))
    assert mm["replayed"] is True and mm["data"] == rm.json()
    with api.db() as s:
        assert len(s.execute(select(Message)).scalars().all()) == 1
    # --- approval-request parity
    k6 = uid()
    ab = {"kind": "push", "summary": "s", "action": {"destination": "origin/x", "commit_digest": "c" * 64}}
    ra = api.req(agent, "POST", api.p("/approval-requests"), ab, idem=k6)
    ma = ok(await mcp.call(key, "relay_request_approval", {"project_id": api.project_id, "approval": ab, "request_id": k6}))
    assert ma["replayed"] is True and ma["data"] == ra.json()
    assert api.count(ApprovalRequest) == 1


async def test_same_request_id_for_a_different_principal_is_not_a_replay(mcp: Harness, api: Api, coord):
    k = uid()
    mb = {"client_message_id": "x1", "kind": "note", "body": "hi"}
    a = ok(await mcp.call(coord["key"], "relay_post_message", {"project_id": api.project_id, "message": mb, "request_id": k}))
    b = ok(await mcp.call(api.keys["impl"], "relay_post_message", {"project_id": api.project_id, "message": mb, "request_id": k}))
    assert a["replayed"] is False and b["replayed"] is False
    assert a["data"]["id"] != b["data"]["id"]


async def test_busy_database_is_a_retryable_tool_error_not_a_success(mcp: Harness, api: Api, coord, monkeypatch):
    from sqlalchemy.exc import OperationalError

    import nozo_relay.usecases as usecases

    class Boom:
        def __enter__(self):
            raise OperationalError("BEGIN IMMEDIATE", {}, Exception("database is locked"))

        def __exit__(self, *a):
            return False

    monkeypatch.setattr(usecases, "write_session", lambda engine: Boom())
    e = err(await mcp.call(coord["key"], "relay_post_message", {
        "project_id": api.project_id, "request_id": uid(),
        "message": {"client_message_id": "b1", "kind": "note", "body": "x"}}))
    assert e["code"] == "database_busy" and e["status"] == 503 and e["retryable"] is True
    monkeypatch.undo()
    with api.db() as s:
        assert s.execute(select(Message)).scalars().all() == []


async def test_idempotent_replay_is_denied_after_revocation(mcp: Harness, api: Api, coord):
    k = uid()
    args = {"project_id": api.project_id, "task": tbody(api, coord), "request_id": k}
    ok(await mcp.call(coord["key"], "relay_create_task", args))
    revoke(api, coord["key"])
    async with mcp.http(coord["key"]) as hc:
        r = await hc.post("/mcp", json={"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "relay_create_task", "arguments": args}},
                          headers={"Accept": "application/json, text/event-stream", "MCP-Protocol-Version": "2025-11-25"})
    assert r.status_code == 401  # cached answer is never readable once the credential is gone
    assert api.count(Task) == 1


# ------------------------------------------------------------------------------------------------ transport auth
async def test_revoked_credential_is_denied_on_the_next_request_even_mid_session(mcp: Harness, api: Api, coord):
    async with mcp.client(coord["key"]) as c:
        assert not (await c.call_tool("relay_list_projects", {})).is_error
        revoke(api, coord["key"])
        with pytest.raises(Exception):  # transport-level 401, not a tool result
            await c.call_tool("relay_list_projects", {})
    with pytest.raises(BaseException):
        await mcp.call(coord["key"], "relay_list_projects", {})


async def test_deactivated_principal_and_expired_credential_are_denied(mcp: Harness, api: Api, coord):
    cid_key = coord["key"]
    with write_session(api.app.state.engine) as ws:  # type: ignore[attr-defined]
        ws.get(Principal, coord["id"]).active = False
    async with mcp.http(cid_key) as hc:
        r = await hc.post("/mcp", json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"}, headers={"Accept": "application/json, text/event-stream"})
    assert r.status_code == 401
    with write_session(api.app.state.engine) as ws:  # type: ignore[attr-defined]
        ws.get(Principal, coord["id"]).active = True
        ws.get(Credential, credential_id(api, cid_key)).expires_at = api.clock.now_ms() + 1000
    api.clock.advance(seconds=5)
    async with mcp.http(cid_key) as hc:
        r = await hc.post("/mcp", json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"}, headers={"Accept": "application/json, text/event-stream"})
    assert r.status_code == 401


RPC = {"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}}
ACCEPT = {"Accept": "application/json, text/event-stream", "Content-Type": "application/json"}


async def test_missing_wrong_malformed_and_misplaced_tokens_are_denied(mcp: Harness, api: Api, coord):
    good = coord["key"]
    async with mcp.http() as hc:
        r = await hc.post("/mcp", json=RPC, headers=ACCEPT)
        assert r.status_code == 401 and r.headers["www-authenticate"].startswith("Bearer")
        assert r.json()["error"]["code"] == "unauthenticated"
        for authz in ("Bearer nzr_0000000000000000.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "Bearer garbage", "Basic Zm9vOmJhcg==", "Bearer ", "bearer"):
            r = await hc.post("/mcp", json=RPC, headers={**ACCEPT, "Authorization": authz})
            assert r.status_code == 401, authz
        # a valid key with a corrupted secret
        r = await hc.post("/mcp", json=RPC, headers={**ACCEPT, "Authorization": "Bearer " + good[:-3] + "AAA"})
        assert r.status_code == 401
        # credentials are never read from the query string or cookies
        r = await hc.post(f"/mcp?access_token={good}&key={good}", json=RPC, headers=ACCEPT)
        assert r.status_code == 401
        r = await hc.post("/mcp", json=RPC, headers=ACCEPT, cookies={"nozo_session": good})
        assert r.status_code == 401


async def test_owner_browser_session_cannot_use_mcp(mcp: Harness, api: Api):
    owner = api.clients["owner"]
    cookie = owner.cookies.get("nozo_session")
    assert cookie
    async with mcp.http() as hc:
        r = await hc.post("/mcp", json=RPC, headers=ACCEPT, cookies={"nozo_session": cookie})
    assert r.status_code == 401


async def test_invalid_origin_is_denied_even_with_a_valid_token(mcp: Harness, api: Api, coord):
    good = coord["key"]
    async with mcp.http(good) as hc:
        for origin in ("https://evil.example", "http://127.0.0.1:9", "null", "http://localhost.evil.test:8765"):
            r = await hc.post("/mcp", json=RPC, headers={**ACCEPT, "Origin": origin})
            assert r.status_code == 403, origin
            assert r.json()["error"]["code"] == "origin_not_allowed"
        # an allow-listed Origin is accepted; no Origin (non-browser client) is accepted
        assert (await hc.post("/mcp", json=RPC, headers={**ACCEPT, "Origin": BASE_URL})).status_code == 200
        assert (await hc.post("/mcp", json=RPC, headers=ACCEPT)).status_code == 200
    # invalid origin is refused BEFORE credentials are examined (no 401/403 oracle for browsers)
    async with mcp.http("nzr_bad") as hc:
        r = await hc.post("/mcp", json=RPC, headers={**ACCEPT, "Origin": "https://evil.example"})
        assert r.status_code == 403


async def test_invalid_host_header_is_denied(mcp: Harness, coord):
    async with mcp.http(coord["key"]) as hc:
        r = await hc.post("/mcp", json=RPC, headers={**ACCEPT, "Host": "attacker.example"})
    assert r.status_code in (400, 421)


async def test_get_and_delete_are_not_a_state_channel(mcp: Harness, coord):
    async with mcp.http(coord["key"]) as hc:
        for method in ("GET", "DELETE", "PUT", "PATCH"):
            r = await hc.request(method, "/mcp", headers={"Accept": "text/event-stream"})
            assert r.status_code == 405 and r.headers["allow"] == "POST", method


# ------------------------------------------------------------------------------------------------ availability
def test_mcp_disabled_or_sdk_missing_serves_nothing(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    from fastapi.testclient import TestClient

    s = make_settings(tmp_path / "a", mcp_enabled=False)
    bootstrap(s, owner_password=OWNER_PASSWORD, clock=FakeClock())
    with TestClient(create_app(s, FakeClock()), base_url=BASE_URL) as c:
        assert c.post("/mcp", json=RPC).status_code == 404
    monkeypatch.setattr("nozo_relay.mcp.install.sdk_available", lambda: False)
    s2 = make_settings(tmp_path / "b")
    bootstrap(s2, owner_password=OWNER_PASSWORD, clock=FakeClock())
    app = create_app(s2, FakeClock())
    assert app.state.mcp is None
    with TestClient(app, base_url=BASE_URL) as c:
        assert c.post("/mcp", json=RPC).status_code == 404


def test_sdk_is_pinned_in_the_lockfile():
    assert sdk_available()
    lock = (Path(__file__).parent.parent / "uv.lock").read_text()
    assert 'name = "mcp"\nversion = "2.3.0"' in lock
    assert 'name = "mcp-types"\nversion = "2.3.0"' in lock


def test_rest_is_unchanged_by_the_facade(api: Api):
    # unknown paths keep the uniform JSON 404 shape (the facade registers exact routes only)
    r = api.req("owner", "GET", "/api/v1/nope")
    assert r.status_code == 404 and "error" in r.json()


# ------------------------------------------------------------------------------------------------ catalog evidence
async def test_tool_catalog_evidence(mcp: Harness, coord):
    async with mcp.client(coord["key"]) as c:
        tools = (await c.list_tools()).tools
    doc = {
        "tools": [
            {
                "name": t.name,
                "annotations": t.annotations.model_dump(exclude_none=True, by_alias=True) if t.annotations else None,
                "required_inputs": sorted(t.input_schema.get("required", [])),
                "has_output_schema": t.output_schema is not None,
                "input_schema_sha256": hashlib.sha256(json.dumps(t.input_schema, sort_keys=True).encode()).hexdigest(),
            }
            for t in tools
        ],
        "absent_by_design": ["owner approve/decision", "approval execute", "publish/push/deploy", "shell/exec/sudo", "key/delegation/policy management", "resume + project-wide/emergency controls", "runner lifecycle"],
    }
    assert len(doc["tools"]) == 10
    write_evidence("tool_catalog.json", doc)


# ------------------------------------------------------------------------------------------------ stdio
async def test_stdio_wrapper_uses_the_same_use_cases_and_honours_revocation(api: Api, coord, env: Env):
    data_dir = str(env.settings.data_dir)
    params = StdioServerParameters(
        command=sys.executable,
        args=["-m", "nozo_relay.mcp_stdio"],
        env={"NOZO_RELAY_DATA_DIR": data_dir, "NOZO_RELAY_MCP_AGENT_KEY": coord["key"], "PATH": os.environ.get("PATH", "")},
        cwd=str(Path(__file__).parent.parent),
    )
    async with Client(stdio_client(params), mode="legacy") as c:
        tools = {t.name for t in (await c.list_tools()).tools}
        assert tools == EXPECTED_TOOLS
        k = uid()
        body = tbody(api, coord)
        created = ok(await c.call_tool("relay_create_task", {"project_id": api.project_id, "task": body, "request_id": k}))
        assert created["status"] == 201
        # REST retry of the stdio-created task replays: one shared idempotency scope
        r = api.req(api.client_for_key(coord["key"]), "POST", api.p("/tasks"), body, idem=k)
        assert r.status_code == 201 and r.headers.get("Idempotent-Replay") == "true" and r.json() == created["data"]
        assert api.count(Task) == 1
        revoke(api, coord["key"])
        e = err(await c.call_tool("relay_list_projects", {}))
        assert e["code"] == "unauthenticated"  # re-verified on every call
        write_evidence("stdio_probe.json", {"transport": "stdio (python -m nozo_relay.mcp_stdio)", "protocol_version": c.protocol_version,
                                            "tools": sorted(tools), "created_then_rest_replay": True, "revocation_mid_session": e["code"]})


def test_stdio_refuses_missing_or_revoked_key(env: Env, api: Api, coord):
    import subprocess

    base = {"NOZO_RELAY_DATA_DIR": str(env.settings.data_dir), "PATH": os.environ.get("PATH", "")}
    cwd = str(Path(__file__).parent.parent)
    p = subprocess.run([sys.executable, "-m", "nozo_relay.mcp_stdio"], env=base, cwd=cwd, capture_output=True, text=True, timeout=60)
    assert p.returncode == 2 and "NOZO_RELAY_MCP_AGENT_KEY" in p.stderr and p.stdout == ""
    revoke(api, coord["key"])
    p = subprocess.run([sys.executable, "-m", "nozo_relay.mcp_stdio"], env={**base, "NOZO_RELAY_MCP_AGENT_KEY": coord["key"]}, cwd=cwd, capture_output=True, text=True, timeout=60)
    assert p.returncode == 2 and coord["key"] not in p.stderr and coord["key"] not in p.stdout


# ------------------------------------------------------------------------------------------------ real socket
def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


async def test_real_loopback_http_probe(tmp_path: Path):
    """Real uvicorn socket on 127.0.0.1 (no tunnel): both client protocol modes, Origin, auth."""
    import uvicorn

    port = _free_port()
    s = make_settings(tmp_path, port=port)
    clock = FakeClock()
    bootstrap(s, owner_password=OWNER_PASSWORD, clock=clock)
    creds = json.loads(credentials_path(s).read_text())
    key = creds["agents"][0]["key"]
    pid = creds["project"]["id"]
    app = create_app(s, clock)
    server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=port, log_level="warning", lifespan="on"))
    th = threading.Thread(target=server.run, daemon=True)
    th.start()
    deadline = time.time() + 20
    while not server.started and time.time() < deadline:
        time.sleep(0.05)
    assert server.started
    url = f"http://127.0.0.1:{port}/mcp"
    out: dict[str, Any] = {"endpoint": f"http://127.0.0.1:{port}/mcp (loopback only)"}
    try:
        for mode in ("legacy", "auto"):
            async with httpx2.AsyncClient(headers={"Authorization": f"Bearer {key}"}) as hc:
                async with Client(streamable_http_client(url, http_client=hc), mode=mode) as c:
                    out[f"{mode}_protocol_version"] = c.protocol_version
                    r = ok(await c.call_tool("relay_list_tasks", {"project_id": pid}))
                    assert r["items"] == []
        async with httpx2.AsyncClient() as hc:
            r = await hc.post(url, json=RPC, headers={**ACCEPT, "Authorization": f"Bearer {key}", "Origin": "https://evil.example"})
            out["evil_origin_status"] = r.status_code
            assert r.status_code == 403
            r = await hc.post(url, json=RPC, headers={**ACCEPT, "Authorization": "Bearer nzr_x"})
            out["bad_token_status"] = r.status_code
            assert r.status_code == 401
            r = await hc.post(url, json=RPC, headers={**ACCEPT, "Authorization": f"Bearer {key}", "Host": "evil.example"})
            out["bad_host_status"] = r.status_code
            assert r.status_code in (400, 421)
    finally:
        server.should_exit = True
        th.join(timeout=20)
    write_evidence("real_http_probe.json", out)


# ------------------------------------------------------------------------------------------------ OAuth scaffolding
REDIRECT = "http://127.0.0.1:9911/callback"
OAUTH_SCOPES = "relay:read relay:write relay:control"


@pytest.fixture
def oauth_api(tmp_path: Path) -> Api:
    s = make_settings(tmp_path, mcp_oauth_enabled=True, mcp_oauth_redirect_uris=[REDIRECT])
    clock = FakeClock()
    bootstrap(s, owner_password=OWNER_PASSWORD, clock=clock)
    creds = json.loads(credentials_path(s).read_text())
    app = create_app(s, clock)
    return Api(Env(settings=s, clock=clock, creds=creds, app=app))


@pytest_asyncio.fixture
async def oauth(oauth_api: Api) -> AsyncIterator[Harness]:
    async for h in _lifespan_harness(oauth_api):
        yield h


def pkce() -> tuple[str, str]:
    verifier = secrets.token_urlsafe(64)
    return verifier, base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).decode().rstrip("=")


async def register(hc: httpx2.AsyncClient, redirect: str = REDIRECT, scope: str = OAUTH_SCOPES) -> httpx2.Response:
    return await hc.post("/register", json={
        "redirect_uris": [redirect], "token_endpoint_auth_method": "none",
        "grant_types": ["authorization_code", "refresh_token"], "response_types": ["code"],
        "client_name": "probe", "scope": scope,
    })


async def authorize(hc, client_id: str, challenge: str | None, *, resource: str | None, scope: str = OAUTH_SCOPES, redirect: str = REDIRECT, method: str = "S256"):
    q = {"response_type": "code", "client_id": client_id, "redirect_uri": redirect, "state": "st-1", "scope": scope}
    if challenge is not None:
        q.update(code_challenge=challenge, code_challenge_method=method)
    if resource is not None:
        q["resource"] = resource
    return await hc.get("/authorize", params=q)


def location_params(r: httpx2.Response) -> dict[str, str]:
    assert r.status_code in (302, 303, 307), (r.status_code, r.text)
    return {k: v[0] for k, v in parse_qs(urlsplit(r.headers["location"]).query).items()}


async def full_flow(
    oauth: Harness, principal_id: str, *, scope: str = OAUTH_SCOPES, project_ids: list[str] | None = None
) -> dict[str, Any]:
    app = oauth.app
    provider = app.state.mcp.oauth
    async with oauth.http() as hc:
        reg = await register(hc)
        assert reg.status_code == 201, reg.text
        client_id = reg.json()["client_id"]
        verifier, challenge = pkce()
        r = await authorize(hc, client_id, challenge, resource=app.state.settings.mcp_resource, scope=scope)
        request_id = location_params(r)["request_id"]
        redirect = provider.grant(request_id, principal_id, project_ids=project_ids)
        q = {k: v[0] for k, v in parse_qs(urlsplit(redirect).query).items()}
        assert q["state"] == "st-1" and redirect.startswith(REDIRECT)
        tok = await hc.post("/token", data={
            "grant_type": "authorization_code", "code": q["code"], "redirect_uri": REDIRECT,
            "client_id": client_id, "code_verifier": verifier,
        })
        assert tok.status_code == 200, tok.text
        return {"client_id": client_id, "verifier": verifier, "code": q["code"], "tokens": tok.json(), "provider": provider}


def test_oauth_is_off_by_default(api: Api):
    assert api.env.settings.mcp_oauth_enabled is False
    for path in ("/.well-known/oauth-protected-resource/mcp", "/.well-known/oauth-authorization-server", "/authorize", "/token", "/register"):
        assert api.req("owner", "GET", path).status_code in (404, 405), path


async def test_oauth_discovery_metadata_and_challenge(oauth: Harness):
    s = oauth.app.state.settings
    async with oauth.http() as hc:
        prm = (await hc.get("/.well-known/oauth-protected-resource/mcp")).json()
        assert prm["resource"].rstrip("/") == s.mcp_resource and prm["authorization_servers"][0].rstrip("/") == s.mcp_oauth_issuer
        assert set(prm["scopes_supported"]) == {"relay:read", "relay:write", "relay:control"}
        asm = (await hc.get("/.well-known/oauth-authorization-server")).json()
        assert asm["code_challenge_methods_supported"] == ["S256"]  # PKCE S256 only
        assert asm["response_types_supported"] == ["code"]
        assert asm["token_endpoint"].endswith("/token") and asm["revocation_endpoint"].endswith("/revoke")
        assert set(asm["grant_types_supported"]) == {"authorization_code", "refresh_token"}
        r = await hc.post("/mcp", json=RPC, headers=ACCEPT)
        assert r.status_code == 401
        assert 'resource_metadata="' in r.headers["www-authenticate"] and "/.well-known/oauth-protected-resource/mcp" in r.headers["www-authenticate"]
    write_evidence("oauth_probe_discovery.json", {"protected_resource_metadata": prm, "authorization_server_metadata": asm,
                                                  "status": "probe_pass (local, SDK-provided metadata); ChatGPT: not_verified (T11)"})


async def test_oauth_pkce_flow_audience_scopes_and_mcp_call(oauth: Harness):
    api = oauth.api
    cid, ckey = api.make_principal("coordinator", "chatgpt")
    d = delegation(api, cid)
    flow = await full_flow(oauth, cid)
    token = flow["tokens"]["access_token"]
    assert flow["tokens"]["token_type"] == "Bearer" and flow["tokens"]["expires_in"] == 900
    assert set(flow["tokens"]["scope"].split()) == set(OAUTH_SCOPES.split())
    # the OAuth token works on /mcp and maps to the COORDINATOR identity (tier P1), never to the owner
    async with oauth.client(token) as c:
        created = ok(await c.call_tool("relay_create_task", {
            "project_id": api.project_id, "request_id": uid(),
            "task": api.task_body(autonomous=False, delegation_id=d["id"])}))
        assert created["data"]["authority_tier"] == "P1"
    with api.db() as s:
        t = s.execute(select(Task)).scalar_one()
        assert t.origin_principal_id == cid
    # an OAuth token can never be used where an agent key's REST authority is expected
    assert api.req(api.client_for_key(token), "GET", api.p("/tasks")).status_code == 401
    write_evidence("oauth_probe_flow.json", {
        "flow": "register(DCR, exact redirect allowlist) -> /authorize(S256, resource) -> owner-consent hook grant() -> /token -> /mcp",
        "access_ttl_seconds": flow["tokens"]["expires_in"], "mapped_identity": "coordinator (P1), never owner",
        "status": "probe_pass (local, in-process); ChatGPT: not_verified (T11); consent UI: not_implemented (T11)"})


async def test_oauth_rejects_bad_pkce_audience_redirect_and_replay(oauth: Harness):
    api = oauth.api
    cid, _ = api.make_principal("coordinator", "chatgpt")
    res = api.app.state.settings.mcp_resource
    provider = api.app.state.mcp.oauth
    async with oauth.http() as hc:
        # unregistered redirect URI cannot even register a client
        assert (await register(hc, redirect="https://evil.example/cb")).status_code == 400
        client_id = (await register(hc)).json()["client_id"]
        verifier, challenge = pkce()
        # missing PKCE / plain method / missing or foreign resource
        assert (await authorize(hc, client_id, None, resource=res)).status_code in (302, 400)
        r = await authorize(hc, client_id, None, resource=res)
        assert "error" in location_params(r) or r.status_code == 400
        r = await authorize(hc, client_id, challenge, resource=res, method="plain")
        assert r.status_code == 400 or "error" in location_params(r)
        for bad_resource in (None, "https://other.example/mcp", res + "/x"):
            r = await authorize(hc, client_id, challenge, resource=bad_resource)
            assert location_params(r).get("error") == "invalid_target", bad_resource
        for bad_scope in ("relay:read admin", f"relay:read project:{uid()}"):  # project limits are owner-set only
            r = await authorize(hc, client_id, challenge, resource=res, scope=bad_scope)
            assert location_params(r).get("error") == "invalid_scope", bad_scope
        # wrong redirect_uri at /authorize
        r = await authorize(hc, client_id, challenge, resource=res, redirect="http://127.0.0.1:1/other")
        assert r.status_code == 400
        # happy authorize, then attack the token endpoint
        rid = location_params(await authorize(hc, client_id, challenge, resource=res))["request_id"]
        code = {k: v[0] for k, v in parse_qs(urlsplit(provider.grant(rid, cid)).query).items()}["code"]
        base = {"grant_type": "authorization_code", "code": code, "redirect_uri": REDIRECT, "client_id": client_id}
        assert (await hc.post("/token", data={**base, "code_verifier": secrets.token_urlsafe(64)})).status_code == 400  # wrong verifier
        assert (await hc.post("/token", data={**base, "redirect_uri": "http://127.0.0.1:1/other", "code_verifier": verifier})).status_code == 400
        assert (await hc.post("/token", data={**base, "client_id": "someone-else", "code_verifier": verifier})).status_code in (400, 401)
        ok_tok = await hc.post("/token", data={**base, "code_verifier": verifier})
        assert ok_tok.status_code == 200
        # code replay -> invalid_grant AND the tokens minted from it are revoked
        again = await hc.post("/token", data={**base, "code_verifier": verifier})
        assert again.status_code == 400 and again.json()["error"] == "invalid_grant"
        probe = await hc.post("/mcp", json=RPC, headers={**ACCEPT, "Authorization": f"Bearer {ok_tok.json()['access_token']}"})
        assert probe.status_code == 401


async def test_oauth_owner_and_non_coordinator_principals_cannot_be_granted(oauth: Harness):
    api = oauth.api
    provider = api.app.state.mcp.oauth
    from mcp.server.auth.provider import AuthorizeError

    async with oauth.http() as hc:
        client_id = (await register(hc)).json()["client_id"]
        for pid in (api.owner_id, api.impl_id, api.aud_id, uid()):
            _, ch = pkce()
            rid = location_params(await authorize(hc, client_id, ch, resource=api.app.state.settings.mcp_resource))["request_id"]
            with pytest.raises(AuthorizeError):
                provider.grant(rid, pid)


async def test_oauth_scope_limits_project_scope_and_read_only(oauth: Harness):
    api = oauth.api
    cid, _ = api.make_principal("coordinator", "chatgpt")
    d = delegation(api, cid)
    # read-only token: reads work, every mutation is denied with insufficient_scope
    flow = await full_flow(oauth, cid, scope="relay:read")
    async with oauth.client(flow["tokens"]["access_token"]) as c:
        assert not (await c.call_tool("relay_list_projects", {})).is_error
        e = err(await c.call_tool("relay_create_task", {"project_id": api.project_id, "request_id": uid(),
                                                       "task": api.task_body(autonomous=False, delegation_id=d["id"])}))
        assert e["code"] == "insufficient_scope" and e["status"] == 403
        e = err(await c.call_tool("relay_post_message", {"project_id": api.project_id, "request_id": uid(),
                                                         "message": {"client_message_id": "a", "kind": "note", "body": "x"}}))
        assert e["code"] == "insufficient_scope"
    assert api.count(Task) == 0
    # project-limited token: another project id is indistinguishable from unknown (404)
    other = uid()
    flow = await full_flow(oauth, cid, scope="relay:read", project_ids=[other])
    async with oauth.client(flow["tokens"]["access_token"]) as c:
        assert err(await c.call_tool("relay_list_tasks", {"project_id": api.project_id}))["code"] == "not_found"
    flow = await full_flow(oauth, cid, scope="relay:read", project_ids=[api.project_id])
    async with oauth.client(flow["tokens"]["access_token"]) as c:
        assert not (await c.call_tool("relay_list_tasks", {"project_id": api.project_id})).is_error


async def test_oauth_expiry_revocation_refresh_rotation_and_reuse_detection(oauth: Harness):
    api = oauth.api
    cid, _ = api.make_principal("coordinator", "chatgpt")
    flow = await full_flow(oauth, cid)
    provider = flow["provider"]
    at, rt, client_id = flow["tokens"]["access_token"], flow["tokens"]["refresh_token"], flow["client_id"]
    async with oauth.http() as hc:
        async def mcp_status(token: str) -> int:
            return (await hc.post("/mcp", json=RPC, headers={**ACCEPT, "Authorization": f"Bearer {token}"})).status_code

        assert await mcp_status(at) == 200
        # refresh rotation: new pair, old access token dies, old refresh token is single-use
        r = await hc.post("/token", data={"grant_type": "refresh_token", "refresh_token": rt, "client_id": client_id})
        assert r.status_code == 200, r.text
        new = r.json()
        assert new["access_token"] != at and new["refresh_token"] != rt
        assert await mcp_status(at) == 401
        assert await mcp_status(new["access_token"]) == 200
        # reuse of the rotated refresh token => whole grant family revoked
        reuse = await hc.post("/token", data={"grant_type": "refresh_token", "refresh_token": rt, "client_id": client_id})
        assert reuse.status_code == 400
        assert await mcp_status(new["access_token"]) == 401
        assert (await hc.post("/token", data={"grant_type": "refresh_token", "refresh_token": new["refresh_token"], "client_id": client_id})).status_code == 400

        # explicit revocation through /revoke
        flow2 = await full_flow(oauth, cid)
        t2 = flow2["tokens"]
        assert await mcp_status(t2["access_token"]) == 200
        rv = await hc.post("/revoke", data={"token": t2["access_token"], "client_id": flow2["client_id"], "client_secret": ""})
        assert rv.status_code == 200
        assert await mcp_status(t2["access_token"]) == 401
        assert (await hc.post("/token", data={"grant_type": "refresh_token", "refresh_token": t2["refresh_token"], "client_id": flow2["client_id"]})).status_code == 400

        # short TTL: the access token expires
        flow3 = await full_flow(oauth, cid)
        assert await mcp_status(flow3["tokens"]["access_token"]) == 200
        provider.now = lambda: time.time() + 901
        assert await mcp_status(flow3["tokens"]["access_token"]) == 401
        provider.now = time.time

        # owner-side revocation of every grant of a principal (e.g. when the coordinator is retired)
        flow4 = await full_flow(oauth, cid)
        assert provider.revoke_principal(cid) >= 1
        assert await mcp_status(flow4["tokens"]["access_token"]) == 401


async def test_oauth_token_for_deactivated_or_demoted_principal_is_denied(oauth: Harness):
    api = oauth.api
    cid, _ = api.make_principal("coordinator", "chatgpt")
    flow = await full_flow(oauth, cid)
    token = flow["tokens"]["access_token"]
    with write_session(api.app.state.engine) as ws:  # type: ignore[attr-defined]
        ws.get(Principal, cid).active = False
    async with oauth.http() as hc:
        r = await hc.post("/mcp", json=RPC, headers={**ACCEPT, "Authorization": f"Bearer {token}"})
    assert r.status_code == 401


async def test_oauth_token_with_wrong_audience_is_denied(oauth: Harness):
    api = oauth.api
    cid, _ = api.make_principal("coordinator", "chatgpt")
    flow = await full_flow(oauth, cid)
    provider = flow["provider"]
    # simulate a token minted for another resource (confused deputy): the gateway re-checks audience
    for t in provider._access.values():
        t.resource = "https://other.example/mcp"
    async with oauth.http() as hc:
        r = await hc.post("/mcp", json=RPC, headers={**ACCEPT, "Authorization": f"Bearer {flow['tokens']['access_token']}"})
    assert r.status_code == 401
