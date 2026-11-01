"""Optional stdio transport for the MCP facade: ``python -m nozo_relay.mcp_stdio``.

Same closed toolset and the same use cases as ``/mcp`` and REST, run in-process against the local
SQLite database (stop nothing: WAL + BEGIN IMMEDIATE make it safe next to a running server).

* The agent key is read from the ENVIRONMENT (``NOZO_RELAY_MCP_AGENT_KEY``), never from argv, and is
  removed from ``os.environ`` after reading. It is re-verified on EVERY tool call, so revoking the
  credential takes effect immediately, mid-session.
* stdout is the protocol channel; all logging goes to stderr.
* Owner credentials are refused, exactly like the HTTP gateway.
"""

from __future__ import annotations

import asyncio
import logging
import os
import sys

KEY_ENV = "NOZO_RELAY_MCP_AGENT_KEY"


def main() -> int:
    logging.basicConfig(stream=sys.stderr, level=logging.WARNING)
    raw_key = os.environ.pop(KEY_ENV, "").strip()
    if not raw_key:
        print(f"{KEY_ENV} is not set (agent key is read from the environment, never argv)", file=sys.stderr)
        return 2
    try:
        import mcp.server.mcpserver  # noqa: F401
    except ImportError:
        print("MCP SDK not installed: uv sync --extra mcp", file=sys.stderr)
        return 2

    from nozo_relay import logsafe
    from nozo_relay.clock import SystemClock
    from nozo_relay.config import Settings
    from nozo_relay.db.engine import create_engine_from_settings
    from nozo_relay.db.schema import ensure_schema
    from nozo_relay.mcp.gateway import McpAuth, authenticate_agent_key
    from nozo_relay.mcp.server import build_mcp_server
    from nozo_relay.usecases import Ctx

    logsafe.install()
    settings = Settings()
    clock = SystemClock()
    engine = create_engine_from_settings(settings)
    ensure_schema(engine, clock, require_wal_fix=settings.sqlite_require_wal_fix)
    ctx = Ctx.from_engine(engine, clock, settings)

    first = authenticate_agent_key(ctx, raw_key)
    if first is None:
        print("agent key is invalid, expired or revoked", file=sys.stderr)
        return 2

    async def source() -> McpAuth | None:
        return await asyncio.to_thread(authenticate_agent_key, ctx, raw_key)

    server = build_mcp_server(ctx, source)
    try:
        server.run("stdio")
    finally:
        engine.dispose()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
