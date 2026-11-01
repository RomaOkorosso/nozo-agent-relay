# PROJECT STATUS - Nozo Agent Relay

**Состояние: «Реализация подготовлена к независимому аудиту Codex».**
This is **not** a "ready" / "GO" statement. The final independent audit (T12) has not been performed, and the capabilities
marked NOT_VERIFIED / BLOCKED_EXTERNAL below were never exercised for real. Updated: 2026-10-28 (UTC), end of T11 preparation.

| Item | Value |
|---|---|
| Design revision | **v1.0-draft.2** (`../nozo-relay-design/`) |
| Project root | `/home/roma/Desktop/Nozo Agent Relay/nozo-agent-relay` |
| Owner approval | 2026-10-28, Roman (Cursor session): M0-M3 implementation; intermediate Codex audits (T05) deferred into the final audit |
| Git | repository initialised, **no commit exists**; whole tree is untracked -> audit the **working tree** (see `CODEX_AUDIT_HANDOFF.md`). No push, no remote. |
| Schema | v5 (`schema_version`; v2/v3/v4 migrate additively), SQLite WAL, single Uvicorn worker |
| Python / deps | 3.14 via uv; `uv.lock` pinned; MCP SDK `mcp` 2.3.0 (optional extra, in dev group) |
| Last full test run | see "Verification" below |

## Task status

| Task | State | Notes |
|---|---|---|
| T00 design gate | done (owner) | |
| T01 foundation (auth, sessions, keys, health, idempotency base) | implemented | Cursor self-check |
| T02 tasks / messages / events | implemented | |
| T03 workflow (queue, leases, runs, audits, failure budget, controls) | implemented | test workers = fixtures only |
| T04 durable WebSocket + phone/admin UI | implemented | local Chrome emulation evidence; real phone NOT verified |
| **T05 intermediate Codex M0 audit** | **NOT DONE (deliberately)** | folded into the final audit by owner decision |
| T06 multi-project, policy, delegations, approvals (records only), artifacts, backup/restore | implemented | no publish executor by design |
| T07 runner isolation (Landlock/seccomp/cgroup supervisor) | implemented | needs a host that allows the sandbox; probe_pass outside the tool sandbox |
| T08 Cursor adapter | implemented; **real edit NOT_VERIFIED** | CLI not logged in; mocks only |
| T09 Codex adapter | implemented; real host-readonly audit evidence exists | sandboxed Codex blocked (credentials/egress) |
| T10 MCP facade + OAuth scaffolding | implemented | local SDK client/stdio/raw HTTP only |
| **T11 phone/ChatGPT** | **prepared, NOT completed** | local regression, docs, receipts; real phone and ChatGPT blocked |
| T12 final independent audit | round 1 **FAILED / NO-GO** (F01-F07, `CODEX_FINDINGS.md`); fixes implemented, **re-audit pending, NOT passed** | Codex; see `docs/FIX_ROUND_T12.md` |

## Capability table (evidence ladder: DESIGN -> UNIT -> INTEGRATION_FIXTURE -> LOCAL_BROWSER -> REAL_CLI -> REAL_CHATGPT_WEB -> REAL_CHATGPT_MOBILE)

| Capability | Status | Highest evidence level reached | Evidence |
|---|---|---|---|
| Core API, auth, idempotency, queue/leases, failure budget, controls | probe_pass (local) | INTEGRATION_FIXTURE | `tests/test_t01..t03*`, `t06*` |
| Durable WebSocket + replay | probe_pass (local) | INTEGRATION_FIXTURE (real socket) | `tests/test_t04_websocket_ui.py` |
| PHONE_UI - local browser (emulated 360x800 Chrome) | probe_pass | LOCAL_BROWSER | `evidence/t04/`, `evidence/t11/PHONE_UI.json` |
| PHONE_UI - **real mobile over private HTTPS (Q32)** | **BLOCKED_EXTERNAL** | none | Tailscale not installed; no device |
| Runner isolation (sandbox, snapshots, quarantine) | probe_pass (outside nested tool sandbox) | INTEGRATION_FIXTURE | `evidence/t07/` |
| CURSOR_CLI adapter (parsing, deny rules, lifecycle with mocks) | probe_pass (mocks) | INTEGRATION_FIXTURE | `tests/test_t08_cursor_adapter.py` |
| CURSOR_CLI **real edit (Q27)** | **NOT_VERIFIED / blocked_external** | none | agent not logged in; `evidence/t08/capability_report.json` |
| CODEX_CLI auditor - real host-readonly | probe_pass | REAL_CLI (unsandboxed host mode, read-only disposable copy) | `evidence/t09/` |
| CODEX_CLI auditor - sandboxed production mode | blocked_external | none | credential/egress blocked in T07 sandbox |
| MCP facade (HTTP + stdio) with official SDK client | probe_pass (local) | INTEGRATION_FIXTURE | `evidence/t10/` |
| MCP Inspector CLI | not_run | none | Node 18.19.1 < 22.19 |
| OAuth for MCP (in-process) | probe_pass (local) | INTEGRATION_FIXTURE | `evidence/t10/oauth_probe_*.json`; **owner consent page NOT implemented** |
| Coordinator delegation + `mint-key` CLI, no approve/publish | probe_pass (local) | INTEGRATION_FIXTURE | `tests/test_t11_phone_regression.py`, `tests/test_t10_mcp.py` |
| **CHATGPT_WEB (Q30)** | **NOT_VERIFIED** | none | `evidence/t11/CHATGPT_WEB.json` |
| **CHATGPT_MOBILE (Q31)** | **NOT_VERIFIED** | none | `evidence/t11/CHATGPT_MOBILE.json` |
| Publish / push / deploy | not implemented by design | - | `execute` always 501 `no_executor` |
| Production runner daemon (claim loop -> real adapters) | **not implemented** | - | only `runner/test_worker.py` claims jobs; real adapters are driven by tests/host probe |
| Billing / overage of Cursor and Codex | unknown | - | nothing purchased or verified |

## Added in T11 preparation
* `tests/test_t11_phone_regression.py` (12 tests): login/session, tasks, chat, reports, controls, offline-indicator contract, layout/no-OS-surface, `mint-key` + narrow coordinator delegation + no approve/publish/admin, receipt-honesty guards.
* `python -m nozo_relay mint-key` (owner CLI; key written once to a 0600 file, never printed; owner principals refused) - closes the gap that `POST /agents` creates identities without keys. This is the only production-code change in T11.
* `scripts/start.sh` one-command start; README sections: Tailscale Serve owner steps, coordinator delegation, ChatGPT MCP checklist.
* `evidence/t11/{PHONE_UI,CHATGPT_WEB,CHATGPT_MOBILE}.json` + README.

## Verification
`uv sync --extra mcp && uv run pytest -q` -> **408 passed, 4 skipped** (plain terminal); details in `CODEX_AUDIT_HANDOFF.md` section 9. Skips are NOT passes: they mark
real_cli opt-in tests, nested-sandbox-only environments and optional Playwright tests.

## T12 fix round (after the first independent audit)
F01-F07 fixed in code with regressions (`tests/test_independent_audit.py` 11 passed, `tests/test_t12_fixes.py` 51 passed, full suite **470 passed, 4 skipped**
outside nested sandboxes; supersedes the 408 figure above). **The independent audit is NOT passed**; the new snapshot and re-audit commands are in `docs/FIX_ROUND_T12.md`.

## Next
1. Owner actions (see `KNOWN_LIMITATIONS.md` / `CODEX_AUDIT_HANDOFF.md`).
2. Independent Codex audit T12 on the exact working tree (no intermediate T05).
3. Only after a real phone/ChatGPT/Cursor run may the corresponding receipts change.
