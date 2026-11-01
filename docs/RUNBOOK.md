# RUNBOOK

All commands run from the repo root. Nothing here needs `sudo`, a remote push, a purchase or a public port. Secrets are never printed;
credential files are `0600` under `data/` (gitignored). `NOZO_RELAY_DATA_DIR` selects another data directory for any command.

## Start / stop

```bash
./scripts/start.sh                                  # sync deps, bootstrap once, `check`, serve on 127.0.0.1:8765 (loopback; dev cookies)
# equivalent manual form:
uv sync --extra mcp
export NOZO_RELAY_INSECURE_DEV_COOKIES=1            # plain HTTP on loopback ONLY
uv run python -m nozo_relay check                   # settings + SQLite + schema; prints "ok"
uv run python -m nozo_relay serve                   # exactly ONE Uvicorn worker (SQLite single writer)
curl -s http://127.0.0.1:8765/api/v1/health/ready   # {"status":"ready","db":"ok","schema_version":4}
```

Stop: Ctrl-C (foreground) or `kill -TERM <pid>` (graceful). Running workers lose their lease after `LEASE_TTL_SECONDS` (90 s); the task becomes
`blocked(recovery_required)` and **nothing is re-issued** until the owner reconciles/resumes. Never run two server processes on one data dir.

Behind HTTPS (Tailscale Serve): see README "Phone access". Never bind `0.0.0.0` (refused unless `NOZO_RELAY_ALLOW_NON_LOOPBACK_BIND=1`, and never with insecure cookies).

## Bootstrap (one time)

```bash
uv run python -m nozo_relay bootstrap               # owner password + 2 test agent keys -> data/bootstrap_credentials.json (0600, once)
uv run python -m nozo_relay bootstrap --prompt-password   # choose the owner password interactively (not written to the file)
```
Copy secrets to a private store, then delete `bootstrap_credentials.json`. A second bootstrap is refused. Lost owner password: no reset path in v1
(restore from a backup or re-bootstrap into a NEW data dir).

## Identities, keys, delegations

```bash
# owner session (UI/curl) registers: POST /api/v1/agents {"display_name","kind":"coordinator|implementer|auditor|runner","project_ids":[...]}
uv run python -m nozo_relay mint-key --agent <principal id or exact name> [--expires-in-days N]   # key -> data/minted_keys/*.json (0600), not printed
# revoke a key:        POST /api/v1/agents/{agent_id}/keys/{key_id}/revoke   (owner; fences the agent's active runs)
# coordinator rights:  POST /api/v1/projects/{p}/delegations  (see README "Coordinator delegation")
```

## Backup / verify / restore

```bash
uv run python -m nozo_relay backup --to /path/backup-NEW          # online SQLite backup + artifacts + sha256 manifest (exit 3 if incomplete)
uv run python -m nozo_relay verify-backup --from /path/backup-NEW # read-only manifest check
uv run python -m nozo_relay restore --from /path/backup-NEW --to-data-dir /path/data-NEW [--migrate]
NOZO_RELAY_DATA_DIR=/path/data-NEW uv run python -m nozo_relay serve
```
Restore refuses a non-empty target, never touches the original, **revokes all sessions** and fences active runs (`recovery_required`). `bootstrap_credentials.json`,
`minted_keys/` and `.env` are NOT backed up (re-mint keys). Backups contain digests: treat as sensitive. Schema upgrade of a stopped v2/v3 DB:
`uv run python -m nozo_relay migrate` (backs up first to `data/backups/pre-migrate-<ts>`).

## Workers and runners

* **Fixture workers (no LLM)** - protocol/QA only:
  ```bash
  export NOZO_WORKER_KEY=<implementer key>; python -m nozo_relay.runner.test_worker --project-id <id> --stage implement --script pass --max-runs 2 &
  export NOZO_WORKER_KEY=<auditor key>;     python -m nozo_relay.runner.test_worker --project-id <id> --stage audit --script fail,pass --max-runs 2
  ```
* **Repo binding (owner only, never via API):** `repo-bind --project default --root /abs/repo`; `repo-approve-dirty --binding <id>`; `repo-clear-quarantine --binding <id>`.
* **Sandbox capability:** `uv run python -m nozo_relay sandbox-probe` (exit 3 if not `probe_pass`; in that case runs are blocked, there is no bypass flag).
* **Provider capability reports:** `uv run python -m nozo_relay.runner.adapters.capability {cursor|codex} --out evidence/tNN/capability_report.json [--live]` (`--live` = ONE tiny real call, consumes quota).
* **Real CLIs:** opt-in `NOZO_RUN_REAL_CLI=1 uv run pytest -m real_cli` (Cursor needs `cursor-agent login`; Codex uses the user's `CODEX_HOME` login). No always-on runner daemon exists yet (KNOWN_LIMITATIONS B1).

## MCP

```bash
uv sync --extra mcp                                          # SDK is optional; without it /mcp answers 404 (never a fake PASS)
curl -s -X POST http://127.0.0.1:8765/mcp -H "Authorization: Bearer $AGENT_OR_COORDINATOR_KEY" \
  -H 'Content-Type: application/json' -H 'Accept: application/json, text/event-stream' \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}'
NOZO_RELAY_MCP_AGENT_KEY=nzr_... uv run python -m nozo_relay.mcp_stdio   # stdio wrapper; key via environment only
```
Owner keys are refused on MCP. Settings: `MCP_ENABLED`, `MCP_RESOURCE_URL`, `MCP_OAUTH_*` (OAuth off by default; consent page not implemented). ChatGPT connection: README checklist (NOT verified).

## Tests

```bash
uv sync --extra mcp && uv run pytest -q                      # full suite
uv run pytest -q tests/test_t11_phone_regression.py          # T11 local regression + receipt guards
uv run --with playwright python -m pytest tests/test_t04_browser_smoke.py   # real Chrome 360x800 smoke (rewrites evidence/t04/)
NOZO_RUN_REAL_CLI=1 uv run pytest -q -m real_cli             # real Cursor/Codex (quota!); skips cleanly when blocked
```
Run outside nested sandboxes (e.g. a plain terminal, not the Cursor tool sandbox) so T07/T08/T09 sandbox tests are executed instead of skipped.

## Troubleshooting

| Symptom | Likely cause | Action |
|---|---|---|
| Login works but UI shows 403 on mutations over HTTPS | Origin/Host not in `ALLOWED_ORIGINS`/`ALLOWED_HOSTS` | Set exact JSON lists, no wildcards |
| Cookies not stored on plain HTTP | Secure cookies on a non-HTTPS origin | Loopback only: `NOZO_RELAY_INSECURE_DEV_COOKIES=1` |
| Task `blocked(recovery_required)` after restart | Lease lost | Owner reconcile/resume in the panel |
| UI says "Запрошено" not "Остановлено" | No runner `stopped` receipt yet (by design) | Wait for/inspect the runner; "Остановка не подтверждена" = deadline missed |
| `sandbox-probe` exit 3 / tests skipped | Nested sandbox or no Landlock/cgroup | Run in a normal terminal; see KNOWN_LIMITATIONS C |
| `/mcp` 404 | SDK missing or `MCP_ENABLED=false` | `uv sync --extra mcp` |
