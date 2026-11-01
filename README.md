# Nozo Agent Relay

Local relay that lets separate agents (implementer / auditor / coordinator) exchange tasks, results and
audits through a durable queue with strict authentication. Design package: `../nozo-relay-design/`
(normative: `03_DATA_MODEL`, `04_API_CONTRACTS`, `05_SECURITY`, `06_EXECUTION_PROTOCOL`).

**Status: «Реализация подготовлена к независимому аудиту Codex».** This is NOT a "project ready" claim: the final
independent audit (T12) has not been done and several capabilities are NOT_VERIFIED / BLOCKED_EXTERNAL
(real phone over private HTTPS, real Cursor CLI edit, ChatGPT web/mobile). See `docs/PROJECT_STATUS.md`,
`docs/KNOWN_LIMITATIONS.md`, `docs/RUNBOOK.md` and `CODEX_AUDIT_HANDOFF.md`.
Design revision: **v1.0-draft.2** (`../nozo-relay-design/`, normative: `03_DATA_MODEL`, `04_API_CONTRACTS`,
`05_SECURITY`, `06_EXECUTION_PROTOCOL`). Implemented: T01-T04, T06-T10 and T11 preparation (T05 intermediate audit deliberately not done).

## One-command start (local, loopback only)

```bash
./scripts/start.sh        # uv sync --extra mcp, one-time bootstrap if no DB, health check, serve on 127.0.0.1:8765
# open http://127.0.0.1:8765/login  (user "owner"; password is in data/bootstrap_credentials.json, 0600 - copy it, delete the file)
```

Behind an HTTPS proxy (Tailscale Serve): `NOZO_RELAY_HTTPS_PROXY=1 NOZO_RELAY_ALLOWED_ORIGINS=... NOZO_RELAY_ALLOWED_HOSTS=... ./scripts/start.sh`
(see "Phone access" below). Stop with Ctrl-C / `SIGTERM`. Everything else: `docs/RUNBOOK.md`.

## Requirements

* Linux, [uv](https://docs.astral.sh/uv/), Python 3.14 (managed by uv; the system Python is not touched)
* SQLite >= 3.35 (build bundled with the uv Python is used; `NOZO_RELAY_SQLITE_REQUIRE_WAL_FIX=1`
  additionally rejects builds without the WAL-reset fix)

## Setup

```bash
uv sync --extra mcp          # creates .venv with Python 3.14 and locked dependencies (+ the MCP SDK)
uv run pytest                # full test suite
```

## Bootstrap (one time)

```bash
# Generates the owner password. It is written ONCE to data/bootstrap_credentials.json (0600, gitignored)
uv run python -m nozo_relay bootstrap

# ...or choose the password interactively (it is then not written to the file)
uv run python -m nozo_relay bootstrap --prompt-password
```

Creates: owner principal (Argon2id password), default project `default`, two test agents
(`test-implementer`, `test-auditor`) with separate keys, and memberships. Keys and the generated password
appear only in `data/bootstrap_credentials.json`; the database stores only hashes/digests. Copy the secrets
to a private store (OS keyring / `0600` config) and delete the file. Bootstrap refuses to run twice.

## Run

```bash
# Plain-HTTP development on loopback needs the insecure-cookie profile (loopback only):
export NOZO_RELAY_INSECURE_DEV_COOKIES=1

uv run python -m nozo_relay serve                       # 127.0.0.1:8765
# or
uv run uvicorn nozo_relay.main:app_factory --factory --host 127.0.0.1 --port 8765
```

Behind an HTTPS reverse proxy (e.g. Tailscale Serve) keep the backend on `127.0.0.1`, leave
`INSECURE_DEV_COOKIES` unset (cookies are `Secure`) and set `NOZO_RELAY_ALLOWED_ORIGINS` /
`NOZO_RELAY_ALLOWED_HOSTS` to the HTTPS origin/host. Binding to a non-loopback address is refused unless
`NOZO_RELAY_ALLOW_NON_LOOPBACK_BIND=1`, and never together with insecure cookies. Use exactly one Uvicorn worker (SQLite single writer).

Smoke test:

```bash
curl -s http://127.0.0.1:8765/api/v1/health/live
curl -s http://127.0.0.1:8765/api/v1/health/ready
KEY=$(python -c "import json;print(json.load(open('data/bootstrap_credentials.json'))['agents'][0]['key'])")
curl -s -H "Authorization: Bearer $KEY" http://127.0.0.1:8765/api/v1/me
```

## Configuration (`NOZO_RELAY_*`, optional `.env`)

| Variable | Default |
|---|---|
| `DATA_DIR` | `./data` (dir 0700) |
| `SQLITE_PATH` | `<DATA_DIR>/relay.sqlite` |
| `HOST` / `PORT` | `127.0.0.1` / `8765` |
| `SESSION_IDLE_SECONDS` / `SESSION_ABSOLUTE_SECONDS` | `1800` / `43200` |
| `INSECURE_DEV_COOKIES` | `false` (allowed only on loopback) |
| `ALLOWED_ORIGINS`, `ALLOWED_HOSTS` | extra proxy origin/host (JSON list); no wildcards |
| `LOGIN_MAX_FAILURES`, `LOGIN_WINDOW_SECONDS`, `LOGIN_LOCKOUT_SECONDS` | `5`, `300`, `60` |

## Endpoints (T01)

`GET /api/v1/health/live`, `GET /api/v1/health/ready`, `POST /api/v1/auth/login`,
`POST /api/v1/auth/logout` (session + `X-CSRF-Token`), `GET /api/v1/me` (Bearer key or session).
Errors: `{"error":{"code","message","request_id","retryable","details"}}`.

## Layout

```
src/nozo_relay/  config clock bootstrap main __main__
  db/      models (M0 tables) engine (SQLite WAL/FULL/FK) schema (create_all + schema_version)
  auth/    passwords (Argon2id) keys (nzr_<prefix>.<secret>) credentials sessions ratelimit context
  api/     errors deps health auth_routes
  domain/  enums (closed enums from 03_DATA_MODEL)
```

## T02/T03: tasks, runs, controls (schema v2)

Every mutation (except login) needs `Idempotency-Key: <uuid>`; task mutations also need `If-Match: "<version>"`
(428 if missing, 412 if stale). Same key + same request replays the stored response (`Idempotent-Replay: true`);
same key + different request is `409 idempotency_conflict`. Inaccessible resources are `404`.

| Area | Endpoints (all under `/api/v1/projects/{project_id}` unless noted) |
|---|---|
| projects | `GET/POST /api/v1/projects`, `GET/PATCH /api/v1/projects/{id}`, `/delegations`, `/events?after_seq=`, `/snapshot` |
| tasks | `GET/POST /tasks`, `GET /tasks/{id}`, `POST /tasks/{id}/enqueue`, `GET/POST /tasks/{id}/messages` |
| controls | `POST /tasks/{id}/controls` (pause/cancel/resume/reassign/revise), `POST /controls` (project), `POST /controls/emergency-stop`, `GET /controls/{id}` |
| runs | `POST /jobs/claim`, `/runs/{id}/start`, `/heartbeat`, `/implementation-result`, `/audit-result`, `/fail`, `/stopped`, `/reconcile`, `POST /jobs/{id}/dispatch` |
| agents | `GET/POST /agents`, `POST /agents/{id}/keys/{key_id}/revoke` |

Claims use `BEGIN IMMEDIATE`; each run carries a `lease_epoch` fence (also bumped by controls). Leases:
heartbeat 15 s, TTL 90 s (`LEASE_TTL_SECONDS`, `HEARTBEAT_INTERVAL_SECONDS`, `WATCHDOG_INTERVAL_SECONDS`,
`STOP_CONFIRM_DEADLINE_SECONDS`, `RUNTIME_RETRY_LIMIT`). Expired leases become `lost` and the task
`blocked(recovery_required)`; nothing is re-issued until the owner reconciles/resumes.

### Running a mock cycle with test workers (no LLM)

```bash
uv run python -m nozo_relay --help   # start the server as in the T01 section, then:
export NOZO_WORKER_KEY=<implementer key from data/bootstrap_credentials.json>
python -m nozo_relay.runner.test_worker --project-id <project id> --stage implement --script pass --max-runs 2 &
export NOZO_WORKER_KEY=<auditor key>
python -m nozo_relay.runner.test_worker --project-id <project id> --stage audit --script fail,pass --max-runs 2
```

Scripts: `pass,fail,inconclusive,wait,crash,api_fail` (one per run, last repeats). `wait` runs until an owner
control arrives; with `NOZO_SUPERVISOR_KEY` (a runner-kind key) it posts the `stopped` receipt. Exit codes:
0 ok, 2 usage, 3 idle, 4 API error, 7 simulated crash. Real-process tests: `tests/test_t03_real_workers.py`.

## T04: durable WebSocket + phone/admin UI

### Open the UI locally

```bash
export NOZO_RELAY_INSECURE_DEV_COOKIES=1        # plain HTTP on loopback only
uv run python -m nozo_relay bootstrap           # once; owner password -> data/bootstrap_credentials.json
uv run python -m nozo_relay serve               # 127.0.0.1:8765
# open http://127.0.0.1:8765/login  (log in as owner)
```

Pages: `/login`, `/projects`, `/projects/{id}` (tasks / chat / controls), `/projects/{id}/tasks/{tid}`.
Server-rendered Jinja2 + vanilla JS/CSS (no SPA, no Node). Russian labels, mobile-first from 360 px, touch
targets >= 44 px. It is a control/chat panel, not a remote desktop, terminal or file browser.
The browser never stores agent keys: only the `HttpOnly` session cookie plus a CSRF header for mutations;
nothing in `localStorage`/`sessionStorage`. Commands are **not** queued offline (they fail visibly).

### WebSocket `WS /ws/v1/projects/{project_id}?after_seq=N`

* Auth happens **before** the handshake is accepted: session cookie (Origin must be allow-listed) or
  `Authorization: Bearer <key>`. No credentials in the query string (unknown query parameters are rejected).
* Replays durable events with `seq > after_seq`, then streams live. Frames: `schema_version, event_id, seq,
  project_id, task_id, type, entity_version, occurred_at, data`; control frames `ready`, `heartbeat` (~20 s),
  `resync_required`. Project `seq` may have gaps; clients dedup by `event_id`/`seq`.
* The DB event log is the source of truth. A commit hook wakes subscribers immediately; a periodic DB scan
  (`WS_SCAN_INTERVAL_SECONDS`) guarantees delivery even if the process dies between commit and notify.
* Slow consumer (>1000 queued events or >2 MiB, or a stalled send): `resync_required` and close `4411`.
  Close `4401` = session/key expired or revoked (logout and key revoke close sockets at once), `4410` = cursor ahead.
* UI indicator: `connected` / `reconnecting` / `polling` (after 3 failed attempts, every 10 s; polling does not
  extend the idle session) / `offline`, plus "last synced".

| Variable | Default |
|---|---|
| `WS_HEARTBEAT_SECONDS` | `20` |
| `WS_SCAN_INTERVAL_SECONDS` | `1` |
| `WS_AUTH_RECHECK_SECONDS` | `5` |
| `WS_QUEUE_MAX_EVENTS` / `WS_QUEUE_MAX_BYTES` | `1000` / `2097152` |
| `WS_SEND_TIMEOUT_SECONDS` | `10` |
| `WS_BATCH_SIZE`, `WS_MAX_CONNECTIONS_PER_PRINCIPAL` | `200`, `20` |

### Status honesty

A stop request that the server accepted (HTTP 202) is shown as **"Запрошено"**, never as stopped.
"Остановлено" appears only with a runner `stopped` receipt for the target run; a missed deadline shows
"Остановка не подтверждена". Claimed lease, started process, heartbeat age and output are shown as separate
signals ("взято" is not "выполняется").

### Phone access (private HTTPS, Tailscale Serve)

**Status on the build host: Tailscale is NOT installed -> real phone HTTPS (Q32) is BLOCKED_EXTERNAL.** Every step below
is an **owner action**; the agent/automation never runs `sudo`, installs packages or joins a tailnet. Never bind the relay to
`0.0.0.0`, never use Tailscale Funnel / port forwarding / a public tunnel for the admin panel.

1. *(owner, needs sudo)* Install Tailscale on the laptop following <https://tailscale.com/download/linux> and sign in
   (`sudo tailscale up`). Install the Tailscale app on the phone and sign in to the **same tailnet**.
2. *(owner, admin console)* Enable MagicDNS and HTTPS certificates (DNS page -> "HTTPS Certificates"). Note the machine name:
   `tailscale status --self --json | jq -r .Self.DNSName` -> `<machine>.<tailnet>.ts.net.` (drop the trailing dot).
3. *(owner, admin console)* ACL: allow only the phone -> this laptop on `tcp:443`; no other tailnet device needs access.
   Do **not** enable Funnel (`tailscale funnel status` must say it is off).
4. Start the relay on loopback with Secure cookies and the exact HTTPS origin (no wildcards):

   ```bash
   unset NOZO_RELAY_INSECURE_DEV_COOKIES
   export NOZO_RELAY_ALLOWED_ORIGINS='["https://<machine>.<tailnet>.ts.net"]'
   export NOZO_RELAY_ALLOWED_HOSTS='["<machine>.<tailnet>.ts.net"]'
   NOZO_RELAY_HTTPS_PROXY=1 ./scripts/start.sh        # 127.0.0.1:8765, ONE Uvicorn worker
   ```
5. In a second terminal publish it to the tailnet only (the command form can differ per Tailscale version - check `tailscale serve --help`):

   ```bash
   tailscale serve --bg 8765            # https://<machine>.<tailnet>.ts.net -> http://127.0.0.1:8765 (also carries wss://)
   tailscale serve status               # verify: tailnet-only, no "Funnel on"
   tailscale funnel status              # must be off
   ```
6. On the phone (tailnet connected, **mobile data, Wi-Fi off**) open `https://<machine>.<tailnet>.ts.net/login`. Run the Q32 checklist:
   login; create + enqueue a task; chat; read a report; pause/stop (UI must say "Запрошено", never "Остановлено" without a runner receipt);
   switch Wi-Fi<->LTE, background the tab, lock the phone, return -> indicator goes offline/reconnecting and replays without duplicates;
   log out on the phone and confirm protected pages/fragments/WebSocket are rejected (there is NO owner UI/API to revoke another device's session in v1 - a known gap; sessions end by logout, 30 min idle/12 h absolute expiry, or `restore`, which revokes all); confirm there is no OS/file/terminal access.
7. Record the result (device, OS, browser versions, screenshots without secrets) in `evidence/t11/PHONE_UI.json` ->
   `levels.real_mobile`. Only a real device test may change `BLOCKED_EXTERNAL`.

Stop publishing: `tailscale serve reset` (or `tailscale serve --https=443 off`). Local, emulated and unit checks are NOT a substitute (Q32).

### Tests and Q32 status

`tests/test_t04_websocket_ui.py` (WebSocket/UI/CSRF/honesty rules, real-socket slow-consumer test) runs in
`uv run pytest`. `tests/test_t04_browser_smoke.py` drives system Chrome (Playwright, 360x800 emulation + desktop)
against a real server and writes screenshots to `evidence/t04/`; it is skipped when Playwright/Chrome are absent:

```bash
uv run --with playwright python -m pytest tests/test_t04_browser_smoke.py
```

**Q32 (real phone test over private HTTPS) is NOT_VERIFIED / BLOCKED** until the owner provides a device.
The emulated-Chrome smoke is not a substitute (WebKit/Safari untested; touch/keyboard/background-tab behaviour of a
real phone is unverified).

## T06: multi-project, policy, scope, backup/restore, approval records (schema v3)

Schema v3 is additive (`projects.last_claimed_at`, `sessions.reauth_at`, approval-request columns). A v2 database is
upgraded in place with `uv run python -m nozo_relay migrate` (takes a backup to `data_dir/backups/pre-migrate-<ts>` first).
Only v2 -> v3 is supported.

Routes (all under `/api/v1`):
* `POST /jobs/claim` - cross-project claim (tier, urgency, round-robin across the caller's projects; paused projects skipped).
* `GET/PUT /projects/{p}/policy` (owner only, `If-Match`). A policy change alters `policy_digest`; queued jobs become
  stale (claim -> 409 `policy_stale`) until the owner revises the task.
* `POST/GET /projects/{p}/delegations`, `POST .../delegations/{id}/revoke` (owner only). Ceiling may not exceed the project ceiling.
* `POST/GET /projects/{p}/approval-requests`, `GET .../{id}`, `POST .../{id}/decision` (owner, session, recent auth,
  bound to `action_digest`, single use, expiry). `POST .../{id}/execute` always answers **501 `no_executor`**: nothing publishes in v1.
* `POST /auth/reauth {password}` - refreshes the owner's recent-auth window (`recent_auth_seconds`, default 300).
* `POST/GET /projects/{p}/artifacts[/{id}]` - raw-byte upload (`artifact_max_bytes` 10 MiB, project quota 1 GiB), sha256-verified,
  always served as an octet-stream attachment; other projects get 404.

Backup / restore:
```bash
uv run python -m nozo_relay backup --to /path/backup-dir          # SQLite online backup + manifest (sha256)
uv run python -m nozo_relay verify-backup --from /path/backup-dir
uv run python -m nozo_relay restore --from /path/backup-dir --to-data-dir /path/NEW-dir [--migrate]
```
Restore refuses a non-empty target, never touches the original, revokes all sessions and fences active runs
(`recovery_required`). `bootstrap_credentials.json` and `.env` are not backed up. Backups contain digests: treat as sensitive.

Retention (`nozo_relay/retention.py`): events and reports are kept forever (no auto-deletion in v1); projects are
archive-only; backups are operator-managed.

## Known gaps

* Schema bumped to v2 (CHECK widening) without a v1 migration; recreate dev databases.
* No artifact upload endpoints (artifact id lists must be empty), evidence redaction is truncation only.
* No claim-start 30 s deadline; no owner "budget decision" flow (resume after iteration_limit/loop is refused).
* Project `limits` PATCH, `repo_bindings`/locks unused; heartbeat responses are not idempotency-cached.
* Supervisor = any RUNNER-kind member (no per-run registration); owner CLI `mint-key` (T11) mints keys for registered agents; no per-run supervisor registration.
* Alembic migrations are a later step.
* T06: no OS sandbox (T07); no publish executor; approvals have no UI; backups/artifacts are never pruned;
  an artifact file can be orphaned if its DB commit fails; cross-project claim only covers the caller's memberships.

## Runner isolation (T07)

```bash
uv run python -m nozo_relay repo-bind --project default --root /abs/path/to/repo   # owner-only; API payloads can never carry paths
uv run python -m nozo_relay repo-approve-dirty --binding <id>                      # explicit saved snapshot of a dirty tree
uv run python -m nozo_relay repo-clear-quarantine --binding <id>
uv run python -m nozo_relay sandbox-probe                                          # Landlock/seccomp/cgroup capability report (exit 3 if not probe_pass)
```

The supervisor (`nozo_relay.runner.supervisor`) runs a child by argv list in a disposable clone, under Landlock +
seccomp + rlimits (+ cgroup v2 when delegated), with a clean env and temporary HOME. It never resets your tree,
never runs git inside the clone, hashes the result itself and quarantines scope violations. No flag disables the
sandbox: if the probe fails, runs are blocked with an explanation. Evidence and limitations: `evidence/t07/`.
T07 tests need the real sandbox (outside nested sandboxes): `uv run pytest tests/test_t07_runner_isolation.py`.

## MCP facade (T10)

Streamable HTTP `POST /mcp` on the same loopback listener, plus an optional stdio wrapper. Both call the SAME use
cases as REST (`nozo_relay/usecases.py`), so idempotency scope (principal + operation + key), ACL, guards and events
are shared; `request_id` == `Idempotency-Key`. Official SDK `mcp` **2.3.0** (optional extra, pinned in `uv.lock`).

```bash
uv sync --extra mcp                      # (the dev group already includes it)
# 1. start the relay (see "Run"), 2. use an AGENT/coordinator key from bootstrap_credentials.json (owner keys are refused)
curl -s -X POST http://127.0.0.1:8765/mcp \
  -H "Authorization: Bearer $RELAY_AGENT_KEY" -H 'Content-Type: application/json' \
  -H 'Accept: application/json, text/event-stream' \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}'
# stdio (key from the ENVIRONMENT, never argv; re-verified on every call):
NOZO_RELAY_MCP_AGENT_KEY=nzr_... uv run python -m nozo_relay.mcp_stdio
# MCP Inspector CLI (needs Node >= 22.19 for @modelcontextprotocol/inspector 2.x; GUI not required):
npx @modelcontextprotocol/inspector --cli http://127.0.0.1:8765/mcp --transport http \
    --header "Authorization: Bearer $RELAY_AGENT_KEY" --method tools/list
```

Tools: `relay_list_projects`, `relay_get_task`, `relay_list_tasks`, `relay_create_task`, `relay_enqueue_task`,
`relay_control_task` (pause/cancel/reassign/revise only), `relay_post_message`, `relay_get_report`, `relay_get_events`,
`relay_request_approval` (creates a pending record; cannot approve). Not exposed: owner approve/decision/execute,
publish/deploy, shell, keys/delegations/policy, resume, project-wide/emergency controls, runner lifecycle.
Settings: `MCP_ENABLED` (default true; skipped if the SDK is missing), `MCP_RESOURCE_URL`, and the OAuth scaffolding
(`MCP_OAUTH_ENABLED=false` by default, `MCP_OAUTH_REDIRECT_URIS`, ...). Evidence and limits: `evidence/t10/`.

## Coordinator delegation (narrow, no approve/publish)

A coordinator (ChatGPT or any MCP client) is a **P1 principal that never holds owner authority**. It can only create/enqueue/control
tasks inside a time-boxed, owner-signed delegation, and may only *request* approvals. Owner-only actions (decision/execute, agents,
keys, delegations, policy, emergency/project-wide controls, reauth) are denied; MCP has no tool for them and owner keys are refused.
Tests proving this: `tests/test_t11_phone_regression.py`, `tests/test_t10_mcp.py::test_coordinator_cannot_approve_anything`.

```bash
# 1. owner session (login via the UI or POST /api/v1/auth/login) registers the identity (no key yet):
curl -s -b cookies.txt -H "X-CSRF-Token: $CSRF" -H "Idempotency-Key: $(uuidgen)" -H 'Content-Type: application/json' \
  -d '{"display_name":"chatgpt-coordinator","kind":"coordinator","project_ids":["<project_id>"]}' http://127.0.0.1:8765/api/v1/agents   # -> {"id": "<coordinator_id>", ...}
# 2. owner CLI mints a key: written ONCE to data/minted_keys/<id>-<cred>.json (0600), never printed
uv run python -m nozo_relay mint-key --agent <coordinator_id> --expires-in-days 30
# 3. owner grants the narrow delegation (omit task.control unless needed; ceiling is checked on every create/enqueue)
curl -s -b cookies.txt -H "X-CSRF-Token: $CSRF" -H "Idempotency-Key: $(uuidgen)" -H 'Content-Type: application/json' \
  -d '{"coordinator_id":"<coordinator_id>","allowed_actions":["task.create","task.enqueue"],"scope_ceiling":{"allowed_paths":["src/**"],"max_changed_files":5,"max_diff_lines":200},"valid_until":"2026-12-31T00:00:00+00:00"}' \
  http://127.0.0.1:8765/api/v1/projects/<project_id>/delegations
# revoke at any time: POST /projects/<p>/delegations/<id>/revoke {"reason":"..."}; revoke a key: POST /agents/<id>/keys/<key_id>/revoke
```

Tasks created by a coordinator must carry `delegation_id` and `autonomous:false`; an out-of-ceiling or expired/revoked delegation is refused.

## ChatGPT MCP connection checklist (owner-run; NOT verified by the agent)

Receipts: `evidence/t11/CHATGPT_WEB.json` and `CHATGPT_MOBILE.json` are **NOT_VERIFIED**. Do not mark them verified from MCP Inspector or SDK-client results.

1. **Account/permissions (owner):** confirm the ChatGPT plan/workspace allows custom MCP connectors (developer mode / admin setting). Do not buy or change a plan on the agent's behalf; record plan name and any workspace admin restriction.
2. **Transport (pick one, owner decision):**
   * **Secure MCP Tunnel** (preferred to investigate): no public inbound port; needs a tunnel runtime/key and possibly platform rights/cost - verify current vendor docs before use; the relay stays on `127.0.0.1`.
   * **HTTPS OAuth alternative:** a stable public HTTPS URL for `/mcp` + OAuth 2.1/PKCE. Needs the **owner consent page** (`/oauth/consent`, NOT implemented - a separate approved task), exact `MCP_OAUTH_REDIRECT_URIS`, `MCP_RESOURCE_URL`, `MCP_OAUTH_ENABLED=true`, a public-exposure review (see `evidence/t10/KNOWN_LIMITATIONS.md` #3-#6), and a rate limit on `/register`/`/authorize`. Tailscale Serve is tailnet-only and is not reachable by ChatGPT's servers; Funnel is forbidden for the admin panel.
3. **Identity:** register a coordinator and give it a **narrow delegation** (section above). Use a dedicated test project.
4. **Connect** the connector to `<https-origin>/mcp` and run, recording tool-call transcripts without secrets:
   `relay_list_projects` -> `relay_create_task` -> `relay_get_task` readback -> repeat `relay_create_task` with the same `request_id` (must replay, one task) -> `relay_post_message` -> `relay_request_approval` -> revoke the key/delegation and confirm the next call fails.
5. **Prove no approve/publish:** the tool list contains no approve/decide/execute/publish/shell/key/delegation/policy tool; the pending approval stays `pending`; `POST .../decision` with the coordinator key is `403`; `POST .../execute` can never publish (501 `no_executor`).
6. **Web vs mobile:** test desktop web first (Q30), then mobile web and the native app **separately** (Q31) with OS/app versions; record unsupported surfaces as unsupported.
7. Update the receipts only after a real call; `tests/test_t11_phone_regression.py::test_t11_receipts_*` guards against over-claiming.
