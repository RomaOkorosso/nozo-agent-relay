# CODEX_AUDIT_HANDOFF - Nozo Agent Relay (final independent audit request, T12)

**This is the FINAL audit request.** The intermediate T05 Codex audit was **not done** (deliberately folded into this audit by owner decision of 2026-10-28).
Implementation state: **«Реализация подготовлена к независимому аудиту Codex»**. It is NOT declared ready; several capabilities are
NOT_VERIFIED / BLOCKED_EXTERNAL (below). You are the independent, sceptical auditor: treat every Cursor claim here as a hypothesis to verify, start from the requirements.

## 1. Identity and scope

| | |
|---|---|
| Design revision (normative) | **v1.0-draft.2** - `/home/roma/Desktop/Nozo Agent Relay/nozo-relay-design/` (read `README`, `AGENTS`, `02_ARCHITECTURE`, `03_DATA_MODEL`, `04_API_CONTRACTS`, `05_SECURITY`, `06_EXECUTION_PROTOCOL`, `09_QA_CODEX`, `tasks/T12_V1_AUDIT.md`) |
| Project root | `/home/roma/Desktop/Nozo Agent Relay/nozo-agent-relay` |
| Stage under audit | M0-M3 implementation T01-T04, T06-T11(prep). Verdict requested per stage + `GO/NO-GO` + `not_verified` list |
| Authority | Read, run tests, write an independent harness and temp outputs in a **separate copy**. **No** production-source edits, **no** push/publish, no purchases, no sudo. |
| Reports | Fill `../nozo-relay-design/templates/AUDIT_REPORT.md`; findings in `CODEX_FINDINGS.md` (S0/S1/S2 with exact repro/expected/actual/evidence/snapshot) |

## 2. Git state - AUDIT THE WORKING TREE

The repository has been `git init`-ed but has **NO commit** (branch `master`, every file untracked, nothing staged). Cursor did **not** commit (no owner permission) and did not push.
Therefore there is no commit hash. Record the exact snapshot yourself before touching anything:

```bash
cd "/home/roma/Desktop/Nozo Agent Relay/nozo-agent-relay"
git status --short --branch                       # expect: "No commits yet on master" + all paths "??"
git rev-parse --verify HEAD || echo "no HEAD (expected)"
# tree hash of the working tree WITHOUT touching the real index (uses a throw-away index; honours .gitignore: data/, .venv, *.sqlite, secrets excluded):
export GIT_INDEX_FILE="$(mktemp -u)" && git add -A && git write-tree && rm -f "$GIT_INDEX_FILE"; unset GIT_INDEX_FILE
# plain `git write-tree` on the real (empty) index returns the empty tree 4b825dc642cb6eb9a0e1fd5e82fd4bd8a9be4de6... - that is NOT the snapshot.
# content manifest independent of git:
git ls-files --others --exclude-standard -z | sort -z | xargs -0 sha256sum | sha256sum
```
Cursor's reference values at handoff (computed over the tree **excluding** `CODEX_AUDIT_HANDOFF.md` and `docs/PROJECT_STATUS.md`, which embed them; see section 9). If your values differ, the tree changed after handoff - record and report the difference.
Work in a copy: `rsync -a --exclude .venv --exclude data --exclude .git ./ /tmp/audit-copy/` (then `uv sync --extra mcp` there).

## 3. Commands

```bash
uv sync --extra mcp && uv run pytest -q                                   # full suite
uv run pytest -q tests/test_t11_phone_regression.py                       # T11 local regression + receipt-honesty guards
uv run --with playwright python -m pytest -q tests/test_t04_browser_smoke.py   # real Chrome 360x800 + desktop smoke (needs system Chrome)
NOZO_RUN_REAL_CLI=1 uv run pytest -q -m real_cli                          # REAL Cursor/Codex (opt-in; consumes quota; skips cleanly if blocked)
uv run python -m nozo_relay sandbox-probe                                 # exit 0 = probe_pass
```
**Important:** run in a normal terminal. Inside nested sandboxes (e.g. the Cursor tool sandbox) the T07/T08/T09 sandbox tests are *skipped* (`probe_fail: supervisor cannot stop child`) - a skip is not a pass. Cursor's baseline inside the tool sandbox was 331 passed / 69 skipped; outside it, see section 9.
`-m real_cli` runs real Codex (logged in, host-readonly, unsandboxed read-only copy). Real Cursor is expected to skip/block (not logged in). Do not buy, upgrade or bypass anything to unblock.

## 4. Capabilities and acceptance criteria

| Capability | Acceptance (what must be true for PASS) | Cursor status |
|---|---|---|
| Auth/sessions/keys | Argon2id, only digests stored, session HttpOnly+CSRF+Origin/Host allow-list, rate limit, revoke closes REST+WS at once (Q20, Q21) | UNIT/INTEGRATION_FIXTURE pass |
| Idempotent mutations | same key+body replays, different body 409, lost response not duplicated, shared with MCP (Q01, Q02, Q04, Q05) | pass (fixture) |
| Queue/leases/fences | single active lease, stale epoch/revision/snapshot rejected, lost lease -> `recovery_required`, no re-issue (Q03, Q07, Q08, Q16, Q35) | pass (fixture) |
| Failure budget / loops | 3 FAILs -> blocked across restart, no 4th run; repeated FAIL not double-counted; A->B->A loop block (Q11-Q13) | pass (fixture) |
| Controls / stop honesty | pause/cancel -> fence + kill tree; UI says "Запрошено" until runner receipt; unreachable runner -> unknown not stopped (Q09, Q10) | pass (fixture + real sandbox) |
| Durable WebSocket | auth before accept, replay by seq, exactly-once on reconnect, slow-consumer resync, crash-before-notify (Q06, Q18, Q19) | pass (real socket) |
| Phone/admin UI (local) | login, tasks, chat, reports, controls, offline indicator, escaping, CSP (Q21, Q32-local) | **probe_pass LOCAL_BROWSER (emulated)** |
| Multi-project/policy/approvals | cross-project IDs -> 404 over REST/WS/artifact/messages/MCP (Q14); approval bound to digest, single use, expiry, no executor (Q33); paused project starves nothing (Q34) | pass (fixture) |
| Backup/restore/migrate | counts/history/snapshots intact, sessions revoked, original untouched (Q24) | pass |
| Runner isolation | scope violation via rename/symlink/binary/shell interpreter -> sandbox deny/quarantine, repo intact (Q25, Q26); secrets not visible (Q22) | probe_pass outside nested sandbox |
| Cursor adapter | real CLI edits fixture, honours deny, cancels with descendants (Q27); auth/quota -> exact blocker (Q29); hostile model JSON not executed (Q36) | mocks pass; **real NOT_VERIFIED** |
| Codex adapter | independently finds injected defect without editing production (Q28); never PASS for not_run (Q17) | real host-readonly `probe_pass` (REAL_CLI) |
| MCP facade | same use cases/ACL/idempotency as REST; closed toolset; owner keys refused; no approve/publish tool (Q14, Q15) | local SDK/stdio/raw HTTP pass |
| Coordinator delegation | narrow, expiring, revocable; ceiling enforced; no decision/execute/admin (Q15, Q30-equivalent locally) | pass (fixture); `mint-key` CLI new in T11 |
| ChatGPT web / mobile | real connector list/create/readback/retry/revoke with identical guards; mobile web vs native separate (Q30, Q31) | **NOT_VERIFIED** |
| Phone real network | Q32 on a real phone over private HTTPS, Wi-Fi<->LTE, revoked session rejected | **BLOCKED_EXTERNAL** |

## 5. Qxx coverage map (`../nozo-relay-design/09_QA_CODEX.md`)

"Cursor-tested" = covered by an automated test in this repo at INTEGRATION_FIXTURE level or above (test file in parentheses). It is **not** independent verification; assert correct behaviour yourself.

| Q | Status | Where |
|---|---|---|
| Q01, Q02 | Cursor-tested | t02 |
| Q03, Q04, Q05, Q07 | Cursor-tested | t03 |
| Q06 | Cursor-tested | t02, t04 |
| Q08, Q09, Q10 | Cursor-tested (stop/lease logic t03; real process-tree kill needs sandbox, t07) | t03, t07 |
| Q11, Q12, Q13 | Cursor-tested | t03, t06 |
| Q14 | Cursor-tested incl. MCP | t06, t10 |
| Q15 | Cursor-tested | t02, t03, t10, t11 |
| Q16, Q17 | Cursor-tested (also with real snapshot hashes) | t03, t09 |
| Q18, Q19, Q20, Q21 | Cursor-tested (real socket / TestClient) | t01, t04 |
| Q22 | Cursor-tested (sentinel secrets; redaction limits in KNOWN_LIMITATIONS) | t01, t07 |
| Q23 | **PARTIAL**: only a monkeypatched `database is locked` on one message POST -> 503 retryable (t04). Disk-full, other routes and outbox/no-lost-write are NOT tested | t04 |
| Q24 | Cursor-tested on copies | t06 |
| Q25, Q26 | Cursor-tested - **only executed outside nested sandbox** | t06, t07 |
| Q27 | **not_verified (real)**: mock adapter only; Cursor not logged in | t08 |
| Q28 | Cursor-tested with **real Codex** (host-readonly, REAL_CLI) | t09, `evidence/t09/` |
| Q29 | Cursor-tested (mocks + real blockers recorded) | t08, t09, `evidence/t08/`, `evidence/t09/` |
| Q30 | **NOT_VERIFIED** (ChatGPT never connected; local SDK client is not ChatGPT) | `evidence/t11/CHATGPT_WEB.json`, `evidence/t10/` |
| Q31 | **NOT_VERIFIED** | `evidence/t11/CHATGPT_MOBILE.json` |
| Q32 | **local only** (emulated Chrome + TestClient); real phone **BLOCKED_EXTERNAL** | t04, t11, `evidence/t04/`, `evidence/t11/PHONE_UI.json` |
| Q33, Q34 | Cursor-tested | t06, t03 |
| Q35 | Cursor-tested (serialised outcomes, barriers) | t03 |
| Q36 | Cursor-tested with mocks (+ real Codex run ignored an injection comment) | t07, t08, t09 |

## 6. Known problems / suspicion list (verify, do not trust)

1. **No production runner daemon**: only `runner/test_worker.py` claims jobs; real adapters are driven by tests/host probe. A real end-to-end autonomous cycle was shown only via harness (`evidence/t09/full_cycle_real_codex.json`: *mock* Cursor + real Codex).
2. **OAuth consent page missing** (`/oauth/consent` 404): MCP OAuth only proven in-process; ChatGPT registration/transport (DCR/CIMD, tunnel) unknown. SDK CORS `*` on token/register/revoke; no rate limit on `/register`, `/authorize`; OAuth state in memory.
3. **Sandboxed Codex/Cursor cannot reach provider hosts** (DNS/UDP blocked; credentials not mounted). Codex audit evidence is **unsandboxed host mode** by design. Cursor not logged in; its real parsing is mock-verified only.
4. T07 sandbox guarantees: chmod/chown/utime outside the sandbox on owned files; cgroup-less fallback may miss a fast `setsid` double-fork; no PDEATHSIG; disk quota not enforced during a run; aarch64 untested (`evidence/t07/KNOWN_LIMITATIONS.md`).
5. No owner UI/API to revoke another device's session; no approval UI; no publish executor (by design); events/artifacts/backups never pruned.
6. Browser evidence is **emulated Chromium** only; no Safari/WebKit/Android.
7. T11 added production code: `nozo_relay/keymint.py` + `mint-key` CLI (owner-only, key to 0600 file, owners refused). Review it for key-material handling (file written inside the DB transaction; a failed commit could leave an unusable key file).
8. `mint-key`, `scripts/start.sh`, README Tailscale/ChatGPT steps are **documented, not executed against Tailscale/ChatGPT**.
9. Billing/overage for both providers unknown; nothing purchased.
10. Suspected-but-unverified areas worth extra negative testing: Q23 beyond the single busy-DB test (disk full, every mutating route), WS limits under load, Q35 races with real threads rather than the TestClient, backup/restore with live WAL writers, UI JS (no JS unit tests; only browser smoke).
Full list: `docs/KNOWN_LIMITATIONS.md`.

## 7. Owner actions that gate NOT_VERIFIED items

1. Install Tailscale (sudo) on laptop + phone, enable HTTPS certs, run README "Phone access", test Q32 on a real phone -> then update `evidence/t11/PHONE_UI.json`.
2. `cursor-agent login` (or register a `CURSOR_API_KEY` with the supervisor) -> rerun `capability cursor --live` / `-m real_cli` for Q27.
3. ChatGPT: confirm plan/workspace allows custom MCP connectors; choose Secure MCP Tunnel vs HTTPS OAuth; (OAuth needs the consent-page task) -> README checklist -> update `CHATGPT_WEB.json` (Q30) then `CHATGPT_MOBILE.json` (Q31).
4. Decide Codex mode for production (accept host-readonly auditing vs `CODEX_API_KEY` + egress allow-list).
5. Optional: Node >= 22.19 for MCP Inspector CLI.

## 8. Expected output from you

Audit report (template), `CODEX_FINDINGS.md`, exit codes of every command run, Qxx coverage achieved, snapshot (tree hash) audited, `not_verified` list, GO/NO-GO per stage. Do not convert any NOT_VERIFIED/BLOCKED_EXTERNAL item to PASS without a real invocation. After fixes by Cursor, re-audit only the exact new snapshot + affected regressions; stop and escalate at the iteration limit.

## 9. Results at handoff (Cursor, 2026-10-28 UTC)

| Check | Result |
|---|---|
| `uv sync --extra mcp && uv run pytest -q` (plain terminal, outside tool sandbox, 2026-10-28) | **408 passed, 4 skipped, 0 failed** (3m29s) |
| Skips (4) | `test_t04_browser_smoke` module (Playwright not in project deps), 1 real Cursor test + 2 real Codex tests (`NOZO_RUN_REAL_CLI` opt-in) |
| `uv run --with playwright python -m pytest tests/test_t04_browser_smoke.py` | **3 passed** (real Chrome, 360x800 + desktop; screenshots in `evidence/t04/`) |
| `tests/test_t11_phone_regression.py` alone | 12 passed |
| Same suite inside the Cursor tool sandbox (before the 12 T11 tests were added) | 331 passed, 69 skipped (nested sandbox: T07/T08/T09 sandbox tests skip) - shown only to explain skips |
| `-m real_cli` | **not run by this handoff** (consumes quota; Cursor not logged in). Existing real Codex evidence: `evidence/t09/` (generated earlier, host-readonly) |
| `git` | repo has **no commits**; real index empty; everything untracked; nothing pushed |

Reference snapshot (tree **excluding** `CODEX_AUDIT_HANDOFF.md` and `docs/PROJECT_STATUS.md`; 171 files):

```bash
export GIT_INDEX_FILE="$(mktemp -u)" && git add -A && git rm -q --cached CODEX_AUDIT_HANDOFF.md docs/PROJECT_STATUS.md && git write-tree; rm -f "$GIT_INDEX_FILE"; unset GIT_INDEX_FILE
# expected tree: ca63a22ca562ba0654c831896593bc5c9bcea268
git ls-files --others --exclude-standard -z | grep -zv -e '^CODEX_AUDIT_HANDOFF.md$' -e '^docs/PROJECT_STATUS.md$' | sort -z | xargs -0 sha256sum | sha256sum
# expected manifest sha256: 7925248a9fd9949d88d1fd27c5e49d57e15a271d51e01461c1e2f82b22a1d06e
```
(`git write-tree` with a throw-away index writes tree/blob objects into `.git/objects` but creates no commit, ref or index change.)



---

## Update after T12 round 1 (FAIL): fix round

Findings F01-F07 (`CODEX_FINDINGS.md`) were fixed; see `docs/FIX_ROUND_T12.md` for the file list, deliberate deviations, the NEW snapshot hash and
re-audit commands. The tree hash and the 408-test figures above describe the FIRST audited snapshot only. Schema is now v5; the independent audit
is **not** passed - re-audit of the exact new snapshot is pending.
