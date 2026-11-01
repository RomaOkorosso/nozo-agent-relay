# Known limitations and blockers

Status vocabulary: `NOT_STARTED`, `DOC_SUPPORTED`, `PROBE_PASS`, `PROBE_FAIL`, `BLOCKED_EXTERNAL`, `NOT_VERIFIED`, `NOT_IMPLEMENTED`.
A limitation is never removed because a future fix is planned. Per-stage details: `evidence/t07/KNOWN_LIMITATIONS.md`, `evidence/t10/KNOWN_LIMITATIONS.md`, `evidence/t09/README.md`.

## A. External / host blockers (owner action required; NOT faked)

| # | Capability | Status | Reason | Evidence | Owner action |
|---|---|---|---|---|---|
| A1 | Phone UI over private HTTPS, mobile network (Q32) | **BLOCKED_EXTERNAL** | Tailscale not installed (needs sudo); no phone/tailnet | `evidence/t11/PHONE_UI.json` | Install Tailscale on laptop + phone, run README "Phone access", record results |
| A2 | Cursor CLI real edit (Q27) | **NOT_VERIFIED / blocked_external** | `cursor-agent` not logged in; no `CURSOR_API_KEY` registered; sandbox cannot resolve `api2.cursor.sh` | `evidence/t08/capability_report.json` | `cursor-agent login` (browser) or register an API key with the supervisor; egress allow-list design |
| A3 | ChatGPT web (Q30) | **NOT_VERIFIED** | Custom MCP connection needs the owner's account consent/permissions + remote HTTPS transport | `evidence/t11/CHATGPT_WEB.json` | README "ChatGPT MCP connection checklist" |
| A4 | ChatGPT mobile web / native (Q31) | **NOT_VERIFIED** | Depends on A3 and a physical device | `evidence/t11/CHATGPT_MOBILE.json` | After A3, test each surface separately |
| A5 | Sandboxed Codex production mode | blocked_external | ChatGPT login lives in the user's `CODEX_HOME` (not mounted); sandbox denies DNS/UDP so `chatgpt.com` is unreachable | `evidence/t09/capability_report.json` | Owner decision: accept host-readonly audit mode or register `CODEX_API_KEY` (per-token billing); egress path design |
| A6 | MCP Inspector CLI | not_run | Node 18.19.1; Inspector 2.x needs >= 22.19 | `evidence/t10/README.md` | Upgrade Node (owner), run documented command |
| A7 | Billing / overage for Cursor and Codex | unknown | Nothing purchased; plan limits not visible | capability reports | Owner checks plans |
| A8 | Real Codex/Cursor tests (`-m real_cli`) | skipped unless `NOZO_RUN_REAL_CLI=1` | They consume provider quota | `pyproject.toml` markers | Opt in deliberately |

## B. Not implemented (known gaps in v1)

| # | Gap | Impact |
|---|---|---|
| B1 | **No production runner daemon**: only `runner/test_worker.py` (deterministic fixture) claims jobs via REST; real Cursor/Codex adapters are exercised by tests/host probe, not by an always-on claim loop | The relay cannot yet autonomously run a real implement -> audit cycle without a harness |
| B2 | **OAuth owner-consent page** (`/oauth/consent`) missing; `/authorize` -> 404 | OAuth cannot complete with a real client; use a Bearer coordinator key (client support unverified) |
| B3 | OAuth state is in-process memory; restart revokes all grants | Fails closed; no multi-process |
| B4 | SDK CORS `*` on `/token`, `/register`, `/revoke`, discovery; no rate limit on `/register`, `/authorize` | Review before any public exposure |
| B5 | No owner UI/API to list or revoke another device's session | Sessions end via logout / idle 30 min / absolute 12 h / restore |
| B6 | Publish/push/deploy executor | By design none; `execute` -> 501; approvals have no UI |
| B7 | Artifacts/backups/events never pruned; artifact file can be orphaned if its DB commit fails | Disk growth; operator-managed |
| B8 | No offline command queue in the phone UI | By design: commands fail visibly offline |
| B9 | Alembic migrations not used; only the additive v2/v3/v4 -> v5 (`migrate`) path; dev DB recreate otherwise | |
| B10 | `mint-key` is a local CLI only; no UI for key/agent management | Owner uses curl/CLI (README) |
| B11 | Heartbeat responses not idempotency-cached; project `limits` PATCH, `repo_bindings` locks partly unused; no claim-start 30 s deadline; no owner "budget decision" resume flow | Documented in README "Known gaps" |
| B12 | MCP: stateless transport only (no server push/sampling/SSE GET/resumability); stdio does not synchronously notify the WS hub (scan <= ~1 s) | |

## C. Environment / sandbox limits (T07)

* Landlock does not mediate chmod/chown/utime on files the uid owns; **since the T12 fix round (F04) seccomp denies those syscalls (EPERM) for the whole sandbox** (so sandboxed tools also cannot chmod/utime inside the workspace; `fchmodat2`/`futimesat` included; aarch64 table untested). Re-audit pending. seccomp also denies `AF_UNIX`; UDP/DNS blocked inside the sandbox.
* Process-tree guarantee airtight only with a delegated cgroup v2; otherwise a procfs fallback that can miss a fast `setsid` double-fork (reported in the probe).
* **Nested sandboxes**: T07/T08/T09 sandbox tests are *skipped* (with an explanation) when run inside the Cursor tool sandbox (`probe_fail`: supervisor cannot stop child). Run the suite outside nested sandboxes to execute them. Skips are not passes.
* aarch64 seccomp/landlock tables untested; submodules not cloned; redaction masks known secrets/common shapes only; no PDEATHSIG (reconcile() is the recovery path); disk quota not enforced during a run.
* Host-mode Codex audit is **unsandboxed** by design (`host_probe_no_landlock`), read-only disposable copy, evidence only.

## D. Evidence-level caveats

* Real-browser evidence is **emulated Chrome 360x800**, Chromium only. WebKit/Safari/Android untested.
* Mock results are labelled `INTEGRATION_FIXTURE`; only real-CLI results may carry `REAL_CLI`.
* Cursor stream-json parsing is verified against mocks only.
* The T11 test suite and receipts make **no** claim about real mobile networks or ChatGPT.

## E. T12 fix round (F01-F07) - fixed, awaiting independent re-audit

See `docs/FIX_ROUND_T12.md`. Residual notes (not new defects, not removed limitations):

* F01: ceiling proof compares `allowed_paths` only (the ceiling has no deny list); each scope glob must be covered by ONE ceiling glob (a union of several ceiling globs is not combined). Over-restrictive in rare cases by design (fail closed).
* F02: the claimant names the supervisor (any active runner member of the project); the server cannot prove which physical process holds the runner key. No production runner daemon exists yet (B1), so the binding is exercised only by tests/test_worker. Old (pre-v5) runs have no supervisor and can never be confirmed.
* F03: tested on REST, WS and the MCP gateway; UI HTML routes are session (owner) only. Runner credentials have no read access at all.
* F04: tested with real launch_shim on x86_64; aarch64 table added but not run. Hardening still leaves xattr/ACL/`setxattr` syscalls to Landlock/uid semantics (not in scope of F04, not tested).
* F05: restore refuses incomplete backups; a backup with a missing artifact must be re-created (no partial restore mode).
* F06: crash between commit and file write leaves a valid credential without a key file (owner revokes it; no secret on disk).
* F07: classified through fault injection only; real ENOSPC on tmpfs not exercised. Outbox of the client remains the recovery path.
