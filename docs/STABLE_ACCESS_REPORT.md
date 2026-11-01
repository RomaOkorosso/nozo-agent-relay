# Stable Access report (corrected after SA audit) — 2026-11-01

Supersedes earlier optimistic wording. Independent audit: `docs/CODEX_STABLE_ACCESS_AUDIT.md` (FAIL).  
Fix round: `docs/STABLE_ACCESS_FIX_REPORT.md`.

## Architecture

| Path | Role |
|---|---|
| `https://roma-gv628rc.tailbfec94.ts.net` via **Tailscale Funnel** (public IP + SNI) | Coordinator HTTP/API only; **no WebSocket** |
| Same hostname via **Tailscale Serve** (tailnet identity headers) | Full owner/coordinator UI in tailnet |
| `http://127.0.0.1:8765` | Loopback owner/dev |
| GitHub Pages SPA | Static UI; Bearer to Relay; reads `pointer.json` |

**Offline laptop:** static Pages remain reachable; Relay API / Funnel operations do not.  
**pointer.json:** written locally by `ensure_tailscale_surface.sh`; **published Pages update requires commit/push** (not automatic recovery).

## Acceptance checks (separated routes)

| Case | Route | Expected | Result (fix round) |
|---|---|---|---|
| Local owner HTML login + Origin | loopback | 303 + cookie | PASS (tests + curl) |
| Owner login on public Host without Tailscale identity | loopback Host spoof / public | 403, no cookie | PASS (TestClient + fixture) |
| Owner login via private Serve hostname from laptop | private DNS→100.x | may 303 (tailnet) | Not a public Funnel proof |
| Coordinator `/me` + CORS github.io | public IP+SNI | 200 + ACAO | PASS |
| Auditor `/me` on Funnel | public IP+SNI | 403 | PASS |
| Auditor WebSocket on Funnel | public IP+SNI | handshake reject | PASS (`public-ws-reprobe.json` 403) |
| Idempotent message | public/local | same id | PASS |
| Watchdog Serve-only | disposable PATH stubs | calls `funnel --bg` | PASS |
| HTML health not public_ok | stubs | no public_ok | PASS |
| Funnel apply failure exit≠0 | stubs | nonzero | PASS |
| Gateway startup dead saved→pointer | Playwright mock | connects to NEW | PASS |
| Rejected message discard | Playwright | pending cleared | PASS |
| Origin:null login | API | 403 by default | PASS |

## SameSite Lax note

Session cookies use `SameSite=Lax` (not Strict) so top-level HTML form login redirects and claim-GET recovery keep the session through reverse proxies. Mutations still require CSRF + Origin allowlist. This is an intentional deviation from a Strict-only reading of design 05_SECURITY; documented here rather than treated as a silent refactor.
