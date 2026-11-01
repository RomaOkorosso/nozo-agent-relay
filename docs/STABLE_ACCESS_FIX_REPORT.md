# Stable Access fix report — SA-01…SA-08 (2026-11-01)

**Implements fixes for** `docs/CODEX_STABLE_ACCESS_AUDIT.md` (FAIL / NO-GO).  
**This document is implementer evidence, not an independent Codex PASS.**

## Commit / tree

- Target commit: *(filled after git commit)*  
- Working tree: full `src/`, `tests/`, `scripts/`, `pyproject.toml`, `uv.lock`, docs committed (secrets/`data/` gitignored).  
- Gateway Pages assets updated in same commit where applicable.

## SA-01…SA-08

| ID | Root cause | Fix | Test / evidence | Result |
|---|---|---|---|---|
| SA-01 | `BaseHTTPMiddleware` skipped WebSocket | Pure ASGI `ExternalSurfaceMiddleware` rejects public WS before accept; defense in `ws/routes.py` | `test_public_surface_denies_auditor_websocket`; live `evidence/stable-access-fix-2026-11-01/public-ws-reprobe.json` (public IP + SNI → HTTP 403) | CLOSED |
| SA-02 | Watchdog regex matched Serve-only hostname | Require `Funnel on` + optional `serve status --json` AllowFunnel | `test_watchdog_repairs_serve_only_surface` | CLOSED |
| SA-03 | `{` in HTML counted as health | Parse JSON, require `status=="live"` | `test_watchdog_does_not_accept_html_with_brace` | CLOSED |
| SA-04 | `funnel --bg \|\| true` | Apply must succeed; verify Funnel on + proxy port; no pointer write on failure | `test_surface_refresh_failure_is_not_success` | CLOSED |
| SA-05 | Startup always preferred dead `savedBase` | After failure, one retry to trusted same-origin `pointer.json` (https, no userinfo; pointer is trust root) | `test_startup_uses_current_pointer_if_saved_endpoint_dead` (+ connected-tab recovery) | CLOSED |
| SA-06 | Final 422 stuck; UI steps lied | `outcome: final\|unknown`; discard button; disconnect clears **final** only; unknown keeps idempotent retry | `test_rejected_message_can_be_cleared_by_documented_ui_steps`; drop/reload same key | CLOSED |
| SA-07 | `Origin:null` trusted via Host | Default deny; opt-in `allow_opaque_origin` only on loopback | `test_null_origin_does_not_bypass_login_origin_boundary`; unit rejects null | CLOSED |
| SA-08 | Report claimed 403 vs matrix 303; Pages/offline confusion | Corrected `STABLE_ACCESS_REPORT.md`; separated loopback/private/public; pointer publish = manual push | docs + matrix note | CLOSED |

### SameSite Lax

Cookies remain `SameSite=Lax` so HTML form login → 303 redirect keeps the session. CSRF header + Origin allowlist still guard mutations. Documented in `STABLE_ACCESS_REPORT.md`.

## Commands run (implementer)

```text
uv run pytest -q tests/test_stable_independent.py tests/test_origin_login_cookies.py tests/test_gateway_cors.py
# → 14 passed

uv run --with playwright python -m pytest -q tests/test_stable_browser_independent.py
# → 4 passed

uv run --with playwright python -m pytest -q tests/test_gateway_previous_regression.py
# → 5 passed (prior run)

# Public Funnel WS (dig @8.8.8.8 → 176.58.x.x, curl --resolve, websockets)
# me_http=403, ws=HTTP 403 InvalidStatus
```

Full suite: see `evidence/stable-access-fix-2026-11-01/full-suite.log` after run completes.

## Public vs isolated

| Check | Mode |
|---|---|
| Auditor WS deny on Funnel | **Public** IP + SNI |
| Auditor HTTP /me 403 | **Public** IP + SNI |
| Watchdog/surface shell faults | Isolated PATH stubs (live Funnel not disabled) |
| Gateway pointer/message UX | Playwright + mock transport |
| Owner public login 403 | TestClient Host=public, no identity |

## NOT_VERIFIED

- ChatGPT cloud browser end-to-end  
- Physical phone / LTE  
- Full laptop reboot; `Linger=no` until `sudo loginctl enable-linger roma`  
- Independent Codex re-audit PASS (pending)

## External check (no secrets)

1. Pages: https://romaokorosso.github.io/nozo-agent-relay/ — pointer should show Funnel host.  
2. Coordinator Bearer only in UI.  
3. Owner: https://roma-gv628rc.tailbfec94.ts.net/login from tailnet browser.  
4. Confirm WS not required for Gateway (HTTP polling).

## Codex handoff

Please re-audit commit listed above: all eight SA findings, public WS/HTTP parity, recovery scripts, Origin:null default deny, report honesty. Issue new PASS/FAIL with evidence. Do not edit product files in parallel with implementer.
