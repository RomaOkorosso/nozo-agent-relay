# Command ledger

See REPORT.md for test/probe commands, results and inner exit codes. Shell wrappers that echo a failing pytest exit themselves return 0; pytest status is recorded explicitly.

- Initial rg/cat/git status/log reads: exit 0, except one combined read ending with rg of absent tests/test*surface* glob returned 2; actual files subsequently read.
- Read-only systemctl cat/show, loginctl Linger, tailscale status/version: exit 0, saved in separate files. No stop/start/restart/enable-linger executed.
- Snapshot/copy creation, HTTP/Pages/DNS read scripts, public HTTP probe: exit 0.
- uv sync --extra mcp: exit 0.
- Baseline relevant tests: exit 0, 53 passed.
- Independent shell/API tests, first 5 tests: exit 1 (4 failed,1 passed); added public WS check, final 6 tests: exit 1 (5 failed,1 passed).
- Browser tests first run: exit 1, 3 failed/1 passed; one failure was harness synchronization, corrected to await actual recovery. Final run: exit 1, 2 failed/2 passed. Expected product behavior unchanged.
- Previous Gateway regression: exit 0, 5 passed.
- Live public WS probe: exit 0 script, handshake 101 confirms FAIL of public-surface policy.
- bash -n for three scripts: exit 0.
- Version inspection, report writing, final source integrity and Relay-key-pattern scan: exit 0.
- Official Tailscale docs fetched read-only through web tool to verify proxy identity semantics.

All tests in disposable /tmp/nozo-stable-audit-ozjmwsl2/repo. No system Python changes, purchases, commits, pushes or live task/message mutations. Authenticated read-only requests may update existing credential last_used metadata. Original 260-file snapshot unchanged.
