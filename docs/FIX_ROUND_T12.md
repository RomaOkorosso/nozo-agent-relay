# Fix round after Codex T12 (findings F01-F07)

Status: **fixes implemented, NOT re-audited.** The independent Codex audit is NOT marked PASS. This round only prepares the
exact new snapshot for re-audit (`CODEX_FINDINGS.md` stays as the record of the first failed round; round counter is Codex's).
Nothing was committed or pushed. Schema is now **v5**.

| ID | Sev | Fix | Where | Regression |
|---|---|---|---|---|
| F01 | S0 | `scope_within` proves glob inclusion (exact NFA product over the same semantics as `_glob_regex`/`path_matches`); anything not proven, non-canonical (`..`, `//`, leading `/`, `\`) or too large -> `False`. Each scope glob must be covered by one ceiling glob. Budgets/dependency checks unchanged. Applies to every caller (task create/revise, delegation, project policy). | `services/scope.py` (`glob_covers`), `services/acl.py` | `tests/test_independent_audit.py` (2), `tests/test_t12_fixes.py::test_f01_*` |
| F02 | S0 | `runs.supervisor_principal_id` (FK principals, schema v5, additive migration v2/v3/v4 -> v5). Claim verifies it is an ACTIVE runner principal with the runner membership of the project and stores it once; never updated. `confirm_stopped` / `reconcile_run` answer 404 unless `principal.id == run.supervisor_principal_id` (legacy rows with NULL can never be confirmed). Bootstrap creates `default-supervisor` (runner + membership + key under `runner` in `bootstrap_credentials.json`). | `db/models.py`, `db/schema.py`, `api/schemas.py`, `services/jobs.py`, `services/controls.py`, `bootstrap.py`, `runner/test_worker.py` (`--supervisor-principal-id`) | independent test + `test_f02_*` |
| F03 | S0 | Runner-kind principals are refused (403) on every project content route: `acl.get_project` denies runners unless the lifecycle receipt routes (`stopped`, `reconcile`) pass `allow_runner=True`; `GET /projects` refuses runners; WS auth refuses runner keys; MCP gateway refuses runner credentials. Helpers: `acl.deny_runner_content_read` (= `require_not_runner_for_content`). | `services/acl.py`, `api/runs.py`, `services/projects.py`, `ws/routes.py`, `mcp/gateway.py` | independent test + `test_f03_*` |
| F04 | S0 | seccomp now denies (EPERM) `chmod fchmod fchmodat fchmodat2 chown fchown lchown fchownat utime utimes futimesat utimensat` (x86_64) and `fchmod fchmodat fchmodat2 fchownat fchown utimensat` (aarch64; the others do not exist there). In-sandbox `cli_wrapper` no longer uses `copytree/copystat/chmod`. T07 expectation flipped: `chmod_sentinel` must now be denied. | `runner/sandbox_exec.py`, `runner/adapters/cli_wrapper.py`, `fixture_child.py`, `tests/test_t07_runner_isolation.py` | independent test + `test_f04_*` |
| F05 | S1 | `verify_backup` (hence `restore_backup`) raises `BackupError` for `complete != true`, non-empty `problems`, DB artifact rows != manifest artifacts (set + key/sha256), size/hash mismatch. `--migrate` accepts v2/v3/v4. | `backup.py` | independent test + `test_f05_*` |
| F06 | S2 | Credential is issued and COMMITTED first; the key file is written only afterwards. If writing fails the file is unlinked and the credential revoked. A failing commit never creates a file. | `keymint.py` | independent test + `test_f06_*` |
| F07 | S2 | `is_disk_full` (SQLITE_FULL / "disk is full" / ENOSPC / "no space left", through the exception chain) -> 503 `storage_full`, `retryable=true`, `Retry-After`. Handlers for SQLAlchemy `OperationalError`, raw `sqlite3.OperationalError`, and the generic fallback; MCP tool errors likewise. Idempotency-Key retry after the fault gives 201. | `api/errors.py`, `mcp/server.py` | independent test + `test_f07_*` |

## Deliberate behaviours / deviations (state them to the auditor)

* `ClaimRequest.supervisor_principal_id` is **optional in the schema** but a run ALWAYS gets one: when omitted the server uses the
  project's single active runner member; with zero or several runners the claim is refused (`422 supervisor_required`). Reason: the
  independent audit file posts raw claims without the field (`test_independent_concurrent_claim_and_cancel_fence`) and must pass unchanged.
  The test harness (`tests/api_helpers.py`) always sends it explicitly.
* The claimant (implementer/auditor) names the supervisor; the server only verifies the named principal is a legitimate runner of the
  project. A leased agent key can therefore choose among that project's runners, but can no longer pick one that is not a runner member,
  and no runner outside the binding (including one registered after the claim) can confirm or reconcile the run.
* Denying `chmod/chown/utime` applies to the WHOLE sandbox (workspace included): tools needing `shutil.copystat`, `cp -p`, `touch -t` etc.
  get EPERM. `git` itself works (T07/T08/T09 suites pass).
* Runner credentials can no longer read project data at all (previously membership gave them read access); the only runner endpoints are
  `POST /runs/{id}/stopped` and `POST /runs/{id}/reconcile`.
* `tests/test_t01_foundation.py`/`test_t02_tasks_messages.py` expectations include the new default supervisor principal + 3rd credential.

## Verification (this machine, outside nested sandboxes)

```bash
uv sync --extra mcp
uv run pytest -q tests/test_independent_audit.py     # 11 passed
uv run pytest -q tests/test_t12_fixes.py             # 51 passed
uv run pytest -q                                     # 470 passed, 4 skipped (opt-in real_cli x3, playwright not installed x1)
uv run python -m nozo_relay sandbox-probe            # verdict probe_pass
```

Not re-run in this round: Playwright browser smoke (needs `uv run --with playwright` + system Chrome), `-m real_cli`.

## New snapshot for re-audit

The tree excludes the three documents that embed it (`CODEX_AUDIT_HANDOFF.md`, `docs/PROJECT_STATUS.md`, `docs/FIX_ROUND_T12.md`):

```bash
cd "/home/roma/Desktop/Nozo Agent Relay/nozo-agent-relay"
export GIT_INDEX_FILE="$(mktemp -u)" && git add -A && git rm -q --cached CODEX_AUDIT_HANDOFF.md docs/PROJECT_STATUS.md docs/FIX_ROUND_T12.md && git write-tree; rm -f "$GIT_INDEX_FILE"; unset GIT_INDEX_FILE
git ls-files --others --exclude-standard -z | grep -zv -e '^CODEX_AUDIT_HANDOFF.md$' -e '^docs/PROJECT_STATUS.md$' -e '^docs/FIX_ROUND_T12.md$' | sort -z | xargs -0 sha256sum | sha256sum
```
Expected values: 2e95310a67c05f59c99df5d561d315606d315d87 / 18385987cab801db327074a5a44d8395ef18bd2597903a74ceafd5798185796c (compare; a difference means the tree changed after this note).

## Re-audit commands for the owner / Codex

```bash
rsync -a --exclude .venv --exclude data --exclude .git ./ /tmp/audit-copy-r2/ && cd /tmp/audit-copy-r2
uv sync --extra mcp
uv run pytest -q tests/test_independent_audit.py          # F01-F07 (must be 11 passed)
uv run pytest -q                                          # regression; run OUTSIDE nested sandboxes
uv run python -m nozo_relay sandbox-probe
# F05 operational check: uv run python -m nozo_relay backup --to X && uv run python -m nozo_relay verify-backup --from X (complete=true, problems=[])
# additional adversarial ideas: scope globs with [] / ** mixes; second runner registered mid-run; chown/utime from inside a real adapter run;
#   runner key against /api/v1/projects/*/artifacts, /events, /ws, /mcp; real ENOSPC (tmpfs) for REST/MCP mutations.
```
