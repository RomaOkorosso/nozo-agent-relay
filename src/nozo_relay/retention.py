"""Retention rules (v1). Machine-readable so tests and docs cannot drift apart.

v1 policy: NOTHING is deleted automatically. History is the audit trail; disk is cheap at this scale.
Operators prune manually (and only after a verified backup). There is no HTTP delete for any of these.
"""

from __future__ import annotations

from typing import Final

RETENTION_RULES: Final[dict[str, dict[str, str]]] = {
    "events": {"rule": "keep_forever", "why": "append-only audit log; DB triggers reject UPDATE/DELETE"},
    "task_revisions": {"rule": "keep_forever", "why": "immutable policy history; DB triggers reject UPDATE/DELETE"},
    "reports": {"rule": "keep_forever", "why": "evidence behind every verdict"},
    "findings": {"rule": "keep_forever", "why": "loop detection and lineage depend on history"},
    "snapshots": {"rule": "keep_forever", "why": "audits are bound to exact snapshots"},
    "messages": {"rule": "keep_forever", "why": "task conversation record"},
    "approval_requests": {"rule": "keep_forever", "why": "record of every dangerous-action decision"},
    "delegations": {"rule": "keep_forever", "why": "revoked/expired rows prove what was delegated"},
    "artifacts": {"rule": "keep_forever", "why": "evidence; per-file 10 MiB and per-project quota instead of expiry"},
    "sessions": {"rule": "keep_until_manual_prune", "why": "expired/revoked rows are inert; small"},
    "idempotency": {"rule": "keep_until_manual_prune", "why": "pruning younger than 7 days can re-execute a retry"},
    "backups": {"rule": "operator_managed", "why": "the relay never deletes a backup; rotate by hand"},
    "projects": {"rule": "archive_only", "why": "disable (enabled=false); no cascading delete of history"},
}
