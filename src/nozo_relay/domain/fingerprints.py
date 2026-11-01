"""Finding fingerprints, canonical hashing, policy digests and the invariant/diff loop detector.

Fingerprints are computed by the server from structured data (06_EXECUTION_PROTOCOL): never from a
model-supplied id. Line numbers, timestamps and random UUIDs are normalised away.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from typing import Any

_UUID_RE = re.compile(r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b", re.I)
_TS_RE = re.compile(r"\b\d{4}-\d{2}-\d{2}[t ]\d{2}:\d{2}(:\d{2}(\.\d+)?)?(z|[+-]\d{2}:?\d{2})?\b", re.I)
_LINE_REF_RE = re.compile(r"(:\d+(:\d+)?\b|\bline[s]?\s+\d+(\s*-\s*\d+)?\b|\bl\d+\b)", re.I)
_HEX_ADDR_RE = re.compile(r"\b0x[0-9a-f]+\b", re.I)
_WS_RE = re.compile(r"\s+")


def canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str)


def sha256_hex(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def digest_of(value: Any) -> str:
    return sha256_hex(canonical_json(value))


def normalize_reproduction(text: str) -> str:
    out = _UUID_RE.sub("<uuid>", text)
    out = _TS_RE.sub("<ts>", out)
    out = _HEX_ADDR_RE.sub("<addr>", out)
    out = _LINE_REF_RE.sub("", out)
    return _WS_RE.sub(" ", out).strip().lower()


def invariant_id(invariant_key: str, component: str) -> str:
    """Identity of a violated invariant independent of reproduction wording (used by loop rules)."""
    return sha256_hex(f"{invariant_key.strip().lower()}\x1f{component.strip().lower()}")


def finding_fingerprint(
    *,
    project_id: str,
    lineage: str,
    invariant_key: str,
    component: str,
    reproduction: str,
    error_class: str = "",
) -> str:
    """hash(project + task lineage + invariant_key + component + normalized reproduction + error class)."""
    parts = [
        project_id,
        lineage,
        invariant_key.strip().lower(),
        component.strip().lower(),
        normalize_reproduction(reproduction),
        error_class.strip().lower(),
    ]
    return sha256_hex("\x1f".join(parts))


def policy_digest(
    *,
    project_id: str,
    policy_revision: int,
    project_policy: Any,
    mode: str,
    autonomous: bool,
    scope: Any,
    requirements: str,
    acceptance: list[str],
) -> str:
    return digest_of(
        {
            "project_id": project_id,
            "policy_revision": policy_revision,
            "project_policy": project_policy,
            "mode": mode,
            "autonomous": autonomous,
            "scope": scope,
            "requirements": requirements,
            "acceptance": acceptance,
        }
    )


# ----------------------------------------------------------------------------- loop detector


@dataclass(frozen=True)
class AuditRound:
    """One accepted FAIL audit round (blocking findings only) used by the loop detector."""

    invariants: frozenset[str]  # invariant_id values of blocking (S0/S1) findings
    diff_hash: str
    tree_hash: str = ""

    @property
    def signature(self) -> str:
        return f"{self.tree_hash}:{self.diff_hash}"


@dataclass(frozen=True)
class LoopVerdict:
    rule: str
    evidence: dict[str, Any] = field(default_factory=dict)


def detect_loop(history: list[AuditRound], current: AuditRound) -> LoopVerdict | None:
    """Simple deterministic detector (no embeddings / LLM).

    ``history`` holds the previous accepted FAIL rounds (oldest first) of the current revision.
    Rules (06_EXECUTION_PROTOCOL):
      1. same blocking invariant + same diff_hash in two FAILs in a row  -> immediate loop;
      2. same blocking invariant after two fix attempts (3 consecutive FAILs) -> loop;
      3. A->B->A over the last 4 accepted snapshot signatures -> loop;
      4. any earlier, non-adjacent snapshot signature revisited (A->B->C->A) -> loop.
    """
    if history:
        prev = history[-1]
        shared = prev.invariants & current.invariants
        if shared and prev.diff_hash == current.diff_hash:
            return LoopVerdict(
                "same_invariant_same_diff",
                {"invariants": sorted(shared), "diff_hash": current.diff_hash},
            )
    if len(history) >= 2:
        shared = history[-2].invariants & history[-1].invariants & current.invariants
        if shared:
            return LoopVerdict(
                "same_invariant_after_two_fixes",
                {"invariants": sorted(shared), "rounds": 3},
            )
    window = [*history[-3:], current]
    sigs = [r.signature for r in window]
    for i in range(len(sigs) - 2):
        if sigs[i] == sigs[i + 2] and sigs[i + 1] != sigs[i]:
            return LoopVerdict("state_cycle_aba", {"signatures": sigs[i : i + 3]})
    # Longer cycle (A->B->C->A ...): the model returned to ANY earlier, non-adjacent state.
    all_sigs = [r.signature for r in history]
    for j in range(len(all_sigs) - 2, -1, -1):  # j == len-1 is the adjacent round (handled above)
        if all_sigs[j] == current.signature:
            return LoopVerdict(
                "state_cycle_revisit",
                {"signature": current.signature, "rounds_ago": len(all_sigs) - j, "signatures": all_sigs[j:] + [current.signature]},
            )
    return None
