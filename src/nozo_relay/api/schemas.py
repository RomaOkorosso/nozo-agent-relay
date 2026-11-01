"""Request DTOs (04_API_CONTRACTS). Closed enums, unknown fields -> 422, no actor/tier/role inputs.

Responses are plain dicts built by the services/view helpers (no secrets, no filesystem paths).
"""

from __future__ import annotations

import re
import uuid
from datetime import datetime
from typing import Annotated, Any, Literal

from pydantic import AfterValidator, BaseModel, ConfigDict, Field, field_validator, model_validator

from nozo_relay.domain.enums import (
    CheckStatus,
    EvidenceLevel,
    FindingSeverity,
    JobStage,
    MessageKind,
    TaskMode,
    Urgency,
    Verdict,
)


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=False)


def _canon_uuid(value: str) -> str:
    try:
        return str(uuid.UUID(value))
    except (ValueError, AttributeError, TypeError):
        raise ValueError("must be a UUID") from None


UuidStr = Annotated[str, AfterValidator(_canon_uuid)]
Hex64 = Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
Slug = Annotated[str, Field(pattern=r"^[a-z0-9-]{1,64}$")]
ClientId = Annotated[str, Field(min_length=1, max_length=128, pattern=r"^[A-Za-z0-9._:-]+$")]


def _utf8_len(value: str, limit: int, what: str) -> str:
    if len(value.encode("utf-8")) > limit:
        raise ValueError(f"{what} exceeds {limit} bytes")
    return value


_PATH_RE = re.compile(r"^[^\x00\\]+$")


def validate_path_pattern(value: str) -> str:
    if not value or len(value) > 300 or not _PATH_RE.match(value):
        raise ValueError("invalid path pattern")
    if value.startswith("/") or value.startswith("~") or re.match(r"^[A-Za-z]:", value):
        raise ValueError("paths must be relative")
    if ".." in value.split("/"):
        raise ValueError("'..' is not allowed")
    return value


PathPattern = Annotated[str, AfterValidator(validate_path_pattern)]


# ------------------------------------------------------------------ projects


class ProjectCreate(StrictModel):
    slug: Slug
    name: str = Field(min_length=1, max_length=120)


class ProjectPatch(StrictModel):
    name: str | None = Field(default=None, min_length=1, max_length=120)
    paused: bool | None = None

    @model_validator(mode="after")
    def _non_empty(self) -> ProjectPatch:
        if self.name is None and self.paused is None:
            raise ValueError("at least one field is required")
        return self


class ScopeCeiling(StrictModel):
    allowed_paths: list[PathPattern] = Field(min_length=1, max_length=100)
    max_changed_files: int = Field(ge=1, le=10_000)
    max_diff_lines: int = Field(ge=1, le=1_000_000)
    allow_new_dependencies: bool = False
    allow_autonomous: bool = False


class ProjectPolicy(StrictModel):
    """Owner-controlled project policy (hashed into every revision's policy_digest).

    * ``max_failed_reviews_cap``: failure budget; tasks may not ask for more failed reviews.
    * ``runtime_retry_limit``: technical (non-review) retry budget; ``None`` = server default.
    * ``scope_ceiling``: hard ceiling for EVERY task scope of the project (owner included).
    * ``allow_autonomous``: ``False`` forces owner dispatch for every job.
    """

    max_failed_reviews_cap: Literal[2, 3] = 3
    runtime_retry_limit: int | None = Field(default=None, ge=0, le=5)
    scope_ceiling: ScopeCeiling | None = None
    allow_autonomous: bool = True


class PolicyUpdate(StrictModel):
    policy: ProjectPolicy
    reason: str = Field(min_length=1, max_length=1000)


class DelegationRevoke(StrictModel):
    reason: str = Field(min_length=1, max_length=1000)


ApprovalKind = Literal["push", "publish", "deploy", "merge_protected", "spend", "delete_user_data", "host_security"]


class ApprovalAction(StrictModel):
    """What exactly would be approved. All of it is hashed into ``action_digest``."""

    destination: Annotated[str, Field(min_length=1, max_length=300)]
    commit_digest: Hex64 | None = None
    artifact_digest: Hex64 | None = None
    max_cost_cents: int = Field(default=0, ge=0, le=100_000_000)

    @model_validator(mode="after")
    def _object(self) -> ApprovalAction:
        if self.commit_digest is None and self.artifact_digest is None:
            raise ValueError("commit_digest or artifact_digest is required")
        return self


class ApprovalRequestCreate(StrictModel):
    kind: ApprovalKind
    summary: Annotated[str, Field(min_length=1, max_length=2000)]
    action: ApprovalAction
    task_id: UuidStr | None = None
    expires_in_seconds: int = Field(default=3600, ge=60, le=7 * 24 * 3600)


class ApprovalDecision(StrictModel):
    decision: Literal["approve", "reject"]
    action_digest: Hex64
    reason: Annotated[str, Field(max_length=1000)] = ""


class ApprovalExecute(StrictModel):
    action_digest: Hex64


class DelegationCreate(StrictModel):
    coordinator_id: UuidStr
    allowed_actions: list[Literal["task.create", "task.enqueue", "task.control"]] = Field(
        min_length=1, max_length=3
    )
    scope_ceiling: ScopeCeiling
    valid_until: datetime

    @field_validator("valid_until")
    @classmethod
    def _tz(cls, v: datetime) -> datetime:
        if v.tzinfo is None:
            raise ValueError("valid_until must include a timezone")
        return v


# ------------------------------------------------------------------ tasks


class Scope(StrictModel):
    allowed_paths: list[PathPattern] = Field(min_length=1, max_length=100)
    denied_paths: list[PathPattern] = Field(default_factory=list, max_length=100)
    max_changed_files: int = Field(ge=1, le=10_000)
    max_diff_lines: int = Field(ge=1, le=1_000_000)
    allow_new_dependencies: bool = False


Requirements = Annotated[
    str, Field(min_length=1), AfterValidator(lambda v: _utf8_len(v, 32 * 1024, "requirements"))
]
AcceptanceItem = Annotated[str, Field(min_length=1, max_length=2000)]


class TaskCreate(StrictModel):
    title: str = Field(min_length=1, max_length=200)
    requirements: Requirements
    acceptance: list[AcceptanceItem] = Field(min_length=1, max_length=30)
    implementer_id: UuidStr
    auditor_id: UuidStr
    mode: TaskMode
    autonomous: bool
    scope: Scope
    urgency: Urgency = Urgency.NORMAL
    max_failed_reviews: Literal[2, 3] = 3
    delegation_id: UuidStr | None = None


class RevisionPayload(StrictModel):
    requirements: Requirements | None = None
    acceptance: list[AcceptanceItem] | None = Field(default=None, min_length=1, max_length=30)
    scope: Scope | None = None
    mode: TaskMode | None = None
    autonomous: bool | None = None

    @model_validator(mode="after")
    def _non_empty(self) -> RevisionPayload:
        if all(getattr(self, f) is None for f in type(self).model_fields):
            raise ValueError("revision must change at least one field")
        return self


class _ControlBase(StrictModel):
    reason: str = Field(min_length=1, max_length=1000)


class PauseControl(_ControlBase):
    command: Literal["pause"]


class ResumeControl(_ControlBase):
    command: Literal["resume"]


class CancelControl(_ControlBase):
    command: Literal["cancel"]


class CompleteControl(_ControlBase):
    command: Literal["complete"]


class ReassignControl(_ControlBase):
    command: Literal["reassign"]
    implementer_id: UuidStr | None = None
    auditor_id: UuidStr | None = None

    @model_validator(mode="after")
    def _non_empty(self) -> ReassignControl:
        if self.implementer_id is None and self.auditor_id is None:
            raise ValueError("implementer_id or auditor_id is required")
        return self


class ReviseControl(_ControlBase):
    command: Literal["revise"]
    revision: RevisionPayload


ControlCreate = Annotated[
    PauseControl | ResumeControl | CancelControl | CompleteControl | ReassignControl | ReviseControl,
    Field(discriminator="command"),
]


class ProjectControlCreate(_ControlBase):
    command: Literal["pause", "resume"]


class EmergencyStop(_ControlBase):
    pass


# ------------------------------------------------------------------ messages


class MessageCreate(StrictModel):
    client_message_id: ClientId
    kind: MessageKind
    body: Annotated[str, Field(min_length=1), AfterValidator(lambda v: _utf8_len(v, 16 * 1024, "body"))]
    task_id: UuidStr | None = None
    reply_to: UuidStr | None = None


# ------------------------------------------------------------------ runs


class RunGuard(StrictModel):
    lease_epoch: int = Field(ge=1)
    revision: int = Field(ge=1)
    policy_digest: Hex64


class ClaimRequest(StrictModel):
    stage: JobStage
    claim_request_id: ClientId
    runner_instance_id: Annotated[str, Field(min_length=1, max_length=128)]
    # T12/F02: the registered supervisor (runner principal) that owns this run's process tree. Verified server-side and
    # bound immutably to the run. Omitting it is accepted ONLY when the project has exactly one active runner member.
    supervisor_principal_id: UuidStr | None = None
    capabilities_digest: Annotated[str, Field(max_length=128)] | None = None


class Check(StrictModel):
    id: Annotated[str, Field(min_length=1, max_length=64)]
    command_label: Annotated[str, Field(min_length=1, max_length=200)]
    expected: Annotated[str, Field(max_length=1000)] = ""
    observed: Annotated[str, Field(max_length=4000)] = ""
    status: CheckStatus
    evidence_artifact_ids: list[UuidStr] = Field(default_factory=list, max_length=20)
    duration_ms: int | None = Field(default=None, ge=0)
    exit_code: int | None = None
    required: bool = True


class SnapshotIn(StrictModel):
    base_commit: Annotated[str, Field(max_length=64)] | None = None
    head_commit: Annotated[str, Field(max_length=64)] | None = None
    tree_hash: Hex64
    diff_hash: Hex64
    manifest: dict[str, Any] = Field(default_factory=dict)


class ChangedFile(StrictModel):
    path: Annotated[str, AfterValidator(validate_path_pattern)]
    change: Literal["added", "modified", "deleted", "renamed"]
    binary: bool = False
    symlink: bool = False
    mode_changed: bool = False  # permission / executable-bit change
    renamed_from: Annotated[str, AfterValidator(validate_path_pattern)] | None = None


class ScopeManifest(StrictModel):
    changed_files: list[ChangedFile] = Field(default_factory=list, max_length=10_000)
    diff_lines: int = Field(ge=0, le=10_000_000)
    new_dependencies: list[Annotated[str, Field(min_length=1, max_length=200)]] = Field(
        default_factory=list, max_length=100
    )


class ImplementationResult(RunGuard):
    status: Literal["ready_for_review"]
    snapshot: SnapshotIn
    summary: Annotated[str, Field(min_length=1, max_length=4000)]
    checks: list[Check] = Field(default_factory=list, max_length=100)
    artifacts: list[UuidStr] = Field(default_factory=list, max_length=50)
    scope_manifest: ScopeManifest


class FindingIn(StrictModel):
    invariant_key: Annotated[str, Field(min_length=1, max_length=200)]
    component: Annotated[str, Field(min_length=1, max_length=200)]
    severity: FindingSeverity
    reproduction: Annotated[str, Field(min_length=1, max_length=4000)]
    expected: Annotated[str, Field(min_length=1, max_length=2000)]
    actual: Annotated[str, Field(min_length=1, max_length=2000)]
    error_class: Annotated[str, Field(max_length=64)] = ""
    evidence_artifact_ids: list[UuidStr] = Field(default_factory=list, max_length=20)


class AuditResult(RunGuard):
    snapshot_id: UuidStr
    verdict: Verdict
    summary: Annotated[str, Field(max_length=4000)] = ""
    checks: list[Check] = Field(default_factory=list, max_length=100)
    findings: list[FindingIn] = Field(default_factory=list, max_length=50)
    evidence_level: EvidenceLevel
    limitations: list[Annotated[str, Field(min_length=1, max_length=1000)]] = Field(
        default_factory=list, max_length=20
    )


class RunFail(RunGuard):
    error_code: Annotated[str, Field(min_length=1, max_length=64, pattern=r"^[a-z0-9_.-]+$")]
    retryable: bool
    evidence: Annotated[str, Field(max_length=2000)] | None = None


class StoppedReceipt(StrictModel):
    control_id: UuidStr
    target_epoch: int = Field(ge=1)
    process_tree_absent: bool
    receipt: Annotated[str, Field(max_length=2000)] = ""


class ReconcileReceipt(StrictModel):
    process_tree_absent: bool
    workspace_quarantined: bool
    receipt: Annotated[str, Field(max_length=2000)] = ""


# ------------------------------------------------------------------ agents


class AgentRegister(StrictModel):
    display_name: Annotated[str, Field(min_length=1, max_length=120)]
    kind: Literal["coordinator", "implementer", "auditor", "runner"]
    project_ids: list[UuidStr] = Field(min_length=1, max_length=50)
