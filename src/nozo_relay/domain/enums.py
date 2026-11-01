"""Closed enums from 03_DATA_MODEL.md. Values are persisted as TEXT with CHECK constraints."""

from __future__ import annotations

from enum import StrEnum


class PrincipalKind(StrEnum):
    OWNER = "owner"
    COORDINATOR = "coordinator"
    IMPLEMENTER = "implementer"
    AUDITOR = "auditor"
    RUNNER = "runner"


class MembershipRole(StrEnum):
    OWNER = "owner"
    COORDINATOR = "coordinator"
    IMPLEMENTER = "implementer"
    AUDITOR = "auditor"
    RUNNER = "runner"


class AuthorityTier(StrEnum):
    """P0 owner, P1 coordinator within delegation, P2 implementer/auditor."""

    P0 = "P0"
    P1 = "P1"
    P2 = "P2"


class Urgency(StrEnum):
    LOW = "low"
    NORMAL = "normal"
    HIGH = "high"


class TaskStatus(StrEnum):
    DRAFT = "draft"
    QUEUED = "queued"
    CLAIMED = "claimed"
    RUNNING = "running"
    AWAITING_REVIEW = "awaiting_review"
    REVIEWING = "reviewing"
    CHANGES_REQUESTED = "changes_requested"
    STOP_REQUESTED = "stop_requested"
    PAUSED = "paused"
    BLOCKED = "blocked"
    COMPLETED = "completed"
    CANCELLED = "cancelled"


TERMINAL_TASK_STATUSES = frozenset({TaskStatus.COMPLETED, TaskStatus.CANCELLED})


class JobStatus(StrEnum):
    READY = "ready"
    LEASED = "leased"
    RUNNING = "running"
    STOPPING = "stopping"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    LOST = "lost"
    CANCELLED = "cancelled"


ACTIVE_JOB_STATUSES = frozenset(
    {JobStatus.READY, JobStatus.LEASED, JobStatus.RUNNING, JobStatus.STOPPING}
)


class RunStatus(StrEnum):
    LEASED = "leased"
    RUNNING = "running"
    STOPPING = "stopping"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    LOST = "lost"
    CANCELLED = "cancelled"


ACTIVE_RUN_STATUSES = frozenset({RunStatus.LEASED, RunStatus.RUNNING, RunStatus.STOPPING})


class JobStage(StrEnum):
    IMPLEMENT = "implement"
    AUDIT = "audit"


class TaskMode(StrEnum):
    CREATIVE = "creative"
    SURGICAL = "surgical"


class ReportKind(StrEnum):
    IMPLEMENTATION = "implementation"
    AUDIT = "audit"


class Verdict(StrEnum):
    PASS = "PASS"
    FAIL = "FAIL"
    INCONCLUSIVE = "INCONCLUSIVE"


class FindingSeverity(StrEnum):
    S0 = "S0"
    S1 = "S1"
    S2 = "S2"


class FindingStatus(StrEnum):
    OPEN = "open"
    RESOLVED = "resolved"
    ACCEPTED = "accepted"


class CheckStatus(StrEnum):
    PASS = "pass"
    FAIL = "fail"
    NOT_RUN = "not_run"
    NOT_VERIFIED = "not_verified"


class EvidenceLevel(StrEnum):
    """Evidence ladder (09_QA_CODEX). Independent capabilities, not a percentage."""

    DESIGN = "DESIGN"
    UNIT = "UNIT"
    INTEGRATION_FIXTURE = "INTEGRATION_FIXTURE"
    LOCAL_BROWSER = "LOCAL_BROWSER"
    REAL_CLI = "REAL_CLI"
    REAL_CHATGPT_WEB = "REAL_CHATGPT_WEB"
    REAL_CHATGPT_MOBILE = "REAL_CHATGPT_MOBILE"


class MessageKind(StrEnum):
    NOTE = "note"
    QUESTION = "question"
    PROGRESS = "progress"
    RESULT_REFERENCE = "result_reference"


class ControlCommand(StrEnum):
    PAUSE = "pause"
    RESUME = "resume"
    CANCEL = "cancel"
    REASSIGN = "reassign"
    REVISE = "revise"
    # Owner-only priority path (POST /controls/emergency-stop); not accepted in ControlCreate DTO.
    EMERGENCY_STOP = "emergency_stop"


class ControlStatus(StrEnum):
    REQUESTED = "requested"
    STOPPING = "stopping"
    CONFIRMED = "confirmed"
    UNKNOWN = "unknown"


class CapabilityStatus(StrEnum):
    UNKNOWN = "unknown"
    DOC_SUPPORTED = "doc_supported"
    PROBE_PASS = "probe_pass"
    PROBE_FAIL = "probe_fail"
    BLOCKED_EXTERNAL = "blocked_external"


class ApprovalStatus(StrEnum):
    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"
    EXPIRED = "expired"
    USED = "used"


class BlockedReason(StrEnum):
    ITERATION_LIMIT = "iteration_limit"
    LOOP_DETECTED = "loop_detected"
    VERIFICATION_UNAVAILABLE = "verification_unavailable"
    STOP_UNKNOWN = "stop_unknown"
    # T03 additions (06_EXECUTION_PROTOCOL): lease loss, out-of-scope output, runtime failures.
    RECOVERY_REQUIRED = "recovery_required"
    SCOPE_CHANGE_REQUIRED = "scope_change_required"
    AUTH_REQUIRED = "auth_required"
    QUOTA = "quota"
    RUNTIME_FAILURE = "runtime_failure"


def values(enum_cls: type[StrEnum]) -> tuple[str, ...]:
    return tuple(m.value for m in enum_cls)
