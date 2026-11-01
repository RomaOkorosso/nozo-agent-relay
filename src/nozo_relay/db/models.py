"""SQLAlchemy 2 models for the M0 schema (03_DATA_MODEL.md).

Conventions: ids are UUID strings, times are epoch milliseconds (UTC), JSON is validated TEXT,
enums are closed via CHECK constraints. Project-bound relations use composite FKs
(``project_id, id``) so a job/snapshot/message/artifact cannot reference another project's task.

Deviations / additions (documented in README):
* ``principals.username`` / ``principals.password_hash`` (owner login needs a place to live).
* ``projects.repo_binding_id`` has no FK (would create a cycle with ``repo_bindings.project_id``).
* extra bookkeeping columns: ``delegations.created_at``, ``approval_requests.created_at/use_count``.
* v3 (T06): ``projects.last_claimed_at`` (round-robin), ``sessions.reauth_at`` (owner recent-auth),
  ``approval_requests.summary/action_json/revision/decided_at/decision_reason`` (bound approval record).
* v4 (T07): ``repo_bindings.created_at/registered_by/baseline_policy/approved_tree_hash/approved_at/
  quarantined_at`` (owner-configured canonical root, dirty-tree approval, quarantine bookkeeping).
"""

from __future__ import annotations

import uuid
from enum import StrEnum

from sqlalchemy import (
    DDL,
    BigInteger,
    Boolean,
    CheckConstraint,
    ForeignKey,
    ForeignKeyConstraint,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
    event,
    text,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

from nozo_relay.domain.enums import (
    ApprovalStatus,
    AuthorityTier,
    CapabilityStatus,
    BlockedReason,
    ControlCommand,
    ControlStatus,
    FindingSeverity,
    FindingStatus,
    JobStage,
    JobStatus,
    MembershipRole,
    MessageKind,
    PrincipalKind,
    ReportKind,
    RunStatus,
    TaskMode,
    TaskStatus,
    Urgency,
    Verdict,
)


class Base(DeclarativeBase):
    pass


def new_id() -> str:
    return str(uuid.uuid4())


def _in(column: str, enum_cls: type[StrEnum], *, nullable: bool = False) -> str:
    vals = ",".join(f"'{m.value}'" for m in enum_cls)
    expr = f"{column} IN ({vals})"
    return f"{column} IS NULL OR {expr}" if nullable else expr


def _enum_check(column: str, enum_cls: type[StrEnum], *, nullable: bool = False) -> CheckConstraint:
    return CheckConstraint(_in(column, enum_cls, nullable=nullable), name=f"ck_{column}_enum")


def _json_check(column: str, *, nullable: bool = False) -> CheckConstraint:
    expr = f"json_valid({column})"
    if nullable:
        expr = f"{column} IS NULL OR {expr}"
    return CheckConstraint(expr, name=f"ck_{column}_json")


Id = String(36)
Ms = BigInteger


class Principal(Base):
    __tablename__ = "principals"
    __table_args__ = (_enum_check("kind", PrincipalKind),)

    id: Mapped[str] = mapped_column(Id, primary_key=True, default=new_id)
    display_name: Mapped[str] = mapped_column(String(120))
    kind: Mapped[str] = mapped_column(String(16))
    active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[int] = mapped_column(Ms)
    # Owner login only (nullable for agents).
    username: Mapped[str | None] = mapped_column(String(64), unique=True, nullable=True)
    password_hash: Mapped[str | None] = mapped_column(Text, nullable=True)


class Credential(Base):
    __tablename__ = "credentials"

    id: Mapped[str] = mapped_column(Id, primary_key=True, default=new_id)
    principal_id: Mapped[str] = mapped_column(ForeignKey("principals.id"), index=True)
    key_prefix: Mapped[str] = mapped_column(String(32), unique=True)
    secret_digest: Mapped[str] = mapped_column(String(64))
    created_at: Mapped[int] = mapped_column(Ms)
    expires_at: Mapped[int | None] = mapped_column(Ms, nullable=True)
    revoked_at: Mapped[int | None] = mapped_column(Ms, nullable=True)
    last_used_at: Mapped[int | None] = mapped_column(Ms, nullable=True)


class SessionRow(Base):
    __tablename__ = "sessions"

    id_digest: Mapped[str] = mapped_column(String(64), primary_key=True)
    owner_id: Mapped[str] = mapped_column(ForeignKey("principals.id"), index=True)
    csrf_digest: Mapped[str] = mapped_column(String(64))
    created_at: Mapped[int] = mapped_column(Ms)
    idle_expires_at: Mapped[int] = mapped_column(Ms)
    absolute_expires_at: Mapped[int] = mapped_column(Ms)
    revoked_at: Mapped[int | None] = mapped_column(Ms, nullable=True)
    # v3: last time the owner proved the password (login or POST /auth/reauth) -> "recent-auth".
    reauth_at: Mapped[int | None] = mapped_column(Ms, nullable=True)


class Project(Base):
    __tablename__ = "projects"

    id: Mapped[str] = mapped_column(Id, primary_key=True, default=new_id)
    slug: Mapped[str] = mapped_column(String(64), unique=True)
    name: Mapped[str] = mapped_column(String(120))
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    paused: Mapped[bool] = mapped_column(Boolean, default=False)
    version: Mapped[int] = mapped_column(Integer, default=1)
    repo_binding_id: Mapped[str | None] = mapped_column(Id, nullable=True)  # no FK: see module doc
    policy_revision: Mapped[int] = mapped_column(Integer, default=1)
    policy_json: Mapped[str] = mapped_column(Text, default="{}")
    created_at: Mapped[int] = mapped_column(Ms)
    # v3: scheduling fairness across projects (round-robin within equal tier + urgency).
    last_claimed_at: Mapped[int | None] = mapped_column(Ms, nullable=True)

    __table_args__ = (_json_check("policy_json"),)


class Membership(Base):
    __tablename__ = "memberships"
    __table_args__ = (_enum_check("role", MembershipRole), _json_check("scopes_json"))

    principal_id: Mapped[str] = mapped_column(ForeignKey("principals.id"), primary_key=True)
    project_id: Mapped[str] = mapped_column(ForeignKey("projects.id"), primary_key=True)
    role: Mapped[str] = mapped_column(String(16))
    scopes_json: Mapped[str] = mapped_column(Text, default="[]")


class Delegation(Base):
    __tablename__ = "delegations"
    __table_args__ = (_json_check("allowed_actions_json"), _json_check("scope_ceiling_json"))

    id: Mapped[str] = mapped_column(Id, primary_key=True, default=new_id)
    project_id: Mapped[str] = mapped_column(ForeignKey("projects.id"), index=True)
    coordinator_id: Mapped[str] = mapped_column(ForeignKey("principals.id"))
    owner_id: Mapped[str] = mapped_column(ForeignKey("principals.id"))
    allowed_actions_json: Mapped[str] = mapped_column(Text)
    scope_ceiling_json: Mapped[str] = mapped_column(Text)
    valid_until: Mapped[int] = mapped_column(Ms)
    revoked_at: Mapped[int | None] = mapped_column(Ms, nullable=True)
    created_at: Mapped[int] = mapped_column(Ms)


class Task(Base):
    __tablename__ = "tasks"
    __table_args__ = (
        UniqueConstraint("id", "project_id", name="uq_tasks_id_project"),
        _enum_check("status", TaskStatus),
        _enum_check("effective_tier", AuthorityTier),
        _enum_check("urgency", Urgency),
        _enum_check("blocked_reason", BlockedReason, nullable=True),
        _enum_check("desired_control", ControlCommand, nullable=True),
        _enum_check("resume_stage", JobStage, nullable=True),
        CheckConstraint("max_failed_reviews IN (2,3)", name="ck_tasks_max_failed_reviews"),
        Index("ix_tasks_queue", "project_id", "status", "effective_tier", "urgency", "created_at"),
    )

    id: Mapped[str] = mapped_column(Id, primary_key=True, default=new_id)
    project_id: Mapped[str] = mapped_column(ForeignKey("projects.id"))
    title: Mapped[str] = mapped_column(String(200))
    status: Mapped[str] = mapped_column(String(24), default=TaskStatus.DRAFT.value)
    version: Mapped[int] = mapped_column(Integer, default=1)
    current_revision: Mapped[int] = mapped_column(Integer, default=1)
    origin_principal_id: Mapped[str] = mapped_column(ForeignKey("principals.id"))
    effective_tier: Mapped[str] = mapped_column(String(2))
    urgency: Mapped[str] = mapped_column(String(8), default=Urgency.NORMAL.value)
    implementer_id: Mapped[str | None] = mapped_column(ForeignKey("principals.id"), nullable=True)
    auditor_id: Mapped[str | None] = mapped_column(ForeignKey("principals.id"), nullable=True)
    failed_review_count: Mapped[int] = mapped_column(Integer, default=0)
    max_failed_reviews: Mapped[int] = mapped_column(Integer, default=3)
    blocked_reason: Mapped[str | None] = mapped_column(String(32), nullable=True)
    desired_control: Mapped[str | None] = mapped_column(String(16), nullable=True)
    resume_stage: Mapped[str | None] = mapped_column(String(16), nullable=True)
    created_at: Mapped[int] = mapped_column(Ms)
    updated_at: Mapped[int] = mapped_column(Ms)


class TaskRevision(Base):
    """Append-only (enforced by triggers)."""

    __tablename__ = "task_revisions"
    __table_args__ = (
        _json_check("requirements_json"),
        _json_check("acceptance_json"),
        _json_check("scope_json"),
        _enum_check("mode", TaskMode),
    )

    task_id: Mapped[str] = mapped_column(ForeignKey("tasks.id"), primary_key=True)
    revision: Mapped[int] = mapped_column(Integer, primary_key=True)
    requirements_json: Mapped[str] = mapped_column(Text)
    acceptance_json: Mapped[str] = mapped_column(Text)
    mode: Mapped[str] = mapped_column(String(16))
    autonomous: Mapped[bool] = mapped_column(Boolean)
    scope_json: Mapped[str] = mapped_column(Text)
    base_snapshot_id: Mapped[str | None] = mapped_column(ForeignKey("snapshots.id"), nullable=True)
    policy_digest: Mapped[str] = mapped_column(String(64))
    delegation_id: Mapped[str | None] = mapped_column(ForeignKey("delegations.id"), nullable=True)
    created_by: Mapped[str] = mapped_column(ForeignKey("principals.id"))
    created_at: Mapped[int] = mapped_column(Ms)


class Snapshot(Base):
    __tablename__ = "snapshots"
    __table_args__ = (
        UniqueConstraint("id", "project_id", name="uq_snapshots_id_project"),
        ForeignKeyConstraint(
            ["task_id", "project_id"], ["tasks.id", "tasks.project_id"], name="fk_snapshots_task_project"
        ),
        _json_check("manifest_json"),
    )

    id: Mapped[str] = mapped_column(Id, primary_key=True, default=new_id)
    project_id: Mapped[str] = mapped_column(ForeignKey("projects.id"))
    task_id: Mapped[str] = mapped_column(Id)
    revision: Mapped[int] = mapped_column(Integer)
    base_commit: Mapped[str | None] = mapped_column(String(64), nullable=True)
    head_commit: Mapped[str | None] = mapped_column(String(64), nullable=True)
    tree_hash: Mapped[str] = mapped_column(String(64))
    diff_hash: Mapped[str] = mapped_column(String(64))
    manifest_json: Mapped[str] = mapped_column(Text)
    created_by: Mapped[str] = mapped_column(ForeignKey("principals.id"))
    verified_at: Mapped[int | None] = mapped_column(Ms, nullable=True)


class Job(Base):
    __tablename__ = "jobs"
    __table_args__ = (
        UniqueConstraint("task_id", "revision", "stage", "sequence", name="uq_jobs_task_rev_stage_seq"),
        ForeignKeyConstraint(
            ["task_id", "project_id"], ["tasks.id", "tasks.project_id"], name="fk_jobs_task_project"
        ),
        ForeignKeyConstraint(
            ["task_id", "revision"],
            ["task_revisions.task_id", "task_revisions.revision"],
            name="fk_jobs_task_revision",
        ),
        ForeignKeyConstraint(
            ["input_snapshot_id", "project_id"],
            ["snapshots.id", "snapshots.project_id"],
            name="fk_jobs_input_snapshot_project",
        ),
        ForeignKeyConstraint(
            ["output_snapshot_id", "project_id"],
            ["snapshots.id", "snapshots.project_id"],
            name="fk_jobs_output_snapshot_project",
        ),
        _enum_check("stage", JobStage),
        _enum_check("status", JobStatus),
        Index("ix_jobs_ready", "project_id", "status", "ready_at", "stage", "assignee_id"),
        Index(
            "uq_jobs_one_active_per_task",
            "task_id",
            unique=True,
            sqlite_where=text("status IN ('ready','leased','running','stopping')"),
        ),
    )

    id: Mapped[str] = mapped_column(Id, primary_key=True, default=new_id)
    task_id: Mapped[str] = mapped_column(Id)
    project_id: Mapped[str] = mapped_column(Id)
    revision: Mapped[int] = mapped_column(Integer)
    stage: Mapped[str] = mapped_column(String(16))
    sequence: Mapped[int] = mapped_column(Integer)
    status: Mapped[str] = mapped_column(String(16), default=JobStatus.READY.value)
    assignee_id: Mapped[str] = mapped_column(ForeignKey("principals.id"))
    input_snapshot_id: Mapped[str | None] = mapped_column(Id, nullable=True)
    output_snapshot_id: Mapped[str | None] = mapped_column(Id, nullable=True)
    lease_epoch: Mapped[int] = mapped_column(Integer, default=0)
    dispatch_authorized: Mapped[bool] = mapped_column(Boolean, default=False)
    delivery_count: Mapped[int] = mapped_column(Integer, default=0)
    runtime_retry_count: Mapped[int] = mapped_column(Integer, default=0)
    ready_at: Mapped[int] = mapped_column(Ms)
    created_at: Mapped[int] = mapped_column(Ms)


class Run(Base):
    __tablename__ = "runs"
    __table_args__ = (
        UniqueConstraint("job_id", "lease_epoch", name="uq_runs_job_epoch"),
        _enum_check("status", RunStatus),
        Index("ix_runs_status_lease", "status", "lease_expires_at"),
        Index(
            "uq_runs_one_active_per_job",
            "job_id",
            unique=True,
            sqlite_where=text("status IN ('leased','running','stopping')"),
        ),
    )

    id: Mapped[str] = mapped_column(Id, primary_key=True, default=new_id)
    job_id: Mapped[str] = mapped_column(ForeignKey("jobs.id"))
    principal_id: Mapped[str] = mapped_column(ForeignKey("principals.id"))
    runner_instance_id: Mapped[str] = mapped_column(String(128))
    # T12/F02: immutable bind of the supervisor (runner principal) that owns this run's process tree. Set at claim,
    # never updated. Nullable only so a pre-v5 database migrates; every new claim stores it.
    supervisor_principal_id: Mapped[str | None] = mapped_column(
        ForeignKey("principals.id"), nullable=True
    )
    lease_epoch: Mapped[int] = mapped_column(Integer)
    lease_expires_at: Mapped[int] = mapped_column(Ms)
    started_at: Mapped[int | None] = mapped_column(Ms, nullable=True)
    finished_at: Mapped[int | None] = mapped_column(Ms, nullable=True)
    status: Mapped[str] = mapped_column(String(16), default=RunStatus.LEASED.value)
    heartbeat_at: Mapped[int] = mapped_column(Ms)
    control_ack_id: Mapped[str | None] = mapped_column(Id, nullable=True)
    exit_code: Mapped[int | None] = mapped_column(Integer, nullable=True)
    error_code: Mapped[str | None] = mapped_column(String(64), nullable=True)
    cli_version: Mapped[str | None] = mapped_column(String(64), nullable=True)
    policy_digest: Mapped[str] = mapped_column(String(64))


class Report(Base):
    __tablename__ = "reports"
    __table_args__ = (
        _enum_check("kind", ReportKind),
        _enum_check("verdict", Verdict, nullable=True),
        _json_check("checks_json"),
        _json_check("blockers_json"),
    )

    id: Mapped[str] = mapped_column(Id, primary_key=True, default=new_id)
    task_id: Mapped[str] = mapped_column(ForeignKey("tasks.id"), index=True)
    revision: Mapped[int] = mapped_column(Integer)
    run_id: Mapped[str] = mapped_column(ForeignKey("runs.id"), unique=True)
    snapshot_id: Mapped[str | None] = mapped_column(ForeignKey("snapshots.id"), nullable=True)
    kind: Mapped[str] = mapped_column(String(16))
    verdict: Mapped[str | None] = mapped_column(String(16), nullable=True)
    summary: Mapped[str] = mapped_column(Text)
    checks_json: Mapped[str] = mapped_column(Text)
    blockers_json: Mapped[str] = mapped_column(Text)
    evidence_level: Mapped[str] = mapped_column(String(32))
    report_hash: Mapped[str] = mapped_column(String(64))
    created_at: Mapped[int] = mapped_column(Ms)


class Finding(Base):
    __tablename__ = "findings"
    __table_args__ = (
        UniqueConstraint("report_id", "fingerprint", name="uq_findings_report_fingerprint"),
        _enum_check("severity", FindingSeverity),
        _enum_check("status", FindingStatus),
        _json_check("repro_json"),
        _json_check("evidence_json"),
        Index("ix_findings_task_fingerprint", "task_id", "fingerprint"),
    )

    id: Mapped[str] = mapped_column(Id, primary_key=True, default=new_id)
    report_id: Mapped[str] = mapped_column(ForeignKey("reports.id"))
    task_id: Mapped[str] = mapped_column(ForeignKey("tasks.id"))
    lineage_id: Mapped[str] = mapped_column(Id)
    fingerprint: Mapped[str] = mapped_column(String(64))
    severity: Mapped[str] = mapped_column(String(2))
    status: Mapped[str] = mapped_column(String(16), default=FindingStatus.OPEN.value)
    component: Mapped[str] = mapped_column(String(200))
    invariant_key: Mapped[str] = mapped_column(String(200))
    repro_json: Mapped[str] = mapped_column(Text)
    evidence_json: Mapped[str] = mapped_column(Text)


class Message(Base):
    __tablename__ = "messages"
    __table_args__ = (
        UniqueConstraint("sender_id", "client_message_id", name="uq_messages_sender_client"),
        ForeignKeyConstraint(
            ["task_id", "project_id"], ["tasks.id", "tasks.project_id"], name="fk_messages_task_project"
        ),
        _enum_check("kind", MessageKind),
        Index("ix_messages_task_created", "task_id", "created_at", "id"),
    )

    id: Mapped[str] = mapped_column(Id, primary_key=True, default=new_id)
    project_id: Mapped[str] = mapped_column(ForeignKey("projects.id"))
    task_id: Mapped[str | None] = mapped_column(Id, nullable=True)
    sender_id: Mapped[str] = mapped_column(ForeignKey("principals.id"))
    client_message_id: Mapped[str] = mapped_column(String(128))
    kind: Mapped[str] = mapped_column(String(24))
    body: Mapped[str] = mapped_column(Text)
    reply_to: Mapped[str | None] = mapped_column(ForeignKey("messages.id"), nullable=True)
    created_at: Mapped[int] = mapped_column(Ms)


class Event(Base):
    """Append-only durable event log (enforced by triggers)."""

    __tablename__ = "events"
    __table_args__ = (
        _json_check("payload_json"),
        Index("ix_events_project_seq", "project_id", "seq"),
        {"sqlite_autoincrement": True},
    )

    seq: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    event_id: Mapped[str] = mapped_column(Id, unique=True, default=new_id)
    project_id: Mapped[str | None] = mapped_column(ForeignKey("projects.id"), nullable=True)
    task_id: Mapped[str | None] = mapped_column(ForeignKey("tasks.id"), nullable=True)
    entity_version: Mapped[int | None] = mapped_column(Integer, nullable=True)
    type: Mapped[str] = mapped_column(String(64))
    actor_id: Mapped[str | None] = mapped_column(ForeignKey("principals.id"), nullable=True)
    correlation_id: Mapped[str] = mapped_column(Id)
    causation_event_id: Mapped[str | None] = mapped_column(Id, nullable=True)
    payload_json: Mapped[str] = mapped_column(Text)
    created_at: Mapped[int] = mapped_column(Ms)


class Idempotency(Base):
    __tablename__ = "idempotency"
    __table_args__ = (_json_check("response_json"),)

    principal_id: Mapped[str] = mapped_column(ForeignKey("principals.id"), primary_key=True)
    operation: Mapped[str] = mapped_column(String(128), primary_key=True)
    key: Mapped[str] = mapped_column(String(128), primary_key=True)
    request_digest: Mapped[str] = mapped_column(String(64))
    response_status: Mapped[int] = mapped_column(Integer)
    response_json: Mapped[str] = mapped_column(Text)
    created_at: Mapped[int] = mapped_column(Ms)


class Control(Base):
    __tablename__ = "controls"
    __table_args__ = (
        ForeignKeyConstraint(
            ["task_id", "project_id"], ["tasks.id", "tasks.project_id"], name="fk_controls_task_project"
        ),
        # ControlCommand also contains emergency_stop (POST /controls/emergency-stop).
        _enum_check("command", ControlCommand),
        _enum_check("status", ControlStatus),
        _json_check("payload_json"),
    )

    id: Mapped[str] = mapped_column(Id, primary_key=True, default=new_id)
    project_id: Mapped[str] = mapped_column(ForeignKey("projects.id"), index=True)
    task_id: Mapped[str | None] = mapped_column(Id, nullable=True)
    command: Mapped[str] = mapped_column(String(16))
    requested_by: Mapped[str] = mapped_column(ForeignKey("principals.id"))
    target_run_id: Mapped[str | None] = mapped_column(ForeignKey("runs.id"), nullable=True)
    target_epoch: Mapped[int | None] = mapped_column(Integer, nullable=True)
    status: Mapped[str] = mapped_column(String(16), default=ControlStatus.REQUESTED.value)
    payload_json: Mapped[str] = mapped_column(Text, default="{}")
    reason: Mapped[str] = mapped_column(Text)
    requested_at: Mapped[int] = mapped_column(Ms)
    confirmed_at: Mapped[int | None] = mapped_column(Ms, nullable=True)


class Artifact(Base):
    __tablename__ = "artifacts"
    __table_args__ = (
        ForeignKeyConstraint(
            ["task_id", "project_id"], ["tasks.id", "tasks.project_id"], name="fk_artifacts_task_project"
        ),
    )

    id: Mapped[str] = mapped_column(Id, primary_key=True, default=new_id)
    project_id: Mapped[str] = mapped_column(ForeignKey("projects.id"))
    task_id: Mapped[str | None] = mapped_column(Id, nullable=True)
    run_id: Mapped[str | None] = mapped_column(ForeignKey("runs.id"), nullable=True)
    storage_key: Mapped[str] = mapped_column(String(255), unique=True)
    sha256: Mapped[str] = mapped_column(String(64))
    size_bytes: Mapped[int] = mapped_column(Integer)
    media_type: Mapped[str] = mapped_column(String(128))
    created_at: Mapped[int] = mapped_column(Ms)


class RepoBinding(Base):
    __tablename__ = "repo_bindings"

    id: Mapped[str] = mapped_column(Id, primary_key=True, default=new_id)
    project_id: Mapped[str] = mapped_column(ForeignKey("projects.id"), unique=True)
    canonical_root: Mapped[str] = mapped_column(Text)  # admin-configured only; never from API
    repo_identity: Mapped[str] = mapped_column(String(255))
    active_lock_run: Mapped[str | None] = mapped_column(ForeignKey("runs.id"), nullable=True)
    lock_epoch: Mapped[int] = mapped_column(Integer, default=0)
    quarantine_reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    # v4 (T07): who/when registered it, baseline policy and the owner-approved dirty-tree snapshot.
    created_at: Mapped[int | None] = mapped_column(Ms, nullable=True)
    registered_by: Mapped[str | None] = mapped_column(Id, nullable=True)
    baseline_policy: Mapped[str] = mapped_column(String(24), default="clean", server_default="clean")
    approved_tree_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)
    approved_at: Mapped[int | None] = mapped_column(Ms, nullable=True)
    quarantined_at: Mapped[int | None] = mapped_column(Ms, nullable=True)


class Capability(Base):
    __tablename__ = "capabilities"
    __table_args__ = (_enum_check("status", CapabilityStatus), _json_check("details_json"))

    principal_id: Mapped[str] = mapped_column(ForeignKey("principals.id"), primary_key=True)
    capability: Mapped[str] = mapped_column(String(64), primary_key=True)
    status: Mapped[str] = mapped_column(String(24), default=CapabilityStatus.UNKNOWN.value)
    client_version: Mapped[str | None] = mapped_column(String(64), nullable=True)
    checked_at: Mapped[int | None] = mapped_column(Ms, nullable=True)
    evidence_artifact_id: Mapped[str | None] = mapped_column(ForeignKey("artifacts.id"), nullable=True)
    details_json: Mapped[str] = mapped_column(Text, default="{}")


class ApprovalRequest(Base):
    __tablename__ = "approval_requests"
    __table_args__ = (
        ForeignKeyConstraint(
            ["task_id", "project_id"],
            ["tasks.id", "tasks.project_id"],
            name="fk_approvals_task_project",
        ),
        _enum_check("status", ApprovalStatus),
        Index("ix_approvals_project_status", "project_id", "status"),
    )

    id: Mapped[str] = mapped_column(Id, primary_key=True, default=new_id)
    project_id: Mapped[str] = mapped_column(ForeignKey("projects.id"))
    task_id: Mapped[str | None] = mapped_column(Id, nullable=True)
    requested_by: Mapped[str] = mapped_column(ForeignKey("principals.id"))
    kind: Mapped[str] = mapped_column(String(64))
    action_digest: Mapped[str] = mapped_column(String(64))
    scope_digest: Mapped[str] = mapped_column(String(64))
    status: Mapped[str] = mapped_column(String(16), default=ApprovalStatus.PENDING.value)
    approved_by: Mapped[str | None] = mapped_column(ForeignKey("principals.id"), nullable=True)
    expires_at: Mapped[int] = mapped_column(Ms)
    max_uses: Mapped[int] = mapped_column(Integer, default=1)
    use_count: Mapped[int] = mapped_column(Integer, default=0)
    created_at: Mapped[int] = mapped_column(Ms)
    # v3: human-readable summary + canonical bound action (never executed by the relay).
    summary: Mapped[str] = mapped_column(Text, default="")
    action_json: Mapped[str] = mapped_column(Text, default="{}")
    revision: Mapped[int | None] = mapped_column(Integer, nullable=True)
    decided_at: Mapped[int | None] = mapped_column(Ms, nullable=True)
    decision_reason: Mapped[str | None] = mapped_column(Text, nullable=True)


class SchemaVersion(Base):
    __tablename__ = "schema_version"
    __table_args__ = (CheckConstraint("id = 1", name="ck_schema_version_singleton"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    version: Mapped[int] = mapped_column(Integer)
    applied_at: Mapped[int] = mapped_column(Ms)


# --- Append-only enforcement (application guarantee reinforced at DB level) -------------------
for _table in ("events", "task_revisions"):
    for _op in ("UPDATE", "DELETE"):
        event.listen(
            Base.metadata.tables[_table],
            "after_create",
            DDL(
                f"CREATE TRIGGER IF NOT EXISTS trg_{_table}_no_{_op.lower()} "
                f"BEFORE {_op} ON {_table} "
                f"BEGIN SELECT RAISE(ABORT, '{_table} is append-only'); END"
            ),
        )

M0_TABLES = frozenset(
    t.name for t in Base.metadata.sorted_tables if t.name != "schema_version"
)
