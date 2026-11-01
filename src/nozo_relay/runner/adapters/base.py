"""Adapter protocol (07_ADAPTERS "Общий интерфейс adapter").

``probe, prepare, launch, observe, collect, cancel, reconcile`` are PYTHON methods of runner modules - not a
remote shell API, not something a model or the relay can call with a command string.

Division of labour:

* The adapter DESCRIBES a launch (``LaunchSpec``: an argv tuple, fixed env, credential env NAMES, network
  needs) and parses/validates what the child produced. It never spawns, signals or sandboxes anything.
* The supervisor owns lifecycle: sandbox, process tree, limits, heartbeat/lease, watchdog, workspace, snapshot,
  receipts. A model never decides these.

An adapter must not: change owner policy, pick a paid fallback, reset a limit, publish a result, accept
"exit code 0" as success, execute strings from task input/model output, mix control messages into arbitrary
stdout, or put secrets into the report or argv. ``collect`` therefore returns a STRICT pydantic model: unknown
fields (``role=owner``, ``shell``...) make the report invalid instead of being interpreted (Q36).
"""

from __future__ import annotations

import os
import stat
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Annotated, Any, Literal, Protocol, runtime_checkable

from pydantic import BaseModel, ConfigDict, Field

from nozo_relay.api.schemas import Check
from nozo_relay.domain.enums import CapabilityStatus

MAX_REPORT_BYTES = 256 * 1024


class StrictFrozen(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class TaskInput(StrictFrozen):
    """The validated, immutable task revision content that may reach a child. No paths, no commands."""

    title: Annotated[str, Field(min_length=1, max_length=200)]
    requirements: Annotated[str, Field(min_length=1, max_length=32 * 1024)]
    acceptance: tuple[Annotated[str, Field(min_length=1, max_length=2000)], ...] = Field(min_length=1, max_length=30)


class ReportInvalid(ValueError):
    """The child's report is missing, oversized, not a regular file, not JSON, or violates the strict schema."""

    def __init__(self, message: str, *, missing: bool = False) -> None:
        super().__init__(message)
        self.missing = missing


@dataclass(frozen=True)
class ProbeCheck:
    name: str
    status: Literal["pass", "fail", "skipped", "blocked"]
    detail: str = ""


@dataclass(frozen=True)
class AdapterProbe:
    adapter: str
    verdict: CapabilityStatus
    version: str | None
    checks: tuple[ProbeCheck, ...] = ()
    explanation: str = ""
    next_action: str | None = None


@dataclass(frozen=True)
class NetworkNeeds:
    """``none`` = no sockets at all. ``tcp_connect`` = outbound TCP to the listed ports only (no UDP/DNS/unix)."""

    mode: Literal["none", "tcp_connect"] = "none"
    ports: tuple[int, ...] = ()


@dataclass(frozen=True)
class PrepareContext:
    run_id: str
    task: TaskInput
    workspace: Path  # child: read-write
    ro_dir: Path  # child: read-only (adapter scripts, task input)
    out_dir: Path  # child: read-write; the report is read from here, untrusted
    home: Path
    tmp: Path
    interpreter: Path  # resolved python for fixture-style children
    attempt: int
    profile_digest: str


@dataclass(frozen=True)
class PreparedRun:
    adapter: str
    run_id: str
    report_path: Path
    ro_files: tuple[Path, ...] = ()


@dataclass(frozen=True)
class LaunchSpec:
    argv: tuple[str, ...]
    fixed_env: Mapping[str, str] = field(default_factory=dict)
    credential_env: tuple[str, ...] = ()  # NAMES only; values come from the CredentialsManager
    extra_ro: tuple[Path, ...] = ()
    network: NetworkNeeds = NetworkNeeds()
    stdin: bytes = b""

    def __post_init__(self) -> None:
        if isinstance(self.argv, (str, bytes)) or not self.argv or not all(isinstance(a, str) for a in self.argv):
            raise TypeError("LaunchSpec.argv must be a non-empty tuple of str (never a shell command string)")


@dataclass(frozen=True)
class Observation:
    kind: Literal["progress", "descendants", "info", "unparsed"]
    data: Mapping[str, Any] = field(default_factory=dict)


class CollectedReport(StrictFrozen):
    status: Literal["ready_for_review", "failed", "blocked"]
    summary: Annotated[str, Field(min_length=1, max_length=4000)]
    checks: tuple[Check, ...] = Field(default=(), max_length=100)
    # What the child CLAIMS it changed. A hypothesis only: the supervisor's own manifest is authoritative and a
    # mismatch quarantines the run (inconsistent manifest).
    claimed_changed_paths: tuple[Annotated[str, Field(max_length=300)], ...] | None = None
    error_code: Annotated[str, Field(min_length=1, max_length=64, pattern=r"^[a-z0-9_.-]+$")] | None = None


@dataclass(frozen=True)
class CancelPlan:
    grace_seconds: float = 10.0
    note: str = ""


@dataclass(frozen=True)
class ReconcileView:
    adapter: str
    run_id: str
    safe_to_discard: bool
    note: str = ""


@runtime_checkable
class Adapter(Protocol):
    name: str

    def probe(self) -> AdapterProbe: ...
    def prepare(self, ctx: PrepareContext) -> PreparedRun: ...
    def launch(self, prepared: PreparedRun, ctx: PrepareContext) -> LaunchSpec: ...
    def observe(self, line: str) -> Observation: ...
    def collect(self, prepared: PreparedRun) -> CollectedReport: ...
    def cancel(self, prepared: PreparedRun) -> CancelPlan: ...
    def reconcile(self, receipt: Mapping[str, Any]) -> ReconcileView: ...


def read_report_bytes(path: Path, *, max_bytes: int = MAX_REPORT_BYTES) -> bytes:
    """Read an untrusted report: regular file only, no symlinks, size-capped."""
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
    except OSError as exc:
        raise ReportInvalid(f"report not readable: {exc.strerror}", missing=isinstance(exc, FileNotFoundError)) from exc
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise ReportInvalid("report is not a regular file")
        if st.st_size > max_bytes:
            raise ReportInvalid("report exceeds the size limit")
        return os.read(fd, max_bytes + 1)
    finally:
        os.close(fd)
