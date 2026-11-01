"""Runner supervisor (T07): lifecycle, isolation, snapshots, durable receipts. Models never decide any of it.

One run = one disposable clone of the owner-registered repository, one sandboxed child, one process tree
(cgroup v2 when delegated, else /proc based), one durable receipt, at most one outbox message that carries the
result. Only ARGV LISTS are ever spawned (no ``shell=True`` anywhere); the task reaches the child as a file.

Lifecycle (06_EXECUTION_PROTOCOL)::

    start(): validate -> sandbox probe PASS? -> retry budget -> binding (quarantine? other unreconciled run?
             flock + DB lock) -> clean baseline / approved snapshot -> start_gate (server ``start``) ->
             clone + baseline copy -> adapter.prepare/launch -> receipt=launching -> spawn shim ->
             sandbox READY -> receipt=running
    monitor: heartbeat thread (independent of the child's output) + monotonic watchdog (no successful
             heartbeat for ``watchdog_window`` -> kill the tree), wall-clock deadline, stop requests
    finish : tree confirmed absent -> collect report -> OWN manifest/hashes -> scope + consistency + git/secret
             checks -> snapshot payload (outbox) or QUARANTINE -> receipt=finished -> release lock

Exit code 0 alone never means success. A run whose tree cannot be proven absent is ``stop_unknown`` and its
binding is quarantined: the supervisor never claims a stop it did not verify.

Technical retries (crash / no report / watchdog / timeout / lost) have their own bounded budget derived from the
receipts of the job; they never touch ``failed_review_count`` (a server-side review counter).
"""

from __future__ import annotations

import contextlib
import enum
import fcntl
import json
import logging
import os
import re
import signal
import subprocess
import threading
import time
import uuid
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import IO, Any

from pydantic import ValidationError

from nozo_relay.api.schemas import ChangedFile, ImplementationResult, RunFail, Scope, ScopeManifest
from nozo_relay.clock import Clock, SystemClock
from nozo_relay.domain.enums import CapabilityStatus
from nozo_relay.logsafe import redact, redact_obj
from nozo_relay.runner import snapshots
from nozo_relay.runner.adapters.base import Adapter, PrepareContext, ReportInvalid, TaskInput
from nozo_relay.runner.credentials import CredentialsManager
from nozo_relay.runner.processes import (
    CgroupSupport,
    CgroupTree,
    ProcessTree,
    ProcfsTree,
    ProcId,
    alive,
    detect_cgroup_support,
    find_by_marker,
    proc_id,
    terminate_tree,
    user_process_count,
)
from nozo_relay.runner.receipts import NON_TERMINAL, Outbox, ReceiptStore, RunAlreadyUsed, atomic_write_json
from nozo_relay.runner.sandbox import (
    LandlockBackend,
    Limits,
    RunDirs,
    SandboxBackend,
    SandboxReport,
    SandboxUnavailable,
    build_policy,
    interpreter_prefix,
    launch_shim,
    profile_digest,
)
from nozo_relay.services.repo_bindings import (
    BindingLocked,
    BindingRegistry,
    PathInPayload,
    RepoBindingError,
    reject_path_fields,
)
from nozo_relay.services.scope import scope_violations

log = logging.getLogger("nozo_relay.runner.supervisor")
_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,80}$")
_SCOPE_KINDS = frozenset({"path_not_allowed", "git_internal", "symlink", "permission_change", "binary_in_surgical",
                          "too_many_files", "diff_too_large", "new_dependency", "path_not_canonical", "rename_without_source",
                          "special_file", "path_invalid", "tree_too_large"})


class RunRejected(ValueError):
    """The request itself is invalid (bad ids, path-like payload, unknown adapter, cross-project binding)."""


class Blocked(Exception):
    def __init__(self, code: str, detail: str, *, retryable: bool = False, report: SandboxReport | None = None) -> None:
        super().__init__(f"{code}: {detail}")
        self.code, self.detail, self.retryable, self.report = code, detail, retryable, report


class HeartbeatOutcome(enum.Enum):
    OK = "ok"
    FAILED = "failed"  # transport / 5xx: does NOT extend the watchdog
    FENCED = "fenced"  # lease lost / epoch superseded -> stop
    STOP = "stop"  # owner control pending -> stop


@dataclass(frozen=True)
class SupervisorConfig:
    state_dir: Path
    heartbeat_interval: float = 15.0
    watchdog_window: float = 45.0  # monotonic watchdog (06_EXECUTION_PROTOCOL: 45 s without a successful heartbeat)
    poll_interval: float = 0.05
    stop_grace: float = 10.0
    kill_wait: float = 5.0
    max_technical_retries: int = 2
    limits: Limits = Limits()
    use_cgroup: bool | None = None  # None = auto, False = never, True = required (blocked_external if unavailable)
    max_log_bytes: int = 256 * 1024
    max_events: int = 200


@dataclass(frozen=True)
class RunRequest:
    project_id: str
    task_id: str
    job_id: str
    run_id: str
    binding_id: str
    adapter: str
    lease_epoch: int
    revision: int
    policy_digest: str
    scope: Mapping[str, Any]
    mode: str
    task: Mapping[str, Any]  # title / requirements / acceptance ONLY
    limits: Limits | None = None

    def __post_init__(self) -> None:
        for name in ("project_id", "task_id", "job_id", "run_id", "binding_id", "adapter"):
            if not _ID.match(str(getattr(self, name))):
                raise RunRejected(f"invalid {name}")
        if self.mode not in ("surgical", "creative"):
            raise RunRejected("invalid mode")
        if not re.fullmatch(r"[0-9a-f]{64}", self.policy_digest):
            raise RunRejected("invalid policy_digest")


@dataclass(frozen=True)
class RunOutcome:
    run_id: str
    outcome: str  # ready_for_review | quarantined | failed | stopped | stop_unknown | lost | timeout | watchdog_killed | blocked | not_started
    reason: str
    technical: bool = False  # counts against the bounded technical retry budget
    retryable: bool = False
    tree_absent: bool = True
    quarantined: bool = False
    violations: tuple[Mapping[str, str], ...] = ()
    snapshot: Mapping[str, Any] | None = None
    exit_code: int | None = None
    exit_signal: int | None = None
    outbox_kinds: tuple[str, ...] = ()


@dataclass(frozen=True)
class StopResult:
    confirmed: bool  # the WHOLE process tree is verifiably absent
    remaining_pids: tuple[int, ...]
    outcome: RunOutcome | None


@dataclass
class Capabilities:
    verdict: str
    explanation: str
    next_action: str | None
    sandbox: SandboxReport
    cgroup: dict[str, Any]
    tree_control: str
    limits: dict[str, str]
    adapters: dict[str, Any]
    profile_digest: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "verdict": self.verdict, "explanation": self.explanation, "next_action": self.next_action,
            "sandbox": self.sandbox.to_dict(), "cgroup": self.cgroup, "tree_control": self.tree_control,
            "limits": self.limits, "adapters": self.adapters, "profile_digest": self.profile_digest,
        }


class _UnionTree:
    """Several trees seen as one (reconciliation: cgroup + recorded pid + cmdline marker)."""

    kind = "union"

    def __init__(self, trees: list[ProcessTree]) -> None:
        self.trees = trees

    def members(self) -> set[ProcId]:
        out: set[ProcId] = set()
        for t in self.trees:
            out |= t.members()
        return out

    def signal_all(self, sig: int) -> None:
        for t in self.trees:
            t.signal_all(sig)

    def kill_all(self) -> None:
        for t in self.trees:
            t.kill_all()

    def absent(self) -> bool:
        return all(t.absent() for t in self.trees)

    def release(self) -> None:
        for t in self.trees:
            t.release()


# ============================================================================================ run handle
class RunHandle:
    def __init__(self, sup: "Supervisor", request: RunRequest) -> None:
        self._sup = sup
        self.request = request
        self.run_id = request.run_id
        self.events: list[dict[str, Any]] = []
        self._events_lock = threading.Lock()
        self._event_cv = threading.Condition(self._events_lock)
        self._done = threading.Event()
        self._wake = threading.Event()
        self._outcome: RunOutcome | None = None
        self._stop_req: dict[str, Any] | None = None
        self._stop_lock = threading.Lock()
        # filled by Supervisor._spawn
        self.proc: subprocess.Popen[bytes] | None = None
        self.tree: ProcessTree | None = None
        self.child: ProcId | None = None
        self.ctx: Any = None
        self.prepared: Any = None
        self.adapter: Adapter | None = None
        self.dirs: Path | None = None
        self.run_dir: Path | None = None
        self.baseline: dict[str, Any] = {}
        self.base_scan: snapshots.TreeScan | None = None
        self.git_fp: dict[str, str] = {}
        self.lock_fd: int | None = None
        self.epoch: int = 0
        self.heartbeat: Callable[[], HeartbeatOutcome] | None = None
        self.last_hb_ok = 0.0
        self.deadline = 0.0
        self.log_bytes = {"stdout": 0, "stderr": 0}
        self.readers: list[threading.Thread] = []

    # -- public ---------------------------------------------------------------------------
    @property
    def pid(self) -> int | None:
        return self.proc.pid if self.proc else None

    @property
    def done(self) -> bool:
        return self._done.is_set()

    @property
    def outcome(self) -> RunOutcome | None:
        return self._outcome

    def wait(self, timeout: float | None = None) -> RunOutcome | None:
        self._done.wait(timeout)
        return self._outcome

    def wait_for_event(self, kind: str, timeout: float = 10.0) -> dict[str, Any] | None:
        deadline = time.monotonic() + timeout
        with self._event_cv:
            while True:
                for e in self.events:
                    if e["kind"] == kind:
                        return e
                left = deadline - time.monotonic()
                if left <= 0 or self._done.is_set():
                    for e in self.events:
                        if e["kind"] == kind:
                            return e
                    return None
                self._event_cv.wait(min(left, 0.2))

    def stop(
        self, reason: str = "control", *, control_id: str | None = None, target_epoch: int | None = None,
        timeout: float | None = None,
    ) -> StopResult:
        """Graceful stop of the WHOLE tree; returns only after the monitor verified (or failed to verify) absence."""
        if not self._done.is_set():
            with self._stop_lock:
                if self._stop_req is None:
                    self._stop_req = {"reason": reason, "control_id": control_id, "target_epoch": target_epoch}
            self._wake.set()
        limit = timeout if timeout is not None else self._sup.cfg.stop_grace + self._sup.cfg.kill_wait + 30
        self._done.wait(limit)
        out = self._outcome
        if out is None:
            return StopResult(False, tuple(sorted(m.pid for m in self.tree.members())) if self.tree else (), None)
        remaining = () if out.tree_absent else tuple(sorted(m.pid for m in self.tree.members())) if self.tree else ()
        return StopResult(out.tree_absent, remaining, out)

    # -- internal -------------------------------------------------------------------------
    def _add_event(self, kind: str, data: Mapping[str, Any]) -> None:
        with self._event_cv:
            if len(self.events) < self._sup.cfg.max_events:
                self.events.append({"kind": kind, "data": dict(data)})
            self._event_cv.notify_all()

    def _request_stop(self, reason: str) -> None:
        with self._stop_lock:
            if self._stop_req is None:
                self._stop_req = {"reason": reason, "control_id": None, "target_epoch": None}
        self._wake.set()


# ============================================================================================ supervisor
class Supervisor:
    def __init__(
        self,
        config: SupervisorConfig,
        adapters: Mapping[str, Adapter],
        registry: BindingRegistry,
        *,
        credentials: CredentialsManager | None = None,
        sandbox: SandboxBackend | None = None,
        clock: Clock | None = None,
        monotonic: Callable[[], float] = time.monotonic,
    ) -> None:
        self.cfg = config
        self.adapters = dict(adapters)
        self.registry = registry
        self.credentials = credentials or CredentialsManager({})
        self.sandbox = sandbox or LandlockBackend()
        self.clock = clock or SystemClock()
        self.mono = monotonic
        self.root = config.state_dir
        for sub in ("", "runs", "locks", "quarantine", "capabilities"):
            (self.root / sub).mkdir(parents=True, exist_ok=True, mode=0o700)
            os.chmod(self.root / sub, 0o700)
        self.receipts = ReceiptStore(self.root, self.clock)
        self.outbox = Outbox(self.root, self.clock)
        self.instance_id = uuid.uuid4().hex
        self._me = proc_id(os.getpid())
        self._handles: dict[str, RunHandle] = {}
        self._mutex = threading.Lock()
        self._spawn_disabled = False
        self._caps: Capabilities | None = None
        self._cgroup: CgroupSupport | None = None

    # ====================================================================================== capabilities
    def probe(self, *, force: bool = False) -> Capabilities:
        if self._caps is not None and not force:
            return self._caps
        report = self.sandbox.probe(self.root / "probe")
        if self.cfg.use_cgroup is False:
            cg = CgroupSupport(False, "disabled by configuration")
        else:
            cg = detect_cgroup_support()
        self._cgroup = cg
        verdict, why, nxt = report.verdict, report.explanation, report.next_action
        if self.cfg.use_cgroup is True and not cg.available and verdict == CapabilityStatus.PROBE_PASS.value:
            verdict, why = CapabilityStatus.BLOCKED_EXTERNAL.value, f"cgroup v2 is required but unavailable: {cg.reason}"
            nxt = "Run inside a systemd user session with a delegated cgroup (cpu/memory/pids) or set use_cgroup=None."
        controllers = set(cg.controllers) if cg.available else set()
        limits = {
            "memory": "cgroup memory.max (+swap 0, oom.group)" if "memory" in controllers else "RLIMIT_AS (virtual address space, approximation)",
            "pids": "cgroup pids.max" if "pids" in controllers else "RLIMIT_NPROC = current user process count + limit (heuristic)",
            "cpu_time": "RLIMIT_CPU" + (" + cgroup cpu.max" if "cpu" in controllers else ""),
            "wall_time": "supervisor deadline (kills the tree)",
            "file_size": "RLIMIT_FSIZE", "open_files": "RLIMIT_NOFILE",
            "disk_quota": "NOT enforced (manifest limits total bytes/files after the run)",
            "tree_stop": "cgroup.kill" if cg.available else "SIGTERM/SIGKILL over pgid+session+descendant scan (can miss a setsid double-fork between polls)",
        }
        adapters = {n: _probe_to_dict(a) for n, a in self.adapters.items()}
        caps = Capabilities(verdict, why, nxt, report, cg.describe(), "cgroup" if cg.available else "procfs", limits, adapters,
                            report.profile_digest or profile_digest())
        self._caps = caps
        atomic_write_json(self.root / "capabilities" / "sandbox.json", caps.to_dict())
        return caps

    def disable_spawn(self) -> None:
        """Emergency stop switch: no new run is started until the process is restarted."""
        self._spawn_disabled = True

    # ====================================================================================== start
    def start(
        self,
        request: RunRequest,
        *,
        heartbeat: Callable[[], HeartbeatOutcome],
        start_gate: Callable[[], bool] | None = None,
    ) -> RunHandle:
        """Reserve, admit and spawn. Admission failures return a COMPLETED handle (outcome ``blocked``)."""
        try:
            reject_path_fields(request.task)
            task = TaskInput.model_validate(dict(request.task))
            scope = Scope.model_validate(dict(request.scope))
        except PathInPayload as exc:
            raise RunRejected(str(exc)) from exc
        except ValidationError as exc:
            raise RunRejected(f"invalid task/scope: {exc.error_count()} error(s)") from None
        if request.adapter not in self.adapters:
            raise RunRejected(f"unknown adapter {request.adapter!r}")
        failures = sum(1 for r in self.receipts.for_job(request.job_id) if r.get("technical_failure"))
        self.receipts.create(
            request.run_id, job_id=request.job_id, task_id=request.task_id, project_id=request.project_id,
            binding_id=request.binding_id, adapter=request.adapter, lease_epoch=request.lease_epoch,
            revision=request.revision, policy_digest=request.policy_digest, attempt=failures, technical_failure=False,
            supervisor={"instance": self.instance_id, "pid": self._me.pid if self._me else os.getpid(),
                        "start": self._me.start if self._me else 0},
        )
        handle = RunHandle(self, request)
        handle.heartbeat = heartbeat
        lock_fd: int | None = None
        lock_held = False
        try:
            if self._spawn_disabled:
                raise Blocked("spawn_disabled", "emergency stop: no new run may be spawned")
            caps = self.probe()
            if caps.verdict != CapabilityStatus.PROBE_PASS.value:
                raise Blocked("sandbox_unavailable", f"{caps.verdict}: {caps.explanation}", report=caps.sandbox)
            if failures > self.cfg.max_technical_retries:
                raise Blocked("retry_budget_exhausted",
                              f"{failures} technical failures for job {request.job_id} (limit {self.cfg.max_technical_retries} retries)")
            try:
                info = self.registry.get(request.binding_id)
            except RepoBindingError as exc:
                raise RunRejected(str(exc)) from exc
            if info.project_id != request.project_id:
                raise RunRejected("binding belongs to another project")
            if info.quarantine_reason:
                raise Blocked("binding_quarantined", info.quarantine_reason)
            busy = [r["run_id"] for r in self.receipts.for_binding(request.binding_id)
                    if r["state"] in NON_TERMINAL and r["run_id"] != request.run_id]
            if busy:
                raise Blocked("binding_busy", f"unreconciled/active run {busy[0]} holds this binding; run reconcile() first")
            lock_fd = self._flock(request.binding_id)
            if lock_fd is None:
                raise Blocked("binding_busy", "another supervisor process holds the binding lock")
            try:
                handle.epoch = self.registry.acquire_lock(request.binding_id, request.run_id)
            except BindingLocked as exc:
                raise Blocked("binding_busy", str(exc)) from exc
            lock_held = True
            handle.lock_fd = lock_fd
            try:
                kind, tree_hash, dirty = snapshots.check_baseline(
                    info.canonical_root, expected_identity=info.repo_identity, approved_tree_hash=info.approved_tree_hash)
            except snapshots.DirtyBaselineError as exc:
                raise Blocked("dirty_baseline", f"{exc} Dirty paths (first {len(exc.dirty_paths)}): {', '.join(exc.dirty_paths[:5])}") from exc
            except snapshots.IdentityMismatchError as exc:
                raise Blocked("repo_identity_mismatch", str(exc)) from exc
            except snapshots.SnapshotError as exc:
                raise Blocked("baseline_failed", str(exc)) from exc
            if start_gate is not None and not start_gate():
                raise Blocked("start_refused", "the relay refused `start`; nothing was spawned")
            self._spawn(handle, request, task, scope, info, kind, tree_hash)
        except Blocked as b:
            self._finish_blocked(handle, b, lock_held=lock_held, lock_fd=lock_fd)
            return handle
        except RunRejected as exc:
            self._finish_rejected(handle, str(exc), lock_held=lock_held, lock_fd=lock_fd)
            raise
        except BaseException:
            self._finish_blocked(handle, Blocked("internal_error", "supervisor error before spawn"), lock_held=lock_held, lock_fd=lock_fd)
            raise
        with self._mutex:
            self._handles[request.run_id] = handle
        threading.Thread(target=self._monitor, args=(handle,), name=f"nozo-run-{request.run_id}", daemon=True).start()
        threading.Thread(target=self._heartbeat_loop, args=(handle,), name=f"nozo-hb-{request.run_id}", daemon=True).start()
        return handle

    def execute(self, request: RunRequest, *, heartbeat: Callable[[], HeartbeatOutcome], start_gate: Callable[[], bool] | None = None) -> RunOutcome:
        h = self.start(request, heartbeat=heartbeat, start_gate=start_gate)
        out = h.wait()
        assert out is not None
        return out

    def stop_all(self, reason: str = "emergency_stop") -> list[StopResult]:
        self.disable_spawn()
        with self._mutex:
            handles = [h for h in self._handles.values() if not h.done]
        for h in handles:
            h._request_stop(reason)
        return [h.stop(reason) for h in handles]

    # ====================================================================================== spawn
    def _flock(self, binding_id: str) -> int | None:
        fd = os.open(self.root / "locks" / f"{binding_id}.lock", os.O_CREAT | os.O_RDWR | os.O_CLOEXEC, 0o600)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            os.close(fd)
            return None
        return fd

    def _spawn(self, h: RunHandle, req: RunRequest, task: TaskInput, scope: Scope, info: Any, baseline_kind: str, tree_hash: str) -> None:
        adapter = self.adapters[req.adapter]
        ap = adapter.probe()
        if ap.verdict != CapabilityStatus.PROBE_PASS:
            raise Blocked("adapter_unavailable", f"{ap.adapter}: {ap.verdict.value} {ap.explanation}")
        run_dir = self.root / "runs" / req.run_id
        run_dir.mkdir(mode=0o700)
        h.run_dir = run_dir
        dirs = RunDirs(workspace=run_dir / "workspace", ro=run_dir / "ro", out=run_dir / "out", home=run_dir / "home", tmp=run_dir / "tmp")
        control = run_dir / "control"  # supervisor-private: policy, logs, baseline - never in the child's allow-list
        for d in (dirs.ro, dirs.out, dirs.home, dirs.tmp, control, control / "logs"):
            d.mkdir(mode=0o700)
        try:
            base_commit = snapshots.create_workspace(info.canonical_root, dirs.workspace, baseline_kind, home=control)
            base_scan = snapshots.scan_tree(dirs.workspace)
            snapshots.copy_baseline(dirs.workspace, control / "baseline", base_scan.entries)
        except snapshots.SnapshotError as exc:
            raise Blocked("baseline_failed", f"cannot build the disposable clone: {exc}") from exc
        h.dirs, h.base_scan = dirs.workspace, base_scan
        h.git_fp = snapshots.git_fingerprint(dirs.workspace)
        ws_hash = snapshots.tree_hash(base_scan.entries)
        h.baseline = {"kind": baseline_kind, "base_commit": base_commit, "canonical_tree_hash": tree_hash,
                      "workspace_tree_hash": ws_hash, "repo_identity": info.repo_identity}
        limits = req.limits or self.cfg.limits
        exe, _prefix = interpreter_prefix()
        digest = profile_digest()
        ctx = PrepareContext(run_id=req.run_id, task=task, workspace=dirs.workspace, ro_dir=dirs.ro, out_dir=dirs.out, home=dirs.home,
                             tmp=dirs.tmp, interpreter=exe, attempt=self.receipts.get(req.run_id)["attempt"], profile_digest=digest)
        try:
            prepared = adapter.prepare(ctx)
            spec = adapter.launch(prepared, ctx)
            env = self.credentials.child_env(adapter.name, home=dirs.home, tmp=dirs.tmp, credential_env=spec.credential_env, fixed=spec.fixed_env)
        except (OSError, ValueError, TypeError) as exc:
            raise Blocked("adapter_prepare_failed", f"{type(exc).__name__}: {exc}") from exc
        h.adapter, h.ctx, h.prepared = adapter, ctx, prepared

        cg = self._cgroup or detect_cgroup_support()
        tree: ProcessTree | None = None
        cg_tree: CgroupTree | None = None
        enforced: dict[str, Any] = {}
        if cg.available:
            try:
                cg_tree = CgroupTree.create(cg, req.run_id, memory_bytes=limits.memory_bytes, pids_max=limits.pids_max,
                                            cpu_percent=limits.cpu_percent)
                enforced = dict(cg_tree.enforced)
            except OSError as exc:
                if self.cfg.use_cgroup is True:
                    raise Blocked("cgroup_required", f"cannot create a run cgroup: {exc}") from exc
                log.warning("run %s: cgroup creation failed (%s); using procfs tree control", req.run_id, type(exc).__name__)
        elif self.cfg.use_cgroup is True:
            raise Blocked("cgroup_required", cg.reason)
        policy = build_policy(
            argv=spec.argv, dirs=dirs, extra_ro=spec.extra_ro, net_mode=spec.network.mode, net_ports=spec.network.ports,
            limits=limits, cgroup_procs=cg_tree.procs_file if cg_tree else None,
            memory_via_rlimit=not (cg_tree and enforced.get("memory_max")),
            nproc_limit=None if (cg_tree and enforced.get("pids_max")) else user_process_count() + limits.pids_max,
        )
        policy_path = control / "policy.json"
        fd = os.open(policy_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC, 0o600)
        with os.fdopen(fd, "w") as fh:
            json.dump(policy, fh)
        h.deadline = self.mono() + limits.wall_seconds
        self.receipts.update(
            req.run_id, state="launching", note="before spawn", run_dir=str(run_dir), policy_path=str(policy_path),
            cgroup=str(cg_tree.path) if cg_tree else None, tree_control="cgroup" if cg_tree else "procfs",
            baseline=h.baseline, lock_epoch=h.epoch, profile_digest=digest, limits_enforced=enforced or "rlimit/procfs",
            adapter_probe=_probe_to_dict(adapter),
        )
        try:
            sh = launch_shim(policy_path, env=env, cwd=dirs.workspace, stdin=subprocess.PIPE if spec.stdin else subprocess.DEVNULL,
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        except OSError as exc:
            if cg_tree:
                cg_tree.release()
            raise Blocked("spawn_failed", f"{type(exc).__name__}: {exc}", retryable=True) from exc
        h.proc = sh.proc
        child = proc_id(sh.proc.pid)
        h.child = child
        h.tree = cg_tree if cg_tree else ProcfsTree(root=child or ProcId(sh.proc.pid, 0))
        ready, why = sh.wait_ready()
        if not ready:
            terminate_tree(h.tree, grace=0, kill_wait=3)
            with contextlib.suppress(Exception):
                sh.proc.wait(5)
            h.tree.release()
            raise Blocked("sandbox_setup_failed", why or "sandbox could not be applied; the child was NOT executed")
        if spec.stdin and sh.proc.stdin:
            with contextlib.suppress(OSError):
                sh.proc.stdin.write(spec.stdin)
                sh.proc.stdin.close()
        h.last_hb_ok = self.mono()
        self.receipts.update(
            req.run_id, state="running", note="sandbox ready", child_pid=sh.proc.pid, child_start=child.start if child else None,
            pgid=sh.proc.pid, sandbox_ready=True,
        )
        for stream_name, fh in (("stdout", sh.proc.stdout), ("stderr", sh.proc.stderr)):
            t = threading.Thread(target=self._reader, args=(h, stream_name, fh), name=f"nozo-{stream_name}-{req.run_id}", daemon=True)
            h.readers.append(t)
            t.start()

    # ====================================================================================== output handling
    def _redact(self, text: str) -> str:
        return redact(text, extra=self.credentials.secret_values(), max_len=2000)

    def _reader(self, h: RunHandle, stream: str, fh: IO[bytes] | None) -> None:
        if fh is None or h.run_dir is None:
            return
        log_path = h.run_dir / "control" / "logs" / f"{stream}.log"
        cap = self.cfg.max_log_bytes
        with open(log_path, "ab") as out:
            for raw in iter(lambda: fh.readline(65536), b""):
                line = self._redact(raw.decode("utf-8", "replace").rstrip("\r\n"))
                if h.log_bytes[stream] < cap:
                    data = (line + "\n").encode()
                    out.write(data)
                    out.flush()
                    h.log_bytes[stream] += len(data)
                    if h.log_bytes[stream] >= cap:
                        out.write(b"[log truncated]\n")
                if stream == "stdout" and h.adapter is not None:
                    try:
                        obs = h.adapter.observe(line)
                    except Exception:  # noqa: BLE001 - a parser bug must never touch the lifecycle
                        continue
                    if obs.kind != "unparsed":
                        h._add_event(obs.kind, obs.data)

    def _heartbeat_loop(self, h: RunHandle) -> None:
        assert h.heartbeat is not None
        while not h._done.wait(self.cfg.heartbeat_interval):
            try:
                res = h.heartbeat()
            except Exception:  # noqa: BLE001
                res = HeartbeatOutcome.FAILED
            if res == HeartbeatOutcome.OK:
                h.last_hb_ok = self.mono()
            elif res == HeartbeatOutcome.FENCED:
                h._request_stop("fenced")
            elif res == HeartbeatOutcome.STOP:
                h._request_stop("control")

    # ====================================================================================== monitor
    def _monitor(self, h: RunHandle) -> None:
        assert h.proc is not None and h.tree is not None
        reason: str | None = None
        stop_info: dict[str, Any] = {}
        absent = True
        remaining: list[int] = []
        last_scan = 0.0
        try:
            while True:
                if h.proc.poll() is not None:
                    break
                now = self.mono()
                with h._stop_lock:
                    req = h._stop_req
                if req is not None:
                    reason, stop_info = req["reason"], req
                elif now > h.deadline:
                    reason = "timeout"
                elif now - h.last_hb_ok > self.cfg.watchdog_window:
                    reason = "watchdog"
                if reason:
                    break
                if h.tree.kind == "procfs" and now - last_scan > 0.2:
                    h.tree.members()  # keeps the (pid,start) history for the fallback tree
                    last_scan = now
                h._wake.wait(self.cfg.poll_interval)
                h._wake.clear()
            with h._stop_lock:  # a stop that raced with a natural exit must still be honoured/reported
                if reason is None and h._stop_req is not None:
                    reason, stop_info = h._stop_req["reason"], h._stop_req
            if reason:
                self.receipts.update(h.run_id, state="stopping", note=reason)
            plan_grace = self.cfg.stop_grace
            if reason and h.adapter is not None and h.prepared is not None:
                with contextlib.suppress(Exception):
                    plan_grace = min(h.adapter.cancel(h.prepared).grace_seconds, self.cfg.stop_grace)
            if reason:
                absent, remaining = terminate_tree(h.tree, grace=plan_grace, kill_wait=self.cfg.kill_wait)
                with contextlib.suppress(Exception):
                    h.proc.wait(5)
            else:
                # the child exited on its own: nothing may outlive it (descendants would keep writing)
                leftovers = h.tree.members()
                if leftovers:
                    h._add_event("info", {"leftover_descendants": len(leftovers)})
                absent, remaining = terminate_tree(h.tree, grace=0, kill_wait=self.cfg.kill_wait)
            for t in h.readers:
                t.join(3)
            outcome = self._finalize(h, reason, stop_info, absent, remaining)
        except BaseException as exc:  # noqa: BLE001 - never leave a run without a verdict
            log.error("run %s: monitor crashed: %s", h.run_id, type(exc).__name__)
            with contextlib.suppress(Exception):
                absent, remaining = terminate_tree(h.tree, grace=0, kill_wait=self.cfg.kill_wait)
            outcome = self._finish(h, RunOutcome(h.run_id, "stop_unknown" if not absent else "failed", f"monitor_error:{type(exc).__name__}",
                                                 technical=True, tree_absent=absent), kinds=())
        h._outcome = outcome
        h._done.set()
        h._wake.set()
        with h._event_cv:
            h._event_cv.notify_all()
        with self._mutex:
            self._handles.pop(h.run_id, None)

    # ------------------------------------------------------------------------------------ finalize
    def _guard_fields(self, h: RunHandle) -> dict[str, Any]:
        r = h.request
        return {"lease_epoch": r.lease_epoch, "revision": r.revision, "policy_digest": r.policy_digest}

    def _fail_body(self, h: RunHandle, code: str, retryable: bool, evidence: str) -> dict[str, Any]:
        body = {**self._guard_fields(h), "error_code": code, "retryable": retryable, "evidence": self._redact(evidence)[:1900]}
        RunFail.model_validate(body)
        return body

    def _finalize(self, h: RunHandle, reason: str | None, stop_info: Mapping[str, Any], absent: bool, remaining: list[int]) -> RunOutcome:
        assert h.proc is not None
        rc = h.proc.returncode
        exit_signal = -rc if rc is not None and rc < 0 else None
        exit_code = rc if rc is not None and rc >= 0 else None
        base = dict(exit_code=exit_code, exit_signal=exit_signal, tree_absent=absent)
        if not absent:
            return self._finish(h, RunOutcome(h.run_id, "stop_unknown", f"process tree not confirmed absent (pids {remaining[:5]})",
                                              technical=True, quarantined=True, **base), kinds=("stopped" if stop_info.get("control_id") else "reconcile",),
                                stop_info=stop_info, quarantine=True, binding_quarantine=f"run {h.run_id}: process tree not confirmed absent")
        if reason not in (None, "timeout", "watchdog"):  # control / fenced / emergency_stop
            kinds = ("stopped",) if stop_info.get("control_id") else ()
            return self._finish(h, RunOutcome(h.run_id, "stopped", f"stopped by {reason}; process tree verified absent", **base), kinds=kinds, stop_info=stop_info)
        if reason == "watchdog":
            return self._finish(h, RunOutcome(h.run_id, "watchdog_killed", "no successful heartbeat inside the watchdog window", technical=True,
                                              retryable=True, **base), kinds=("fail",), fail=("watchdog_timeout", True), quarantine=True)
        if reason == "timeout":
            return self._finish(h, RunOutcome(h.run_id, "timeout", "wall-clock limit reached", technical=True, retryable=True, **base),
                                kinds=("fail",), fail=("job_timeout", True), quarantine=True)
        return self._finalize_exit(h, base)

    def _resource_reason(self, h: RunHandle, sig: int | None) -> str | None:
        if isinstance(h.tree, CgroupTree) and h.tree.stats().get("memory_oom_kill", 0) > 0:
            return "oom_killed"
        if sig in (int(signal.SIGXCPU),):
            return "cpu_limit"
        if sig == int(signal.SIGXFSZ):
            return "file_size_limit"
        return None

    def _finalize_exit(self, h: RunHandle, base: dict[str, Any]) -> RunOutcome:
        sig, code = base["exit_signal"], base["exit_code"]
        res = self._resource_reason(h, sig)
        if res:
            return self._finish(h, RunOutcome(h.run_id, "failed", res, technical=False, **base), kinds=("fail",), fail=("resource_limit", False),
                                fail_evidence=f"child stopped by resource limit: {res}", quarantine=True)
        assert h.adapter is not None and h.prepared is not None
        try:
            report = h.adapter.collect(h.prepared)
        except ReportInvalid as exc:
            code_ = "child_crashed" if (sig is not None or code != 0) else ("no_report" if exc.missing else "report_invalid")
            return self._finish(h, RunOutcome(h.run_id, "failed", code_, technical=True, retryable=True, **base), kinds=("fail",),
                                fail=(code_, True), fail_evidence=f"{exc}; exit_code={code} signal={sig}", quarantine=True)
        if sig is not None or code != 0:
            return self._finish(h, RunOutcome(h.run_id, "failed", "child_crashed", technical=True, retryable=True, **base), kinds=("fail",),
                                fail=("child_crashed", True), fail_evidence=f"exit_code={code} signal={sig} (a report exists but exit != 0)", quarantine=True)
        if report.status != "ready_for_review":
            code_ = report.error_code or ("agent_blocked" if report.status == "blocked" else "agent_failed")
            return self._finish(h, RunOutcome(h.run_id, "failed", f"agent reported {report.status}", technical=False, **base), kinds=("fail",),
                                fail=(code_, False), fail_evidence=report.summary, quarantine=False)
        return self._build_result(h, report, base)

    def _build_result(self, h: RunHandle, report: Any, base: dict[str, Any]) -> RunOutcome:
        assert h.dirs is not None and h.run_dir is not None and h.base_scan is not None
        scope = Scope.model_validate(dict(h.request.scope))
        after = snapshots.scan_tree(h.dirs)
        diff = snapshots.diff_trees(h.run_dir / "control" / "baseline", h.dirs, h.base_scan, after)
        problems = list(diff.problems)
        fp_after = snapshots.git_fingerprint(h.dirs)
        for key in sorted(set(fp_after) | set(h.git_fp)):
            if fp_after.get(key) != h.git_fp.get(key):
                problems.append({"kind": "git_internal", "detail": f".git/{key}"})
        valid_changed = [c for c in diff.changed_files if snapshots._valid_name(c["path"])]
        manifest_ok = True
        try:
            manifest = ScopeManifest(changed_files=[ChangedFile(**c) for c in valid_changed], diff_lines=min(diff.diff_lines, 10_000_000),
                                     new_dependencies=diff.new_dependencies)
            problems += scope_violations(scope.model_dump(), h.request.mode, manifest)
        except (ValidationError, ValueError, TypeError) as exc:
            manifest_ok = False
            problems.append({"kind": "manifest_invalid", "detail": type(exc).__name__})
        actual_paths = {c["path"] for c in diff.changed_files} | {c["renamed_from"] for c in diff.changed_files if c.get("renamed_from")}
        if report.claimed_changed_paths is not None and set(report.claimed_changed_paths) != actual_paths:
            diff_names = sorted(set(report.claimed_changed_paths) ^ actual_paths)[:5]
            problems.append({"kind": "inconsistent_manifest", "detail": f"reported vs actual differ: {', '.join(diff_names)}"})
        secret_hits = snapshots.scan_for_secrets(
            h.dirs, [c["path"] for c in diff.changed_files if c["change"] != "deleted"], self.credentials.secret_values())
        for p in secret_hits:
            problems.append({"kind": "secret_in_output", "detail": p})
        if problems:
            kinds = {p["kind"] for p in problems}
            code = ("manifest_inconsistent" if "inconsistent_manifest" in kinds or "manifest_invalid" in kinds
                    else "secret_in_output" if "secret_in_output" in kinds
                    else "scope_violation")
            summary = "; ".join(f"{p['kind']}({p['detail']})" for p in problems[:10])
            return self._finish(h, RunOutcome(h.run_id, "quarantined", f"{code}: {self._redact(summary)[:300]}", technical=False, quarantined=True,
                                              violations=tuple(problems[:50]), **base), kinds=("fail",), fail=(code, False),
                                fail_evidence=f"output quarantined, nothing applied: {summary}", quarantine=True)
        tree = snapshots.tree_hash(after.entries)
        files = [{"path": c["path"], "change": c["change"], "sha256": after.entries[c["path"]].sha256 if c["path"] in after.entries else None,
                  **({"renamed_from": c["renamed_from"]} if c.get("renamed_from") else {})} for c in diff.changed_files[:500]]
        snapshot = {
            "base_commit": h.baseline["base_commit"], "head_commit": None, "tree_hash": tree, "diff_hash": diff.diff_hash,
            "manifest": {"kind": "nozo-relay-snapshot-v1", "baseline": {k: h.baseline[k] for k in ("kind", "canonical_tree_hash", "workspace_tree_hash")},
                         "file_count": len(diff.changed_files), "diff_lines": diff.diff_lines, "files": files,
                         "truncated": len(diff.changed_files) > 500, "local_only": True},
        }
        body = redact_obj({
            **self._guard_fields(h), "status": "ready_for_review", "snapshot": snapshot, "summary": report.summary,
            "checks": [c.model_dump(mode="json") for c in report.checks], "artifacts": [],
            "scope_manifest": {"changed_files": valid_changed, "diff_lines": min(diff.diff_lines, 10_000_000), "new_dependencies": diff.new_dependencies},
        }, extra=self.credentials.secret_values())
        # structural redaction must not have damaged hashes (they are hex) - re-assert the exact digests
        body["snapshot"]["tree_hash"], body["snapshot"]["diff_hash"] = tree, diff.diff_hash
        try:
            ImplementationResult.model_validate(body)
        except ValidationError as exc:
            return self._finish(h, RunOutcome(h.run_id, "quarantined", "manifest_invalid: result does not satisfy the API schema", quarantined=True,
                                              violations=({"kind": "manifest_invalid", "detail": f"{exc.error_count()} error(s)"},), **base),
                                kinds=("fail",), fail=("manifest_inconsistent", False), fail_evidence="result failed schema validation", quarantine=True)
        return self._finish(h, RunOutcome(h.run_id, "ready_for_review", "ok", snapshot=snapshot, **base), kinds=("implementation-result",),
                            result_body=body, freeze=True)

    def _finish(
        self, h: RunHandle, out: RunOutcome, *, kinds: tuple[str, ...], fail: tuple[str, bool] | None = None, fail_evidence: str = "",
        result_body: dict[str, Any] | None = None, stop_info: Mapping[str, Any] | None = None, quarantine: bool = False,
        binding_quarantine: str | None = None, freeze: bool = False,
    ) -> RunOutcome:
        """Persist everything in crash-safe order: outbox entry, then terminal receipt, then release resources."""
        sent: list[str] = []
        quarantined_dir: str | None = None
        try:
            if "implementation-result" in kinds and result_body is not None:
                self.outbox.enqueue(h.run_id, "implementation-result", "implementation-result", result_body)
                sent.append("implementation-result")
            if "fail" in kinds and fail is not None:
                self.outbox.enqueue(h.run_id, "fail", "fail", self._fail_body(h, fail[0], fail[1], fail_evidence or out.reason))
                sent.append("fail")
            if "stopped" in kinds and stop_info is not None and stop_info.get("control_id"):
                self.outbox.enqueue(h.run_id, "stopped", "stopped", {
                    "control_id": stop_info["control_id"], "target_epoch": stop_info["target_epoch"] or h.request.lease_epoch,
                    "process_tree_absent": out.tree_absent, "receipt": self._redact(f"supervisor {self.instance_id[:8]}: {out.reason}")[:1900]})
                sent.append("stopped")
            if "reconcile" in kinds:
                self.outbox.enqueue(h.run_id, "reconcile", "reconcile", {
                    "process_tree_absent": out.tree_absent, "workspace_quarantined": True,
                    "receipt": self._redact(f"{out.outcome}: {out.reason}")[:1900]})
                sent.append("reconcile")
        finally:
            if h.tree is not None and out.tree_absent:
                with contextlib.suppress(Exception):
                    h.tree.release()
            if h.run_dir is not None:
                for sub in ("home", "tmp"):
                    with contextlib.suppress(Exception):
                        snapshots.remove_tree(h.run_dir / sub, allowed_root=self.root / "runs")
                if freeze and h.dirs is not None:
                    with contextlib.suppress(Exception):
                        snapshots.freeze_tree(h.dirs)
                if quarantine:
                    quarantined_dir = self._quarantine_dir(h.run_id, h.run_dir)
            terminal = {
                "outcome": out.outcome, "reason": self._redact(out.reason)[:500], "technical_failure": out.technical,
                "retryable": out.retryable, "tree_absent": out.tree_absent, "quarantined_dir": quarantined_dir,
                "violations": [dict(v) for v in out.violations][:50], "outbox": sent, "exit_code": out.exit_code,
                "exit_signal": out.exit_signal, "finished_at": self.clock.now_ms(),
                "snapshot": {k: out.snapshot[k] for k in ("base_commit", "tree_hash", "diff_hash")} if out.snapshot else None,
                "workspace": str(h.dirs) if (h.dirs and out.outcome == "ready_for_review") else None,
                "events_seen": len(h.events),
            }
            self.receipts.update(h.run_id, state="finished", note=out.outcome, **terminal)
            if binding_quarantine:
                with contextlib.suppress(Exception):
                    self.registry.quarantine(h.request.binding_id, binding_quarantine)
            elif h.lock_fd is not None or h.epoch:
                with contextlib.suppress(Exception):
                    self.registry.release_lock(h.request.binding_id, h.run_id)
            if h.lock_fd is not None:
                with contextlib.suppress(OSError):
                    os.close(h.lock_fd)
                h.lock_fd = None
        log.info("run %s finished: %s (%s)", h.run_id, out.outcome, self._redact(out.reason)[:120])
        return RunOutcome(**{**out.__dict__, "outbox_kinds": tuple(sent), "quarantined": out.quarantined or quarantine})

    def _quarantine_dir(self, run_id: str, run_dir: Path) -> str | None:
        dest = self.root / "quarantine" / run_id
        try:
            os.replace(run_dir, dest)
        except OSError:
            return None
        return str(dest)

    def _finish_blocked(self, h: RunHandle, b: Blocked, *, lock_held: bool, lock_fd: int | None) -> None:
        h.lock_fd = lock_fd if lock_held else None
        if lock_fd is not None and not lock_held:
            with contextlib.suppress(OSError):
                os.close(lock_fd)
        h.epoch = h.epoch if lock_held else 0
        run_dir = h.run_dir
        if run_dir is not None and run_dir.exists():
            with contextlib.suppress(Exception):
                snapshots.remove_tree(run_dir, allowed_root=self.root / "runs")
        out = RunOutcome(h.run_id, "blocked", f"{b.code}: {self._redact(b.detail)[:400]}", retryable=b.retryable, tree_absent=True)
        h.dirs = None
        h.tree = None
        out = self._finish(h, out, kinds=("fail",), fail=(b.code[:64], b.retryable), fail_evidence=b.detail)
        h._outcome = out
        h._done.set()

    def _finish_rejected(self, h: RunHandle, why: str, *, lock_held: bool, lock_fd: int | None) -> None:
        """An invalid request is an error of the CALLER: terminal receipt, lock released, nothing is reported to the relay."""
        if lock_held:
            with contextlib.suppress(Exception):
                self.registry.release_lock(h.request.binding_id, h.run_id)
        if lock_fd is not None:
            with contextlib.suppress(OSError):
                os.close(lock_fd)
        self.receipts.update(h.run_id, state="finished", note="rejected", outcome="rejected", reason=self._redact(why)[:300],
                             technical_failure=False, finished_at=self.clock.now_ms())

    # ====================================================================================== reconcile
    def reconcile(self) -> list[dict[str, Any]]:
        """After a supervisor crash/restart: find every unfinished receipt, kill+verify its tree, quarantine, report.

        A run found here is NEVER resumed: it ends as ``lost`` (or ``stop_unknown``), its output is not collected and
        no implementation result is produced for it. Run ids are single-use, so it cannot come back as a writer.
        """
        results: list[dict[str, Any]] = []
        for rec in self.receipts.non_terminal():
            run_id = rec["run_id"]
            with self._mutex:
                if run_id in self._handles:
                    results.append({"run_id": run_id, "action": "skipped", "why": "active in this supervisor"})
                    continue
            sup = rec.get("supervisor", {})
            owner = ProcId(int(sup.get("pid", 0)), int(sup.get("start", 0)))
            if sup.get("instance") != self.instance_id and owner.pid and alive(owner) and owner != self._me:
                results.append({"run_id": run_id, "action": "skipped", "why": "owned by a live supervisor process"})
                continue
            results.append(self._reconcile_one(rec))
        return results

    def _discover_tree(self, rec: dict[str, Any]) -> _UnionTree:
        trees: list[ProcessTree] = []
        cg = rec.get("cgroup")
        if cg and Path(cg).exists():
            trees.append(CgroupTree(Path(cg)))
        roots: set[ProcId] = set()
        if rec.get("child_pid") and rec.get("child_start"):
            cand = ProcId(int(rec["child_pid"]), int(rec["child_start"]))
            if alive(cand):
                roots.add(cand)
        if rec.get("run_dir"):
            roots.update(find_by_marker(rec["run_dir"]))  # spawned but the pid was never recorded (crash window)
        for r in roots:
            trees.append(ProcfsTree(root=r))
        return _UnionTree(trees)

    def _reconcile_one(self, rec: dict[str, Any]) -> dict[str, Any]:
        run_id, binding = rec["run_id"], rec["binding_id"]
        state = rec["state"]
        run_dir = Path(rec["run_dir"]) if rec.get("run_dir") else self.root / "runs" / run_id
        tree = self._discover_tree(rec) if state != "reserved" else _UnionTree([])
        survivors = len(tree.members())
        absent, remaining = terminate_tree(tree, grace=0.2, kill_wait=self.cfg.kill_wait) if survivors else (True, [])
        # one more sweep by marker: a process may have appeared between the first scan and the kill
        if absent and rec.get("run_dir") and find_by_marker(rec["run_dir"]):
            absent, remaining = terminate_tree(self._discover_tree(rec), grace=0, kill_wait=self.cfg.kill_wait)
        finished_before = self.outbox.get(run_id, "implementation-result")
        if state == "reserved":
            outcome, reason, technical = "not_started", "crash before launch; no process can exist", False
        elif not absent:
            outcome, reason, technical = "stop_unknown", f"process tree not confirmed absent after crash (pids {remaining[:5]})", True
        elif finished_before is not None:
            outcome, reason, technical = "ready_for_review", "result was already in the outbox before the crash", False
        else:
            outcome, reason, technical = "lost", f"supervisor died in state {state}; {survivors} orphan process(es) killed and verified absent", True
        quarantined_dir = None
        if outcome in ("lost", "stop_unknown") and run_dir.exists():
            quarantined_dir = self._quarantine_dir(run_id, run_dir)
        sent: list[str] = []
        if outcome in ("lost", "stop_unknown"):
            self.outbox.enqueue(run_id, "reconcile", "reconcile", {
                "process_tree_absent": absent, "workspace_quarantined": quarantined_dir is not None or not run_dir.exists(),
                "receipt": self._redact(f"{outcome}: {reason}")[:1900]})
            sent.append("reconcile")
        self.receipts.update(
            run_id, state="finished", note=f"reconciled:{outcome}", outcome=outcome, reason=reason, technical_failure=technical,
            tree_absent=absent, quarantined_dir=quarantined_dir, outbox=sent, finished_at=self.clock.now_ms(), reconciled_by=self.instance_id)
        if absent:
            with contextlib.suppress(Exception):
                self.registry.release_lock(binding, run_id)
        else:
            with contextlib.suppress(Exception):
                self.registry.quarantine(binding, f"run {run_id}: process tree not confirmed absent after supervisor crash")
        with contextlib.suppress(Exception):
            tree.release()
        log.info("reconciled run %s -> %s", run_id, outcome)
        return {"run_id": run_id, "action": "reconciled", "outcome": outcome, "survivors_killed": survivors, "tree_absent": absent}

    # ====================================================================================== housekeeping
    def deliver_outbox(self, send: Callable[[dict[str, Any]], Any]) -> dict[str, int]:
        return self.outbox.deliver_pending(send)

    def cleanup_run(self, run_id: str, *, include_quarantined: bool = False) -> bool:
        """Delete ONLY this supervisor's own disposable directory of a FINISHED run (never a quarantined one by default)."""
        rec = self.receipts.get(run_id)
        if rec is None or rec["state"] != "finished":
            raise RunRejected("only finished runs can be cleaned up")
        qd = self.root / "quarantine" / run_id
        if qd.exists():
            if not include_quarantined:
                raise RunRejected("run is quarantined; the owner must explicitly allow its deletion")
            snapshots.remove_tree(qd, allowed_root=self.root / "quarantine")
            return True
        rd = self.root / "runs" / run_id
        if rd.exists():
            snapshots.remove_tree(rd, allowed_root=self.root / "runs")
            return True
        return False

    def verify_snapshot(self, run_id: str) -> bool:
        """Recompute the tree hash of a finished run's workspace and compare it with the receipt."""
        rec = self.receipts.get(run_id)
        if not rec or not rec.get("snapshot") or not rec.get("workspace"):
            return False
        scan = snapshots.scan_tree(Path(rec["workspace"]))
        return snapshots.tree_hash(scan.entries) == rec["snapshot"]["tree_hash"]


def _probe_to_dict(adapter: Adapter) -> dict[str, Any]:
    p = adapter.probe()
    return {"adapter": p.adapter, "verdict": p.verdict.value, "version": p.version, "explanation": p.explanation,
            "checks": [{"name": c.name, "status": c.status, "detail": c.detail} for c in p.checks]}


__all__ = [
    "Blocked", "Capabilities", "HeartbeatOutcome", "RunAlreadyUsed", "RunHandle", "RunOutcome", "RunRejected", "RunRequest",
    "SandboxUnavailable", "StopResult", "Supervisor", "SupervisorConfig",
]
