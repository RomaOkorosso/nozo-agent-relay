"""Sandbox backend (supervisor side): capability detection, active self-test, policy building, launch.

Backend choice on THIS class of host (Ubuntu >= 23.10 / KDE Neon): AppArmor restricts unprivileged user
namespaces, so ``bwrap``/``unshare`` mount-namespace sandboxes fail (``bwrap: setting up uid map``). The
backend used is therefore **Landlock + seccomp-bpf + rlimits + (optional) cgroup v2**, which need no namespaces
and no privileges. If these are unavailable the capability verdict is ``probe_fail`` / ``blocked_external`` with
a concrete explanation and **no run is started**. There is deliberately no ``unsafe``/``bypass``/``yolo``
switch anywhere in this module or in the supervisor.

Mount/secret classes (also emitted in the capability report):

* readable by the child: runtime (``/usr``, libs, ld.so/nsswitch/passwd/group/localtime/ssl certs), the
  interpreter prefix, the run's ``ro`` dir (adapter scripts + task input), ``/dev/{null,zero,urandom,random}``
* read-write: the disposable workspace clone, the run's HOME, TMP and OUT dirs (and ``/dev/null``, ``/dev/zero``)
* NOT reachable: owner DB / relay data dir / receipts / outbox / other runs, the canonical repository, the user's
  real HOME (ssh keys, gh/Cursor/Codex login caches, browser stores), ``/proc`` (other processes' environ),
  ``/sys``, ``/tmp`` and every other path; unix-domain sockets (Docker, ssh-agent, D-Bus), netlink, UDP/raw
  sockets, ptrace/mount/bpf/io_uring, signals to processes outside the sandbox (ABI >= 6)
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import os
import platform
import select
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import time
from collections.abc import Iterable
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import IO, Any, Protocol

from nozo_relay.domain.enums import CapabilityStatus
from nozo_relay.runner import sandbox_exec

SHIM = Path(sandbox_exec.__file__).resolve()
MIN_LANDLOCK_ABI = 4  # filesystem + truncate + TCP deny; signal/abstract-socket scoping needs 6 (reported)
READY_TIMEOUT = 15.0

RUNTIME_RO = (
    ("/usr", False), ("/bin", True), ("/sbin", True), ("/lib", True), ("/lib32", True), ("/lib64", True), ("/libx32", True),
    ("/etc/ld.so.cache", True), ("/etc/ld.so.conf", True), ("/etc/ld.so.conf.d", True), ("/etc/alternatives", True),
    ("/etc/localtime", True), ("/etc/nsswitch.conf", True), ("/etc/passwd", True), ("/etc/group", True),
)
TLS_RO = (("/etc/ssl/certs", True), ("/etc/ca-certificates", True), ("/usr/share/ca-certificates", True))
DEV_RW = ("/dev/null", "/dev/zero")
DEV_RO = ("/dev/urandom", "/dev/random")
PROTECTED_CLASSES = (
    "owner_db_and_relay_data_dir", "receipts_outbox_and_other_runs", "canonical_repository",
    "user_home (ssh, gh, Cursor/Codex login caches, browser stores)", "/proc", "/sys", "/tmp and every unlisted path",
    "unix-domain sockets (docker, ssh-agent, dbus)", "netlink/raw/udp sockets", "signals outside the sandbox (ABI>=6)",
)


class SandboxUnavailable(RuntimeError):
    def __init__(self, report: "SandboxReport") -> None:
        super().__init__(f"{report.verdict}: {report.explanation}")
        self.report = report


@dataclass
class SandboxReport:
    """Capability report for the sandbox (07_ADAPTERS "Форма capability report")."""

    backend: str
    verdict: str  # CapabilityStatus value: probe_pass | probe_fail | blocked_external
    explanation: str
    next_action: str | None
    checks: list[dict[str, str]] = field(default_factory=list)
    environment: dict[str, Any] = field(default_factory=dict)
    mounts: dict[str, Any] = field(default_factory=dict)
    profile_digest: str = ""

    @property
    def ok(self) -> bool:
        return self.verdict == CapabilityStatus.PROBE_PASS.value

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class Limits:
    wall_seconds: float = 30 * 60
    cpu_seconds: int = 20 * 60
    memory_bytes: int = 2 * 1024**3
    pids_max: int = 128
    cpu_percent: int | None = None
    file_size_bytes: int = 256 * 1024 * 1024
    nofile: int = 1024


def interpreter_prefix() -> tuple[Path, Path]:
    """(realpath of the interpreter used for children, directory tree it needs to read)."""
    exe = Path(os.path.realpath(getattr(sys, "_base_executable", sys.executable)))
    base = Path(os.path.realpath(sys.base_prefix))
    prefix = base if base in exe.parents else exe.parent.parent
    return exe, prefix


@dataclass(frozen=True)
class RunDirs:
    workspace: Path
    ro: Path
    out: Path
    home: Path
    tmp: Path


def build_policy(
    *,
    argv: Iterable[str],
    dirs: RunDirs,
    extra_ro: Iterable[Path],
    net_mode: str,
    net_ports: Iterable[int],
    limits: Limits,
    cgroup_procs: Path | None,
    memory_via_rlimit: bool,
    nproc_limit: int | None,
) -> dict[str, Any]:
    exe, prefix = interpreter_prefix()
    fs: list[dict[str, Any]] = [{"path": p, "access": "ro", "optional": opt} for p, opt in RUNTIME_RO]
    if net_mode == "tcp_connect":
        fs += [{"path": p, "access": "ro", "optional": opt} for p, opt in TLS_RO]
    fs += [{"path": str(prefix), "access": "ro", "optional": False}]
    fs += [{"path": p, "access": "dev", "optional": True} for p in DEV_RW]
    fs += [{"path": p, "access": "ro", "optional": True} for p in DEV_RO]
    fs += [{"path": str(dirs.ro), "access": "ro", "optional": False}]
    fs += [{"path": str(p), "access": "ro", "optional": False} for p in extra_ro]
    fs += [{"path": str(dirs.workspace), "access": "rwx", "optional": False}]
    fs += [{"path": str(p), "access": "rw", "optional": False} for p in (dirs.home, dirs.tmp, dirs.out)]
    lim: dict[str, Any] = {
        "cpu_seconds": limits.cpu_seconds, "file_size_bytes": limits.file_size_bytes, "nofile": limits.nofile,
    }
    if memory_via_rlimit:
        lim["address_space_bytes"] = limits.memory_bytes
    if nproc_limit:
        lim["nproc"] = nproc_limit
    return {
        "argv": list(argv), "cwd": str(dirs.workspace), "fs": fs,
        "net": {"mode": net_mode, "ports": sorted(set(net_ports)), "seccomp_inet": "stream" if net_mode == "tcp_connect" else "none"},
        "limits": lim, "require": {"landlock_abi_min": MIN_LANDLOCK_ABI},
        "cgroup_procs": str(cgroup_procs) if cgroup_procs else None,
    }


def profile_digest(net_mode: str = "none", limits_keys: Iterable[str] = ()) -> str:
    """Digest of the policy TEMPLATE (classes, not per-run paths): changes whenever the rules change."""
    template = {
        "version": 1, "runtime_ro": [p for p, _ in RUNTIME_RO], "tls_ro": [p for p, _ in TLS_RO] if net_mode == "tcp_connect" else [],
        "dev_rw": DEV_RW, "dev_ro": DEV_RO, "min_abi": MIN_LANDLOCK_ABI, "net_mode": net_mode,
        "seccomp_denied": sorted(sandbox_exec._SYSCALLS.get(platform.machine(), {})), "limits": sorted(limits_keys),
    }
    return hashlib.sha256(json.dumps(template, sort_keys=True).encode()).hexdigest()


# ------------------------------------------------------------------------------------------- launching
class ShimLaunch:
    def __init__(self, proc: subprocess.Popen[bytes], status_fd: int) -> None:
        self.proc = proc
        self._fd = status_fd
        self._buf = b""

    def wait_ready(self, timeout: float = READY_TIMEOUT) -> tuple[bool, str]:
        """(ready, reason). Ready iff the pipe delivered exactly ``R`` and then EOF (exec happened)."""
        deadline = time.monotonic() + timeout
        try:
            while True:
                left = deadline - time.monotonic()
                if left <= 0:
                    return False, "sandbox shim did not become ready in time"
                r, _, _ = select.select([self._fd], [], [], min(left, 0.25))
                if not r:
                    if self.proc.poll() is not None and not self._buf:
                        pass  # EOF will follow on the next select
                    continue
                chunk = os.read(self._fd, 4096)
                if not chunk:
                    break
                self._buf += chunk
        finally:
            with contextlib.suppress(OSError):
                os.close(self._fd)
        if self._buf == b"R":
            return True, ""
        text = self._buf.decode(errors="replace")
        with contextlib.suppress(ValueError):
            text = json.loads(text.lstrip("R")).get("sandbox_setup_failed", text)
        return False, text or f"shim exited ({self.proc.poll()}) before applying the sandbox"


def launch_shim(
    policy_path: Path, *, env: dict[str, str], cwd: Path, stdin: int | IO[bytes] | None, stdout: int | IO[bytes],
    stderr: int | IO[bytes],
) -> ShimLaunch:
    """Spawn ``python -I sandbox_exec.py policy status_fd env_fd``: argv list, no shell, near-empty environment.

    The child's environment is handed over through a pipe so that secrets never touch the disk or the shim's argv/env.
    """
    payload = json.dumps(env).encode()
    if len(payload) > 48 * 1024:
        raise ValueError("child environment too large")
    r, w = os.pipe()
    er, ew = os.pipe()
    try:
        os.write(ew, payload)
        os.close(ew)
        proc = subprocess.Popen(  # noqa: S603
            [sys.executable, "-I", str(SHIM), str(policy_path), str(w), str(er)],
            cwd=cwd, env={"PATH": "/usr/bin:/bin"}, stdin=stdin, stdout=stdout, stderr=stderr,
            pass_fds=(w, er), close_fds=True, start_new_session=True, shell=False,
        )
    except BaseException:
        os.close(r)
        raise
    finally:
        os.close(w)
        os.close(er)
    return ShimLaunch(proc, r)


# ------------------------------------------------------------------------------------------- backends
class SandboxBackend(Protocol):
    name: str

    def probe(self, scratch: Path) -> SandboxReport: ...


def _environment() -> dict[str, Any]:
    env: dict[str, Any] = {
        "kernel": platform.release(), "machine": platform.machine(), "python": platform.python_version(),
        "landlock_abi": sandbox_exec.landlock_abi(), "seccomp": sandbox_exec.seccomp_supported(),
        "bwrap": shutil.which("bwrap"),
    }
    with contextlib.suppress(OSError):
        env["lsm"] = Path("/sys/kernel/security/lsm").read_text().strip()
    with contextlib.suppress(OSError):
        env["apparmor_restrict_unprivileged_userns"] = Path("/proc/sys/kernel/apparmor_restrict_unprivileged_userns").read_text().strip()
    with contextlib.suppress(OSError):
        env["unprivileged_userns_clone"] = Path("/proc/sys/kernel/unprivileged_userns_clone").read_text().strip()
    return env


def mounts_description() -> dict[str, Any]:
    exe, prefix = interpreter_prefix()
    return {
        "readable": {
            "runtime": [p for p, _ in RUNTIME_RO], "interpreter_prefix": str(prefix), "adapter_ro": "<run>/ro",
            "devices": list(DEV_RW + DEV_RO),
        },
        "read_write": {"workspace_clone": "<run>/workspace", "home": "<run>/home", "tmp": "<run>/tmp", "out": "<run>/out",
                       "devices": list(DEV_RW)},
        "not_reachable": list(PROTECTED_CLASSES),
        "secret_classes": {
            "owner_relay_secrets": "never in child env/argv/mounts", "supervisor_relay_keys": "never",
            "publish_credentials": "never", "provider_credentials": "only the declared env name, only for that adapter",
        },
    }


_SELFTEST = r'''
import json, os, socket, subprocess, sys
t = json.load(open(sys.argv[1]))
R = {}
def a(name, fn):
    try:
        fn(); R[name] = "ok"
    except BaseException as e:
        R[name] = type(e).__name__
a("ws_write", lambda: open(os.path.join(t["ws"], "w.txt"), "w").write("x"))
a("ws_read", lambda: open(os.path.join(t["ws"], "w.txt")).read())
a("ro_read", lambda: open(os.path.join(t["ro"], "selftest.py")).read())
a("sh_exec", lambda: subprocess.run(["/bin/sh", "-c", "exit 0"], check=True))
a("read_sentinel", lambda: open(t["sentinel"]).read())
a("write_outside", lambda: open(os.path.join(t["outside"], "pwn"), "w").write("x"))
a("symlink_read_through", lambda: (os.symlink(t["outside"], os.path.join(t["ws"], "ln")), open(os.path.join(t["ws"], "ln", "sentinel")).read()))
a("sh_cat_sentinel", lambda: subprocess.run(["/bin/sh", "-c", "cat " + t["sentinel"]], check=True, capture_output=True))
a("proc_environ", lambda: open("/proc/%d/environ" % os.getppid(), "rb").read())
a("tcp_connect", lambda: socket.create_connection(("127.0.0.1", t["tcp_port"]), timeout=2))
a("unix_connect", lambda: socket.socket(socket.AF_UNIX, socket.SOCK_STREAM).connect(t["unix"]))
a("udp_socket", lambda: socket.socket(socket.AF_INET, socket.SOCK_DGRAM))
a("signal_outside", lambda: os.kill(t["supervisor_pid"], 0))
print(json.dumps(R))
'''
_MUST_SUCCEED = ("ws_write", "ws_read", "ro_read", "sh_exec")
_MUST_FAIL = ("read_sentinel", "write_outside", "symlink_read_through", "sh_cat_sentinel", "proc_environ", "tcp_connect",
              "unix_connect", "udp_socket")


class LandlockBackend:
    """Landlock + seccomp + rlimits (+cgroup). See module doc."""

    name = "landlock+seccomp"

    def __init__(self, *, min_abi: int = MIN_LANDLOCK_ABI) -> None:
        self.min_abi = min_abi

    def probe(self, scratch: Path) -> SandboxReport:
        env = _environment()
        mounts = mounts_description()
        digest = profile_digest()

        def report(verdict: CapabilityStatus, why: str, nxt: str | None, checks: list[dict[str, str]]) -> SandboxReport:
            return SandboxReport(self.name, verdict.value, why, nxt, checks, env, mounts, digest)

        if sys.platform != "linux":
            return report(CapabilityStatus.BLOCKED_EXTERNAL, f"{sys.platform} is not Linux; no OS sandbox backend exists", None, [])
        abi = env["landlock_abi"]
        if abi == 0:
            return report(
                CapabilityStatus.BLOCKED_EXTERNAL,
                "Landlock is not available (not in the active LSM list, disabled at boot, kernel < 5.13, or its syscalls "
                f"are blocked by a container/seccomp policy). lsm={env.get('lsm')!r}. User namespaces are "
                f"{'restricted by AppArmor' if env.get('apparmor_restrict_unprivileged_userns') == '1' else 'not usable'}, "
                "so bubblewrap cannot replace it. Refusing to run children unconfined.",
                "Boot a kernel with Landlock enabled (lsm=...,landlock), or run the supervisor inside a VM/container that "
                "provides it. There is no bypass.",
                [{"name": "landlock_abi", "status": "blocked", "detail": "0"}],
            )
        if abi < self.min_abi:
            return report(
                CapabilityStatus.PROBE_FAIL,
                f"Landlock ABI {abi} < {self.min_abi}: TCP connect/bind cannot be denied, so unauthorised network egress "
                "cannot be ruled out.",
                "Upgrade to a kernel with Landlock ABI >= 4 (Linux 6.7+).",
                [{"name": "landlock_abi", "status": "fail", "detail": str(abi)}],
            )
        if not env["seccomp"]:
            return report(
                CapabilityStatus.BLOCKED_EXTERNAL,
                f"seccomp-bpf is unavailable or the architecture {env['machine']} has no syscall table: unix-domain, "
                "UDP and raw sockets cannot be denied.",
                "Run on x86_64/aarch64 Linux with seccomp enabled.",
                [{"name": "seccomp", "status": "blocked", "detail": env["machine"]}],
            )
        return self._selftest(scratch, report, abi)

    @staticmethod
    def _control_check(root: Path, dirs: RunDirs, exe: Path) -> dict[str, str]:
        """Stop must work: the supervisor has to be able to signal AND reap a sandboxed child. A nested sandbox (or a
        platform policy) that forbids it would make 'stopped' unprovable, so that is a failed capability."""
        name = "supervisor_can_stop_child"
        policy = build_policy(argv=[str(exe), "-I", "-c", "import time; time.sleep(60)"], dirs=dirs, extra_ro=[], net_mode="none",
                              net_ports=[], limits=Limits(cpu_seconds=30), cgroup_procs=None, memory_via_rlimit=False, nproc_limit=None)
        ppath = root / "policy-control.json"
        ppath.write_text(json.dumps(policy))
        sh = launch_shim(ppath, env={"PATH": "/usr/bin:/bin"}, cwd=dirs.workspace, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                         stderr=subprocess.DEVNULL)
        try:
            ready, why = sh.wait_ready()
            if not ready:
                return {"name": name, "status": "fail", "detail": f"control child did not start: {why[:200]}"}
            try:
                os.kill(sh.proc.pid, signal.SIGKILL)
            except OSError as exc:
                return {"name": name, "status": "fail",
                        "detail": f"cannot signal a sandboxed child ({exc}); an outer sandbox or Landlock scope forbids it"}
            try:
                sh.proc.wait(10)
            except subprocess.TimeoutExpired:
                return {"name": name, "status": "fail", "detail": "child did not die after SIGKILL"}
            return {"name": name, "status": "pass", "detail": "SIGKILL delivered and child reaped"}
        finally:
            with contextlib.suppress(Exception):
                sh.proc.kill()
                sh.proc.wait(5)

    def _selftest(self, scratch: Path, report: Any, abi: int) -> SandboxReport:
        scratch.mkdir(parents=True, exist_ok=True, mode=0o700)
        root = Path(tempfile.mkdtemp(prefix="probe-", dir=scratch))
        listeners: list[socket.socket] = []
        sock_dir = root / "nosock"
        try:
            outside = root / "outside"
            outside.mkdir()
            (outside / "sentinel").write_text("SENTINEL-SELFTEST-DO-NOT-READ")
            dirs = RunDirs(*(root / n for n in ("ws", "ro", "out", "home", "tmp")))
            for d in (dirs.workspace, dirs.ro, dirs.out, dirs.home, dirs.tmp):
                d.mkdir()
            tcp = socket.socket()
            tcp.bind(("127.0.0.1", 0))
            tcp.listen(4)
            listeners.append(tcp)
            unix = socket.socket(socket.AF_UNIX)
            sock_dir = Path(tempfile.mkdtemp(prefix="nzs-"))  # short path: sun_path is limited to 107 bytes
            unix_path = str(sock_dir / "s.sock")
            unix.bind(unix_path)
            unix.listen(1)
            listeners.append(unix)
            (dirs.ro / "selftest.py").write_text(_SELFTEST)
            cfg = {"ws": str(dirs.workspace), "ro": str(dirs.ro), "outside": str(outside), "sentinel": str(outside / "sentinel"),
                   "tcp_port": tcp.getsockname()[1], "unix": unix_path, "supervisor_pid": os.getpid()}
            (dirs.ro / "cfg.json").write_text(json.dumps(cfg))
            exe, _ = interpreter_prefix()
            policy = build_policy(
                argv=[str(exe), "-I", str(dirs.ro / "selftest.py"), str(dirs.ro / "cfg.json")], dirs=dirs, extra_ro=[], net_mode="none", net_ports=[], limits=Limits(cpu_seconds=30), cgroup_procs=None,
                memory_via_rlimit=False, nproc_limit=None,
            )
            ppath = root / "policy.json"
            ppath.write_text(json.dumps(policy))
            out_path = root / "stdout"
            with open(out_path, "wb") as so:
                sh = launch_shim(ppath, env={"PATH": "/usr/bin:/bin"}, cwd=dirs.workspace, stdin=subprocess.DEVNULL, stdout=so,
                                 stderr=subprocess.DEVNULL)
                ready, why = sh.wait_ready()
                if not ready:
                    with contextlib.suppress(Exception):
                        sh.proc.kill()
                        sh.proc.wait(5)
                    return report(CapabilityStatus.BLOCKED_EXTERNAL, f"sandbox could not be applied: {why}",
                                  "Fix the platform restriction named above; there is no unconfined fallback.",
                                  [{"name": "apply", "status": "blocked", "detail": why[:300]}])
                try:
                    sh.proc.wait(timeout=60)
                except subprocess.TimeoutExpired:
                    sh.proc.kill()
                    sh.proc.wait(5)
                    return report(CapabilityStatus.PROBE_FAIL, "sandbox self-test timed out", None, [])
            try:
                res = json.loads(out_path.read_text())
            except ValueError:
                return report(CapabilityStatus.PROBE_FAIL, "sandbox self-test produced no result", None, [])
            checks = [{"name": n, "status": "pass" if res.get(n) == "ok" else "fail", "detail": f"allowed op -> {res.get(n)}"} for n in _MUST_SUCCEED]
            checks += [{"name": f"deny:{n}", "status": "pass" if res.get(n) not in ("ok", None) else "fail", "detail": f"attack -> {res.get(n)}"}
                       for n in _MUST_FAIL]
            scoped = res.get("signal_outside") not in ("ok", None)
            checks.append({"name": "deny:signal_outside", "status": "pass" if scoped else ("skipped" if abi < 6 else "fail"),
                           "detail": f"abi={abi}; signal scoping needs ABI>=6 -> {res.get('signal_outside')}"})
            checks.append(self._control_check(root, dirs, exe))
            failed = [c for c in checks if c["status"] == "fail"]
            if failed:
                names = ", ".join(c["name"] for c in failed)
                return report(CapabilityStatus.PROBE_FAIL, f"sandbox self-test failed: {names}", "Real-agent autonomy stays disabled.", checks)
            return report(CapabilityStatus.PROBE_PASS, f"Landlock ABI {abi} + seccomp: all deny tests passed", None, checks)
        finally:
            for s in listeners:
                s.close()
            shutil.rmtree(root, ignore_errors=True)
            shutil.rmtree(sock_dir, ignore_errors=True)


class UnavailableBackend:
    """Test/diagnostic backend that reports a platform where the sandbox cannot be provided."""

    name = "unavailable"

    def __init__(self, verdict: CapabilityStatus, explanation: str, next_action: str | None = None) -> None:
        self.verdict, self.explanation, self.next_action = verdict, explanation, next_action

    def probe(self, scratch: Path) -> SandboxReport:  # noqa: ARG002
        return SandboxReport(self.name, self.verdict.value, self.explanation, self.next_action, [], _environment(), mounts_description(), profile_digest())

