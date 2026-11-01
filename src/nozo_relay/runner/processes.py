"""Process-tree control: cgroup v2 (preferred) or a /proc based fallback.

Contract (06_EXECUTION_PROTOCOL "Stop"): SIGTERM the WHOLE tree -> grace -> kill what is left -> verify that
no member remains -> only then may the caller confirm the stop. Signals are only ever sent to pids that were
read from the kernel's own view of THIS run's tree (cgroup.procs, or a /proc scan rooted at the child we
spawned), verified against their start time - never to a pid taken from an agent report.

cgroup v2 (``CgroupTree``): ``cgroup.kill`` kills every member atomically (kernel >= 5.14), members cannot
escape by ``setsid``/double-fork, and ``memory.max`` / ``pids.max`` / ``cpu.max`` give real limits.
It requires a writable *delegated* cgroup (systemd user session: ``user@UID.service`` with cpu/memory/pids).

Fallback (``ProcfsTree``): descendants (ppid walk) + the process group + the session + every (pid,starttime)
seen during polling. A process that double-forks AND ``setsid``s between two polls can escape this mode; only
cgroup mode closes that gap. The fallback is therefore reported as ``tree_control=procfs`` in the capability
report and listed as a known limitation.
"""

from __future__ import annotations

import contextlib
import errno
import os
import signal
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Protocol

_CGROUP_ROOT = Path("/sys/fs/cgroup")
_WANTED_CONTROLLERS = ("cpu", "memory", "pids")


@dataclass(frozen=True, order=True)
class ProcId:
    """pid + kernel start time: immune to pid reuse."""

    pid: int
    start: int


@dataclass(frozen=True)
class ProcInfo:
    pid: int
    ppid: int
    pgrp: int
    session: int
    start: int
    state: str


def read_proc(pid: int) -> ProcInfo | None:
    try:
        raw = Path(f"/proc/{pid}/stat").read_text()
    except (FileNotFoundError, ProcessLookupError, PermissionError, OSError):
        return None
    head, _, tail = raw.rpartition(")")  # comm may contain spaces/parentheses
    f = tail.split()
    try:
        return ProcInfo(pid=pid, ppid=int(f[1]), pgrp=int(f[2]), session=int(f[3]), start=int(f[19]), state=f[0])
    except (IndexError, ValueError):
        return None


def proc_id(pid: int) -> ProcId | None:
    info = read_proc(pid)
    return ProcId(pid, info.start) if info else None


def alive(pid_id: ProcId) -> bool:
    info = read_proc(pid_id.pid)
    return info is not None and info.start == pid_id.start and info.state != "Z"


def scan_all() -> dict[int, ProcInfo]:
    out: dict[int, ProcInfo] = {}
    for entry in os.scandir("/proc"):
        if entry.name.isdigit():
            info = read_proc(int(entry.name))
            if info:
                out[info.pid] = info
    return out


def user_process_count() -> int:
    """Tasks (processes + threads) owned by this uid: what ``RLIMIT_NPROC`` actually counts."""
    uid = os.getuid()
    n = 0
    for entry in os.scandir("/proc"):
        if entry.name.isdigit():
            try:
                if os.stat(entry.path).st_uid == uid:
                    n += max(1, len(os.listdir(f"{entry.path}/task")))
            except OSError:
                continue
    return n


def find_by_cmdline(marker: str) -> list[ProcId]:
    """Own-user processes whose argv contains ``marker`` (used by reconciliation when no pid was recorded)."""
    found: list[ProcId] = []
    me = os.getpid()
    for entry in os.scandir("/proc"):
        if not entry.name.isdigit() or int(entry.name) == me:
            continue
        try:
            cmd = Path(entry.path, "cmdline").read_bytes()
        except OSError:
            continue
        if marker.encode() in cmd:
            pid_id = proc_id(int(entry.name))
            if pid_id and alive(pid_id):
                found.append(pid_id)
    return found


def find_by_marker(prefix: str) -> list[ProcId]:
    """Own-user processes whose argv mentions ``prefix`` or whose cwd lies under it (a run directory)."""
    found: list[ProcId] = []
    me = os.getpid()
    needle = prefix.rstrip("/") + "/"
    for entry in os.scandir("/proc"):
        if not entry.name.isdigit() or int(entry.name) == me:
            continue
        hit = False
        try:
            hit = needle.encode() in Path(entry.path, "cmdline").read_bytes()
        except OSError:
            pass
        if not hit:
            try:
                hit = (os.readlink(Path(entry.path, "cwd")) + "/").startswith(needle)
            except OSError:
                pass
        if hit:
            pid_id = proc_id(int(entry.name))
            if pid_id and alive(pid_id):
                found.append(pid_id)
    return found


class ProcessTree(Protocol):
    kind: str

    def members(self) -> set[ProcId]: ...
    def signal_all(self, sig: int) -> None: ...
    def kill_all(self) -> None: ...
    def absent(self) -> bool: ...
    def release(self) -> None: ...


def terminate_tree(tree: ProcessTree, *, grace: float, kill_wait: float = 5.0, poll: float = 0.02) -> tuple[bool, list[int]]:
    """SIGTERM -> grace -> kill -> verify. Returns (confirmed_absent, remaining_pids)."""
    with contextlib.suppress(OSError):
        tree.signal_all(signal.SIGTERM)
    deadline = time.monotonic() + max(grace, 0)
    while time.monotonic() < deadline and not tree.absent():
        time.sleep(poll)
    if not tree.absent():
        tree.kill_all()
    deadline = time.monotonic() + kill_wait
    while time.monotonic() < deadline:
        if tree.absent():
            return True, []
        tree.kill_all()
        time.sleep(poll)
    return tree.absent(), sorted(m.pid for m in tree.members())


# --------------------------------------------------------------------------------------------- cgroup
@dataclass(frozen=True)
class CgroupSupport:
    available: bool
    reason: str
    parent: Path | None = None
    controllers: tuple[str, ...] = ()
    cgroup_kill: bool = False

    def describe(self) -> dict[str, object]:
        return {
            "available": self.available,
            "reason": self.reason,
            "parent": str(self.parent) if self.parent else None,
            "controllers": list(self.controllers),
            "cgroup_kill": self.cgroup_kill,
        }


def _own_cgroup_dir() -> Path | None:
    try:
        for line in Path("/proc/self/cgroup").read_text().splitlines():
            if line.startswith("0::"):
                return _CGROUP_ROOT / line[3:].lstrip("/")
    except OSError:
        return None
    return None


def detect_cgroup_support(*, create_probe: bool = True) -> CgroupSupport:
    """Probe for a writable delegated cgroup v2 subtree by actually creating (and removing) a cgroup."""
    if not (_CGROUP_ROOT / "cgroup.controllers").exists():
        return CgroupSupport(False, "cgroup v2 is not mounted at /sys/fs/cgroup")
    own = _own_cgroup_dir()
    if own is None or not own.exists():
        return CgroupSupport(False, "cannot determine own cgroup from /proc/self/cgroup")
    candidates = [own.parent, own]
    last = "no writable cgroup found"
    for base in candidates:
        probe = base / f"nozo-relay-probe-{os.getpid()}"
        try:
            probe.mkdir()
        except OSError as exc:
            last = f"cannot create cgroup under {base}: {exc.strerror}"
            continue
        try:
            controllers = tuple(c for c in (probe / "cgroup.controllers").read_text().split() if c in _WANTED_CONTROLLERS)
            kill = (probe / "cgroup.kill").exists()
        except OSError:
            controllers, kill = (), False
        finally:
            with contextlib.suppress(OSError):
                probe.rmdir()
        if not kill:
            last = "kernel lacks cgroup.kill (need >= 5.14)"
            continue
        return CgroupSupport(True, "delegated cgroup v2 subtree is writable", base, controllers, kill)
    return CgroupSupport(False, last)


def _write(path: Path, value: str) -> None:
    path.write_text(value)


class CgroupTree:
    kind = "cgroup"

    def __init__(self, path: Path) -> None:
        self.path = path
        self.enforced: dict[str, int | None] = {}

    @classmethod
    def create(cls, support: CgroupSupport, run_id: str, *, memory_bytes: int | None, pids_max: int | None, cpu_percent: int | None) -> "CgroupTree":
        assert support.parent is not None
        root = support.parent / "nozo-relay-runs"
        root.mkdir(exist_ok=True)
        with contextlib.suppress(OSError):  # enable limit controllers for the per-run leaves
            sub = (root / "cgroup.subtree_control").read_text().split()
            want = [f"+{c}" for c in support.controllers if c not in sub]
            if want:
                _write(root / "cgroup.subtree_control", " ".join(want))
        path = root / f"run-{run_id}"
        path.mkdir()
        tree = cls(path)
        have = set((path / "cgroup.controllers").read_text().split())
        with contextlib.suppress(OSError):
            if memory_bytes and "memory" in have:
                _write(path / "memory.max", str(memory_bytes))
                _write(path / "memory.swap.max", "0")
                _write(path / "memory.oom.group", "1")
            if pids_max and "pids" in have:
                _write(path / "pids.max", str(pids_max))
            if cpu_percent and "cpu" in have:
                _write(path / "cpu.max", f"{int(cpu_percent) * 1000} 100000")
        tree.enforced = {
            "memory_max": memory_bytes if memory_bytes and "memory" in have else None,
            "pids_max": pids_max if pids_max and "pids" in have else None,
            "cpu_percent": cpu_percent if cpu_percent and "cpu" in have else None,
        }
        return tree

    @property
    def procs_file(self) -> Path:
        return self.path / "cgroup.procs"

    def _pids(self) -> list[int]:
        try:
            return [int(x) for x in (self.path / "cgroup.procs").read_text().split()]
        except (FileNotFoundError, OSError):
            return []

    def members(self) -> set[ProcId]:
        out: set[ProcId] = set()
        for pid in self._pids():
            pid_id = proc_id(pid)
            if pid_id:
                out.add(pid_id)
        return out

    def signal_all(self, sig: int) -> None:
        for pid_id in self.members():
            with contextlib.suppress(ProcessLookupError, PermissionError):
                if alive(pid_id):
                    os.kill(pid_id.pid, sig)

    def kill_all(self) -> None:
        try:
            _write(self.path / "cgroup.kill", "1")
        except OSError:
            for pid_id in self.members():
                with contextlib.suppress(ProcessLookupError, PermissionError):
                    os.kill(pid_id.pid, signal.SIGKILL)

    def absent(self) -> bool:
        if not self.path.exists():
            return True
        return not self._pids_alive()

    def _pids_alive(self) -> bool:
        for pid in self._pids():
            info = read_proc(pid)
            if info and info.state != "Z":
                return True
        return False

    def stats(self) -> dict[str, int]:
        out: dict[str, int] = {}
        for name in ("memory.events", "memory.peak", "pids.peak"):
            try:
                text = (self.path / name).read_text()
            except OSError:
                continue
            if name == "memory.events":
                for line in text.splitlines():
                    k, _, v = line.partition(" ")
                    if k in ("oom", "oom_kill", "max"):
                        out[f"memory_{k}"] = int(v)
            else:
                out[name.replace(".", "_")] = int(text.strip() or 0)
        return out

    def release(self) -> None:
        for _ in range(50):
            try:
                self.path.rmdir()
                return
            except FileNotFoundError:
                return
            except OSError as exc:
                if exc.errno not in (errno.EBUSY, errno.ENOTEMPTY):
                    return
                self.kill_all()
                time.sleep(0.02)


# --------------------------------------------------------------------------------------------- procfs fallback
@dataclass
class ProcfsTree:
    root: ProcId
    kind: str = field(default="procfs", init=False)
    tracked: set[ProcId] = field(default_factory=set)

    def __post_init__(self) -> None:
        self.tracked.add(self.root)

    def _scan(self) -> set[ProcId]:
        table = scan_all()
        root_info = table.get(self.root.pid)
        groups: set[int] = set()
        sessions: set[int] = set()
        if root_info and root_info.start == self.root.start:
            groups.add(root_info.pgrp)
            sessions.add(root_info.session)
        else:
            groups.add(self.root.pid)  # we started it with start_new_session: pgid == sid == pid
            sessions.add(self.root.pid)
        children: dict[int, list[int]] = {}
        for info in table.values():
            children.setdefault(info.ppid, []).append(info.pid)
        found: set[ProcId] = set()
        stack = [t.pid for t in self.tracked if alive(t)]
        seen: set[int] = set()
        while stack:
            pid = stack.pop()
            if pid in seen:
                continue
            seen.add(pid)
            info = table.get(pid)
            if info is None or info.state == "Z":
                continue
            found.add(ProcId(pid, info.start))
            stack.extend(children.get(pid, ()))
        for info in table.values():
            if info.state == "Z":
                continue
            # session/group membership: a pgid/sid that only matches because of pid reuse is excluded by
            # requiring the process to have started no earlier than the root.
            if (info.pgrp in groups or info.session in sessions) and info.start >= self.root.start:
                found.add(ProcId(info.pid, info.start))
        self.tracked |= found
        return found

    def members(self) -> set[ProcId]:
        return {m for m in self._scan() if alive(m)}

    def signal_all(self, sig: int) -> None:
        for m in self.members():
            with contextlib.suppress(ProcessLookupError, PermissionError):
                if alive(m):
                    os.kill(m.pid, sig)

    def kill_all(self) -> None:
        for _ in range(5):  # freeze first so the tree cannot fork faster than we kill, then re-scan
            members = self.members()
            if not members:
                return
            for m in members:
                with contextlib.suppress(ProcessLookupError, PermissionError):
                    if alive(m):
                        os.kill(m.pid, signal.SIGSTOP)
            for m in self.members() | members:
                with contextlib.suppress(ProcessLookupError, PermissionError):
                    if alive(m):
                        os.kill(m.pid, signal.SIGKILL)

    def absent(self) -> bool:
        return not self.members()

    def release(self) -> None:
        return None
