"""Sandbox launcher shim: applies the OS confinement to ITSELF, then ``execve``s the child argv.

Standalone on purpose (stdlib only, no ``nozo_relay`` imports): the supervisor starts it as
``python -I <this file> <policy.json> <status_fd> <env_fd>`` with an almost empty environment, so neither the
relay package nor any secret is needed by - or visible to - the shim. ``policy.json`` never contains secrets:
the child's environment (which may hold the adapter's provider credential) travels through ``env_fd`` only. The supervisor ALSO imports this
module for read-only capability detection (``landlock_abi``, ``seccomp_supported``).

Confinement (Linux, unprivileged, no user namespaces needed - this host's AppArmor forbids them):

* **Landlock** filesystem allow-list (read-only runtime paths + a few read-write run directories).
  Everything else - owner DB, the relay data dir, other runs, the canonical repo, ``$HOME``, ``/proc`` -
  is simply not reachable, no matter which interpreter or tool the child uses. Symlinks cannot widen
  access: Landlock rules are attached to the resolved inode hierarchy.
* **Landlock** TCP bind/connect (ABI >= 4), abstract-unix-socket and signal scopes (ABI >= 6).
* **seccomp-bpf**: ``socket()`` is denied for AF_UNIX / AF_NETLINK / AF_PACKET (pathname-unix sockets such
  as the Docker or ssh-agent sockets are NOT covered by Landlock before ABI 9) and for every non-stream
  type (UDP/raw egress); AF_INET/INET6 is denied completely in ``net=none`` mode. ptrace, process_vm_*,
  mount API, bpf, io_uring, keyrings, open_by_handle_at, setns/unshare, ... are denied.
* ``PR_SET_NO_NEW_PRIVS`` (required for both of the above), resource limits, optional cgroup join.

Failure is FAIL-CLOSED: if any requested protection cannot be applied the shim reports the reason on the
status pipe, exits ``EXIT_SETUP_FAILED`` and the child is never executed. There is no "unsandboxed" mode.

Status pipe: the write end is ``O_CLOEXEC``. Just before ``execve`` the shim writes ``R``; a successful exec
closes the pipe, so the supervisor reads exactly ``R`` then EOF = "sandbox applied, child running". Any failure
writes a JSON ``sandbox_setup_failed`` record instead (or after the ``R`` if exec itself fails). The child never
holds the descriptor and cannot spoof it.
"""

from __future__ import annotations

import ctypes
import json
import os
import platform
import resource
import signal
import struct
import sys
from typing import Any

EXIT_SETUP_FAILED = 70

# --------------------------------------------------------------------------- landlock ABI
SYS_LANDLOCK_CREATE_RULESET = 444
SYS_LANDLOCK_ADD_RULE = 445
SYS_LANDLOCK_RESTRICT_SELF = 446
LANDLOCK_CREATE_RULESET_VERSION = 1
LANDLOCK_RULE_PATH_BENEATH = 1
LANDLOCK_RULE_NET_PORT = 2

FS_EXECUTE = 1 << 0
FS_WRITE_FILE = 1 << 1
FS_READ_FILE = 1 << 2
FS_READ_DIR = 1 << 3
FS_REMOVE_DIR = 1 << 4
FS_REMOVE_FILE = 1 << 5
FS_MAKE_REG = 1 << 8
FS_MAKE_DIR = 1 << 7
FS_MAKE_SYM = 1 << 12
FS_REFER = 1 << 13  # ABI 2
FS_TRUNCATE = 1 << 14  # ABI 3
FS_IOCTL_DEV = 1 << 15  # ABI 5
NET_BIND_TCP = 1 << 0
NET_CONNECT_TCP = 1 << 1
SCOPE_ABSTRACT_UNIX = 1 << 0
SCOPE_SIGNAL = 1 << 1
MAX_USED_ABI = 6

PR_SET_CHILD_SUBREAPER = 36
PR_SET_NO_NEW_PRIVS = 38
PR_SET_SECCOMP = 22
PR_GET_SECCOMP = 21
SECCOMP_MODE_FILTER = 2

_FILE_BITS = FS_EXECUTE | FS_WRITE_FILE | FS_READ_FILE | FS_TRUNCATE | FS_IOCTL_DEV


def _libc() -> Any:
    lib = ctypes.CDLL(None, use_errno=True)
    lib.syscall.restype = ctypes.c_long
    return lib


def landlock_abi() -> int:
    """Kernel Landlock ABI version, 0 if Landlock is not available (disabled/unsupported/denied)."""
    try:
        lib = _libc()
        v = lib.syscall(SYS_LANDLOCK_CREATE_RULESET, None, 0, LANDLOCK_CREATE_RULESET_VERSION)
    except Exception:  # noqa: BLE001
        return 0
    return int(v) if v > 0 else 0


def seccomp_supported() -> bool:
    try:
        lib = _libc()
        return int(lib.prctl(PR_GET_SECCOMP, 0, 0, 0, 0)) >= 0 and platform.machine() in _SYSCALLS
    except Exception:  # noqa: BLE001
        return False


def _handled_fs(abi: int) -> int:
    bits = (1 << 13) - 1  # execute .. make_sym
    if abi >= 2:
        bits |= FS_REFER
    if abi >= 3:
        bits |= FS_TRUNCATE
    if abi >= 5:
        bits |= FS_IOCTL_DEV
    return bits


def _access_bits(kind: str, abi: int) -> int:
    ro = FS_EXECUTE | FS_READ_FILE | FS_READ_DIR
    rw = FS_READ_FILE | FS_READ_DIR | FS_WRITE_FILE | FS_REMOVE_DIR | FS_REMOVE_FILE | FS_MAKE_REG | FS_MAKE_DIR | FS_MAKE_SYM
    if abi >= 2:
        rw |= FS_REFER
    if abi >= 3:
        rw |= FS_TRUNCATE
    if kind == "ro":
        return ro
    if kind == "rw":
        return rw
    if kind == "rwx":
        return rw | FS_EXECUTE
    if kind == "dev":  # /dev/null & friends: read/write the node, no ioctl
        return FS_READ_FILE | FS_WRITE_FILE | (FS_TRUNCATE if abi >= 3 else 0)
    raise ValueError(f"unknown access kind {kind!r}")


class _RulesetAttr(ctypes.Structure):
    _fields_ = [("handled_access_fs", ctypes.c_uint64), ("handled_access_net", ctypes.c_uint64), ("scoped", ctypes.c_uint64)]


class _NetPort(ctypes.Structure):
    _fields_ = [("allowed_access", ctypes.c_uint64), ("port", ctypes.c_uint64)]


def apply_landlock(policy: dict[str, Any], kernel_abi: int) -> dict[str, Any]:
    """Create + enforce the ruleset. Raises on any failure (caller fails closed)."""
    lib = _libc()
    abi = min(kernel_abi, MAX_USED_ABI)
    net = policy.get("net", {})
    attr = _RulesetAttr()
    attr.handled_access_fs = _handled_fs(abi)
    attr.handled_access_net = (NET_BIND_TCP | NET_CONNECT_TCP) if abi >= 4 else 0
    attr.scoped = (SCOPE_ABSTRACT_UNIX | SCOPE_SIGNAL) if abi >= 6 else 0
    size = 8 if abi < 4 else (16 if abi < 6 else 24)
    fd = lib.syscall(SYS_LANDLOCK_CREATE_RULESET, ctypes.byref(attr), size, 0)
    if fd < 0:
        raise OSError(ctypes.get_errno(), "landlock_create_ruleset failed")
    try:
        added = 0
        for rule in policy["fs"]:
            path, kind = rule["path"], rule["access"]
            try:
                pfd = os.open(path, os.O_PATH | os.O_CLOEXEC)
            except FileNotFoundError:
                if rule.get("optional"):
                    continue
                raise
            try:
                bits = _access_bits(kind, abi) & attr.handled_access_fs
                if not os.path.isdir(path):
                    bits &= _FILE_BITS
                pb = ctypes.create_string_buffer(struct.pack("=Qi", bits, pfd), 12)  # packed C struct
                if lib.syscall(SYS_LANDLOCK_ADD_RULE, fd, LANDLOCK_RULE_PATH_BENEATH, pb, 0) < 0:
                    raise OSError(ctypes.get_errno(), f"landlock_add_rule failed for {path}")
                added += 1
            finally:
                os.close(pfd)
        if abi >= 4 and net.get("mode") == "tcp_connect":
            for port in net.get("ports", []):
                np_ = _NetPort(NET_CONNECT_TCP, int(port))
                if lib.syscall(SYS_LANDLOCK_ADD_RULE, fd, LANDLOCK_RULE_NET_PORT, ctypes.byref(np_), 0) < 0:
                    raise OSError(ctypes.get_errno(), f"landlock net rule failed for port {port}")
        if lib.prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0:
            raise OSError(ctypes.get_errno(), "PR_SET_NO_NEW_PRIVS failed")
        if lib.syscall(SYS_LANDLOCK_RESTRICT_SELF, fd, 0) != 0:
            raise OSError(ctypes.get_errno(), "landlock_restrict_self failed")
        return {"abi": abi, "fs_rules": added, "net_enforced": abi >= 4, "scope_enforced": abi >= 6}
    finally:
        os.close(fd)


# --------------------------------------------------------------------------- seccomp
_AUDIT_ARCH = {"x86_64": 0xC000003E, "aarch64": 0xC00000B7}
_SYSCALLS: dict[str, dict[str, int]] = {
    "x86_64": {
        "socket": 41, "ptrace": 101, "process_vm_readv": 310, "process_vm_writev": 311, "mount": 165,
        "umount2": 166, "pivot_root": 155, "chroot": 161, "bpf": 321, "keyctl": 250, "add_key": 248,
        "request_key": 249, "io_uring_setup": 425, "io_uring_enter": 426, "io_uring_register": 427,
        "userfaultfd": 323, "perf_event_open": 298, "kexec_load": 246, "init_module": 175,
        "finit_module": 313, "delete_module": 176, "open_by_handle_at": 304, "name_to_handle_at": 303,
        "setns": 308, "unshare": 272, "pidfd_getfd": 438, "move_mount": 429, "open_tree": 428,
        "fsopen": 430, "fsconfig": 431, "fsmount": 432, "fspick": 433, "mount_setattr": 442,
        # T12/F04: Landlock does not mediate metadata changes of owner-uid files outside the roots
        "chmod": 90, "fchmod": 91, "fchmodat": 268, "fchmodat2": 452, "chown": 92, "fchown": 93,
        "lchown": 94, "fchownat": 260, "utime": 132, "utimes": 235, "futimesat": 261, "utimensat": 280,
    },
    "aarch64": {
        "socket": 198, "ptrace": 117, "process_vm_readv": 270, "process_vm_writev": 271, "mount": 40,
        "umount2": 39, "pivot_root": 41, "chroot": 51, "bpf": 280, "keyctl": 219, "add_key": 217,
        "request_key": 218, "io_uring_setup": 425, "io_uring_enter": 426, "io_uring_register": 427,
        "userfaultfd": 282, "perf_event_open": 241, "kexec_load": 104, "init_module": 105,
        "finit_module": 273, "delete_module": 106, "open_by_handle_at": 265, "name_to_handle_at": 264,
        "setns": 268, "unshare": 97, "pidfd_getfd": 438, "move_mount": 429, "open_tree": 428,
        "fsopen": 430, "fsconfig": 431, "fsmount": 432, "fspick": 433, "mount_setattr": 442,
        # T12/F04 (generic table: no chmod/chown/lchown/utime/utimes/futimesat syscalls exist on aarch64)
        "fchmod": 52, "fchmodat": 53, "fchmodat2": 452, "fchownat": 54, "fchown": 55, "utimensat": 88,
    },
}
_AF_INET, _AF_INET6, _SOCK_STREAM = 2, 10, 1
_RET_ALLOW = 0x7FFF0000
_RET_KILL = 0x80000000  # SECCOMP_RET_KILL_PROCESS
_RET_EPERM = 0x00050000 | 1


class _SockFilter(ctypes.Structure):
    _fields_ = [("code", ctypes.c_uint16), ("jt", ctypes.c_uint8), ("jf", ctypes.c_uint8), ("k", ctypes.c_uint32)]


class _SockFprog(ctypes.Structure):
    _fields_ = [("len", ctypes.c_uint16), ("filter", ctypes.POINTER(_SockFilter))]


def build_seccomp_program(machine: str, inet: str) -> list[tuple[int, int, int, int]]:
    """Classic BPF. ``inet``: ``none`` (no sockets at all) | ``stream`` (AF_INET/AF_INET6 SOCK_STREAM only)."""
    nrs = _SYSCALLS[machine]
    deny_always = [v for k, v in nrs.items() if k != "socket"]
    prog: list[Any] = []  # items: ("ins", code, k, jt_label, jf_label) | ("label", name)

    def ld(off: int) -> None:
        prog.append(("ins", 0x20, off, None, None))

    def jeq(k: int, t: str, f: str | None = None) -> None:
        prog.append(("ins", 0x15, k, t, f))

    def jge(k: int, t: str, f: str | None = None) -> None:
        prog.append(("ins", 0x35, k, t, f))

    def and_(k: int) -> None:
        prog.append(("ins", 0x54, k, None, None))

    def ret(v: int) -> None:
        prog.append(("ins", 0x06, v, None, None))

    def label(name: str) -> None:
        prog.append(("label", name))

    ld(4)  # arch
    jeq(_AUDIT_ARCH[machine], "arch_ok", "kill")
    label("arch_ok")
    ld(0)  # syscall nr
    if machine == "x86_64":
        jge(0x40000000, "kill")  # x32 ABI would bypass the table below
    for nr in deny_always:
        jeq(nr, "deny")
    jeq(nrs["socket"], "sock", "allow")
    label("sock")
    ld(16)  # args[0] (low 32 bits, little endian) = domain
    if inet == "none":
        ret(_RET_EPERM)
    else:
        jeq(_AF_INET, "stype")
        jeq(_AF_INET6, "stype", "deny")
        label("stype")
        ld(24)  # args[1] = type | flags
        and_(0xFF)
        jeq(_SOCK_STREAM, "allow", "deny")
    label("deny")
    ret(_RET_EPERM)
    label("kill")
    ret(_RET_KILL)
    label("allow")
    ret(_RET_ALLOW)

    index: dict[str, int] = {}
    n = 0
    for item in prog:
        if item[0] == "label":
            index[item[1]] = n
        else:
            n += 1
    out: list[tuple[int, int, int, int]] = []
    pc = 0
    for item in prog:
        if item[0] == "label":
            continue
        _, code, k, tl, fl = item
        jt = jf = 0
        if code in (0x15, 0x35):
            jt = index[tl] - (pc + 1)
            jf = (index[fl] - (pc + 1)) if fl else 0
            if not (0 <= jt <= 255 and 0 <= jf <= 255):
                raise ValueError("seccomp jump out of range")
        out.append((code, jt, jf, k))
        pc += 1
    return out


def apply_seccomp(inet: str) -> int:
    machine = platform.machine()
    if machine not in _SYSCALLS:
        raise OSError(0, f"seccomp filter not available for architecture {machine}")
    insns = build_seccomp_program(machine, inet)
    arr = (_SockFilter * len(insns))(*[_SockFilter(*i) for i in insns])
    prog = _SockFprog(len(insns), arr)
    lib = _libc()
    if lib.prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0:
        raise OSError(ctypes.get_errno(), "PR_SET_NO_NEW_PRIVS failed")
    if lib.prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, ctypes.byref(prog), 0, 0) != 0:
        raise OSError(ctypes.get_errno(), "seccomp filter install failed")
    return len(insns)


# --------------------------------------------------------------------------- limits
def apply_rlimits(limits: dict[str, Any]) -> dict[str, Any]:
    applied: dict[str, Any] = {}

    def setl(name: str, res: int, soft: int, hard: int | None = None) -> None:
        hard = soft if hard is None else hard
        cur_soft, cur_hard = resource.getrlimit(res)
        if cur_hard != resource.RLIM_INFINITY:
            hard = min(hard, cur_hard)
            soft = min(soft, hard)
        resource.setrlimit(res, (soft, hard))
        applied[name] = soft

    if limits.get("cpu_seconds"):
        setl("cpu_seconds", resource.RLIMIT_CPU, int(limits["cpu_seconds"]), int(limits["cpu_seconds"]) + 1)
    if limits.get("address_space_bytes"):
        setl("address_space_bytes", resource.RLIMIT_AS, int(limits["address_space_bytes"]))
    if limits.get("file_size_bytes"):
        setl("file_size_bytes", resource.RLIMIT_FSIZE, int(limits["file_size_bytes"]))
    if limits.get("nofile"):
        setl("nofile", resource.RLIMIT_NOFILE, int(limits["nofile"]))
    if limits.get("nproc"):
        setl("nproc", resource.RLIMIT_NPROC, int(limits["nproc"]))
    setl("core", resource.RLIMIT_CORE, 0)
    return applied


# --------------------------------------------------------------------------- entry point
def _fail(status_fd: int, reason: str) -> "None":
    try:
        os.write(status_fd, json.dumps({"sandbox_setup_failed": reason}).encode())
    finally:
        os._exit(EXIT_SETUP_FAILED)


def main(argv: list[str]) -> int:
    if len(argv) != 4:
        sys.stderr.write("usage: sandbox_exec.py <policy.json> <status_fd> <env_fd>\n")
        return 2
    status_fd, env_fd = int(argv[2]), int(argv[3])
    os.set_inheritable(status_fd, False)
    os.set_inheritable(env_fd, False)  # closed by a successful execve => EOF == sandbox applied
    try:
        with open(argv[1], "rb") as fh:
            policy = json.loads(fh.read())
        with os.fdopen(env_fd, "rb") as efh:
            child_env: dict[str, str] = json.loads(efh.read() or b"{}")
        if not isinstance(child_env, dict) or not all(isinstance(k, str) and isinstance(v, str) for k, v in child_env.items()):
            raise ValueError("env must be a str->str mapping")
        child_argv: list[str] = policy["argv"]
        if not isinstance(child_argv, list) or not child_argv or not all(isinstance(a, str) for a in child_argv):
            raise ValueError("argv must be a non-empty list of strings")
        os.umask(0o077)
        # Orphaned descendants are re-parented to the child (preserved across execve), so the /proc based
        # fallback can still see double-forked daemons while the child is alive.
        _libc().prctl(PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0)
        if policy.get("cgroup_procs"):
            with open(policy["cgroup_procs"], "w") as fh:  # join BEFORE anything can fork
                fh.write(str(os.getpid()))
        applied: dict[str, Any] = {}
        applied["rlimits"] = apply_rlimits(policy.get("limits", {}))
        req = policy.get("require", {})
        kernel_abi = landlock_abi()
        if kernel_abi < int(req.get("landlock_abi_min", 4)):
            raise RuntimeError(
                f"Landlock ABI {kernel_abi} < required {req.get('landlock_abi_min', 4)}: filesystem/network "
                "confinement cannot be guaranteed (refusing to run unconfined)"
            )
        os.chdir(policy["cwd"])
        applied["landlock"] = apply_landlock(policy, kernel_abi)
        applied["seccomp_instructions"] = apply_seccomp(policy.get("net", {}).get("seccomp_inet", "none"))
        signal.signal(signal.SIGPIPE, signal.SIG_DFL)
        signal.signal(signal.SIGXFSZ, signal.SIG_DFL)
    except BaseException as exc:  # noqa: BLE001 - fail closed on ANY problem
        _fail(status_fd, f"{type(exc).__name__}: {exc}")
        return EXIT_SETUP_FAILED
    try:
        os.write(status_fd, b"R")  # "ready": everything is applied; a failing exec appends an error below
        os.execve(child_argv[0], child_argv, child_env)
    except BaseException as exc:  # noqa: BLE001
        _fail(status_fd, f"exec failed: {type(exc).__name__}: {exc}")
    return EXIT_SETUP_FAILED


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
