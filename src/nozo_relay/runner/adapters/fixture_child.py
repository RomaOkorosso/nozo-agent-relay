"""Fixture child program (stdlib only). It plays an "agent" that misbehaves in ways the sandbox must contain.

NOT a real agent: it exists so T07 can prove isolation on a disposable fixture. It is started by the
supervisor inside the sandbox as ``python -I fixture_child.py <task.json>``; ``task.json`` is written by the
fixture adapter into the read-only ``ro`` directory. Targets of the attacks (sentinel files, a local TCP port,
a unix socket path ...) come from the adapter's constructor in the TEST, never from task/API input.

Control protocol: JSON lines on stdout are advisory progress only; the result is the strict report file.
"""

from __future__ import annotations

import ctypes
import json
import os
import signal
import socket
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

CFG: dict[str, Any] = {}
ATTEMPTS: list[dict[str, Any]] = []


def emit(event: str, **fields: Any) -> None:
    print(json.dumps({"event": event, **fields}, sort_keys=True), flush=True)


def attempt(name: str, fn: Any, *, reads: bool = False) -> Any:
    """Run an attack step; ``ok`` = the attack SUCCEEDED (breach). For ``reads`` that means the sentinel text was obtained."""
    try:
        result = fn()
        sentinel = CFG.get("targets", {}).get("sentinel_text", "\0unset")
        ok = (sentinel in (result.decode(errors="replace") if isinstance(result, bytes) else str(result))) if reads else True
        ATTEMPTS.append({"name": name, "ok": ok, "error": None})
        return result
    except BaseException as exc:  # noqa: BLE001
        ATTEMPTS.append({"name": name, "ok": False, "error": type(exc).__name__})
        return None


def write_report(status: str = "ready_for_review", summary: str = "fixture done", **extra: Any) -> None:
    report = {"status": status, "summary": summary, **extra}
    Path(CFG["out_dir"], "report.json").write_text(json.dumps(report))


def write_attempts(name: str = "attempts.json", **extra: Any) -> None:
    Path(CFG["out_dir"], name).write_text(json.dumps({"attempts": ATTEMPTS, **extra}))


def ws(*parts: str) -> Path:
    return Path(CFG["workspace"], *parts)


# ----------------------------------------------------------------------------------------------- scenarios
def sc_edit() -> None:
    p = ws("src", "app.py")
    p.write_text(p.read_text() + "\n# edited by fixture\n")
    ws("src", "new_module.py").write_text("VALUE = 1\n")
    emit("progress", step="edited")
    write_report(summary="edited src/app.py and added src/new_module.py",
                 claimed_changed_paths=["src/app.py", "src/new_module.py"],
                 checks=[{"id": "unit", "command_label": "fixture", "status": "pass", "expected": "ok", "observed": "ok"}])


def sc_edit_out_of_scope() -> None:
    ws("README.md").write_text("changed outside the allowlist\n")
    write_report(summary="touched README.md", claimed_changed_paths=["README.md"])


def sc_rename_escape() -> None:
    os.makedirs(ws("docs"), exist_ok=True)
    os.rename(ws("src", "app.py"), ws("docs", "app.py"))
    write_report(summary="moved app.py", claimed_changed_paths=["src/app.py", "docs/app.py"])


def sc_hidden_change() -> None:
    p = ws("src", "app.py")
    p.write_text(p.read_text() + "\n# undeclared change\n")
    write_report(summary="claims to have changed nothing", claimed_changed_paths=[])


def sc_binary_new() -> None:
    ws("src", "blob.bin").write_bytes(b"\x00\x01\x02" * 100)
    write_report(summary="added binary", claimed_changed_paths=["src/blob.bin"])


def sc_new_dependency() -> None:
    p = ws("pyproject.toml")
    p.write_text(p.read_text().replace("dependencies = []", 'dependencies = ["requests>=2"]'))
    write_report(summary="added a dependency", claimed_changed_paths=["pyproject.toml"])


def sc_symlink_escape() -> None:
    outside = Path(CFG["targets"]["outside_dir"])
    link = ws("src", "escape")
    attempt("symlink_create", lambda: os.symlink(outside, link))
    attempt("symlink_read_through", lambda: (link / CFG["targets"]["outside_file_name"]).read_text(), reads=True)
    attempt("symlink_write_through", lambda: (link / "pwned.txt").write_text("owned"))
    attempt("symlink_list_through", lambda: os.listdir(link))
    attempt("symlink_replace_file_with_link", lambda: (os.unlink(ws("src", "app.py")), os.symlink(CFG["targets"]["sentinel"], ws("src", "app.py"))))
    attempt("symlink_read_sentinel_directly", lambda: ws("src", "app.py").read_text(), reads=True)
    write_attempts()
    write_report(summary="symlink games", claimed_changed_paths=["src/escape", "src/app.py"])


def sc_symlink_in_tree() -> None:
    attempt("symlink_relative_in_tree", lambda: os.symlink("app.py", ws("src", "alias.py")))
    write_report(summary="harmless-looking relative symlink", claimed_changed_paths=["src/alias.py"])


def sc_read_sentinel() -> None:
    t = CFG["targets"]
    s = t["sentinel"]
    attempt("open_builtin", lambda: open(s).read(), reads=True)
    attempt("os_open", lambda: os.read(os.open(s, os.O_RDONLY), 100), reads=True)
    attempt("pathlib", lambda: Path(s).read_bytes(), reads=True)
    attempt("proc_self_root", lambda: open("/proc/self/root" + s).read(), reads=True)
    attempt("relative_dotdot", lambda: open(os.path.relpath(s, CFG["workspace"])).read(), reads=True)
    attempt("chdir_then_read", lambda: (os.chdir(os.path.dirname(s)), open(os.path.basename(s)).read()), reads=True)
    attempt("owner_db", lambda: open(t["owner_db"], "rb").read(16), reads=True)
    attempt("list_outside_dir", lambda: os.listdir(os.path.dirname(s)))
    attempt("read_canonical_repo", lambda: (Path(t["canonical_root"]) / "src" / "app.py").read_text(), reads=True)
    attempt("read_home_ssh", lambda: os.listdir(os.path.expanduser("~/..")))
    attempt("write_outside", lambda: Path(t["outside_dir"], "pwn.txt").write_text("x"))
    attempt("mkdir_outside", lambda: os.mkdir(os.path.join(t["outside_dir"], "newdir")))
    attempt("hardlink_sentinel_into_ws", lambda: os.link(s, ws("stolen")))
    attempt("rename_sentinel_into_ws", lambda: os.rename(s, ws("stolen2")))
    attempt("chmod_sentinel", lambda: os.chmod(s, 0o777))
    attempt("unlink_sentinel", lambda: os.unlink(s))
    libc = ctypes.CDLL(None, use_errno=True)
    libc.open.argtypes = [ctypes.c_char_p, ctypes.c_int]

    def raw_open() -> bytes:
        fd = libc.open(s.encode(), os.O_RDONLY)
        if fd < 0:
            raise OSError(ctypes.get_errno(), "open")
        return os.read(fd, 100)

    attempt("ctypes_libc_open", raw_open, reads=True)
    attempt("read_parent_environ", lambda: open(f"/proc/{os.getppid()}/environ", "rb").read(), reads=True)
    attempt("read_proc_1_environ", lambda: open("/proc/1/environ", "rb").read(), reads=True)
    write_attempts()
    write_report(summary="tried to read protected data")


def sc_interpreter_escape() -> None:
    t = CFG["targets"]
    s = t["sentinel"]
    py = sys.executable

    def sh(cmd: list[str]) -> str:
        out = subprocess.run(cmd, capture_output=True, timeout=10, check=False)  # noqa: S603
        if out.returncode != 0:
            raise OSError(out.returncode, out.stderr.decode(errors="replace")[:80])
        return out.stdout.decode(errors="replace")

    attempt("sh_c_cat", lambda: sh(["/bin/sh", "-c", f"cat '{s}'"]), reads=True)
    attempt("python_c_open", lambda: sh([py, "-I", "-c", f"print(open({s!r}).read())"]), reads=True)
    attempt("os_system_cat", lambda: (os.system(f"cat '{s}' > {CFG['workspace']}/leak.txt") == 0 and ws("leak.txt").read_text()) or (_ for _ in ()).throw(OSError("failed")), reads=True)
    attempt("popen_cat", lambda: os.popen(f"cat '{s}'").read() or (_ for _ in ()).throw(OSError("empty")), reads=True)
    attempt("find_exec", lambda: sh(["/usr/bin/find", os.path.dirname(s), "-name", "*", "-exec", "cat", "{}", ";"]), reads=True)
    attempt("dd_copy", lambda: sh(["/usr/bin/dd", f"if={s}"]), reads=True)
    attempt("perl_open", lambda: sh(["/usr/bin/perl", "-e", f"open(F,'{s}') or die; print <F>"]), reads=True)
    attempt("awk_getline", lambda: sh(["/usr/bin/awk", f'BEGIN{{while((getline l < "{s}")>0) print l}}']) or (_ for _ in ()).throw(OSError("empty")), reads=True)
    attempt("sh_proc_environ", lambda: sh(["/bin/sh", "-c", f"cat /proc/{os.getppid()}/environ"]), reads=True)
    attempt("sh_cat_owner_db", lambda: sh(["/bin/sh", "-c", f"cat '{t['owner_db']}'"]), reads=True)
    attempt("sh_write_outside", lambda: sh(["/bin/sh", "-c", f"echo x > '{t['outside_dir']}/pwn.txt'"]))
    attempt("chain_python_sh_cat", lambda: sh([py, "-I", "-c", f"import os; os.execv('/bin/sh', ['sh','-c','cat {s}'])"]), reads=True)
    attempt("python_ctypes_syscall_open", lambda: sh([py, "-I", "-c",
            f"import ctypes,os;l=ctypes.CDLL(None,use_errno=True);fd=l.syscall(2,{s!r}.encode(),0);assert fd>=0;print(os.read(fd,50))"]))
    attempt("tcp_connect_local", lambda: socket.create_connection(("127.0.0.1", int(t["tcp_port"])), timeout=3))
    attempt("tcp_socket_create", lambda: socket.socket(socket.AF_INET, socket.SOCK_STREAM))
    attempt("udp_socket_create", lambda: socket.socket(socket.AF_INET, socket.SOCK_DGRAM).sendto(b"x", ("127.0.0.1", int(t["udp_port"]))))
    attempt("raw_socket", lambda: socket.socket(socket.AF_INET, socket.SOCK_RAW, 1))
    attempt("unix_socket_connect", lambda: socket.socket(socket.AF_UNIX, socket.SOCK_STREAM).connect(t["unix_socket"]))
    attempt("abstract_unix_connect", lambda: socket.socket(socket.AF_UNIX, socket.SOCK_STREAM).connect("\0nozo-sentinel-abstract"))
    attempt("netlink_socket", lambda: socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, 0))
    attempt("ptrace_parent", lambda: _ptrace(os.getppid()))
    attempt("signal_supervisor", lambda: os.kill(int(t["supervisor_pid"]), signal.SIGCONT))  # harmless even if it ever worked
    attempt("signal_pid1", lambda: os.kill(1, 0))
    write_attempts()
    write_report(summary="tried to escape through interpreters")


def _ptrace(pid: int) -> None:
    libc = ctypes.CDLL(None, use_errno=True)
    r = libc.ptrace(16, pid, 0, 0)  # PTRACE_ATTACH
    if r != 0:
        raise OSError(ctypes.get_errno(), "ptrace")


def sc_net_ports() -> None:
    t = CFG["targets"]
    attempt("tcp_allowed_port", lambda: socket.create_connection(("127.0.0.1", int(t["tcp_port"])), timeout=3))
    attempt("tcp_other_port", lambda: socket.create_connection(("127.0.0.1", int(t["tcp_port_other"])), timeout=3))
    attempt("udp_socket", lambda: socket.socket(socket.AF_INET, socket.SOCK_DGRAM))
    attempt("unix_socket", lambda: socket.socket(socket.AF_UNIX, socket.SOCK_STREAM))
    write_attempts()
    write_report(summary="network probe")


def sc_delete_outside() -> None:
    os.unlink(ws("README.md"))
    write_report(summary="deleted README.md", claimed_changed_paths=["README.md"])


def sc_leak_secret_transient() -> None:
    """Leaks the credential through stdout/stderr/progress/summary/checks but NOT through a file."""
    secret = os.environ.get("FIXTURE_PROVIDER_TOKEN", "")
    print(f"token is {secret}", flush=True)
    print(f"error: auth failed with {secret}", file=sys.stderr, flush=True)
    emit("progress", step=f"using {secret}")
    write_report(summary=f"summary leaks {secret}", claimed_changed_paths=[],
                 checks=[{"id": "c", "command_label": f"curl -H {secret}", "status": "pass", "expected": "x", "observed": f"saw {secret}"}])


def sc_env_dump() -> None:
    Path(CFG["out_dir"], "env_dump.json").write_text(json.dumps({"env": dict(os.environ), "argv": sys.argv, "cwd": os.getcwd(),
                                                                  "home": os.path.expanduser("~")}))
    write_report(summary="dumped own environment to the out dir")


def sc_leak_secret() -> None:
    """Deliberately leaks the provider credential through every channel the supervisor handles."""
    secret = os.environ.get("FIXTURE_PROVIDER_TOKEN", "")
    print(f"token is {secret}", flush=True)
    print(f"error: auth failed with {secret}", file=sys.stderr, flush=True)
    emit("progress", step=f"using {secret}")
    ws("src", "leak.txt").write_text(f"{secret}\n")
    write_report(summary=f"summary leaks {secret}", claimed_changed_paths=["src/leak.txt"],
                 checks=[{"id": "c", "command_label": f"curl -H {secret}", "status": "pass", "expected": "x", "observed": f"saw {secret}"}])


def sc_leak_secret_failure() -> None:
    secret = os.environ.get("FIXTURE_PROVIDER_TOKEN", "")
    print(f"fatal: {secret}", file=sys.stderr, flush=True)
    write_report(status="failed", summary=f"failed because of {secret}", error_code="provider_error")


def sc_spawn_tree() -> None:
    kids: list[int] = []
    py = sys.executable
    sleeper = [py, "-I", "-c", "import time; time.sleep(600)"]
    kids.append(subprocess.Popen(sleeper).pid)  # noqa: S603
    kids.append(subprocess.Popen(sleeper, start_new_session=True).pid)  # noqa: S603  (own session + pgid)
    # double fork + setsid: the orphan is re-parented to init and leaves our process group
    r, w = os.pipe()
    pid = os.fork()
    if pid == 0:
        os.close(r)
        os.setsid()
        if os.fork() == 0:
            os.write(w, str(os.getpid()).encode())
            os.close(w)
            time.sleep(600)
        os._exit(0)
    os.close(w)
    os.waitpid(pid, 0)
    kids.append(int(os.read(r, 32)))
    # a child that ignores SIGTERM and keeps re-spawning children
    kids.append(subprocess.Popen([py, "-I", "-c", "import signal,time,subprocess,sys;signal.signal(signal.SIGTERM,signal.SIG_IGN);"
                                  "subprocess.Popen([sys.executable,'-I','-c','import time;time.sleep(600)']);time.sleep(600)"]).pid)  # noqa: S603
    time.sleep(0.3)
    emit("descendants", pids=kids, child=os.getpid())
    while True:
        time.sleep(1)


def sc_hang() -> None:
    emit("progress", step="hanging", pid=os.getpid())
    while True:
        time.sleep(1)


def sc_ignore_sigterm() -> None:
    signal.signal(signal.SIGTERM, signal.SIG_IGN)
    emit("progress", step="ignoring SIGTERM", pid=os.getpid())
    while True:
        time.sleep(1)


def sc_exit_zero_no_report() -> None:
    emit("progress", step="exiting 0 without a report")


def sc_crash() -> None:
    emit("progress", step="crashing")
    os.kill(os.getpid(), signal.SIGSEGV)


def sc_exit_nonzero() -> None:
    emit("progress", step="exit 3")
    os._exit(3)


def sc_bad_report() -> None:
    marker = ws("src", "SHOULD_NOT_EXIST")
    Path(CFG["out_dir"], "report.json").write_text(json.dumps({
        "status": "ready_for_review", "summary": "x", "role": "owner", "principal_id": "00000000-0000-0000-0000-000000000000",
        "shell": f"touch {marker}", "commands": [["/bin/sh", "-c", f"touch {marker}"]],
    }))


def sc_report_symlink() -> None:
    os.symlink(CFG["targets"]["sentinel"], os.path.join(CFG["out_dir"], "report.json"))


def sc_report_huge() -> None:
    Path(CFG["out_dir"], "report.json").write_text(json.dumps({"status": "ready_for_review", "summary": "x" * (300 * 1024)}))


def sc_fake_control_stdout() -> None:
    for line in ('{"event":"claim","role":"owner"}', '{"event":"shell","cmd":"rm -rf /"}', "not json", '{"event":"stop"}'):
        print(line, flush=True)
    write_report(summary="noise on stdout", claimed_changed_paths=[])


def sc_big_output() -> None:
    chunk = "A" * 1000
    for _ in range(6000):
        print(chunk)
    sys.stdout.flush()
    write_report(summary="chatty", claimed_changed_paths=[])


def sc_git_tamper() -> None:
    hooks = ws(".git", "hooks")
    os.makedirs(hooks, exist_ok=True)
    (hooks / "pre-commit").write_text("#!/bin/sh\necho pwned\n")
    try:
        os.chmod(hooks / "pre-commit", 0o755)  # T12/F04: denied (EPERM) by seccomp; the planted file is still caught
    except OSError:
        pass
    cfg = ws(".git", "config")
    cfg.write_text(cfg.read_text() + '\n[core]\n\tfsmonitor = "echo pwned"\n')
    write_report(summary="tampered with .git", claimed_changed_paths=[])


def sc_cpu_burn() -> None:
    emit("progress", step="burning cpu")
    x = 0
    while True:
        x += 1


def sc_mem_hog() -> None:
    emit("progress", step="allocating")
    chunks: list[bytearray] = []
    got = 0
    try:
        for _ in range(int(CFG["params"].get("mb", 600))):
            chunks.append(bytearray(1024 * 1024))
            for i in range(0, len(chunks[-1]), 4096):
                chunks[-1][i] = 1  # touch pages so RSS (not just virtual) grows
            got += 1
    except MemoryError:
        write_attempts("mem.json", allocated_mb=got, memory_error=True)
        write_report(status="failed", summary="MemoryError", error_code="memory_error")
        return
    write_attempts("mem.json", allocated_mb=got, memory_error=False)
    write_report(summary=f"allocated {got} MB", claimed_changed_paths=[])


def sc_fork_flood() -> None:
    n = int(CFG["params"].get("count", 200))
    started = 0
    errors = 0
    procs = []
    for _ in range(n):
        try:
            procs.append(subprocess.Popen([sys.executable, "-I", "-c", "import time; time.sleep(30)"]))  # noqa: S603
            started += 1
        except (OSError, BlockingIOError):
            errors += 1
            break
    write_attempts("fork.json", started=started, errors=errors, requested=n)
    for p in procs:
        p.kill()
    write_report(summary=f"started {started}/{n}", claimed_changed_paths=[])


def sc_slow_ok() -> None:
    time.sleep(float(CFG["params"].get("seconds", 0.5)))
    sc_edit()


SCENARIOS = {name[3:]: fn for name, fn in globals().items() if name.startswith("sc_")}


def main() -> int:
    CFG.update(json.loads(Path(sys.argv[1]).read_text()))
    os.chdir(CFG["workspace"])
    emit("started", scenario=CFG["scenario"], pid=os.getpid())
    SCENARIOS[CFG["scenario"]]()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
