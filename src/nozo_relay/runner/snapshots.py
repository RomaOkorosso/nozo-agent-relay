"""Repository baseline, disposable clone, tree/diff hashing and manifest construction (T07).

Design rules (07_ADAPTERS "Git и снимки", 06_EXECUTION_PROTOCOL "Scope enforce"):

* The canonical repository is only ever READ. It is never reset, cleaned, checked out or written to.
  Baseline = clean ``HEAD``, or an owner-approved dirty-tree snapshot whose ``tree_hash`` matches the
  working tree EXACTLY. Anything else is a blocker for that project (``DirtyBaselineError``).
* The child works in a disposable clone with its own ``.git`` (no shared metadata, ``origin`` removed,
  empty hook template).
* After the run the supervisor builds the manifest in PURE PYTHON (``lstat``, never following symlinks).
  It never runs ``git`` inside the untrusted clone (``core.fsmonitor``/hooks/aliases there are child-
  controlled). ``.git`` internals are only fingerprinted (config, hooks, info, alternates).
* ``tree_hash`` / ``diff_hash`` are deterministic functions of content, paths, symlink targets and the
  executable bit - not of timestamps or git object ids.
"""

from __future__ import annotations

import contextlib
import difflib
import hashlib
import json
import os
import shutil
import stat
import subprocess
import tomllib
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

MAX_FILES = 50_000
MAX_TOTAL_BYTES = 1024 * 1024 * 1024
MAX_DIFF_FILE_BYTES = 1024 * 1024
_BINARY_SNIFF = 8192


class SnapshotError(RuntimeError):
    pass


class GitError(SnapshotError):
    pass


class DirtyBaselineError(SnapshotError):
    """The canonical working tree has unsaved changes and no matching owner-approved snapshot."""

    def __init__(self, message: str, dirty_paths: list[str]) -> None:
        super().__init__(message)
        self.dirty_paths = dirty_paths


class IdentityMismatchError(SnapshotError):
    pass


# ------------------------------------------------------------------------------------------- git (trusted repo only)
def _git_env(home: str) -> dict[str, str]:
    return {
        "PATH": "/usr/local/bin:/usr/bin:/bin",
        "HOME": home,
        "LC_ALL": "C",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_OPTIONAL_LOCKS": "0",  # `git status` must not even refresh the user's index
        "GIT_TERMINAL_PROMPT": "0",
        "GIT_ASKPASS": "/bin/false",
    }


def run_git(args: list[str], cwd: Path, *, timeout: float = 120.0, home: str = "/nonexistent") -> bytes:
    """argv-list only (never a shell). Hardened config: no fsmonitor, no external helpers, no hooks."""
    argv = ["git", "-c", "core.fsmonitor=false", "-c", "core.hooksPath=" + os.devnull, "-c", "protocol.ext.allow=never", *args]
    try:
        proc = subprocess.run(argv, cwd=cwd, env=_git_env(home), capture_output=True, timeout=timeout, check=False)  # noqa: S603
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise GitError(f"git {args[0]} failed: {type(exc).__name__}") from exc
    if proc.returncode != 0:
        raise GitError(f"git {args[0]} exited {proc.returncode}: {proc.stderr.decode(errors='replace')[:300]}")
    return proc.stdout


def git_root_commit(root: Path) -> str:
    out = run_git(["rev-list", "--max-parents=0", "HEAD"], root).decode().split()
    if not out:
        raise GitError("repository has no commits")
    return sorted(out)[0]


def repo_identity(root: Path) -> str:
    return f"git:{git_root_commit(root)}"


def head_commit(root: Path) -> str:
    return run_git(["rev-parse", "HEAD"], root).decode().strip()


def dirty_paths(root: Path) -> list[str]:
    out = run_git(["status", "--porcelain=v1", "-z", "--untracked-files=all"], root)
    parts = [p for p in out.split(b"\0") if p]
    paths: list[str] = []
    skip_next = False
    for rec in parts:
        if skip_next:
            skip_next = False
            continue
        xy, path = rec[:2], rec[3:]
        paths.append(path.decode(errors="replace"))
        if xy[:1] in (b"R", b"C") or xy[1:2] in (b"R", b"C"):
            skip_next = True  # the next record is the rename source
    return paths


def worktree_files(root: Path) -> list[str]:
    """Tracked + untracked-not-ignored paths that EXIST in the working tree."""
    out = run_git(["ls-files", "-z", "--cached", "--others", "--exclude-standard"], root)
    names = sorted({p.decode("utf-8", "surrogateescape") for p in out.split(b"\0") if p})
    return [n for n in names if _lexists(root / n)]


def _lexists(p: Path) -> bool:
    try:
        os.lstat(p)
        return True
    except OSError:
        return False


# ------------------------------------------------------------------------------------------- tree scan / hashing
@dataclass(frozen=True)
class Entry:
    kind: str  # "file" | "symlink"
    executable: bool
    sha256: str  # content digest (file) or digest of the link target text (symlink)
    size: int
    target: str | None = None


@dataclass
class TreeScan:
    entries: dict[str, Entry] = field(default_factory=dict)
    specials: list[str] = field(default_factory=list)  # fifo / socket / device nodes
    bad_names: list[str] = field(default_factory=list)  # not valid UTF-8, backslash, control chars, ...
    total_bytes: int = 0
    truncated: bool = False


def _sha256_file(path: str, size_hint: int = 0) -> str:
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise SnapshotError("not a regular file")
        h = hashlib.sha256()
        with os.fdopen(fd, "rb", closefd=False) as fh:
            while chunk := fh.read(1024 * 1024):
                h.update(chunk)
        return h.hexdigest()
    finally:
        os.close(fd)


def _valid_name(rel: str) -> bool:
    try:
        rel.encode("utf-8")
    except UnicodeEncodeError:
        return False
    return not any(ord(c) < 32 or c in "\\\x7f" for c in rel) and len(rel) <= 300


def scan_tree(root: Path, *, only: Iterable[str] | None = None, skip_top_git: bool = True) -> TreeScan:
    """Walk ``root`` without following symlinks. ``.git`` at the top level is excluded from the tree."""
    scan = TreeScan()
    base = str(root)

    def add(rel: str, full: str, st: os.stat_result) -> bool:
        if len(scan.entries) >= MAX_FILES or scan.total_bytes > MAX_TOTAL_BYTES:
            scan.truncated = True
            return False
        if not _valid_name(rel):
            scan.bad_names.append(rel.encode("utf-8", "replace").decode())
            return True
        if stat.S_ISLNK(st.st_mode):
            target = os.readlink(full)
            scan.entries[rel] = Entry("symlink", False, hashlib.sha256(os.fsencode(target)).hexdigest(), 0, target)
        elif stat.S_ISREG(st.st_mode):
            scan.entries[rel] = Entry("file", bool(st.st_mode & 0o111), _sha256_file(full), st.st_size)
            scan.total_bytes += st.st_size
        else:
            scan.specials.append(rel)
        return True

    if only is not None:
        for rel in sorted(only):
            full = os.path.join(base, rel)
            try:
                st = os.lstat(full)
            except OSError:
                continue
            if not add(rel, full, st):
                break
        return scan

    stack = [("", base)]
    while stack:
        rel_dir, full_dir = stack.pop()
        try:
            it = list(os.scandir(full_dir))
        except OSError:
            continue
        for e in sorted(it, key=lambda x: x.name):
            rel = f"{rel_dir}/{e.name}" if rel_dir else e.name
            if skip_top_git and not rel_dir and e.name == ".git":
                continue
            try:
                st = e.stat(follow_symlinks=False)
            except OSError:
                continue
            if stat.S_ISDIR(st.st_mode):
                stack.append((rel, e.path))
            elif not add(rel, e.path, st):
                return scan
    return scan


def tree_hash(entries: dict[str, Entry]) -> str:
    h = hashlib.sha256(b"nozo-tree-v1\n")
    for path in sorted(entries, key=lambda p: p.encode("utf-8", "surrogateescape")):
        e = entries[path]
        h.update(f"{e.kind}\0{int(e.executable)}\0{e.sha256}\0".encode())
        h.update(path.encode("utf-8", "surrogateescape"))
        h.update(b"\n")
    return h.hexdigest()


def worktree_tree_hash(root: Path) -> str:
    scan = scan_tree(root, only=worktree_files(root))
    return tree_hash(scan.entries)


# ------------------------------------------------------------------------------------------- baseline + clone
@dataclass(frozen=True)
class Baseline:
    kind: str  # "clean_head" | "saved_dirty_snapshot"
    base_commit: str
    tree_hash: str  # hash of the canonical working tree the clone was built from
    workspace_tree_hash: str  # hash of what the child actually starts with
    repo_identity: str


def check_baseline(
    canonical_root: Path, *, expected_identity: str, approved_tree_hash: str | None
) -> tuple[str, str, list[str]]:
    """Return (kind, tree_hash, dirty_paths) or raise. Never modifies the repository."""
    root = canonical_root
    if not root.is_dir() or root.is_symlink() or not (root / ".git").is_dir():
        raise SnapshotError("canonical_root is not a plain git repository directory")
    ident = repo_identity(root)
    if ident != expected_identity:
        raise IdentityMismatchError(f"repository identity changed ({ident} != registered {expected_identity})")
    dirty = dirty_paths(root)
    if not dirty:
        return "clean_head", worktree_tree_hash(root), []
    current = worktree_tree_hash(root)
    if approved_tree_hash and approved_tree_hash == current:
        return "saved_dirty_snapshot", current, dirty
    raise DirtyBaselineError(
        "working tree has unsaved changes and no matching owner-approved snapshot; "
        "commit/stash them or approve the current tree. Nothing was reset or cleaned.",
        dirty[:20],
    )


def create_workspace(canonical_root: Path, dest: Path, baseline_kind: str, *, home: Path) -> str:
    """Disposable clone with its own .git. Returns the base commit. ``dest`` must not exist."""
    if dest.exists():
        raise SnapshotError("workspace destination already exists")
    empty_template = home / "empty-git-template"
    empty_template.mkdir(parents=True, exist_ok=True)
    run_git(["clone", "--quiet", "--no-hardlinks", f"--template={empty_template}", "--", str(canonical_root), str(dest)],
            home, home=str(home))
    run_git(["remote", "remove", "origin"], dest, home=str(home))  # no way back to the user's repository
    run_git(["config", "core.hooksPath", os.devnull], dest, home=str(home))
    run_git(["config", "user.name", "nozo-relay-child"], dest, home=str(home))
    run_git(["config", "user.email", "child@nozo-relay.invalid"], dest, home=str(home))
    base = head_commit(dest)
    if baseline_kind == "saved_dirty_snapshot":
        _overlay_worktree(canonical_root, dest)
    return base


def _overlay_worktree(src: Path, dest: Path) -> None:
    wanted = set(worktree_files(src))
    # tracked files deleted in the user's tree are deleted in the clone as well
    for rel in run_git(["ls-files", "-z"], dest).decode("utf-8", "surrogateescape").split("\0"):
        if rel and rel not in wanted:
            with contextlib.suppress(OSError):
                os.unlink(dest / rel)
    for rel in sorted(wanted):
        copy_entry(src, dest, rel)


def copy_entry(src_root: Path, dst_root: Path, rel: str) -> None:
    s, d = src_root / rel, dst_root / rel
    st = os.lstat(s)
    d.parent.mkdir(parents=True, exist_ok=True)
    if _lexists(d):
        os.unlink(d)
    if stat.S_ISLNK(st.st_mode):
        os.symlink(os.readlink(s), d)
    elif stat.S_ISREG(st.st_mode):
        shutil.copyfile(s, d, follow_symlinks=False)
        os.chmod(d, 0o755 if st.st_mode & 0o111 else 0o644)
    else:
        raise SnapshotError(f"unsupported file type in baseline: {rel}")


def copy_baseline(workspace: Path, baseline_dir: Path, entries: dict[str, Entry]) -> None:
    """Supervisor-owned pristine copy used later for diffs (the child can never reach it)."""
    baseline_dir.mkdir(parents=True)
    for rel in entries:
        copy_entry(workspace, baseline_dir, rel)


def git_fingerprint(workspace: Path) -> dict[str, str]:
    """Digest of the security-relevant parts of the clone's .git (config, hooks, info, alternates).

    Commits/objects/index legitimately change while the child works; hooks, config, info/ and alternates
    must not. ``.git`` being replaced by a file/symlink is itself a change.
    """
    gd = workspace / ".git"
    out: dict[str, str] = {}
    try:
        st = os.lstat(gd)
    except OSError:
        return {".git": "missing"}
    if not stat.S_ISDIR(st.st_mode):
        return {".git": "not-a-directory"}

    def digest(p: Path) -> str:
        try:
            s = os.lstat(p)
        except OSError:
            return "absent"
        if stat.S_ISLNK(s.st_mode):
            return "symlink:" + os.readlink(p)
        if stat.S_ISDIR(s.st_mode):
            return "dir"
        return _sha256_file(str(p))

    for name in ("config", "info/exclude", "info/attributes", "info/grafts", "objects/info/alternates", "commondir", "gitdir"):
        out[name] = digest(gd / name)
    for sub in ("hooks", "info", "objects/info"):
        d = gd / sub
        if d.is_dir() and not d.is_symlink():
            for p in sorted(d.rglob("*")):
                rel = str(p.relative_to(gd))
                if rel not in out:
                    out[rel] = digest(p)
    return out


# ------------------------------------------------------------------------------------------- diff / manifest
@dataclass
class DiffResult:
    changed_files: list[dict[str, Any]]
    diff_lines: int
    new_dependencies: list[str]
    problems: list[dict[str, str]]
    diff_hash: str
    records: list[dict[str, Any]]


def _is_binary(path: Path) -> bool:
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    except OSError:
        return False
    try:
        return b"\0" in os.read(fd, _BINARY_SNIFF)
    finally:
        os.close(fd)


def _read_lines(path: Path) -> list[str] | None:
    try:
        if os.lstat(path).st_size > MAX_DIFF_FILE_BYTES:
            return None
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    except OSError:
        return None
    try:
        data = os.read(fd, MAX_DIFF_FILE_BYTES + 1)
    finally:
        os.close(fd)
    return data.decode("utf-8", "replace").splitlines()


def _count_diff_lines(old: Path | None, new: Path | None) -> int:
    a = _read_lines(old) if old else []
    b = _read_lines(new) if new else []
    if a is None or b is None:  # too large to diff precisely: count the size of both sides (upper bound)
        la = len(a) if a else 0
        lb = len(b) if b else 0
        return max(la + lb, 1_000_000)
    n = 0
    for line in difflib.unified_diff(a, b, n=0, lineterm=""):
        if line.startswith(("+++", "---", "@@")):
            continue
        n += 1
    return n


def _dep_pyproject(data: bytes | None) -> set[str]:
    if data is None:
        return set()
    doc = tomllib.loads(data.decode("utf-8"))
    out: set[str] = set()
    proj = doc.get("project", {})
    out.update(str(d).strip() for d in proj.get("dependencies", []))
    for v in proj.get("optional-dependencies", {}).values():
        out.update(str(d).strip() for d in v)
    for v in doc.get("dependency-groups", {}).values():
        out.update(str(d).strip() for d in v if isinstance(d, str))
    out.update(str(d).strip() for d in doc.get("build-system", {}).get("requires", []))
    for k, v in doc.get("tool", {}).get("poetry", {}).get("dependencies", {}).items():
        out.add(f"{k}={v}")
    out.update(str(d).strip() for d in doc.get("tool", {}).get("uv", {}).get("dev-dependencies", []))
    return out


def _dep_requirements(data: bytes | None) -> set[str]:
    if data is None:
        return set()
    return {ln.strip() for ln in data.decode("utf-8", "replace").splitlines() if ln.strip() and not ln.lstrip().startswith("#")}


def _dep_package_json(data: bytes | None) -> set[str]:
    if data is None:
        return set()
    doc = json.loads(data)
    out: set[str] = set()
    for sec in ("dependencies", "devDependencies", "peerDependencies", "optionalDependencies"):
        out.update(f"{k}@{v}" for k, v in (doc.get(sec) or {}).items())
    return out


def _dep_cargo(data: bytes | None) -> set[str]:
    if data is None:
        return set()
    doc = tomllib.loads(data.decode("utf-8"))
    out: set[str] = set()
    for sec in ("dependencies", "dev-dependencies", "build-dependencies"):
        out.update(f"{k}={v}" for k, v in (doc.get(sec) or {}).items())
    return out


def _dep_gomod(data: bytes | None) -> set[str]:
    if data is None:
        return set()
    return {ln.strip() for ln in data.decode("utf-8", "replace").splitlines() if ln.strip().startswith("require") or (ln.startswith("\t") and "/" in ln)}


_DEP_PARSERS: tuple[tuple[Callable[[str], bool], Callable[[bytes | None], set[str]]], ...] = (
    (lambda n: n == "pyproject.toml", _dep_pyproject),
    (lambda n: n.startswith(("requirements", "constraints")) and n.endswith(".txt"), _dep_requirements),
    (lambda n: n == "package.json", _dep_package_json),
    (lambda n: n == "Cargo.toml", _dep_cargo),
    (lambda n: n == "go.mod", _dep_gomod),
)


def _read_bytes(path: Path) -> bytes | None:
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    except OSError:
        return None
    try:
        return os.read(fd, 4 * 1024 * 1024)
    finally:
        os.close(fd)


def detect_new_dependencies(base_root: Path, after_root: Path, changed: Iterable[str]) -> tuple[list[str], list[dict[str, str]]]:
    new: list[str] = []
    problems: list[dict[str, str]] = []
    for rel in changed:
        name = rel.rsplit("/", 1)[-1]
        for match, parse in _DEP_PARSERS:
            if not match(name):
                continue
            try:
                before = parse(_read_bytes(base_root / rel))
                after = parse(_read_bytes(after_root / rel))
            except Exception:  # noqa: BLE001 - unparseable dependency file: cannot prove "no new deps"
                new.append(f"unparseable:{rel}"[:200])
                continue
            new.extend(sorted(f"{rel}: {d}"[:200] for d in after - before))
    return new[:100], problems


def diff_trees(
    base_root: Path, after_root: Path, base: TreeScan, after: TreeScan
) -> DiffResult:
    problems: list[dict[str, str]] = []
    for kind, names in (("special_file", after.specials), ("path_invalid", after.bad_names)):
        for n in names:
            problems.append({"kind": kind, "detail": n[:300]})
    if after.truncated:
        problems.append({"kind": "tree_too_large", "detail": f">{MAX_FILES} files or >{MAX_TOTAL_BYTES} bytes"})
    be, ae = base.entries, after.entries
    added = sorted(p for p in ae if p not in be)
    deleted = sorted(p for p in be if p not in ae)
    modified = sorted(p for p in ae if p in be and ae[p] != be[p])

    # exact-content renames: a deleted file whose digest re-appears under a new path (one-to-one)
    renames: dict[str, str] = {}
    by_sha: dict[str, list[str]] = {}
    for p in deleted:
        if be[p].kind == "file" and be[p].size > 0:
            by_sha.setdefault(be[p].sha256, []).append(p)
    for p in added:
        src = by_sha.get(ae[p].sha256) if ae[p].kind == "file" else None
        if src:
            renames[p] = src.pop(0)
    renamed_sources = set(renames.values())

    changed: list[dict[str, Any]] = []
    records: list[dict[str, Any]] = []
    diff_lines = 0

    def rec(path: str, change: str, b: Entry | None, a: Entry | None, renamed_from: str | None = None) -> dict[str, Any]:
        return {
            "path": path, "change": change, "renamed_from": renamed_from,
            "before": b.sha256 if b else None, "after": a.sha256 if a else None,
            "before_kind": b.kind if b else None, "after_kind": a.kind if a else None,
            "before_exec": b.executable if b else None, "after_exec": a.executable if a else None,
        }

    for p in added:
        a = ae[p]
        src = renames.get(p)
        file_changed = {
            "path": p, "change": "renamed" if src else "added", "binary": a.kind == "file" and _is_binary(after_root / p),
            "symlink": a.kind == "symlink", "mode_changed": False,
        }
        if src:
            file_changed["renamed_from"] = src
            file_changed["mode_changed"] = be[src].executable != a.executable
        else:
            diff_lines += 0 if file_changed["binary"] or a.kind == "symlink" else _count_diff_lines(None, after_root / p)
        changed.append(file_changed)
        records.append(rec(p, file_changed["change"], be.get(src) if src else None, a, src))
    for p in deleted:
        if p in renamed_sources:
            continue
        b = be[p]
        binary = b.kind == "file" and _is_binary(base_root / p)
        changed.append({"path": p, "change": "deleted", "binary": binary, "symlink": b.kind == "symlink", "mode_changed": False})
        diff_lines += 0 if binary or b.kind == "symlink" else _count_diff_lines(base_root / p, None)
        records.append(rec(p, "deleted", b, None))
    for p in modified:
        b, a = be[p], ae[p]
        binary = a.kind == "file" and (_is_binary(after_root / p) or _is_binary(base_root / p))
        content_same = b.kind == a.kind and b.sha256 == a.sha256
        changed.append({
            "path": p, "change": "modified", "binary": binary, "symlink": a.kind == "symlink" or b.kind == "symlink",
            "mode_changed": b.kind == "file" and a.kind == "file" and b.executable != a.executable,
        })
        if not content_same and not binary and a.kind == "file" and b.kind == "file":
            diff_lines += _count_diff_lines(base_root / p, after_root / p)
        records.append(rec(p, "modified", b, a))

    changed.sort(key=lambda c: c["path"])
    records.sort(key=lambda r: (r["path"], r["change"]))
    deps, dep_problems = detect_new_dependencies(base_root, after_root, [c["path"] for c in changed])
    problems.extend(dep_problems)
    diff_hash = hashlib.sha256(b"nozo-diff-v1\n" + json.dumps(records, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    return DiffResult(changed, diff_lines, deps, problems, diff_hash, records)


def scan_for_secrets(root: Path, paths: Iterable[str], secrets: Iterable[str]) -> list[str]:
    """Registered sentinel/secret values appearing in changed files (names only; never the value)."""
    needles = [s.encode() for s in secrets if s and len(s) >= 4]
    hits: list[str] = []
    if not needles:
        return hits
    for rel in paths:
        data = _read_bytes(root / rel)
        if data is not None and any(n in data for n in needles):
            hits.append(rel)
    return hits


# ------------------------------------------------------------------------------------------- safe removal
def remove_tree(path: Path, *, allowed_root: Path) -> None:
    """Delete ONLY a disposable directory that lives under ``allowed_root`` (never follows symlinks)."""
    allowed = allowed_root.resolve()
    try:
        st = os.lstat(path)
    except FileNotFoundError:
        return
    real = Path(os.path.realpath(path))
    if stat.S_ISLNK(st.st_mode) or allowed not in real.parents:
        raise SnapshotError(f"refusing to delete {path}: not a disposable directory under {allowed_root}")
    for dirpath, dirnames, _ in os.walk(path, followlinks=False):
        with contextlib.suppress(OSError):
            os.chmod(dirpath, 0o700)
        for d in dirnames:
            full = os.path.join(dirpath, d)
            if not os.path.islink(full):
                with contextlib.suppress(OSError):
                    os.chmod(full, 0o700)
    shutil.rmtree(path, ignore_errors=False)


def freeze_tree(path: Path) -> None:
    """Make a finished snapshot read-only (defence against accidental later writes)."""
    for dirpath, dirnames, filenames in os.walk(path, followlinks=False):
        for f in filenames:
            full = os.path.join(dirpath, f)
            if not os.path.islink(full):
                with contextlib.suppress(OSError):
                    os.chmod(full, os.stat(full).st_mode & ~0o222)
    for dirpath, dirnames, _ in os.walk(path, topdown=False, followlinks=False):
        if not os.path.islink(dirpath):
            with contextlib.suppress(OSError):
                os.chmod(dirpath, os.stat(dirpath).st_mode & ~0o222)
