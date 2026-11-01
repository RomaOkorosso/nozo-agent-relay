"""Scope enforcement on an ACCEPTED manifest (06_EXECUTION_PROTOCOL "Scope enforce").

Every changed / new / deleted / renamed / binary / symlinked path is checked against the task scope.
A violation is never "partially accepted": the caller quarantines the whole output (no snapshot, no
report, task blocked ``scope_change_required``). This is a *post-hoc* protection of the result, not a
replacement for the OS sandbox (T07): a model that already leaked data is not undone by a manifest check.

Rules (deny wins, case-insensitive for deny, everything normalised first):
* path must be canonical (no ``./``, ``//``, trailing ``/``) - ambiguous spellings are rejected
* any ``.git`` path component (hooks, config, objects) is always forbidden
* denied_paths first, then allowed_paths; a rename is checked at BOTH ends
* symlinks are always out (a link may point anywhere); permission changes are out
* binary files are out in surgical mode; new dependencies need ``allow_new_dependencies``
* file-count and diff-line budgets
"""

from __future__ import annotations

import re
from functools import lru_cache
from typing import Any


@lru_cache(maxsize=512)
def _glob_regex(pattern: str, flags: int = 0) -> re.Pattern[str]:
    out: list[str] = []
    i = 0
    while i < len(pattern):
        c = pattern[i]
        if c == "*":
            if pattern[i : i + 2] == "**":
                i += 2
                if pattern[i : i + 1] == "/":
                    out.append("(?:.*/)?")
                    i += 1
                else:
                    out.append(".*")
                continue
            out.append("[^/]*")
        elif c == "?":
            out.append("[^/]")
        else:
            out.append(re.escape(c))
        i += 1
    return re.compile("^" + "".join(out) + "$", flags)


def path_matches(pattern: str, path: str, *, casefold: bool = False) -> bool:
    flags = re.IGNORECASE if casefold else 0
    rx = _glob_regex(pattern, flags)
    if rx.match(path):
        return True
    # A bare pattern without "/" (e.g. ".env*") also protects/matches the same name at any depth.
    return "/" not in pattern and bool(rx.match(path.rsplit("/", 1)[-1]))


# ------------------------------------------------------------------ glob language inclusion (T12/F01)
#
# ``glob_covers(sub, sup)`` decides, EXACTLY and conservatively, whether every path matched by ``path_matches(sub, p)``
# is also matched by ``path_matches(sup, p)``. Both globs are compiled to small NFAs with the very same semantics as
# ``_glob_regex`` / ``path_matches`` (``*`` = [^/]*, ``?`` = [^/], ``**`` = .*, ``**/`` = (?:.*/)?, everything else -
# including ``[`` - literal; a bare pattern without "/" also matches the same name at any depth) and inclusion is
# checked by exploring the product automaton over the alphabet {literals of both patterns, "/", one "other" symbol}.
# Anything that cannot be decided (unsupported spelling, search budget exhausted) answers False: never widen.

_OTHER = "\x00"  # stands for "any character that is neither "/" nor a literal of either pattern"
_MAX_PRODUCT_STATES = 20000


def _tokens(pattern: str, *, slash_free: bool) -> list[tuple[str, str]]:
    out: list[tuple[str, str]] = []
    i = 0
    while i < len(pattern):
        c = pattern[i]
        if c == "*":
            if pattern[i : i + 2] == "**":
                i += 2
                if pattern[i : i + 1] == "/":
                    out.append(("optdir", ""))
                    i += 1
                else:
                    out.append(("star", "") if slash_free else ("any", ""))
                continue
            out.append(("star", ""))
        elif c == "?":
            out.append(("one", ""))
        else:
            out.append(("lit", c))
        i += 1
    return out


def _variants(pattern: str) -> list[list[tuple[str, str]]]:
    variants = [_tokens(pattern, slash_free=False)]
    if "/" not in pattern:  # path_matches: a bare name pattern also matches the basename at any depth
        variants.append([("dir", ""), *_tokens(pattern, slash_free=True)])
    return variants


_State = tuple[int, int, int]  # (variant, position, in-directory-loop flag)


def _closure(variants: list[list[tuple[str, str]]], states: set[_State]) -> frozenset[_State]:
    todo = list(states)
    seen = set(states)
    while todo:
        v, i, mode = todo.pop()
        toks = variants[v]
        if mode == 0 and i < len(toks) and toks[i][0] in ("star", "any", "optdir"):
            nxt = (v, i + 1, 0)
            if nxt not in seen:
                seen.add(nxt)
                todo.append(nxt)
    return frozenset(seen)


def _step(variants: list[list[tuple[str, str]]], states: frozenset[_State], sym: str) -> frozenset[_State]:
    out: set[_State] = set()
    for v, i, mode in states:
        toks = variants[v]
        if i >= len(toks):
            continue
        kind, ch = toks[i]
        if mode == 1:  # inside ".*/" of an optdir/dir token
            out.add((v, i, 1))
            if sym == "/":
                out.add((v, i + 1, 0))
        elif kind == "lit":
            if sym == ch:
                out.add((v, i + 1, 0))
        elif kind == "one":
            if sym != "/":
                out.add((v, i + 1, 0))
        elif kind == "star":
            if sym != "/":
                out.add((v, i, 0))
        elif kind == "any":
            out.add((v, i, 0))
        else:  # optdir / dir
            out.add((v, i, 1))
            if sym == "/":
                out.add((v, i + 1, 0))
    return _closure(variants, out)


def _accepting(variants: list[list[tuple[str, str]]], states: frozenset[_State]) -> bool:
    return any(mode == 0 and i == len(variants[v]) for v, i, mode in states)


def _well_formed_glob(pattern: str) -> bool:
    """Only canonical, relative, forward-slash spellings take part in a ceiling proof."""
    if not pattern or pattern.startswith("/") or "\\" in pattern or _OTHER in pattern:
        return False
    parts = pattern.split("/")
    return not any(p in ("", ".", "..") for p in parts)


@lru_cache(maxsize=2048)
def glob_covers(sub: str, sup: str) -> bool:
    """True iff every path matching glob ``sub`` also matches glob ``sup``; False when not proven."""
    if sub == sup:
        return _well_formed_glob(sub)
    if not (_well_formed_glob(sub) and _well_formed_glob(sup)):
        return False
    sub_v, sup_v = _variants(sub), _variants(sup)
    alphabet = sorted({*(c for c in sub + sup if c not in "*?/"), "/", _OTHER})
    start = (
        _closure(sub_v, {(v, 0, 0) for v in range(len(sub_v))}),
        _closure(sup_v, {(v, 0, 0) for v in range(len(sup_v))}),
    )
    seen = {start}
    todo = [start]
    while todo:
        a, b = todo.pop()
        if _accepting(sub_v, a) and not _accepting(sup_v, b):
            return False  # witness: a path matched by ``sub`` but not by ``sup``
        for sym in alphabet:
            na = _step(sub_v, a, sym)
            if not na:
                continue
            nxt = (na, _step(sup_v, b, sym))
            if nxt not in seen:
                if len(seen) >= _MAX_PRODUCT_STATES:
                    return False  # undecided -> not proven -> reject
                seen.add(nxt)
                todo.append(nxt)
    return True


def _canonical(path: str) -> bool:
    parts = path.split("/")
    return not (path.endswith("/") or any(p in ("", ".") for p in parts))


def _is_git_internal(path: str) -> bool:
    return any(p.lower() == ".git" for p in path.split("/"))


def scope_violations(scope: dict[str, Any], mode: str, manifest: Any) -> list[dict[str, str]]:
    """Every changed/deleted/new/binary/renamed path must be inside the allowlist (deny wins)."""
    problems: list[dict[str, str]] = []

    def allowed(path: str) -> bool:
        if _is_git_internal(path):
            return False
        if any(path_matches(p, path, casefold=True) for p in scope.get("denied_paths", [])):
            return False
        return any(path_matches(p, path) for p in scope["allowed_paths"])

    if len(manifest.changed_files) > scope["max_changed_files"]:
        problems.append({"kind": "too_many_files", "detail": str(len(manifest.changed_files))})
    if manifest.diff_lines > scope["max_diff_lines"]:
        problems.append({"kind": "diff_too_large", "detail": str(manifest.diff_lines)})
    if manifest.new_dependencies and not scope.get("allow_new_dependencies"):
        problems.append({"kind": "new_dependency", "detail": ",".join(manifest.new_dependencies[:5])})
    for f in manifest.changed_files:
        for candidate in (f.path, f.renamed_from):
            if not candidate:
                continue
            if _is_git_internal(candidate):
                problems.append({"kind": "git_internal", "detail": candidate})
            elif not _canonical(candidate):
                problems.append({"kind": "path_not_canonical", "detail": candidate})
            elif not allowed(candidate):
                problems.append({"kind": "path_not_allowed", "detail": candidate})
        if f.change == "renamed" and not f.renamed_from:
            problems.append({"kind": "rename_without_source", "detail": f.path})
        if f.symlink:
            problems.append({"kind": "symlink", "detail": f.path})
        if f.mode_changed:
            problems.append({"kind": "permission_change", "detail": f.path})
        if f.binary and mode == "surgical":
            problems.append({"kind": "binary_in_surgical", "detail": f.path})
    return problems
