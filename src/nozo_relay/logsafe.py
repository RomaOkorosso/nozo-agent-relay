"""Sanitised logs: redact known secret shapes and sentinel values before text reaches logs/events/UI.

Honest limits (05_SECURITY): this catches *known shapes* (relay keys, bearer tokens, cookies, password-
like assignments, PEM blocks, provider key prefixes) and any explicitly registered sentinel strings. It
does NOT promise to detect an arbitrary secret. Tests use sentinel secrets.
"""

from __future__ import annotations

import logging
import re
from collections.abc import Iterable, Mapping
from typing import Any

REDACTED = "[REDACTED]"
MAX_TEXT = 2000

_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"nzr_[0-9a-f]{16}\.[A-Za-z0-9_-]{20,}"),  # Relay agent key
    re.compile(r"nzr_[0-9a-f]{16}\b"),  # key prefix alone still identifies a credential
    re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._~+/=-]{8,}"),
    re.compile(r"(?i)\b(authorization|proxy-authorization)\s*[:=]\s*[^\r\n]+"),
    re.compile(r"(?i)\b(set-cookie|cookie)\s*:\s*[^\r\n]+"),
    re.compile(r"(?i)\b(nozo_session|nozo_csrf|session(?:id)?|csrf[_-]?token)\s*=\s*[^\s;,]+"),
    re.compile(
        r"(?i)\b([A-Za-z0-9_.-]*(?:password|passwd|secret|token|api[_-]?key|private[_-]?key|credential)[A-Za-z0-9_.-]*)"
        r"\s*[:=]\s*(?:\"[^\"]*\"|'[^']*'|[^\s,;&]+)"
    ),
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?(?:-----END [A-Z ]*PRIVATE KEY-----|\Z)", re.S),
    re.compile(r"\b(?:sk|pk|ghp|gho|ghs|github_pat|xox[bpaso]|AKIA)[-_A-Za-z0-9]{16,}"),  # provider-style keys
    re.compile(r"\bSENTINEL[_-]?SECRET[_A-Za-z0-9-]*"),  # conventional test sentinel
)
_ANSI = re.compile(r"\x1b\[[0-9;?]*[ -/]*[@-~]|\x1b\][^\x07]*(?:\x07|\x1b\\)")
_CONTROL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
_SECRET_KEY_NAMES = re.compile(
    r"(?i)(password|passwd|secret|token|api[_-]?key|authorization|cookie|credential|private[_-]?key|csrf)"
)


def redact(text: str, *, extra: Iterable[str] = (), max_len: int = MAX_TEXT) -> str:
    """Strip ANSI/control characters, redact secret shapes and ``extra`` sentinels, cap the length."""
    out = _ANSI.sub("", text)
    out = _CONTROL.sub("", out)
    for pattern in _PATTERNS:
        out = pattern.sub(REDACTED, out)
    for s in extra:
        if s and len(s) >= 4:
            out = out.replace(s, REDACTED)
    if len(out) > max_len:
        out = out[:max_len] + "…[truncated]"
    return out


def redact_obj(value: Any, *, extra: Iterable[str] = (), _depth: int = 0) -> Any:
    """Recursively redact strings; values under secret-looking keys are masked entirely."""
    extra = tuple(extra)
    if _depth > 8:
        return REDACTED
    if isinstance(value, str):
        return redact(value, extra=extra)
    if isinstance(value, Mapping):
        return {
            str(k): (REDACTED if _SECRET_KEY_NAMES.search(str(k)) else redact_obj(v, extra=extra, _depth=_depth + 1))
            for k, v in value.items()
        }
    if isinstance(value, (list, tuple, set, frozenset)):
        return [redact_obj(v, extra=extra, _depth=_depth + 1) for v in value]
    return value


class RedactingFilter(logging.Filter):
    """Redacts formatted messages (and string args) of every record passing through a handler/logger."""

    def __init__(self, extra: Iterable[str] = ()) -> None:
        super().__init__()
        self._extra = tuple(extra)

    def filter(self, record: logging.LogRecord) -> bool:
        try:
            message = record.getMessage()
        except Exception:  # noqa: BLE001 - never let a logging filter raise
            message = str(record.msg)
        record.msg = redact(message, extra=self._extra, max_len=8000)
        record.args = ()
        if record.exc_text:
            record.exc_text = redact(record.exc_text, extra=self._extra, max_len=8000)
        return True


_INSTALLED = "_nozo_redacting_factory"


def install(prefix: str = "nozo_relay", extra: Iterable[str] = ()) -> None:
    """Redact every record of loggers named ``prefix*`` at creation time (idempotent).

    A logger-level Filter would not see records of child loggers, so a record factory is used.
    """
    previous = logging.getLogRecordFactory()
    if getattr(previous, _INSTALLED, False):
        return
    flt = RedactingFilter(extra)

    def factory(*args: Any, **kwargs: Any) -> logging.LogRecord:
        record = previous(*args, **kwargs)
        if record.name == prefix or record.name.startswith(prefix + "."):
            flt.filter(record)
        return record

    setattr(factory, _INSTALLED, True)
    logging.setLogRecordFactory(factory)
