"""Russian UI vocabulary and the small, pure view-model rules that must never lie.

Two rules are safety-relevant and unit-tested:

* ``control_view``: an accepted stop (HTTP 202 / ``requested``) is shown as "Запрошено". "Остановлено" is
  produced only for a control that is ``confirmed`` AND carries a confirmation timestamp AND had a
  real run to stop (i.e. a runner receipt). A lost runner is "Остановка не подтверждена".
* ``activity_view``: a lease alone is "claimed", not "running": claimed / process started / fresh
  heartbeat / output last seen are separate signals (08_UI_OPERATIONS).
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

TASK_STATUS_RU: dict[str, str] = {
    "draft": "Черновик",
    "queued": "В очереди",
    "claimed": "Выдана исполнителю",
    "running": "Выполняется",
    "awaiting_review": "Ждёт аудита",
    "reviewing": "На аудите",
    "changes_requested": "Нужны правки",
    "stop_requested": "Остановка запрошена",
    "paused": "Пауза",
    "blocked": "Заблокирована",
    "completed": "Завершена",
    "cancelled": "Отменена",
}
TASK_TONE: dict[str, str] = {
    "draft": "muted",
    "queued": "info",
    "claimed": "info",
    "running": "ok",
    "awaiting_review": "info",
    "reviewing": "ok",
    "changes_requested": "warn",
    "stop_requested": "warn",
    "paused": "warn",
    "blocked": "danger",
    "completed": "ok",
    "cancelled": "muted",
}
BLOCKED_RU: dict[str, str] = {
    "iteration_limit": "Достигнут лимит неудачных аудитов",
    "loop_detected": "Обнаружен цикл правок",
    "verification_unavailable": "Проверка недоступна",
    "stop_unknown": "Остановка не подтверждена исполнителем",
    "recovery_required": "Нужно восстановление после потери исполнителя",
    "scope_change_required": "Результат вне разрешённого scope",
    "auth_required": "Требуется авторизация исполнителя",
    "quota": "Исчерпана квота",
    "runtime_failure": "Сбой среды выполнения",
}
URGENCY_RU = {"low": "Низкая", "normal": "Обычная", "high": "Высокая"}
MODE_RU = {"creative": "Творческий", "surgical": "Точечный"}
STAGE_RU = {"implement": "Реализация", "audit": "Аудит"}
KIND_RU = {
    "owner": "Владелец",
    "coordinator": "Координатор",
    "implementer": "Исполнитель",
    "auditor": "Аудитор",
    "runner": "Runner",
}
MESSAGE_KIND_RU = {
    "note": "Заметка",
    "question": "Вопрос",
    "progress": "Прогресс",
    "result_reference": "Ссылка на результат",
}
VERDICT_RU = {"PASS": "Принято", "FAIL": "Отклонено", "INCONCLUSIVE": "Не определено"}
VERDICT_TONE = {"PASS": "ok", "FAIL": "danger", "INCONCLUSIVE": "warn"}
REPORT_KIND_RU = {"implementation": "Отчёт реализации", "audit": "Отчёт аудита"}
CHECK_RU = {
    "pass": "Пройдено",
    "fail": "Провалено",
    "not_run": "Не запускалось",
    "not_verified": "Не проверено",
}
CHECK_TONE = {"pass": "ok", "fail": "danger", "not_run": "muted", "not_verified": "warn"}
CONTROL_CMD_RU = {
    "pause": "Пауза",
    "resume": "Продолжить",
    "cancel": "Отмена",
    "reassign": "Переназначение",
    "revise": "Изменение направления",
    "emergency_stop": "Аварийная остановка",
}
EVENT_RU = {
    "task.created": "Задача создана",
    "task.status_changed": "Статус изменён",
    "task.reassigned": "Исполнители переназначены",
    "task.revision_created": "Новая ревизия",
    "job.created": "Создано задание",
    "job.claimed": "Задание выдано (claim)",
    "job.dispatched": "Задание разрешено к запуску",
    "job.cancelled": "Задание отменено",
    "run.started": "Процесс запущен",
    "run.failed": "Запуск завершился ошибкой",
    "run.lost": "Исполнитель потерян",
    "run.quarantined": "Результат отклонён (карантин)",
    "run.reconciled": "Запуск согласован",
    "run.reconcile_incomplete": "Согласование не завершено",
    "report.created": "Отчёт получен",
    "message.created": "Сообщение",
    "control.requested": "Команда запрошена",
    "control.confirmed": "Остановка подтверждена",
    "control.unknown": "Остановка не подтверждена",
    "control.authority_expired": "Полномочия команды истекли",
    "project.created": "Проект создан",
    "project.updated": "Проект изменён",
}

CONN_STATES_RU = {
    "connected": "Онлайн",
    "reconnecting": "Переподключение…",
    "polling": "Опрос (WS недоступен)",
    "offline": "Нет сети",
}


def label(table: dict[str, str], key: str | None, default: str = "—") -> str:
    if key is None:
        return default
    return table.get(key, key)


def fmt_utc(ms: int | None) -> str:
    if not ms:
        return "—"
    return datetime.fromtimestamp(ms / 1000, tz=UTC).strftime("%Y-%m-%d %H:%M:%S UTC")


def fmt_iso(ms: int | None) -> str:
    if not ms:
        return ""
    return datetime.fromtimestamp(ms / 1000, tz=UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def human_age(seconds: float | None) -> str:
    if seconds is None:
        return "—"
    s = max(0, int(seconds))
    if s < 60:
        return f"{s} с назад"
    if s < 3600:
        return f"{s // 60} мин назад"
    return f"{s // 3600} ч назад"


# ---------------------------------------------------------------- stop / control honesty


def control_view(control: dict[str, Any]) -> dict[str, Any]:
    """Display state of one control. ``confirmed`` is never inferred from an HTTP 202."""
    status = control.get("status")
    has_run = control.get("target_run_id") is not None
    cmd = control.get("command", "")
    verb = CONTROL_CMD_RU.get(cmd, cmd)
    if status == "confirmed" and control.get("confirmed_at"):
        if has_run:
            return {
                "state": "confirmed", "tone": "ok", "label": "Остановлено",
                "detail": f"{verb}: получена квитанция runner — процесс отсутствует",
            }
        return {
            "state": "applied", "tone": "ok", "label": "Применено",
            "detail": f"{verb}: активного процесса не было, остановка не требовалась",
        }
    if status == "unknown":
        return {
            "state": "unknown", "tone": "danger", "label": "Остановка не подтверждена",
            "detail": f"{verb}: runner не прислал квитанцию в срок — процесс может ещё работать",
        }
    # requested / stopping / anything not proven confirmed
    return {
        "state": "requested", "tone": "warn", "label": "Запрошено",
        "detail": f"{verb}: запрос принят, ожидаем подтверждение runner (ещё не остановлено)",
    }


def activity_view(run: dict[str, Any] | None, now_ms: int, heartbeat_interval_s: int) -> dict[str, Any]:
    """Separate signals for an active run; never collapses 'leased' into 'running'."""
    if run is None:
        return {
            "state": "none", "tone": "muted", "headline": "Нет активного исполнителя",
            "signals": [],
        }
    status = run["status"]
    started = run.get("started_at")
    hb_age = max(0.0, (now_ms - run["heartbeat_at"]) / 1000) if run.get("heartbeat_at") else None
    fresh = hb_age is not None and hb_age <= heartbeat_interval_s * 2
    lease_left = (run["lease_expires_at"] - now_ms) / 1000 if run.get("lease_expires_at") else None
    signals = [
        {"key": "claimed", "label": "Лиз (claim) выдан", "ok": True,
         "value": f"эпоха {run.get('lease_epoch', '?')}"
                  + (f", истекает через {int(lease_left)} с" if lease_left is not None and lease_left > 0 else ", истёк")},
        {"key": "process", "label": "Процесс запущен", "ok": bool(started),
         "value": "да" if started else "нет подтверждения"},
        {"key": "heartbeat", "label": "Heartbeat", "ok": bool(started and fresh),
         "value": human_age(hb_age) if started else "нет (процесс не стартовал)"},
        {"key": "output", "label": "Последний вывод", "ok": False, "value": "не передаётся клиентом"},
    ]
    if status == "stopping":
        state, tone, head = "stopping", "warn", "Останавливается: ждём квитанцию runner"
    elif not started:
        state, tone, head = "claimed_only", "info", "Выдана (claim), запуск процесса не подтверждён"
    elif fresh:
        state, tone, head = "running", "ok", f"Выполняется (heartbeat {human_age(hb_age)})"
    else:
        state, tone, head = "stale", "warn", f"Запущена, но heartbeat устарел ({human_age(hb_age)})"
    return {"state": state, "tone": tone, "headline": head, "signals": signals}


def group_checks(checks: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """pass / fail / not_run / not_verified are shown as separate groups, never merged."""
    groups = []
    for status in ("pass", "fail", "not_verified", "not_run"):
        items = [c for c in checks if c.get("status") == status]
        if items:
            groups.append({"status": status, "label": CHECK_RU[status], "tone": CHECK_TONE[status], "rows": items})
    return groups
