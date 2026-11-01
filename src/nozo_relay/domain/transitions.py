"""Task / job / run state machine guards (03_DATA_MODEL "Жизненный цикл задачи").

Services never assign ``status`` directly: they call ``check_task``/``check_job``/``check_run``
(or the ``services.common`` wrappers) so an illegal transition fails loudly instead of corrupting
state. Triggers are server-derived; clients can only request typed commands.
"""

from __future__ import annotations

from nozo_relay.domain.enums import JobStatus, RunStatus, TaskStatus

T = TaskStatus
J = JobStatus
R = RunStatus


class IllegalTransition(RuntimeError):
    """A service attempted a transition the lifecycle table does not allow (programming error)."""


# trigger -> (allowed source statuses, allowed target statuses)
TASK_TRANSITIONS: dict[str, tuple[frozenset[T], frozenset[T]]] = {
    "enqueue": (frozenset({T.DRAFT}), frozenset({T.QUEUED})),
    "claim_implement": (frozenset({T.QUEUED, T.CHANGES_REQUESTED}), frozenset({T.CLAIMED})),
    "start": (frozenset({T.CLAIMED}), frozenset({T.RUNNING})),
    "implementation_result": (frozenset({T.RUNNING}), frozenset({T.AWAITING_REVIEW})),
    "claim_audit": (frozenset({T.AWAITING_REVIEW}), frozenset({T.REVIEWING})),
    "audit_pass": (frozenset({T.REVIEWING}), frozenset({T.COMPLETED})),
    "audit_fail": (frozenset({T.REVIEWING}), frozenset({T.CHANGES_REQUESTED, T.BLOCKED})),
    "audit_inconclusive": (frozenset({T.REVIEWING}), frozenset({T.BLOCKED})),
    "stop_request": (frozenset({T.CLAIMED, T.RUNNING, T.REVIEWING}), frozenset({T.STOP_REQUESTED})),
    "stop_confirmed": (
        frozenset({T.STOP_REQUESTED}),
        frozenset({T.PAUSED, T.CANCELLED, T.QUEUED, T.CHANGES_REQUESTED, T.AWAITING_REVIEW}),
    ),
    "stop_unknown": (frozenset({T.STOP_REQUESTED}), frozenset({T.BLOCKED})),
    "pause_idle": (
        frozenset({T.QUEUED, T.CHANGES_REQUESTED, T.AWAITING_REVIEW}),
        frozenset({T.PAUSED}),
    ),
    "cancel_idle": (
        frozenset(
            {T.DRAFT, T.QUEUED, T.CHANGES_REQUESTED, T.AWAITING_REVIEW, T.PAUSED, T.BLOCKED}
        ),
        frozenset({T.CANCELLED}),
    ),
    # Owner/coordinator force-complete of idle work (no active run). Distinct from auditor audit_pass.
    "complete_idle": (
        frozenset(
            {T.DRAFT, T.QUEUED, T.CHANGES_REQUESTED, T.AWAITING_REVIEW, T.PAUSED, T.BLOCKED}
        ),
        frozenset({T.COMPLETED}),
    ),
    "lease_lost": (frozenset({T.CLAIMED, T.RUNNING, T.REVIEWING}), frozenset({T.BLOCKED})),
    "runtime_fail": (
        frozenset({T.CLAIMED, T.RUNNING, T.REVIEWING}),
        frozenset({T.QUEUED, T.CHANGES_REQUESTED, T.AWAITING_REVIEW, T.BLOCKED}),
    ),
    "resume": (
        frozenset({T.PAUSED, T.BLOCKED}),
        frozenset({T.QUEUED, T.CHANGES_REQUESTED, T.AWAITING_REVIEW}),
    ),
    "reconcile": (frozenset({T.BLOCKED}), frozenset({T.PAUSED})),
    "revise_idle": (
        frozenset(
            {T.DRAFT, T.QUEUED, T.CHANGES_REQUESTED, T.AWAITING_REVIEW, T.PAUSED, T.BLOCKED}
        ),
        frozenset({T.DRAFT, T.QUEUED, T.PAUSED}),
    ),
}

JOB_TRANSITIONS: dict[J, frozenset[J]] = {
    J.READY: frozenset({J.LEASED, J.CANCELLED}),
    J.LEASED: frozenset({J.RUNNING, J.STOPPING, J.FAILED, J.LOST, J.CANCELLED}),
    J.RUNNING: frozenset({J.SUCCEEDED, J.FAILED, J.STOPPING, J.LOST, J.CANCELLED}),
    J.STOPPING: frozenset({J.CANCELLED, J.LOST}),
    J.SUCCEEDED: frozenset(),
    J.FAILED: frozenset(),
    J.LOST: frozenset(),
    J.CANCELLED: frozenset(),
}

RUN_TRANSITIONS: dict[R, frozenset[R]] = {
    R.LEASED: frozenset({R.RUNNING, R.STOPPING, R.FAILED, R.LOST, R.CANCELLED}),
    R.RUNNING: frozenset({R.SUCCEEDED, R.FAILED, R.STOPPING, R.LOST, R.CANCELLED}),
    R.STOPPING: frozenset({R.CANCELLED, R.LOST}),
    R.SUCCEEDED: frozenset(),
    R.FAILED: frozenset(),
    R.LOST: frozenset(),
    R.CANCELLED: frozenset(),
}


def check_task(trigger: str, src: str, dst: str) -> None:
    try:
        sources, targets = TASK_TRANSITIONS[trigger]
    except KeyError as exc:
        raise IllegalTransition(f"unknown task trigger {trigger!r}") from exc
    if TaskStatus(src) not in sources or TaskStatus(dst) not in targets:
        raise IllegalTransition(f"task {trigger}: {src} -> {dst} is not allowed")


def check_job(src: str, dst: str) -> None:
    if JobStatus(dst) not in JOB_TRANSITIONS[JobStatus(src)]:
        raise IllegalTransition(f"job {src} -> {dst} is not allowed")


def check_run(src: str, dst: str) -> None:
    if RunStatus(dst) not in RUN_TRANSITIONS[RunStatus(src)]:
        raise IllegalTransition(f"run {src} -> {dst} is not allowed")
