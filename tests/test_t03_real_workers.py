"""End-to-end mock cycles with REAL OS processes: uvicorn (thread) + ``test_worker`` subprocesses.

The workers speak the public REST protocol over loopback HTTP with no access to the database.
Scripted behaviours (pass/fail/inconclusive/wait/crash/api_fail) replace any real LLM.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import threading
import time
from collections.abc import Callable
from pathlib import Path

import pytest
import uvicorn

from api_helpers import Api
from conftest import OWNER_PASSWORD, Env, make_settings
from nozo_relay.bootstrap import bootstrap, credentials_path
from nozo_relay.clock import SystemClock
from nozo_relay.db.models import Job, Run
from nozo_relay.main import create_app


class Live:
    def __init__(self, tmp_path: Path) -> None:
        settings = make_settings(
            tmp_path, lease_ttl_seconds=3, heartbeat_interval_seconds=1,
            watchdog_interval_seconds=0.3, stop_confirm_deadline_seconds=20,
        )
        clock = SystemClock()
        bootstrap(settings, owner_password=OWNER_PASSWORD, clock=clock)
        creds = json.loads(credentials_path(settings).read_text())
        self.app = create_app(settings, clock)
        self.env = Env(settings=settings, clock=clock, creds=creds, app=self.app)  # type: ignore[arg-type]
        self.api = Api(self.env)
        cfg = uvicorn.Config(self.app, host="127.0.0.1", port=0, log_level="warning", lifespan="on")
        self.server = uvicorn.Server(cfg)
        self.thread = threading.Thread(target=self.server.run, daemon=True)
        self.thread.start()
        deadline = time.monotonic() + 15
        while not (self.server.started and self.server.servers):
            assert time.monotonic() < deadline, "uvicorn did not start"
            time.sleep(0.05)
        self.port = self.server.servers[0].sockets[0].getsockname()[1]
        self.procs: list[subprocess.Popen] = []
        self.supervisor_key = self.api.make_runner()

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self.port}"

    def worker(self, stage: str, script: str, *, supervisor: bool = False, **flags) -> subprocess.Popen:
        key = self.api.keys["impl" if stage == "implement" else "aud"]
        env = {**os.environ, "NOZO_WORKER_KEY": key}
        if supervisor:
            env["NOZO_SUPERVISOR_KEY"] = self.supervisor_key
        cmd = [
            sys.executable, "-m", "nozo_relay.runner.test_worker", "--url", self.url,
            "--project-id", self.api.project_id, "--stage", stage, "--script", script,
            "--supervisor-principal-id", self.api.runner_id, "--poll-interval", "0.1", "--idle-timeout", flags.pop("idle_timeout", "20"),
        ]
        for k, v in flags.items():
            cmd += [f"--{k.replace('_', '-')}"] + ([] if v is True else [str(v)])
        p = subprocess.Popen(cmd, env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        self.procs.append(p)
        return p

    def close(self) -> None:
        for p in self.procs:
            if p.poll() is None:
                p.kill()
            if p.stdout:
                p.stdout.close()
            p.wait(timeout=5)
        self.server.should_exit = True
        self.thread.join(timeout=10)


@pytest.fixture
def live(tmp_path: Path):
    lv = Live(tmp_path)
    try:
        yield lv
    finally:
        lv.close()


def wait_for(cond: Callable[[], object], timeout: float = 30.0, what: str = "condition"):
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        v = cond()
        if v:
            return v
        time.sleep(0.1)
    raise AssertionError(f"timed out waiting for {what}")


def finish(p: subprocess.Popen, timeout: float = 40.0) -> tuple[int, list[dict]]:
    out, _ = p.communicate(timeout=timeout)
    events = []
    for line in out.splitlines():
        try:
            events.append(json.loads(line))
        except ValueError:
            pass
    return p.returncode, events


def status(api: Api, task_id: str) -> str:
    return api.get_task(task_id)["status"]


def test_real_workers_full_success_cycle(live: Live):
    api = live.api
    t = api.queued_task()
    impl = live.worker("implement", "pass", max_runs=1)
    aud = live.worker("audit", "pass", max_runs=1)
    assert finish(impl)[0] == 0
    assert finish(aud)[0] == 0
    wait_for(lambda: status(api, t["id"]) == "completed", what="task completed")
    assert api.get_task(t["id"])["failed_review_count"] == 0


def test_real_workers_repair_cycle_fail_then_pass(live: Live):
    api = live.api
    t = api.queued_task()
    impl = live.worker("implement", "pass", max_runs=2)
    aud = live.worker("audit", "fail,pass", max_runs=2)
    assert finish(impl)[0] == 0
    assert finish(aud)[0] == 0
    wait_for(lambda: status(api, t["id"]) == "completed", what="task completed after repair")
    assert api.get_task(t["id"])["failed_review_count"] == 1
    assert api.count(Job, Job.stage == "implement") == 2


def test_real_workers_three_fails_hit_iteration_limit_without_a_fourth_job(live: Live):
    api = live.api
    t = api.queued_task()
    impl = live.worker("implement", "pass", max_runs=3)
    aud = live.worker("audit", "fail", max_runs=3)
    assert finish(impl)[0] == 0
    assert finish(aud)[0] == 0
    wait_for(lambda: status(api, t["id"]) == "blocked", what="blocked after 3 FAILs")
    assert api.get_task(t["id"])["blocked_reason"] in {"iteration_limit", "loop_detected"}
    assert api.count(Job, Job.stage == "implement") == 3


def test_real_worker_retries_api_failure_then_succeeds(live: Live):
    api = live.api
    t = api.queued_task()
    impl = live.worker("implement", "api_fail,pass", max_runs=2)
    aud = live.worker("audit", "pass", max_runs=1)
    assert finish(impl)[0] == 0
    assert finish(aud)[0] == 0
    wait_for(lambda: status(api, t["id"]) == "completed", what="completed after retry")
    assert sorted(api.statuses(Run)) == ["failed", "succeeded", "succeeded"]  # impl fail, impl retry, audit


def test_real_worker_stops_on_owner_cancel_and_reports_receipt(live: Live, tmp_path: Path):
    api = live.api
    t = api.queued_task()
    receipt = tmp_path / "receipt.json"
    w = live.worker("implement", "wait", supervisor=True, max_runs=1, wait_seconds=30, receipt_file=str(receipt))
    wait_for(lambda: status(api, t["id"]) == "running", what="run started")
    assert api.control(t["id"], "cancel", expect=202)
    code, events = finish(w)
    assert code == 0
    assert any(e.get("event") == "stopped_reported" and e.get("status") == 200 for e in events), events
    wait_for(lambda: status(api, t["id"]) == "cancelled", what="cancelled after receipt")
    assert api.count(Run, Run.status == "cancelled") == 1
    assert not any("key" in json.dumps(e).lower() and "relay_" in json.dumps(e) for e in events)


def test_real_worker_crash_becomes_recovery_required_and_no_auto_reissue(live: Live):
    api = live.api
    t = api.queued_task()
    w = live.worker("implement", "crash", max_runs=1)
    code, _ = finish(w)
    assert code == 7
    wait_for(lambda: status(api, t["id"]) == "blocked", timeout=20, what="blocked after lease expiry")
    task = api.get_task(t["id"])
    assert task["blocked_reason"] == "recovery_required"
    # no second worker may take it over until the owner reconciles
    assert api.claim("impl", expect=None).status_code == 204
    assert api.count(Run, Run.status == "lost") == 1
