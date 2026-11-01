"""Deterministic test agent (implementer OR auditor) as a separate OS process. No LLM, no shell.

It speaks the real REST protocol: claim -> start -> heartbeat -> result/fail, reusing one
Idempotency-Key per logical operation so a lost response is retried, never re-executed. It never
executes anything taken from task input; results are synthetic fixtures derived from hashes.

Behaviour per processed run is taken from ``--script`` (comma separated, last value repeats):

  pass          implementer: submit a valid fixture implementation;  auditor: verdict PASS
  fail          auditor: verdict FAIL with one blocking finding
  inconclusive  auditor: verdict INCONCLUSIVE (limitations, not_run check)
  wait          start, then heartbeat until stopped by a control / fenced / --wait-seconds elapsed
  crash         start, then die abruptly (os._exit) without result: server must treat the lease as lost
  api_fail      report a retryable technical failure via POST /runs/{r}/fail

On a ``pending_control`` heartbeat the worker "terminates its (fixture) child" and, when a supervisor
key is supplied, posts the ``stopped`` receipt (a separate narrow credential, never the run lease).

Keys are read from environment variables (names given on the command line), never printed.
Usage:  python -m nozo_relay.runner.test_worker --help
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
import time
import uuid
from pathlib import Path
from typing import Any

import httpx

EXIT_OK = 0
EXIT_USAGE = 2
EXIT_IDLE = 3
EXIT_API = 4
EXIT_CRASH = 7
RETRY_BACKOFF = (0.2, 0.5, 1.0, 2.0)


def sha(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


def emit(event: str, **fields: Any) -> None:
    """One JSON line on stdout; contains ids/status only, never credentials."""
    print(json.dumps({"event": event, **fields}, sort_keys=True), flush=True)


class Api:
    def __init__(self, base_url: str, key: str, project_id: str) -> None:
        self.http = httpx.Client(
            base_url=base_url.rstrip("/"),
            headers={"Authorization": f"Bearer {key}"},
            timeout=httpx.Timeout(10.0),
        )
        self.project = project_id

    def post(self, path: str, body: dict[str, Any], *, key: str | None = None, retries: bool = True) -> httpx.Response:
        """POST with ONE idempotency key reused across retries (lost response => same effect)."""
        key = key or str(uuid.uuid4())
        last: Exception | None = None
        for delay in (0.0, *RETRY_BACKOFF) if retries else (0.0,):
            if delay:
                time.sleep(delay)
            try:
                r = self.http.post(f"/api/v1/projects/{self.project}{path}", json=body, headers={"Idempotency-Key": key})
            except httpx.TransportError as exc:
                last = exc
                continue
            if r.status_code in (502, 503, 504):
                last = RuntimeError(f"http {r.status_code}")
                continue
            return r
        raise RuntimeError(f"request failed after retries: {type(last).__name__ if last else 'unknown'}")


def parse_script(raw: str) -> list[str]:
    items = [s.strip() for s in raw.split(",") if s.strip()]
    allowed = {"pass", "fail", "inconclusive", "wait", "crash", "api_fail"}
    bad = [i for i in items if i not in allowed]
    if not items or bad:
        raise ValueError(f"invalid --script {raw!r}; allowed: {sorted(allowed)}")
    return items


def guard_of(claim: dict[str, Any]) -> dict[str, Any]:
    return {
        "lease_epoch": claim["lease_epoch"],
        "revision": claim["revision"],
        "policy_digest": claim["policy_digest"],
    }


def fixture_path(scope: dict[str, Any]) -> str:
    pattern = scope["allowed_paths"][0]
    cut = min([i for i in (pattern.find("*"), pattern.find("?"), pattern.find("[")) if i != -1] or [len(pattern)])
    prefix = pattern[:cut]
    return f"{prefix}fixture.txt" if prefix.endswith("/") or not prefix else f"{prefix}/fixture.txt"


def implementation_body(claim: dict[str, Any], *, constant_diff: bool) -> dict[str, Any]:
    ti = claim["task_input"]
    variant = "const" if constant_diff else f"round{ti['failed_review_count']}"
    seed = f"{claim['task_id']}|{claim['revision']}|{variant}"
    return {
        **guard_of(claim),
        "status": "ready_for_review",
        "snapshot": {
            "base_commit": sha(f"base|{claim['task_id']}")[:40],
            "head_commit": sha(f"head|{seed}")[:40],
            "tree_hash": sha(f"tree|{seed}"),
            "diff_hash": sha(f"diff|{seed}"),
            "manifest": {"fixture": True, "variant": variant},
        },
        "summary": f"fixture implementation ({variant})",
        "checks": [
            {"id": "fixture-unit", "command_label": "fixture unit suite", "status": "pass",
             "expected": "all green", "observed": "all green", "duration_ms": 1, "exit_code": 0}
        ],
        "artifacts": [],
        "scope_manifest": {
            "changed_files": [{"path": fixture_path(ti["scope"]), "change": "modified"}],
            "diff_lines": 1,
            "new_dependencies": [],
        },
    }


def audit_body(claim: dict[str, Any], verdict: str, *, same_invariant: bool) -> dict[str, Any]:
    ti = claim["task_input"]
    n = 0 if same_invariant else ti["failed_review_count"] + 1
    body: dict[str, Any] = {
        **guard_of(claim),
        "snapshot_id": (claim.get("input_snapshot") or {}).get("id"),
        "verdict": verdict,
        "summary": f"fixture audit {verdict}",
        "checks": [{"id": "fixture-check", "command_label": "fixture audit suite", "status": "pass",
                    "expected": "ok", "observed": "ok", "duration_ms": 1, "exit_code": 0}],
        "findings": [],
        "evidence_level": "INTEGRATION_FIXTURE",
        "limitations": [],
    }
    if verdict == "FAIL":
        body["checks"][0].update(status="fail", observed="fixture defect", exit_code=1)
        body["findings"] = [{
            "invariant_key": f"fixture.invariant.{n}",
            "component": "fixture.component",
            "severity": "S1",
            "reproduction": f"run the fixture check for defect {n}",
            "expected": "fixture invariant holds",
            "actual": "fixture invariant violated",
        }]
    elif verdict == "INCONCLUSIVE":
        body["checks"][0].update(status="not_run", observed="")
        body["limitations"] = ["fixture auditor could not run the verification suite"]
    return body


class Worker:
    def __init__(self, args: argparse.Namespace, key: str, supervisor_key: str | None) -> None:
        self.args = args
        self.api = Api(args.url, key, args.project_id)
        self.sup = Api(args.url, supervisor_key, args.project_id) if supervisor_key else None
        self.script = parse_script(args.script)
        self.processed = 0
        self.receipt_path = Path(args.receipt_file) if args.receipt_file else None

    def receipt(self, **fields: Any) -> None:
        """Durable local receipt (what a real supervisor persists before spawning anything)."""
        if self.receipt_path is None:
            return
        data = {}
        if self.receipt_path.exists():
            data = json.loads(self.receipt_path.read_text())
        data.update(fields)
        tmp = self.receipt_path.with_suffix(".tmp")
        tmp.write_text(json.dumps(data, sort_keys=True))
        os.replace(tmp, self.receipt_path)

    # ---------------------------------------------------------------- claim loop
    def claim(self) -> dict[str, Any] | None:
        deadline = time.monotonic() + self.args.idle_timeout
        while True:
            r = self.api.post(
                "/jobs/claim",
                {
                    "stage": self.args.stage,
                    "claim_request_id": str(uuid.uuid4()),
                    "runner_instance_id": self.args.runner_instance_id,
                    **({"supervisor_principal_id": self.args.supervisor_principal_id} if self.args.supervisor_principal_id else {}),
                },
            )
            if r.status_code == 200:
                return r.json()
            if r.status_code not in (204, 409):  # 409 project_paused: wait, do not spin
                emit("claim_error", status=r.status_code, code=_code(r))
                if r.status_code in (401, 403):
                    raise SystemExit(EXIT_API)
            if time.monotonic() >= deadline:
                return None
            time.sleep(self.args.poll_interval)

    def run(self) -> int:
        while self.args.max_runs == 0 or self.processed < self.args.max_runs:
            claim = self.claim()
            if claim is None:
                emit("idle_timeout", processed=self.processed)
                return EXIT_IDLE if self.processed == 0 else EXIT_OK
            behavior = self.script[min(self.processed, len(self.script) - 1)]
            self.processed += 1
            code = self.handle(claim, behavior)
            if code != EXIT_OK:
                return code
        return EXIT_OK

    # ---------------------------------------------------------------- one run
    def handle(self, claim: dict[str, Any], behavior: str) -> int:
        run_path = f"/runs/{claim['run_id']}"
        self.receipt(run_id=claim["run_id"], job_id=claim["job_id"], lease_epoch=claim["lease_epoch"],
                     stage=claim["stage"], state="claimed")
        emit("claimed", run_id=claim["run_id"], stage=claim["stage"], epoch=claim["lease_epoch"], behavior=behavior)
        r = self.api.post(f"{run_path}/start", guard_of(claim))
        if r.status_code != 200:  # server refused: never spawn
            emit("start_refused", status=r.status_code, code=_code(r))
            return EXIT_API
        self.receipt(state="started")
        emit("started", run_id=claim["run_id"])

        hb = self.args.heartbeat_interval or float(claim.get("heartbeat_interval_seconds", 15))
        if behavior == "crash":
            emit("crashing", run_id=claim["run_id"])
            sys.stdout.flush()
            os._exit(EXIT_CRASH)
        if behavior == "wait":
            return self.wait_for_stop(claim, run_path, hb)
        if self.args.work_seconds > 0 and not self.work(claim, run_path, hb, self.args.work_seconds):
            return EXIT_OK
        if behavior == "api_fail":
            r = self.api.post(f"{run_path}/fail", {**guard_of(claim), "error_code": "fixture_failure",
                                                   "retryable": True, "evidence": "deterministic fixture failure"})
            emit("failed_reported", status=r.status_code, outcome=(r.json() or {}).get("outcome") if r.status_code == 200 else None)
            return EXIT_OK if r.status_code == 200 else EXIT_API
        if claim["stage"] == "implement":
            body = implementation_body(claim, constant_diff=self.args.constant_diff)
            r = self.api.post(f"{run_path}/implementation-result", body)
        else:
            verdict = {"pass": "PASS", "fail": "FAIL", "inconclusive": "INCONCLUSIVE"}[behavior]
            body = audit_body(claim, verdict, same_invariant=self.args.same_invariant)
            r = self.api.post(f"{run_path}/audit-result", body)
        emit("result_submitted", status=r.status_code, code=_code(r), run_id=claim["run_id"])
        self.receipt(state="reported", http_status=r.status_code)
        return EXIT_OK if r.status_code == 200 else EXIT_API

    def heartbeat(self, claim: dict[str, Any], run_path: str) -> tuple[str, dict[str, Any] | None]:
        r = self.api.post(f"{run_path}/heartbeat", guard_of(claim), retries=False)
        if r.status_code == 200:
            return "ok", r.json().get("pending_control")
        emit("fenced", status=r.status_code, code=_code(r))  # stale/lost/revoked: stop at once
        return "fenced", None

    def work(self, claim: dict[str, Any], run_path: str, hb: float, seconds: float) -> bool:
        end = time.monotonic() + seconds
        while time.monotonic() < end:
            time.sleep(min(hb, max(0.0, end - time.monotonic())))
            state, pending = self.heartbeat(claim, run_path)
            if state == "fenced":
                return False
            if pending:
                self.stop(claim, run_path, pending)
                return False
        return True

    def wait_for_stop(self, claim: dict[str, Any], run_path: str, hb: float) -> int:
        end = time.monotonic() + self.args.wait_seconds
        while time.monotonic() < end:
            time.sleep(hb)
            state, pending = self.heartbeat(claim, run_path)
            if state == "fenced":
                return EXIT_OK
            if pending:
                self.stop(claim, run_path, pending)
                return EXIT_OK
        emit("wait_elapsed", run_id=claim["run_id"])
        return EXIT_OK

    def stop(self, claim: dict[str, Any], run_path: str, pending: dict[str, Any]) -> None:
        emit("stopping", control=pending["command"], control_id=pending["control_id"])
        self.receipt(state="stopping", control_id=pending["control_id"])
        # Fixture child == nothing to kill: the process tree is trivially absent.
        if self.sup is None:
            emit("no_supervisor_credential")  # server will mark the control `unknown`
            return
        r = self.sup.post(
            f"{run_path}/stopped",
            {"control_id": pending["control_id"], "target_epoch": pending["target_epoch"],
             "process_tree_absent": True, "receipt": f"fixture worker pid={os.getpid()} exited cleanly"},
        )
        emit("stopped_reported", status=r.status_code, code=_code(r))
        self.receipt(state="stopped", http_status=r.status_code)


def _code(r: httpx.Response) -> str | None:
    try:
        return r.json().get("error", {}).get("code")
    except Exception:  # noqa: BLE001
        return None


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="nozo-test-worker", description=__doc__.split("\n\n")[0])
    p.add_argument("--url", default="http://127.0.0.1:8765")
    p.add_argument("--project-id", required=True)
    p.add_argument("--stage", choices=["implement", "audit"], required=True)
    p.add_argument("--key-env", default="NOZO_WORKER_KEY", help="env var holding the agent key")
    p.add_argument("--supervisor-principal-id", default=os.environ.get("NOZO_SUPERVISOR_PRINCIPAL_ID"),
                   help="runner principal id bound to each claimed run (omit only if the project has exactly one runner)")
    p.add_argument("--supervisor-key-env", default="NOZO_SUPERVISOR_KEY", help="optional env var with the runner key")
    p.add_argument("--script", default="pass", help="comma list: pass,fail,inconclusive,wait,crash,api_fail")
    p.add_argument("--runner-instance-id", default=f"test-worker-{os.getpid()}")
    p.add_argument("--max-runs", type=int, default=1, help="0 = until idle timeout")
    p.add_argument("--poll-interval", type=float, default=0.3)
    p.add_argument("--idle-timeout", type=float, default=30.0)
    p.add_argument("--heartbeat-interval", type=float, default=0.0, help="0 = server suggestion")
    p.add_argument("--work-seconds", type=float, default=0.0)
    p.add_argument("--wait-seconds", type=float, default=60.0)
    p.add_argument("--constant-diff", action="store_true", help="implementer: identical diff every round")
    p.add_argument("--same-invariant", action="store_true", help="auditor FAIL: same invariant every round")
    p.add_argument("--receipt-file", default=None)
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    key = os.environ.get(args.key_env)
    if not key:
        print(f"error: environment variable {args.key_env} is not set", file=sys.stderr)
        return EXIT_USAGE
    try:
        worker = Worker(args, key, os.environ.get(args.supervisor_key_env) or None)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_USAGE
    try:
        return worker.run()
    except RuntimeError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_API


if __name__ == "__main__":
    raise SystemExit(main())
