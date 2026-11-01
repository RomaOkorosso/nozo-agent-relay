"""Test harness over the public HTTP API (owner via session+CSRF, agents via Bearer keys)."""

from __future__ import annotations

import uuid
from typing import Any

from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import Session

from conftest import BASE_URL, OWNER_PASSWORD, Env, login
from nozo_relay.auth.credentials import issue_credential
from nozo_relay.db.engine import make_session_factory, write_session
from nozo_relay.db.models import Membership, Principal
from nozo_relay.services.snapshots import fixture_snapshot_payload

MUTATING = {"POST", "PATCH", "PUT", "DELETE"}
SCOPE = {
    "allowed_paths": ["src/**"],
    "denied_paths": ["src/secret/**", ".env*"],
    "max_changed_files": 5,
    "max_diff_lines": 200,
    "allow_new_dependencies": False,
}


def uid() -> str:
    return str(uuid.uuid4())


class Api:
    def __init__(self, env: Env) -> None:
        self.env = env
        self.clock = env.clock
        self.app = env.app
        c = env.creds
        self.project_id: str = c["project"]["id"]
        self.owner_id: str = c["owner"]["principal_id"]
        agents = {a["name"]: a for a in c["agents"]}
        self.impl_id = agents["test-implementer"]["principal_id"]
        self.aud_id = agents["test-auditor"]["principal_id"]
        self.runner_id: str = c["runner"]["principal_id"]  # bootstrap default supervisor (T12/F02)
        self.keys = {
            "impl": agents["test-implementer"]["key"],
            "aud": agents["test-auditor"]["key"],
            "runner": c["runner"]["key"],
        }
        self.clients: dict[str, TestClient] = {}
        owner = TestClient(env.app, base_url=BASE_URL)  # type: ignore[arg-type]
        r = login(owner)
        assert r.status_code == 200, r.text
        self.csrf = r.json()["csrf_token"]
        self.clients["owner"] = owner
        for name, key in self.keys.items():
            self.clients[name] = TestClient(
                env.app, base_url=BASE_URL, headers={"Authorization": f"Bearer {key}"}  # type: ignore[arg-type]
            )
        self._factory = make_session_factory(env.app.state.engine)  # type: ignore[attr-defined]

    # ---------------------------------------------------------------- plumbing
    def client_for_key(self, key: str) -> TestClient:
        return TestClient(self.app, base_url=BASE_URL, headers={"Authorization": f"Bearer {key}"})  # type: ignore[arg-type]

    def req(
        self,
        who: str | TestClient,
        method: str,
        path: str,
        json: Any = None,
        *,
        idem: str | None | bool = True,
        if_match: int | str | None = None,
        headers: dict[str, str] | None = None,
    ):
        client = self.clients[who] if isinstance(who, str) else who
        h: dict[str, str] = dict(headers or {})
        if method in MUTATING:
            if idem is True:
                h["Idempotency-Key"] = uid()
            elif isinstance(idem, str):
                h["Idempotency-Key"] = idem
            if who == "owner":
                h["X-CSRF-Token"] = self.csrf
        if if_match is not None:
            h["If-Match"] = if_match if isinstance(if_match, str) else f'"{if_match}"'
        return client.request(method, path, json=json, headers=h)

    def owner_client(self) -> TestClient:
        """Independent client carrying the owner's session cookies (for concurrent requests)."""
        c = TestClient(self.app, base_url=BASE_URL)  # type: ignore[arg-type]
        c.cookies.update(self.clients["owner"].cookies)
        return c

    def db(self) -> Session:
        return self._factory()

    def p(self, suffix: str = "") -> str:
        return f"/api/v1/projects/{self.project_id}{suffix}"

    # ---------------------------------------------------------------- tasks
    def task_body(self, **over: Any) -> dict[str, Any]:
        body: dict[str, Any] = {
            "title": "Fixture task",
            "requirements": "Implement the fixture feature.",
            "acceptance": ["feature works", "tests pass"],
            "implementer_id": self.impl_id,
            "auditor_id": self.aud_id,
            "mode": "surgical",
            "autonomous": True,
            "scope": dict(SCOPE),
        }
        body.update(over)
        return body

    def create_task(self, *, who: str = "owner", idem: str | bool = True, **over: Any) -> dict[str, Any]:
        r = self.req(who, "POST", self.p("/tasks"), self.task_body(**over), idem=idem)
        assert r.status_code == 201, r.text
        return r.json()

    def get_task(self, task_id: str, who: str = "owner") -> dict[str, Any]:
        r = self.req(who, "GET", self.p(f"/tasks/{task_id}"))
        assert r.status_code == 200, r.text
        return r.json()

    def enqueue(self, task: dict[str, Any]) -> dict[str, Any]:
        r = self.req("owner", "POST", self.p(f"/tasks/{task['id']}/enqueue"), if_match=task["version"])
        assert r.status_code == 200, r.text
        return r.json()

    def queued_task(self, **over: Any) -> dict[str, Any]:
        return self.enqueue(self.create_task(**over))

    def control(self, task_id: str, command: str, *, reason: str = "test", expect: int | None = None, **extra: Any):
        t = self.get_task(task_id)
        r = self.req(
            "owner", "POST", self.p(f"/tasks/{task_id}/controls"),
            {"command": command, "reason": reason, **extra}, if_match=t["version"],
        )
        if expect is not None:
            assert r.status_code == expect, r.text
        return r

    # ---------------------------------------------------------------- runs
    def claim(self, who: str = "impl", stage: str = "implement", *, expect: int | None = 200, runner: str = "r1", supervisor: str | None = None, **kw):
        stage = "audit" if who == "aud" and stage == "implement" else stage
        r = self.req(
            who, "POST", self.p("/jobs/claim"),
            {
                "stage": stage, "claim_request_id": uid(), "runner_instance_id": runner,
                "supervisor_principal_id": supervisor or self.runner_id,
            },
            **kw,
        )
        if expect is not None:
            assert r.status_code == expect, r.text
        return r.json() if r.status_code == 200 else r

    @staticmethod
    def guard(claim: dict[str, Any], **over: Any) -> dict[str, Any]:
        g = {"lease_epoch": claim["lease_epoch"], "revision": claim["revision"], "policy_digest": claim["policy_digest"]}
        g.update(over)
        return g

    def start(self, who: str, claim: dict[str, Any], *, expect: int | None = 200, **over: Any):
        r = self.req(who, "POST", self.p(f"/runs/{claim['run_id']}/start"), self.guard(claim, **over))
        if expect is not None:
            assert r.status_code == expect, r.text
        return r

    def heartbeat(self, who: str, claim: dict[str, Any], *, expect: int | None = 200, **over: Any):
        r = self.req(who, "POST", self.p(f"/runs/{claim['run_id']}/heartbeat"), self.guard(claim, **over))
        if expect is not None:
            assert r.status_code == expect, r.text
        return r

    def impl_payload(self, claim: dict[str, Any], *, variant: str = "v1", **over: Any) -> dict[str, Any]:
        body = {
            **self.guard(claim),
            "status": "ready_for_review",
            "snapshot": fixture_snapshot_payload(claim["task_id"], claim["revision"], variant),
            "summary": f"implemented {variant}",
            "checks": [{"id": "unit", "command_label": "pytest -q", "status": "pass", "expected": "green", "observed": "green"}],
            "artifacts": [],
            "scope_manifest": {
                "changed_files": [{"path": "src/app.py", "change": "modified"}],
                "diff_lines": 12,
                "new_dependencies": [],
            },
        }
        body.update(over)
        return body

    def submit_impl(self, claim: dict[str, Any], *, expect: int | None = 200, idem: str | bool = True, **over: Any):
        r = self.req("impl", "POST", self.p(f"/runs/{claim['run_id']}/implementation-result"), self.impl_payload(claim, **over), idem=idem)
        if expect is not None:
            assert r.status_code == expect, r.text
        return r

    @staticmethod
    def pass_checks() -> list[dict[str, Any]]:
        return [{"id": "c1", "command_label": "pytest -q", "status": "pass", "expected": "green", "observed": "green"}]

    def finding(self, n: int = 1, **over: Any) -> dict[str, Any]:
        f = {
            "invariant_key": f"inv.{n}", "component": "core", "severity": "S1",
            "reproduction": f"run step {n}", "expected": "ok", "actual": "broken",
        }
        f.update(over)
        return f

    def audit_payload(self, claim: dict[str, Any], verdict: str, **over: Any) -> dict[str, Any]:
        body: dict[str, Any] = {
            **self.guard(claim),
            "snapshot_id": claim["input_snapshot"]["id"],
            "verdict": verdict,
            "summary": verdict,
            "checks": self.pass_checks(),
            "findings": [],
            "evidence_level": "INTEGRATION_FIXTURE",
            "limitations": [],
        }
        if verdict == "FAIL":
            body["findings"] = [self.finding(1)]
            body["checks"] = [{"id": "c1", "command_label": "pytest -q", "status": "fail"}]
        if verdict == "INCONCLUSIVE":
            body["limitations"] = ["could not run the suite"]
            body["checks"] = [{"id": "c1", "command_label": "pytest -q", "status": "not_run"}]
        body.update(over)
        return body

    def submit_audit(self, claim: dict[str, Any], verdict: str, *, expect: int | None = 200, idem: str | bool = True, **over: Any):
        r = self.req("aud", "POST", self.p(f"/runs/{claim['run_id']}/audit-result"), self.audit_payload(claim, verdict, **over), idem=idem)
        if expect is not None:
            assert r.status_code == expect, r.text
        return r

    # ---------------------------------------------------------------- higher-level cycles
    def implement(self, task_id: str | None = None, *, variant: str = "v1", **over: Any) -> dict[str, Any]:
        """claim + start + submit implementation; returns the implement claim."""
        c = self.claim("impl", "implement")
        if task_id:
            assert c["task_id"] == task_id
        self.start("impl", c)
        self.submit_impl(c, variant=variant, **over)
        return c

    def audit(self, verdict: str, **over: Any) -> dict[str, Any]:
        c = self.claim("aud", "audit")
        self.start("aud", c)
        self.submit_audit(c, verdict, **over)
        return c

    # ---------------------------------------------------------------- supervisor
    def make_runner(self, name: str = "test-supervisor") -> str:
        """Key of the bootstrap default supervisor: the principal every claim binds its run to (T12/F02).

        Use ``make_principal("runner", ...)`` for an UNRELATED runner that must not be able to confirm stops.
        """
        return self.keys["runner"]

    def stopped(self, claim: dict[str, Any], control: dict[str, Any], *, absent: bool = True, expect: int | None = 200, **over: Any):
        body = {
            "control_id": control["id"], "target_epoch": claim["lease_epoch"],
            "process_tree_absent": absent, "receipt": "fixture receipt",
        }
        body.update(over)
        r = self.req("runner", "POST", self.p(f"/runs/{claim['run_id']}/stopped"), body)
        if expect is not None:
            assert r.status_code == expect, r.text
        return r

    def make_principal(self, kind: str, name: str) -> tuple[str, str]:
        """Register an identity + key (what the owner CLI does). Returns (principal_id, key)."""
        with write_session(self.app.state.engine) as ws:  # type: ignore[attr-defined]
            p = Principal(display_name=name, kind=kind, active=True, created_at=self.clock.now_ms())
            ws.add(p)
            ws.flush()
            ws.add(Membership(principal_id=p.id, project_id=self.project_id, role=kind))
            key, _ = issue_credential(ws, self.clock, p.id)
        return p.id, key.full_key

    def restart(self) -> "Api":
        """New app instance over the same database (server restart); owner logs in again."""
        import dataclasses

        from nozo_relay.main import create_app

        return Api(dataclasses.replace(self.env, app=create_app(self.env.settings, self.env.clock)))

    def jobs(self, task_id: str) -> list[Any]:
        from nozo_relay.db.models import Job

        with self.db() as s:
            return list(s.execute(select(Job).where(Job.task_id == task_id)).scalars().all())

    # ---------------------------------------------------------------- inspection
    def events(self, after: int = 0, limit: int = 200) -> list[dict[str, Any]]:
        r = self.req("owner", "GET", self.p(f"/events?after_seq={after}&limit={limit}"))
        assert r.status_code == 200, r.text
        return r.json()["events"]

    def statuses(self, model: Any) -> list[str]:
        with self.db() as s:
            return [r for r in s.execute(select(model.status)).scalars()]

    def count(self, model: Any, *where: Any) -> int:
        from sqlalchemy import func

        with self.db() as s:
            return s.execute(select(func.count()).select_from(model).where(*where)).scalar_one()


__all__ = ["Api", "OWNER_PASSWORD", "SCOPE", "uid"]
