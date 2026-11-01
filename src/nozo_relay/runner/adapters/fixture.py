"""Fixture child adapter: exercises isolation with a misbehaving stand-in for an agent (NOT a real CLI)."""

from __future__ import annotations

import json
import shutil
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from pydantic import ValidationError

from nozo_relay.domain.enums import CapabilityStatus
from nozo_relay.runner.adapters.base import (
    AdapterProbe,
    CancelPlan,
    CollectedReport,
    LaunchSpec,
    NetworkNeeds,
    Observation,
    PrepareContext,
    PreparedRun,
    ProbeCheck,
    ReconcileView,
    ReportInvalid,
    read_report_bytes,
)

CHILD_SCRIPT = Path(__file__).with_name("fixture_child.py")
PROVIDER_ENV = "FIXTURE_PROVIDER_TOKEN"


class FixtureChildAdapter:
    name = "fixture"

    def __init__(
        self,
        scenario: str = "edit",
        *,
        targets: Mapping[str, Any] | None = None,
        params: Mapping[str, Any] | None = None,
        use_provider_credential: bool = False,
        grace_seconds: float = 2.0,
        network: NetworkNeeds | None = None,
    ) -> None:
        self.scenario = scenario
        self.targets = dict(targets or {})  # attack targets: configured by the TEST, never by task/API input
        self.params = dict(params or {})
        self.use_provider_credential = use_provider_credential
        self.grace_seconds = grace_seconds
        self.network = network or NetworkNeeds()

    # ------------------------------------------------------------------ protocol
    def probe(self) -> AdapterProbe:
        ok = CHILD_SCRIPT.is_file()
        return AdapterProbe(
            adapter=self.name,
            verdict=CapabilityStatus.PROBE_PASS if ok else CapabilityStatus.PROBE_FAIL,
            version="fixture-1",
            checks=(ProbeCheck("fixture_script", "pass" if ok else "fail", str(CHILD_SCRIPT.name)),),
            explanation="fixture child, no real client" if ok else "fixture_child.py is missing",
        )

    def prepare(self, ctx: PrepareContext) -> PreparedRun:
        script = ctx.ro_dir / "fixture_child.py"
        shutil.copyfile(CHILD_SCRIPT, script)
        cfg = {
            "scenario": self.scenario, "params": self.params, "targets": self.targets,
            "workspace": str(ctx.workspace), "out_dir": str(ctx.out_dir),
        }
        (ctx.ro_dir / "task.json").write_text(json.dumps(cfg))
        (ctx.ro_dir / "task_input.json").write_text(ctx.task.model_dump_json())
        return PreparedRun(self.name, ctx.run_id, ctx.out_dir / "report.json", (script, ctx.ro_dir / "task.json"))

    def launch(self, prepared: PreparedRun, ctx: PrepareContext) -> LaunchSpec:
        return LaunchSpec(
            argv=(str(ctx.interpreter), "-I", str(prepared.ro_files[0]), str(prepared.ro_files[1])),
            credential_env=(PROVIDER_ENV,) if self.use_provider_credential else (),
            network=self.network,
        )

    def observe(self, line: str) -> Observation:
        try:
            doc = json.loads(line)
        except ValueError:
            return Observation("unparsed")
        if not isinstance(doc, dict) or doc.get("event") not in ("started", "progress", "descendants"):
            return Observation("unparsed")  # nothing on stdout can steer the supervisor
        kind = "descendants" if doc["event"] == "descendants" else "progress"
        return Observation(kind, {k: v for k, v in doc.items() if isinstance(v, (str, int, float, bool, list))})

    def collect(self, prepared: PreparedRun) -> CollectedReport:
        raw = read_report_bytes(prepared.report_path)
        try:
            return CollectedReport.model_validate_json(raw)
        except ValidationError as exc:
            fields = sorted({".".join(map(str, e["loc"])) or "?" for e in exc.errors()})[:8]
            raise ReportInvalid(f"report violates the strict schema (fields: {', '.join(fields)})") from None

    def cancel(self, prepared: PreparedRun) -> CancelPlan:
        return CancelPlan(grace_seconds=self.grace_seconds, note="fixture: SIGTERM then kill")

    def reconcile(self, receipt: Mapping[str, Any]) -> ReconcileView:
        return ReconcileView(self.name, str(receipt.get("run_id")), safe_to_discard=True, note="fixture state is disposable")
