"""Helper process for the T07 crash test: starts a run, reports its ids, then dies abruptly (SIGKILL on itself).

Run as ``python tests/t07_crash_driver.py <config.json>``. The sandboxed child (and its descendants) keep
running: that is exactly the state a supervisor crash leaves behind.
"""

from __future__ import annotations

import json
import os
import signal
import sys
from pathlib import Path

from nozo_relay.runner.adapters.fixture import FixtureChildAdapter
from nozo_relay.runner.supervisor import HeartbeatOutcome, RunRequest, Supervisor, SupervisorConfig
from nozo_relay.services.repo_bindings import BindingInfo, StaticBindingRegistry

cfg = json.loads(Path(sys.argv[1]).read_text())
binding = BindingInfo(id=cfg["binding_id"], project_id=cfg["project_id"], canonical_root=Path(cfg["root"]), repo_identity=cfg["identity"])
reg = StaticBindingRegistry([binding])
sup = Supervisor(
    SupervisorConfig(state_dir=Path(cfg["state_dir"]), heartbeat_interval=0.1, watchdog_window=600, use_cgroup=cfg.get("use_cgroup")),
    {"fixture": FixtureChildAdapter(cfg["scenario"], targets=cfg.get("targets", {}), params=cfg.get("params", {}))},
    reg,
)
req = RunRequest(
    project_id=cfg["project_id"], task_id="task-1", job_id=cfg["job_id"], run_id=cfg["run_id"], binding_id=cfg["binding_id"],
    adapter="fixture", lease_epoch=1, revision=1, policy_digest="a" * 64, mode="surgical", scope=cfg["scope"],
    task={"title": "crash", "requirements": "hang", "acceptance": ["x"]},
)
h = sup.start(req, heartbeat=lambda: HeartbeatOutcome.OK)
if h.outcome is not None:
    print(json.dumps({"blocked": h.outcome.reason}), flush=True)
    sys.exit(3)
h.wait_for_event("progress", 10)
print(json.dumps({"run_id": req.run_id, "child_pid": h.pid}), flush=True)
os.kill(os.getpid(), signal.SIGKILL)
