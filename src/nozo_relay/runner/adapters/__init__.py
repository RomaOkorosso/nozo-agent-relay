"""Runner adapters (07_ADAPTERS). T07: protocol + fixture child. T08: cursor_cli. T09: codex_cli. Real CLIs are started only by cli_wrapper.py."""

from nozo_relay.runner.adapters.base import (  # noqa: F401
    Adapter,
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
    TaskInput,
)
