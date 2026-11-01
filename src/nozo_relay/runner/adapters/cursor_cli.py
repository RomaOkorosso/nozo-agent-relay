"""T08: Cursor CLI headless executor adapter (``agent -p --output-format stream-json``).

This is the LOCAL CLI workflow only; it is NOT remote control of a live Cursor IDE window (07_ADAPTERS).

Policy decisions (all enforced structurally, with tests):

* ``--yolo`` is never emitted. ``--force`` (its alias) is only emitted when the OWNER constructs
  ``CursorPolicy(allow_force=True)``; it is never a default, never a retry step after a permission failure, and it
  never replaces the OS sandbox (Landlock/seccomp/cgroup of T07) or the post-run scope/manifest checks.
* ``--sandbox enabled`` is always passed; the adapter has no switch to disable it.
* Authentication: the user's interactive login lives in the user's real HOME, which the sandbox deliberately does not
  mount. A sandboxed run therefore authenticates ONLY through ``CURSOR_API_KEY`` supplied by the supervisor's
  ``CredentialsManager`` (env, never argv). Without it the adapter's probe is ``blocked_external`` with the exact owner action.
* A failed/blocked run is final: auth / 429 / quota / permission / malformed output never starts a second CLI, never switches
  model/provider/plan, never buys anything.
* Provider egress: T07's profile denies UDP/DNS/unix sockets. The Cursor endpoint needs DNS + TCP/443. Until the supervisor
  provides an allow-listed egress path, ``assume_provider_network`` stays False and the probe reports the gap.
"""

from __future__ import annotations

import os
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from nozo_relay.domain.enums import CapabilityStatus
from nozo_relay.runner.adapters.base import (
    AdapterProbe,
    LaunchSpec,
    NetworkNeeds,
    PrepareContext,
    PreparedRun,
    ProbeCheck,
)
from nozo_relay.runner.adapters.cli_common import (
    FORBIDDEN_ARGV,
    BinaryLocation,
    ProbeCache,
    WrappedCliAdapter,
    discover_binary,
    host_env,
    parse_version,
    run_probe,
)
from nozo_relay.runner.adapters.cli_wrapper import REPORT_BEGIN, REPORT_END
from nozo_relay.runner.credentials import CredentialError, CredentialsManager

ENV_BIN = "NOZO_CURSOR_AGENT_BIN"
API_KEY_ENV = "CURSOR_API_KEY"
PROVIDER_ENDPOINT = "api2.cursor.sh"
KNOWN_GLOBS = (
    "~/.config/Cursor/User/globalStorage/anysphere.cursor-agent-worker/agent-cli/.local/share/cursor-agent/versions/*/cursor-agent",
    "~/.local/share/cursor-agent/versions/*/cursor-agent",
    "~/.local/bin/agent",
    "~/.local/bin/cursor-agent",
)
REQUIRED_FLAGS = ("--print", "--output-format", "--sandbox", "--workspace", "--trust")
DOCS_URL = "https://cursor.com/docs/cli/headless"


@dataclass(frozen=True)
class CursorPolicy:
    """Owner-set policy. Nothing in task input, model output or an API payload can change it."""

    allow_force: bool = False  # emits --force; NEVER a default, NEVER a retry step; OS sandbox + scope checks stay in force
    model: str | None = None
    timeout_seconds: float = 1500.0


def implementer_prompt(task: Any, scope_hint: Mapping[str, Any] | None = None) -> str:
    acc = "\n".join(f"- {a}" for a in task.acceptance)
    scope = ""
    if scope_hint:
        scope = (
            "\nScope (enforced independently; anything outside is rejected and the whole run is quarantined):\n"
            f"- allowed paths: {', '.join(scope_hint.get('allowed_paths', []))}\n"
            f"- denied paths (never touch, never read): {', '.join(scope_hint.get('denied_paths', []))}\n"
        )
    return (
        "You are the IMPLEMENTER in an automated relay. Work only inside the current workspace directory.\n"
        f"Task: {task.title}\n\nRequirements:\n{task.requirements}\n\nAcceptance criteria:\n{acc}\n{scope}\n"
        "Rules: make the smallest change that satisfies the requirements; do not add dependencies; do not run git commit/push; "
        "do not try to read or modify anything outside the workspace.\n"
        "When finished, end your final message with exactly one block:\n"
        f"{REPORT_BEGIN}\n"
        '{"status": "ready_for_review", "summary": "<what you changed and why>"}\n'
        f"{REPORT_END}\n"
        'Use status "blocked" or "failed" (with a clear summary) if you could not complete the task. '
        "Do not add any other keys to that JSON object."
    )


class CursorCliAdapter(WrappedCliAdapter):
    name = "cursor"
    provider = "cursor"

    def __init__(
        self,
        binary: str | os.PathLike[str] | None = None,
        *,
        policy: CursorPolicy | None = None,
        credentials: CredentialsManager | None = None,
        scope_hint: Mapping[str, Any] | None = None,
        assume_provider_network: bool = False,
        network: NetworkNeeds | None = None,
        probe_env: Mapping[str, str] | None = None,
        environ: Mapping[str, str] | None = None,
        probe_ttl: float = 60.0,
    ) -> None:
        self.policy = policy or CursorPolicy()
        self.credentials = credentials
        self.scope_hint = dict(scope_hint) if scope_hint else None
        self.assume_provider_network = assume_provider_network
        self.network = network or NetworkNeeds("tcp_connect", (443,))
        self._explicit = binary
        self._environ = os.environ if environ is None else environ
        self._probe_env = dict(probe_env or {})
        self._cache = ProbeCache(probe_ttl)
        self._location: BinaryLocation | None = None

    # ------------------------------------------------------------------------------------------ discovery
    def locate(self) -> BinaryLocation:
        self._location = discover_binary(explicit=self._explicit, env_name=ENV_BIN, names=("agent", "cursor-agent"), globs=KNOWN_GLOBS,
                                         environ=self._environ)
        return self._location

    def _credential_registered(self) -> bool:
        if self.credentials is None:
            return False
        try:
            self.credentials.provider_env(self.name, (API_KEY_ENV,))
            return True
        except CredentialError:
            return False

    def _host_probe_env(self) -> tuple[dict[str, str], list[str]]:
        extra = dict(self._probe_env)
        key = extra.get(API_KEY_ENV) or self._environ.get(API_KEY_ENV)
        if key:
            extra[API_KEY_ENV] = key
        return host_env(extra, self._environ), [key] if key else []

    # ---------------------------------------------------------------------------------------------- probe
    def probe_fresh(self) -> AdapterProbe:
        self._cache.clear()
        return self.probe()

    def probe(self) -> AdapterProbe:
        cached = self._cache.get()
        if cached is not None:
            return cached
        return self._cache.put(self._probe())

    def _probe(self) -> AdapterProbe:
        checks: list[ProbeCheck] = []
        loc = self.locate()
        if loc.path is None:
            checks.append(ProbeCheck("binary", "blocked", f"Cursor CLI not found ({loc.how}); looked at {len(loc.tried)} location(s)"))
            return AdapterProbe(
                self.name, CapabilityStatus.BLOCKED_EXTERNAL, None, tuple(checks), "Cursor CLI is not installed or not discoverable",
                f"owner: install the Cursor CLI (docs: {DOCS_URL}) or set {ENV_BIN}=/absolute/path/to/agent for the supervisor",
            )
        checks.append(ProbeCheck("binary", "pass", f"found via {loc.how}"))
        env, secrets = self._host_probe_env()
        binary = str(loc.path)

        ver = run_probe([binary, "--version"], env=env, redact=secrets)
        version = parse_version(ver.out) if ver.ok else None
        if version is None:
            checks.append(ProbeCheck("version", "fail", f"`--version` failed: rc={ver.rc} {ver.error or ver.err.strip()[:200]}"))
            return AdapterProbe(self.name, CapabilityStatus.PROBE_FAIL, None, tuple(checks), "the Cursor CLI does not run on this host",
                                "owner: repair/reinstall the Cursor CLI")
        checks.append(ProbeCheck("version", "pass", version))

        helptxt = run_probe([binary, "--help"], env=env, redact=secrets)
        missing = [f for f in REQUIRED_FLAGS if f not in helptxt.text]
        if not helptxt.ok or missing:
            checks.append(ProbeCheck("help_flags", "fail", f"missing flags: {', '.join(missing) or 'help failed'}"))
            return AdapterProbe(self.name, CapabilityStatus.PROBE_FAIL, version, tuple(checks),
                                "installed CLI lacks the documented headless flags (re-probe after an update)", f"owner: update the Cursor CLI ({DOCS_URL})")
        checks.append(ProbeCheck("help_flags", "pass", f"all of {', '.join(REQUIRED_FLAGS)} present"))
        checks.append(ProbeCheck("bypass_flags", "pass", "--force/--yolo exist in this build but are never emitted by default (policy flag only)"
                                 if "--yolo" in helptxt.text else "no bypass flag in this build"))

        blocked: list[str] = []
        auth = run_probe([binary, "status"], env=env, redact=secrets)
        logged_in = auth.ok and not any(s in auth.text.lower() for s in ("not logged in", "not authenticated", "unauthor", "please log in", "login required"))
        has_key = bool(secrets)
        if logged_in:
            checks.append(ProbeCheck("auth", "pass", "`status` reports an authenticated session" + (" (API key in probe env)" if has_key else "")))
        else:
            detail = "not logged in" if auth.ok or auth.rc else f"status unavailable: {auth.error or auth.rc}"
            checks.append(ProbeCheck("auth", "blocked", detail + ("; CURSOR_API_KEY present but not accepted" if has_key else "")))
            blocked.append(
                f"owner: run `{binary} login` once in a browser (interactive login), or create a Cursor API key and register it as "
                f"{API_KEY_ENV} for the supervisor (CredentialsManager.load_provider_file('{self.name}', <0600 json>)). "
                "Do not purchase anything to unblock this; no paid fallback is configured")
        if self._credential_registered():
            checks.append(ProbeCheck("sandbox_credential", "pass", f"{API_KEY_ENV} is registered for adapter '{self.name}' (delivered via env only)"))
        else:
            checks.append(ProbeCheck("sandbox_credential", "blocked",
                                     f"no {API_KEY_ENV} registered: the interactive login cache lives in the user's HOME, which the sandbox never mounts"))
            blocked.append(f"owner: register {API_KEY_ENV} with the supervisor credentials store (login alone cannot authenticate a sandboxed run)")
        if self.assume_provider_network:
            checks.append(ProbeCheck("provider_network", "pass", "owner asserts the sandbox profile provides DNS + TCP/443 egress"))
        else:
            checks.append(ProbeCheck(
                "provider_network", "blocked",
                f"T07 profile denies UDP/DNS/unix sockets; {PROVIDER_ENDPOINT} cannot be resolved inside the sandbox. Required allowlist: "
                f"DNS for {PROVIDER_ENDPOINT} + TCP/443 to it (or a supervisor-side CONNECT proxy on loopback)"))
            blocked.append("engineering/owner: provide an allow-listed egress path for the sandbox (supervisor-side CONNECT proxy or resolver); "
                           "until then set assume_provider_network only for mocked/offline tests")
        checks.append(ProbeCheck("real_mini_edit", "skipped", "NOT_VERIFIED by probe: a real fixture edit needs an authenticated run (see capability report)"))
        verdict = CapabilityStatus.BLOCKED_EXTERNAL if blocked else CapabilityStatus.PROBE_PASS
        return AdapterProbe(
            self.name, verdict, version, tuple(checks),
            "; ".join(c.detail for c in checks if c.status == "blocked") if blocked else "preconditions satisfied (real mini-edit still NOT_VERIFIED)",
            " | ".join(blocked) or None,
        )

    # ---------------------------------------------------------------------------------------------- run
    def build_cli_argv(self, binary: Path, workspace: Path, prompt: str) -> tuple[str, ...]:
        argv = [str(binary), "-p", "--output-format", "stream-json", "--sandbox", "enabled", "--trust", "--workspace", str(workspace)]
        if self.policy.model:
            argv += ["--model", self.policy.model]
        self.assert_argv_policy(argv)
        if self.policy.allow_force:  # explicit owner policy flag only; never reached by default or from a failure path
            argv.append("--force")
        argv.append(prompt)
        if "--yolo" in argv:  # structural: the alias is never emitted
            raise ValueError("--yolo must never be emitted")
        return tuple(argv)

    def prepare(self, ctx: PrepareContext) -> PreparedRun:
        loc = self._location or self.locate()
        if loc.path is None:
            raise ValueError("Cursor CLI not found (probe must pass before a run)")
        prompt = implementer_prompt(ctx.task, self.scope_hint)
        self._write_ro(ctx, "prompt.md", prompt)
        cli_argv = self.build_cli_argv(loc.path, ctx.workspace, prompt)
        cfg = {
            "provider": "cursor", "argv": list(cli_argv), "cwd": str(ctx.workspace), "out_dir": str(ctx.out_dir),
            "timeout_seconds": self.policy.timeout_seconds, "secret_env": [API_KEY_ENV],
        }
        script, cfg_path = self._install_wrapper(ctx, cfg)
        return PreparedRun(self.name, ctx.run_id, ctx.out_dir / "report.json", (script, cfg_path, loc.path.parent))

    def launch(self, prepared: PreparedRun, ctx: PrepareContext) -> LaunchSpec:
        script, cfg_path, install_dir = prepared.ro_files
        return LaunchSpec(
            argv=(str(ctx.interpreter), "-I", str(script), str(cfg_path)),
            fixed_env={"AGENT_CLI_CREDENTIAL_STORE": "file"},  # no keyring/dbus (unix sockets are denied in the sandbox)
            credential_env=(API_KEY_ENV,) if self._credential_registered() else (),
            extra_ro=(install_dir,),
            network=self.network,
        )


__all__ = ["API_KEY_ENV", "CursorCliAdapter", "CursorPolicy", "ENV_BIN", "FORBIDDEN_ARGV", "implementer_prompt"]
