"""Supervisor-side credentials manager (05_SECURITY: "LLM subprocess не наследует master Relay key").

Classes of secret and where they may go:

=========================== ===================================== =======================================
class                       examples                              child?
=========================== ===================================== =======================================
owner / relay-server        owner DB, admin cookie store, Relay    NEVER (not mounted, not in env, not in
                            master key, other agents' relay keys   argv; ``/proc`` is not reachable)
supervisor-side relay keys  implementer/auditor/runner key         NEVER (supervisor talks to the relay)
publish credentials         GitHub push token, SSH agent, docker   NEVER (no publish executor in T07)
provider credentials        the client's own login cache / API key ONLY the adapter that declared the env
                                                                   name, ONLY that name, per run
=========================== ===================================== =======================================

The child environment is built from an EMPTY dict: only a fixed allow-list plus the provider variables that the
adapter explicitly declares AND that were registered here. Nothing is inherited from the supervisor process, so
a secret that happens to sit in the supervisor's environment cannot reach the child by omission of a filter.

Every secret value that the supervisor knows (including the ones it must never share) is kept in
``secret_values()`` so output redaction can mask them wherever they would surface (logs, receipts, reports).
Honest limit (05_SECURITY): redaction masks KNOWN values and known shapes; it cannot find an unknown secret.
"""

from __future__ import annotations

import os
import re
import tempfile
from collections.abc import Iterable, Mapping
from pathlib import Path

# Environment names no adapter may ever request, whatever the value.
FORBIDDEN_ENV = re.compile(
    r"(?i)^(NOZO_RELAY_.*|.*MASTER_KEY.*|.*RELAY_KEY.*|SSH_AUTH_SOCK|SSH_AGENT_PID|GH_TOKEN|GITHUB_TOKEN|GITLAB_TOKEN|"
    r"DOCKER_HOST|DOCKER_CONFIG|KUBECONFIG|AWS_.*|GOOGLE_APPLICATION_CREDENTIALS|AZURE_.*|NPM_TOKEN|PYPI_TOKEN|"
    r"LD_PRELOAD|LD_LIBRARY_PATH|PYTHON.*|BASH_ENV|ENV|IFS|SHELLOPTS|PROMPT_COMMAND|GIT_.*|HOME|PATH|TMPDIR)$"
)
SAFE_ENV_NAME = re.compile(r"^[A-Z][A-Z0-9_]{2,63}$")
BASE_PATH = "/usr/local/bin:/usr/bin:/bin"


class CredentialError(ValueError):
    pass


class CredentialsManager:
    """Holds provider credentials per adapter, outside the child, and builds clean child environments."""

    def __init__(self, supervisor_env: Mapping[str, str] | None = None) -> None:
        self._provider: dict[str, dict[str, str]] = {}
        self._supervisor_only: set[str] = set()
        env = os.environ if supervisor_env is None else supervisor_env
        # Values of secret-looking variables in OUR OWN environment are known secrets (for redaction only).
        for name, value in env.items():
            if value and len(value) >= 8 and re.search(r"(?i)(secret|token|key|password|passwd|cookie|credential)", name):
                self._supervisor_only.add(value)

    # -- registration (supervisor side only) -------------------------------------------------
    def register_provider_credential(self, adapter: str, env_name: str, value: str) -> None:
        self._check_env_name(env_name)
        if not value:
            raise CredentialError("empty credential")
        self._provider.setdefault(adapter, {})[env_name] = value

    def register_supervisor_secret(self, value: str) -> None:
        """A secret the child must never see (relay master key, owner password, ...). Redaction only."""
        if value:
            self._supervisor_only.add(value)

    def load_provider_file(self, adapter: str, path: Path) -> None:
        """Private 0600 JSON ``{"ENV_NAME": "value"}`` outside the repo and the data dir."""
        st = path.stat()
        if st.st_mode & 0o077 or st.st_uid != os.getuid():
            raise CredentialError(f"{path} must be owned by the current user with mode 0600")
        import json

        for name, value in json.loads(path.read_text()).items():
            self.register_provider_credential(adapter, name, str(value))

    @staticmethod
    def _check_env_name(name: str) -> None:
        if not SAFE_ENV_NAME.match(name) or FORBIDDEN_ENV.match(name):
            raise CredentialError(f"environment variable {name!r} may never be passed to a child")

    # -- views -------------------------------------------------------------------------------
    def secret_values(self) -> frozenset[str]:
        vals = set(self._supervisor_only)
        for creds in self._provider.values():
            vals.update(creds.values())
        return frozenset(v for v in vals if v)

    def provider_env(self, adapter: str, requested: Iterable[str]) -> dict[str, str]:
        out: dict[str, str] = {}
        for name in requested:
            self._check_env_name(name)
            try:
                out[name] = self._provider[adapter][name]
            except KeyError as exc:
                raise CredentialError(f"adapter {adapter!r} requested unregistered credential {name!r}") from exc
        return out

    def child_env(
        self,
        adapter: str,
        *,
        home: Path,
        tmp: Path,
        credential_env: Iterable[str] = (),
        fixed: Mapping[str, str] | None = None,
    ) -> dict[str, str]:
        env: dict[str, str] = {
            "PATH": BASE_PATH,
            "HOME": str(home),
            "TMPDIR": str(tmp),
            "LANG": "C.UTF-8",
            "LC_ALL": "C.UTF-8",
            "NO_COLOR": "1",
            "PYTHONNOUSERSITE": "1",
            "PYTHONDONTWRITEBYTECODE": "1",
        }
        for name, value in (fixed or {}).items():
            self._check_env_name(name)
            env[name] = value
        env.update(self.provider_env(adapter, credential_env))
        return env


def temp_home(parent: Path) -> Path:
    """Fresh private HOME for a run (0700)."""
    parent.mkdir(parents=True, exist_ok=True)
    return Path(tempfile.mkdtemp(prefix="home-", dir=parent))
