"""Authenticated principal context. Actor/tier/roles are derived server-side, never from input."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Literal

from nozo_relay.domain.enums import AuthorityTier, PrincipalKind

AuthMethod = Literal["key", "session"]

_TIER_BY_KIND = {
    PrincipalKind.OWNER: AuthorityTier.P0,
    PrincipalKind.COORDINATOR: AuthorityTier.P1,
    PrincipalKind.IMPLEMENTER: AuthorityTier.P2,
    PrincipalKind.AUDITOR: AuthorityTier.P2,
    PrincipalKind.RUNNER: AuthorityTier.P2,
}


@dataclass(frozen=True, slots=True)
class PrincipalContext:
    id: str
    kind: PrincipalKind
    display_name: str
    # project_id -> role, resolved from memberships. Knowing a UUID grants nothing.
    project_roles: Mapping[str, str] = field(default_factory=lambda: MappingProxyType({}))
    auth_method: AuthMethod = "key"
    credential_id: str | None = None
    session_id_digest: str | None = None
    # Epoch ms of the owner's last password proof for this session (None for keys / unknown).
    reauth_at: int | None = None

    @property
    def roles(self) -> frozenset[str]:
        return frozenset({self.kind.value, *self.project_roles.values()})

    @property
    def tier(self) -> AuthorityTier:
        return _TIER_BY_KIND[self.kind]

    @property
    def is_owner(self) -> bool:
        return self.kind is PrincipalKind.OWNER

    def role_in(self, project_id: str) -> str | None:
        return self.project_roles.get(project_id)

    def is_member(self, project_id: str) -> bool:
        return project_id in self.project_roles
