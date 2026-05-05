"""Base service patterns for flext-ldap services.

Defines the canonical LDAP service root used by service mixins and the API facade:
- FlextLdapService provides typed settings access via self.settings
- All services MUST inherit from this base through cooperative MRO

Settings access goes through ``FlextLdapSettings.fetch_global()`` (rule 1
shared singleton, propagating via ``update_global``).

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from flext_core import s
from flext_ldap import FlextLdapSettings, c, p, t
from flext_ldif import FlextLdif, m, u

if TYPE_CHECKING:
    from flext_ldap.adapters.ldap3 import FlextLdapLdap3Adapter


class FlextLdapService[
    TResult: t.JsonPayload | t.SequenceOf[t.JsonPayload] = t.JsonPayload
    | t.SequenceOf[t.JsonPayload]
](s[TResult]):
    """Base class for all flext-ldap services.

    Services default to the centralized ``m.Ldap.Response`` pipeline and may
    specialize only when bridging adapter-level protocols.
    """

    _adapter: FlextLdapLdap3Adapter | None = u.PrivateAttr(default_factory=lambda: None)
    _ldif: p.Ldif.LdifClient = u.PrivateAttr(default_factory=FlextLdif)
    _server_type: str = u.PrivateAttr(default_factory=lambda: c.Ldap.DEFAULT_TYPE)

    @classmethod
    def _runtime_bootstrap_options(cls) -> p.RuntimeBootstrapOptions:
        """Return runtime bootstrap options for LDAP services."""
        return m.RuntimeBootstrapOptions(settings_type=FlextLdapSettings)

    @classmethod
    def _get_service_config_type(cls) -> type[FlextLdapSettings]:
        """Expose the canonical LDAP settings model for legacy callers."""
        return FlextLdapSettings

    def _ensure_adapter(self) -> FlextLdapLdap3Adapter:
        """Return the shared ldap3 adapter for this service instance."""
        if self._adapter is None:
            from flext_ldap.adapters.ldap3 import FlextLdapLdap3Adapter  # noqa: PLC0415

            self._adapter = FlextLdapLdap3Adapter()
        return self._adapter

    @property
    def is_connected(self) -> bool:
        """Return ``True`` when the shared adapter has an active bind."""
        adapter = self._adapter
        if adapter is None:
            return False
        return adapter.is_connected


s = FlextLdapService

__all__: list[str] = ["FlextLdapService", "s"]
