"""Base service patterns for flext-ldap services.

Defines the canonical LDAP service root used by service mixins and the API facade:
- FlextLdapService provides typed settings access via self.settings
- All services MUST inherit from this base through cooperative MRO
- All settings access MUST use self.settings.ldap / self.settings.ldif

The settings namespace access uses FlextSettings.auto_register pattern:
- FlextLdapSettings is registered via @FlextSettings.auto_register("ldap")
- FlextLdifSettings is registered via @FlextSettings.auto_register("ldif")
- Access via self.settings.ldap / self.settings.ldif from x.settings

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from abc import ABC
from collections.abc import (
    Sequence,
)
from typing import TYPE_CHECKING, override

from flext_core import s
from flext_ldif import FlextLdif, m, u

from flext_ldap import FlextLdapSettings, c, p, t

if TYPE_CHECKING:
    from flext_ldap.adapters.ldap3 import FlextLdapLdap3Adapter


class FlextLdapService[
    TResult: t.JsonPayload | Sequence[t.JsonPayload] = t.JsonPayload
    | Sequence[t.JsonPayload]
](s[TResult], ABC):
    """Base class for all flext-ldap services.

    Services default to the centralized ``m.Ldap.Response`` pipeline and may
    specialize only when bridging adapter-level protocols.
    """

    _adapter: FlextLdapLdap3Adapter | None = u.PrivateAttr(default_factory=lambda: None)
    _ldif: FlextLdif = u.PrivateAttr(default_factory=FlextLdif)
    _server_type: str = u.PrivateAttr(
        default_factory=lambda: c.Ldap.ServerDefaults.DEFAULT_TYPE
    )

    @classmethod
    @override
    def _runtime_bootstrap_options(cls) -> p.RuntimeBootstrapOptions:
        """Return runtime bootstrap options for LDAP services."""
        return m.RuntimeBootstrapOptions(settings_type=FlextLdapSettings)

    @classmethod
    @override
    def _get_service_config_type(cls) -> type[FlextLdapSettings]:
        """Expose the canonical LDAP settings model for legacy callers."""
        return FlextLdapSettings

    @override
    def _ensure_adapter(self) -> FlextLdapLdap3Adapter:
        """Return the shared ldap3 adapter for this service instance."""
        if self._adapter is None:
            from flext_ldap.adapters.ldap3 import FlextLdapLdap3Adapter  # noqa: PLC0415

            self._adapter = FlextLdapLdap3Adapter()
        return self._adapter

    @property
    @override
    def is_connected(self) -> bool:
        """Return ``True`` when the shared adapter has an active bind."""
        adapter = self._adapter
        if adapter is None:
            return False
        return adapter.is_connected


s = FlextLdapService

__all__: list[str] = ["FlextLdapService", "s"]
