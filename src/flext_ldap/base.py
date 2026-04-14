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
from collections.abc import Sequence
from typing import override

from pydantic import PrivateAttr

from flext_core import s
from flext_ldap.adapters.ldap3 import FlextLdapLdap3Adapter
from flext_ldap.settings import FlextLdapSettings
from flext_ldap.constants import c
from flext_ldap.models import m
from flext_ldap.protocols import p
from flext_ldap.typings import t
from flext_ldif import FlextLdif


class FlextLdapService[
    TResult: t.ValueOrModel | Sequence[t.ValueOrModel] = t.ValueOrModel
    | Sequence[t.ValueOrModel]
](s[TResult], ABC):
    """Base class for all flext-ldap services.

    Subclasses parametrize via s[T] for their specific result type.
    """

    _adapter: FlextLdapLdap3Adapter | None = PrivateAttr(default=None)
    _ldif: FlextLdif = PrivateAttr(default_factory=FlextLdif)
    _server_type: str = PrivateAttr(default=c.Ldap.ServerDefaults.DEFAULT_TYPE)

    @classmethod
    @override
    def _runtime_bootstrap_options(cls) -> p.RuntimeBootstrapOptions:
        """Return runtime bootstrap options for LDAP services."""
        return m.RuntimeBootstrapOptions(settings_type=FlextLdapSettings)

    def _ensure_adapter(self) -> FlextLdapLdap3Adapter:
        """Return the shared ldap3 adapter for this service instance."""
        if self._adapter is None:
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
