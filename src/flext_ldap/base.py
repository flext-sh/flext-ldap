"""Base service patterns for flext-ldap services.

Defines common patterns for settings namespace access:
- FlextLdapServiceBase provides typed settings access via self.settings
- All services MUST inherit from this base
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

from flext_core import m, s
from flext_ldap import FlextLdapSettings, p, t


class FlextLdapServiceBase[
    TResult: t.ValueOrModel | Sequence[t.ValueOrModel] = t.ValueOrModel
    | Sequence[t.ValueOrModel]
](s[TResult], ABC):
    """Base class for all flext-ldap services.

    Subclasses parametrize via s[T] for their specific result type.
    """

    @classmethod
    @override
    def _runtime_bootstrap_options(cls) -> p.RuntimeBootstrapOptions:
        """Return runtime bootstrap options for LDAP services."""
        return m.RuntimeBootstrapOptions(settings_type=FlextLdapSettings)


s = FlextLdapServiceBase
__all__: list[str] = ["FlextLdapServiceBase", "s"]
