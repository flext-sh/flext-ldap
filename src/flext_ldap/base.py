"""Base service patterns for flext-ldap services.

Defines common patterns for config namespace access:
- FlextLdapServiceBase provides typed config access via self.config
- All services MUST inherit from this base
- All config access MUST use self.config.ldap / self.config.ldif

The config namespace access uses FlextSettings.auto_register pattern:
- FlextLdapSettings is registered via @FlextSettings.auto_register("ldap")
- FlextLdifSettings is registered via @FlextSettings.auto_register("ldif")
- Access via self.config.ldap / self.config.ldif from x.config

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from abc import ABC
from typing import override

from flext_core import FlextService, p

from flext_ldap import FlextLdapSettings
from flext_ldap.typings import t


class FlextLdapServiceBase(FlextService[t.TDomainResult], ABC):
    """Base class for all flext-ldap services with typed config access.

    Inherits config property from x which provides:
    - self.config → FlextSettings.get_global_instance()
    - self.config.ldap → FlextLdapSettings (via @FlextSettings.auto_register)
    - self.config.ldif → FlextLdifSettings (via @FlextSettings.auto_register)

    Usage in services:
        class MyService(FlextLdapServiceBase[MyResult]):
            def execute(self) -> FlextResult[MyResult]:
                host = self.config.ldap.host  # Typed access!
                encoding = self.config.ldif.ldif_encoding  # Typed access!
    """

    @classmethod
    @override
    def _runtime_bootstrap_options(cls) -> p.RuntimeBootstrapOptions:
        """Return runtime bootstrap options for LDAP services.

        Business Rule: This method provides runtime bootstrap configuration for
        all LDAP services, ensuring they use FlextLdapSettings as the configuration
        type. This enables proper DI integration and namespace access.

        Implication: All services extending FlextLdapServiceBase automatically
        use FlextLdapSettings for their runtime configuration, ensuring consistent
        configuration handling across all LDAP services.

        Returns:
            Runtime bootstrap options with config_type set to FlextLdapSettings

        """
        options = super()._runtime_bootstrap_options()
        model_copy = getattr(options, "model_copy", None)
        if model_copy:
            return model_copy(update={"config_type": FlextLdapSettings})
        options.config_type = FlextLdapSettings
        return options


s = FlextLdapServiceBase
__all__ = ["FlextLdapServiceBase", "s"]
