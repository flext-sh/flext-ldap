"""Base service patterns for flext-ldap services.

Defines common patterns for config namespace access:
- FlextLdapServiceBase provides typed config access via self.config
- All services MUST inherit from this base
- All config access MUST use self.config.ldap / self.config.ldif

The config namespace access uses FlextConfig.auto_register pattern:
- FlextLdapConfig is registered via @FlextConfig.auto_register("ldap")
- FlextLdifConfig is registered via @FlextConfig.auto_register("ldif")
- Access via self.config.ldap / self.config.ldif from x.config

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from flext_core import FlextService, t

from flext_ldap.config import FlextLdapConfig
from flext_ldap.typings import FlextLdapDomainResultT as TDomainResult


class FlextLdapServiceBase(FlextService[TDomainResult]):
    """Base class for all flext-ldap services with typed config access.

    Inherits config property from x which provides:
    - self.config → FlextConfig.get_global_instance()
    - self.config.ldap → FlextLdapConfig (via @FlextConfig.auto_register)
    - self.config.ldif → FlextLdifConfig (via @FlextConfig.auto_register)

    Usage in services:
        class MyService(FlextLdapServiceBase[MyResult]):
            def execute(self) -> r[MyResult]:
                host = self.config.ldap.host  # Typed access!
                encoding = self.config.ldif.ldif_encoding  # Typed access!
    """

    @classmethod
    def _runtime_bootstrap_options(cls) -> t.Types.RuntimeBootstrapOptions:
        """Return runtime bootstrap options for LDAP services.

        Business Rule: This method provides runtime bootstrap configuration for
        all LDAP services, ensuring they use FlextLdapConfig as the configuration
        type. This enables proper DI integration and namespace access.

        Implication: All services extending FlextLdapServiceBase automatically
        use FlextLdapConfig for their runtime configuration, ensuring consistent
        configuration handling across all LDAP services.

        Returns:
            Runtime bootstrap options with config_type set to FlextLdapConfig

        """
        return {"config_type": FlextLdapConfig}


# Convenience alias for common usage pattern - exported for domain usage
s = FlextLdapServiceBase

__all__ = ["FlextLdapServiceBase", "s"]
