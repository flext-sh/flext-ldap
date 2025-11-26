"""Base service patterns for flext-ldap services.

Defines common patterns for config namespace access:
- FlextLdapServiceBase provides typed config access via self.config
- All services MUST inherit from this base
- All config access MUST use self.config.ldap / self.config.ldif

The config namespace access uses FlextConfig.auto_register pattern:
- FlextLdapConfig is registered via @FlextConfig.auto_register("ldap")
- FlextLdifConfig is registered via @FlextConfig.auto_register("ldif")
- Access via self.config.ldap / self.config.ldif from FlextMixins.config

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from typing import TypeVar

from flext_core import FlextService, FlextUtilities
from flext_ldif.utilities import FlextLdifUtilities

TDomainResult = TypeVar("TDomainResult")


class FlextLdapServiceBase(FlextService[TDomainResult]):
    """Base class for all flext-ldap services with typed config access.

    Inherits config property from FlextMixins which provides:
    - self.config → FlextConfig.get_global_instance()
    - self.config.ldap → FlextLdapConfig (via @FlextConfig.auto_register)
    - self.config.ldif → FlextLdifConfig (via @FlextConfig.auto_register)

    Usage in services:
        class MyService(FlextLdapServiceBase[MyResult]):
            def execute(self) -> FlextResult[MyResult]:
                host = self.config.ldap.host  # Typed access!
                encoding = self.config.ldif.ldif_encoding  # Typed access!
    """

    def __init__(self, **kwargs: object) -> None:
        """Initialize service with optional kwargs."""
        super().__init__(**kwargs)

    @staticmethod
    def safe_dn_string(dn: str | object | None) -> str:
        """Safely extract DN string value, defaulting to 'unknown' if None.

        Uses FlextUtilities for type-safe string conversion and FlextLdifUtilities
        for DN-specific value extraction. Generalizes DN string extraction pattern.

        Args:
            dn: DN value to extract string from

        Returns:
            DN string value or 'unknown' if None

        """
        if dn is None:
            return "unknown"
        if FlextUtilities.TypeGuards.is_string_non_empty(dn):
            return str(dn)
        return FlextLdifUtilities.DN.get_dn_value(dn)
