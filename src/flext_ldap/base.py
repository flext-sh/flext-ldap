"""Base service patterns for flext-ldap services.

Defines common patterns for config namespace access:
- FlextLdapServiceBase provides typed config access via self.config
- All services MUST inherit from this base
- All config access MUST use self.config.ldap / self.config.ldif

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from typing import Self

from flext_core import FlextService, T
from flext_ldif.config import FlextLdifConfig

from flext_ldap.config import FlextLdapConfig, LdapFlextConfig


class FlextLdapServiceBase(FlextService[T]):
    """Base class for all flext-ldap services with typed config access.

    Provides:
    - self.config property → LdapFlextConfig (typed)
    - self.config.ldap → FlextLdapConfig
    - self.config.ldif → FlextLdifConfig

    Usage in services:
        class MyService(FlextLdapServiceBase[MyResult]):
            def execute(self) -> FlextResult[MyResult]:
                host = self.config.ldap.host  # Typed access!
                encoding = self.config.ldif.ldif_encoding  # Typed access!
    """

    _injected_config: LdapFlextConfig | None = None

    def __init__(self, **kwargs: object) -> None:
        """Initialize service with optional kwargs."""
        super().__init__(**kwargs)

    @property
    def config(self) -> LdapFlextConfig:
        """Get LdapFlextConfig with typed namespace access.

        Returns:
            LdapFlextConfig: Typed config with ldap/ldif namespaces

        Usage:
            host = self.config.ldap.host
            encoding = self.config.ldif.ldif_encoding

        """
        if self._injected_config is not None:
            return self._injected_config
        return LdapFlextConfig.get_global_instance()

    def with_config(self, config: LdapFlextConfig) -> Self:
        """Inject config for dependency injection.

        Args:
            config: LdapFlextConfig instance to inject

        Returns:
            Self: This service instance for chaining

        """
        self._injected_config = config
        return self

    # =========================================================================
    # BACKWARD COMPATIBILITY - These will be deprecated
    # =========================================================================

    @property
    def ldap_config(self) -> FlextLdapConfig:
        """Get FlextLdapConfig (DEPRECATED - use self.config.ldap).

        Returns:
            FlextLdapConfig: LDAP configuration with typed access

        """
        return self.config.ldap

    @property
    def ldif_config(self) -> FlextLdifConfig:
        """Get FlextLdifConfig (DEPRECATED - use self.config.ldif).

        Returns:
            FlextLdifConfig: LDIF configuration with typed access

        """
        return self.config.ldif

    # =========================================================================
    # STATIC METHODS for usage outside services
    # =========================================================================

    @staticmethod
    def get_flext_config() -> LdapFlextConfig:
        """Get LdapFlextConfig singleton (static access).

        Returns:
            LdapFlextConfig: Typed FlextConfig instance

        """
        return LdapFlextConfig.get_global_instance()

    @staticmethod
    def get_ldap_config() -> FlextLdapConfig:
        """Get FlextLdapConfig singleton (static access).

        Returns:
            FlextLdapConfig: LDAP configuration

        """
        return LdapFlextConfig.get_global_instance().ldap

    @staticmethod
    def get_ldif_config() -> FlextLdifConfig:
        """Get FlextLdifConfig singleton (static access).

        Returns:
            FlextLdifConfig: LDIF configuration

        """
        return LdapFlextConfig.get_global_instance().ldif
