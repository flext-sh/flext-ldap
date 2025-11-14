"""LDAP Connection Service.

This service manages LDAP connections using the ldap3 adapter.
Provides connection lifecycle management and status checking.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

from flext_core import FlextLogger, FlextResult, FlextService
from flext_ldif.services.parser import FlextLdifParser

from flext_ldap.adapters.ldap3 import Ldap3Adapter
from flext_ldap.config import FlextLdapConfig
from flext_ldap.models import FlextLdapModels


class FlextLdapConnection(FlextService[bool]):
    """LDAP connection service managing connection lifecycle.

    Handles connection establishment, binding, and disconnection.
    Uses Ldap3Adapter for low-level ldap3 operations.
    """

    _adapter: Ldap3Adapter
    _config: FlextLdapConfig
    _logger: FlextLogger

    def __init__(
        self,
        config: FlextLdapConfig | None = None,
        parser: FlextLdifParser | None = None,
    ) -> None:
        """Initialize connection service.

        Args:
            config: Optional FlextLdapConfig instance. If None, uses default config.
            parser: Optional FlextLdifParser instance for adapter. If None, creates new instance.

        """
        super().__init__()
        self._config = config if config is not None else FlextLdapConfig()
        self._logger = FlextLogger(__name__)
        # Pass parser to adapter to maximize reuse
        self._adapter = Ldap3Adapter(parser=parser)

    def connect(
        self,
        connection_config: FlextLdapModels.ConnectionConfig | None = None,
    ) -> FlextResult[bool]:
        """Establish LDAP connection.

        Args:
            connection_config: Optional connection config. If None, uses service config.

        Returns:
            FlextResult[bool] indicating connection success

        """
        if connection_config is None:
            # Build config from service config
            connection_config = FlextLdapModels.ConnectionConfig(
                host=self._config.ldap_host,
                port=self._config.ldap_port,
                use_ssl=self._config.ldap_use_ssl,
                use_tls=self._config.ldap_use_tls,
                bind_dn=self._config.ldap_bind_dn,
                bind_password=self._config.ldap_bind_password,
                timeout=self._config.ldap_timeout,
                auto_bind=self._config.ldap_auto_bind,
                auto_range=self._config.ldap_auto_range,
            )

        result = self._adapter.connect(connection_config)
        if result.is_success:
            return FlextResult[bool].ok(True)
        return FlextResult[bool].fail(result.error or "Connection failed")

    def disconnect(self) -> None:
        """Close LDAP connection."""
        self._adapter.disconnect()
        self._logger.info("LDAP connection closed")

    @property
    def is_connected(self) -> bool:
        """Check if service has active connection.

        Returns:
            True if connected, False otherwise

        """
        return self._adapter.is_connected

    @property
    def adapter(self) -> Ldap3Adapter:
        """Get underlying ldap3 adapter.

        Returns:
            Ldap3Adapter instance

        """
        return self._adapter

    def execute(self) -> FlextResult[bool]:
        """Execute service health check.

        Returns:
            FlextResult[bool] indicating service status

        """
        if self.is_connected:
            return FlextResult[bool].ok(True)
        return FlextResult[bool].fail("Not connected to LDAP server")
