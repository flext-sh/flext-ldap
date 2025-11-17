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
            config: FlextLdapConfig instance (optional, creates default if not provided)
            parser: FlextLdifParser instance (optional, creates default if not provided)

        """
        super().__init__()
        self._config = config or FlextLdapConfig()
        self._logger = FlextLogger(__name__)
        # Pass parser to adapter (optional, creates default if not provided)
        self._adapter = Ldap3Adapter(parser=parser or FlextLdifParser())

    def connect(
        self,
        connection_config: FlextLdapModels.ConnectionConfig,
    ) -> FlextResult[bool]:
        """Establish LDAP connection.

        Args:
            connection_config: Connection configuration (required, no fallback)

        Returns:
            FlextResult[bool] indicating connection success

        """
        # Monadic pattern - map success to True, preserve failure
        return self._adapter.connect(connection_config).map(lambda _: True)

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
