"""LDAP Connection Service.

This service manages LDAP connections using the ldap3 adapter.
Provides connection lifecycle management and status checking.

Module: FlextLdapConnection
Scope: LDAP connection lifecycle, auto-retry, server detection
Pattern: Service extending FlextLdapServiceBase, uses Ldap3Adapter

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from flext_core import FlextResult, FlextUtilities
from flext_ldif import FlextLdif
from flext_ldif.services.parser import FlextLdifParser

from flext_ldap.adapters.ldap3 import Ldap3Adapter
from flext_ldap.base import FlextLdapServiceBase
from flext_ldap.config import FlextLdapConfig
from flext_ldap.constants import FlextLdapConstants
from flext_ldap.models import FlextLdapModels
from flext_ldap.services.detection import FlextLdapServerDetector


class FlextLdapConnection(FlextLdapServiceBase[bool]):
    """LDAP connection service managing connection lifecycle.

    Handles connection establishment, binding, and disconnection.
    Uses Ldap3Adapter for low-level ldap3 operations.
    """

    _adapter: Ldap3Adapter
    _config: FlextLdapConfig

    def __init__(
        self,
        config: FlextLdapConfig | None = None,
        parser: FlextLdifParser | None = None,
    ) -> None:
        """Initialize connection service."""
        super().__init__()
        self._config = (
            config
            if config is not None
            else self.config.get_namespace("ldap", FlextLdapConfig)
        )
        if parser is None:
            parser = FlextLdif.get_instance().parser
        self._adapter = Ldap3Adapter(parser=parser)

    def connect(
        self,
        connection_config: FlextLdapModels.ConnectionConfig,
        *,
        auto_retry: bool = False,
        max_retries: int = 3,
        retry_delay: float = 1.0,
        **_kwargs: object,
    ) -> FlextResult[bool]:
        """Establish LDAP connection with optional auto-retry on failure."""

        def attempt_connect() -> FlextResult[bool]:
            return self._adapter.connect(connection_config)

        result = (
            FlextUtilities.Reliability.retry(
                operation=attempt_connect,
                max_attempts=max_retries,
                delay_seconds=retry_delay,
            )
            if auto_retry
            else attempt_connect()
        )

        if result.is_success:
            self._detect_server_type_optional()
            return FlextResult[bool].ok(True)
        return result

    def disconnect(self) -> None:
        """Close LDAP connection."""
        self._adapter.disconnect()

    @property
    def is_connected(self) -> bool:
        """Check if service has active connection."""
        return self._adapter.is_connected

    @property
    def adapter(self) -> Ldap3Adapter:
        """Get underlying ldap3 adapter."""
        return self._adapter

    def _detect_server_type_optional(self) -> None:
        """Attempt automatic server type detection (optional, non-blocking)."""
        connection = self._adapter.connection
        if not connection:
            return

        detector = FlextLdapServerDetector()
        detection_result = detector.detect_from_connection(connection)

        if detection_result.is_success:
            self.logger.info(
                "Server type detected automatically",
                operation=FlextLdapConstants.LdapOperationLogging.OPERATION_CONNECT,
                detected_server_type=detection_result.unwrap(),
            )
        else:
            self.logger.debug(
                "Server type detection failed (non-critical)",
                operation=FlextLdapConstants.LdapOperationLogging.OPERATION_CONNECT,
                error=str(detection_result.error) if detection_result.error else "",
            )

    def execute(self, **_kwargs: object) -> FlextResult[bool]:
        """Execute service health check."""
        if self.is_connected:
            return FlextResult[bool].ok(True)
        return FlextResult[bool].fail(FlextLdapConstants.ErrorStrings.NOT_CONNECTED)
