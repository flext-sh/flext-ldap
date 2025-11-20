"""LDAP Connection Service.

This service manages LDAP connections using the ldap3 adapter.
Provides connection lifecycle management and status checking.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

import time
from typing import cast

from flext_core import (
    FlextConfig,
    FlextLogger,
    FlextResult,
    FlextService,
)
from flext_ldif import FlextLdifParser
from pydantic import computed_field

from flext_ldap.adapters.ldap3 import Ldap3Adapter
from flext_ldap.config import FlextLdapConfig
from flext_ldap.models import FlextLdapModels
from flext_ldap.services.detection import FlextLdapServerDetector


class FlextLdapConnection(FlextService[bool]):
    """LDAP connection service managing connection lifecycle.

    Handles connection establishment, binding, and disconnection.
    Uses Ldap3Adapter for low-level ldap3 operations.
    """

    _adapter: Ldap3Adapter
    _config: FlextLdapConfig
    _logger: FlextLogger

    @computed_field
    def service_config(self) -> FlextConfig:
        """Automatic config binding via Pydantic v2 computed_field."""
        return FlextConfig.get_global_instance()

    def __init__(
        self,
        config: FlextLdapConfig | None = None,
        parser: FlextLdifParser | None = None,
    ) -> None:
        """Initialize connection service.

        Args:
            config: FlextLdapConfig instance (optional, uses namespace default if not provided)
            parser: FlextLdifParser instance (optional, creates default if not provided)

        """
        super().__init__()
        # Use FlextConfig namespace pattern: access via namespace when config not provided
        self._config = (
            config
            if config is not None
            else cast("FlextLdapConfig", FlextConfig.get_global_instance().ldap)
        )
        self._logger = FlextLogger.create_module_logger(__name__)
        # Pass parser to adapter (optional, creates default if not provided)
        self._adapter = Ldap3Adapter(parser=parser or FlextLdifParser())

    def connect(
        self,
        connection_config: FlextLdapModels.ConnectionConfig,
        *,
        auto_retry: bool = False,
        max_retries: int = 3,
        retry_delay: float = 1.0,
    ) -> FlextResult[bool]:
        """Establish LDAP connection with optional auto-retry on failure.

        Args:
            connection_config: Connection configuration (required, no fallback)
            auto_retry: Enable automatic reconnection on failure (default: False)
            max_retries: Maximum number of retry attempts (default: 3)
            retry_delay: Delay in seconds between retries (default: 1.0)

        Returns:
            FlextResult[bool] indicating connection success

        """
        self._logger.debug(
            "Connecting to LDAP server",
            operation="connect",
            host=connection_config.host,
            port=connection_config.port,
            use_ssl=connection_config.use_ssl,
            use_tls=connection_config.use_tls,
            auto_retry=auto_retry,
            max_retries=max_retries,
            retry_delay=retry_delay,
            bind_dn=connection_config.bind_dn[:50]
            if connection_config.bind_dn
            else None,
            has_password=connection_config.bind_password is not None,
        )

        connect_result = self._adapter.connect(connection_config)

        if connect_result.is_success:
            self._logger.debug(
                "Adapter connection succeeded",
                operation="connect",
                host=connection_config.host,
                port=connection_config.port,
            )
        else:
            self._logger.debug(
                "Adapter connection failed",
                operation="connect",
                host=connection_config.host,
                port=connection_config.port,
                error=str(connect_result.error),
            )

        if not auto_retry or connect_result.is_success:
            if connect_result.is_success:
                self._detect_server_type_optional()

                self._logger.info(
                    "LDAP connection established",
                    operation="connect",
                    host=connection_config.host,
                    port=connection_config.port,
                    use_ssl=connection_config.use_ssl,
                    use_tls=connection_config.use_tls,
                )
            else:
                self._logger.error(
                    "LDAP connection failed",
                    operation="connect",
                    host=connection_config.host,
                    port=connection_config.port,
                    error=str(connect_result.error),
                    auto_retry_disabled=True,
                )
            return connect_result.map(lambda _: True)

        last_error = connect_result.error
        for attempt in range(1, max_retries + 1):
            self._logger.warning(
                "LDAP connection failed, retrying",
                operation="connect",
                attempt=attempt,
                max_retries=max_retries,
                host=connection_config.host,
                port=connection_config.port,
                error=str(last_error)[:200],
                retry_delay=retry_delay,
            )

            time.sleep(retry_delay)

            connect_result = self._adapter.connect(connection_config)

            if connect_result.is_success:
                self._detect_server_type_optional()

                self._logger.info(
                    "LDAP connection established after retry",
                    operation="connect",
                    attempt=attempt,
                    host=connection_config.host,
                    port=connection_config.port,
                )
                return connect_result.map(lambda _: True)

            self._logger.debug(
                "Retry attempt failed",
                operation="connect",
                attempt=attempt,
                host=connection_config.host,
                port=connection_config.port,
                error=str(connect_result.error)[:200],
            )

            last_error = connect_result.error

        self._logger.error(
            "LDAP connection failed after all retries",
            operation="connect",
            max_retries=max_retries,
            host=connection_config.host,
            port=connection_config.port,
            final_error=str(last_error)[:200],
        )
        return FlextResult[bool].fail(
            f"Connection failed after {max_retries} retries: {last_error}",
        )

    def disconnect(self) -> None:
        """Close LDAP connection."""
        self._logger.debug(
            "Disconnecting from LDAP server",
            operation="disconnect",
            was_connected=self.is_connected,
        )

        self._adapter.disconnect()

        self._logger.info(
            "LDAP connection closed",
            operation="disconnect",
        )

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

    def _detect_server_type_optional(self) -> None:
        """Attempt automatic server type detection (optional, non-blocking).

        Uses FlextLdapServerDetector to detect server type from rootDSE.
        Failures are logged but do not affect connection success.
        """
        if not self.is_connected:
            return

        try:
            connection = self._adapter.connection
            if connection is None:
                return

            detector = FlextLdapServerDetector()
            detection_result = detector.detect_from_connection(connection)

            if detection_result.is_success:
                detected_type = detection_result.unwrap()
                self._logger.info(
                    "Server type detected automatically",
                    operation="connect",
                    detected_server_type=detected_type,
                )
            else:
                self._logger.debug(
                    "Server type detection failed (non-critical)",
                    operation="connect",
                    error=str(detection_result.error),
                )
        except Exception as e:
            self._logger.debug(
                "Server type detection exception (non-critical)",
                operation="connect",
                error=str(e),
                error_type=type(e).__name__,
            )

    def execute(self, **_kwargs: object) -> FlextResult[bool]:
        """Execute service health check.

        Args:
            **_kwargs: Unused - health check requires no configuration

        Returns:
            FlextResult[bool] indicating service status

        """
        if self.is_connected:
            return FlextResult[bool].ok(data=True)
        return FlextResult[bool].fail("Not connected to LDAP server")
