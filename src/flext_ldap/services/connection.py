"""LDAP Connection Service.

This service manages LDAP connections using the ldap3 adapter.
Provides connection lifecycle management and status checking.

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
        """Initialize connection service.

        Args:
            config: FlextLdapConfig instance (optional, uses ldap_config if not provided)
            parser: Parser instance (optional, uses FlextLdif API if not provided)

        """
        super().__init__()
        # Use typed ldap config from namespace
        self._config = (
            config
            if config is not None
            else self.config.get_namespace("ldap", FlextLdapConfig)
        )
        # Pass parser to adapter (optional, uses FlextLdif API if not provided)
        if parser is None:
            ldif = FlextLdif.get_instance()
            parser = ldif.parser
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
        """Establish LDAP connection with optional auto-retry on failure.

        Args:
            connection_config: Connection configuration (required, no fallback)
            auto_retry: Enable automatic reconnection on failure (default: False)
            max_retries: Maximum number of retry attempts (default: 3)
            retry_delay: Delay in seconds between retries (default: 1.0)

        Returns:
            FlextResult[bool] indicating connection success

        """
        self.logger.debug(
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
            self.logger.debug(
                "Adapter connection succeeded",
                operation="connect",
                host=connection_config.host,
                port=connection_config.port,
            )
        else:
            self.logger.debug(
                "Adapter connection failed",
                operation="connect",
                host=connection_config.host,
                port=connection_config.port,
                error=str(connect_result.error),
            )

        if not auto_retry or connect_result.is_success:
            if connect_result.is_success:
                self._detect_server_type_optional()

                self.logger.info(
                    "LDAP connection established",
                    operation="connect",
                    host=connection_config.host,
                    port=connection_config.port,
                    use_ssl=connection_config.use_ssl,
                    use_tls=connection_config.use_tls,
                )
            else:
                self.logger.error(
                    "LDAP connection failed",
                    operation="connect",
                    host=connection_config.host,
                    port=connection_config.port,
                    error=str(connect_result.error),
                    auto_retry_disabled=True,
                )
            return (
                FlextResult[bool].ok(True)
                if connect_result.is_success
                else connect_result
            )

        # Use FlextUtilities.Reliability.retry for retry logic
        retry_result = FlextUtilities.Reliability.retry(
            operation=lambda: self._adapter.connect(connection_config),
            max_attempts=max_retries,
            delay_seconds=retry_delay,
        )

        if retry_result.is_success:
            self._detect_server_type_optional()
            self.logger.info(
                "LDAP connection established after retry",
                operation="connect",
                host=connection_config.host,
                port=connection_config.port,
            )
            return (
                FlextResult[bool].ok(True) if retry_result.is_success else retry_result
            )

        last_error = retry_result.error
        self.logger.error(
            "LDAP connection failed after all retries",
            operation="connect",
            max_retries=max_retries,
            host=connection_config.host,
            port=connection_config.port,
            final_error=str(last_error)[:200] if last_error else "Unknown error",
        )
        return FlextResult[bool].fail(
            f"Connection failed after {max_retries} retries: {last_error}",
        )

    def disconnect(self) -> None:
        """Close LDAP connection."""
        self.logger.debug(
            "Disconnecting from LDAP server",
            operation="disconnect",
            was_connected=self.is_connected,
        )

        self._adapter.disconnect()

        self.logger.info(
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
        if not self.is_connected:  # pragma: no cover
            return

        try:
            connection = self._adapter.connection
            if connection is None:  # pragma: no cover
                return

            detector = FlextLdapServerDetector()
            detection_result = detector.detect_from_connection(connection)

            if detection_result.is_success:
                detected_type = detection_result.unwrap()
                self.logger.info(
                    "Server type detected automatically",
                    operation="connect",
                    detected_server_type=detected_type,
                )
            else:  # pragma: no cover
                # Detection failed but non-critical for connection
                self.logger.debug(  # pragma: no cover
                    "Server type detection failed (non-critical)",
                    operation="connect",
                    error=str(detection_result.error),
                )
        except Exception as e:  # pragma: no cover
            # Exception in optional detection is non-critical
            self.logger.debug(  # pragma: no cover
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
            return FlextResult[bool].ok(True)
        return FlextResult[bool].fail("Not connected to LDAP server")
