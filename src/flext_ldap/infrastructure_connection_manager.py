"""LDAP Connection Manager using FLEXT patterns.

This module provides standardized LDAP connection management using
FLEXT core patterns to eliminate manual connection handling.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

from flext_core import FlextResult, create_ldap_config

from flext_ldap.config import FlextLdapConnectionConfig
from flext_ldap.ldap_infrastructure import FlextLdapClient


class FlextLDAPConnectionManager:
    """LDAP connection manager using FLEXT patterns."""

    def __init__(self, host: str, port: int, *, use_ssl: bool = True) -> None:
        """Initialize LDAP connection manager.

        Args:
            host: LDAP server host
            port: LDAP server port
            use_ssl: Whether to use SSL

        """
        self.host = host
        self.port = port
        self.use_ssl = use_ssl

    async def create_connection(self) -> FlextResult[FlextLdapClient]:
        """Create a new LDAP connection.

        Returns:
            Result containing LDAP client or error

        """
        try:
            # Create configuration for the client

            base = create_ldap_config(host=self.host, port=self.port)
            FlextLdapConnectionConfig.model_validate({
                **base.model_dump(),
                "use_ssl": self.use_ssl,
            })

            client = FlextLdapClient(None)

            # Test connection - using new async API
            scheme = "ldaps" if self.use_ssl else "ldap"
            server_uri = f"{scheme}://{self.host}:{self.port}"
            connect_result = await client.connect(server_uri)
            if not connect_result.is_success:
                return FlextResult.fail(
                    f"Connection test failed: {connect_result.error}",
                )
            # On success return client instance (simple manager contract used by tests)
            return FlextResult.ok(client)

        except (ValueError, TypeError, OSError) as e:
            return FlextResult.fail(f"Failed to create LDAP connection: {e}")

    @staticmethod
    async def close_connection(
        connection: FlextLdapClient | object,
    ) -> FlextResult[None]:
        """Close LDAP connection.

        Args:
            connection: Client instance or object with a compatible disconnect method

        Returns:
            Result indicating success or error

        """
        try:
            # Support both our client and mock objects with .disconnect()
            if hasattr(connection, "disconnect"):
                maybe_result = connection.disconnect()
                # Handle either FlextResult or awaitable
                if hasattr(maybe_result, "is_success"):
                    disconnect_result = maybe_result
                else:
                    disconnect_result = await maybe_result
                if not disconnect_result.is_success:
                    return FlextResult.fail(
                        f"Disconnect failed: {disconnect_result.error}",
                    )
                return FlextResult.ok(None)
            return FlextResult.fail("Invalid connection object: no disconnect()")
        except (ValueError, TypeError, OSError) as e:
            return FlextResult.fail(f"Failed to close LDAP connection: {e}")

    @staticmethod
    async def validate_connection(
        connection: FlextLdapClient,
    ) -> FlextResult[bool]:
        """Validate LDAP connection is still active.

        Args:
            connection: Client instance that exposes is_connected()

        Returns:
            Result containing validation status

        """
        try:
            # Check if client has _is_connected attribute
            is_connected: bool = bool(getattr(connection, "_is_connected", False))
            return FlextResult.ok(is_connected)
        except (ValueError, TypeError, OSError) as e:
            return FlextResult.fail(f"Failed to validate LDAP connection: {e}")
