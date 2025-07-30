"""LDAP Connection Manager using FLEXT patterns.

This module provides standardized LDAP connection management using
FLEXT core patterns to eliminate manual connection handling.
"""

from __future__ import annotations

from flext_core import FlextResult

from flext_ldap.client import FlextLdapClient
from flext_ldap.config import FlextLdapConnectionConfig


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

            config = FlextLdapConnectionConfig(
                server=self.host,
                port=self.port,
                use_ssl=self.use_ssl,
            )

            client = FlextLdapClient(config)

            # Test connection
            await client.connect()
            return FlextResult.ok(client)

        except (ValueError, TypeError, OSError) as e:
            return FlextResult.fail(f"Failed to create LDAP connection: {e}")

    async def close_connection(self, connection: FlextLdapClient) -> FlextResult[None]:
        """Close LDAP connection.

        Args:
            connection: LDAP client to close

        Returns:
            Result indicating success or error

        """
        try:
            await connection.disconnect()
            return FlextResult.ok(None)
        except (ValueError, TypeError, OSError) as e:
            return FlextResult.fail(f"Failed to close LDAP connection: {e}")

    async def validate_connection(
        self, connection: FlextLdapClient,
    ) -> FlextResult[bool]:
        """Validate LDAP connection is still active.

        Args:
            connection: LDAP client to validate

        Returns:
            Result containing validation status

        """
        try:
            is_connected = connection.is_connected()
            return FlextResult.ok(is_connected)
        except (ValueError, TypeError, OSError) as e:
            return FlextResult.fail(f"Failed to validate LDAP connection: {e}")
