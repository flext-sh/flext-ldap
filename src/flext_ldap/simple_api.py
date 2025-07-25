"""Simple API interface for FLEXT-LDAP v0.7.0.

REFACTORED: Direct implementation with FlextResult - NO dependency injection.
Provides clean API interface for all LDAP operations.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any
from uuid import uuid4

# 🚨 ARCHITECTURAL COMPLIANCE: Using flext_core root imports
from flext_core import FlextConnectionError, FlextResult

from flext_ldap.client import FlextLdapClient
from flext_ldap.config import FlextLdapAuthConfig, FlextLdapConnectionConfig
from flext_ldap.domain.entities import FlextLdapConnection
from flext_ldap.domain.value_objects import FlextLdapCreateUserRequest
from flext_ldap.infrastructure.ldap_client import FlextLdapInfrastructureClient
from flext_ldap.infrastructure.ldap_simple_client import LdapConnectionInfo

if TYPE_CHECKING:
    from typing import Protocol

    class ConnectionProtocol(Protocol):
        """Protocol for LDAP connection providers."""

        async def connect(
            self,
            server_url: str,
            bind_dn: str | None = None,
            password: str | None = None,
        ) -> FlextResult[str]:
            """Connect to LDAP server."""
            ...


class FlextLdapAPI:
    """Simple API interface for LDAP operations.

    Direct implementation using LDAP infrastructure client.
    All operations return FlextResult for type-safe error handling.
    """

    def __init__(self, connection_provider: ConnectionProtocol | None = None) -> None:
        """Initialize API with connection provider.

        Args:
            connection_provider: ConnectionProtocol implementation for LDAP connections

        """
        if connection_provider is None:
            # Use default LDAP client implementation
            self._connection_provider = FlextLdapClient()
        else:
            self._connection_provider = connection_provider

        self._connections: dict[str, FlextLdapConnection] = {}
        self._active_connection: FlextLdapConnection | None = None
        self._active_connection_id: str | None = None

        # Initialize infrastructure client for user operations
        self._ldap_client = FlextLdapInfrastructureClient()

    # Connection operations
    async def create_connection(
        self,
        server_uri: str,
        bind_dn: str | None = None,
        password: str | None = None,
        *,
        use_ssl: bool = False,
    ) -> FlextResult[FlextLdapConnection]:
        """Create a new LDAP connection using ConnectionProtocol pattern."""
        # 🚨 ARCHITECTURAL COMPLIANCE: Using DI container for flext-core imports
        # Initialize types via DI container

        try:
            # Configure connection provider with settings
            if hasattr(self._connection_provider, "config"):
                # Update provider configuration
                # Create connection configuration directly
                connection_config = FlextLdapConnectionConfig(
                    server=(
                        server_uri.split("://")[1]
                        if "://" in server_uri
                        else server_uri
                    ),
                    port=636 if use_ssl else 389,
                    use_ssl=use_ssl,
                )
                FlextLdapAuthConfig(
                    bind_dn=bind_dn or "",
                    bind_password=password or "",
                )
                # Don't create settings if not used directly
                self._connection_provider.config = connection_config

            # Use FLEXT connection services through infrastructure client
            try:
                # Use the FlextLdapClient connect method
                await self._connection_provider.connect()

                # Create domain entity for successful connection
                connection = FlextLdapConnection(
                    id=str(uuid4()),
                    server_url=server_uri,
                    bind_dn=bind_dn,
                )
                # Set as connected since we got success from infrastructure
                connection = connection.connect()

                # Store connection using infrastructure ID pattern
                self._active_connection_id = str(connection.id)
                self._connections[server_uri] = connection
                self._active_connection = connection
                return FlextResult.ok(connection)

            except Exception as exc:
                msg = f"Connection failed: {exc}"
                raise FlextConnectionError(
                    msg,
                ) from exc

        except Exception as e:
            return FlextResult.fail(f"Failed to create connection: {e}")

    async def connect(self, server_uri: str) -> FlextResult[FlextLdapConnection]:
        """Connect to LDAP server by URI."""
        # 🚨 ARCHITECTURAL COMPLIANCE: Using DI container for flext-core imports

        if server_uri in self._connections:
            connection = self._connections[server_uri]
            self._active_connection = connection
            return FlextResult.ok(connection)

        return FlextResult.fail(f"Connection not found for server: {server_uri}")

    async def disconnect(self) -> FlextResult[bool]:
        """Disconnect from current LDAP server."""
        # 🚨 ARCHITECTURAL COMPLIANCE: Using DI container for flext-core imports

        try:
            if self._active_connection:  # Removed protocol method
                # Use ConnectionProtocol pattern - disconnect managed by context manager
                # but we can manually disconnect if needed
                if self._active_connection:
                    self._active_connection.disconnect()  # Update domain state
                    self._active_connection = None
                    self._active_connection_id = None
                return FlextResult.ok(True)

            return FlextResult.ok(True)  # Already disconnected

        except Exception as e:
            return FlextResult.fail(f"Failed to disconnect: {e}")

    def get_active_connection(self) -> FlextResult[FlextLdapConnection | None]:
        """Get the currently active connection."""
        # 🚨 ARCHITECTURAL COMPLIANCE: Using DI container for flext-core imports

        return FlextResult.ok(self._active_connection)

    # User operations
    async def create_user(
        self,
        dn: str,
        uid: str,
        cn: str,
        sn: str,
        mail: str | None = None,
        phone: str | None = None,
        ou: str | None = None,
        department: str | None = None,
        title: str | None = None,
        object_classes: list[str] | None = None,
    ) -> FlextResult[Any]:
        """Create a new LDAP user."""
        # 🚨 ARCHITECTURAL COMPLIANCE: Using DI container for flext-core imports

        try:
            if not self._active_connection:
                return FlextResult.fail("No active LDAP connection")

            # Create user request object
            request = FlextLdapCreateUserRequest(
                dn=dn,
                uid=uid,
                cn=cn,
                sn=sn,
                mail=mail,
                phone=phone,
                ou=ou,
                department=department,
                title=title,
                object_classes=object_classes or ["person", "inetOrgPerson"],
            )

            return await self._ldap_client.create_user(self._active_connection, request)

        except Exception as e:
            return FlextResult.fail(f"Failed to create user: {e}")

    async def find_user_by_dn(self, dn: str) -> FlextResult[Any]:
        """Find user by distinguished name."""
        # 🚨 ARCHITECTURAL COMPLIANCE: Using DI container for flext-core imports

        try:
            if not self._active_connection:
                return FlextResult.fail("No active LDAP connection")

            return await self._ldap_client.find_user_by_dn(self._active_connection, dn)

        except Exception as e:
            return FlextResult.fail(f"Failed to find user by DN: {e}")

    async def find_user_by_uid(self, uid: str) -> FlextResult[Any]:
        """Find user by UID."""
        # 🚨 ARCHITECTURAL COMPLIANCE: Using DI container for flext-core imports

        try:
            if not self._active_connection:
                return FlextResult.fail("No active LDAP connection")

            return await self._ldap_client.find_user_by_uid(
                self._active_connection,
                uid,
            )

        except Exception as e:
            return FlextResult.fail(f"Failed to find user by UID: {e}")

    async def list_users(
        self,
        base_dn: str,
        limit: int = 100,
    ) -> FlextResult[Any]:
        """List users in organizational unit."""
        # 🚨 ARCHITECTURAL COMPLIANCE: Using DI container for flext-core imports

        try:
            if not self._active_connection:
                return FlextResult.fail("No active LDAP connection")

            # Convert connection to LdapConnectionInfo
            connection_info = LdapConnectionInfo(
                server_url=self._active_connection.server_url,
                bind_dn=self._active_connection.bind_dn,
            )

            return await self._ldap_client.list_users(
                connection_info,
                base_dn,
            )

        except Exception as e:
            return FlextResult.fail(f"Failed to list users: {e}")

    async def delete_user(self, dn: str) -> FlextResult[bool]:
        """Delete user account by DN."""
        # 🚨 ARCHITECTURAL COMPLIANCE: Using DI container for flext-core imports

        try:
            if not self._active_connection:
                return FlextResult.fail("No active LDAP connection")

            # Convert connection to LdapConnectionInfo
            connection_info = LdapConnectionInfo(
                server_url=self._active_connection.server_url,
                bind_dn=self._active_connection.bind_dn,
            )

            result = await self._ldap_client.delete_user(connection_info, dn)
            # Convert None result to bool for compatibility
            return FlextResult.ok(result.success)

        except Exception as e:
            return FlextResult.fail(f"Failed to delete user: {e}")


# Factory function for easy API creation
def create_ldap_api() -> FlextLdapAPI:
    """Create and return LDAP API instance."""
    return FlextLdapAPI()
