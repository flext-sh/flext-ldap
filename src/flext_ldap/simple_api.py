"""Simple API interface for FLEXT-LDAP v0.7.0.

REFACTORED: Direct implementation with ServiceResult - NO dependency injection.
Provides clean API interface for all LDAP operations.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from flext_core import (
        ConnectionProtocol,
        ServiceResult,  # Use simplified flext-core imports
    )

    from flext_ldap.domain.entities import LDAPConnection


class LDAPAPI:
    """Simple API interface for LDAP operations.

    Direct implementation using LDAP infrastructure client.
    All operations return ServiceResult for type-safe error handling.
    """

    def __init__(self, connection_provider: ConnectionProtocol | None = None) -> None:
        """Initialize API with connection provider.

        Args:
            connection_provider: ConnectionProtocol implementation for LDAP connections

        """
        if connection_provider is None:
            # Use default LDAP client implementation
            from flext_ldap.client import LDAPClient

            self._connection_provider: ConnectionProtocol = LDAPClient()
        else:
            self._connection_provider = connection_provider

        self._connections: dict[str, LDAPConnection] = {}
        self._active_connection: LDAPConnection | None = None
        self._active_connection_id: str | None = None

        # Initialize infrastructure client for user operations
        from flext_ldap.infrastructure.ldap_client import LDAPInfrastructureClient

        self._ldap_client = LDAPInfrastructureClient()

    # Connection operations
    async def create_connection(
        self,
        server_uri: str,
        bind_dn: str | None = None,
        password: str | None = None,
        *,
        use_ssl: bool = False,
    ) -> ServiceResult[LDAPConnection]:
        """Create a new LDAP connection using ConnectionProtocol pattern."""
        from datetime import UTC, datetime
        from uuid import uuid4

        from flext_core.domain.shared_types import ServiceResult

        from flext_ldap.config import (
            FlextLDAPSettings,
            LDAPAuthConfig,
            LDAPConnectionConfig,
        )
        from flext_ldap.domain.entities import LDAPConnection

        try:
            # Configure connection provider with settings
            if hasattr(self._connection_provider, "config"):
                # Update provider configuration
                settings = FlextLDAPSettings(
                    connection=LDAPConnectionConfig(
                        server=server_uri.split("://")[1]
                        if "://" in server_uri
                        else server_uri,
                        port=636 if use_ssl else 389,
                        use_ssl=use_ssl,
                    ),
                    auth=LDAPAuthConfig(
                        bind_dn=bind_dn or "",
                        bind_password=password or "",
                    ),
                )
                self._connection_provider.config = settings.connection

            # Use ConnectionProtocol interface
            await self._connection_provider.connect()

            if self._connection_provider.is_connected():
                # Create domain entity for connection
                connection = LDAPConnection(
                    id=uuid4(),
                    server_url=server_uri,
                    bind_dn=bind_dn,
                    created_at=datetime.now(UTC),
                    updated_at=datetime.now(UTC),
                )
                # Domain entity tracks its own state
                connection.connect()
                if bind_dn:
                    connection.bind(bind_dn)

                # Store connection using infrastructure ID pattern
                self._active_connection_id = str(connection.id)
                self._connections[server_uri] = connection
                self._active_connection = connection
                return ServiceResult.ok(connection)

            return ServiceResult.fail("Connection failed - not connected")

        except Exception as e:
            return ServiceResult.fail(f"Failed to create connection: {e}")

    async def connect(self, server_uri: str) -> ServiceResult[LDAPConnection]:
        """Connect to LDAP server by URI."""
        from flext_core.domain.shared_types import ServiceResult
        if server_uri in self._connections:
            connection = self._connections[server_uri]
            self._active_connection = connection
            return ServiceResult.ok(connection)

        return ServiceResult.fail(f"Connection not found for server: {server_uri}")

    async def disconnect(self) -> ServiceResult[bool]:
        """Disconnect from current LDAP server."""
        from flext_core.domain.shared_types import ServiceResult
        try:
            if self._active_connection and self._connection_provider.is_connected():
                # Use ConnectionProtocol pattern - disconnect managed by context manager
                # but we can manually disconnect if needed
                await self._connection_provider.disconnect()
                if self._active_connection:
                    self._active_connection.disconnect()  # Update domain state
                    self._active_connection = None
                    self._active_connection_id = None
                return ServiceResult.ok(True)

            return ServiceResult.ok(True)  # Already disconnected

        except Exception as e:
            return ServiceResult.fail(f"Failed to disconnect: {e}")

    def get_active_connection(self) -> ServiceResult[LDAPConnection | None]:
        """Get the currently active connection."""
        from flext_core.domain.shared_types import ServiceResult
        return ServiceResult.ok(self._active_connection)

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
    ) -> ServiceResult[Any]:
        """Create a new LDAP user."""
        from flext_core.domain.shared_types import ServiceResult
        try:
            if not self._active_connection:
                return ServiceResult.fail("No active LDAP connection")

            # Create user request object
            from flext_ldap.domain.value_objects import CreateUserRequest

            request = CreateUserRequest(
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
            return ServiceResult.fail(f"Failed to create user: {e}")

    async def find_user_by_dn(self, dn: str) -> ServiceResult[Any]:
        """Find user by distinguished name."""
        from flext_core.domain.shared_types import ServiceResult
        try:
            if not self._active_connection:
                return ServiceResult.fail("No active LDAP connection")

            return await self._ldap_client.find_user_by_dn(self._active_connection, dn)

        except Exception as e:
            return ServiceResult.fail(f"Failed to find user by DN: {e}")

    async def find_user_by_uid(self, uid: str) -> ServiceResult[Any]:
        """Find user by UID."""
        from flext_core.domain.shared_types import ServiceResult
        try:
            if not self._active_connection:
                return ServiceResult.fail("No active LDAP connection")

            return await self._ldap_client.find_user_by_uid(
                self._active_connection,
                uid,
            )

        except Exception as e:
            return ServiceResult.fail(f"Failed to find user by UID: {e}")

    async def list_users(
        self,
        base_dn: str,
        limit: int = 100,
    ) -> ServiceResult[Any]:
        """List users in organizational unit."""
        from flext_core.domain.shared_types import ServiceResult
        try:
            if not self._active_connection:
                return ServiceResult.fail("No active LDAP connection")

            return await self._ldap_client.list_users(
                self._active_connection,
                base_dn,
                limit,
            )

        except Exception as e:
            return ServiceResult.fail(f"Failed to list users: {e}")

    async def delete_user(self, dn: str) -> ServiceResult[bool]:
        """Delete user account by DN."""
        from flext_core.domain.shared_types import ServiceResult
        try:
            if not self._active_connection:
                return ServiceResult.fail("No active LDAP connection")

            return await self._ldap_client.delete_user(self._active_connection, dn)

        except Exception as e:
            return ServiceResult.fail(f"Failed to delete user: {e}")


# Factory function for easy API creation
def create_ldap_api() -> LDAPAPI:
    """Create and return LDAP API instance."""
    return LDAPAPI()
