"""High-level LDAP service integrating all operations.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

Complete LDAP service with real directory integration.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from flext_core.config import injectable
from flext_core.domain.types import ServiceResult

from flext_ldap.application.services import (
    LDAPConnectionService,
    LDAPGroupService,
    LDAPOperationService,
    LDAPUserService,
)
from flext_ldap.infrastructure.ldap_client import LDAPInfrastructureClient

if TYPE_CHECKING:
    from uuid import UUID

    from flext_ldap.domain.entities import LDAPConnection, LDAPGroup, LDAPUser
    from flext_ldap.domain.value_objects import CreateUserRequest


@injectable()
class LDAPService:
    """High-level LDAP service integrating all LDAP operations."""

    def __init__(
        self,
        ldap_client: LDAPInfrastructureClient | None = None,
        user_service: LDAPUserService | None = None,
        group_service: LDAPGroupService | None = None,
        connection_service: LDAPConnectionService | None = None,
        operation_service: LDAPOperationService | None = None,
    ) -> None:
        """Initialize the LDAP service with all dependencies."""
        self._ldap_client = ldap_client or LDAPInfrastructureClient()
        self._user_service = user_service or LDAPUserService(self._ldap_client)
        self._group_service = group_service or LDAPGroupService()
        self._connection_service = connection_service or LDAPConnectionService(
            self._ldap_client,
        )
        self._operation_service = operation_service or LDAPOperationService()
        self._active_connection_id: UUID | None = None

    async def connect_to_server(
        self,
        server_uri: str,
        bind_dn: str | None = None,
        password: str | None = None,
        *,
        use_ssl: bool = False,
    ) -> ServiceResult[LDAPConnection]:
        """Connect to LDAP server and set as active connection.

        Args:
            server_uri: LDAP server URI
            bind_dn: Distinguished name for binding (optional for anonymous)
            password: Password for binding (optional)
            use_ssl: Use SSL/TLS connection

        Returns:
            ServiceResult containing the established LDAPConnection or error

        """
        try:
            # Create the connection
            result = await self._connection_service.create_connection(
                server_uri,
                bind_dn,
                password,
                use_ssl=use_ssl,
            )

            if not result.is_success:
                return result

            connection = result.data
            if connection is not None:
                self._active_connection_id = connection.id

            # Set connection for user service to enable real LDAP operations
            ldap_connection_id = f"{server_uri}:{bind_dn or 'anonymous'}"
            await self._user_service.set_connection(ldap_connection_id)

            if connection is not None:
                return ServiceResult.ok(connection)
            return ServiceResult.fail("Failed to create connection")

        except Exception as e:
            msg = f"Failed to connect to server: {e}"
            return ServiceResult.fail(msg)

    async def disconnect_from_server(self) -> ServiceResult[bool]:
        """Disconnect from the currently active LDAP server.

        Returns:
            ServiceResult indicating success or failure

        """
        try:
            if not self._active_connection_id:
                return ServiceResult.fail("No active connection")

            # Disconnect from server
            result = await self._connection_service.disconnect(
                self._active_connection_id,
            )
            if not result.is_success:
                return ServiceResult.fail(
                    result.error or "Failed to disconnect",
                )

            # Clear connection from user service
            await self._user_service.clear_connection()
            self._active_connection_id = None

            return ServiceResult.ok(True)

        except Exception as e:
            msg = f"Failed to disconnect from server: {e}"
            return ServiceResult.fail(msg)

    # User Operations

    async def create_user(self, request: CreateUserRequest) -> ServiceResult[LDAPUser]:
        """Create a new LDAP user.

        Args:
            request: User creation request with validation

        Returns:
            ServiceResult containing the created LDAPUser or error

        """
        return await self._user_service.create_user(request)

    async def find_user_by_dn(self, dn: str) -> ServiceResult[LDAPUser | None]:
        """Find an LDAP user by distinguished name.

        Args:
            dn: Distinguished name to search for

        Returns:
            ServiceResult containing the LDAPUser if found, None if not found, or error

        """
        return await self._user_service.find_user_by_dn(dn)

    async def find_user_by_uid(self, uid: str) -> ServiceResult[LDAPUser | None]:
        """Find an LDAP user by user identifier.

        Args:
            uid: User identifier to search for

        Returns:
            ServiceResult containing the LDAPUser if found, None if not found, or error

        """
        return await self._user_service.find_user_by_uid(uid)

    async def update_user(
        self,
        user_id: UUID,
        updates: dict[str, Any],
    ) -> ServiceResult[LDAPUser]:
        """Update an existing LDAP user.

        Args:
            user_id: The unique identifier of the user to update
            updates: Dictionary of attributes to update

        Returns:
            ServiceResult containing the updated LDAPUser or error

        """
        return await self._user_service.update_user(user_id, updates)

    async def delete_user(self, user_id: UUID) -> ServiceResult[bool]:
        """Delete an LDAP user.

        Args:
            user_id: The unique identifier of the user to delete

        Returns:
            ServiceResult containing True if deleted successfully, or error

        """
        return await self._user_service.delete_user(user_id)

    async def list_users(
        self,
        ou: str | None = None,
        limit: int = 100,
    ) -> ServiceResult[list[LDAPUser]]:
        """List LDAP users with optional filtering.

        Args:
            ou: Organizational unit to filter by (optional)
            limit: Maximum number of users to return (default: 100)

        Returns:
            ServiceResult containing list of LDAPUsers or error

        """
        return await self._user_service.list_users(ou, limit)

    async def lock_user(self, user_id: UUID) -> ServiceResult[LDAPUser]:
        """Lock an LDAP user account.

        Args:
            user_id: The unique identifier of the user to lock

        Returns:
            ServiceResult containing the locked LDAPUser or error

        """
        return await self._user_service.lock_user(user_id)

    async def unlock_user(self, user_id: UUID) -> ServiceResult[LDAPUser]:
        """Unlock an LDAP user account.

        Args:
            user_id: The unique identifier of the user to unlock

        Returns:
            ServiceResult containing the unlocked LDAPUser or error

        """
        return await self._user_service.unlock_user(user_id)

    # Group Operations

    async def create_group(
        self,
        dn: str,
        cn: str,
        ou: str | None = None,
        members: list[str] | None = None,
        owners: list[str] | None = None,
        object_classes: list[str] | None = None,
    ) -> ServiceResult[LDAPGroup]:
        """Create a new LDAP group.

        Args:
            dn: Distinguished name for the group
            cn: Common name
            ou: Organizational unit (optional)
            members: List of member DNs (optional)
            owners: List of owner DNs (optional)
            object_classes: LDAP object classes (optional, defaults to ["groupOfNames"])

        Returns:
            ServiceResult containing the created LDAPGroup or error

        """
        return await self._group_service.create_group(
            dn,
            cn,
            ou,
            members,
            owners,
            object_classes,
        )

    async def find_group_by_dn(self, dn: str) -> ServiceResult[LDAPGroup | None]:
        """Find an LDAP group by distinguished name.

        Args:
            dn: Distinguished name to search for

        Returns:
            ServiceResult containing the LDAPGroup if found, None if not found, or error

        """
        return await self._group_service.find_group_by_dn(dn)

    async def add_user_to_group(
        self,
        group_id: UUID,
        user_dn: str,
    ) -> ServiceResult[LDAPGroup]:
        """Add a user to an LDAP group.

        Args:
            group_id: The unique identifier of the group
            user_dn: Distinguished name of the user to add

        Returns:
            ServiceResult containing the updated LDAPGroup or error

        """
        return await self._group_service.add_member(group_id, user_dn)

    async def remove_user_from_group(
        self,
        group_id: UUID,
        user_dn: str,
    ) -> ServiceResult[LDAPGroup]:
        """Remove a user from an LDAP group.

        Args:
            group_id: The unique identifier of the group
            user_dn: Distinguished name of the user to remove

        Returns:
            ServiceResult containing the updated LDAPGroup or error

        """
        return await self._group_service.remove_member(group_id, user_dn)

    async def list_groups(
        self,
        ou: str | None = None,
        limit: int = 100,
    ) -> ServiceResult[list[LDAPGroup]]:
        """List LDAP groups with optional filtering.

        Args:
            ou: Organizational unit to filter by (optional)
            limit: Maximum number of groups to return (default: 100)

        Returns:
            ServiceResult containing list of LDAPGroups or error

        """
        return await self._group_service.list_groups(ou, limit)

    async def delete_group(self, group_id: UUID) -> ServiceResult[bool]:
        """Delete an LDAP group.

        Args:
            group_id: The unique identifier of the group to delete

        Returns:
            ServiceResult containing True if deleted successfully, or error

        """
        return await self._group_service.delete_group(group_id)

    # Connection Operations

    async def get_active_connection(self) -> ServiceResult[LDAPConnection | None]:
        """Get the currently active LDAP connection.

        Returns:
            ServiceResult containing the active LDAPConnection if exists, None otherwise, or error

        """
        if not self._active_connection_id:
            return ServiceResult.ok(None)

        return await self._connection_service.get_connection(self._active_connection_id)

    async def list_connections(self) -> ServiceResult[list[LDAPConnection]]:
        """List all LDAP connections.

        Returns:
            ServiceResult containing list of LDAPConnections or error

        """
        return await self._connection_service.list_connections()

    # Utility Methods

    def is_connected(self) -> bool:
        """Check if there is an active LDAP connection.

        Returns:
            True if connected to an LDAP server, False otherwise

        """
        return self._active_connection_id is not None

    async def test_connection(self) -> ServiceResult[dict[str, Any]]:
        """Test the current LDAP connection.

        Returns:
            ServiceResult containing connection test results or error

        """
        try:
            if not self._active_connection_id:
                return ServiceResult.fail("No active connection to test")

            connection_result = await self.get_active_connection()
            if not connection_result.is_success:
                return ServiceResult.fail("Failed to get active connection")

            connection = connection_result.data
            if not connection:
                return ServiceResult.fail("No active connection found")

            # Get connection info from infrastructure client
            ldap_connection_id = (
                f"{connection.server_url}:{connection.bind_dn or 'anonymous'}"
            )
            info_result = self._ldap_client.get_connection_info(ldap_connection_id)

            if not info_result.is_success:
                return ServiceResult.fail(
                    f"Failed to get connection info: {info_result.error or 'Unknown error'}",
                )

            test_result = {
                "connected": connection.is_connected,
                "bound": connection.is_bound,
                "server": connection.server_url,
                "bind_dn": connection.bind_dn,
                "connection_info": info_result.data,
            }

            return ServiceResult.ok(test_result)

        except (ValueError, KeyError, AttributeError) as e:
            return ServiceResult.fail(f"Connection test failed: {e}")
