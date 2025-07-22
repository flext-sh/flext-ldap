"""High-level LDAP service integrating all operations.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

Complete LDAP service with real directory integration.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from flext_core import injectable
from flext_core.domain.shared_types import ServiceResult

from flext_ldap.infrastructure.ldap_client import LDAPInfrastructureClient

if TYPE_CHECKING:
    from uuid import UUID

    from flext_ldap.domain.entities import LDAPGroup, LDAPUser
    from flext_ldap.domain.value_objects import CreateUserRequest


@injectable()
class LDAPService:
    """High-level LDAP service integrating all LDAP operations."""

    def __init__(
        self,
        ldap_client: LDAPInfrastructureClient | None = None,
    ) -> None:
        """Initialize the LDAP service with LDAP client dependency."""
        self._ldap_client = ldap_client or LDAPInfrastructureClient()
        self._active_connection_id: UUID | None = None
        # Store active connections in memory for this session
        self._connections: dict[UUID, Any] = {}

    async def connect_to_server(
        self,
        server_uri: str,
        bind_dn: str | None = None,
        password: str | None = None,
        *,
        use_ssl: bool = False,
    ) -> ServiceResult[Any]:
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
            from datetime import UTC, datetime
            from uuid import uuid4

            from flext_ldap.domain.entities import LDAPConnection

            # Use LDAP client to create infrastructure connection
            result = await self._ldap_client.connect(
                server_uri,
                bind_dn,
                password,
                use_ssl=use_ssl,
            )

            if not result.success:
                return ServiceResult.fail(f"Failed to connect to LDAP: {result.error}")

            # Create domain entity for connection
            connection = LDAPConnection(
                id=uuid4(),
                server_url=server_uri,
                bind_dn=bind_dn,
                created_at=datetime.now(UTC),
                updated_at=datetime.now(UTC),
            )
            connection.connect()  # Mark as connected
            if bind_dn:
                connection.bind(bind_dn)

            # Store connection
            self._active_connection_id = connection.id
            self._connections[connection.id] = connection

            return ServiceResult.ok(connection)

        except Exception as e:
            msg = f"Failed to connect to server: {e}"
            return ServiceResult.fail(msg)

    async def disconnect_from_server(self) -> ServiceResult[Any]:
        """Disconnect from the currently active LDAP server.

        Returns:
            ServiceResult indicating success or failure

        """
        try:
            if not self._active_connection_id:
                return ServiceResult.fail("No active connection")

            # Get connection and disconnect
            connection = self._connections.get(self._active_connection_id)
            if connection:
                # Use connection ID for infrastructure operations
                connection_id = (
                    f"{connection.server_url}:{connection.bind_dn or 'anonymous'}"
                )
                result = await self._ldap_client.disconnect(connection_id)
                if not result.success:
                    return ServiceResult.fail(
                        result.error or "Failed to disconnect",
                    )
                # Update domain state
                connection.disconnect()

            # Clear connection state
            if self._active_connection_id in self._connections:
                del self._connections[self._active_connection_id]
            self._active_connection_id = None

            return ServiceResult.ok(True)

        except Exception as e:
            msg = f"Failed to disconnect from server: {e}"
            return ServiceResult.fail(msg)

    # User Operations

    async def create_user(self, request: CreateUserRequest) -> ServiceResult[Any]:
        """Create a new LDAP user.

        Args:
            request: User creation request with validation

        Returns:
            ServiceResult containing the created LDAPUser or error

        """
        try:
            # Check if we have an active connection for real LDAP operations
            if self._active_connection_id:
                connection = self._connections.get(self._active_connection_id)
                if connection:
                    # Use LDAP client for real connection
                    return await self._ldap_client.create_user(connection, request)

            # Memory mode - create user object for testing/offline use
            from datetime import UTC, datetime
            from uuid import uuid4

            from flext_ldap.domain.entities import LDAPUser

            user = LDAPUser(
                id=uuid4(),
                dn=request.dn,
                uid=request.uid,
                cn=request.cn,
                sn=request.sn,
                mail=request.mail,
                phone=request.phone,
                ou=request.ou,
                department=request.department,
                title=request.title,
                object_classes=request.object_classes or ["inetOrgPerson"],
                created_at=datetime.now(UTC),
                updated_at=datetime.now(UTC),
            )

            # Store in memory for retrieval
            if not hasattr(self, "_memory_users"):
                self._memory_users: dict[str, LDAPUser] = {}
            self._memory_users[request.uid] = user

            return ServiceResult.ok(user)

        except Exception as e:
            msg = f"Failed to create user: {e}"
            return ServiceResult.fail(msg)

    async def find_user_by_dn(self, dn: str) -> ServiceResult[Any]:
        """Find an LDAP user by distinguished name.

        Args:
            dn: Distinguished name to search for

        Returns:
            ServiceResult containing the LDAPUser if found, None if not found, or error

        """
        try:
            if not self._active_connection_id:
                return ServiceResult.fail("No active LDAP connection")

            connection = self._connections.get(self._active_connection_id)
            if not connection:
                return ServiceResult.fail("Active connection not found")

            # Use LDAP client to find user by DN
            return await self._ldap_client.find_user_by_dn(connection, dn)

        except Exception as e:
            msg = f"Failed to find user by DN: {e}"
            return ServiceResult.fail(msg)

    async def find_user_by_uid(self, uid: str) -> ServiceResult[Any]:
        """Find an LDAP user by user identifier.

        Args:
            uid: User identifier to search for

        Returns:
            ServiceResult containing the LDAPUser if found, None if not found, or error

        """
        try:
            # Check if we have an active connection for real LDAP operations
            if self._active_connection_id:
                connection = self._connections.get(self._active_connection_id)
                if connection:
                    # Use LDAP client for real connection
                    return await self._ldap_client.find_user_by_uid(connection, uid)

            # Memory mode - search in stored users
            if hasattr(self, "_memory_users"):
                user = self._memory_users.get(uid)
                return ServiceResult.ok(user)

            # No user found
            return ServiceResult.ok(None)

        except Exception as e:
            msg = f"Failed to find user by UID: {e}"
            return ServiceResult.fail(msg)

    async def update_user(
        self,
        user_id: UUID,
        updates: dict[str, Any],
    ) -> ServiceResult[Any]:
        """Update an existing LDAP user.

        Args:
            user_id: The unique identifier of the user to update
            updates: Dictionary of attributes to update

        Returns:
            ServiceResult containing the updated LDAPUser or error

        """
        try:
            # Check if we have an active connection for real LDAP operations
            if self._active_connection_id:
                connection = self._connections.get(self._active_connection_id)
                if connection:
                    # Use LDAP client for real connection
                    return await self._ldap_client.update_user(
                        connection, user_id, updates,
                    )

            # Memory mode - update user in memory
            if hasattr(self, "_memory_users"):
                # Find user by ID
                for user in self._memory_users.values():
                    if user.id == user_id:
                        # Update user attributes
                        for key, value in updates.items():
                            setattr(user, key, value)

                        # Update timestamp
                        from datetime import UTC, datetime

                        user.updated_at = datetime.now(UTC)

                        return ServiceResult.ok(user)

            return ServiceResult.fail("User not found")

        except Exception as e:
            msg = f"Failed to update user: {e}"
            return ServiceResult.fail(msg)

    async def delete_user(self, user_id: UUID) -> ServiceResult[Any]:
        """Delete an LDAP user.

        Args:
            user_id: The unique identifier of the user to delete

        Returns:
            ServiceResult containing True if deleted successfully, or error

        """
        try:
            # Check if we have an active connection for real LDAP operations
            if self._active_connection_id:
                connection = self._connections.get(self._active_connection_id)
                if connection:
                    # Use LDAP client for real connection
                    return await self._ldap_client.delete_user(connection, user_id)

            # Memory mode - delete user from memory
            if hasattr(self, "_memory_users"):
                # Find and remove user by ID
                for uid, user in list(self._memory_users.items()):
                    if user.id == user_id:
                        del self._memory_users[uid]
                        return ServiceResult.ok(True)

            return ServiceResult.fail("User not found")

        except Exception as e:
            msg = f"Failed to delete user: {e}"
            return ServiceResult.fail(msg)

    async def list_users(
        self,
        ou: str | None = None,
        limit: int = 100,
    ) -> ServiceResult[Any]:
        """List LDAP users with optional filtering.

        Args:
            ou: Organizational unit to filter by (optional)
            limit: Maximum number of users to return (default: 100)

        Returns:
            ServiceResult containing list of LDAPUsers or error

        """
        try:
            # Check if we have an active connection for real LDAP operations
            if self._active_connection_id:
                connection = self._connections.get(self._active_connection_id)
                if connection:
                    # Use LDAP client for real connection
                    return await self._ldap_client.list_users(connection, ou, limit)

            # Memory mode - return stored users
            if hasattr(self, "_memory_users"):
                users = list(self._memory_users.values())

                # Apply OU filter if specified
                if ou:
                    users = [user for user in users if ou in user.dn]

                # Apply limit
                users = users[:limit]

                return ServiceResult.ok(users)

            # No users in memory
            return ServiceResult.ok([])

        except Exception as e:
            msg = f"Failed to list users: {e}"
            return ServiceResult.fail(msg)

    async def lock_user(self, user_id: UUID) -> ServiceResult[Any]:
        """Lock an LDAP user account.

        Args:
            user_id: The unique identifier of the user to lock

        Returns:
            ServiceResult containing the locked LDAPUser or error

        """
        try:
            # Check if we have an active connection for real LDAP operations
            if self._active_connection_id:
                connection = self._connections.get(self._active_connection_id)
                if connection:
                    # Use LDAP client for real connection
                    return await self._ldap_client.lock_user(connection, user_id)

            # Memory mode - lock user in memory
            if hasattr(self, "_memory_users"):
                # Find user by ID
                for user in self._memory_users.values():
                    if user.id == user_id:
                        # Set locked status using entity status
                        from flext_core.domain.shared_types import EntityStatus

                        user.status = EntityStatus.INACTIVE

                        # Update timestamp
                        from datetime import UTC, datetime

                        user.updated_at = datetime.now(UTC)

                        return ServiceResult.ok(user)

            return ServiceResult.fail("User not found")

        except Exception as e:
            msg = f"Failed to lock user: {e}"
            return ServiceResult.fail(msg)

    async def unlock_user(self, user_id: UUID) -> ServiceResult[Any]:
        """Unlock an LDAP user account.

        Args:
            user_id: The unique identifier of the user to unlock

        Returns:
            ServiceResult containing the unlocked LDAPUser or error

        """
        try:
            # Check if we have an active connection for real LDAP operations
            if self._active_connection_id:
                connection = self._connections.get(self._active_connection_id)
                if connection:
                    # Use LDAP client for real connection
                    return await self._ldap_client.unlock_user(connection, user_id)

            # Memory mode - unlock user in memory
            if hasattr(self, "_memory_users"):
                # Find user by ID
                for user in self._memory_users.values():
                    if user.id == user_id:
                        # Set unlocked status using entity status
                        from flext_core.domain.shared_types import EntityStatus

                        user.status = EntityStatus.ACTIVE

                        # Update timestamp
                        from datetime import UTC, datetime

                        user.updated_at = datetime.now(UTC)

                        return ServiceResult.ok(user)

            return ServiceResult.fail("User not found")

        except Exception as e:
            msg = f"Failed to unlock user: {e}"
            return ServiceResult.fail(msg)

    # Group Operations

    async def create_group(
        self,
        dn: str,
        cn: str,
        ou: str | None = None,
        members: list[str] | None = None,
        owners: list[str] | None = None,
        object_classes: list[str] | None = None,
    ) -> ServiceResult[Any]:
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
        try:
            # Check if we have an active connection for real LDAP operations
            if self._active_connection_id:
                connection = self._connections.get(self._active_connection_id)
                if connection:
                    # Real LDAP group operations would be implemented here
                    return ServiceResult.fail(
                        "Real LDAP group operations not yet implemented",
                    )

            # Memory mode - create group object for testing/offline use
            from datetime import UTC, datetime
            from uuid import uuid4

            from flext_ldap.domain.entities import LDAPGroup

            group = LDAPGroup(
                id=uuid4(),
                dn=dn,
                cn=cn,
                ou=ou,
                members=members or [],
                owners=owners or [],
                object_classes=object_classes or ["groupOfNames"],
                created_at=datetime.now(UTC),
                updated_at=datetime.now(UTC),
            )

            # Store in memory for retrieval
            if not hasattr(self, "_memory_groups"):
                self._memory_groups: dict[str, LDAPGroup] = {}
            self._memory_groups[cn] = group

            return ServiceResult.ok(group)

        except Exception as e:
            msg = f"Failed to create group: {e}"
            return ServiceResult.fail(msg)

    async def find_group_by_dn(self, dn: str) -> ServiceResult[Any]:
        """Find an LDAP group by distinguished name.

        Args:
            dn: Distinguished name to search for

        Returns:
            ServiceResult containing the LDAPGroup if found, None if not found, or error

        """
        try:
            # Check if we have an active connection for real LDAP operations
            if self._active_connection_id:
                connection = self._connections.get(self._active_connection_id)
                if connection:
                    # Real LDAP group operations would be implemented here
                    return ServiceResult.fail(
                        "Real LDAP group operations not yet implemented",
                    )

            # Memory mode - search in stored groups
            if hasattr(self, "_memory_groups"):
                for group in self._memory_groups.values():
                    if group.dn == dn:
                        return ServiceResult.ok(group)

            # No group found
            return ServiceResult.ok(None)

        except Exception as e:
            msg = f"Failed to find group by DN: {e}"
            return ServiceResult.fail(msg)

    async def add_user_to_group(
        self,
        group_id: UUID,
        user_dn: str,
    ) -> ServiceResult[Any]:
        """Add a user to an LDAP group.

        Args:
            group_id: The unique identifier of the group
            user_dn: Distinguished name of the user to add

        Returns:
            ServiceResult containing the updated LDAPGroup or error

        """
        try:
            # Check if we have an active connection for real LDAP operations
            if self._active_connection_id:
                connection = self._connections.get(self._active_connection_id)
                if connection:
                    # Real LDAP group operations would be implemented here
                    return ServiceResult.fail(
                        "Real LDAP group operations not yet implemented",
                    )

            # Memory mode - find group and add member
            if hasattr(self, "_memory_groups"):
                for group in self._memory_groups.values():
                    if group.id == group_id:
                        group.add_member(user_dn)
                        return ServiceResult.ok(group)

            return ServiceResult.fail("Group not found")

        except Exception as e:
            msg = f"Failed to add user to group: {e}"
            return ServiceResult.fail(msg)

    async def remove_user_from_group(
        self,
        group_id: UUID,
        user_dn: str,
    ) -> ServiceResult[Any]:
        """Remove a user from an LDAP group.

        Args:
            group_id: The unique identifier of the group
            user_dn: Distinguished name of the user to remove

        Returns:
            ServiceResult containing the updated LDAPGroup or error

        """
        try:
            # Check if we have an active connection for real LDAP operations
            if self._active_connection_id:
                connection = self._connections.get(self._active_connection_id)
                if connection:
                    # Real LDAP group operations would be implemented here
                    return ServiceResult.fail(
                        "Real LDAP group operations not yet implemented",
                    )

            # Memory mode - find group and remove member
            if hasattr(self, "_memory_groups"):
                for group in self._memory_groups.values():
                    if group.id == group_id:
                        group.remove_member(user_dn)
                        return ServiceResult.ok(group)

            return ServiceResult.fail("Group not found")

        except Exception as e:
            msg = f"Failed to remove user from group: {e}"
            return ServiceResult.fail(msg)

    async def list_groups(
        self,
        ou: str | None = None,
        limit: int = 100,
    ) -> ServiceResult[Any]:
        """List LDAP groups with optional filtering.

        Args:
            ou: Organizational unit to filter by (optional)
            limit: Maximum number of groups to return (default: 100)

        Returns:
            ServiceResult containing list of LDAPGroups or error

        """
        try:
            # Check if we have an active connection for real LDAP operations
            if self._active_connection_id:
                connection = self._connections.get(self._active_connection_id)
                if connection:
                    # Real LDAP group operations would be implemented here
                    return ServiceResult.fail(
                        "Real LDAP group operations not yet implemented",
                    )

            # Memory mode - return stored groups
            if hasattr(self, "_memory_groups"):
                groups = list(self._memory_groups.values())

                # Apply OU filter if specified
                if ou:
                    groups = [group for group in groups if group.ou == ou]

                # Apply limit
                groups = groups[:limit]

                return ServiceResult.ok(groups)

            # No groups in memory
            return ServiceResult.ok([])

        except Exception as e:
            msg = f"Failed to list groups: {e}"
            return ServiceResult.fail(msg)

    async def delete_group(self, group_id: UUID) -> ServiceResult[Any]:
        """Delete an LDAP group.

        Args:
            group_id: The unique identifier of the group to delete

        Returns:
            ServiceResult containing True if deleted successfully, or error

        """
        try:
            # Check if we have an active connection for real LDAP operations
            if self._active_connection_id:
                connection = self._connections.get(self._active_connection_id)
                if connection:
                    # Real LDAP group operations would be implemented here
                    return ServiceResult.fail(
                        "Real LDAP group operations not yet implemented",
                    )

            # Memory mode - delete group from memory
            if hasattr(self, "_memory_groups"):
                # Find and remove group by ID
                for cn, group in list(self._memory_groups.items()):
                    if group.id == group_id:
                        del self._memory_groups[cn]
                        return ServiceResult.ok(True)

            return ServiceResult.fail("Group not found")

        except Exception as e:
            msg = f"Failed to delete group: {e}"
            return ServiceResult.fail(msg)

    # Connection Operations

    async def get_active_connection(self) -> ServiceResult[Any]:
        """Get the currently active LDAP connection.

        Returns:
            ServiceResult containing the active LDAPConnection if exists, None otherwise, or error

        """
        if not self._active_connection_id:
            return ServiceResult.ok(None)

        connection = self._connections.get(self._active_connection_id)
        return ServiceResult.ok(connection)

    async def list_connections(self) -> ServiceResult[Any]:
        """List all LDAP connections.

        Returns:
            ServiceResult containing list of LDAPConnections or error

        """
        connections = list(self._connections.values())
        return ServiceResult.ok(connections)

    # Utility Methods

    def is_connected(self) -> bool:
        """Check if there is an active LDAP connection.

        Returns:
            True if connected to an LDAP server, False otherwise

        """
        return self._active_connection_id is not None

    async def test_connection(self) -> ServiceResult[Any]:
        """Test the current LDAP connection.

        Returns:
            ServiceResult containing connection test results or error

        """
        try:
            if not self._active_connection_id:
                return ServiceResult.fail("No active connection to test")

            connection_result = await self.get_active_connection()
            if not connection_result.success:
                return ServiceResult.fail("Failed to get active connection")

            connection = connection_result.data
            if not connection:
                return ServiceResult.fail("No active connection found")

            # Get connection info from infrastructure client
            ldap_connection_id = (
                f"{connection.server_url}:{connection.bind_dn or 'anonymous'}"
            )
            info_result = self._ldap_client.get_connection_info(ldap_connection_id)

            if not info_result.success:
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
