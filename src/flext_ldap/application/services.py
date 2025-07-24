"""Application services for FLEXT-LDAP v0.7.0.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

REFACTORED:
    Using flext-core service patterns - NO duplication.
    Clean architecture with dependency injection and FlextResult pattern.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any
from uuid import UUID

# 🚨 ARCHITECTURAL COMPLIANCE: Using flext-core root imports
from flext_core import FlextResult

from flext_ldap.application.base import (
    FlextLdapConnectionBaseService,
    FlextLdapGroupBaseService,
    FlextLdapOperationBaseService,
    FlextLdapUserBaseService,
)
from flext_ldap.domain.entities import (
    FlextLdapConnection,
    FlextLdapGroup,
    FlextLdapOperation,
    FlextLdapUser,
)

# Removed port imports to avoid signature conflicts

if TYPE_CHECKING:
    from flext_ldap.domain.value_objects import FlextLdapCreateUserRequest
    from flext_ldap.infrastructure.ldap_client import FlextLdapInfrastructureClient


class FlextLdapUserApplicationService(FlextLdapUserBaseService):
    """Application service for managing LDAP users - ELIMINATES MASSIVE DUPLICATION.

    Inherits from UserBaseService which provides:
    - Dictionary storage pattern (eliminates _users dict duplication)
    - DN search functionality (eliminates find_by_dn duplication)
    - UID search functionality (eliminates find_by_uid duplication)
    - LDAP client integration (eliminates client setup duplication)
    - Connection awareness (eliminates connection management duplication)
    - CRUD operations (eliminates get/delete duplication)

    Note: This is the concrete implementation of the FlextLdapUserService port.
    """

    def __init__(
        self,
        ldap_client: FlextLdapInfrastructureClient | None = None,
    ) -> None:
        """Initialize the LDAP user service with base capabilities."""
        super().__init__(ldap_client)

    async def create_user(
        self,
        request: FlextLdapCreateUserRequest,
    ) -> FlextResult[FlextLdapUser]:
        """Create a new LDAP user.

        Args:
            request: User creation request with validation

        Returns:
            FlextResult containing the created FlextLdapUser or error

        """
        try:
            user = FlextLdapUser(
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
            )

            self._store_entity(user)
            return FlextResult.ok(user)
        except (ValueError, TypeError) as e:
            return FlextResult.fail(f"Failed to create user: {e}")
        except Exception as e:
            msg = f"Unexpected error creating user: {e}"
            return FlextResult.fail(msg)

    async def get_user(self, user_id: UUID) -> FlextResult[FlextLdapUser | None]:
        """Get an LDAP user by ID - USES BASE CLASS IMPLEMENTATION.

        Args:
            user_id: The unique identifier of the user

        Returns:
            FlextResult containing the FlextLdapUser if found, None if not found,
            or error

        """
        return await self.get_entity(user_id)

    async def find_user_by_dn(self, dn: str) -> FlextResult[FlextLdapUser | None]:
        """Find an LDAP user by distinguished name - USES BASE CLASS IMPLEMENTATION.

        Args:
            dn: Distinguished name to search for

        Returns:
            FlextResult containing the FlextLdapUser if found, None if not found,
            or error

        """
        return await self.find_entity_by_dn(dn)

    async def find_user_by_uid(self, uid: str) -> FlextResult[FlextLdapUser | None]:
        """Find an LDAP user by user identifier - USES BASE CLASS IMPLEMENTATION.

        Args:
            uid: User identifier to search for

        Returns:
            FlextResult containing the FlextLdapUser if found, None if not found,
            or error

        """
        return await self.find_entity_by_uid(uid)

    async def update_user(
        self,
        user_id: UUID,
        updates: dict[str, Any],
    ) -> FlextResult[FlextLdapUser]:
        """Update an existing LDAP user.

        Args:
            user_id: The unique identifier of the user to update
            updates: Dictionary of attributes to update

        Returns:
            FlextResult containing the updated FlextLdapUser or error

        """
        try:
            # Convert UUID to string for entity lookup
            key = str(user_id) if isinstance(user_id, UUID) else user_id
            user = self._entities.get(key)
            if not user:
                return FlextResult.fail("User not found")

            # Create a new immutable entity with updates
            entity_data = user.model_dump()
            entity_data.update(updates)
            entity_data.update(
                {
                    "version": user.version + 1,
                },
            )

            updated_user = FlextLdapUser(**entity_data)
            # Store the updated entity back
            self._entities[key] = updated_user
            return FlextResult.ok(updated_user)
        except (KeyError, AttributeError, ValueError) as e:
            return FlextResult.fail(f"Failed to update user: {e}")

    async def lock_user(self, user_id: UUID) -> FlextResult[FlextLdapUser]:
        """Lock an LDAP user account.

        Args:
            user_id: The unique identifier of the user to lock

        Returns:
            FlextResult containing the locked FlextLdapUser or error

        """
        try:
            # Convert UUID to string for entity lookup
            key = str(user_id) if isinstance(user_id, UUID) else user_id
            user = self._entities.get(key)
            if not user:
                return FlextResult.fail("User not found")

            # Entity lock_account returns a new immutable entity
            locked_user = user.lock_account()
            # Store the updated entity back
            self._entities[key] = locked_user
            return FlextResult.ok(locked_user)
        except (KeyError, AttributeError) as e:
            return FlextResult.fail(f"Failed to lock user: {e}")

    async def unlock_user(self, user_id: UUID) -> FlextResult[FlextLdapUser]:
        """Unlock an LDAP user account.

        Args:
            user_id: The unique identifier of the user to unlock

        Returns:
            FlextResult containing the unlocked FlextLdapUser or error

        """
        try:
            # Convert UUID to string for entity lookup
            key = str(user_id) if isinstance(user_id, UUID) else user_id
            user = self._entities.get(key)
            if not user:
                return FlextResult.fail("User not found")

            # Entity unlock_account returns a new immutable entity
            unlocked_user = user.unlock_account()
            # Store the updated entity back
            self._entities[key] = unlocked_user
            return FlextResult.ok(unlocked_user)
        except (KeyError, AttributeError) as e:
            return FlextResult.fail(f"Failed to unlock user: {e}")

    async def delete_user(self, user_id: UUID) -> FlextResult[bool]:
        """Delete an LDAP user - USES BASE CLASS IMPLEMENTATION.

        Args:
            user_id: The unique identifier of the user to delete

        Returns:
            FlextResult containing True if deleted successfully, or error

        """
        return await self.delete_entity(user_id)

    async def list_users(
        self,
        ou: str | None = None,
        limit: int = 100,
    ) -> FlextResult[list[FlextLdapUser]]:
        """List LDAP users with optional filtering - USES BASE CLASS IMPLEMENTATION.

        Args:
            ou: Organizational unit to filter by (optional)
            limit: Maximum number of users to return (default: 100)

        Returns:
            FlextResult containing list of FlextLdapUsers or error

        """
        return await self.list_entities_by_ou(ou, limit)

    # set_connection is inherited from ConnectionAwareService via UserBaseService

    # clear_connection is inherited from ConnectionAwareService via UserBaseService


class FlextLdapGroupService(FlextLdapGroupBaseService):
    """Service for managing LDAP groups - ELIMINATES MASSIVE DUPLICATION.

    Inherits from GroupBaseService which provides:
    - Dictionary storage pattern (eliminates _groups dict duplication)
    - DN search functionality (eliminates find_by_dn duplication)
    - CRUD operations (eliminates get/delete duplication)
    - List operations with OU filtering (eliminates list duplication)
    """

    def __init__(
        self,
        ldap_client: FlextLdapInfrastructureClient | None = None,
    ) -> None:
        """Initialize the LDAP group service with base capabilities."""
        super().__init__(ldap_client)

    async def create_group(
        self,
        dn: str,
        cn: str,
        ou: str | None = None,
        members: list[str] | None = None,
        owners: list[str] | None = None,
        object_classes: list[str] | None = None,
    ) -> FlextResult[FlextLdapGroup]:
        """Create a new LDAP group.

        Args:
            dn: Distinguished name for the group
            cn: Common name
            ou: Organizational unit (optional)
            members: List of member DNs (optional)
            owners: List of owner DNs (optional)
            object_classes: LDAP object classes (optional, defaults to ["groupOfNames"])

        Returns:
            FlextResult containing the created FlextLdapGroup or error

        """
        try:
            group = FlextLdapGroup(
                dn=dn,
                cn=cn,
                ou=ou,
                members=members or [],
                owners=owners or [],
                object_classes=object_classes or ["groupOfNames"],
            )

            self._store_entity(group)
            return FlextResult.ok(group)
        except (ValueError, TypeError) as e:
            return FlextResult.fail(f"Failed to create group: {e}")

    async def get_group(self, group_id: UUID) -> FlextResult[FlextLdapGroup | None]:
        """Get an LDAP group by ID - USES BASE CLASS IMPLEMENTATION.

        Args:
            group_id: The unique identifier of the group

        Returns:
            FlextResult containing the FlextLdapGroup if found, None if not found,
            or error

        """
        return await self.get_entity(group_id)

    async def find_group_by_dn(self, dn: str) -> FlextResult[FlextLdapGroup | None]:
        """Find an LDAP group by distinguished name - USES BASE CLASS IMPLEMENTATION.

        Args:
            dn: Distinguished name to search for

        Returns:
            FlextResult containing the FlextLdapGroup if found, None if not found,
            or error

        """
        return await self.find_entity_by_dn(dn)

    async def add_member(
        self,
        group_id: UUID,
        member_dn: str,
    ) -> FlextResult[FlextLdapGroup]:
        """Add a member to an LDAP group.

        Args:
            group_id: The unique identifier of the group
            member_dn: Distinguished name of the member to add

        Returns:
            FlextResult containing the updated FlextLdapGroup or error

        """
        try:
            # Convert UUID to string for entity lookup
            key = str(group_id) if isinstance(group_id, UUID) else group_id
            group = self._entities.get(key)
            if not group:
                return FlextResult.fail("Group not found")

            # Entity add_member returns a new immutable entity
            updated_group = group.add_member(member_dn)
            # Store the updated entity back
            self._entities[key] = updated_group
            return FlextResult.ok(updated_group)
        except (KeyError, AttributeError, ValueError) as e:
            return FlextResult.fail(f"Failed to add member: {e}")

    async def remove_member(
        self,
        group_id: UUID,
        member_dn: str,
    ) -> FlextResult[FlextLdapGroup]:
        """Remove a member from an LDAP group.

        Args:
            group_id: The unique identifier of the group
            member_dn: Distinguished name of the member to remove

        Returns:
            FlextResult containing the updated FlextLdapGroup or error

        """
        try:
            # Convert UUID to string for entity lookup
            key = str(group_id) if isinstance(group_id, UUID) else group_id
            group = self._entities.get(key)
            if not group:
                return FlextResult.fail("Group not found")

            # Entity remove_member returns a new immutable entity
            updated_group = group.remove_member(member_dn)
            # Store the updated entity back
            self._entities[key] = updated_group
            return FlextResult.ok(updated_group)
        except (KeyError, AttributeError, ValueError) as e:
            return FlextResult.fail(f"Failed to remove member: {e}")

    async def list_groups(
        self,
        ou: str | None = None,
        limit: int = 100,
    ) -> FlextResult[list[FlextLdapGroup]]:
        """List LDAP groups with optional filtering - USES BASE CLASS IMPLEMENTATION.

        Args:
            ou: Organizational unit to filter by (optional)
            limit: Maximum number of groups to return (default: 100)

        Returns:
            FlextResult containing list of FlextLdapGroups or error

        """
        return await self.list_entities_by_ou(ou, limit)

    async def delete_group(self, group_id: UUID) -> FlextResult[bool]:
        """Delete an LDAP group - USES BASE CLASS IMPLEMENTATION.

        Args:
            group_id: The unique identifier of the group to delete

        Returns:
            FlextResult containing True if deleted successfully, or error

        """
        return await self.delete_entity(group_id)


class FlextLdapConnectionApplicationService(FlextLdapConnectionBaseService):
    """Application service for managing LDAP connections with real LDAP integration.

    Inherits from ConnectionBaseService which provides:
    - Dictionary storage pattern (eliminates _connections dict duplication)
    - LDAP client integration (eliminates client setup duplication)
    - CRUD operations (eliminates get duplication)

    Note: This is the concrete implementation of the FlextLdapConnectionService port.
    """

    def __init__(
        self,
        ldap_client: FlextLdapInfrastructureClient | None = None,
    ) -> None:
        """Initialize the LDAP connection service with base capabilities."""
        super().__init__(ldap_client)

    async def create_connection(
        self,
        server_uri: str,
        bind_dn: str | None = None,
        password: str | None = None,
        *,
        use_ssl: bool = False,
    ) -> FlextResult[FlextLdapConnection]:
        """Create and establish a real LDAP connection.

        Args:
            server_uri: LDAP server URI
            bind_dn: Distinguished name for binding (optional for anonymous)
            password: Password for binding (optional)
            use_ssl: Use SSL/TLS connection

        Returns:
            FlextResult containing the created FlextLdapConnection or error

        """
        try:
            # Create domain entity
            connection = FlextLdapConnection(
                server_url=server_uri,
                bind_dn=bind_dn,
            )

            # Establish real LDAP connection
            result = await self._ldap_client.connect(
                server_uri,
                bind_dn,
                password,
                use_ssl=use_ssl,
            )

            if not result.is_success:
                error_msg = getattr(result, "error_message", "Unknown error")
                return FlextResult.fail(
                    f"Failed to connect to LDAP: {error_msg}",
                )

            # Mark as connected and bound
            if bind_dn:
                connection.bind(bind_dn)

            self._store_entity(connection)
            return FlextResult.ok(connection)

        except (ValueError, TypeError) as e:
            return FlextResult.fail(f"Failed to create connection: {e}")
        except Exception as e:
            msg = f"Unexpected error creating connection: {e}"
            return FlextResult.fail(msg)

    async def connect(self, connection_id: UUID) -> FlextResult[FlextLdapConnection]:
        """Establish a connection to the LDAP server.

        Args:
            connection_id: The unique identifier of the connection

        Returns:
            FlextResult containing the connected FlextLdapConnection or error

        """
        try:
            # Convert UUID to string for entity lookup
            key = str(connection_id) if isinstance(connection_id, UUID) else connection_id
            connection = self._entities.get(key)
            if not connection:
                return FlextResult.fail("Connection not found")

            # Real LDAP connection already established in create_connection
            # Just mark as connected if not already
            if not connection.is_connected:
                connection.connect()

            return FlextResult.ok(connection)
        except (KeyError, AttributeError) as e:
            return FlextResult.fail(f"Failed to connect: {e}")

    async def disconnect(self, connection_id: UUID) -> FlextResult[FlextLdapConnection]:
        """Disconnect from the LDAP server.

        Args:
            connection_id: The unique identifier of the connection

        Returns:
            FlextResult containing the disconnected FlextLdapConnection or error

        """
        try:
            # Convert UUID to string for entity lookup
            key = str(connection_id) if isinstance(connection_id, UUID) else connection_id
            connection = self._entities.get(key)
            if not connection:
                return FlextResult.fail("Connection not found")

            # Get the real LDAP connection ID
            ldap_connection_id = (
                f"{connection.server_url}:{connection.bind_dn or 'anonymous'}"
            )

            # Disconnect from real LDAP server
            result = await self._ldap_client.disconnect(ldap_connection_id)
            if not result.is_success:
                error_msg = getattr(result, "error_message", "Unknown error")
                return FlextResult.fail(
                    f"Failed to disconnect from LDAP: {error_msg}",
                )

            # Mark domain entity as disconnected
            connection.disconnect()
            return FlextResult.ok(connection)
        except (KeyError, AttributeError) as e:
            return FlextResult.fail(f"Failed to disconnect: {e}")

    async def bind(self, connection_id: UUID) -> FlextResult[FlextLdapConnection]:
        """Bind to the LDAP server using the connection's bind DN.

        Args:
            connection_id: The unique identifier of the connection

        Returns:
            FlextResult containing the bound FlextLdapConnection or error

        """
        try:
            # Convert UUID to string for entity lookup
            key = str(connection_id) if isinstance(connection_id, UUID) else connection_id
            connection = self._entities.get(key)
            if not connection:
                return FlextResult.fail("Connection not found")

            if not connection.is_connected:
                return FlextResult.fail("Connection not established")

            # For LDAP3, binding is typically done during connection establishment
            # If we need to rebind or change credentials, we would reconnect
            # For now, just mark as bound if we have a bind DN
            if connection.bind_dn:
                connection.bind(connection.bind_dn)
            else:
                connection.bind("")  # Anonymous bind

            return FlextResult.ok(connection)
        except (KeyError, AttributeError) as e:
            return FlextResult.fail(f"Failed to bind: {e}")

    async def get_connection(
        self,
        connection_id: UUID,
    ) -> FlextResult[FlextLdapConnection | None]:
        """Get an LDAP connection by ID - USES BASE CLASS IMPLEMENTATION.

        Args:
            connection_id: The unique identifier of the connection

        Returns:
            FlextResult containing the FlextLdapConnection if found, None if not
            found, or error

        """
        return await self.get_entity(connection_id)

    async def list_connections(self) -> FlextResult[list[FlextLdapConnection]]:
        """List all LDAP connections - USES BASE CLASS IMPLEMENTATION.

        Returns:
            FlextResult containing list of FlextLdapConnections or error

        """
        # Use base class list_entities_by_ou without OU filtering
        return await self.list_entities_by_ou(
            None,
            1000,
        )  # High limit for all connections

    # Port interface adapter methods removed to avoid duplication

    async def unbind(self, connection: FlextLdapConnection) -> FlextResult[Any]:
        """Unbind from LDAP server - Port interface adapter.

        Args:
            connection: FlextLdapConnection entity to unbind

        Returns:
            FlextResult containing unbind result or error

        """
        # For ldap3, unbind is typically handled during disconnect
        # Mark connection as unbound in domain entity
        connection.unbind()
        return FlextResult.ok(True)

    async def test_connection(
        self,
        connection: FlextLdapConnection,
    ) -> FlextResult[Any]:
        """Test LDAP connection health - Port interface adapter.

        Args:
            connection: FlextLdapConnection entity to test

        Returns:
            FlextResult containing connection test results or error

        """
        test_result = {
            "connected": connection.is_connected,
            "bound": connection.is_bound,
            "server": connection.server_url,
            "bind_dn": connection.bind_dn,
        }
        return FlextResult.ok(test_result)

    async def get_connection_info(
        self,
        connection: FlextLdapConnection,
    ) -> FlextResult[Any]:
        """Get connection information - Port interface adapter.

        Args:
            connection: FlextLdapConnection entity to get info for

        Returns:
            FlextResult containing connection information or error

        """
        connection_info = {
            "id": connection.id,
            "server_url": connection.server_url,
            "bind_dn": connection.bind_dn,
            "is_connected": connection.is_connected,
            "is_bound": connection.is_bound,
            "created_at": connection.created_at,
            "version": connection.version,
        }
        return FlextResult.ok(connection_info)


class FlextLdapOperationService(FlextLdapOperationBaseService):
    """Service for tracking LDAP operations - ELIMINATES MASSIVE DUPLICATION.

    Inherits from OperationBaseService which provides:
    - Dictionary storage pattern (eliminates _operations dict duplication)
    - CRUD operations (eliminates get duplication)
    - List operations with connection filtering (eliminates list duplication)
    """

    def __init__(self) -> None:
        """Initialize the LDAP operation service with base capabilities."""
        super().__init__()

    async def create_operation(
        self,
        operation_type: str,
        target_dn: str,
        connection_id: UUID,
        user_dn: str | None = None,
        filter_expression: str | None = None,
        attributes: list[str] | None = None,
    ) -> FlextResult[FlextLdapOperation]:
        """Create a new LDAP operation.

        Args:
            operation_type: Type of LDAP operation (search, add, modify, delete)
            target_dn: Target distinguished name for the operation
            connection_id: Connection to use for the operation
            user_dn: User performing the operation (optional)
            filter_expression: LDAP search filter (optional)
            attributes: List of attributes to retrieve (optional)

        Returns:
            FlextResult containing the created FlextLdapOperation or error

        """
        try:
            operation = FlextLdapOperation(
                operation_type=operation_type,
                target_dn=target_dn,
                connection_id=str(connection_id),
                user_dn=user_dn,
                filter_expression=filter_expression,
                attributes=attributes or [],
            )

            operation.start_operation()
            self._store_entity(operation)
            return FlextResult.ok(operation)
        except (ValueError, TypeError) as e:
            return FlextResult.fail(f"Failed to create operation: {e}")

    async def complete_operation(
        self,
        operation_id: UUID,
        *,
        success: bool,
        result_count: int = 0,
        error_message: str | None = None,
    ) -> FlextResult[FlextLdapOperation]:
        """Mark an LDAP operation as completed.

        Args:
            operation_id: The unique identifier of the operation
            success: Whether the operation was successful
            result_count: Number of results returned (default: 0)
            error_message: Error message if operation failed (optional)

        Returns:
            FlextResult containing the completed FlextLdapOperation or error

        """
        try:
            # Convert UUID to string for entity lookup
            key = str(operation_id) if isinstance(operation_id, UUID) else operation_id
            operation = self._entities.get(key)
            if not operation:
                return FlextResult.fail("Operation not found")

            # Entity complete_operation returns a new immutable entity
            completed_operation = operation.complete_operation(
                success=success,
                result_count=result_count,
                error_message=error_message,
            )
            # Store the updated entity back
            self._entities[key] = completed_operation
            return FlextResult.ok(completed_operation)
        except (KeyError, AttributeError) as e:
            return FlextResult.fail(f"Failed to complete operation: {e}")

    async def get_operation(
        self,
        operation_id: UUID,
    ) -> FlextResult[FlextLdapOperation | None]:
        """Get an LDAP operation by ID - USES BASE CLASS IMPLEMENTATION.

        Args:
            operation_id: The unique identifier of the operation

        Returns:
            FlextResult containing the FlextLdapOperation if found, None if not
            found, or error

        """
        return await self.get_entity(operation_id)

    async def list_operations(
        self,
        connection_id: UUID | None = None,
        limit: int = 100,
    ) -> FlextResult[list[FlextLdapOperation]]:
        r"""List LDAP operations with optional filtering - BASE CLASS IMPLEMENTATION.

        Args:
            connection_id: Filter by connection ID (optional)
            limit: Maximum number of operations to return (default: 100)

        Returns:
            FlextResult containing list of FlextLdapOperations sorted by start time
            or error

        """
        return await self.list_entities_by_connection(connection_id, limit)
