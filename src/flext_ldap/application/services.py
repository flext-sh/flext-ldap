"""Application services for FLEXT-LDAP v0.7.0.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

REFACTORED:
    Using flext-core service patterns - NO duplication.
    Clean architecture with dependency injection and ServiceResult pattern.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

from flext_core.config import injectable
from flext_core.domain.types import ServiceResult
from flext_ldap.domain.entities import (
    LDAPConnection,
    LDAPGroup,
    LDAPOperation,
    LDAPUser,
)
from flext_ldap.domain.exceptions import LDAPConnectionError, LDAPUserError
from flext_ldap.infrastructure.ldap_client import LDAPInfrastructureClient

if TYPE_CHECKING:
    from uuid import UUID

    from flext_ldap.domain.value_objects import CreateUserRequest


@injectable()  # type: ignore[arg-type]
class LDAPUserService:
    """Service for managing LDAP users."""

    def __init__(self, ldap_client: LDAPInfrastructureClient | None = None) -> None:
        """Initialize the LDAP user service."""
        self._ldap_client = ldap_client or LDAPInfrastructureClient()
        self._connection_id: str | None = None
        # Fallback in-memory storage for non-connected operations
        self._users: dict[UUID, LDAPUser] = {}

    async def create_user(
        self,
        request: CreateUserRequest,
    ) -> ServiceResult[LDAPUser]:
        """Create a new LDAP user.

        Args:
            request: User creation request with validation

        Returns:
            ServiceResult containing the created LDAPUser or error

        """
        try:
            user = LDAPUser(
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

            self._users[user.id] = user
            return ServiceResult.ok(user)
        except (ValueError, TypeError) as e:
            return ServiceResult.fail(f"Failed to create user: {e}")
        except Exception as e:
            msg = f"Unexpected error creating user: {e}"
            raise LDAPUserError(msg) from e

    async def get_user(self, user_id: UUID) -> ServiceResult[LDAPUser | None]:
        """Get an LDAP user by ID.

        Args:
            user_id: The unique identifier of the user

        Returns:
            ServiceResult containing the LDAPUser if found, None if not found, or error

        """
        try:
            user = self._users.get(user_id)
            return ServiceResult.ok(user)
        except (KeyError, AttributeError) as e:
            return ServiceResult.fail(f"Failed to get user: {e}")

    async def find_user_by_dn(self, dn: str) -> ServiceResult[LDAPUser | None]:
        """Find an LDAP user by distinguished name.

        Args:
            dn: Distinguished name to search for

        Returns:
            ServiceResult containing the LDAPUser if found, None if not found, or error

        """
        try:
            for user in self._users.values():
                if user.dn == dn:
                    return ServiceResult.ok(user)
            return ServiceResult.ok(None)
        except (KeyError, AttributeError) as e:
            return ServiceResult.fail(f"Failed to find user by DN: {e}")

    async def find_user_by_uid(self, uid: str) -> ServiceResult[LDAPUser | None]:
        """Find an LDAP user by user identifier.

        Args:
            uid: User identifier to search for

        Returns:
            ServiceResult containing the LDAPUser if found, None if not found, or error

        """
        try:
            for user in self._users.values():
                if user.uid == uid:
                    return ServiceResult.ok(user)
            return ServiceResult.ok(None)
        except (KeyError, AttributeError) as e:
            return ServiceResult.fail(f"Failed to find user by UID: {e}")

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
        try:
            user = self._users.get(user_id)
            if not user:
                return ServiceResult.fail("User not found")

            for key, value in updates.items():
                if hasattr(user, key):
                    setattr(user, key, value)

            # Update timestamp using pydantic model approach
            user.updated_at = datetime.now(UTC)
            return ServiceResult.ok(user)
        except (KeyError, AttributeError, ValueError) as e:
            return ServiceResult.fail(f"Failed to update user: {e}")

    async def lock_user(self, user_id: UUID) -> ServiceResult[LDAPUser]:
        """Lock an LDAP user account.

        Args:
            user_id: The unique identifier of the user to lock

        Returns:
            ServiceResult containing the locked LDAPUser or error

        """
        try:
            user = self._users.get(user_id)
            if not user:
                return ServiceResult.fail("User not found")

            user.lock_account()
            return ServiceResult.ok(user)
        except (KeyError, AttributeError) as e:
            return ServiceResult.fail(f"Failed to lock user: {e}")

    async def unlock_user(self, user_id: UUID) -> ServiceResult[LDAPUser]:
        """Unlock an LDAP user account.

        Args:
            user_id: The unique identifier of the user to unlock

        Returns:
            ServiceResult containing the unlocked LDAPUser or error

        """
        try:
            user = self._users.get(user_id)
            if not user:
                return ServiceResult.fail("User not found")

            user.unlock_account()
            return ServiceResult.ok(user)
        except (KeyError, AttributeError) as e:
            return ServiceResult.fail(f"Failed to unlock user: {e}")

    async def delete_user(self, user_id: UUID) -> ServiceResult[bool]:
        """Delete an LDAP user.

        Args:
            user_id: The unique identifier of the user to delete

        Returns:
            ServiceResult containing True if deleted successfully, or error

        """
        try:
            if user_id in self._users:
                del self._users[user_id]
                return ServiceResult.ok(True)
            return ServiceResult.fail("User not found")
        except (KeyError, ValueError) as e:
            return ServiceResult.fail(f"Failed to delete user: {e}")

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
        try:
            users = list(self._users.values())

            if ou:
                users = [u for u in users if u.ou == ou]

            return ServiceResult.ok(users[:limit])
        except (KeyError, ValueError) as e:
            return ServiceResult.fail(f"Failed to list users: {e}")

    async def set_connection(self, connection_id: str) -> ServiceResult[bool]:
        """Set the LDAP connection ID for directory operations.

        Args:
            connection_id: The LDAP connection identifier

        Returns:
            ServiceResult indicating success or failure

        """
        try:
            self._connection_id = connection_id
            return ServiceResult.ok(True)
        except (ValueError, TypeError) as e:
            return ServiceResult.fail(f"Failed to set connection: {e}")

    async def clear_connection(self) -> ServiceResult[bool]:
        """Clear the LDAP connection (revert to memory-only mode).

        Returns:
            ServiceResult indicating success or failure

        """
        try:
            self._connection_id = None
            return ServiceResult.ok(True)
        except (ValueError, TypeError) as e:
            return ServiceResult.fail(f"Failed to clear connection: {e}")


@injectable()  # type: ignore[arg-type]
class LDAPGroupService:
    """Service for managing LDAP groups."""

    def __init__(self) -> None:
        """Initialize the LDAP group service."""
        self._groups: dict[UUID, LDAPGroup] = {}

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
        try:
            group = LDAPGroup(
                dn=dn,
                cn=cn,
                ou=ou,
                members=members or [],
                owners=owners or [],
                object_classes=object_classes or ["groupOfNames"],
            )

            self._groups[group.id] = group
            return ServiceResult.ok(group)
        except (ValueError, TypeError) as e:
            return ServiceResult.fail(f"Failed to create group: {e}")

    async def get_group(self, group_id: UUID) -> ServiceResult[LDAPGroup | None]:
        """Get an LDAP group by ID.

        Args:
            group_id: The unique identifier of the group

        Returns:
            ServiceResult containing the LDAPGroup if found, None if not found, or error

        """
        try:
            group = self._groups.get(group_id)
            return ServiceResult.ok(group)
        except (KeyError, AttributeError) as e:
            return ServiceResult.fail(f"Failed to get group: {e}")

    async def find_group_by_dn(self, dn: str) -> ServiceResult[LDAPGroup | None]:
        """Find an LDAP group by distinguished name.

        Args:
            dn: Distinguished name to search for

        Returns:
            ServiceResult containing the LDAPGroup if found, None if not found, or error

        """
        try:
            for group in self._groups.values():
                if group.dn == dn:
                    return ServiceResult.ok(group)
            return ServiceResult.ok(None)
        except (KeyError, AttributeError) as e:
            return ServiceResult.fail(f"Failed to find group by DN: {e}")

    async def add_member(
        self,
        group_id: UUID,
        member_dn: str,
    ) -> ServiceResult[LDAPGroup]:
        """Add a member to an LDAP group.

        Args:
            group_id: The unique identifier of the group
            member_dn: Distinguished name of the member to add

        Returns:
            ServiceResult containing the updated LDAPGroup or error

        """
        try:
            group = self._groups.get(group_id)
            if not group:
                return ServiceResult.fail("Group not found")

            group.add_member(member_dn)
            return ServiceResult.ok(group)
        except (KeyError, AttributeError, ValueError) as e:
            return ServiceResult.fail(f"Failed to add member: {e}")

    async def remove_member(
        self,
        group_id: UUID,
        member_dn: str,
    ) -> ServiceResult[LDAPGroup]:
        """Remove a member from an LDAP group.

        Args:
            group_id: The unique identifier of the group
            member_dn: Distinguished name of the member to remove

        Returns:
            ServiceResult containing the updated LDAPGroup or error

        """
        try:
            group = self._groups.get(group_id)
            if not group:
                return ServiceResult.fail("Group not found")

            group.remove_member(member_dn)
            return ServiceResult.ok(group)
        except (KeyError, AttributeError, ValueError) as e:
            return ServiceResult.fail(f"Failed to remove member: {e}")

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
        try:
            groups = list(self._groups.values())

            if ou:
                groups = [g for g in groups if g.ou == ou]

            return ServiceResult.ok(groups[:limit])
        except (KeyError, ValueError) as e:
            return ServiceResult.fail(f"Failed to list groups: {e}")

    async def delete_group(self, group_id: UUID) -> ServiceResult[bool]:
        """Delete an LDAP group.

        Args:
            group_id: The unique identifier of the group to delete

        Returns:
            ServiceResult containing True if deleted successfully, or error

        """
        try:
            if group_id in self._groups:
                del self._groups[group_id]
                return ServiceResult.ok(True)
            return ServiceResult.fail("Group not found")
        except (KeyError, ValueError) as e:
            return ServiceResult.fail(f"Failed to delete group: {e}")


@injectable()  # type: ignore[arg-type]
class LDAPConnectionService:
    """Service for managing LDAP connections with real LDAP integration."""

    def __init__(self, ldap_client: LDAPInfrastructureClient | None = None) -> None:
        """Initialize the LDAP connection service."""
        self._connections: dict[UUID, LDAPConnection] = {}
        self._ldap_client = ldap_client or LDAPInfrastructureClient()

    async def create_connection(
        self,
        server_uri: str,
        bind_dn: str | None = None,
        password: str | None = None,
        *,
        use_ssl: bool = False,
    ) -> ServiceResult[LDAPConnection]:
        """Create and establish a real LDAP connection.

        Args:
            server_uri: LDAP server URI
            bind_dn: Distinguished name for binding (optional for anonymous)
            password: Password for binding (optional)
            use_ssl: Use SSL/TLS connection

        Returns:
            ServiceResult containing the created LDAPConnection or error

        """
        try:
            # Create domain entity
            connection = LDAPConnection(
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
                return ServiceResult.fail(
                    f"Failed to connect to LDAP: {result.error_message}",
                )

            # Mark as connected and bound
            if bind_dn:
                connection.bind(bind_dn)

            self._connections[connection.id] = connection
            return ServiceResult.ok(connection)

        except (ValueError, TypeError) as e:
            return ServiceResult.fail(f"Failed to create connection: {e}")
        except Exception as e:
            msg = f"Unexpected error creating connection: {e}"
            raise LDAPConnectionError(msg) from e

    async def connect(self, connection_id: UUID) -> ServiceResult[LDAPConnection]:
        """Establish a connection to the LDAP server.

        Args:
            connection_id: The unique identifier of the connection

        Returns:
            ServiceResult containing the connected LDAPConnection or error

        """
        try:
            connection = self._connections.get(connection_id)
            if not connection:
                return ServiceResult.fail("Connection not found")

            # Real LDAP connection already established in create_connection
            # Just mark as connected if not already
            if not connection.is_connected:
                connection.connect()

            return ServiceResult.ok(connection)
        except (KeyError, AttributeError) as e:
            return ServiceResult.fail(f"Failed to connect: {e}")

    async def disconnect(self, connection_id: UUID) -> ServiceResult[LDAPConnection]:
        """Disconnect from the LDAP server.

        Args:
            connection_id: The unique identifier of the connection

        Returns:
            ServiceResult containing the disconnected LDAPConnection or error

        """
        try:
            connection = self._connections.get(connection_id)
            if not connection:
                return ServiceResult.fail("Connection not found")

            # Get the real LDAP connection ID
            ldap_connection_id = (
                f"{connection.server_url}:{connection.bind_dn or 'anonymous'}"
            )

            # Disconnect from real LDAP server
            result = await self._ldap_client.disconnect(ldap_connection_id)
            if not result.is_success:
                return ServiceResult.fail(
                    f"Failed to disconnect from LDAP: {result.error_message}",
                )

            # Mark domain entity as disconnected
            connection.disconnect()
            return ServiceResult.ok(connection)
        except (KeyError, AttributeError) as e:
            return ServiceResult.fail(f"Failed to disconnect: {e}")

    async def bind(self, connection_id: UUID) -> ServiceResult[LDAPConnection]:
        """Bind to the LDAP server using the connection's bind DN.

        Args:
            connection_id: The unique identifier of the connection

        Returns:
            ServiceResult containing the bound LDAPConnection or error

        """
        try:
            connection = self._connections.get(connection_id)
            if not connection:
                return ServiceResult.fail("Connection not found")

            if not connection.is_connected:
                return ServiceResult.fail("Connection not established")

            # For LDAP3, binding is typically done during connection establishment
            # If we need to rebind or change credentials, we would reconnect
            # For now, just mark as bound if we have a bind DN
            if connection.bind_dn:
                connection.bind(connection.bind_dn)
            else:
                connection.bind("")  # Anonymous bind

            return ServiceResult.ok(connection)
        except (KeyError, AttributeError) as e:
            return ServiceResult.fail(f"Failed to bind: {e}")

    async def get_connection(
        self,
        connection_id: UUID,
    ) -> ServiceResult[LDAPConnection | None]:
        """Get an LDAP connection by ID.

        Args:
            connection_id: The unique identifier of the connection

        Returns:
            ServiceResult containing the LDAPConnection if found, None if not found, or error

        """
        try:
            connection = self._connections.get(connection_id)
            return ServiceResult.ok(connection)
        except (KeyError, AttributeError) as e:
            return ServiceResult.fail(f"Failed to get connection: {e}")

    async def list_connections(self) -> ServiceResult[list[LDAPConnection]]:
        """List all LDAP connections.

        Returns:
            ServiceResult containing list of LDAPConnections or error

        """
        try:
            connections = list(self._connections.values())
            return ServiceResult.ok(connections)
        except (KeyError, ValueError) as e:
            return ServiceResult.fail(f"Failed to list connections: {e}")


@injectable()  # type: ignore[arg-type]
class LDAPOperationService:
    """Service for tracking LDAP operations."""

    def __init__(self) -> None:
        """Initialize the LDAP operation service."""
        self._operations: dict[UUID, LDAPOperation] = {}

    async def create_operation(
        self,
        operation_type: str,
        target_dn: str,
        connection_id: UUID,
        user_dn: str | None = None,
        filter_expression: str | None = None,
        attributes: list[str] | None = None,
    ) -> ServiceResult[LDAPOperation]:
        """Create a new LDAP operation.

        Args:
            operation_type: Type of LDAP operation (search, add, modify, delete)
            target_dn: Target distinguished name for the operation
            connection_id: Connection to use for the operation
            user_dn: User performing the operation (optional)
            filter_expression: LDAP search filter (optional)
            attributes: List of attributes to retrieve (optional)

        Returns:
            ServiceResult containing the created LDAPOperation or error

        """
        try:
            operation = LDAPOperation(
                operation_type=operation_type,
                target_dn=target_dn,
                connection_id=str(connection_id),
                user_dn=user_dn,
                filter_expression=filter_expression,
                attributes=attributes or [],
            )

            operation.start_operation()
            self._operations[operation.id] = operation
            return ServiceResult.ok(operation)
        except (ValueError, TypeError) as e:
            return ServiceResult.fail(f"Failed to create operation: {e}")

    async def complete_operation(
        self,
        operation_id: UUID,
        *,
        success: bool,
        result_count: int = 0,
        error_message: str | None = None,
    ) -> ServiceResult[LDAPOperation]:
        """Mark an LDAP operation as completed.

        Args:
            operation_id: The unique identifier of the operation
            success: Whether the operation was successful
            result_count: Number of results returned (default: 0)
            error_message: Error message if operation failed (optional)

        Returns:
            ServiceResult containing the completed LDAPOperation or error

        """
        try:
            operation = self._operations.get(operation_id)
            if not operation:
                return ServiceResult.fail("Operation not found")

            operation.complete_operation(
                success=success, result_count=result_count, error_message=error_message,
            )
            return ServiceResult.ok(operation)
        except (KeyError, AttributeError) as e:
            return ServiceResult.fail(f"Failed to complete operation: {e}")

    async def get_operation(
        self,
        operation_id: UUID,
    ) -> ServiceResult[LDAPOperation | None]:
        """Get an LDAP operation by ID.

        Args:
            operation_id: The unique identifier of the operation

        Returns:
            ServiceResult containing the LDAPOperation if found, None if not found, or error

        """
        try:
            operation = self._operations.get(operation_id)
            return ServiceResult.ok(operation)
        except (KeyError, AttributeError) as e:
            return ServiceResult.fail(f"Failed to get operation: {e}")

    async def list_operations(
        self,
        connection_id: UUID | None = None,
        limit: int = 100,
    ) -> ServiceResult[list[LDAPOperation]]:
        """List LDAP operations with optional filtering.

        Args:
            connection_id: Filter by connection ID (optional)
            limit: Maximum number of operations to return (default: 100)

        Returns:
            ServiceResult containing list of LDAPOperations sorted by start time (descending) or error

        """
        try:
            operations = list(self._operations.values())

            if connection_id:
                operations = [
                    op for op in operations if op.connection_id == str(connection_id)
                ]

            # Sort by started_at descending (handle None values)
            operations.sort(
                key=lambda op: op.started_at or "",
                reverse=True,
            )

            return ServiceResult.ok(operations[:limit])
        except (KeyError, ValueError, AttributeError) as e:
            return ServiceResult.fail(f"Failed to list operations: {e}")
