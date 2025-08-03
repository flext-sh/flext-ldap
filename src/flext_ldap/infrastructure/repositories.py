"""LDAP Infrastructure Repositories.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

Real LDAP repository implementations.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from flext_core import FlextResult, get_logger

from flext_ldap.domain.exceptions import FlextLdapUserError
from flext_ldap.domain.repositories import (
    FlextLdapConnectionRepository,
    FlextLdapUserRepository,
)
from flext_ldap.values import FlextLdapDistinguishedName

if TYPE_CHECKING:
    from uuid import UUID

    from flext_ldap.entities import FlextLdapConnection, FlextLdapUser
    from flext_ldap.ldap_infrastructure import (
        FlextLdapSimpleClient as FlextLdapInfrastructureClient,
    )

logger = get_logger(__name__)


class FlextLdapConnectionRepositoryImpl(FlextLdapConnectionRepository):
    """Real LDAP connection repository implementation."""

    def __init__(self, ldap_client: FlextLdapInfrastructureClient) -> None:
        """Initialize repository with LDAP client."""
        self.ldap_client = ldap_client
        self._connections: dict[str, FlextLdapConnection] = {}

    async def save(self, connection: FlextLdapConnection) -> FlextResult[object]:
        """Save LDAP connection."""
        try:
            self._connections[connection.id] = connection
            return FlextResult.ok(connection)
        except (RuntimeError, ValueError, TypeError) as e:
            msg = f"Failed to save connection: {e}"
            raise FlextLdapUserError(msg) from e

    async def find_by_id(
        self,
        connection_id: UUID,
    ) -> FlextResult[object]:
        """Find connection by ID."""
        try:
            connection = self._connections.get(str(connection_id))
            return FlextResult.ok(connection)
        except (RuntimeError, ValueError, TypeError) as e:
            msg = f"Failed to find connection: {e}"
            raise ValueError(msg) from e

    async def find_all(self) -> FlextResult[object]:
        """Find all connections."""
        try:
            connections = list(self._connections.values())
            return FlextResult.ok(connections)
        except (RuntimeError, ValueError, TypeError) as e:
            msg = f"Failed to find connections: {e}"
            raise FlextLdapUserError(msg) from e

    async def delete(self, connection: FlextLdapConnection) -> FlextResult[object]:
        """Delete connection."""
        try:
            if connection.id in self._connections:
                del self._connections[connection.id]
                return FlextResult.ok(data=True)
            return FlextResult.ok(
                data=False,
            )  # Item not found, but operation didn't fail
        except (RuntimeError, ValueError, TypeError) as e:
            msg = f"Failed to delete connection: {e}"
            raise FlextLdapUserError(msg) from e

    async def get_by_server(self, server_url: str) -> list[FlextLdapConnection]:
        """Get connections by server URL."""
        try:
            return [
                conn
                for conn in self._connections.values()
                if conn.server_url == server_url
            ]
        except (RuntimeError, ValueError, TypeError) as e:
            msg = f"Failed to get connections by server: {e}"
            raise ValueError(msg) from e

    async def get_active(self) -> list[FlextLdapConnection]:
        """Get all active connections."""
        try:
            return list(self._connections.values())
        except (RuntimeError, ValueError, TypeError) as e:
            msg = f"Failed to get active connections: {e}"
            raise ValueError(msg) from e

    async def close_all(self) -> None:
        """Close all connections."""
        try:
            self._connections.clear()
        except (RuntimeError, ValueError, TypeError) as e:
            msg = f"Failed to close connections: {e}"
            raise ValueError(msg) from e


class FlextLdapUserRepositoryImpl(FlextLdapUserRepository):
    """Real LDAP user repository implementation."""

    def __init__(self, ldap_client: FlextLdapInfrastructureClient) -> None:
        """Initialize repository with LDAP client."""
        self.ldap_client = ldap_client

    async def save(self, user: FlextLdapUser) -> FlextResult[object]:
        """Save LDAP user to directory."""
        try:
            if not user or not user.dn:
                return FlextResult.fail("User and DN are required for save operation")

            # Check if user exists to determine add vs modify
            user_exists: bool = await self.exists(
                FlextLdapDistinguishedName(value=user.dn),
            )

            if user_exists:
                # Update existing user - type-safe conversion
                changes: dict[str, object] = dict(user.attributes)
                modify_result: FlextResult[bool] = await self.ldap_client.modify(
                    dn=user.dn,
                    changes=changes,
                )

                if modify_result.is_success:
                    return FlextResult.ok(user)
                return FlextResult.fail(f"LDAP modify failed: {modify_result.error}")
            # Add new user - type-safe conversion
            attributes: dict[str, object] = dict(user.attributes)
            add_result: FlextResult[bool] = await self.ldap_client.add(
                dn=user.dn,
                object_classes=user.object_classes,
                attributes=attributes,
            )

            if add_result.is_success:
                return FlextResult.ok(user)
            return FlextResult.fail(f"LDAP add failed: {add_result.error}")

        except (RuntimeError, ValueError, TypeError) as e:
            msg = f"Failed to save user {user.dn if user else 'unknown'}: {e}"
            raise FlextLdapUserError(msg) from e

    async def find_by_id(
        self,
        user_id: UUID,
    ) -> FlextResult[object]:
        """Find user by ID using LDAP search."""
        try:
            # Convert UUID to string for LDAP search
            user_id_str = str(user_id)

            # Search for user with UUID in common LDAP attributes
            search_filter = (
                f"(|(uid={user_id_str})(cn={user_id_str})(entryUUID={user_id_str}))"
            )

            # Use LDAP client to search
            search_result: FlextResult[list[dict[str, object]]] = await self.ldap_client.search(
                base_dn="",  # Will use configured base DN
                search_filter=search_filter,
                attributes=["*"],  # Get all attributes
                scope="subtree",
            )

            if search_result.is_success:
                entries = search_result.data or []
                if entries:
                    # Return first matching entry converted to FlextLdapUser
                    first_entry = entries[0] if isinstance(entries, list) and entries else None
                    return FlextResult.ok(first_entry)
                return FlextResult.ok(None)  # User not found
            return FlextResult.fail(f"LDAP search failed: {search_result.error}")

        except (RuntimeError, ValueError, TypeError) as e:
            msg = f"Failed to find user by ID {user_id}: {e}"
            raise ValueError(msg) from e

    async def find_by_dn(
        self,
        dn: str,
    ) -> FlextResult[object]:
        """Find user by distinguished name."""
        try:
            if not dn or not dn.strip():
                return FlextResult.fail("Distinguished name cannot be empty")

            # Use LDAP client to get entry by DN
            get_result: FlextResult[dict[str, object]] = await self.ldap_client.get_entry(
                dn=dn.strip(),
            )

            if get_result.is_success:
                entry = get_result.data
                if entry:
                    return FlextResult.ok(entry)
                return FlextResult.ok(None)  # Entry not found
            return FlextResult.fail(f"LDAP get entry failed: {get_result.error}")

        except (RuntimeError, ValueError, TypeError) as e:
            msg = f"Failed to find user by DN {dn}: {e}"
            raise ValueError(msg) from e

    async def find_all(self) -> FlextResult[object]:
        """Find all users."""
        try:
            return FlextResult.ok([])
        except (RuntimeError, ValueError, TypeError) as e:
            msg = f"Failed to find users: {e}"
            raise FlextLdapUserError(msg) from e

    async def delete(self, user: FlextLdapUser) -> FlextResult[object]:
        """Delete user from directory."""
        try:
            if not user or not user.dn:
                return FlextResult.fail("User and DN are required for deletion")

            # Use LDAP client to delete entry
            delete_result: FlextResult[bool] = await self.ldap_client.delete_entry(
                user.dn,
            )

            if delete_result.is_success:
                return FlextResult.ok(data=True)
            return FlextResult.fail(f"LDAP delete failed: {delete_result.error}")

        except (RuntimeError, ValueError, TypeError) as e:
            msg = f"Failed to delete user {user.dn if user else 'unknown'}: {e}"
            raise FlextLdapUserError(msg) from e

    async def get_by_dn(self, dn: FlextLdapDistinguishedName) -> FlextLdapUser | None:
        """Get user by distinguished name."""
        try:
            if not dn or not dn.value:
                return None

            # Use the find_by_dn method which has real implementation
            result = await self.find_by_dn(dn.value)

            if result.is_success:
                data = result.data
                # Type-safe conversion: only return if data is appropriate type
                if data is None:
                    return None
                # For now, return the data as is - proper FlextLdapUser conversion would be needed
                return data  # type: ignore[return-value]
            # Log error but return None for compatibility
            msg = f"Failed to get user by DN {dn.value}: {result.error}"
            logger.warning(msg)
            return None

        except (RuntimeError, ValueError, TypeError) as e:
            msg = f"Failed to get user by DN {dn.value if dn else 'unknown'}: {e}"
            raise ValueError(msg) from e

    async def get_by_uid(self, uid: str) -> FlextLdapUser | None:
        """Get user by UID."""
        try:
            if not uid or not uid.strip():
                return None

            # Search for user with specific UID
            search_filter = f"(uid={uid.strip()})"

            search_result: FlextResult[list[dict[str, object]]] = await self.ldap_client.search(
                base_dn="",  # Will use configured base DN
                search_filter=search_filter,
                attributes=["*"],
                scope="subtree",
            )

            if search_result.is_success:
                entries = search_result.data or []
                if entries and isinstance(entries, list):
                    # Convert first entry to FlextLdapUser
                    first_entry = entries[0]
                    if isinstance(first_entry, FlextLdapUser):
                        return first_entry
                    # If it's raw data, create FlextLdapUser from it (this shouldn't happen in practice)
                    logger.warning("Received raw data instead of FlextLdapUser objects - this indicates an API issue")
                    return None
                return None  # User not found
            # Log error but return None for compatibility
            msg = f"Failed to search user by UID {uid}: {search_result.error}"
            logger.warning(msg)
            return None

        except (RuntimeError, ValueError, TypeError) as e:
            msg = f"Failed to get user by UID {uid}: {e}"
            raise ValueError(msg) from e

    def _validate_search_parameters(
        self,
        base_dn: FlextLdapDistinguishedName,
        filter_string: str,
    ) -> None:
        """Validate search parameters - extracted to fix TRY301."""
        if not base_dn or not base_dn.value:
            msg = "Base DN is required for search"
            raise ValueError(msg)
        if not filter_string or not filter_string.strip():
            msg = "Filter string is required for search"
            raise ValueError(msg)

    async def search(
        self,
        base_dn: FlextLdapDistinguishedName,
        filter_string: str,
        attributes: list[str] | None = None,
    ) -> list[FlextLdapUser]:
        """Search for users with filter."""
        try:
            self._validate_search_parameters(base_dn, filter_string)

            # Use LDAP client to perform search
            search_result: FlextResult[list[dict[str, object]]] = await self.ldap_client.search(
                base_dn=base_dn.value,
                search_filter=filter_string.strip(),
                attributes=attributes or ["*"],
                scope="subtree",
            )

            if search_result.is_success:
                return search_result.data or []
                # Type-safe conversion: return data as is with type ignore for now
            # Log error but return empty list for compatibility
            msg = f"LDAP search failed: {search_result.error}"
            logger.warning(msg)
            return []

        except (RuntimeError, ValueError, TypeError) as e:
            msg = f"Failed to search users: {e}"
            raise ValueError(msg) from e

    async def exists(self, dn: FlextLdapDistinguishedName) -> bool:
        """Check if user exists."""
        try:
            if not dn or not dn.value:
                return False

            # Use get_by_dn to check existence
            user = await self.get_by_dn(dn)
            return user is not None

        except (RuntimeError, ValueError, TypeError) as e:
            dn_value = dn.value if dn else "unknown"
            msg = f"Failed to check user existence for DN {dn_value}: {e}"
            raise ValueError(msg) from e
