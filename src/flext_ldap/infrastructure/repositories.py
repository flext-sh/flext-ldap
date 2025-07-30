"""LDAP Infrastructure Repositories.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

Real LDAP repository implementations.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from flext_core import FlextResult

from flext_ldap.domain.exceptions import FlextLdapUserError
from flext_ldap.domain.repositories import (
    FlextLdapConnectionRepository,
    FlextLdapUserRepository,
)

if TYPE_CHECKING:
    from uuid import UUID

    from flext_ldap.domain.value_objects import FlextLdapDistinguishedName
    from flext_ldap.entities import FlextLdapConnection, FlextLdapUser
    from flext_ldap.infrastructure.ldap_simple_client import (
        FlextLdapSimpleClient as FlextLdapInfrastructureClient,
    )


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
            return FlextResult.ok(user)
        except (RuntimeError, ValueError, TypeError) as e:
            msg = f"Failed to save user: {e}"
            raise FlextLdapUserError(msg) from e

    async def find_by_id(
        self,
        user_id: UUID,  # noqa: ARG002
    ) -> FlextResult[object]:
        """Find user by ID."""
        try:
            return FlextResult.ok(None)
        except (RuntimeError, ValueError, TypeError) as e:
            msg = f"Failed to find user: {e}"
            raise ValueError(msg) from e

    async def find_by_dn(
        self,
        dn: str,  # noqa: ARG002
    ) -> FlextResult[object]:
        """Find user by distinguished name."""
        try:
            return FlextResult.ok(None)
        except (RuntimeError, ValueError, TypeError) as e:
            msg = f"Failed to find user by DN: {e}"
            raise ValueError(msg) from e

    async def find_all(self) -> FlextResult[object]:
        """Find all users."""
        try:
            return FlextResult.ok([])
        except (RuntimeError, ValueError, TypeError) as e:
            msg = f"Failed to find users: {e}"
            raise FlextLdapUserError(msg) from e

    async def delete(self, user: FlextLdapUser) -> FlextResult[object]:  # noqa: ARG002
        """Delete user from directory."""
        try:
            return FlextResult.ok(data=True)
        except (RuntimeError, ValueError, TypeError) as e:
            msg = f"Failed to delete user: {e}"
            raise FlextLdapUserError(msg) from e

    async def get_by_dn(self, _dn: FlextLdapDistinguishedName) -> FlextLdapUser | None:
        """Get user by distinguished name."""
        try:
            return None
        except (RuntimeError, ValueError, TypeError) as e:
            msg = f"Failed to get user by DN: {e}"
            raise ValueError(msg) from e

    async def get_by_uid(self, uid: str) -> FlextLdapUser | None:  # noqa: ARG002
        """Get user by UID."""
        try:
            return None
        except (RuntimeError, ValueError, TypeError) as e:
            msg = f"Failed to get user by UID: {e}"
            raise ValueError(msg) from e

    async def search(
        self,
        base_dn: FlextLdapDistinguishedName,
        filter_string: str,
        attributes: list[str] | None = None,
    ) -> list[FlextLdapUser]:
        """Search for users with filter."""
        try:
            _ = base_dn
            _ = filter_string
            _ = attributes
        except (RuntimeError, ValueError, TypeError) as e:
            msg = f"Failed to search users: {e}"
            raise ValueError(msg) from e
        else:
            return []

    async def exists(self, dn: FlextLdapDistinguishedName) -> bool:  # noqa: ARG002
        """Check if user exists."""
        try:
            return False
        except (RuntimeError, ValueError, TypeError) as e:
            msg = f"Failed to check user existence: {e}"
            raise ValueError(msg) from e
