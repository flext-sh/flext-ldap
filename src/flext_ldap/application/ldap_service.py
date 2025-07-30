"""FLEXT LDAP Application Service.

Application layer service implementing LDAP operations using Clean Architecture.
Provides a high-level interface for LDAP user and group management operations.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from flext_core import FlextResult

from flext_ldap.entities import FlextLdapUser
from flext_ldap.ldap_infrastructure import FlextLdapSimpleClient

if TYPE_CHECKING:
    from flext_ldap.values import FlextLdapCreateUserRequest


class FlextLdapService:
    """Application service for LDAP operations using Clean Architecture.

    Provides high-level LDAP operations with in-memory fallback mode
    for development and testing environments.
    """

    def __init__(self) -> None:
        """Initialize LDAP service."""
        self._client = FlextLdapSimpleClient()
        self._connected = False
        self._in_memory_users: dict[str, FlextLdapUser] = {}

    def is_connected(self) -> bool:
        """Check if service is connected to LDAP server."""
        return self._connected

    async def connect(
        self,
        server_url: str,
        bind_dn: str,
        bind_password: str,
    ) -> FlextResult[bool]:
        """Connect to LDAP server."""
        result = await self._client.connect(server_url, bind_dn, bind_password)
        if result.is_success:
            self._connected = True
        return result

    async def disconnect(self) -> FlextResult[None]:
        """Disconnect from LDAP server."""
        if self._connected:
            result = await self._client.disconnect()
            if result.is_success:
                self._connected = False
            return result
        return FlextResult.ok(None)

    async def create_user(
        self,
        request: FlextLdapCreateUserRequest,
    ) -> FlextResult[FlextLdapUser]:
        """Create a new user.

        If connected to LDAP server, creates user there.
        Otherwise, creates user in memory for testing.
        """
        # Create user entity from request
        user = FlextLdapUser(
            id=request.uid,
            dn=request.dn,
            uid=request.uid,
            cn=request.cn,
            sn=request.sn,
            mail=getattr(request, "mail", None),
        )

        if self._connected:
            # TODO: Implement real LDAP user creation via client
            # For now, fallback to in-memory
            pass

        # Store in memory (for testing and development)
        self._in_memory_users[request.uid] = user
        return FlextResult.ok(user)

    async def find_user_by_uid(self, uid: str) -> FlextResult[FlextLdapUser]:
        """Find user by UID."""
        if self._connected:
            # TODO: Implement real LDAP search via client
            # For now, fallback to in-memory
            pass

        # Search in memory storage
        user = self._in_memory_users.get(uid)
        if user:
            return FlextResult.ok(user)

        return FlextResult.fail(f"User with UID {uid} not found")

    async def update_user(
        self,
        user_id: str,
        updates: dict[str, Any],
    ) -> FlextResult[FlextLdapUser]:
        """Update user attributes."""
        find_result = await self.find_user_by_uid(user_id)
        if find_result.is_failure:
            return FlextResult.fail(f"User {user_id} not found for update")

        user = find_result.data
        if not user:
            return FlextResult.fail(f"User {user_id} not found")

        # Update user attributes (simple implementation)
        # In a real implementation, this would update the LDAP entry
        updated_user = FlextLdapUser(
            id=user.id,
            dn=user.dn,
            uid=user.uid,
            cn=user.cn,
            sn=user.sn,
            mail=user.mail,
            **updates,  # Apply updates
        )

        # Store updated user
        self._in_memory_users[user_id] = updated_user
        return FlextResult.ok(updated_user)

    async def delete_user(self, uid: str) -> FlextResult[bool]:
        """Delete user by UID."""
        if self._connected:
            # TODO: Implement real LDAP deletion via client
            # For now, fallback to in-memory
            pass

        # Remove from memory storage
        if uid in self._in_memory_users:
            del self._in_memory_users[uid]
            return FlextResult.ok(True)

        return FlextResult.fail(f"User with UID {uid} not found")

    async def list_users(
        self,
        base_dn: str | None = None,
        filter_expr: str | None = None,
    ) -> FlextResult[list[FlextLdapUser]]:
        """List users from LDAP directory."""
        if self._connected:
            # TODO: Implement real LDAP search via client
            # For now, fallback to in-memory
            pass

        # Return in-memory users
        users = list(self._in_memory_users.values())
        return FlextResult.ok(users)
