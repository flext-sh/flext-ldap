"""FLEXT-LDAP API - Clean Architecture Implementation.

High-level API facade following SOLID principles and Domain-Driven Design.
Uses dependency injection and proper service layer patterns.
"""

from __future__ import annotations

import uuid
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from flext_core import FlextEntityId, FlextEntityStatus, FlextResult, get_logger

from flext_ldap.configuration import FlextLdapSettings
from flext_ldap.container import get_ldap_container
from flext_ldap.entities import (
    FlextLdapCreateUserRequest,
    FlextLdapEntry,
    FlextLdapGroup,
    FlextLdapSearchRequest,
    FlextLdapUser,
)
from flext_ldap.exceptions import FlextLdapConnectionError
from flext_ldap.services import FlextLdapService
from flext_ldap.typings import LdapAttributeDict

logger = get_logger(__name__)


class FlextLdapApi:
    """High-level LDAP API facade using proper SOLID architecture.

    This API provides a clean, type-safe interface to LDAP operations
    without exposing internal implementation details. All operations
    go through the service layer and use dependency injection.
    """

    def __init__(self, config: FlextLdapSettings | None = None) -> None:
        """Initialize API with configuration and dependency injection."""
        self._config = config or FlextLdapSettings()
        self._container = get_ldap_container()
        self._service = FlextLdapService(self._container)

        logger.info("FlextLdapApi initialized with clean architecture")

    def _generate_session_id(self) -> str:
        """Generate unique session ID."""
        return f"session_{uuid.uuid4()}"

    # Connection Management

    async def connect(
        self,
        server_uri: str,
        bind_dn: str,
        bind_password: str,
    ) -> FlextResult[str]:
        """Connect to LDAP server and return session ID."""
        if not bind_dn or not bind_password:
            return FlextResult[str].fail("bind_dn and bind_password are required")

        # Get client from container
        client = self._container.get_client()

        # Connect using real client
        connect_result = await client.connect(server_uri, bind_dn, bind_password)
        if not connect_result.is_success:
            return FlextResult[str].fail(f"Connection failed: {connect_result.error}")

        # Generate session ID for this connection
        session_id = self._generate_session_id()
        logger.info(
            "LDAP connection established",
            extra={"session_id": session_id, "server": server_uri},
        )

        return FlextResult[str].ok(session_id)

    async def disconnect(self, session_id: str) -> FlextResult[bool]:
        """Disconnect from LDAP server."""
        client = self._container.get_client()
        disconnect_result = await client.unbind()

        if disconnect_result.is_success:
            logger.info("LDAP connection terminated", extra={"session_id": session_id})
            success = True
            return FlextResult[bool].ok(success)
        return FlextResult[bool].fail(f"Disconnect failed: {disconnect_result.error}")

    @asynccontextmanager
    async def connection(
        self,
        server_uri: str,
        bind_dn: str,
        bind_password: str,
    ) -> AsyncIterator[str]:
        """Context manager for LDAP connections."""
        connect_result = await self.connect(server_uri, bind_dn, bind_password)
        if not connect_result.is_success:
            msg = f"Connection failed: {connect_result.error}"
            raise FlextLdapConnectionError(msg)

        # Use unwrap_or() pattern for cleaner code
        session_id = connect_result.unwrap_or("")
        if not session_id:
            msg = "Failed to get session ID"
            raise FlextLdapConnectionError(msg)

        try:
            yield session_id
        finally:
            await self.disconnect(session_id)

    # Search Operations

    async def search(
        self,
        base_dn: str,
        search_filter: str = "(objectClass=*)",
        *,
        attributes: list[str] | None = None,
        scope: str = "subtree",
        size_limit: int = 1000,
        time_limit: int = 30,
    ) -> FlextResult[list[FlextLdapEntry]]:
        """Search LDAP directory using proper architecture."""
        # Create search request
        search_request = FlextLdapSearchRequest(
            base_dn=base_dn,
            scope=scope,
            filter_str=search_filter,
            attributes=attributes,
            size_limit=size_limit,
            time_limit=time_limit,
        )

        # Execute search via service
        search_result = await self._service.search(search_request)
        if not search_result.is_success:
            return FlextResult[list[FlextLdapEntry]].fail(
                search_result.error or "Search failed"
            )

        # Convert response entries to FlextLdapEntry objects
        entries = []
        for entry_data in search_result.value.entries:
            entry_dn = entry_data.get("dn")
            if not entry_dn:
                continue

            # Extract object classes
            object_classes = []
            if "objectClass" in entry_data:
                oc_value = entry_data["objectClass"]
                if isinstance(oc_value, list):
                    object_classes = [str(oc) for oc in oc_value]
                else:
                    object_classes = [str(oc_value)]

            # Create entry
            entry = FlextLdapEntry(
                id=FlextEntityId(
                    f"api_entry_{str(entry_dn).replace(',', '_').replace('=', '_')}"
                ),
                dn=str(entry_dn),
                object_classes=object_classes,
                attributes=dict(entry_data),
                status=FlextEntityStatus.ACTIVE,
            )
            entries.append(entry)

        return FlextResult[list[FlextLdapEntry]].ok(entries)

    # User Operations

    async def create_user(
        self,
        user_request: FlextLdapCreateUserRequest,
    ) -> FlextResult[FlextLdapUser]:
        """Create user using proper service layer."""
        return await self._service.create_user(user_request)

    async def get_user(self, dn: str) -> FlextResult[FlextLdapUser | None]:
        """Get user by DN."""
        return await self._service.get_user(dn)

    async def update_user(
        self, dn: str, attributes: LdapAttributeDict
    ) -> FlextResult[None]:
        """Update user attributes."""
        return await self._service.update_user(dn, attributes)

    async def delete_user(self, dn: str) -> FlextResult[None]:
        """Delete user."""
        return await self._service.delete_user(dn)

    async def search_users(
        self,
        filter_str: str,
        base_dn: str,
        scope: str = "subtree",
    ) -> FlextResult[list[FlextLdapUser]]:
        """Search users with filter."""
        return await self._service.search_users(filter_str, base_dn, scope)

    # Group Operations

    async def create_group(
        self,
        dn: str,
        cn: str,
        description: str | None = None,
        members: list[str] | None = None,
    ) -> FlextResult[FlextLdapGroup]:
        """Create group using proper service layer."""
        # Create group entity with required status
        group = FlextLdapGroup(
            id=FlextEntityId(f"api_group_{dn.replace(',', '_').replace('=', '_')}"),
            dn=dn,
            cn=cn,
            description=description,
            members=members or [],
            status=FlextEntityStatus.ACTIVE,
        )

        # Create via service
        create_result = await self._service.create_group(group)
        if create_result.is_success:
            return FlextResult[FlextLdapGroup].ok(group)
        return FlextResult[FlextLdapGroup].fail(
            create_result.error or "Group creation failed"
        )

    async def get_group(self, dn: str) -> FlextResult[FlextLdapGroup | None]:
        """Get group by DN."""
        return await self._service.get_group(dn)

    async def update_group(
        self, dn: str, attributes: LdapAttributeDict
    ) -> FlextResult[None]:
        """Update group attributes."""
        return await self._service.update_group(dn, attributes)

    async def delete_group(self, dn: str) -> FlextResult[None]:
        """Delete group."""
        return await self._service.delete_group(dn)

    async def add_member(self, group_dn: str, member_dn: str) -> FlextResult[None]:
        """Add member to group."""
        return await self._service.add_member(group_dn, member_dn)

    async def remove_member(self, group_dn: str, member_dn: str) -> FlextResult[None]:
        """Remove member from group."""
        return await self._service.remove_member(group_dn, member_dn)

    async def get_members(self, group_dn: str) -> FlextResult[list[str]]:
        """Get group members."""
        return await self._service.get_members(group_dn)

    # Entry Operations

    async def delete_entry(self, dn: str) -> FlextResult[None]:
        """Delete LDAP entry by DN."""
        repository = self._container.get_repository()
        return await repository.delete(dn)

    # Validation Methods

    def validate_dn(self, dn: str) -> FlextResult[None]:
        """Validate distinguished name format."""
        return self._service.validate_dn(dn)

    def validate_filter(self, filter_str: str) -> FlextResult[None]:
        """Validate LDAP search filter."""
        return self._service.validate_filter(filter_str)


# Factory Functions


def get_ldap_api(config: FlextLdapSettings | None = None) -> FlextLdapApi:
    """Factory function to create FlextLdapApi instance."""
    return FlextLdapApi(config)


def create_ldap_api(config: FlextLdapSettings | None = None) -> FlextLdapApi:
    """Alternative factory function for FlextLdapApi."""
    return FlextLdapApi(config)


# Export main API
__all__ = [
    "FlextLdapApi",
    "create_ldap_api",
    "get_ldap_api",
]
