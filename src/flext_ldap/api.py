"""LDAP API module.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import uuid
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from functools import cached_property
from typing import cast, overload

from flext_core import (
    FlextExceptions,
    FlextMixins,
    FlextResult,
    FlextTypes,
)

from flext_ldap.config import FlextLDAPConfig, get_flext_ldap_config
from flext_ldap.container import FlextLDAPContainer
from flext_ldap.domain import FlextLDAPDomain
from flext_ldap.entities import FlextLDAPEntities
from flext_ldap.repositories import FlextLDAPRepositories
from flext_ldap.services import FlextLDAPServices
from flext_ldap.typings import LdapAttributeDict

# Python 3.13 type aliases
type ApiRequest = FlextTypes.Core.Dict
type ApiResponse = FlextResult[object]

# FlextLogger available via FlextMixins.Loggable inheritance


class FlextLDAPApi(FlextMixins.Loggable):
    """High-level LDAP API facade using FlextMixins.Loggable for logging and utilities."""

    def __init__(self, config: FlextLDAPConfig | None = None) -> None:
        """Initialize API using FlextMixins.Loggable patterns with FlextLDAPConfig singleton."""
        # Initialize FlextMixins.Loggable
        super().__init__()
        # Use provided config directly if given, otherwise use singleton
        if config is not None:
            self._config = config
        else:
            self._config = get_flext_ldap_config()
        self._container_manager = FlextLDAPContainer()
        self._container = self._container_manager.get_container()
        self._service = FlextLDAPServices(self._container)

        self.log_info(
            "FlextLDAPApi initialized with FlextLDAPConfig singleton",
            api="FlextLDAPApi",
        )

    @cached_property
    def session_id(self) -> str:
        """Generate session ID using Python stdlib SOURCE OF TRUTH."""
        return f"session_{uuid.uuid4()}"

    def _get_entry_attribute(
        self,
        entry: FlextTypes.Core.Dict | FlextLDAPEntities.Entry,
        key: str,
        default: str = "",
    ) -> str:
        """Extract string attribute from entry using Python 3.13 pattern matching."""
        # Get raw value from entry based on union type
        raw_value: object
        if isinstance(entry, FlextLDAPEntities.Entry):
            raw_value = entry.get_attribute(key)
        else:  # Must be dict due to union type constraint
            raw_value = entry.get(key)

        # Return default if no value found
        if raw_value is None:
            return default

        # Convert value to string with type safety
        if isinstance(raw_value, str):
            return raw_value
        if isinstance(raw_value, bytes):
            return raw_value.decode("utf-8", errors="replace")
        if isinstance(raw_value, list):
            if len(raw_value) > 0:
                # Check if first element is None
                first_element = raw_value[0]
                if first_element is None:
                    return default
                try:
                    return str(first_element)
                except (ValueError, TypeError):
                    return default
            else:
                # Empty list should return default value
                return default
        elif isinstance(raw_value, (int, float, bool)):
            return str(raw_value)
        elif isinstance(raw_value, dict):
            try:
                return str(raw_value)
            except (ValueError, TypeError):
                return default
        else:
            # For any other type, try string conversion
            try:
                return str(raw_value)
            except (ValueError, TypeError):
                return default

    # Connection Management

    async def connect(
        self,
        server_uri: str,
        bind_dn: str,
        bind_password: str,
    ) -> FlextResult[str]:
        """Connect to LDAP server.

        Args:
            server_uri: LDAP server URI
            bind_dn: Distinguished name for binding
            bind_password: Password for binding

        Returns:
            FlextResult containing session ID or error

        """
        # Use cached session_id property from FlextUtilities
        new_session_id = self.session_id
        result = await self._service.connect(server_uri, bind_dn, bind_password)
        if not result.is_success:
            return FlextResult[str].fail(result.error or "Connection failed")
        return FlextResult[str].ok(new_session_id)

    async def disconnect(self, session_id: str | None = None) -> FlextResult[None]:
        """Disconnect from LDAP server.

        Args:
            session_id: Session ID to disconnect (optional, currently unused)

        Returns:
            FlextResult indicating success or error

        """
        # Note: session_id parameter maintained for API compatibility
        # Currently not used by the service layer implementation
        _ = session_id  # Acknowledge parameter to silence linter
        return await self._service.disconnect()

    @asynccontextmanager
    async def connection(
        self,
        server_uri: str,
        bind_dn: str,
        bind_password: str,
    ) -> AsyncIterator[str]:
        """Context manager for LDAP connection.

        Args:
            server_uri: LDAP server URI
            bind_dn: Distinguished name for binding
            bind_password: Password for binding

        Yields:
            Session ID for use within context

        """
        connect_result = await self.connect(server_uri, bind_dn, bind_password)
        if not connect_result.is_success:
            error_msg = connect_result.error or "Connection failed"
            raise FlextExceptions.ConnectionError(error_msg)

        session_id = connect_result.value
        try:
            yield session_id
        finally:
            await self.disconnect(session_id)

    # Search Operations

    async def search(
        self,
        search_request: FlextLDAPEntities.SearchRequest,
    ) -> FlextResult[list[FlextLDAPEntities.Entry]]:
        """Execute LDAP search using validated request entity.

        Args:
            search_request: Encapsulated search parameters with validation

        Returns:
            FlextResult containing search results or error

        """
        # Execute search via service - eliminates parameter mapping duplication
        search_result = await self._service.search(search_request)
        if not search_result.is_success:
            return FlextResult[list[FlextLDAPEntities.Entry]].fail(
                search_result.error or "Search failed",
            )

        # Convert response entries to FlextLDAPEntities.Entry objects
        entries: list[FlextLDAPEntities.Entry] = []
        for entry_data in search_result.value.entries:
            typed_entry = entry_data
            entry_dn = typed_entry.get("dn")
            if not entry_dn:
                continue

            # Extract object classes
            object_classes = []
            if "objectClass" in typed_entry:
                oc_value = typed_entry["objectClass"]
                if isinstance(oc_value, list):
                    typed_oc_list: list[str] = cast(
                        "list[str]", oc_value
                    )
                    object_classes = [str(oc) for oc in typed_oc_list]
                else:
                    object_classes = [str(oc_value)]

            # Convert to LDAP attributes using Python standard conversion
            ldap_attributes = {
                k: [str(v)] if not isinstance(v, list) else [str(item) for item in v]
                for k, v in typed_entry.items()
                if v is not None
            }

            # Create entry with properly typed attributes
            typed_attributes = cast("LdapAttributeDict", ldap_attributes)
            entry = FlextLDAPEntities.Entry(
                id=f"api_entry_{str(entry_dn).replace(',', '_').replace('=', '_')}",
                dn=str(entry_dn),
                object_classes=object_classes,
                attributes=typed_attributes,
                modified_at=None,
            )
            entries.append(entry)

        return FlextResult[list[FlextLDAPEntities.Entry]].ok(entries)

    # Convenience methods using factory patterns from SearchRequest
    async def search_simple(
        self,
        base_dn: str,
        search_filter: str = "(objectClass=*)",
        *,
        scope: str = "subtree",
        attributes: list[str] | None = None,
    ) -> FlextResult[list[FlextLDAPEntities.Entry]]:
        """Simplified search interface using factory method pattern."""
        # Use factory method from SearchRequest for convenience
        search_request = FlextLDAPEntities.SearchRequest(
            base_dn=base_dn,
            filter_str=search_filter,
            scope=scope,
            attributes=attributes,
            size_limit=1000,
            time_limit=30,
        )
        return await self.search(search_request)

    async def search_users(
        self,
        base_dn: str,
        uid: str | None = None,
    ) -> FlextResult[list[FlextLDAPEntities.Entry]]:
        """Search users using factory method for common pattern."""
        search_request = FlextLDAPEntities.SearchRequest.create_user_search(
            base_dn=base_dn,
            uid=uid,
        )
        return await self.search(search_request)

    # User Operations

    async def create_user(
        self,
        user_request: FlextLDAPEntities.CreateUserRequest,
    ) -> FlextResult[FlextLDAPEntities.User]:
        """Create user using proper service layer."""
        return await self._service.create_user(user_request)

    async def get_user(self, dn: str) -> FlextResult[FlextLDAPEntities.User | None]:
        """Get user by DN."""
        return await self._service.get_user(dn)

    async def update_user(
        self,
        dn: str,
        attributes: LdapAttributeDict,
    ) -> FlextResult[None]:
        """Update user attributes."""
        result = await self._service.update_user(dn, attributes)
        return result.map(lambda _: None)

    async def delete_user(self, dn: str) -> FlextResult[None]:
        """Delete user."""
        result = await self._service.delete_user(dn)
        return result.map(lambda _: None)

    async def search_users_by_filter(
        self,
        filter_str: str,
        base_dn: str,
        scope: str = "subtree",
    ) -> FlextResult[list[FlextLDAPEntities.User]]:
        """Search users with filter."""
        # Use the generic search method with user-specific filter
        search_request = FlextLDAPEntities.SearchRequest(
            base_dn=base_dn,
            filter_str=f"(&(objectClass=person){filter_str})",
            scope=scope,
            attributes=["uid", "cn", "mail", "objectClass"],
            size_limit=1000,
            time_limit=30,
        )
        search_result = await self._service.search(search_request)

        # Convert search response entries to users (simplified)
        if search_result.is_success and search_result.value:
            users: list[FlextLDAPEntities.User] = []
            for entry in search_result.value.entries:
                # Create user from entry - simplified mapping
                uid = self._get_entry_attribute(entry, "uid", "unknown")
                user = FlextLDAPEntities.User(
                    id=f"user_{uid}",
                    dn=self._get_entry_attribute(entry, "dn"),
                    uid=uid,
                    cn=self._get_entry_attribute(entry, "cn"),
                    modified_at=None,
                    sn=None,
                    given_name=None,
                    mail=None,
                    user_password=None,
                )
                users.append(user)
            return FlextResult[list[FlextLDAPEntities.User]].ok(users)
        return FlextResult[list[FlextLDAPEntities.User]].ok([])

    # Group Operations

    @overload
    async def create_group(
        self,
        dn_or_request: FlextLDAPEntities.CreateGroupRequest,
    ) -> FlextResult[FlextLDAPEntities.Group]: ...

    @overload
    async def create_group(
        self,
        dn_or_request: str,
        cn: str,
        description: str | None = None,
        members: list[str] | None = None,
    ) -> FlextResult[FlextLDAPEntities.Group]: ...

    async def create_group(
        self,
        dn_or_request: str | FlextLDAPEntities.CreateGroupRequest,
        cn: str | None = None,
        description: str | None = None,
        members: list[str] | None = None,
    ) -> FlextResult[FlextLDAPEntities.Group]:
        """Create group using proper service layer.

        Can accept either a CreateGroupRequest object or individual parameters.
        """
        # Handle both request object and individual parameters
        if isinstance(dn_or_request, FlextLDAPEntities.CreateGroupRequest):
            request = dn_or_request
            dn = request.dn
            cn = request.cn
            description = request.description
            members = request.member_dns
        else:
            dn = dn_or_request
            if cn is None:
                return FlextResult.fail(
                    "cn parameter is required when using individual parameters"
                )
            members = members or []

        # Create group entity with required status
        group = FlextLDAPEntities.Group(
            id=f"api_group_{dn.replace(',', '_').replace('=', '_')}",
            dn=dn,
            cn=cn,
            description=description,
            members=members,
            modified_at=None,
        )

        # Create via service
        create_result = await self._service.create_group(group)
        if create_result.is_success:
            return FlextResult.ok(group)
        return FlextResult.fail(
            create_result.error or "Group creation failed",
        )

    async def get_group(self, dn: str) -> FlextResult[FlextLDAPEntities.Group | None]:
        """Get group by DN."""
        # Use generic search to find group by DN
        search_request = FlextLDAPEntities.SearchRequest(
            base_dn=dn,
            filter_str="(objectClass=groupOfNames)",
            scope="base",
            attributes=["cn", "member", "description", "objectClass"],
            size_limit=1000,
            time_limit=30,
        )
        search_result = await self._service.search(search_request)

        if (
            search_result.is_success
            and search_result.value
            and search_result.value.entries
        ):
            entry = search_result.value.entries[0]
            # Create group from entry
            cn = self._get_entry_attribute(entry, "cn", "unknown")
            # Handle members list safely
            members_raw = entry.get("member", [])
            members = (
                cast("list[str]", members_raw)
                if isinstance(members_raw, list)
                else []
            )
            group = FlextLDAPEntities.Group(
                id=f"group_{cn}",
                dn=self._get_entry_attribute(entry, "dn"),
                cn=cn,
                members=members,
                modified_at=None,
                description=None,
            )
            return FlextResult.ok(group)
        return FlextResult.ok(None)

    async def update_group(
        self,
        dn: str,
        attributes: LdapAttributeDict,
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

    async def get_members(
        self, group_dn: str
    ) -> FlextResult[list[str]]:
        """Get group members."""
        return await self._service.get_members(group_dn)

    # Entry Operations

    async def delete_entry(self, dn: str) -> FlextResult[None]:
        """Delete LDAP entry by DN."""
        repository_result = self._container.get("FlextLDAPRepositories.Repository")
        if not repository_result.is_success:
            return FlextResult.fail(
                f"Failed to get LDAP repository: {repository_result.error}",
            )
        repository = cast("FlextLDAPRepositories", repository_result.value)
        delete_method = getattr(repository, "_delete_async", None)
        if delete_method is None:
            return FlextResult.fail("Repository does not support _delete_async method")
        result = await delete_method(dn)
        if not result.is_success:
            return FlextResult.fail(result.error or "Delete failed")
        return FlextResult.ok(None)

    # Validation Methods

    def validate_dn(self, dn: str) -> FlextResult[None]:
        """Validate distinguished name format using centralized validation - SOURCE OF TRUTH."""
        return FlextLDAPDomain.CentralizedValidations.validate_dn(dn)

    def validate_filter(self, filter_str: str) -> FlextResult[None]:
        """Validate LDAP search filter using centralized validation - SOURCE OF TRUTH."""
        return FlextLDAPDomain.CentralizedValidations.validate_filter(filter_str)

    @classmethod
    def create(cls, config: FlextLDAPConfig | None = None) -> FlextLDAPApi:
        """Create FlextLDAP API instance with dependency injection.

        Factory method following flext-core pattern for consistent API access
        across the FLEXT ecosystem. Uses FlextLDAPConfig singleton as single
        source of truth for configuration.

        Args:
            config: Optional LDAP configuration. If None, uses FlextLDAPConfig singleton.

        Returns:
            Configured FlextLDAPApi instance ready for LDAP operations.

        Example:
            >>> api = FlextLDAPApi.create()
            >>> result = await api.connect("ldap://server", "cn=REDACTED_LDAP_BIND_PASSWORD", "password")
            >>> if result.is_success:
            ...     session = result.value

        """
        return cls(config)


def get_flext_ldap_api(config: FlextLDAPConfig | None = None) -> FlextLDAPApi:
    """Get FlextLDAP API instance - factory function following flext-core pattern.

    Convenience function that wraps FlextLDAPApi.create() for consistent
    factory pattern usage across the FLEXT ecosystem.

    Args:
        config: Optional LDAP configuration. If None, uses environment variables.

    Returns:
        Configured FlextLDAPApi instance ready for LDAP operations.

    Example:
        >>> from flext_ldap import get_flext_ldap_api
        >>> api = get_flext_ldap_api()
        >>> result = await api.connect("ldap://server", "cn=REDACTED_LDAP_BIND_PASSWORD", "password")

    """
    return FlextLDAPApi.create(config)


# Export main API following flext-core pattern
__all__ = [
    "FlextLDAPApi",
    "get_flext_ldap_api",
]
