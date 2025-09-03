"""FLEXT-LDAP API - Clean Architecture Implementation.

High-level API facade following SOLID principles and Domain-Driven Design.
Uses dependency injection and proper service layer patterns.
"""

from __future__ import annotations

import uuid
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import cast

from flext_core import FlextLogger, FlextResult

from flext_ldap.clients import FlextLDAPClient
from flext_ldap.container import FlextLDAPContainer
from flext_ldap.entities import FlextLDAPEntities
from flext_ldap.exceptions import FlextLDAPExceptions
from flext_ldap.repositories import FlextLDAPRepositories
from flext_ldap.services import FlextLDAPServices
from flext_ldap.settings import FlextLDAPSettings
from flext_ldap.typings import LdapAttributeDict

# Removed FlextLDAPUtilities - using Python standard library

logger = FlextLogger(__name__)


class FlextLDAPApi:
    """High-level LDAP API facade using proper SOLID architecture.

    This API provides a clean, type-safe interface to LDAP operations
    without exposing internal implementation details. All operations
    go through the service layer and use dependency injection.
    """

    def __init__(self, config: FlextLDAPSettings | None = None) -> None:
        """Initialize API with configuration and dependency injection."""
        self._config = config or FlextLDAPSettings()
        self._container_manager = FlextLDAPContainer()
        self._container = self._container_manager.get_container()
        self._service = FlextLDAPServices(self._container)

        logger.info("FlextLDAPApi initialized with clean architecture")

    def _generate_session_id(self) -> str:
        """Generate unique session ID."""
        return f"session_{uuid.uuid4()}"

    def _get_entry_attribute(
        self, entry: dict[str, object], key: str, default: str = ""
    ) -> str:
        """Safely extract string attribute from LDAP entry."""
        value = entry.get(key, [default])

        # Handle list values (common in LDAP)
        if isinstance(value, list):
            if value:
                # Get first item with type safety - suppress type checking for object conversion
                first_value: object = value[0]
                try:
                    # Use type ignore for object to string conversion - safe for LDAP data
                    return str(first_value) if first_value is not None else default
                except (TypeError, ValueError):
                    return default
            return default

        # Handle non-list values - suppress type checking for object conversion
        try:
            return str(value) if value is not None else default
        except (TypeError, ValueError):
            return default

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

        # Get client from flext-core container
        client_result = self._container.get("FlextLDAPClient")
        if not client_result.is_success:
            return FlextResult[str].fail(
                f"Failed to get LDAP client: {client_result.error}"
            )
        client = cast("FlextLDAPClient", client_result.value)

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
        client_result = self._container.get("FlextLDAPClient")
        if not client_result.is_success:
            return FlextResult[bool].fail(
                f"Failed to get LDAP client: {client_result.error}"
            )
        client = cast("FlextLDAPClient", client_result.value)
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
            raise FlextLDAPExceptions.LdapConnectionError(msg)

        # Use FlextResult.value for modern type-safe access
        session_id = connect_result.value
        if not session_id:
            msg = "Failed to get session ID"
            raise FlextLDAPExceptions.LdapConnectionError(msg)

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
    ) -> FlextResult[list[FlextLDAPEntities.Entry]]:
        """Search LDAP directory using proper architecture."""
        # Import cast for type handling
        from typing import cast

        # Create search request
        search_request = FlextLDAPEntities.SearchRequest(
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
                    typed_oc_list: list[object] = cast("list[object]", oc_value)
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

    async def search_users(
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

    async def create_group(
        self,
        dn: str,
        cn: str,
        description: str | None = None,
        members: list[str] | None = None,
    ) -> FlextResult[FlextLDAPEntities.Group]:
        """Create group using proper service layer."""
        # Create group entity with required status
        group = FlextLDAPEntities.Group(
            id=f"api_group_{dn.replace(',', '_').replace('=', '_')}",
            dn=dn,
            cn=cn,
            description=description,
            members=members or [],
            modified_at=None,
        )

        # Create via service
        create_result = await self._service.create_group(group)
        if create_result.is_success:
            return FlextResult[FlextLDAPEntities.Group].ok(group)
        return FlextResult[FlextLDAPEntities.Group].fail(
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
                cast("list[str]", members_raw) if isinstance(members_raw, list) else []
            )
            group = FlextLDAPEntities.Group(
                id=f"group_{cn}",
                dn=self._get_entry_attribute(entry, "dn"),
                cn=cn,
                members=members,
                modified_at=None,
                description=None,
            )
            return FlextResult[FlextLDAPEntities.Group | None].ok(group)
        return FlextResult[FlextLDAPEntities.Group | None].ok(None)

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

    async def get_members(self, group_dn: str) -> FlextResult[list[str]]:
        """Get group members."""
        return await self._service.get_members(group_dn)

    # Entry Operations

    async def delete_entry(self, dn: str) -> FlextResult[None]:
        """Delete LDAP entry by DN."""
        repository_result = self._container.get("FlextLDAPRepositories.Repository")
        if not repository_result.is_success:
            return FlextResult[None].fail(
                f"Failed to get LDAP repository: {repository_result.error}"
            )
        repository = cast("FlextLDAPRepositories.Repository", repository_result.value)
        result = await repository.delete_async(dn)
        if not result.is_success:
            return FlextResult[None].fail(result.error or "Delete failed")
        return FlextResult[None].ok(None)

    # Validation Methods

    def validate_dn(self, dn: str) -> FlextResult[None]:
        """Validate distinguished name format."""
        return self._service.validate_dn(dn)

    def validate_filter(self, filter_str: str) -> FlextResult[None]:
        """Validate LDAP search filter."""
        return self._service.validate_filter(filter_str)

    @classmethod
    def create(cls, config: FlextLDAPSettings | None = None) -> FlextLDAPApi:
        """Create FlextLDAP API instance with dependency injection.

        Factory method following flext-core pattern for consistent API access
        across the FLEXT ecosystem. Provides proper dependency injection and
        service layer initialization.

        Args:
            config: Optional LDAP configuration. If None, uses environment variables.

        Returns:
            Configured FlextLDAPApi instance ready for LDAP operations.

        Example:
            >>> api = FlextLDAPApi.create()
            >>> result = await api.connect("ldap://server", "cn=admin", "password")
            >>> if result.is_success:
            ...     session = result.value

        """
        return cls(config)


# Export main API following flext-core pattern
__all__ = [
    "FlextLDAPApi",
]
