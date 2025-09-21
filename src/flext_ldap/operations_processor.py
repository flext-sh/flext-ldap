"""LDAP operations processor using FlextProcessor pattern with domain services.

This module refactors the monolithic operations class to use the new domain services
following the FlextProcessor pattern for better separation of concerns and reduced complexity.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Protocol

from flext_core import FlextResult
from flext_ldap.connection_service import FlextLdapConnectionService
from flext_ldap.group_service import FlextLdapGroupService
from flext_ldap.models import FlextLdapModels
from flext_ldap.search_service import FlextLdapSearchService
from flext_ldap.user_service import FlextLdapUserService
from flext_ldap.validations import FlextLdapValidations

if TYPE_CHECKING:
    from flext_ldap.clients import FlextLdapClient
    from flext_ldap.typings import FlextLdapTypes


class FlextLdapOperationsProcessor:
    """FlextProcessor-based LDAP operations using domain services.

    This processor delegates LDAP operations to specialized domain services,
    reducing complexity and improving maintainability through proper separation of concerns.

    Attributes:
        _client: LDAP client for infrastructure operations.
        _connection_service: Domain service for connection operations.
        _user_service: Domain service for user operations.
        _group_service: Domain service for group operations.
        _search_service: Domain service for search operations.

    """

    class _OperationProcessor(Protocol):
        """Nested protocol for LDAP operation processing - unified class pattern."""

        async def process(
            self,
            operation_data: dict[str, object],
        ) -> FlextResult[dict[str, object]]:
            """Process LDAP operation with given data."""
            ...

    def __init__(self, client: FlextLdapClient) -> None:
        """Initialize operations processor with domain services.

        Args:
            client: LDAP client for infrastructure operations.

        """
        self._client = client

        # Initialize domain services
        self._connection_service = FlextLdapConnectionService(client)
        self._user_service = FlextLdapUserService(client)
        self._group_service = FlextLdapGroupService(client)
        self._search_service = FlextLdapSearchService(client)

    # Connection Operations Delegation

    async def connect(
        self,
        server_uri: str,
        bind_dn: str,
        bind_password: str,
    ) -> FlextResult[str]:
        """Connect to LDAP server through connection service."""
        return await self._connection_service.connect(
            server_uri,
            bind_dn,
            bind_password,
        )

    async def disconnect(self, session_id: str | None = None) -> FlextResult[None]:
        """Disconnect from LDAP server through connection service."""
        return await self._connection_service.disconnect(session_id)

    async def test_connection(
        self,
        server_uri: str,
        bind_dn: str,
        bind_password: str,
    ) -> FlextResult[bool]:
        """Test LDAP connection through connection service."""
        return await self._connection_service.test_connection(
            server_uri,
            bind_dn,
            bind_password,
        )

    async def reconnect(
        self,
        server_uri: str,
        bind_dn: str,
        bind_password: str,
    ) -> FlextResult[str]:
        """Reconnect to LDAP server through connection service."""
        return await self._connection_service.reconnect(
            server_uri,
            bind_dn,
            bind_password,
        )

    def is_connected(self) -> FlextResult[bool]:
        """Check connection status through connection service."""
        return self._connection_service.is_connected()

    def get_connection_info(self) -> FlextResult[dict[str, str]]:
        """Get connection information through connection service."""
        return self._connection_service.get_connection_info()

    def validate_server_uri(self, server_uri: str) -> FlextResult[None]:
        """Validate server URI through connection service."""
        return self._connection_service.validate_server_uri(server_uri)

    # User Operations Delegation

    async def create_user(
        self,
        user_request_or_dn: FlextLdapModels.CreateUserRequest | str,
        uid: str | None = None,
        cn: str | None = None,
        sn: str | None = None,
        mail: str | None = None,
    ) -> FlextResult[FlextLdapModels.User]:
        """Create user through user service."""
        return await self._user_service.create_user(
            user_request_or_dn,
            uid,
            cn,
            sn,
            mail,
        )

    async def get_user(self, dn: str) -> FlextResult[FlextLdapModels.User | None]:
        """Get user through user service."""
        return await self._user_service.get_user(dn)

    async def update_user(
        self,
        dn: str,
        attributes: FlextLdapTypes.Entry.AttributeDict,
    ) -> FlextResult[None]:
        """Update user through user service."""
        return await self._user_service.update_user(dn, attributes)

    async def delete_user(self, dn: str) -> FlextResult[None]:
        """Delete user through user service."""
        return await self._user_service.delete_user(dn)

    async def search_users_by_filter(
        self,
        filter_str: str,
        base_dn: str,
        scope: str = "subtree",
    ) -> FlextResult[list[FlextLdapModels.User]]:
        """Search users through user service."""
        return await self._user_service.search_users_by_filter(
            filter_str,
            base_dn,
            scope,
        )

    async def user_exists(self, dn: str) -> FlextResult[bool]:
        """Check if user exists through user service."""
        return await self._user_service.user_exists(dn)

    async def batch_create_users(
        self,
        user_requests: list[FlextLdapModels.CreateUserRequest],
    ) -> FlextResult[list[FlextLdapModels.User]]:
        """Create multiple users through user service."""
        return await self._user_service.batch_create_users(user_requests)

    async def batch_delete_users(self, dns: list[str]) -> FlextResult[list[None]]:
        """Delete multiple users through user service."""
        return await self._user_service.batch_delete_users(dns)

    async def batch_get_users(
        self,
        dns: list[str],
    ) -> FlextResult[list[FlextLdapModels.User | None]]:
        """Get multiple users through user service."""
        return await self._user_service.batch_get_users(dns)

    # Group Operations Delegation

    async def create_group(
        self,
        group_request_or_dn: FlextLdapModels.CreateGroupRequest | str,
        cn: str | None = None,
        description: str | None = None,
        member_dns: list[str] | None = None,
    ) -> FlextResult[FlextLdapModels.Group]:
        """Create group through group service."""
        return await self._group_service.create_group(
            group_request_or_dn,
            cn,
            description,
            member_dns,
        )

    async def get_group(self, dn: str) -> FlextResult[FlextLdapModels.Group | None]:
        """Get group through group service."""
        return await self._group_service.get_group(dn)

    async def update_group(
        self,
        dn: str,
        attributes: FlextLdapTypes.Entry.AttributeDict,
    ) -> FlextResult[None]:
        """Update group through group service."""
        return await self._group_service.update_group(dn, attributes)

    async def delete_group(self, dn: str) -> FlextResult[None]:
        """Delete group through group service."""
        return await self._group_service.delete_group(dn)

    async def add_member(self, group_dn: str, member_dn: str) -> FlextResult[None]:
        """Add member to group through group service."""
        return await self._group_service.add_member(group_dn, member_dn)

    async def remove_member(self, group_dn: str, member_dn: str) -> FlextResult[None]:
        """Remove member from group through group service."""
        return await self._group_service.remove_member(group_dn, member_dn)

    async def get_members(self, group_dn: str) -> FlextResult[list[str]]:
        """Get group members through group service."""
        return await self._group_service.get_members(group_dn)

    async def search_groups_by_filter(
        self,
        filter_str: str,
        base_dn: str,
        scope: str = "subtree",
    ) -> FlextResult[list[FlextLdapModels.Group]]:
        """Search groups through search service (delegated)."""
        # Use search service since group service doesn't have this method
        search_request = FlextLdapModels.SearchRequest(
            base_dn=base_dn,
            filter_str=f"(&(objectClass=groupOfNames){filter_str})",
            scope=scope,
            attributes=["cn", "description", "member", "objectClass"],
            size_limit=1000,
            time_limit=30,
        )
        search_result = await self._search_service.search(search_request)
        if search_result.is_failure:
            return FlextResult[list[FlextLdapModels.Group]].fail(
                search_result.error or "Search failed",
            )

        # Convert entries to groups manually since group service doesn't have this
        groups: list[FlextLdapModels.Group] = []
        for entry in search_result.value:
            # Extract attributes for group creation
            cn_values = entry.attributes.get("cn", ["unknown"])
            cn_raw = cn_values[0] if cn_values else "unknown"
            cn = cn_raw.decode("utf-8") if isinstance(cn_raw, bytes) else str(cn_raw)

            description_list = entry.attributes.get("description", [])
            description_raw = description_list[0] if description_list else None
            description = (
                description_raw.decode("utf-8")
                if isinstance(description_raw, bytes)
                else str(description_raw)
                if description_raw
                else None
            )

            member_list = entry.attributes.get("member", [])
            members = (
                [
                    m.decode("utf-8") if isinstance(m, bytes) else str(m)
                    for m in member_list
                ]
                if member_list
                else []
            )

            group = FlextLdapModels.Group(
                id=f"group_{cn}",
                dn=entry.dn,
                cn=cn,
                description=description,
                members=members,
                modified_at=None,
            )
            groups.append(group)

        return FlextResult[list[FlextLdapModels.Group]].ok(groups)

    async def group_exists(self, dn: str) -> FlextResult[bool]:
        """Check if group exists through group service."""
        return await self._group_service.group_exists(dn)

    async def batch_create_groups(
        self,
        group_requests: list[FlextLdapModels.CreateGroupRequest],
    ) -> FlextResult[list[FlextLdapModels.Group]]:
        """Create multiple groups through group service."""
        return await self._group_service.batch_create_groups(group_requests)

    async def batch_delete_groups(self, dns: list[str]) -> FlextResult[list[None]]:
        """Delete multiple groups through individual calls."""
        results: list[None] = []
        for dn in dns:
            result = await self.delete_group(dn)
            if result.is_failure:
                return FlextResult[list[None]].fail(
                    f"Group deletion failed: {result.error}",
                )
            results.append(result.value)
        return FlextResult[list[None]].ok(results)

    async def batch_get_groups(
        self,
        dns: list[str],
    ) -> FlextResult[list[FlextLdapModels.Group | None]]:
        """Get multiple groups through individual calls."""
        results: list[FlextLdapModels.Group | None] = []
        for dn in dns:
            result = await self.get_group(dn)
            if result.is_failure:
                return FlextResult[list[FlextLdapModels.Group | None]].fail(
                    f"Failed to get group {dn}: {result.error}",
                )
            results.append(result.value)
        return FlextResult[list[FlextLdapModels.Group | None]].ok(results)

    async def batch_add_members(
        self,
        operations: list[tuple[str, str]],
    ) -> FlextResult[list[None]]:
        """Add multiple members to groups through group service."""
        return await self._group_service.batch_add_members(operations)

    async def batch_remove_members(
        self,
        operations: list[tuple[str, str]],
    ) -> FlextResult[list[None]]:
        """Remove multiple members from groups through group service."""
        return await self._group_service.batch_remove_members(operations)

    # Search Operations Delegation

    async def search(
        self,
        search_request: FlextLdapModels.SearchRequest,
    ) -> FlextResult[list[FlextLdapModels.Entry]]:
        """Execute search through search service."""
        return await self._search_service.search(search_request)

    async def search_simple(
        self,
        base_dn: str,
        search_filter: str = "(objectClass=*)",
        *,
        scope: str = "subtree",
        attributes: list[str] | None = None,
    ) -> FlextResult[list[FlextLdapModels.Entry]]:
        """Execute simple search through search service."""
        return await self._search_service.search_simple(
            base_dn,
            search_filter,
            scope=scope,
            attributes=attributes,
        )

    async def search_users(
        self,
        base_dn: str,
        uid: str | None = None,
        cn: str | None = None,
        mail: str | None = None,
    ) -> FlextResult[list[FlextLdapModels.User]]:
        """Search users through search service."""
        return await self._search_service.search_users(base_dn, uid, cn, mail)

    async def search_groups(
        self,
        base_dn: str,
        cn: str | None = None,
        description: str | None = None,
    ) -> FlextResult[list[FlextLdapModels.Group]]:
        """Search groups through search service."""
        return await self._search_service.search_groups(base_dn, cn, description)

    async def search_by_object_class(
        self,
        base_dn: str,
        object_class: str,
        scope: str = "subtree",
        attributes: list[str] | None = None,
    ) -> FlextResult[list[FlextLdapModels.Entry]]:
        """Search by object class through search service."""
        return await self._search_service.search_by_object_class(
            base_dn,
            object_class,
            scope,
            attributes,
        )

    async def count_entries(
        self,
        base_dn: str,
        search_filter: str = "(objectClass=*)",
        scope: str = "subtree",
    ) -> FlextResult[int]:
        """Count entries through search service."""
        return await self._search_service.count_entries(base_dn, search_filter, scope)

    # Validation Operations (using centralized FlextLdapValidations)

    def validate_dn(self, dn: str) -> FlextResult[None]:
        """Validate DN using centralized validations."""
        return FlextLdapValidations.validate_dn(dn)

    def validate_filter(self, filter_str: str) -> FlextResult[None]:
        """Validate filter using centralized validations."""
        return FlextLdapValidations.validate_filter(filter_str)

    def validate_email(self, email: str | None) -> FlextResult[None]:
        """Validate email using centralized validations."""
        return FlextLdapValidations.validate_email(email)

    def validate_password(self, password: str | None) -> FlextResult[None]:
        """Validate password using centralized validations."""
        return FlextLdapValidations.validate_password(password)

    def validate_uri(self, uri: str) -> FlextResult[None]:
        """Validate URI using centralized validations."""
        return FlextLdapValidations.validate_uri(uri)

    # Command Processing (simplified through domain service delegation)

    async def execute_command(
        self,
        command_type: str,
        command_data: dict[str, object],
    ) -> FlextResult[dict[str, object]]:
        """Execute LDAP command through appropriate domain service.

        This method routes commands to the appropriate domain service
        based on the command type, providing a unified interface.
        """
        try:
            if command_type == "connect":
                return await self._handle_connect_command(command_data)
            if command_type == "search":
                return await self._handle_search_command(command_data)
            if command_type == "add":
                return await self._handle_add_command(command_data)
            if command_type == "modify":
                return await self._handle_modify_command(command_data)
            if command_type == "delete":
                return await self._handle_delete_command(command_data)
            return FlextResult[dict[str, object]].fail(
                f"Unknown command type: {command_type}",
            )
        except Exception as e:
            return FlextResult[dict[str, object]].fail(f"Command execution error: {e}")

    async def _handle_connect_command(
        self,
        command_data: dict[str, object],
    ) -> FlextResult[dict[str, object]]:
        """Handle connect command."""
        connect_result = await self.connect(
            str(command_data["server_uri"]),
            str(command_data["bind_dn"]),
            str(command_data["bind_password"]),
        )
        if connect_result.is_failure:
            return FlextResult[dict[str, object]].fail(
                connect_result.error or "Connection failed",
            )
        return FlextResult[dict[str, object]].ok({"session_id": connect_result.value})

    async def _handle_search_command(
        self,
        command_data: dict[str, object],
    ) -> FlextResult[dict[str, object]]:
        """Handle search command."""
        # Safely extract attributes
        raw_attributes = command_data.get("attributes")
        attributes = None
        if raw_attributes is not None and isinstance(raw_attributes, list):
            attributes = [str(attr) for attr in raw_attributes]

        # Safely extract numeric values
        raw_size_limit = command_data.get("size_limit", 1000)
        size_limit = (
            int(raw_size_limit) if isinstance(raw_size_limit, (int, str)) else 1000
        )

        raw_time_limit = command_data.get("time_limit", 30)
        time_limit = (
            int(raw_time_limit) if isinstance(raw_time_limit, (int, str)) else 30
        )

        search_request = FlextLdapModels.SearchRequest(
            base_dn=str(command_data["base_dn"]),
            filter_str=str(command_data.get("filter", "(objectClass=*)")),
            scope=str(command_data.get("scope", "subtree")),
            attributes=attributes,
            size_limit=size_limit,
            time_limit=time_limit,
        )
        search_result = await self.search(search_request)
        if search_result.is_failure:
            return FlextResult[dict[str, object]].fail(
                search_result.error or "Search failed",
            )
        return FlextResult[dict[str, object]].ok({"entries": search_result.value})

    async def _handle_add_command(
        self,
        _command_data: dict[str, object],
    ) -> FlextResult[dict[str, object]]:
        """Handle add command."""
        # Implementation would go here
        return FlextResult[dict[str, object]].fail("Add command not implemented")

    async def _handle_modify_command(
        self,
        _command_data: dict[str, object],
    ) -> FlextResult[dict[str, object]]:
        """Handle modify command."""
        # Implementation would go here
        return FlextResult[dict[str, object]].fail("Modify command not implemented")

    async def _handle_delete_command(
        self,
        _command_data: dict[str, object],
    ) -> FlextResult[dict[str, object]]:
        """Handle delete command."""
        # Implementation would go here
        return FlextResult[dict[str, object]].fail("Delete command not implemented")

    async def _handle_create_user_command(
        self,
        command_data: dict[str, object],
    ) -> FlextResult[dict[str, object]]:
        """Handle create user command."""
        # Safe type extraction
        dn = command_data.get("dn")
        uid = command_data.get("uid")
        cn = command_data.get("cn")
        sn = command_data.get("sn")
        mail = command_data.get("mail")
        object_classes = command_data.get(
            "object_classes",
            ["person", "organizationalPerson"],
        )

        # Type validation
        if not all(isinstance(val, str) for val in [dn, uid, cn, sn]):
            return FlextResult[dict[str, object]].fail(
                "Missing required string fields for user creation",
            )

        if mail is not None and not isinstance(mail, str):
            return FlextResult[dict[str, object]].fail("Mail field must be a string")

        if not isinstance(object_classes, list) or not all(
            isinstance(cls, str) for cls in object_classes
        ):
            return FlextResult[dict[str, object]].fail(
                "Object classes must be a list of strings",
            )

        user_request = FlextLdapModels.CreateUserRequest(
            dn=str(dn),
            uid=str(uid),
            cn=str(cn),
            sn=str(sn),
            mail=str(mail) if mail else None,
            object_classes=object_classes,
        )
        result = await self.create_user(user_request)
        if result.is_failure:
            return FlextResult[dict[str, object]].fail(
                result.error or "User creation failed",
            )
        return FlextResult[dict[str, object]].ok({"user": result.value})

    # Property Accessors for Domain Services (for advanced usage)
    @property
    def connection_service(self) -> FlextLdapConnectionService:
        """Access to connection domain service."""
        return self._connection_service

    @property
    def user_service(self) -> FlextLdapUserService:
        """Access to user domain service."""
        return self._user_service

    @property
    def group_service(self) -> FlextLdapGroupService:
        """Access to group domain service."""
        return self._group_service

    @property
    def search_service(self) -> FlextLdapSearchService:
        """Access to search domain service."""
        return self._search_service
