"""LDAP API module.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import uuid
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from functools import cached_property
from typing import cast

from flext_core import (
    FlextExceptions,
    FlextMixins,
    FlextResult,
    FlextTypes,
)
from flext_ldap.config import FlextLdapConfigs as FlextLdapConfig
from flext_ldap.container import FlextLdapContainer
from flext_ldap.models import FlextLdapModels
from flext_ldap.repositories import FlextLdapRepositories
from flext_ldap.typings import FlextLdapTypes
from flext_ldap.validations import FlextLdapValidations


class FlextLdapApi(FlextMixins.Loggable):
    """High-level LDAP API facade providing unified interface for LDAP operations.

    This class serves as the main entry point for LDAP operations in the flext-ldap
    library. It provides a high-level API that abstracts away the complexity of
    LDAP operations while maintaining full functionality and type safety.

    The API uses FlextMixins.Loggable for structured logging and integrates with
    the flext-core ecosystem for configuration management and dependency injection.

    Attributes:
        _config: LDAP configuration instance.
        _container_manager: Container manager for dependency injection.
        _container: Dependency injection container.
        _service: Core LDAP service instance.

    """

    class _Formatters:
        """Nested formatter helper class for CLI output - unified class pattern."""

        @staticmethod
        def display_message(message: str, level: str = "info") -> None:
            """Display formatted message."""

        @staticmethod
        def print_success(message: str) -> None:
            """Print success message."""

    class _ConnectionHelper:
        """Nested connection helper class - unified class pattern."""

        @staticmethod
        def format_connection_info(server_uri: str, bind_dn: str) -> str:
            """Format connection information for display."""
            return f"Server: {server_uri}\nBind DN: {bind_dn}"

    class _SearchHelper:
        """Nested search helper class - unified class pattern."""

        @staticmethod
        def create_search_request(
            base_dn: str,
            filter_str: str,
        ) -> FlextLdapModels.SearchRequest:
            """Create search request with default parameters."""
            return FlextLdapModels.SearchRequest(
                base_dn=base_dn,
                filter_str=filter_str,
                scope="subtree",
                attributes=None,
                size_limit=1000,
                time_limit=30,
            )

    class _UserManagementHelper:
        """Nested user management helper class - unified class pattern."""

        @staticmethod
        def create_user_request(
            dn: str,
            uid: str,
            cn: str,
            sn: str,
        ) -> FlextLdapModels.CreateUserRequest:
            """Create user request with standard parameters."""
            return FlextLdapModels.CreateUserRequest(
                dn=dn,
                uid=uid,
                cn=cn,
                sn=sn,
                mail=None,
                object_classes=["person", "organizationalPerson"],
            )

        @staticmethod
        def format_user_info(user: FlextLdapModels.User) -> str:
            """Format user information for display."""
            return f"User: {user.uid}\nDN: {user.dn}\nCN: {user.cn}"

    def __init__(self, config: FlextLdapConfig | None = None) -> None:
        """Initialize API with configuration and dependency injection.

        Sets up the API instance with logging capabilities, configuration management,
        and dependency injection container. Uses singleton pattern for configuration
        when no specific config is provided.

        Args:
            config: Optional LDAP configuration. If None, uses global singleton.

        """
        # Initialize FlextMixins.Loggable
        super().__init__()
        # Use provided config directly if given, otherwise use singleton
        if config is not None:
            self._config = config
        else:
            self._config = FlextLdapConfig.get_global_instance()
        self._container_manager = FlextLdapContainer()
        self._container = self._container_manager.get_container()
        self._client = self._container_manager.get_client()

        # CLI helper instances for unified class pattern
        self._formatters = self._Formatters()
        self._connection_helper = self._ConnectionHelper()
        self._search_helper = self._SearchHelper()
        self._user_management_helper = self._UserManagementHelper()

        self.log_info(
            "FlextLdapApi initialized with FlextLdapConfig singleton",
            api="FlextLdapApi",
        )

    @cached_property
    def session_id(self) -> str:
        """Generate unique session ID using Python standard library.

        Creates a unique session identifier using UUID4 for tracking
        API operations and maintaining session state.

        Returns:
            str: Unique session identifier in format 'session_{uuid}'.

        """
        return f"session_{uuid.uuid4()}"

    def _get_entry_attribute(
        self,
        entry: FlextTypes.Core.Dict | FlextLdapModels.Entry,
        key: str,
        default: str = "",
    ) -> str:
        """Extract string attribute from entry using Python 3.13 pattern matching."""
        # Get raw value from entry based on union type
        raw_value: object
        if isinstance(entry, FlextLdapModels.Entry):
            attr_values = entry.attributes.get(key, [])
            raw_value = attr_values[0] if attr_values else None
        else:  # Must be dict due to union type constraint
            raw_value = entry.get(key)

        # Return default if no value found
        if raw_value is None:
            return default

        # Convert value to string with type safety
        if isinstance(raw_value, str):
            return raw_value or default
        if isinstance(raw_value, bytes):
            return raw_value.decode("utf-8", errors="replace")
        if isinstance(raw_value, list):
            if len(raw_value) > 0:
                # Check if first element is None or empty string
                first_element = raw_value[0]
                if first_element is None or first_element == "":
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

    # NO CLI compatibility methods - use flext-cli domain library for CLI operations

    # Public helper methods to avoid private member access violations

    def display_message(self, message: str, level: str = "info") -> None:
        """Display formatted message using internal formatter."""
        self._formatters.display_message(message, level)

    def print_success(self, message: str) -> None:
        """Print success message using internal formatter."""
        self._formatters.print_success(message)

    def format_connection_info(self, server_uri: str, bind_dn: str) -> str:
        """Format connection information for display using internal helper."""
        return self._connection_helper.format_connection_info(server_uri, bind_dn)

    def create_search_request(
        self,
        base_dn: str,
        filter_str: str,
    ) -> FlextLdapModels.SearchRequest:
        """Create search request with default parameters using internal helper."""
        return self._search_helper.create_search_request(base_dn, filter_str)

    def create_user_request(
        self,
        dn: str,
        uid: str,
        cn: str,
        sn: str,
    ) -> FlextLdapModels.CreateUserRequest:
        """Create user request with standard parameters using internal helper."""
        return self._user_management_helper.create_user_request(dn, uid, cn, sn)

    def format_user_info(self, user: FlextLdapModels.User) -> str:
        """Format user information for display using internal helper."""
        return self._user_management_helper.format_user_info(user)

    async def connect_to_ldap(
        self,
        server_uri: str,
        bind_dn: str,
        bind_password: str,
    ) -> FlextResult[str]:
        """Connect to LDAP server - CLI method wrapper."""
        return await self.connect(server_uri, bind_dn, bind_password)

    async def search_ldap(
        self,
        base_dn: str,
        filter_str: str = "(objectClass=*)",
        scope: str = "subtree",
    ) -> FlextResult[FlextLdapModels.SearchResponse]:
        """Search LDAP directory - CLI method."""
        search_request = FlextLdapModels.SearchRequest(
            base_dn=base_dn,
            filter_str=filter_str,
            scope=scope,
            attributes=None,
            size_limit=1000,
            time_limit=30,
        )
        return await self._client.search_with_request(search_request)

    # Connection Management

    async def connect(
        self,
        server_uri: str,
        bind_dn: str,
        bind_password: str,
    ) -> FlextResult[str]:
        """Connect to LDAP server and establish session.

        Establishes connection to the specified LDAP server using provided
        credentials. Returns a session ID for tracking the connection.

        Args:
            server_uri: LDAP server URI (ldap:// or ldaps://).
            bind_dn: Distinguished name for authentication.
            bind_password: Password for authentication.

        Returns:
            FlextResult[str]: Success with session ID or error result.

        """
        # Use cached session_id property from FlextUtilities
        new_session_id = self.session_id
        result = await self._client.connect(server_uri, bind_dn, bind_password)
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
        # NO API compatibility maintained - parameter ignored
        # Currently not used by the service layer implementation
        _ = session_id  # Acknowledge parameter to silence linter
        return await self._client.unbind()

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
        search_request: FlextLdapModels.SearchRequest,
    ) -> FlextResult[list[FlextLdapModels.Entry]]:
        """Execute LDAP search using validated request entity.

        Performs LDAP search operation using the provided search request.
        The request is validated and processed through the service layer
        to ensure proper error handling and result formatting.

        Args:
            search_request: Encapsulated search parameters with validation.

        Returns:
            FlextResult[list[FlextLdapModels.Entry]]: Search results or error.

        """
        # Execute search via service - eliminates parameter mapping duplication
        search_result = await self._client.search_with_request(search_request)
        if not search_result.is_success:
            return FlextResult[list[FlextLdapModels.Entry]].fail(
                search_result.error or "Search failed",
            )

        # Convert response entries to FlextLdapModels.Entry objects
        entries: list[FlextLdapModels.Entry] = []
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
                    typed_oc_list: list[str] = cast("list[str]", oc_value)
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
            entry = FlextLdapModels.Entry(
                id=f"api_entry_{str(entry_dn).replace(',', '_').replace('=', '_')}",
                dn=str(entry_dn),
                object_classes=object_classes,
                attributes={
                    str(k): [str(item) for item in v]
                    if isinstance(v, list)
                    else [str(v)]
                    for k, v in ldap_attributes.items()
                },
                modified_at=None,
            )
            entries.append(entry)

        return FlextResult[list[FlextLdapModels.Entry]].ok(entries)

    # Convenience methods using factory patterns from SearchRequest
    async def search_simple(
        self,
        base_dn: str,
        search_filter: str = "(objectClass=*)",
        *,
        scope: str = "subtree",
        attributes: list[str] | None = None,
    ) -> FlextResult[list[FlextLdapModels.Entry]]:
        """Simplified search interface using factory method pattern."""
        # Use factory method from SearchRequest for convenience
        search_request = FlextLdapModels.SearchRequest(
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
    ) -> FlextResult[list[FlextLdapModels.Entry]]:
        """Search users using factory method for common pattern."""
        search_request = FlextLdapModels.SearchRequest.create_user_search(
            base_dn=base_dn,
            uid=uid,
        )
        return await self.search(search_request)

    # User Operations

    async def create_user(
        self,
        user_request_or_dn: FlextLdapModels.CreateUserRequest | str,
        uid: str | None = None,
        cn: str | None = None,
        sn: str | None = None,
        mail: str | None = None,
    ) -> FlextResult[FlextLdapModels.User]:
        """Create user using proper service layer - supports both request object and individual parameters."""
        # Handle both request object and individual parameters
        if isinstance(user_request_or_dn, FlextLdapModels.CreateUserRequest):
            # First overload: request object only - validate no extra params provided
            request = user_request_or_dn
        else:
            # Second overload: individual parameters (uid, cn, sn are required)
            dn = user_request_or_dn
            if uid is None or cn is None or sn is None:
                return FlextResult[FlextLdapModels.User].fail(
                    "uid, cn, and sn are required when using individual parameters",
                )
            request = FlextLdapModels.CreateUserRequest(
                dn=dn,
                uid=uid,
                cn=cn,
                sn=sn,
                mail=mail,
                object_classes=["person", "organizationalPerson"],
            )
        # Create LDAP attributes from the request
        attributes: dict[str, list[str] | list[bytes] | str | bytes] = {
            "uid": [request.uid],
            "cn": [request.cn],
            "sn": [request.sn],
            "objectClass": request.object_classes,
        }
        if request.mail:
            attributes["mail"] = [request.mail]

        # Use client to add the entry
        add_result = await self._client.add_entry(request.dn, attributes)
        if not add_result.is_success:
            return FlextResult[FlextLdapModels.User].fail(
                f"Failed to create user: {add_result.error}"
            )

        # Return the created user object
        created_user = FlextLdapModels.User(
            id=f"user_{request.uid}",
            dn=request.dn,
            uid=request.uid,
            cn=request.cn,
            sn=request.sn,
            mail=request.mail,
            modified_at=None,
            given_name=None,
            user_password=None,
        )
        return FlextResult[FlextLdapModels.User].ok(created_user)

    async def get_user(self, dn: str) -> FlextResult[FlextLdapModels.User | None]:
        """Get user by DN."""
        # Search for the user by DN
        search_request = FlextLdapModels.SearchRequest(
            base_dn=dn,
            filter_str="(objectClass=person)",
            scope="base",
            attributes=["uid", "cn", "sn", "mail", "givenName"],
            size_limit=1,
            time_limit=30,
        )

        search_result = await self._client.search_with_request(search_request)
        if not search_result.is_success:
            return FlextResult[FlextLdapModels.User | None].fail(
                f"Failed to search for user: {search_result.error}"
            )

        if not search_result.value.entries:
            return FlextResult[FlextLdapModels.User | None].ok(None)

        # Convert the first entry to a User object
        entry = search_result.value.entries[0]
        uid = self._get_entry_attribute(entry, "uid", "unknown")
        user = FlextLdapModels.User(
            id=f"user_{uid}",
            dn=dn,
            uid=uid,
            cn=self._get_entry_attribute(entry, "cn"),
            sn=self._get_entry_attribute(entry, "sn"),
            mail=self._get_entry_attribute(entry, "mail"),
            given_name=self._get_entry_attribute(entry, "givenName"),
            modified_at=None,
            user_password=None,
        )
        return FlextResult[FlextLdapModels.User | None].ok(user)

    async def update_user(
        self,
        dn: str,
        attributes: FlextLdapTypes.Entry.AttributeDict,
    ) -> FlextResult[None]:
        """Update user attributes."""
        # Use client to modify the entry
        modify_result = await self._client.modify_entry(dn, attributes)
        if not modify_result.is_success:
            return FlextResult[None].fail(
                f"Failed to update user: {modify_result.error}"
            )
        return FlextResult[None].ok(None)

    async def delete_user(self, dn: str) -> FlextResult[None]:
        """Delete user."""
        # Use client to delete the entry
        delete_result = await self._client.delete(dn)
        if not delete_result.is_success:
            return FlextResult[None].fail(
                f"Failed to delete user: {delete_result.error}"
            )
        return FlextResult[None].ok(None)

    async def search_users_by_filter(
        self,
        filter_str: str,
        base_dn: str,
        scope: str = "subtree",
    ) -> FlextResult[list[FlextLdapModels.User]]:
        """Search users with filter."""
        # Use the generic search method with user-specific filter
        search_request = FlextLdapModels.SearchRequest(
            base_dn=base_dn,
            filter_str=f"(&(objectClass=person){filter_str})",
            scope=scope,
            attributes=["uid", "cn", "mail", "objectClass"],
            size_limit=1000,
            time_limit=30,
        )
        search_result = await self._client.search_with_request(search_request)

        # Convert search response entries to users (simplified)
        if search_result.is_success and search_result.value:
            users: list[FlextLdapModels.User] = []
            for entry in search_result.value.entries:
                # Create user from entry - simplified mapping
                uid = self._get_entry_attribute(entry, "uid", "unknown")
                user = FlextLdapModels.User(
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
            return FlextResult[list[FlextLdapModels.User]].ok(users)
        return FlextResult[list[FlextLdapModels.User]].ok([])

    # Group Operations

    async def create_group(
        self,
        dn_or_request: str | FlextLdapModels.CreateGroupRequest,
        cn: str | None = None,
        description: str | None = None,
        members: list[str] | None = None,
    ) -> FlextResult[FlextLdapModels.Group]:
        """Create group using proper service layer.

        Can accept either a CreateGroupRequest object or individual parameters.
        """
        # Handle both request object and individual parameters
        if isinstance(dn_or_request, FlextLdapModels.CreateGroupRequest):
            request = dn_or_request
            dn = request.dn
            cn = request.cn
            description = request.description
            members = request.member_dns
        else:
            dn = dn_or_request
            if cn is None:
                return FlextResult.fail(
                    "cn parameter is required when using individual parameters",
                )
            members = members or []

        # Create group entity with required status
        group = FlextLdapModels.Group(
            id=f"api_group_{dn.replace(',', '_').replace('=', '_')}",
            dn=dn,
            cn=cn,
            description=description,
            members=members,
            modified_at=None,
        )

        # Create LDAP attributes for the group
        attributes: dict[str, list[str] | list[bytes] | str | bytes] = {
            "cn": [cn],
            "objectClass": ["groupOfNames"],
        }
        if description:
            attributes["description"] = [description]
        if members:
            attributes["member"] = members
        else:
            # Add a dummy member since groupOfNames requires at least one member
            attributes["member"] = ["cn=dummy"]

        # Use client to add the group entry
        add_result = await self._client.add_entry(dn, attributes)
        if not add_result.is_success:
            return FlextResult[FlextLdapModels.Group].fail(
                f"Failed to create group: {add_result.error}"
            )

        return FlextResult[FlextLdapModels.Group].ok(group)

    async def get_group(self, dn: str) -> FlextResult[FlextLdapModels.Group | None]:
        """Get group by DN."""
        # Use generic search to find group by DN
        search_request = FlextLdapModels.SearchRequest(
            base_dn=dn,
            filter_str="(objectClass=groupOfNames)",
            scope="base",
            attributes=["cn", "member", "description", "objectClass"],
            size_limit=1000,
            time_limit=30,
        )
        search_result = await self._client.search_with_request(search_request)

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
            group = FlextLdapModels.Group(
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
        attributes: FlextLdapTypes.Entry.AttributeDict,
    ) -> FlextResult[None]:
        """Update group attributes."""
        # Use client to modify the group entry
        modify_result = await self._client.modify_entry(dn, attributes)
        if not modify_result.is_success:
            return FlextResult[None].fail(
                f"Failed to update group: {modify_result.error}"
            )
        return FlextResult[None].ok(None)

    async def delete_group(self, dn: str) -> FlextResult[None]:
        """Delete group."""
        # Use client to delete the group entry
        delete_result = await self._client.delete(dn)
        if not delete_result.is_success:
            return FlextResult[None].fail(
                f"Failed to delete group: {delete_result.error}"
            )
        return FlextResult[None].ok(None)

    async def add_member(self, group_dn: str, member_dn: str) -> FlextResult[None]:
        """Add member to group."""
        # Modify the group to add the member
        modifications: dict[str, list[str] | list[bytes] | str | bytes] = {
            "member": [member_dn]
        }
        modify_result = await self._client.modify_entry(group_dn, modifications)
        if not modify_result.is_success:
            return FlextResult[None].fail(
                f"Failed to add member to group: {modify_result.error}"
            )
        return FlextResult[None].ok(None)

    async def remove_member(self, group_dn: str, member_dn: str) -> FlextResult[None]:
        """Remove member from group."""
        # First get the current group to find existing members
        group_result = await self.get_group(group_dn)
        if not group_result.is_success:
            return FlextResult[None].fail(
                f"Failed to get group for member removal: {group_result.error}"
            )

        group = group_result.value
        if not group or member_dn not in group.members:
            return FlextResult[None].fail("Member not found in group")

        # Remove the member from the list
        updated_members = [m for m in group.members if m != member_dn]
        modifications: dict[str, list[str] | list[bytes] | str | bytes] = {
            "member": updated_members
        }

        modify_result = await self._client.modify_entry(group_dn, modifications)
        if not modify_result.is_success:
            return FlextResult[None].fail(
                f"Failed to remove member from group: {modify_result.error}"
            )
        return FlextResult[None].ok(None)

    async def get_members(self, group_dn: str) -> FlextResult[list[str]]:
        """Get group members."""
        # Get the group and return its members
        group_result = await self.get_group(group_dn)
        if not group_result.is_success:
            return FlextResult[list[str]].fail(
                f"Failed to get group: {group_result.error}"
            )

        group = group_result.value
        if not group:
            return FlextResult[list[str]].fail("Group not found")

        return FlextResult[list[str]].ok(group.members or [])

    # Entry Operations

    async def delete_entry(self, dn: str) -> FlextResult[None]:
        """Delete LDAP entry by DN."""
        repository_result = self._container.get("FlextLdapRepositories.Repository")
        if not repository_result.is_success:
            return FlextResult.fail(
                f"Failed to get LDAP repository: {repository_result.error}",
            )
        repository = cast("FlextLdapRepositories", repository_result.value)
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
        return FlextLdapValidations.validate_dn(dn)

    def validate_filter(self, filter_str: str) -> FlextResult[None]:
        """Validate LDAP search filter using centralized validation - SOURCE OF TRUTH."""
        return FlextLdapValidations.validate_filter(filter_str)

    def validate_attributes(
        self,
        attributes: FlextLdapTypes.Entry.AttributeDict,
    ) -> FlextResult[None]:
        """Validate LDAP attributes dictionary."""
        if not attributes:
            return FlextResult.fail("Attributes cannot be empty")

        return FlextResult.ok(None)

    def validate_object_classes(
        self,
        object_classes: list[str],
    ) -> FlextResult[None]:
        """Validate LDAP object classes list."""
        if not object_classes:
            return FlextResult.fail("Object classes cannot be empty")
        return FlextResult.ok(None)

    async def user_exists(self, dn: str) -> FlextResult[bool]:
        """Check if user exists at DN."""
        user_result = await self.get_user(dn)
        if not user_result.is_success:
            return FlextResult.fail(user_result.error or "Failed to get user")

        return FlextResult.ok(user_result.value is not None)

    async def group_exists(self, dn: str) -> FlextResult[bool]:
        """Check if group exists at DN."""
        group_result = await self.get_group(dn)
        if not group_result.is_success:
            return FlextResult.fail(group_result.error or "Failed to get group")

        return FlextResult.ok(group_result.value is not None)

    async def add_member_to_group(
        self, group_dn: str, member_dn: str
    ) -> FlextResult[None]:
        """Add member to group (alternative implementation)."""
        return await self.add_member(group_dn, member_dn)

    async def remove_member_from_group(
        self, group_dn: str, member_dn: str
    ) -> FlextResult[None]:
        """Remove member from group (alternative implementation)."""
        return await self.remove_member(group_dn, member_dn)

    async def get_group_members_list(self, group_dn: str) -> FlextResult[list[str]]:
        """Get group members as list of DNs."""
        members_result = await self.get_members(group_dn)
        if not members_result.is_success:
            return FlextResult.fail(members_result.error or "Failed to get members")

        # Convert to list of DNs
        members = members_result.value or []
        return FlextResult.ok([str(member) for member in members])

    async def initialize(self) -> FlextResult[None]:
        """Initialize service using FlextProcessors logging."""
        self.log_info("LDAP service initializing", service="FlextLdapApi")
        return FlextResult[None].ok(None)

    async def cleanup(self) -> FlextResult[None]:
        """Cleanup service resources."""
        self.log_info("LDAP service cleanup", service="FlextLdapApi")
        return FlextResult[None].ok(None)

    def process(self, request: object) -> FlextResult[object]:
        """Process LDAP request using Python 3.13 pattern matching."""
        # Python 3.13 structural pattern matching for LDAP request dispatch
        match request:
            case {"operation": "user_create", "data": user_data} if isinstance(
                user_data,
                dict,
            ):
                return FlextResult[object].ok(
                    {"status": "user_create_processed", "data": user_data}
                )
            case {"operation": "user_read", "dn": dn} if isinstance(dn, str):
                return FlextResult[object].ok(
                    {"status": "user_read_processed", "dn": dn}
                )
            case {"operation": "group_create", "data": group_data} if isinstance(
                group_data,
                dict,
            ):
                return FlextResult[object].ok(
                    {"status": "group_create_processed", "data": group_data}
                )
            case {"operation": "search", "params": search_params} if isinstance(
                search_params,
                dict,
            ):
                return FlextResult[object].ok(
                    {"status": "search_processed", "params": search_params}
                )
            case {"operation": "validate", "target": str(target), "value": value}:
                return FlextResult[object].ok(
                    {"status": "validate_processed", "target": target, "value": value}
                )
            case _:
                return FlextResult[object].ok(request)

    @classmethod
    def create(cls, config: FlextLdapConfig | None = None) -> FlextLdapApi:
        """Create FlextLdap API instance with dependency injection.

        Factory method following flext-core pattern for consistent API access
        across the FLEXT ecosystem. Uses FlextLdapConfig singleton as single
        source of truth for configuration when no specific config is provided.

        Args:
            config: Optional LDAP configuration. If None, uses FlextLdapConfig singleton.

        Returns:
            FlextLdapApi: Configured API instance ready for LDAP operations.

        Example:
            >>> api = FlextLdapApi.create()
            >>> result = await api.connect(
            ...     FlextLdapConstants.LDAP.DEFAULT_SERVER_URI, "cn=REDACTED_LDAP_BIND_PASSWORD", "password"
            ... )
            >>> if result.is_success:
            ...     session = result.value

        """
        return cls(config)


__all__ = [
    "FlextLdapApi",
]
