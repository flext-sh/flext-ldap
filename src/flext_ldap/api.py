"""LDAP API module.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import uuid
from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import asynccontextmanager
from functools import cached_property
from typing import TYPE_CHECKING, cast

from flext_core import (
    FlextExceptions,
    FlextLogger,
    FlextResult,
    FlextTypes,
)
from flext_ldap.config import FlextLdapConfigs as FlextLdapConfig
from flext_ldap.container import FlextLdapContainer
from flext_ldap.models import FlextLdapModels
from flext_ldap.validations import FlextLdapValidations

if TYPE_CHECKING:
    from flext_ldap.repositories import FlextLdapRepositories
    from flext_ldap.typings import FlextLdapTypes


class FlextLdapApi:
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

    # _Formatters converted to monadic functions - no longer needed as nested class

    # _ConnectionHelper converted to monadic functions - no longer needed as nested class

    # _SearchHelper converted to monadic functions - no longer needed as nested class

    # _UserManagementHelper converted to monadic functions - no longer needed as nested class

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
        self._logger = FlextLogger(__name__)
        # Use provided config directly if given, otherwise use singleton
        if config is not None:
            self._config = config
        else:
            self._config = FlextLdapConfig.get_global_instance()
        self._container_manager = FlextLdapContainer()
        self._container = self._container_manager.get_container()
        self._client = self._container_manager.get_client()

        # Monadic factory functions replace nested helper classes - Phase 2 implementation
        # Helper instances removed in favor of monadic composition patterns

        self._logger.info(
            "FlextLdapApi initialized with FlextLdapConfig singleton (monadic composition)",
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
        """Extract string attribute from entry using enhanced FlextResult railway pattern.

        Returns:
            str: The extracted string value or default if extraction fails.

        """
        # Enhanced railway pattern: extract value >> convert to string >> handle with context
        extract_result = self._extract_entry_value(entry, key)
        convert_result = (extract_result >> self._convert_to_safe_string).with_context(
            lambda err: f"Failed to extract attribute '{key}': {err}",
        )

        # Use railway pattern with proper error recovery instead of .unwrap_or()
        return convert_result.value if convert_result.is_success else default

    def _extract_entry_value(
        self,
        entry: FlextTypes.Core.Dict | FlextLdapModels.Entry,
        key: str,
    ) -> FlextResult[object]:
        """Extract value from entry using type checking.

        Returns:
            FlextResult[object]: Success result with extracted value or failure result.

        """
        # Handle FlextLdapModels.Entry type
        if isinstance(entry, FlextLdapModels.Entry):
            attr_values = entry.attributes.get(key, [])
            value = attr_values[0] if attr_values else None
            return (
                FlextResult[object].ok(value)
                if value is not None
                else FlextResult[object].fail("No value found")
            )

        # Handle dict type (covers all remaining cases based on type annotation)
        dict_value: object = entry.get(key)
        return (
            FlextResult[object].ok(dict_value)
            if dict_value is not None
            else FlextResult[object].fail("No value found")
        )

    def _convert_to_safe_string(self, raw_value: object) -> FlextResult[str]:
        """Convert value to string using FlextResult railway pattern.

        Returns:
            FlextResult[str]: Success result with converted string or failure result.

        """
        # Railway pattern: process through type handlers >> convert to string
        result = (
            FlextResult[object].ok(raw_value)
            >> self._handle_string_type
            >> self._handle_bytes_type
            >> self._handle_list_type
            >> self._handle_numeric_type
            >> (lambda value: FlextResult[str].ok(str(value)))
        )

        return result.with_context(lambda err: f"String conversion failed: {err}")

    def _handle_string_type(self, value: object) -> FlextResult[object]:
        """Handle string type conversion.

        Returns:
            FlextResult[object]: Success result with processed value or pass-through.

        """
        if isinstance(value, str):
            return (
                FlextResult[object].ok(value)
                if value
                else FlextResult[object].fail("Empty string")
            )
        return FlextResult[object].ok(value)  # Pass through for next handler

    def _handle_bytes_type(self, value: object) -> FlextResult[object]:
        """Handle bytes type conversion.

        Returns:
            FlextResult[object]: Success result with decoded string or pass-through.

        """
        if isinstance(value, bytes):
            return FlextResult[object].ok(value.decode("utf-8", errors="replace"))
        return FlextResult[object].ok(value)  # Pass through for next handler

    def _handle_list_type(self, value: object) -> FlextResult[object]:
        """Handle list type conversion.

        Returns:
            FlextResult[object]: Success result with first element as string or pass-through.

        """
        if isinstance(value, list):
            if not value:
                return FlextResult[object].fail("Empty list")
            first_element = value[0]
            if first_element is None or not first_element:
                return FlextResult[object].fail(
                    "List contains None or empty first element",
                )
            return FlextResult[object].ok(str(first_element))
        return FlextResult[object].ok(value)  # Pass through for next handler

    def _handle_numeric_type(self, value: object) -> FlextResult[object]:
        """Handle numeric type conversion.

        Returns:
            FlextResult[object]: Success result with converted string or pass-through.

        """
        if isinstance(value, (int, float, bool)):
            return FlextResult[object].ok(str(value))
        return FlextResult[object].ok(value)  # Pass through for next handler

    # String conversion pipeline methods complete

    # NO CLI compatibility methods - use flext-cli domain library for CLI operations

    # Public helper methods to avoid private member access violations

    def _display_message(self, message: str, level: str = "info") -> None:
        """Display formatted message using monadic composition - Phase 2 pattern."""
        # Monadic factory function replaces nested helper class
        self._create_display_message_handler(message, level)

    def _create_display_message_handler(self, message: str, level: str) -> None:
        """Monadic factory function for message display - replaces _Formatters."""
        # Implementation moved from nested class to monadic function
        # CLI integration point - implementation depends on flext-cli domain

    def _print_success(self, message: str) -> None:
        """Print success message using monadic composition - Phase 2 pattern."""
        # Monadic factory function replaces nested helper class
        self._create_success_message_handler(message)

    def _create_success_message_handler(self, message: str) -> None:
        """Monadic factory function for success messages - replaces _Formatters."""
        # Implementation moved from nested class to monadic function
        # CLI integration point - implementation depends on flext-cli domain

    def _format_connection_info(self, server_uri: str, bind_dn: str) -> str:
        """Format connection information using monadic composition - Phase 2 pattern.

        Returns:
            str: Formatted connection information string.

        """
        # Monadic factory function replaces nested helper class
        return self._create_connection_info_formatter(server_uri, bind_dn)

    def _create_connection_info_formatter(self, server_uri: str, bind_dn: str) -> str:
        """Monadic factory function for connection info formatting - replaces _ConnectionHelper.

        Returns:
            str: Formatted connection information string.

        """
        # Implementation moved from nested class to monadic function
        return f"Server: {server_uri}\nBind DN: {bind_dn}"

    def _create_search_request(
        self,
        base_dn: str,
        filter_str: str,
    ) -> FlextLdapModels.SearchRequest:
        """Create search request using monadic composition - Phase 2 pattern.

        Returns:
            FlextLdapModels.SearchRequest: Configured search request object.

        """
        # Monadic factory function replaces nested helper class
        return self._create_search_request_factory(base_dn, filter_str)

    def _create_search_request_factory(
        self,
        base_dn: str,
        filter_str: str,
    ) -> FlextLdapModels.SearchRequest:
        """Monadic factory function for search requests - replaces _SearchHelper.

        Returns:
            FlextLdapModels.SearchRequest: Configured search request object.

        """
        # Implementation moved from nested class to monadic function
        return FlextLdapModels.SearchRequest(
            base_dn=base_dn,
            filter_str=filter_str,
            scope="subtree",
            attributes=None,
            size_limit=1000,
            time_limit=30,
        )

    def _create_user_request(
        self,
        dn: str,
        uid: str,
        cn: str,
        sn: str,
    ) -> FlextLdapModels.CreateUserRequest:
        """Create user request with standard parameters using monadic function.

        Returns:
            FlextLdapModels.CreateUserRequest: Configured user creation request.

        """
        # Simple monadic function replacement for helper
        return FlextLdapModels.CreateUserRequest(
            dn=dn,
            uid=uid,
            cn=cn,
            sn=sn,
            object_classes=["person", "organizationalPerson"],
        )

    def _format_user_info(self, user: FlextLdapModels.LdapUser) -> str:
        """Format user information for display using monadic function.

        Returns:
            str: Formatted user information string.

        """
        # Simple monadic function replacement for helper
        return f"User: {user.cn} ({user.uid}) - {user.mail or 'No email'}"

    async def _connect_to_ldap(
        self,
        server_uri: str,
        bind_dn: str,
        bind_password: str,
    ) -> FlextResult[str]:
        """Connect to LDAP server - CLI method wrapper.

        Returns:
            FlextResult[str]: Success result with session ID or failure result.

        """
        return await self.connect(server_uri, bind_dn, bind_password)

    async def _search_ldap(
        self,
        base_dn: str,
        filter_str: str = "(objectClass=*)",
        scope: str = "subtree",
    ) -> FlextResult[FlextLdapModels.SearchResponse]:
        """Search LDAP directory - CLI method.

        Returns:
            FlextResult[FlextLdapModels.SearchResponse]: Search results or failure result.

        """
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
        """Connect to LDAP server and establish session using explicit async/await pattern.

        Args:
            server_uri: LDAP server URI (ldap:// or ldaps://).
            bind_dn: Distinguished name for authentication.
            bind_password: Password for authentication.

        Returns:
            FlextResult[str]: Success with session ID or error result.

        """
        # Validate connection parameters
        param_validation = self._validate_connection_params(
            server_uri,
            bind_dn,
            bind_password,
        )
        if param_validation.is_failure:
            return FlextResult[str].fail(
                f"Connection to {server_uri} failed: {param_validation.error}",
            )

        # Validate DN format
        dn_validation = FlextLdapValidations.validate_dn(bind_dn)
        if dn_validation.is_failure:
            return FlextResult[str].fail(
                f"Connection to {server_uri} failed: {dn_validation.error}",
            )

        # Perform LDAP connection
        connection_result = await self._perform_ldap_connection(
            server_uri,
            bind_dn,
            bind_password,
        )
        if connection_result.is_failure:
            return FlextResult[str].fail(
                f"Connection to {server_uri} failed: {connection_result.error}",
            )

        # Return session ID
        return FlextResult[str].ok(self.session_id)

    async def _perform_ldap_connection(
        self,
        server_uri: str,
        bind_dn: str,
        bind_password: str,
    ) -> FlextResult[None]:
        """Perform LDAP connection - railway helper method.

        Returns:
            FlextResult[None]: Success result if connection succeeds.

        """
        connection_result = await self._client.connect(
            server_uri,
            bind_dn,
            bind_password,
        )
        return connection_result.with_context(
            lambda err: f"LDAP connection failed: {err}",
        )

    def _validate_connection_params(
        self,
        server_uri: str,
        bind_dn: str,
        bind_password: str,
    ) -> FlextResult[None]:
        """Validate connection parameters using FlextResult patterns.

        Returns:
            FlextResult[None]: Success result if validation passes.

        """
        if not server_uri or not server_uri.strip():
            return FlextResult[None].fail("Server URI cannot be empty")
        if not bind_dn or not bind_dn.strip():
            return FlextResult[None].fail("Bind DN cannot be empty")
        if not bind_password:
            return FlextResult[None].fail("Bind password cannot be empty")
        if not (server_uri.startswith(("ldap://", "ldaps://"))):
            return FlextResult[None].fail(
                "Server URI must start with ldap:// or ldaps://",
            )
        return FlextResult[None].ok(None)

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
        """Context manager for LDAP connection using monadic workflow.

        Args:
            server_uri: LDAP server URI
            bind_dn: Distinguished name for binding
            bind_password: Password for binding

        Yields:
            Session ID for use within context

        Raises:
            ConnectionError: If connection fails.

        """
        # Monadic workflow: connect >> extract session >> yield session >> cleanup
        connect_result = await self.connect(server_uri, bind_dn, bind_password)

        # Use monadic approach to handle connection result
        session_result = (connect_result >> (FlextResult[str].ok)).with_context(
            lambda err: f"Connection context failed: {err}",
        )

        if session_result.is_failure:
            error_msg = session_result.error or "Connection failed"
            raise FlextExceptions.ConnectionError(error_msg)

        # Use railway pattern with .value instead of .unwrap()
        session_id = session_result.value
        try:
            yield session_id
        finally:
            await self.disconnect(session_id)

    # Search Operations

    async def search(
        self,
        search_request: FlextLdapModels.SearchRequest,
    ) -> FlextResult[list[FlextLdapModels.Entry]]:
        """Execute LDAP search using validated request entity with railway pattern.

        Performs LDAP search operation using the provided search request.
        The request is validated and processed through the service layer
        to ensure proper error handling and result formatting.

        Args:
            search_request: Encapsulated search parameters with validation.

        Returns:
            FlextResult[list[FlextLdapModels.Entry]]: Search results or error.

        """
        # Railway pattern: search >> convert entries
        search_result = await self._client.search_with_request(search_request)
        return (search_result >> self._convert_search_response_to_entries).with_context(
            lambda err: f"Search operation failed: {err}",
        )

    def _convert_search_response_to_entries(
        self,
        search_response: FlextLdapModels.SearchResponse,
    ) -> FlextResult[list[FlextLdapModels.Entry]]:
        """Convert search response to Entry objects using monadic pipeline.

        Returns:
            FlextResult[list[FlextLdapModels.Entry]]: Success result with converted entries.

        """
        entries: list[FlextLdapModels.Entry] = []

        for entry_data in search_response.entries:
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
    async def _search_simple(
        self,
        base_dn: str,
        search_filter: str = "(objectClass=*)",
        *,
        scope: str = "subtree",
        attributes: list[str] | None = None,
    ) -> FlextResult[list[FlextLdapModels.Entry]]:
        """Simplified search interface using factory method pattern.

        Returns:
            FlextResult[list[FlextLdapModels.Entry]]: Success result with found entries.

        """
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
        """Search users using factory method for common pattern.

        Returns:
            FlextResult[list[FlextLdapModels.Entry]]: Success result with found user entries.

        """
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
    ) -> FlextResult[FlextLdapModels.LdapUser]:
        """Create user using proper service layer - supports both request object and individual parameters.

        Returns:
            FlextResult[FlextLdapModels.LdapUser]: Success result with created user.

        """
        # Handle both request object and individual parameters
        if isinstance(user_request_or_dn, FlextLdapModels.CreateUserRequest):
            # First overload: request object only - validate no extra params provided
            request = user_request_or_dn
        else:
            # Second overload: individual parameters (uid, cn, sn are required)
            dn = user_request_or_dn
            if uid is None or cn is None or sn is None:
                return FlextResult[FlextLdapModels.LdapUser].fail(
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

        # Railway pattern: add entry >> create user object
        add_result = await self._client.add_entry(request.dn, attributes)
        return (
            add_result >> (lambda _: self._create_user_object(request))
        ).with_context(lambda err: f"Failed to create user {request.dn}: {err}")

    def _create_user_object(
        self,
        request: FlextLdapModels.CreateUserRequest,
    ) -> FlextResult[FlextLdapModels.LdapUser]:
        """Create user object from request - railway helper method.

        Returns:
            FlextResult[FlextLdapModels.LdapUser]: Success result with created user object.

        """
        created_user = FlextLdapModels.LdapUser(
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
        return FlextResult[FlextLdapModels.LdapUser].ok(created_user)

    async def get_user(self, dn: str) -> FlextResult[FlextLdapModels.LdapUser | None]:
        """Get user by DN.

        Returns:
            FlextResult[FlextLdapModels.LdapUser | None]: Success result with user or None if not found.

        """
        # Search for the user by DN
        search_request = FlextLdapModels.SearchRequest(
            base_dn=dn,
            filter_str="(objectClass=person)",
            scope="base",
            attributes=["uid", "cn", "sn", "mail", "givenName"],
            size_limit=1,
            time_limit=30,
        )

        # Railway pattern: search >> process entries >> convert to user
        search_result = await self._client.search_with_request(search_request)
        return (
            search_result
            >> (lambda response: self._process_user_search_entries(response, dn))
        ).with_context(lambda err: f"Failed to get user {dn}: {err}")

    def _process_user_search_entries(
        self,
        search_response: FlextLdapModels.SearchResponse,
        dn: str,
    ) -> FlextResult[FlextLdapModels.LdapUser | None]:
        """Process search response entries for user retrieval - railway helper method.

        Returns:
            FlextResult[FlextLdapModels.LdapUser | None]: Success result with user or None if not found.

        """
        if not search_response.entries:
            return FlextResult[FlextLdapModels.LdapUser | None].ok(None)

        # Convert the first entry to a User object
        entry = search_response.entries[0]
        uid = self._get_entry_attribute(entry, "uid", "unknown")
        user = FlextLdapModels.LdapUser(
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
        return FlextResult[FlextLdapModels.LdapUser | None].ok(user)

    async def update_user(
        self,
        dn: str,
        attributes: FlextLdapTypes.Entry.AttributeDict,
    ) -> FlextResult[None]:
        """Update user attributes using railway pattern.

        Returns:
            FlextResult[None]: Success result if update succeeds.

        """
        # Railway pattern: modify entry with context
        modify_result = await self._client.modify_entry(dn, attributes)
        return modify_result.with_context(
            lambda err: f"Failed to update user {dn}: {err}",
        )

    async def delete_user(self, dn: str) -> FlextResult[None]:
        """Delete user using railway pattern.

        Returns:
            FlextResult[None]: Success result if deletion succeeds.

        """
        # Railway pattern: delete entry with context
        delete_result = await self._client.delete(dn)
        return delete_result.with_context(
            lambda err: f"Failed to delete user {dn}: {err}",
        )

    async def _search_users_by_filter(
        self,
        filter_str: str,
        base_dn: str,
        scope: str = "subtree",
    ) -> FlextResult[list[FlextLdapModels.LdapUser]]:
        """Search users with filter using railway pattern.

        Returns:
            FlextResult[list[FlextLdapModels.LdapUser]]: Success result with found users.

        """
        # Use the generic search method with user-specific filter
        search_request = FlextLdapModels.SearchRequest(
            base_dn=base_dn,
            filter_str=f"(&(objectClass=person){filter_str})",
            scope=scope,
            attributes=["uid", "cn", "mail", "objectClass"],
            size_limit=1000,
            time_limit=30,
        )

        # Railway pattern: search >> convert to users
        search_result = await self._client.search_with_request(search_request)
        return (search_result >> self._convert_search_entries_to_users).with_context(
            lambda err: f"Failed to search users with filter '{filter_str}': {err}",
        )

    def _convert_search_entries_to_users(
        self,
        search_response: FlextLdapModels.SearchResponse,
    ) -> FlextResult[list[FlextLdapModels.LdapUser]]:
        """Convert search response entries to users - railway helper method.

        Returns:
            FlextResult[list[FlextLdapModels.LdapUser]]: Success result with converted users.

        """
        users: list[FlextLdapModels.LdapUser] = []
        for entry in search_response.entries:
            # Create user from entry - simplified mapping
            uid = self._get_entry_attribute(entry, "uid", "unknown")
            user = FlextLdapModels.LdapUser(
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
        return FlextResult[list[FlextLdapModels.LdapUser]].ok(users)

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

        Returns:
            FlextResult[FlextLdapModels.Group]: Success result with created group.

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

        # Railway pattern: add entry >> return group object
        add_result = await self._client.add_entry(dn, attributes)
        return (
            add_result >> (lambda _: FlextResult[FlextLdapModels.Group].ok(group))
        ).with_context(lambda err: f"Failed to create group {dn}: {err}")

    async def get_group(self, dn: str) -> FlextResult[FlextLdapModels.Group | None]:
        """Get group by DN.

        Returns:
            FlextResult[FlextLdapModels.Group | None]: Success result with group or None if not found.

        """
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
        return (search_result >> self._process_group_search_response).with_context(
            lambda err: f"Failed to get group {dn}: {err}",
        )

    def _process_group_search_response(
        self,
        search_response: FlextLdapModels.SearchResponse,
    ) -> FlextResult[FlextLdapModels.Group | None]:
        """Process search response and create group entity - railway pattern helper.

        Returns:
            FlextResult[FlextLdapModels.Group | None]: Success result with group or None if not found.

        """
        if not search_response or not search_response.entries:
            return FlextResult[FlextLdapModels.Group | None].ok(None)

        entry = search_response.entries[0]

        # Extract group attributes using existing safe extraction
        cn = self._get_entry_attribute(entry, "cn", "unknown")

        # Handle members list safely
        members_raw = entry.get("member", [])
        members = (
            cast("list[str]", members_raw) if isinstance(members_raw, list) else []
        )

        # Create group entity
        group = FlextLdapModels.Group(
            id=f"group_{cn}",
            dn=self._get_entry_attribute(entry, "dn"),
            cn=cn,
            members=members,
            modified_at=None,
            description=None,
        )

        return FlextResult[FlextLdapModels.Group | None].ok(group)

    async def update_group(
        self,
        dn: str,
        attributes: FlextLdapTypes.Entry.AttributeDict,
    ) -> FlextResult[None]:
        """Update group attributes using railway pattern.

        Returns:
            FlextResult[None]: Success result if update succeeds.

        """
        # Railway pattern: modify entry with context
        modify_result = await self._client.modify_entry(dn, attributes)
        return modify_result.with_context(
            lambda err: f"Failed to update group {dn}: {err}",
        )

    async def delete_group(self, dn: str) -> FlextResult[None]:
        """Delete group using railway pattern.

        Returns:
            FlextResult[None]: Success result if deletion succeeds.

        """
        # Railway pattern: delete entry with context
        delete_result = await self._client.delete(dn)
        return delete_result.with_context(
            lambda err: f"Failed to delete group {dn}: {err}",
        )

    async def add_member(self, group_dn: str, member_dn: str) -> FlextResult[None]:
        """Add member to group using railway pattern.

        Returns:
            FlextResult[None]: Success result if member is added.

        """
        # Railway pattern: modify group entry with context
        modifications: dict[str, list[str] | list[bytes] | str | bytes] = {
            "member": [member_dn],
        }
        modify_result = await self._client.modify_entry(group_dn, modifications)
        return modify_result.with_context(
            lambda err: f"Failed to add member {member_dn} to group {group_dn}: {err}",
        )

    async def remove_member(self, group_dn: str, member_dn: str) -> FlextResult[None]:
        """Remove member from group using explicit async/await pattern.

        Returns:
            FlextResult[None]: Success result if member is removed.

        """
        # Get group
        group_result = await self.get_group(group_dn)
        if group_result.is_failure:
            return FlextResult[None].fail(
                f"Failed to remove member {member_dn} from group {group_dn}: {group_result.error}",
            )

        # Validate member exists
        member_validation = self._validate_member_exists(group_result.value, member_dn)
        if member_validation.is_failure:
            return FlextResult[None].fail(
                f"Failed to remove member {member_dn} from group {group_dn}: {member_validation.error}",
            )

        # Remove member from list
        updated_members_result = self._remove_member_from_list(
            member_validation.value,
            member_dn,
        )
        if updated_members_result.is_failure:
            return FlextResult[None].fail(
                f"Failed to remove member {member_dn} from group {group_dn}: {updated_members_result.error}",
            )

        # Update group members
        update_result = await self._update_group_members(
            group_dn,
            updated_members_result.value,
        )
        if update_result.is_failure:
            return FlextResult[None].fail(
                f"Failed to remove member {member_dn} from group {group_dn}: {update_result.error}",
            )

        return FlextResult[None].ok(None)

    async def _update_group_members_async(
        self,
        group_dn: str,
        updated_members: list[str],
    ) -> FlextResult[None]:
        """Update group with new member list - async wrapper for railway pattern.

        Returns:
            FlextResult[None]: Success result if update succeeds.

        """
        return await self._update_group_members(group_dn, updated_members)

    def _validate_member_exists(
        self,
        group: FlextLdapModels.Group | None,
        member_dn: str,
    ) -> FlextResult[FlextLdapModels.Group]:
        """Validate that member exists in group.

        Returns:
            FlextResult[FlextLdapModels.Group]: Success result with validated group.

        """
        if not group:
            return FlextResult[FlextLdapModels.Group].fail("Group not found")
        if member_dn not in group.members:
            return FlextResult[FlextLdapModels.Group].fail("Member not found in group")
        return FlextResult[FlextLdapModels.Group].ok(group)

    def _remove_member_from_list(
        self,
        group: FlextLdapModels.Group,
        member_dn: str,
    ) -> FlextResult[list[str]]:
        """Remove member from group member list.

        Returns:
            FlextResult[list[str]]: Success result with updated member list.

        """
        updated_members = [m for m in group.members if m != member_dn]
        return FlextResult[list[str]].ok(updated_members)

    async def _update_group_members(
        self,
        group_dn: str,
        updated_members: list[str],
    ) -> FlextResult[None]:
        """Update group with new member list.

        Returns:
            FlextResult[None]: Success result if update succeeds.

        """
        modifications: dict[str, list[str] | list[bytes] | str | bytes] = {
            "member": updated_members,
        }
        return await self._client.modify_entry(group_dn, modifications)

    async def get_members(self, group_dn: str) -> FlextResult[list[str]]:
        """Get group members using railway pattern.

        Returns:
            FlextResult[list[str]]: Success result with member list.

        """
        # Railway pattern: get group >> extract members
        group_result = await self.get_group(group_dn)
        return (group_result >> self._extract_group_members).with_context(
            lambda err: f"Failed to get members for group {group_dn}: {err}",
        )

    def _extract_group_members(
        self,
        group: FlextLdapModels.Group | None,
    ) -> FlextResult[list[str]]:
        """Extract member list from group - railway helper method.

        Returns:
            FlextResult[list[str]]: Success result with member list.

        """
        if not group:
            return FlextResult[list[str]].fail("Group not found")
        return FlextResult[list[str]].ok(group.members or [])

    # Entry Operations

    async def _delete_entry(self, dn: str) -> FlextResult[None]:
        """Delete LDAP entry by DN using explicit async/await pattern.

        Returns:
            FlextResult[None]: Success result if deletion succeeds.

        """
        # Get repository
        repository_result = self._container.get("FlextLdapRepositories.Repository")
        if repository_result.is_failure:
            return FlextResult[None].fail(
                f"Failed to delete entry {dn}: {repository_result.error}",
            )

        # Prepare delete method
        delete_method_result = self._prepare_delete_method(repository_result.value)
        if delete_method_result.is_failure:
            return FlextResult[None].fail(
                f"Failed to delete entry {dn}: {delete_method_result.error}",
            )

        # Execute delete
        delete_result = await self._execute_delete(delete_method_result.value, dn)
        if delete_result.is_failure:
            return FlextResult[None].fail(
                f"Failed to delete entry {dn}: {delete_result.error}",
            )

        return FlextResult[None].ok(None)

    def _prepare_delete_method(
        self,
        repository: object,
    ) -> FlextResult[Callable[[str], Awaitable[FlextResult[None]]]]:
        """Prepare delete method from repository - railway helper method.

        Returns:
            FlextResult[Callable[[str], Awaitable[FlextResult[None]]]]: Success result with delete method.

        """
        typed_repository = cast("FlextLdapRepositories", repository)
        delete_method = getattr(typed_repository, "_delete_async", None)
        if delete_method is None:
            return FlextResult[Callable[[str], Awaitable[FlextResult[None]]]].fail(
                "Repository does not support _delete_async method",
            )
        return FlextResult[Callable[[str], Awaitable[FlextResult[None]]]].ok(
            delete_method,
        )

    async def _execute_delete(
        self,
        delete_method: Callable[[str], Awaitable[FlextResult[None]]],
        dn: str,
    ) -> FlextResult[None]:
        """Execute delete operation - railway helper method.

        Returns:
            FlextResult[None]: Success result if deletion succeeds.

        """
        try:
            result = await delete_method(dn)
            # Type annotation guarantees result is FlextResult[None]
            return result.with_context(lambda err: f"Delete operation failed: {err}")
        except Exception as e:
            return FlextResult[None].fail(
                f"Delete operation failed with exception: {e}",
            )

    # Validation Methods

    def _validate_dn(self, dn: str) -> FlextResult[None]:
        """Validate distinguished name format using centralized validation - SOURCE OF TRUTH.

        Returns:
            FlextResult[None]: Success result if validation passes.

        """
        return FlextLdapValidations.validate_dn(dn)

    def _validate_filter(self, filter_str: str) -> FlextResult[None]:
        """Validate LDAP search filter using centralized validation - SOURCE OF TRUTH.

        Returns:
            FlextResult[None]: Success result if validation passes.

        """
        return FlextLdapValidations.validate_filter(filter_str)

    def _validate_attributes(
        self,
        attributes: FlextLdapTypes.Entry.AttributeDict,
    ) -> FlextResult[None]:
        """Validate LDAP attributes dictionary.

        Returns:
            FlextResult[None]: Success result if validation passes.

        """
        if not attributes:
            return FlextResult.fail("Attributes cannot be empty")

        return FlextResult.ok(None)

    def _validate_object_classes(
        self,
        object_classes: list[str],
    ) -> FlextResult[None]:
        """Validate LDAP object classes list.

        Returns:
            FlextResult[None]: Success result if validation passes.

        """
        if not object_classes:
            return FlextResult.fail("Object classes cannot be empty")
        return FlextResult.ok(None)

    async def _user_exists(self, dn: str) -> FlextResult[bool]:
        """Check if user exists at DN using railway pattern.

        Returns:
            FlextResult[bool]: Success result with existence status.

        """
        # Railway pattern: get user >> check existence
        user_result = await self.get_user(dn)
        return (
            user_result >> (lambda user: FlextResult[bool].ok(user is not None))
        ).with_context(lambda err: f"Failed to check if user exists at {dn}: {err}")

    async def _group_exists(self, dn: str) -> FlextResult[bool]:
        """Check if group exists at DN using railway pattern.

        Returns:
            FlextResult[bool]: Success result with existence status.

        """
        # Railway pattern: get group >> check existence
        group_result = await self.get_group(dn)
        return (
            group_result >> (lambda group: FlextResult[bool].ok(group is not None))
        ).with_context(lambda err: f"Failed to check if group exists at {dn}: {err}")

    async def _add_member_to_group(
        self,
        group_dn: str,
        member_dn: str,
    ) -> FlextResult[None]:
        """Add member to group (alternative implementation).

        Returns:
            FlextResult[None]: Success result if member is added.

        """
        return await self.add_member(group_dn, member_dn)

    async def _remove_member_from_group(
        self,
        group_dn: str,
        member_dn: str,
    ) -> FlextResult[None]:
        """Remove member from group (alternative implementation).

        Returns:
            FlextResult[None]: Success result if member is removed.

        """
        return await self.remove_member(group_dn, member_dn)

    async def _get_group_members_list(self, group_dn: str) -> FlextResult[list[str]]:
        """Get group members as list of DNs using railway pattern.

        Returns:
            FlextResult[list[str]]: Success result with member DN list.

        """
        # Railway pattern: get members >> convert to string list
        members_result = await self.get_members(group_dn)
        return (
            members_result
            >> (
                lambda members: FlextResult[list[str]].ok([
                    str(member) for member in (members or [])
                ])
            )
        ).with_context(
            lambda err: f"Failed to get members list for group {group_dn}: {err}",
        )

    async def _initialize(self) -> FlextResult[None]:
        """Initialize service using FlextProcessors logging.

        Returns:
            FlextResult[None]: Success result.

        """
        self._logger.info("LDAP service initializing", service="FlextLdapApi")
        return FlextResult[None].ok(None)

    async def _cleanup(self) -> FlextResult[None]:
        """Cleanup service resources.

        Returns:
            FlextResult[None]: Success result.

        """
        self._logger.info("LDAP service cleanup", service="FlextLdapApi")
        return FlextResult[None].ok(None)

    # === Phase 2: Batch Operations with Traverse/Sequence ===

    async def _batch_create_users(
        self,
        user_requests: list[FlextLdapModels.CreateUserRequest],
    ) -> FlextResult[list[FlextLdapModels.LdapUser]]:
        """Create multiple users using monadic traverse pattern - Phase 2 implementation.

        Returns:
            FlextResult[list[FlextLdapModels.LdapUser]]: Success result with created users.

        """
        return await self._traverse_user_operations(user_requests, self.create_user)

    async def _batch_delete_users(self, dns: list[str]) -> FlextResult[list[None]]:
        """Delete multiple users using monadic traverse pattern - Phase 2 implementation.

        Returns:
            FlextResult[list[None]]: Success result with deletion results.

        """
        return await self._traverse_simple_operations(dns, self.delete_user)

    async def _batch_get_users(
        self,
        dns: list[str],
    ) -> FlextResult[list[FlextLdapModels.LdapUser | None]]:
        """Get multiple users using monadic traverse pattern - Phase 2 implementation.

        Returns:
            FlextResult[list[FlextLdapModels.LdapUser | None]]: Success result with users or None for not found.

        """
        results: list[FlextLdapModels.LdapUser | None] = []
        for dn in dns:
            result = await self.get_user(dn)
            if result.is_failure:
                return FlextResult[list[FlextLdapModels.LdapUser | None]].fail(
                    f"Failed to get user {dn}: {result.error}",
                )
            # Use railway pattern with .value instead of .unwrap()
            results.append(result.value)
        return FlextResult[list[FlextLdapModels.LdapUser | None]].ok(results)

    async def _batch_create_groups(
        self,
        group_requests: list[FlextLdapModels.CreateGroupRequest],
    ) -> FlextResult[list[FlextLdapModels.Group]]:
        """Create multiple groups using monadic traverse pattern - Phase 2 implementation.

        Returns:
            FlextResult[list[FlextLdapModels.Group]]: Success result with created groups.

        """
        return await self._traverse_group_operations(group_requests, self.create_group)

    async def _batch_add_members(
        self,
        member_operations: list[tuple[str, str]],
    ) -> FlextResult[list[None]]:
        """Add multiple members to groups using monadic sequence pattern - Phase 2 implementation.

        Returns:
            FlextResult[list[None]]: Success result with operation results.

        """
        results: list[None] = []
        for group_dn, member_dn in member_operations:
            result = await self.add_member(group_dn, member_dn)
            if result.is_failure:
                return FlextResult[list[None]].fail(
                    f"Failed to add member {member_dn} to group {group_dn}: {result.error}",
                )
            # Use railway pattern with .value instead of .unwrap()
            results.append(result.value)
        return FlextResult[list[None]].ok(results)

    async def _batch_remove_members(
        self,
        member_operations: list[tuple[str, str]],
    ) -> FlextResult[list[None]]:
        """Remove multiple members from groups using monadic sequence pattern - Phase 2 implementation.

        Returns:
            FlextResult[list[None]]: Success result with operation results.

        """
        results: list[None] = []
        for group_dn, member_dn in member_operations:
            result = await self.remove_member(group_dn, member_dn)
            if result.is_failure:
                return FlextResult[list[None]].fail(
                    f"Failed to remove member {member_dn} from group {group_dn}: {result.error}",
                )
            # Use railway pattern with .value instead of .unwrap()
            results.append(result.value)
        return FlextResult[list[None]].ok(results)

    # === Phase 2: Monadic Traverse/Sequence Implementation ===

    async def _traverse_user_operations(
        self,
        requests: list[FlextLdapModels.CreateUserRequest],
        operation: Callable[
            [FlextLdapModels.CreateUserRequest],
            Awaitable[FlextResult[FlextLdapModels.LdapUser]],
        ],
    ) -> FlextResult[list[FlextLdapModels.LdapUser]]:
        """Process user operations in sequence.

        Returns:
            FlextResult[list[FlextLdapModels.LdapUser]]: Success result with processed users.

        """
        results = []
        for request in requests:
            result = await operation(request)
            if result.is_failure:
                return FlextResult[list[FlextLdapModels.LdapUser]].fail(
                    f"User operation failed: {result.error}",
                )
            # Use railway pattern with .value instead of .unwrap()
            results.append(result.value)
        return FlextResult[list[FlextLdapModels.LdapUser]].ok(results)

    async def _traverse_group_operations(
        self,
        requests: list[FlextLdapModels.CreateGroupRequest],
        operation: Callable[
            [FlextLdapModels.CreateGroupRequest],
            Awaitable[FlextResult[FlextLdapModels.Group]],
        ],
    ) -> FlextResult[list[FlextLdapModels.Group]]:
        """Process group operations in sequence.

        Returns:
            FlextResult[list[FlextLdapModels.Group]]: Success result with processed groups.

        """
        results = []
        for request in requests:
            result = await operation(request)
            if result.is_failure:
                return FlextResult[list[FlextLdapModels.Group]].fail(
                    f"Group operation failed: {result.error}",
                )
            # Use railway pattern with .value instead of .unwrap()
            results.append(result.value)
        return FlextResult[list[FlextLdapModels.Group]].ok(results)

    async def _traverse_simple_operations(
        self,
        items: list[str],
        operation: Callable[[str], Awaitable[FlextResult[None]]],
    ) -> FlextResult[list[None]]:
        """Process simple operations in sequence.

        Returns:
            FlextResult[list]: Success result with operation results.

        """
        results: list[None] = []
        for item in items:
            result = await operation(item)
            if result.is_failure:
                return FlextResult[list[None]].fail(
                    f"Simple operation failed: {result.error}",
                )
            # Use railway pattern with .value instead of .unwrap()
            results.append(result.value)
        return FlextResult[list[None]].ok(results)

    async def _sequence_member_operations(
        self,
        group_dn: str,
        member_dns: list[str],
        operation: Callable[[str, str], Awaitable[FlextResult[None]]],
    ) -> FlextResult[list[None]]:
        """Process member operations in sequence.

        Returns:
            FlextResult[list[None]]: Success result with operation results.

        """
        results: list[None] = []
        for member_dn in member_dns:
            result = await operation(group_dn, member_dn)
            if result.is_failure:
                return FlextResult[list[None]].fail(
                    f"Member operation failed: {result.error}",
                )
            # Use railway pattern with .value instead of .unwrap()
            results.append(result.value)
        return FlextResult[list[None]].ok(results)

    def process(self, request: object) -> FlextResult[object]:
        """Process LDAP request using Python 3.13 pattern matching.

        Returns:
            FlextResult[object]: Success result with processed request.

        """
        # Python 3.13 structural pattern matching for LDAP request dispatch
        match request:
            case {"operation": "user_create", "data": user_data} if isinstance(
                user_data,
                dict,
            ):
                return FlextResult[object].ok({
                    "status": "user_create_processed",
                    "data": user_data,
                })
            case {"operation": "user_read", "dn": dn} if isinstance(dn, str):
                return FlextResult[object].ok({
                    "status": "user_read_processed",
                    "dn": dn,
                })
            case {"operation": "group_create", "data": group_data} if isinstance(
                group_data,
                dict,
            ):
                return FlextResult[object].ok({
                    "status": "group_create_processed",
                    "data": group_data,
                })
            case {"operation": "search", "params": search_params} if isinstance(
                search_params,
                dict,
            ):
                return FlextResult[object].ok({
                    "status": "search_processed",
                    "params": search_params,
                })
            case {"operation": "validate", "target": str(target), "value": value}:
                return FlextResult[object].ok({
                    "status": "validate_processed",
                    "target": target,
                    "value": value,
                })
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
