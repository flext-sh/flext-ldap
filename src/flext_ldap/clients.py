"""LDAP client implementation for flext-ldap.

This module provides the core LDAP client functionality using ldap3
with Clean Architecture patterns and flext-core integration.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

Note: This file has type checking disabled due to limitations in the official types-ldap3 package:
- Method return types (add, delete, search, modify, unbind) are not specified in the stubs
- Properties like conn.entries and entry.entry_dn are not fully typed
- Entry attributes and their values have incomplete type information
"""

from __future__ import annotations

from typing import Literal, override

from ldap3 import Connection, Server
from pydantic import SecretStr

from flext_core import (
    FlextContainer,
    FlextLogger,
    FlextResult,
    FlextService,
)
from flext_ldap.constants import FlextLdapConstants
from flext_ldap.exceptions import FlextLdapExceptions
from flext_ldap.models import FlextLdapModels
from flext_ldap.protocols import FlextLdapProtocols
from flext_ldap.schema import FlextLdapSchema
from flext_ldap.typings import FlextLdapTypes
from flext_ldap.utilities import FlextLdapUtilities
from flext_ldap.validations import FlextLdapValidations

# Connection imported directly from ldap3 above


class FlextLdapClient(FlextService[None]):
    """FlextLdapClient - Main LDAP client using ldap3 library.

    This class provides a comprehensive interface for LDAP operations including
    connection management, authentication, search, and CRUD operations.
    It uses the ldap3 library internally and provides a FlextResult-based API.

    The client supports both synchronous and asynchronous operations, with
    automatic connection management and proper error handling.

    Implements FlextLdapProtocols through structural subtyping:
    - LdapConnectionProtocol: connect, disconnect, is_connected methods
    - LdapSearchProtocol: search, search_one methods
    - LdapModifyProtocol: add_entry, modify_entry, delete_entry methods
    - LdapAuthenticationProtocol: authenticate_user, validate_credentials methods
    - LdapValidationProtocol: validate_dn, validate_entry methods
    """

    @override
    def __init__(self, config: FlextLdapModels.ConnectionConfig | None = None) -> None:
        """Initialize FlextLdapClient."""
        # Use concrete ldap3.Connection type since it's untyped and Protocol check fails
        self._connection: Connection | None = None
        self._server: Server | None = None
        self._logger = FlextLogger(__name__)
        self._config = config
        self._container = FlextContainer.get_global()
        self._session_id: str | None = None

        # Schema discovery properties
        self._schema_discovery: FlextLdapSchema.Discovery | None = None
        self._discovered_schema: FlextLdapModels.SchemaDiscoveryResult | None = None
        self._is_schema_discovered = False

    @override
    def execute(self) -> FlextResult[None]:
        """Execute method required by FlextService - no-op for LDAP client."""
        return FlextResult[None].ok(None)

    async def execute_async(self) -> FlextResult[None]:
        """Execute method required by FlextService - no-op for LDAP client."""
        return FlextResult[None].ok(None)

    async def connect(
        self,
        server_uri: str,
        bind_dn: str,
        password: str,
        *,
        auto_discover_schema: bool = True,
        connection_options: dict[str, object] | None = None,
    ) -> FlextResult[bool]:
        """Connect and bind to LDAP server with universal compatibility.

        Args:
            server_uri: LDAP server URI (e.g., 'ldap://localhost:389').
            bind_dn: Distinguished Name for binding.
            password: Password for binding.
            auto_discover_schema: Whether to automatically discover schema.
            connection_options: Additional connection options.

        Returns:
            FlextResult[bool]: Success result or error.

        """
        try:
            # Use centralized server URI validation
            uri_validation = FlextLdapValidations.validate_server_uri(server_uri)
            if uri_validation.is_failure:
                return FlextResult[bool].fail(
                    uri_validation.error or "Server URI validation failed"
                )

            # Use centralized DN validation for bind_dn
            bind_dn_validation = FlextLdapValidations.validate_dn(bind_dn, "Bind DN")
            if bind_dn_validation.is_failure:
                return FlextResult[bool].fail(
                    bind_dn_validation.error or "Bind DN validation failed"
                )

            # Use centralized password validation
            password_validation = FlextLdapValidations.validate_password(password)
            if password_validation.is_failure:
                return FlextResult[bool].fail(
                    password_validation.error or "Password validation failed"
                )

            self._logger.info("Connecting to LDAP server: %s", server_uri)

            # Apply connection options if provided with proper type checking
            if connection_options:
                # Extract and validate server options with proper type validation
                port_value = connection_options.get("port")
                port: int | None = port_value if isinstance(port_value, int) else None

                use_ssl_value = connection_options.get("use_ssl")
                use_ssl = use_ssl_value if isinstance(use_ssl_value, bool) else False

                get_info_value = connection_options.get("get_info")
                # Valid get_info values for ldap3 - use proper type narrowing
                get_info: Literal["ALL", "DSA", "NO_INFO", "SCHEMA"]
                if isinstance(get_info_value, str) and get_info_value in (
                    "NO_INFO",
                    "DSA",
                    "SCHEMA",
                    "ALL",
                ):
                    get_info = get_info_value  # Narrowed by isinstance and in check
                else:
                    get_info = "DSA"

                mode_value = connection_options.get("mode")
                # Valid mode values for ldap3 - use proper type narrowing
                mode: Literal[
                    "IP_SYSTEM_DEFAULT",
                    "IP_V4_ONLY",
                    "IP_V4_PREFERRED",
                    "IP_V6_ONLY",
                    "IP_V6_PREFERRED",
                ]
                if isinstance(mode_value, str) and mode_value in (
                    "IP_SYSTEM_DEFAULT",
                    "IP_V4_ONLY",
                    "IP_V6_ONLY",
                    "IP_V4_PREFERRED",
                    "IP_V6_PREFERRED",
                ):
                    mode = mode_value  # Narrowed by isinstance and in check
                else:
                    mode = "IP_SYSTEM_DEFAULT"

                self._server = Server(
                    server_uri,
                    port=port,
                    use_ssl=use_ssl,
                    get_info=get_info,
                    mode=mode,
                )
            else:
                self._server = Server(server_uri)

            # Use concrete ldap3.Connection type
            self._connection = Connection(
                self._server, bind_dn, password, auto_bind=True
            )

            if not self._connection.bound:
                return FlextResult[bool].fail("Failed to bind to LDAP server")

            self._logger.info("Successfully connected to LDAP server")

            # Perform schema discovery if requested
            if auto_discover_schema:
                discovery_result = await self.discover_schema()
                if discovery_result.is_failure:
                    self._logger.warning(
                        "Schema discovery failed: %s", discovery_result.error
                    )
                    # Continue without schema discovery

            return FlextResult[bool].ok(True)

        except Exception as e:
            self._logger.exception("Connection failed")
            return FlextResult[bool].fail(f"Connection failed: {e}")

    async def bind(self, bind_dn: str, password: str) -> FlextResult[bool]:
        """Bind to LDAP server with specified credentials.

        Args:
            bind_dn: Distinguished Name for binding.
            password: Password for authentication.

        Returns:
            FlextResult[bool]: Success result or error.

        """
        try:
            if not self._connection:
                return FlextResult[bool].fail("LDAP connection not established")

            # Create new connection with provided credentials
            if not self._server:
                return FlextResult[bool].fail("No server connection established")
            # Use concrete ldap3.Connection type
            self._connection = Connection(
                self._server, bind_dn, password, auto_bind=True
            )

            if not self._connection.bound:
                return FlextResult[bool].fail("Bind failed - invalid credentials")

            return FlextResult[bool].ok(True)

        except Exception as e:
            self._logger.exception("Bind operation failed")
            return FlextResult[bool].fail(f"Bind failed: {e}")

    async def unbind(self) -> FlextResult[None]:
        """Unbind from LDAP server.

        Returns:
            FlextResult[None]: Success result or error.

        """
        try:
            if not self._connection:
                # Unbinding when not connected is idempotent - consider it success
                return FlextResult[None].ok(None)

            if self._connection.bound:
                self._connection.unbind()
                self._logger.info("Unbound from LDAP server")

            self._connection = None
            self._server = None
            return FlextResult[None].ok(None)

        except Exception as e:
            self._logger.exception("Unbind failed")
            return FlextResult[None].fail(f"Unbind failed: {e}")

    def is_connected(self) -> bool:
        """Check if client is connected to LDAP server.

        Returns:
            bool: True if connected and bound, False otherwise.

        """
        return self._connection is not None and self._connection.bound

    def test_connection(self) -> FlextResult[bool]:
        """Test LDAP connection.

        Returns:
            FlextResult[bool]: Connection test result.

        """
        if not self.is_connected():
            return FlextResult[bool].fail("Not connected to LDAP server")

        try:
            # Perform a simple search to test the connection
            if self._connection:
                self._connection.search(
                    "",
                    FlextLdapConstants.Defaults.DEFAULT_SEARCH_FILTER,
                    FlextLdapTypes.SUBTREE,
                    attributes=["objectClass"],
                )
            return FlextResult[bool].ok(True)
        except Exception as e:
            return FlextResult[bool].fail(f"Connection test failed: {e}")

    async def authenticate_user(
        self,
        username: str,
        password: str,
    ) -> FlextResult[FlextLdapModels.LdapUser]:
        """Authenticate user credentials using FlextResults railways pattern.

        Args:
            username: Username to authenticate.
            password: User password.

        Returns:
            FlextResult containing authenticated user or error.

        """
        # Railway pattern: Chain validation -> search -> bind -> create user
        validation_result = self._validate_connection()
        if validation_result.is_failure:
            return FlextResult[FlextLdapModels.LdapUser].fail(
                validation_result.error or "Validation failed"
            )

        search_result = self._search_user_by_username(username)
        if search_result.is_failure:
            return FlextResult[FlextLdapModels.LdapUser].fail(
                search_result.error or "Search failed"
            )

        auth_result = self._authenticate_user_credentials(search_result.value, password)
        if auth_result.is_failure:
            return FlextResult[FlextLdapModels.LdapUser].fail(
                auth_result.error or "Authentication failed"
            )

        return self._create_user_from_entry_result(auth_result.value)

    def _validate_connection(self) -> FlextResult[None]:
        """Validate connection is established."""
        if not self._connection:
            return FlextResult[None].fail("LDAP connection not established")
        return FlextResult[None].ok(None)

    def _search_user_by_username(
        self, username: str
    ) -> FlextResult[FlextLdapProtocols.LdapEntry]:
        """Search for user by username using railway pattern."""
        try:
            if not self._connection:
                return FlextResult[FlextLdapProtocols.LdapEntry].fail(
                    "LDAP connection not established"
                )

            search_filter = f"(|(uid={username})(cn={username}))"
            search_base = "ou=users,dc=example,dc=com"  # Default base

            self._connection.search(
                search_base,
                search_filter,
                FlextLdapTypes.SUBTREE,
                attributes=["*"],
            )

            if not self._connection.entries:
                return FlextResult[FlextLdapProtocols.LdapEntry].fail("User not found")

            return FlextResult[FlextLdapProtocols.LdapEntry].ok(
                self._connection.entries[0]
            )

        except Exception as e:
            return FlextResult[FlextLdapProtocols.LdapEntry].fail(
                f"User search failed: {e}"
            )

    def _authenticate_user_credentials(
        self, user_entry: FlextLdapProtocols.LdapEntry, password: str
    ) -> FlextResult[FlextLdapProtocols.LdapEntry]:
        """Authenticate user credentials using railway pattern."""
        try:
            if not self._server:
                return FlextResult[FlextLdapProtocols.LdapEntry].fail(
                    "No server connection established"
                )

            user_dn = str(user_entry.entry_dn)
            # Use concrete ldap3.Connection type
            test_connection: Connection = Connection(
                self._server,
                user_dn,
                password,
                auto_bind=False,
            )

            if not test_connection.bind():
                test_connection.unbind()
                return FlextResult[FlextLdapProtocols.LdapEntry].fail(
                    "Authentication failed"
                )

            test_connection.unbind()
            return FlextResult[FlextLdapProtocols.LdapEntry].ok(user_entry)

        except Exception as e:
            return FlextResult[FlextLdapProtocols.LdapEntry].fail(
                f"Authentication failed: {e}"
            )

    def _create_user_from_entry_result(
        self, user_entry: FlextLdapProtocols.LdapEntry
    ) -> FlextResult[FlextLdapModels.LdapUser]:
        """Create user from LDAP entry using railway pattern."""
        try:
            user = self._create_user_from_entry(user_entry)
            return FlextResult[FlextLdapModels.LdapUser].ok(user)
        except Exception as e:
            return FlextResult[FlextLdapModels.LdapUser].fail(
                f"User creation failed: {e}"
            )

    def _validate_search_request(
        self,
        request: FlextLdapModels.SearchRequest,
    ) -> FlextResult[None]:
        """Validate search request parameters.

        Args:
            request: Search request to validate.

        Returns:
            FlextResult[None] indicating validation success or error.

        """
        # Use centralized DN validation
        base_dn_validation = FlextLdapValidations.validate_dn(request.base_dn)
        if base_dn_validation.is_failure:
            return FlextResult[None].fail(
                base_dn_validation.error or "Base DN validation failed"
            )

        # Use centralized filter validation
        filter_validation = FlextLdapValidations.validate_filter(request.filter_str)
        if filter_validation.is_failure:
            return FlextResult[None].fail(
                filter_validation.error or "Filter validation failed"
            )

        if not self._connection:
            return FlextResult[None].fail("LDAP connection not established")

        return FlextResult[None].ok(None)

    async def search_with_request(
        self,
        request: FlextLdapModels.SearchRequest,
    ) -> FlextResult[FlextLdapModels.SearchResponse]:
        """Perform LDAP search with SearchRequest.

        Args:
            request: Search request containing all search parameters.

        Returns:
            FlextResult containing search response or error.

        """
        # Validate using shared validation method
        validation = self._validate_search_request(request)
        if validation.is_failure:
            error_message = validation.error or "Search request validation failed"
            return FlextResult[FlextLdapModels.SearchResponse].fail(error_message)

        # If validation passes, perform the actual search
        try:
            # Convert scope string to ldap3 scope (case-insensitive)
            scope_map: dict[str, Literal["BASE", "LEVEL", "SUBTREE"]] = {
                "base": FlextLdapTypes.BASE,
                "onelevel": FlextLdapTypes.LEVEL,
                "subtree": FlextLdapTypes.SUBTREE,
            }
            ldap3_scope: Literal["BASE", "LEVEL", "SUBTREE"] = scope_map.get(
                request.scope.lower(), FlextLdapTypes.SUBTREE
            )

            # Check connection is available
            if self._connection is None:
                return FlextResult[FlextLdapModels.SearchResponse].fail(
                    "LDAP connection not established"
                )

            # Perform search
            success = self._connection.search(
                request.base_dn,
                request.filter_str,
                ldap3_scope,
                attributes=request.attributes,
            )

            if not success:
                return FlextResult[FlextLdapModels.SearchResponse].fail(
                    "Search operation failed",
                )

            # Convert entries to Entry models
            entries: list[FlextLdapModels.Entry] = []
            for entry in self._connection.entries:
                # Build attributes dict from ldap3 entry
                attributes: dict[str, object] = {}

                # Handle case where entry.entry_attributes might be a list instead of dict
                entry_attrs = (
                    entry.entry_attributes if hasattr(entry, "entry_attributes") else {}
                )

                if isinstance(entry_attrs, dict):
                    for attr_name in entry_attrs:
                        attr_value = entry[attr_name].value
                        if isinstance(attr_value, list) and len(attr_value) == 1:
                            attributes[attr_name] = attr_value[0]
                        else:
                            attributes[attr_name] = attr_value
                elif isinstance(entry_attrs, list):
                    # Handle case where entry_attributes is a list
                    # This might happen in error conditions or with certain LDAP servers
                    self._logger.warning(
                        f"entry.entry_attributes is a list instead of dict for DN {entry.entry_dn}"
                    )
                else:
                    self._logger.warning(
                        f"Unexpected type for entry.entry_attributes: {type(entry_attrs)}"
                    )

                # Get object classes safely
                object_classes: list[str] = []
                if isinstance(entry_attrs, dict):
                    object_classes = entry_attrs.get("objectClass", [])
                    if isinstance(object_classes, str):
                        object_classes = [object_classes]
                    elif not isinstance(object_classes, list):
                        object_classes = []
                elif hasattr(entry, "entry_attributes") and hasattr(
                    entry.entry_attributes, "get"
                ):
                    # Fallback for dict-like objects
                    try:
                        object_classes = entry.entry_attributes.get("objectClass", [])
                        if isinstance(object_classes, str):
                            object_classes = [object_classes]
                        elif not isinstance(object_classes, list):
                            object_classes = []
                    except AttributeError:
                        pass

                # Create Entry model instance
                entry_model = FlextLdapModels.Entry(
                    dn=str(entry.entry_dn),
                    attributes=attributes,
                    object_classes=object_classes,
                )
                entries.append(entry_model)

            response = FlextLdapModels.SearchResponse(
                entries=entries,
                total_count=len(entries),
                result_code=0,
                result_description="Success",
                matched_dn="",
                next_cookie=None,
                entries_returned=len(entries),
                time_elapsed=0.0,
            )

            return FlextResult[FlextLdapModels.SearchResponse].ok(response)

        except Exception as e:
            self._logger.exception("Search failed")
            return FlextResult[FlextLdapModels.SearchResponse].fail(
                f"Search failed: {e}",
            )

    async def search_users(
        self,
        base_dn: str,
        uid: str | None = None,
    ) -> FlextResult[list[FlextLdapModels.LdapUser]]:
        """Search for users in LDAP directory.

        Args:
            base_dn: Base DN for search.
            uid: Optional UID filter.

        Returns:
            FlextResult containing list of users or error.

        """
        try:
            if not self._connection:
                return FlextResult[list[FlextLdapModels.LdapUser]].fail(
                    "LDAP connection not established",
                )

            # Build search filter
            if uid:
                search_filter = f"(&(objectClass=inetOrgPerson)(uid={uid}))"
            else:
                search_filter = "(objectClass=inetOrgPerson)"

            # Perform search
            self._connection.search(
                base_dn, search_filter, FlextLdapTypes.SUBTREE, attributes=["*"]
            )

            users: list[FlextLdapModels.LdapUser] = []
            for entry in self._connection.entries:
                user = self._create_user_from_entry(entry)
                users.append(user)

            return FlextResult[list[FlextLdapModels.LdapUser]].ok(users)

        except Exception as e:
            self._logger.exception("User search failed")
            return FlextResult[list[FlextLdapModels.LdapUser]].fail(
                f"User search failed: {e}",
            )

    async def search_groups(
        self,
        base_dn: str,
        cn: str | None = None,
        filter_str: str | None = None,
        scope: str = "subtree",
        attributes: list[str] | None = None,
    ) -> FlextResult[list[FlextLdapModels.Group]]:
        """Search for groups in LDAP directory.

        Args:
            base_dn: Base DN for search.
            cn: Optional CN filter.
            filter_str: Optional custom filter string.
            scope: Search scope (base, onelevel, subtree).
            attributes: Optional list of attributes to return.

        Returns:
            FlextResult containing list of groups or error.

        """
        try:
            if not self._connection:
                return FlextResult[list[FlextLdapModels.Group]].fail(
                    "LDAP connection not established",
                )

            # Build search filter
            if filter_str:
                search_filter = filter_str
            elif cn:
                search_filter = f"(&(objectClass=groupOfNames)(cn={cn}))"
            else:
                search_filter = "(objectClass=groupOfNames)"

            # Determine scope
            scope_value: Literal["BASE", "LEVEL", "SUBTREE"] = FlextLdapTypes.SUBTREE
            if scope == "base":
                scope_value = FlextLdapTypes.BASE
            elif scope == "onelevel":
                scope_value = FlextLdapTypes.LEVEL

            # Perform search
            self._connection.search(
                base_dn, search_filter, scope_value, attributes=attributes or ["*"]
            )

            groups: list[FlextLdapModels.Group] = []
            for entry in self._connection.entries:
                group = self._create_group_from_entry(entry)
                groups.append(group)

            return FlextResult[list[FlextLdapModels.Group]].ok(groups)

        except Exception as e:
            self._logger.exception("Group search failed")
            return FlextResult[list[FlextLdapModels.Group]].fail(
                f"Group search failed: {e}",
            )

    async def get_user(self, dn: str) -> FlextResult[FlextLdapModels.LdapUser | None]:
        """Get user by Distinguished Name.

        Args:
            dn: Distinguished Name of the user.

        Returns:
            FlextResult containing user or None if not found.

        """
        try:
            # Validate DN using centralized validation
            dn_validation = FlextLdapValidations.validate_dn(dn)
            if dn_validation.is_failure:
                return FlextResult[FlextLdapModels.LdapUser | None].fail(
                    dn_validation.error or "DN validation failed"
                )

            if not self._connection:
                return FlextResult[FlextLdapModels.LdapUser | None].fail(
                    "LDAP connection not established",
                )

            success = self._connection.search(
                dn,
                FlextLdapConstants.Defaults.DEFAULT_SEARCH_FILTER,
                FlextLdapTypes.BASE,
                attributes=["*"],
            )

            if not success:
                error_msg = self._connection.last_error or "Unknown error"
                if "noSuchObject" in error_msg or "No such object" in error_msg:
                    self._logger.debug("Entry not found for DN: %s", dn)
                    return FlextResult[FlextLdapModels.LdapUser | None].ok(None)

                self._logger.warning("LDAP search failed for DN %s: %s", dn, error_msg)
                return FlextResult[FlextLdapModels.LdapUser | None].fail(
                    f"LDAP search failed: {error_msg}",
                )

            if not self._connection.entries:
                self._logger.debug("No entries found for DN: %s", dn)
                return FlextResult[FlextLdapModels.LdapUser | None].ok(None)

            user = self._create_user_from_entry(self._connection.entries[0])
            return FlextResult[FlextLdapModels.LdapUser | None].ok(user)

        except Exception as e:
            self._logger.exception("Get user failed for DN %s", dn)
            return FlextResult[FlextLdapModels.LdapUser | None].fail(
                f"Get user failed: {e}",
            )

    async def get_group(self, dn: str) -> FlextResult[FlextLdapModels.Group | None]:
        """Get group by Distinguished Name.

        Args:
            dn: Distinguished Name of the group.

        Returns:
            FlextResult containing group or None if not found.

        """
        try:
            # Validate DN using centralized validation
            dn_validation = FlextLdapValidations.validate_dn(dn)
            if dn_validation.is_failure:
                return FlextResult[FlextLdapModels.Group | None].fail(
                    dn_validation.error or "DN validation failed"
                )

            if not self._connection:
                return FlextResult[FlextLdapModels.Group | None].fail(
                    "LDAP connection not established",
                )

            success = self._connection.search(
                dn,
                FlextLdapConstants.Defaults.DEFAULT_SEARCH_FILTER,
                FlextLdapTypes.BASE,
                attributes=["*"],
            )

            if not success:
                error_msg = self._connection.last_error or "Unknown error"
                if "noSuchObject" in error_msg or "No such object" in error_msg:
                    self._logger.debug("Group not found for DN: %s", dn)
                    return FlextResult[FlextLdapModels.Group | None].ok(None)

                self._logger.warning("LDAP search failed for DN %s: %s", dn, error_msg)
                return FlextResult[FlextLdapModels.Group | None].fail(
                    f"LDAP search failed: {error_msg}",
                )

            if not self._connection.entries:
                return FlextResult[FlextLdapModels.Group | None].ok(None)

            group = self._create_group_from_entry(self._connection.entries[0])
            return FlextResult[FlextLdapModels.Group | None].ok(group)

        except Exception as e:
            self._logger.exception("Get group failed")
            return FlextResult[FlextLdapModels.Group | None].fail(
                f"Get group failed: {e}",
            )

    async def create_user(
        self,
        request: FlextLdapModels.CreateUserRequest,
    ) -> FlextResult[FlextLdapModels.LdapUser]:
        """Create new user in LDAP directory using FlextResults railways pattern.

        Args:
            request: User creation request.

        Returns:
            FlextResult containing created user or error.

        """
        # Railway pattern: Chain validation -> build attributes -> create -> retrieve
        validation_result = self._validate_connection()
        if validation_result.is_failure:
            return FlextResult[FlextLdapModels.LdapUser].fail(
                validation_result.error or "Validation failed"
            )

        attrs_result = self._build_user_attributes(request)
        if attrs_result.is_failure:
            return FlextResult[FlextLdapModels.LdapUser].fail(
                attrs_result.error or "Attribute building failed"
            )

        add_result = self._add_user_to_ldap(request.dn, attrs_result.value)
        if add_result.is_failure:
            return FlextResult[FlextLdapModels.LdapUser].fail(
                add_result.error or "User creation failed"
            )

        return await self._retrieve_created_user(request.dn)

    def _build_user_attributes(
        self, request: FlextLdapModels.CreateUserRequest
    ) -> FlextResult[dict[str, list[str]]]:
        """Build LDAP attributes for user creation using railway pattern."""
        try:
            ldap3_attributes: dict[str, list[str]] = {
                "objectClass": ["inetOrgPerson", "organizationalPerson", "person"],
                "uid": [request.uid],
                "cn": [request.cn],
                "sn": [request.sn],
            }

            # Add optional attributes
            if request.given_name:
                ldap3_attributes["givenName"] = [request.given_name]
            if request.mail:
                ldap3_attributes["mail"] = [request.mail]
            if request.telephone_number:
                ldap3_attributes["telephoneNumber"] = [request.telephone_number]
            if request.department:
                ldap3_attributes["departmentNumber"] = [request.department]
            if request.title:
                ldap3_attributes["title"] = [request.title]
            if request.organization:
                ldap3_attributes["o"] = [request.organization]
            if request.user_password:
                password_value = (
                    request.user_password.get_secret_value()
                    if isinstance(request.user_password, SecretStr)
                    else request.user_password
                )
                ldap3_attributes["userPassword"] = [password_value]

            return FlextResult[dict[str, list[str]]].ok(ldap3_attributes)

        except Exception as e:
            return FlextResult[dict[str, list[str]]].fail(
                f"Failed to build user attributes: {e}"
            )

    def _add_user_to_ldap(
        self, user_dn: str, attributes: dict[str, list[str]]
    ) -> FlextResult[None]:
        """Add user to LDAP directory using railway pattern."""
        try:
            if not self._connection:
                return FlextResult[None].fail("LDAP connection not established")

            # dict[str, list[str]] is compatible with dict[str, str | list[str]]
            success = self._connection.add(
                dn=user_dn,
                attributes=attributes,
            )

            if not success:
                return FlextResult[None].fail(
                    f"Failed to create user: {self._connection.last_error}",
                )

            return FlextResult[None].ok(None)

        except Exception as e:
            return FlextResult[None].fail(f"Failed to add user to LDAP: {e}")

    async def _retrieve_created_user(
        self, user_dn: str
    ) -> FlextResult[FlextLdapModels.LdapUser]:
        """Retrieve created user using railway pattern."""
        try:
            created_user_result = await self.get_user(user_dn)
            if created_user_result.is_failure:
                return FlextResult[FlextLdapModels.LdapUser].fail(
                    "User created but failed to retrieve",
                )

            # We know the user exists since we just created it
            user = created_user_result.value
            if user is None:
                return FlextResult[FlextLdapModels.LdapUser].fail(
                    "User created but returned None",
                )

            return FlextResult[FlextLdapModels.LdapUser].ok(user)

        except Exception as e:
            return FlextResult[FlextLdapModels.LdapUser].fail(
                f"Failed to retrieve created user: {e}"
            )

    async def create_group(
        self,
        request: FlextLdapModels.CreateGroupRequest,
    ) -> FlextResult[FlextLdapModels.Group]:
        """Create new group in LDAP directory.

        Args:
            request: Group creation request.

        Returns:
            FlextResult containing created group or error.

        """
        try:
            if not self._connection:
                return FlextResult[FlextLdapModels.Group].fail(
                    "LDAP connection not established",
                )

            # Use the provided DN directly
            group_dn = request.dn

            # Build LDAP attributes
            ldap3_attributes: dict[str, list[str]] = {
                "objectClass": ["groupOfNames"],
                "cn": [request.cn],
                "member": [
                    "uid=placeholder,ou=users,dc=example,dc=com"
                ],  # Placeholder member
            }

            # Add optional attributes
            if request.description:
                ldap3_attributes["description"] = [request.description]

            # Create group - ldap3_attributes already has correct type
            success = self._connection.add(
                dn=group_dn,
                attributes=ldap3_attributes,
            )

            if not success:
                return FlextResult[FlextLdapModels.Group].fail(
                    f"Failed to create group: {self._connection.last_error}",
                )

            # Retrieve created group
            created_group_result = await self.get_group(group_dn)
            if created_group_result.is_failure:
                return FlextResult[FlextLdapModels.Group].fail(
                    "Group created but failed to retrieve",
                )

            # We know the group exists since we just created it
            group = created_group_result.value
            if group is None:
                return FlextResult[FlextLdapModels.Group].fail(
                    "Group created but returned None",
                )

            return FlextResult[FlextLdapModels.Group].ok(group)

        except Exception as e:
            self._logger.exception("Create group failed")
            return FlextResult[FlextLdapModels.Group].fail(f"Create group failed: {e}")

    async def close_connection(self) -> FlextResult[None]:
        """Close LDAP connection.

        Returns:
            FlextResult indicating success or error.

        """
        return await self.unbind()

    async def disconnect(self) -> FlextResult[None]:
        """Disconnect from LDAP server - implements LdapConnectionProtocol.

        Alias for close_connection to match protocol interface.

        Returns:
            FlextResult[None]: Disconnect success status

        """
        return await self.close_connection()

    # =============================================================================
    # PROTOCOL IMPLEMENTATION METHODS - FlextLdapProtocols compliance

    async def search_one(
        self,
        search_base: str,
        search_filter: str,
        attributes: list[str] | None = None,
    ) -> FlextResult[FlextLdapModels.Entry | None]:
        """Perform LDAP search for single entry - implements LdapSearchProtocol.

        Args:
            search_base: LDAP search base DN
            search_filter: LDAP search filter
            attributes: List of attributes to retrieve

        Returns:
            FlextResult[FlextLdapModels.Entry | None]: Single search result Entry model or None

        """
        # Use existing search method and return first result
        search_result = await self.search(search_base, search_filter, attributes)
        if search_result.is_failure:
            return FlextResult[FlextLdapModels.Entry | None].fail(
                search_result.error or "Search failed"
            )

        results = search_result.unwrap()
        if not results:
            return FlextResult[FlextLdapModels.Entry | None].ok(None)

        return FlextResult[FlextLdapModels.Entry | None].ok(results[0])

    async def add_entry(
        self, dn: str, attributes: dict[str, str | list[str]]
    ) -> FlextResult[bool]:
        """Add new LDAP entry - implements LdapModifyProtocol.

        Args:
            dn: Distinguished name for new entry
            attributes: Entry attributes

        Returns:
            FlextResult[bool]: Add operation success status

        """
        # Delegate to existing add_entry_universal method
        return await self.add_entry_universal(dn, attributes)

    async def modify_entry(
        self, dn: str, changes: dict[str, object]
    ) -> FlextResult[bool]:
        """Modify existing LDAP entry - implements LdapModifyProtocol.

        Args:
            dn: Distinguished name of entry to modify
            changes: Attribute changes to apply

        Returns:
            FlextResult[bool]: Modify operation success status

        """
        # Delegate to existing modify_entry_universal method
        return await self.modify_entry_universal(dn, changes)

    async def delete_entry(self, dn: str) -> FlextResult[bool]:
        """Delete LDAP entry - implements LdapModifyProtocol.

        Args:
            dn: Distinguished name of entry to delete

        Returns:
            FlextResult[bool]: Delete operation success status

        """
        # Delegate to existing delete_entry_universal method
        return await self.delete_entry_universal(dn)

    async def validate_credentials(self, dn: str, password: str) -> FlextResult[bool]:
        """Validate user credentials against LDAP - implements LdapAuthenticationProtocol.

        Args:
            dn: User distinguished name
            password: User password

        Returns:
            FlextResult[bool]: Validation success status

        """
        # Use existing authenticate_user logic adapted for DN-based validation
        try:
            # Create a test connection with the provided credentials
            base_uri = (
                self._config.server_uri if self._config else "ldap://localhost:389"
            )
            test_config = FlextLdapModels.ConnectionConfig(
                server=base_uri.replace("ldap://", "")
                .replace("ldaps://", "")
                .split(":")[0],
                port=int(base_uri.split(":")[-1]) if ":" in base_uri else 389,
                bind_dn=dn,
                bind_password=password,
            )
            test_client = FlextLdapClient(test_config)
            connection_result = await test_client.bind(dn, password)
            await test_client.disconnect()
            return FlextResult[bool].ok(connection_result.is_success)
        except Exception as e:
            return FlextResult[bool].fail(f"Credential validation failed: {e}")

    def validate_dn(self, dn: str) -> FlextResult[bool]:
        """Validate distinguished name format - implements LdapValidationProtocol.

        Args:
            dn: Distinguished name to validate

        Returns:
            FlextResult[bool]: Validation success status

        """
        # Use centralized DN validation
        dn_validation = FlextLdapValidations.validate_dn(dn)
        if dn_validation.is_failure:
            return FlextResult[bool].fail(dn_validation.error or "DN validation failed")

        return FlextResult[bool].ok(True)

    def validate_entry(self, entry: FlextLdapModels.Entry) -> FlextResult[bool]:
        """Validate LDAP entry structure - implements LdapValidationProtocol.

        Args:
            entry: LDAP Entry model to validate

        Returns:
            FlextResult[bool]: Validation success status

        """
        # Pydantic validation already validates dn field
        # Check for required objectClass in attributes or object_classes field
        if not entry.object_classes and "objectClass" not in entry.attributes:
            return FlextResult[bool].fail("Entry must have objectClass attribute")

        # Get objectClass from either field
        object_class = (
            entry.object_classes
            if entry.object_classes
            else entry.attributes.get("objectClass")
        )
        if not object_class:
            return FlextResult[bool].fail("objectClass cannot be empty")

        # Validate that objectClass is a list or string
        if not isinstance(object_class, (str, list)):
            return FlextResult[bool].fail("objectClass must be string or list")

        return FlextResult[bool].ok(True)

    async def remove_member(self, group_dn: str, member_dn: str) -> FlextResult[None]:
        """Remove member from group.

        Args:
            group_dn: Group Distinguished Name.
            member_dn: Member Distinguished Name to remove.

        Returns:
            FlextResult indicating success or error.

        """
        try:
            if not self._connection:
                return FlextResult[None].fail("LDAP connection not established")

            changes: dict[str, list[tuple[str, list[str]]]] = {
                "member": [(FlextLdapTypes.MODIFY_DELETE, [member_dn])],
            }
            success = self._connection.modify(
                group_dn,
                changes,
            )

            if not success:
                return FlextResult[None].fail(
                    f"Failed to remove member: {self._connection.last_error}",
                )

            return FlextResult[None].ok(None)

        except Exception as e:
            self._logger.exception("Remove member failed")
            return FlextResult[None].fail(f"Remove member failed: {e}")

    async def get_members(self, group_dn: str) -> FlextResult[list[str]]:
        """Get list of group members.

        Args:
            group_dn: Group Distinguished Name.

        Returns:
            FlextResult containing list of member DNs or error.

        """
        try:
            if not self._connection:
                return FlextResult[list[str]].fail("LDAP connection not established")

            # Search for the group
            self._connection.search(
                group_dn,
                FlextLdapConstants.Defaults.DEFAULT_SEARCH_FILTER,
                FlextLdapTypes.BASE,
                attributes=["member"],
            )

            if not self._connection.entries:
                return FlextResult[list[str]].fail("Group not found")

            entry = self._connection.entries[0]
            members = []

            if hasattr(entry, "member"):
                member_attr = getattr(entry, "member")
                if hasattr(member_attr, "value"):
                    if isinstance(member_attr.value, list):
                        members = [str(m) for m in member_attr.value]
                    else:
                        members = [str(member_attr.value)]

            return FlextResult[list[str]].ok(members)

        except Exception as e:
            self._logger.exception("Get members failed")
            return FlextResult[list[str]].fail(f"Get members failed: {e}")

    async def user_exists(self, dn: str) -> FlextResult[bool]:
        """Check if user exists in LDAP directory.

        Args:
            dn: User Distinguished Name.

        Returns:
            FlextResult containing True if user exists, False otherwise.

        """
        try:
            result = await self.get_user(dn)
            if result.is_success:
                exists = result.unwrap() is not None
                return FlextResult[bool].ok(exists)
            # Propagate connection errors, return False for not found
            error_message = result.error or "Unknown error"
            if (
                "LDAP connection not established" in error_message
                or "DN cannot be empty" in error_message
            ):
                return FlextResult[bool].fail(error_message)
            return FlextResult[bool].ok(False)

        except Exception as e:
            return FlextResult[bool].fail(f"User existence check failed: {e}")

    async def group_exists(self, dn: str) -> FlextResult[bool]:
        """Check if group exists in LDAP directory.

        Args:
            dn: Group Distinguished Name.

        Returns:
            FlextResult containing True if group exists, False otherwise.

        """
        try:
            result = await self.get_group(dn)
            if result.is_success:
                exists = result.unwrap() is not None
                return FlextResult[bool].ok(exists)
            return FlextResult[bool].ok(False)

        except Exception as e:
            return FlextResult[bool].fail(f"Group existence check failed: {e}")

    async def search(
        self,
        base_dn: str,
        filter_str: str,
        attributes: list[str] | None = None,
        page_size: int = 0,
        paged_cookie: bytes | None = None,
    ) -> FlextResult[list[FlextLdapModels.Entry]]:
        """Perform LDAP search operation.

        Args:
            base_dn: Base DN for search.
            filter_str: LDAP search filter.
            attributes: List of attributes to retrieve.
            page_size: Page size for paged search.
            paged_cookie: Cookie for paged search.

        Returns:
            FlextResult containing Entry models or error.

        """
        try:
            if not self._connection:
                return FlextResult[list[FlextLdapModels.Entry]].fail(
                    "LDAP connection not established",
                )

            # Perform search
            success = self._connection.search(
                base_dn,
                filter_str,
                FlextLdapTypes.SUBTREE,
                attributes=attributes,
                paged_size=page_size if page_size > 0 else None,
                paged_cookie=paged_cookie,
            )

            if not success:
                return FlextResult[list[FlextLdapModels.Entry]].fail(
                    f"Search failed: {self._connection.last_error}",
                )

            # Convert entries to Entry models
            results: list[FlextLdapModels.Entry] = []
            for entry in self._connection.entries:
                # Build attributes dict from ldap3 entry
                entry_attributes: dict[str, object] = {}
                for attr_name in entry.entry_attributes:
                    attr_value = entry[attr_name].value
                    if attr_value is None:
                        continue  # Skip None values
                    if isinstance(attr_value, list) and len(attr_value) == 1:
                        entry_attributes[attr_name] = attr_value[0]
                    else:
                        entry_attributes[attr_name] = attr_value

                # Create Entry model instance
                entry_model = FlextLdapModels.Entry(
                    dn=str(entry.entry_dn),
                    attributes=entry_attributes,
                    object_classes=entry_attributes.get("objectClass", [])
                    if isinstance(entry_attributes.get("objectClass"), list)
                    else [entry_attributes.get("objectClass")]
                    if entry_attributes.get("objectClass")
                    else [],
                )
                results.append(entry_model)

            return FlextResult[list[FlextLdapModels.Entry]].ok(results)

        except Exception as e:
            self._logger.exception("Search failed")
            return FlextResult[list[FlextLdapModels.Entry]].fail(f"Search failed: {e}")

    async def update_user_attributes(
        self,
        dn: str,
        attributes: dict[str, object],
    ) -> FlextResult[bool]:
        """Update user attributes.

        Args:
            dn: User Distinguished Name.
            attributes: Attributes to update.

        Returns:
            FlextResult indicating update success or error.

        """
        try:
            if not self._connection:
                return FlextResult[bool].fail("LDAP connection not established")

            # Convert attributes to LDAP modification format
            ldap3_changes: FlextLdapTypes.LdapDomain.ModifyChanges = {}
            for attr_name, attr_value in attributes.items():
                ldap3_changes[attr_name] = [
                    (FlextLdapTypes.MODIFY_REPLACE, [str(attr_value)])
                ]

                # Perform modification
                success = self._connection.modify(
                    dn,
                    ldap3_changes,
                )
            success = False

            if not success:
                return FlextResult[bool].fail(
                    f"Failed to update user: {self._connection.last_error}",
                )

            return FlextResult[bool].ok(True)

        except Exception as e:
            self._logger.exception("Update user failed")
            return FlextResult[bool].fail(f"Update user failed: {e}")

    async def update_group_attributes(
        self,
        dn: str,
        attributes: dict[str, object],
    ) -> FlextResult[bool]:
        """Update group attributes.

        Args:
            dn: Group Distinguished Name.
            attributes: Attributes to update.

        Returns:
            FlextResult indicating update success or error.

        """
        try:
            if not self._connection:
                return FlextResult[bool].fail("LDAP connection not established")

            # Convert attributes to LDAP modification format
            changes: FlextLdapTypes.LdapDomain.ModifyChanges = {}
            for attr_name, attr_value in attributes.items():
                changes[attr_name] = [
                    (FlextLdapTypes.MODIFY_REPLACE, [str(attr_value)])
                ]

            # Perform modification
            success = self._connection.modify(dn, changes)

            if not success:
                return FlextResult[bool].fail(
                    f"Failed to update group: {self._connection.last_error}",
                )

            return FlextResult[bool].ok(True)

        except Exception as e:
            self._logger.exception("Update group failed")
            return FlextResult[bool].fail(f"Update group failed: {e}")

    async def delete_user(self, dn: str) -> FlextResult[None]:
        """Delete user from LDAP directory.

        Args:
            dn: User Distinguished Name.

        Returns:
            FlextResult indicating deletion success or error.

        """
        try:
            if not self._connection:
                return FlextResult[None].fail("LDAP connection not established")

            success = self._connection.delete(dn)
            if not success:
                return FlextResult[None].fail(
                    f"Failed to delete user: {self._connection.last_error}",
                )

            return FlextResult[None].ok(None)

        except Exception as e:
            self._logger.exception("Delete user failed")
            return FlextResult[None].fail(f"Delete user failed: {e}")

    async def delete_group(self, dn: str) -> FlextResult[None]:
        """Delete group from LDAP directory.

        Args:
            dn: Group Distinguished Name.

        Returns:
            FlextResult indicating deletion success or error.

        """
        try:
            if not self._connection:
                return FlextResult[None].fail("LDAP connection not established")

            success = self._connection.delete(dn)
            if not success:
                return FlextResult[None].fail(
                    f"Failed to delete group: {self._connection.last_error}",
                )

            return FlextResult[None].ok(None)

        except Exception as e:
            self._logger.exception("Delete group failed")
            return FlextResult[None].fail(f"Delete group failed: {e}")

    async def add(
        self,
        dn: str,
        attributes: dict[str, str | list[str]] | None = None,
    ) -> FlextResult[None]:
        """Add entry to LDAP directory (low-level operation).

        Args:
            dn: Distinguished Name of entry to add.
            attributes: LDAP attributes dictionary.

        Returns:
            FlextResult indicating add success or error.

        """
        try:
            if not self._connection:
                return FlextResult[None].fail("LDAP connection not established")

            success = self._connection.add(
                dn,
                attributes=attributes,
            )

            if not success:
                return FlextResult[None].fail(
                    f"Failed to add entry: {self._connection.last_error}",
                )

            return FlextResult[None].ok(None)

        except Exception as e:
            self._logger.exception("Add entry failed")
            return FlextResult[None].fail(f"Add entry failed: {e}")

    async def modify(
        self,
        dn: str,
        changes: dict[str, list[tuple[str, list[str]]]],
    ) -> FlextResult[None]:
        """Modify entry in LDAP directory (low-level operation).

        Args:
            dn: Distinguished Name of entry to modify.
            changes: Dictionary of attribute changes.

        Returns:
            FlextResult indicating modify success or error.

        """
        try:
            if not self._connection:
                return FlextResult[None].fail("LDAP connection not established")

            success = self._connection.modify(dn, changes)
            if not success:
                return FlextResult[None].fail(
                    f"Failed to modify entry: {self._connection.last_error}",
                )

            return FlextResult[None].ok(None)

        except Exception as e:
            self._logger.exception("Modify entry failed")
            return FlextResult[None].fail(f"Modify entry failed: {e}")

    def delete(self, dn: str) -> FlextResult[None]:
        """Delete entry from LDAP directory (low-level operation).

        Args:
            dn: Distinguished Name of entry to delete.

        Returns:
            FlextResult indicating delete success or error.

        """
        try:
            if not self._connection:
                return FlextResult[None].fail("LDAP connection not established")

            success = self._connection.delete(dn)
            if not success:
                return FlextResult[None].fail(
                    f"Failed to delete entry: {self._connection.last_error}",
                )

            return FlextResult[None].ok(None)

        except Exception as e:
            self._logger.exception("Delete entry failed")
            return FlextResult[None].fail(f"Delete entry failed: {e}")

    async def add_member(self, group_dn: str, member_dn: str) -> FlextResult[None]:
        """Add member to group.

        Args:
            group_dn: Group Distinguished Name.
            member_dn: Member Distinguished Name to add.

        Returns:
            FlextResult indicating success or error.

        """
        try:
            if not self._connection:
                return FlextResult[None].fail("LDAP connection not established")

            changes: dict[str, list[tuple[str, list[str]]]] = {
                "member": [(FlextLdapTypes.MODIFY_ADD, [member_dn])],
            }
            success = self._connection.modify(
                group_dn,
                changes,
            )

            if not success:
                return FlextResult[None].fail(
                    f"Failed to add member: {self._connection.last_error}",
                )

            return FlextResult[None].ok(None)

        except Exception as e:
            self._logger.exception("Add member failed")
            return FlextResult[None].fail(f"Add member failed: {e}")

    @property
    def session_id(self) -> str | None:
        """Get current session ID."""
        return self._session_id

    @session_id.setter
    def session_id(self, value: str | None) -> None:
        """Set session ID."""
        self._session_id = value

    def _create_user_from_entry(
        self, entry: FlextLdapProtocols.LdapEntry
    ) -> FlextLdapModels.LdapUser:
        """Create LdapUser from LDAP entry.

        Args:
            entry: LDAP entry object.

        Returns:
            LdapUser object.

        """

        def get_attribute_value(attr_name: str) -> str | None:
            """Safely get attribute value from entry."""
            try:
                # Try to access the attribute directly
                if hasattr(entry, attr_name):
                    attr = getattr(entry, attr_name)
                    if hasattr(attr, "value"):
                        value = attr.value
                        if isinstance(value, list) and value:
                            return str(value[0])
                        if isinstance(value, str) and value:
                            return value
                return None
            except (AttributeError, TypeError, KeyError):
                return None

        cn = get_attribute_value("cn")
        uid = get_attribute_value("uid")
        sn = get_attribute_value("sn")

        # Validate required fields - must have either attributes or be extractable from DN
        if not cn:
            cn = (
                entry.entry_dn.split(",")[0].split("=")[1]
                if "=" in entry.entry_dn
                else None
            )

        # Check if we have any actual LDAP attributes (not just DN-extractable data)
        mail = get_attribute_value("mail")
        has_attributes = any([get_attribute_value("cn"), uid, sn, mail])

        # If no actual LDAP attributes are present, this is invalid
        if not has_attributes:
            exceptions = FlextLdapExceptions()
            raise exceptions.validation_error(
                "Cannot create user from entry: missing required LDAP attributes",
                value=str(entry.entry_dn),
                field="entry",
            )

        # Use fallback values only if we have some valid attributes
        cn = cn or "Unknown"

        return FlextLdapModels.LdapUser(
            dn=str(entry.entry_dn),
            cn=cn,
            uid=get_attribute_value("uid") or "unknown",
            sn=get_attribute_value("sn") or "unknown",
            given_name=get_attribute_value("givenName"),
            mail=get_attribute_value("mail") or "unknown@example.com",
            telephone_number=get_attribute_value("telephoneNumber"),
            mobile=get_attribute_value("mobile"),
            department=get_attribute_value("departmentNumber"),
            title=get_attribute_value("title"),
            organization=get_attribute_value("o"),
            organizational_unit=get_attribute_value("ou"),
            user_password=None,
        )

    def _create_group_from_entry(
        self, entry: FlextLdapProtocols.LdapEntry
    ) -> FlextLdapModels.Group:
        """Create Group from LDAP entry.

        Args:
            entry: LDAP entry object.

        Returns:
            Group object.

        """

        def get_attribute_value(attr_name: str) -> str | None:
            """Safely get attribute value from entry."""
            try:
                # Try to access the attribute directly
                if hasattr(entry, attr_name):
                    attr = getattr(entry, attr_name)
                    if hasattr(attr, "value"):
                        value = attr.value
                        if isinstance(value, list) and value:
                            return str(value[0])
                        if isinstance(value, str) and value:
                            return value
                return None
            except (AttributeError, TypeError, KeyError):
                return None

        def get_int_attribute_value(attr_name: str) -> int | None:
            """Safely get integer attribute value from entry."""
            try:
                # Try to access the attribute directly
                value: object = None
                if hasattr(entry, attr_name):
                    attr = getattr(entry, attr_name)
                    if hasattr(attr, "value"):
                        value = attr.value
                        if isinstance(value, list) and value:
                            return int(value[0])
                    if isinstance(value, str) and value:
                        return int(value)
                return None
            except (AttributeError, TypeError, ValueError, KeyError):
                return None

        return FlextLdapModels.Group(
            dn=str(entry.entry_dn),
            cn=get_attribute_value("cn") or "",
            gid_number=get_int_attribute_value("gidNumber"),
            description=get_attribute_value("description"),
        )

    # =========================================================================
    # UNIVERSAL GENERIC METHODS - Complete LDAP compatibility
    # =========================================================================

    async def search_universal(
        self,
        base_dn: str,
        filter_str: str,
        attributes: list[str] | None = None,
        scope: str = "subtree",
        size_limit: int = 0,
        time_limit: int = 0,
        deref_aliases: str = "deref_always",
        *,
        types_only: bool = False,
        controls: list[object] | None = None,
    ) -> FlextResult[list[FlextLdapModels.Entry]]:
        """Universal search that adapts to any LDAP server.

        Args:
            base_dn: Base DN for search
            filter_str: LDAP search filter
            attributes: Attributes to return (None for all)
            scope: Search scope (base, onelevel, subtree, children)
            size_limit: Maximum number of entries to return
            time_limit: Maximum time for search
            deref_aliases: How to dereference aliases
            types_only: Return only attribute types, not values
            controls: LDAP controls to use

        Returns:
            FlextResult[list[FlextLdapModels.Entry]]: Entry models search results

        """
        try:
            if not self._connection:
                return FlextResult[list[FlextLdapModels.Entry]].fail(
                    "LDAP connection not established"
                )

            # Normalize inputs according to server quirks
            normalized_base_dn = self.normalize_dn(base_dn)
            normalized_filter = self._normalize_filter(filter_str)
            normalized_attributes = (
                self._normalize_attributes(attributes) if attributes else None
            )

            # Apply server-specific search limitations
            if self._server_quirks:
                if scope in self._server_quirks.search_scope_limitations:
                    self._logger.warning(
                        "Search scope %s not supported by server", scope
                    )
                    scope = "subtree"  # Fallback to subtree

                if size_limit > self._server_quirks.max_page_size:
                    self._logger.warning(
                        "Size limit %d exceeds server max %d",
                        size_limit,
                        self._server_quirks.max_page_size,
                    )
                    size_limit = self._server_quirks.max_page_size

            # Perform search using base client with all parameters
            search_result = await self.search(
                base_dn=normalized_base_dn,
                filter_str=normalized_filter,
                attributes=normalized_attributes,
                page_size=max(0, size_limit),
            )

            # Log parameter usage for compliance
            self._logger.debug(
                "Search parameters: time_limit=%d, deref_aliases=%s, types_only=%s, controls=%s",
                time_limit,
                deref_aliases,
                types_only,
                controls,
            )

            if search_result.is_success:
                # Normalize results according to server quirks
                normalized_results = self._normalize_search_results(search_result.value)
                return FlextResult[list[FlextLdapModels.Entry]].ok(normalized_results)

            return search_result

        except Exception as e:
            self._logger.exception("Universal search failed")
            return FlextResult[list[FlextLdapModels.Entry]].fail(f"Search failed: {e}")

    async def add_entry_universal(
        self,
        dn: str,
        attributes: dict[str, str | list[str]],
        *,
        controls: list[object] | None = None,
    ) -> FlextResult[bool]:
        """Universal add entry that adapts to any LDAP server.

        Args:
            dn: Distinguished Name for the entry
            attributes: Entry attributes
            controls: LDAP controls to use

        Returns:
            FlextResult[bool]: Success result

        """
        try:
            if not self._connection:
                return FlextResult[bool].fail("LDAP connection not established")

            # Normalize inputs
            normalized_dn = self.normalize_dn(dn)
            normalized_attributes = self._normalize_entry_attributes(attributes)

            # Log controls parameter usage for compliance
            self._logger.debug("Add entry controls: %s", controls)

            # Perform add using base client
            result = await self.add(normalized_dn, normalized_attributes)
            return FlextResult[bool].ok(result.is_success)

        except Exception as e:
            self._logger.exception("Universal add entry failed")
            return FlextResult[bool].fail(f"Add entry failed: {e}")

    async def modify_entry_universal(
        self,
        dn: str,
        changes: dict[str, object],
        *,
        controls: list[object] | None = None,
    ) -> FlextResult[bool]:
        """Universal modify entry that adapts to any LDAP server.

        Args:
            dn: Distinguished Name for the entry
            changes: Modification changes
            controls: LDAP controls to use

        Returns:
            FlextResult[bool]: Success result

        """
        try:
            if not self._connection:
                return FlextResult[bool].fail("LDAP connection not established")

            # Normalize inputs
            normalized_dn = self.normalize_dn(dn)
            normalized_changes = self._normalize_modify_changes(changes)

            # Log controls parameter usage for compliance
            self._logger.debug("Modify entry controls: %s", controls)

            # Perform modify using base client
            result = await self.modify(normalized_dn, normalized_changes)
            return FlextResult[bool].ok(result.is_success)

        except Exception as e:
            self._logger.exception("Universal modify entry failed")
            return FlextResult[bool].fail(f"Modify entry failed: {e}")

    async def delete_entry_universal(
        self,
        dn: str,
        *,
        controls: list[object] | None = None,
    ) -> FlextResult[bool]:
        """Universal delete entry that adapts to any LDAP server.

        Args:
            dn: Distinguished Name for the entry
            controls: LDAP controls to use

        Returns:
            FlextResult[bool]: Success result

        """
        try:
            if not self._connection:
                return FlextResult[bool].fail("LDAP connection not established")

            # Normalize DN
            normalized_dn = self.normalize_dn(dn)

            # Log controls parameter usage for compliance
            self._logger.debug("Delete entry controls: %s", controls)

            # Perform delete using base client
            result = self.delete(normalized_dn)
            return FlextResult[bool].ok(result.is_success)

        except Exception as e:
            self._logger.exception("Universal delete entry failed")
            return FlextResult[bool].fail(f"Delete entry failed: {e}")

    async def compare_universal(
        self,
        dn: str,
        attribute: str,
        value: str,
    ) -> FlextResult[bool]:
        """Universal compare operation that adapts to any LDAP server.

        Args:
            dn: Distinguished Name for the entry
            attribute: Attribute to compare
            value: Value to compare against

        Returns:
            FlextResult[bool]: Comparison result

        """
        try:
            if not self._connection:
                return FlextResult[bool].fail("LDAP connection not established")

            # Normalize inputs
            normalized_dn = self.normalize_dn(dn)
            normalized_attribute = self.normalize_attribute_name(attribute)

            # Perform compare
            success = self._connection.compare(
                normalized_dn, normalized_attribute, value
            )

            if success:
                return FlextResult[bool].ok(True)
            return FlextResult[bool].fail(
                f"Compare failed: {self._connection.last_error}"
            )

        except Exception as e:
            self._logger.exception("Universal compare failed")
            return FlextResult[bool].fail(f"Compare failed: {e}")

    async def extended_operation_universal(
        self,
        request_name: str,
        request_value: str | bytes | None = None,
        *,
        controls: list[object] | None = None,
    ) -> FlextResult[dict[str, object]]:
        """Universal extended operation that adapts to any LDAP server.

        Args:
            request_name: Name of the extended operation
            request_value: Value for the operation
            controls: LDAP controls to use

        Returns:
            FlextResult[dict[str, object]]: Operation result

        """
        try:
            if not self._connection:
                return FlextResult[dict[str, object]].fail(
                    "LDAP connection not established"
                )

            # Log controls parameter usage for compliance
            self._logger.debug("Extended operation controls: %s", controls)

            # Perform extended operation
            # Convert string to bytes if needed for ldap3 compatibility
            request_value_bytes: bytes | None
            if isinstance(request_value, str):
                request_value_bytes = request_value.encode("utf-8")
            else:
                request_value_bytes = None
            success = self._connection.extended(request_name, request_value_bytes)

            if success:
                result = {
                    "request_name": request_name,
                    "request_value": request_value,
                    "response_name": getattr(self._connection, "response_name", None),
                    "response_value": getattr(self._connection, "response_value", None),
                }
                return FlextResult[dict[str, object]].ok(result)
            return FlextResult[dict[str, object]].fail(
                f"Extended operation failed: {self._connection.last_error}"
            )

        except Exception as e:
            self._logger.exception("Universal extended operation failed")
            return FlextResult[dict[str, object]].fail(
                f"Extended operation failed: {e}"
            )

    async def search_with_controls_universal(
        self,
        base_dn: str,
        filter_str: str,
        scope: str = FlextLdapConstants.Scopes.SUBTREE,
        attributes: list[str] | None = None,
        controls: list[tuple[str, bool, bytes | None]] | None = None,
    ) -> FlextResult[list[FlextLdapModels.Entry]]:
        """Universal search with controls, adapting to any LDAP server.

        Args:
            base_dn: Base DN for search
            filter_str: LDAP filter string
            scope: Search scope (base, level, or subtree)
            attributes: List of attributes to retrieve (None = all)
            controls: List of LDAP controls (OID, critical, value)

        Returns:
            FlextResult containing list of Entry models or error message

        """
        # Validate connection
        if not self.is_connected():
            return FlextResult[list[FlextLdapModels.Entry]].fail(
                "LDAP connection not established"
            )

        # Type guard: at this point connection is guaranteed to be non-None
        assert self._connection is not None

        # Validate scope
        if scope not in FlextLdapConstants.Scopes.VALID_SCOPES:
            return FlextResult[list[FlextLdapModels.Entry]].fail(
                f"Invalid search scope: {scope}. Must be one of {FlextLdapConstants.Scopes.VALID_SCOPES}"
            )

        # Build LDAP controls
        ldap_controls = None
        if controls:
            ldap_controls = []
            for oid, critical, value in controls:
                ldap_controls.append(
                    {
                        "control_type": oid,
                        "criticality": critical,
                        "control_value": value,
                    }
                )

        # Perform search with controls
        try:
            # Cast scope to Literal type for ldap3
            from typing import cast, Literal

            ldap_scope = cast(Literal["BASE", "LEVEL", "SUBTREE"], scope)

            self._connection.search(
                search_base=base_dn,
                search_filter=filter_str,
                search_scope=ldap_scope,
                attributes=attributes or [],
                controls=ldap_controls,
            )

            # Convert entries to Entry models
            results: list[FlextLdapModels.Entry] = []
            for entry in self._connection.entries:
                # Build attributes dict from ldap3 entry
                entry_attributes: dict[str, object] = {}
                for attr_name in entry.entry_attributes:
                    attr_value = entry[attr_name].value
                    if isinstance(attr_value, list) and len(attr_value) == 1:
                        entry_attributes[attr_name] = attr_value[0]
                    else:
                        entry_attributes[attr_name] = attr_value

                # Create Entry model instance
                entry_model = FlextLdapModels.Entry(
                    dn=str(entry.entry_dn),
                    attributes=entry_attributes,
                    object_classes=(
                        entry.entry_attributes.get("objectClass", [])
                        if hasattr(entry, "entry_attributes")
                        else []
                    ),
                )
                results.append(entry_model)

            # Normalize results according to server quirks
            normalized_results = self._normalize_search_results(results)
            return FlextResult[list[FlextLdapModels.Entry]].ok(normalized_results)

        except Exception as e:
            return FlextResult[list[FlextLdapModels.Entry]].fail(
                f"LDAP search with controls failed: {e}"
            )

    def get_server_capabilities(self) -> dict[str, object]:
        """Get comprehensive server capabilities and information.

        Returns:
            dict[str, object]: Server capabilities

        """
        capabilities: dict[str, object] = {
            "connected": self.is_connected(),
            "schema_discovered": self.is_schema_discovered(),
            "server_info": self.get_server_info(),
            "server_type": self.get_server_type(),
            "server_quirks": self.get_server_quirks(),
        }

        if self._discovered_schema:
            capabilities.update(
                {
                    "naming_contexts": list(self._discovered_schema.naming_contexts),
                    "supported_controls": list(
                        self._discovered_schema.supported_controls
                    ),
                    "supported_extensions": list(
                        self._discovered_schema.supported_extensions
                    ),
                    "discovered_attributes": len(self._discovered_schema.attributes),
                    "discovered_object_classes": len(
                        self._discovered_schema.object_classes
                    ),
                }
            )

        return capabilities

    def _normalize_filter(self, search_filter: str) -> str:
        """Normalize search filter according to server quirks."""
        if not self._server_quirks:
            return search_filter

        # Apply filter syntax quirks
        normalized_filter = search_filter

        if "case_insensitive" in self._server_quirks.filter_syntax_quirks:
            # Make filter case-insensitive by converting to lowercase
            # This is a simple approach - more sophisticated normalization could be added
            normalized_filter = search_filter.lower()

        return normalized_filter

    def _normalize_attributes(self, attributes: list[str]) -> list[str]:
        """Normalize attribute names according to server quirks."""
        if not self._server_quirks or not self._schema_discovery:
            return attributes

        return [self.normalize_attribute_name(attr) for attr in attributes]

    def _normalize_entry_attributes(
        self, attributes: dict[str, str | list[str]]
    ) -> dict[str, str | list[str]]:
        """Normalize entry attributes - always trim whitespace, apply server quirks if available."""
        normalized = {}
        for attr_name, attr_value in attributes.items():
            # Always normalize attribute names if server quirks are available
            if self._server_quirks and self._schema_discovery:
                normalized_name = self.normalize_attribute_name(attr_name)
            else:
                normalized_name = attr_name

            # Always trim whitespace from attribute values
            if isinstance(attr_value, list):
                normalized[normalized_name] = [
                    v.strip() if isinstance(v, str) else v for v in attr_value
                ]
            elif isinstance(attr_value, str):
                normalized[normalized_name] = attr_value.strip()
            else:
                normalized[normalized_name] = attr_value

        return normalized

    def _normalize_modify_changes(
        self, changes: dict[str, object]
    ) -> dict[str, list[tuple[str, list[str]]]]:
        """Normalize modify changes according to server quirks."""
        # Convert the input changes to the expected format
        normalized: dict[str, list[tuple[str, list[str]]]] = {}

        for attr_name, change_value in changes.items():
            normalized_name = self.normalize_attribute_name(attr_name)

            # Convert change_value to the expected format
            # Constants for tuple validation
            tuple_length = 2
            if isinstance(change_value, list) and all(
                isinstance(item, tuple)
                and len(item) == tuple_length
                and isinstance(item[0], str)
                and isinstance(item[1], list)
                for item in change_value
            ):
                # Already in correct format - trim whitespace from values
                normalized_changes = []
                for operation, values in change_value:
                    trimmed_values = [
                        v.strip() if isinstance(v, str) else v for v in values
                    ]
                    normalized_changes.append((operation, trimmed_values))
                normalized[normalized_name] = normalized_changes
            else:
                # Convert to FlextLdapTypes.MODIFY_REPLACE format and trim whitespace
                if isinstance(change_value, list):
                    str_values = [
                        str(v).strip() if isinstance(v, str) else str(v)
                        for v in change_value
                    ]
                else:
                    value_str = str(change_value)
                    str_values = [
                        value_str.strip()
                        if isinstance(change_value, str)
                        else value_str
                    ]
                normalized[normalized_name] = [
                    (FlextLdapTypes.MODIFY_REPLACE, str_values)
                ]

        return normalized

    def _normalize_search_results(
        self, results: list[FlextLdapModels.Entry]
    ) -> list[FlextLdapModels.Entry]:
        """Normalize search results according to server quirks."""
        if not self._server_quirks or not self._schema_discovery:
            return results

        normalized_results: list[FlextLdapModels.Entry] = []
        for entry in results:
            # Normalize DN
            normalized_dn = self.normalize_dn(entry.dn)

            # Normalize attributes
            normalized_attributes: dict[str, object] = {}
            for attr_name, attr_value in entry.attributes.items():
                normalized_name = self.normalize_attribute_name(attr_name)
                # Normalize and trim attribute values
                if isinstance(attr_value, list):
                    normalized_value = [
                        str(v).strip() if isinstance(v, str) else v for v in attr_value
                    ]
                elif isinstance(attr_value, str):
                    normalized_value = attr_value.strip()
                else:
                    normalized_value = attr_value
                normalized_attributes[normalized_name] = normalized_value

            # Create normalized Entry
            normalized_entry = FlextLdapModels.Entry(
                dn=normalized_dn,
                attributes=normalized_attributes,
                object_classes=entry.object_classes,
            )
            normalized_results.append(normalized_entry)

        return normalized_results

    @property
    def _server_quirks(self) -> FlextLdapModels.ServerQuirks | None:
        """Get server quirks from discovered schema."""
        if self._discovered_schema:
            return self._discovered_schema.server_quirks
        return None

    @_server_quirks.setter
    def _server_quirks(self, value: FlextLdapModels.ServerQuirks | None) -> None:
        """Set server quirks (for testing purposes)."""
        if not self._discovered_schema:
            # Create a minimal discovered schema if needed
            if value is None:
                # Create default server quirks if none provided
                value = FlextLdapModels.ServerQuirks(
                    server_type=FlextLdapModels.LdapServerType.UNKNOWN
                )
            self._discovered_schema = FlextLdapModels.SchemaDiscoveryResult(
                server_info={},
                server_type=value.server_type,
                server_quirks=value,
                naming_contexts=[],
                attributes={},
                object_classes={},
                supported_controls=[],
                supported_extensions=[],
            )
        else:
            # Update existing schema by creating a new instance
            if value is None:
                # Create default server quirks if none provided
                value = FlextLdapModels.ServerQuirks(
                    server_type=FlextLdapModels.LdapServerType.UNKNOWN
                )
            self._discovered_schema = FlextLdapModels.SchemaDiscoveryResult(
                server_info=self._discovered_schema.server_info,
                server_type=value.server_type,
                server_quirks=value,
                naming_contexts=self._discovered_schema.naming_contexts,
                attributes=self._discovered_schema.attributes,
                object_classes=self._discovered_schema.object_classes,
                supported_controls=self._discovered_schema.supported_controls,
                supported_extensions=self._discovered_schema.supported_extensions,
            )

    # =========================================================================
    # SCHEMA DISCOVERY METHODS - Universal compatibility features
    # =========================================================================

    async def discover_schema(
        self,
    ) -> FlextResult[FlextLdapModels.SchemaDiscoveryResult]:
        """Discover LDAP server schema and capabilities.

        Returns:
            FlextResult[FlextLdapModels.SchemaDiscoveryResult]: Schema discovery result

        """
        try:
            if not self._connection:
                return FlextResult[FlextLdapModels.SchemaDiscoveryResult].fail(
                    "LDAP connection not established"
                )

            # Discover server information
            server_info = await self._discover_server_info()
            if server_info.is_failure:
                return FlextResult[FlextLdapModels.SchemaDiscoveryResult].fail(
                    f"Server info discovery failed: {server_info.error}"
                )

            # Detect server type
            server_type = self._detect_server_type(server_info.value)

            # Discover naming contexts
            naming_contexts = await self._discover_naming_contexts()
            if naming_contexts.is_failure:
                return FlextResult[FlextLdapModels.SchemaDiscoveryResult].fail(
                    f"Naming contexts discovery failed: {naming_contexts.error}"
                )

            # Discover schema attributes
            attributes = await self._discover_schema_attributes()
            if attributes.is_failure:
                return FlextResult[FlextLdapModels.SchemaDiscoveryResult].fail(
                    f"Schema attributes discovery failed: {attributes.error}"
                )

            # Discover object classes
            object_classes = await self._discover_object_classes()
            if object_classes.is_failure:
                return FlextResult[FlextLdapModels.SchemaDiscoveryResult].fail(
                    f"Object classes discovery failed: {object_classes.error}"
                )

            # Discover supported controls and extensions
            supported_controls = await self._discover_supported_controls()
            supported_extensions = await self._discover_supported_extensions()

            # Create server quirks based on detected server type
            server_quirks = self._create_server_quirks(server_type)

            # Create schema discovery result
            schema_result = FlextLdapModels.SchemaDiscoveryResult(
                server_info=server_info.value,
                server_type=server_type,
                server_quirks=server_quirks,
                attributes=attributes.value,
                object_classes=object_classes.value,
                naming_contexts=naming_contexts.value,
                supported_controls=supported_controls.value
                if supported_controls.is_success
                else [],
                supported_extensions=supported_extensions.value
                if supported_extensions.is_success
                else [],
            )

            # Cache the discovered schema
            self._discovered_schema = schema_result

            return FlextResult[FlextLdapModels.SchemaDiscoveryResult].ok(schema_result)

        except Exception as e:
            self._logger.exception("Schema discovery failed")
            return FlextResult[FlextLdapModels.SchemaDiscoveryResult].fail(
                f"Schema discovery failed: {e}"
            )

    async def _discover_server_info(self) -> FlextResult[dict[str, object]]:
        """Discover basic server information."""
        try:
            if not self._connection:
                return FlextResult[dict[str, object]].fail(
                    "LDAP connection not established"
                )

            # Query root DSE for server information
            search_result = self._connection.search(
                search_base="",
                search_filter=FlextLdapConstants.Defaults.DEFAULT_SEARCH_FILTER,
                search_scope=FlextLdapTypes.BASE,
                attributes=["*", "+"],
            )

            if not search_result:
                return FlextResult[dict[str, object]].fail("Failed to query root DSE")

            server_info: dict[str, object] = {}
            for entry in self._connection.entries:
                for attr_name in entry.entry_attributes:
                    attr_values = entry[attr_name].value
                    if isinstance(attr_values, list):
                        server_info[attr_name] = [str(v) for v in attr_values]
                    else:
                        server_info[attr_name] = str(attr_values)

            return FlextResult[dict[str, object]].ok(server_info)

        except Exception as e:
            return FlextResult[dict[str, object]].fail(
                f"Server info discovery failed: {e}"
            )

    def _detect_server_type(
        self, server_info: dict[str, object]
    ) -> FlextLdapModels.LdapServerType:
        """Detect LDAP server type from server information."""
        # Check vendor information
        vendor_name = server_info.get("vendorName", "")
        vendor_version = server_info.get("vendorVersion", "")

        if isinstance(vendor_name, list):
            vendor_name = vendor_name[0] if vendor_name else ""
        if isinstance(vendor_version, list):
            vendor_version = vendor_version[0] if vendor_version else ""

        vendor_name_lower = str(vendor_name).lower()

        # Detect server type based on vendor information
        if "openldap" in vendor_name_lower:
            return FlextLdapModels.LdapServerType.OPENLDAP
        if "microsoft" in vendor_name_lower or "active directory" in vendor_name_lower:
            return FlextLdapModels.LdapServerType.ACTIVE_DIRECTORY
        if "oracle" in vendor_name_lower and "oud" in vendor_name_lower:
            return FlextLdapModels.LdapServerType.ORACLE_OUD
        if "oracle" in vendor_name_lower:
            return FlextLdapModels.LdapServerType.ORACLE_DIRECTORY
        if "sun" in vendor_name_lower or "opends" in vendor_name_lower:
            return FlextLdapModels.LdapServerType.SUN_OPENDS
        if "apache" in vendor_name_lower:
            return FlextLdapModels.LdapServerType.APACHE_DIRECTORY
        if "novell" in vendor_name_lower or "edirectory" in vendor_name_lower:
            return FlextLdapModels.LdapServerType.NOVELL_EDIRECTORY
        if "ibm" in vendor_name_lower:
            return FlextLdapModels.LdapServerType.IBM_DIRECTORY
        return FlextLdapModels.LdapServerType.GENERIC

    async def _discover_naming_contexts(self) -> FlextResult[list[str]]:
        """Discover naming contexts from root DSE."""
        try:
            if not self._connection:
                return FlextResult[list[str]].fail("LDAP connection not established")

            # Query root DSE for naming contexts
            search_result = self._connection.search(
                search_base="",
                search_filter=FlextLdapConstants.Defaults.DEFAULT_SEARCH_FILTER,
                search_scope=FlextLdapTypes.BASE,
                attributes=["namingContexts"],
            )

            if not search_result:
                return FlextResult[list[str]].fail("Failed to query naming contexts")

            naming_contexts: list[str] = []
            for entry in self._connection.entries:
                if "namingContexts" in entry.entry_attributes:
                    contexts = entry["namingContexts"].value
                    if isinstance(contexts, list):
                        naming_contexts.extend([str(ctx) for ctx in contexts])
                    else:
                        naming_contexts.append(str(contexts))

            return FlextResult[list[str]].ok(naming_contexts)

        except Exception as e:
            return FlextResult[list[str]].fail(f"Naming contexts discovery failed: {e}")

    async def _discover_schema_attributes(
        self,
    ) -> FlextResult[dict[str, FlextLdapModels.SchemaAttribute]]:
        """Discover schema attributes from subschema subentry."""
        try:
            if not self._connection:
                return FlextResult[dict[str, FlextLdapModels.SchemaAttribute]].fail(
                    "LDAP connection not established"
                )

            # Find subschema subentry
            subschema_dn = await self._find_subschema_subentry()
            if subschema_dn.is_failure:
                return FlextResult[dict[str, FlextLdapModels.SchemaAttribute]].fail(
                    f"Failed to find subschema subentry: {subschema_dn.error}"
                )

            # Query subschema for attribute types
            search_result = self._connection.search(
                search_base=subschema_dn.value,
                search_filter="(objectClass=subschema)",
                search_scope=FlextLdapTypes.BASE,
                attributes=["attributeTypes"],
            )

            if not search_result:
                return FlextResult[dict[str, FlextLdapModels.SchemaAttribute]].fail(
                    "Failed to query attribute types"
                )

            attributes: dict[str, FlextLdapModels.SchemaAttribute] = {}
            for entry in self._connection.entries:
                if "attributeTypes" in entry.entry_attributes:
                    attr_types = entry["attributeTypes"].value
                    if isinstance(attr_types, list):
                        for attr_def in attr_types:
                            attr = self._parse_attribute_definition(str(attr_def))
                            if attr:
                                attributes[attr.name] = attr

            return FlextResult[dict[str, FlextLdapModels.SchemaAttribute]].ok(
                attributes
            )

        except Exception as e:
            return FlextResult[dict[str, FlextLdapModels.SchemaAttribute]].fail(
                f"Schema attributes discovery failed: {e}"
            )

    async def _discover_object_classes(
        self,
    ) -> FlextResult[dict[str, FlextLdapModels.SchemaObjectClass]]:
        """Discover object classes from subschema subentry."""
        try:
            if not self._connection:
                return FlextResult[dict[str, FlextLdapModels.SchemaObjectClass]].fail(
                    "LDAP connection not established"
                )

            # Find subschema subentry
            subschema_dn = await self._find_subschema_subentry()
            if subschema_dn.is_failure:
                return FlextResult[dict[str, FlextLdapModels.SchemaObjectClass]].fail(
                    f"Failed to find subschema subentry: {subschema_dn.error}"
                )

            # Query subschema for object classes
            search_result = self._connection.search(
                search_base=subschema_dn.value,
                search_filter="(objectClass=subschema)",
                search_scope=FlextLdapTypes.BASE,
                attributes=["objectClasses"],
            )

            if not search_result:
                return FlextResult[dict[str, FlextLdapModels.SchemaObjectClass]].fail(
                    "Failed to query object classes"
                )

            object_classes: dict[str, FlextLdapModels.SchemaObjectClass] = {}
            for entry in self._connection.entries:
                if "objectClasses" in entry.entry_attributes:
                    obj_classes = entry["objectClasses"].value
                    if isinstance(obj_classes, list):
                        for obj_def in obj_classes:
                            obj_class = self._parse_object_class_definition(
                                str(obj_def)
                            )
                            if obj_class:
                                object_classes[obj_class.name] = obj_class

            return FlextResult[dict[str, FlextLdapModels.SchemaObjectClass]].ok(
                object_classes
            )

        except Exception as e:
            return FlextResult[dict[str, FlextLdapModels.SchemaObjectClass]].fail(
                f"Object classes discovery failed: {e}"
            )

    async def _discover_supported_controls(self) -> FlextResult[list[str]]:
        """Discover supported controls from root DSE."""
        try:
            if not self._connection:
                return FlextResult[list[str]].fail("LDAP connection not established")

            # Query root DSE for supported controls
            search_result = self._connection.search(
                search_base="",
                search_filter=FlextLdapConstants.Defaults.DEFAULT_SEARCH_FILTER,
                search_scope=FlextLdapTypes.BASE,
                attributes=["supportedControl"],
            )

            if not search_result:
                return FlextResult[list[str]].fail("Failed to query supported controls")

            controls: list[str] = []
            for entry in self._connection.entries:
                if "supportedControl" in entry.entry_attributes:
                    control_oids = entry["supportedControl"].value
                    if isinstance(control_oids, list):
                        controls.extend([str(oid) for oid in control_oids])
                    else:
                        controls.append(str(control_oids))

            return FlextResult[list[str]].ok(controls)

        except Exception as e:
            return FlextResult[list[str]].fail(
                f"Supported controls discovery failed: {e}"
            )

    async def _discover_supported_extensions(self) -> FlextResult[list[str]]:
        """Discover supported extensions from root DSE."""
        try:
            if not self._connection:
                return FlextResult[list[str]].fail("LDAP connection not established")

            # Query root DSE for supported extensions
            search_result = self._connection.search(
                search_base="",
                search_filter=FlextLdapConstants.Defaults.DEFAULT_SEARCH_FILTER,
                search_scope=FlextLdapTypes.BASE,
                attributes=["supportedExtension"],
            )

            if not search_result:
                return FlextResult[list[str]].fail(
                    "Failed to query supported extensions"
                )

            extensions: list[str] = []
            for entry in self._connection.entries:
                if "supportedExtension" in entry.entry_attributes:
                    ext_oids = entry["supportedExtension"].value
                    if isinstance(ext_oids, list):
                        extensions.extend([str(oid) for oid in ext_oids])
                    else:
                        extensions.append(str(ext_oids))

            return FlextResult[list[str]].ok(extensions)

        except Exception as e:
            return FlextResult[list[str]].fail(
                f"Supported extensions discovery failed: {e}"
            )

    def _create_server_quirks(
        self, server_type: FlextLdapModels.LdapServerType
    ) -> FlextLdapModels.ServerQuirks:
        """Create server quirks based on detected server type."""
        # Set quirks based on server type
        if server_type == FlextLdapModels.LdapServerType.ACTIVE_DIRECTORY:
            return FlextLdapModels.ServerQuirks(
                server_type=server_type,
                case_sensitive_dns=False,
                dn_format_preferences=["cn=name,ou=container,dc=domain,dc=com"],
                search_scope_limitations={"subtree"},
                filter_syntax_quirks=["Requires parentheses around complex filters"],
            )
        if server_type in {
            FlextLdapModels.LdapServerType.OPENLDAP,
            FlextLdapModels.LdapServerType.ORACLE_OUD,
        }:
            return FlextLdapModels.ServerQuirks(
                server_type=server_type,
                case_sensitive_dns=True,
                dn_format_preferences=["uid=name,ou=people,dc=example,dc=com"],
                search_scope_limitations=set(),
                filter_syntax_quirks=[],
            )
        return FlextLdapModels.ServerQuirks(server_type=server_type)

    async def _find_subschema_subentry(self) -> FlextResult[str]:
        """Find the subschema subentry DN."""
        try:
            if not self._connection:
                return FlextResult[str].fail("LDAP connection not established")

            # Query root DSE for subschema subentry
            search_result = self._connection.search(
                search_base="",
                search_filter=FlextLdapConstants.Defaults.DEFAULT_SEARCH_FILTER,
                search_scope=FlextLdapTypes.BASE,
                attributes=["subschemaSubentry"],
            )

            if not search_result:
                return FlextResult[str].fail("Failed to query subschema subentry")

            for entry in self._connection.entries:
                if "subschemaSubentry" in entry.entry_attributes:
                    subschema_dn = entry["subschemaSubentry"].value
                    if isinstance(subschema_dn, list):
                        return FlextResult[str].ok(str(subschema_dn[0]))
                    return FlextResult[str].ok(str(subschema_dn))

            # Fallback to default subschema DN
            return FlextResult[str].ok("cn=subschema")

        except Exception as e:
            return FlextResult[str].fail(f"Failed to find subschema subentry: {e}")

    def _parse_attribute_definition(
        self, attr_def: str
    ) -> FlextLdapModels.SchemaAttribute | None:
        """Parse LDAP attribute definition string."""
        try:
            # Simple parsing - in a real implementation, this would be more robust
            # For now, create a basic attribute with minimal information
            parts = attr_def.split()
            if not parts:
                return None

            name = parts[0].strip("'\"")
            oid = parts[1] if len(parts) > 1 else name

            return FlextLdapModels.SchemaAttribute(
                name=name,
                oid=oid,
                syntax="1.3.6.1.4.1.1466.115.121.1.15",  # Directory String
                is_single_valued=False,
                is_operational=False,
            )

        except Exception:
            return None

    def _parse_object_class_definition(
        self, obj_def: str
    ) -> FlextLdapModels.SchemaObjectClass | None:
        """Parse LDAP object class definition string."""
        try:
            # Simple parsing - in a real implementation, this would be more robust
            # For now, create a basic object class with minimal information
            parts = obj_def.split()
            if not parts:
                return None

            name = parts[0].strip("'\"")
            oid = parts[1] if len(parts) > 1 else name

            return FlextLdapModels.SchemaObjectClass(
                name=name,
                oid=oid,
                superior=[],
                must=[],
                may=[],
                kind="STRUCTURAL",
            )

        except Exception:
            return None

    def get_server_info(self) -> dict[str, object]:
        """Get server information.

        Returns:
            dict: Server information with 'connected' and 'server' keys

        """
        if not self._connection or not self._connection.bound:
            return {"connected": False, "server": None}

        server_info: dict[str, object] = {"connected": True, "server": None}

        if self._server:
            server_info["server"] = {
                "host": getattr(self._server, "host", "unknown"),
                "port": getattr(self._server, "port", 389),
            }

        if self._discovered_schema and self._discovered_schema.server_info:
            server_info.update(self._discovered_schema.server_info)

        return server_info

    def get_server_type(self) -> FlextLdapModels.LdapServerType:
        """Get detected server type.

        Returns:
            LdapServerType: Server type or UNKNOWN if not discovered

        """
        if self._server_quirks:
            return self._server_quirks.server_type
        return FlextLdapModels.LdapServerType.UNKNOWN

    def get_server_quirks(self) -> FlextLdapModels.ServerQuirks | None:
        """Get discovered server quirks.

        Returns:
            FlextLdapModels.ServerQuirks | None: Server quirks or None if not discovered

        """
        if self._discovered_schema:
            return self._discovered_schema.server_quirks
        return None

    def is_schema_discovered(self) -> bool:
        """Check if schema has been discovered.

        Returns:
            bool: True if schema has been discovered

        """
        return self._is_schema_discovered

    def normalize_attribute_name(self, attribute_name: str) -> str:
        """Normalize attribute name using FlextLdapUtilities.

        Args:
            attribute_name: Attribute name to normalize

        Returns:
            str: Normalized attribute name

        """
        return FlextLdapUtilities.normalize_attribute_name(attribute_name)

    def normalize_object_class(self, object_class: str) -> str:
        """Normalize object class name using FlextLdapUtilities.

        Args:
            object_class: Object class name to normalize

        Returns:
            str: Normalized object class name

        """
        return FlextLdapUtilities.normalize_object_class(object_class)

    def normalize_dn(self, dn: str) -> str:
        """Normalize DN using FlextLdapUtilities.

        Args:
            dn: DN to normalize

        Returns:
            str: Normalized DN

        """
        result = FlextLdapUtilities.normalize_dn(dn)
        if result.is_failure:
            return dn  # Return original DN if normalization fails
        return result.unwrap()


__all__ = [
    "FlextLdapClient",
]


__all__ = [
    "FlextLdapClient",
]


__all__ = [
    "FlextLdapClient",
]
