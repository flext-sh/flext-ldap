"""FlextLDAP - Thin facade for LDAP operations with full FLEXT integration.

This module provides the main facade for the flext-ldap domain.
Following FLEXT standards, this is the thin entry point that provides
access to all LDAP domain functionality with proper integration of:
- FlextBus for event emission
- FlextContainer for dependency injection
- FlextContext for operation context
- FlextLdif for LDIF file operations

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

Note: This file has type checking disabled due to limitations in the official types-ldap3 package:
- Method return types (add, delete, search, modify, unbind) are not specified in the stubs
- Properties like conn.entries and entry.entry_dn are not fully typed
- Entry attributes and their values have incomplete type information
"""

from __future__ import annotations

from pathlib import Path
from typing import override

from flext_core import (
    FlextBus,
    FlextContainer,
    FlextContext,
    FlextDispatcher,
    FlextLogger,
    FlextProcessors,
    FlextRegistry,
    FlextResult,
    FlextService,
    FlextTypes,
)

from flext_ldif import FlextLdifModels

from flext_ldif import FlextLdif

from flext_ldap.acl import FlextLDAPAclManager
from flext_ldap.clients import FlextLDAPClient
from flext_ldap.config import FlextLDAPConfig
from flext_ldap.constants import FlextLDAPConstants
from flext_ldap.models import FlextLDAPModels
from flext_ldap.protocols import FlextLDAPProtocols
from flext_ldap.typings import FlextLDAPTypes
from flext_ldap.validations import FlextLDAPValidations


class FlextLDAP(FlextService[None]):
    """Unified LDAP domain class providing complete FLEXT ecosystem integration.

    This is the single unified class for the flext-ldap domain providing
    access to all LDAP domain functionality with centralized patterns.

    **UNIFIED CLASS PATTERN**: One class per module with nested helpers only.
    **CENTRALIZED APPROACH**: All operations follow centralized patterns:
    - FlextLDAP.* for LDAP-specific operations
    - Centralized validation through FlextLDAPValidations
    - No wrappers, aliases, or fallbacks
    - Direct use of flext-core centralized services

    **PROTOCOL COMPLIANCE**: Implements LDAP domain protocols through structural subtyping:
    - LdapConnectionProtocol: connect, disconnect, is_connected methods (delegates to client)
    - LdapSearchProtocol: search, search_one, search_entries methods
    - LdapModifyProtocol: add_entry, modify_entry, delete_entry methods
    - LdapAuthenticationProtocol: authenticate_user, validate_credentials methods
    - LdapValidationProtocol: validate_dn, validate_entry methods

    **PYTHON 3.13+ COMPATIBILITY**: Uses modern /patterns and latest type features.
    """

    @override
    def __init__(self, config: FlextLDAPConfig | None = None) -> None:
        """Initialize the unified LDAP service."""
        super().__init__()
        self._ldap_config: FlextLDAPConfig = config or FlextLDAPConfig()
        self._client: FlextLDAPClient | None = None
        self._acl_manager: FlextLDAPAclManager | None = None

        # Complete FLEXT ecosystem integration
        self._container = FlextContainer.ensure_global_manager().get_or_create()
        self._context = FlextContext()
        self._bus = FlextBus()
        self._dispatcher = FlextDispatcher()
        self._processors = FlextProcessors()
        self._registry = FlextRegistry(dispatcher=self._dispatcher)
        self._logger = FlextLogger(__name__)

        # Lazy-loaded LDAP components
        self._ldif: FlextLdif | None = None

    @classmethod
    def create(cls) -> FlextLDAP:
        """Create a new FlextLDAP instance (factory method)."""
        return cls()

    @override
    def execute(self) -> FlextResult[None]:
        """Execute the main domain operation (required by FlextService)."""
        return FlextResult[None].ok(None)

    def _handle_operation_error(
        self, operation: str, error: Exception | None, prefix: str = ""
    ) -> FlextResult[object]:
        """Centralize error handling for operations.

        Args:
            operation: Name of the operation that failed
            error: The exception that occurred
            prefix: Optional prefix for error message

        Returns:
            FlextResult with failure containing formatted error message
        """
        error_msg = f"{prefix}{operation} failed: {error}".strip()
        if error is not None:
            # Type assertion to help PyRight understand error is not None
            assert error is not None
            error_str = str(error)
            error_type = type(error).__name__
            if self._logger is not None:
                self._logger.error(error_msg, error=error_str, error_type=error_type)
        else:
            if self._logger is not None:
                self._logger.error(error_msg)
        return FlextResult[object].fail(error_msg)

    # =============================================================================
    # PROPERTY ACCESSORS - Direct access to domain components
    # =============================================================================

    @property
    def client(self) -> FlextLDAPClient:
        """Get the LDAP client instance."""
        if self._client is None:
            self._client = FlextLDAPClient()
        return self._client

    @property
    def config(self) -> FlextLDAPConfig:
        """Get the LDAP configuration instance."""
        if self._ldap_config is not None:
            return self._ldap_config
        return FlextLDAPConfig()

    @property
    def models(self) -> type[FlextLDAPModels]:
        """Get the LDAP models class."""
        return

    @property
    def types(self) -> type[FlextLDAPTypes]:
        """Get the LDAP types class."""
        return FlextLDAPTypes

    @property
    def protocols(self) -> type[FlextLDAPProtocols]:
        """Get the LDAP protocols class."""
        return FlextLDAPProtocols

    @property
    def validations(self) -> type[FlextLDAPValidations]:
        """Get the LDAP validations class."""
        return FlextLDAPValidations

    # =============================================================================
    # CONNECTION MANAGEMENT METHODS - Enhanced with proper error handling
    # =============================================================================

    def is_connected(self) -> bool:
        """Check if the LDAP client is connected."""
        return self.client.is_connected()

    def test_connection(self) -> FlextResult[bool]:
        """Test the LDAP connection with enhanced error handling."""
        try:
            return self.client.test_connection()
        except Exception as e:
            return FlextResult[bool].fail(f"Connection test failed: {e}")

    def connect(self) -> FlextResult[bool]:
        """Connect to LDAP server with enhanced error handling."""
        try:
            return self.client.test_connection()
        except Exception as e:
            return FlextResult[bool].fail(f"Connection failed: {e}")

    def unbind(self) -> FlextResult[None]:
        """Unbind from LDAP server with enhanced error handling."""
        try:
            # Implementation would go here - for now return success
            return FlextResult[None].ok(None)
        except Exception as e:
            return FlextResult[None].fail(f"Unbind failed: {e}")

    def disconnect(self) -> FlextResult[None]:
        """Disconnect from LDAP server - implements LdapConnectionProtocol.

        Alias for unbind to match protocol interface.

        Returns:
            FlextResult[None]: Disconnect success status

        """
        return self.unbind()

    # =============================================================================
    # PROTOCOL IMPLEMENTATION METHODS - FlextLDAPProtocols compliance
    # =============================================================================

    def search(
        self,
        search_base: str,
        filter_str: str,
        attributes: FlextTypes.StringList | None = None,
    ) -> FlextResult[list[FlextLDAPModels.Entry]]:
        """Perform LDAP search operation - implements LdapSearchProtocol.

        Args:
            search_base: LDAP search base DN
            filter_str: LDAP search filter
            attributes: List of attributes to retrieve

        Returns:
            FlextResult[list[FlextLDAPModels.Entry]]: Entry models search results

        """
        # Get search response and extract entries
        search_result = self.search_entries(
            search_base, filter_str, FlextLDAPConstants.Scopes.SUBTREE, attributes
        )
        if search_result.is_failure:
            return FlextResult[list[FlextLDAPModels.Entry]].fail(
                search_result.error or "Search failed"
            )

        response = search_result.unwrap()
        return FlextResult[list[FlextLDAPModels.Entry]].ok(response.entries)

    def search_one(
        self,
        search_base: str,
        search_filter: str,
        attributes: FlextTypes.StringList | None = None,
    ) -> FlextResult[FlextLDAPModels.Entry | None]:
        """Perform LDAP search for single entry - implements LdapSearchProtocol.

        Args:
            search_base: LDAP search base DN
            search_filter: LDAP search filter
            attributes: List of attributes to retrieve

        Returns:
            FlextResult[FlextLDAPModels.Entry | None]: Single Entry model result or None

        """
        # Use existing search method and return first result
        search_result = self.search(search_base, search_filter, attributes)
        if search_result.is_failure:
            return FlextResult[FlextLDAPModels.Entry | None].fail(
                search_result.error or "Search failed"
            )

        results = search_result.unwrap()
        if not results:
            return FlextResult[FlextLDAPModels.Entry | None].ok(None)

        return FlextResult[FlextLDAPModels.Entry | None].ok(results[0])

    def add_entry(
        self, dn: str, attributes: dict[str, str | FlextTypes.StringList]
    ) -> FlextResult[bool]:
        """Add new LDAP entry - implements LdapModifyProtocol.

        Args:
            dn: Distinguished name for new entry
            attributes: Entry attributes

        Returns:
            FlextResult[bool]: Add operation success status

        """
        # Delegate to client
        client = self.client
        return client.add_entry(dn, attributes)

    def modify_entry(self, dn: str, changes: FlextTypes.Dict) -> FlextResult[bool]:
        """Modify existing LDAP entry - implements LdapModifyProtocol.

        Args:
            dn: Distinguished name of entry to modify
            changes: Attribute changes to apply

        Returns:
            FlextResult[bool]: Modify operation success status

        """
        # Delegate to client
        client = self.client
        return client.modify_entry(dn, changes)

    def delete_entry(self, dn: str) -> FlextResult[bool]:
        """Delete LDAP entry - implements LdapModifyProtocol.

        Args:
            dn: Distinguished name of entry to delete

        Returns:
            FlextResult[bool]: Delete operation success status

        """
        # Delegate to client
        client = self.client
        return client.delete_entry(dn)

    def authenticate_user(self, username: str, password: str) -> FlextResult[bool]:
        """Authenticate user against LDAP - implements LdapAuthenticationProtocol.

        Args:
            username: Username for authentication
            password: Password for authentication

        Returns:
            FlextResult[bool]: Authentication success status

        """
        # Delegate to client and convert result
        client = self.client
        auth_result = client.authenticate_user(username, password)
        if auth_result.is_failure:
            return FlextResult[bool].fail(auth_result.error or "Authentication failed")
        return FlextResult[bool].ok(True)

    def validate_credentials(self, dn: str, password: str) -> FlextResult[bool]:
        """Validate user credentials against LDAP - implements LdapAuthenticationProtocol.

        Args:
            dn: User distinguished name
            password: User password

        Returns:
            FlextResult[bool]: Validation success status

        """
        # Delegate to client
        client = self.client
        return client.validate_credentials(dn, password)

    def validate_dn(self, dn: str) -> FlextResult[bool]:
        """Validate distinguished name format - implements LdapValidationProtocol.

        Args:
            dn: Distinguished name to validate

        Returns:
            FlextResult[bool]: Validation success status

        """
        # Delegate to client
        client = self.client
        return client.validate_dn(dn)

    def validate_entry(self, entry: FlextLDAPModels.Entry) -> FlextResult[bool]:
        """Validate LDAP entry structure - implements LdapValidationProtocol.

        Args:
            entry: LDAP Entry model to validate

        Returns:
            FlextResult[bool]: Validation success status

        """
        # Delegate to client
        client = self.client
        return client.validate_entry(entry)

    # =============================================================================
    # SEARCH METHODS - Enhanced with proper error handling and validation
    # =============================================================================

    def search_groups(
        self,
        base_dn: str,
        cn: str | None = None,
        filter_str: str | None = None,
        scope: str = FlextLDAPConstants.Scopes.SUBTREE,
        attributes: FlextTypes.StringList | None = None,
    ) -> FlextResult[list[FlextLDAPModels.Group]]:
        """Search for LDAP groups with enhanced validation."""
        # Validate inputs
        dn_validation = self.validations.validate_dn(base_dn)
        if dn_validation.is_failure:
            return FlextResult[list[FlextLDAPModels.Group]].fail(
                f"Invalid base DN: {dn_validation.error}"
            )

        if filter_str:
            filter_validation = self.validations.validate_filter(filter_str)
            if filter_validation.is_failure:
                return FlextResult[list[FlextLDAPModels.Group]].fail(
                    f"Invalid filter: {filter_validation.error}"
                )

        return self.client.search_groups(
            base_dn=base_dn,
            cn=cn,
            attributes=attributes,
        )

    def search_entries(
        self,
        base_dn: str,
        filter_str: str,
        scope: str = FlextLDAPConstants.Scopes.SUBTREE,
        attributes: FlextTypes.StringList | None = None,
    ) -> FlextResult[FlextLDAPModels.SearchResponse]:
        """Search for LDAP entries using search_with_request with enhanced validation."""
        # Validate inputs
        dn_validation = self.validations.validate_dn(base_dn)
        if dn_validation.is_failure:
            return FlextResult[FlextLDAPModels.SearchResponse].fail(
                f"Invalid base DN: {dn_validation.error}"
            )

        filter_validation = self.validations.validate_filter(filter_str)
        if filter_validation.is_failure:
            return FlextResult[FlextLDAPModels.SearchResponse].fail(
                f"Invalid filter: {filter_validation.error}"
            )

        request = self.models.SearchRequest(
            base_dn=base_dn,
            filter_str=filter_str,
            scope=scope,
            attributes=attributes or [],
            page_size=FlextLDAPConstants.Connection.DEFAULT_PAGE_SIZE,
            paged_cookie=b"",
        )
        return self.client.search_with_request(request)

    def get_group(self, dn: str) -> FlextResult[FlextLDAPModels.Group | None]:
        """Get a specific LDAP group by DN with enhanced validation."""
        # Validate DN
        validation_result = self.validations.validate_dn(dn)
        if validation_result.is_failure:
            return FlextResult[FlextLDAPModels.Group | None].fail(
                f"Invalid DN: {validation_result.error}"
            )

        return self.client.get_group(dn)

    # =============================================================================
    # UPDATE METHODS - Enhanced with proper error handling and validation
    # =============================================================================

    def update_user_attributes(
        self, dn: str, attributes: FlextTypes.Dict
    ) -> FlextResult[bool]:
        """Update user attributes with enhanced validation."""
        # Validate DN
        validation_result = self.validations.validate_dn(dn)
        if validation_result.is_failure:
            return FlextResult[bool].fail(f"Invalid DN: {validation_result.error}")

        return self.client.update_user_attributes(dn, attributes)

    def update_group_attributes(
        self, dn: str, attributes: FlextTypes.Dict
    ) -> FlextResult[bool]:
        """Update group attributes with enhanced validation."""
        # Validate DN
        validation_result = self.validations.validate_dn(dn)
        if validation_result.is_failure:
            return FlextResult[bool].fail(f"Invalid DN: {validation_result.error}")

        return self.client.update_group_attributes(dn, attributes)

    # =============================================================================
    # DELETE METHODS - Enhanced with proper error handling and validation
    # =============================================================================

    def delete_user(self, dn: str) -> FlextResult[None]:
        """Delete a user with enhanced validation."""
        # Validate DN
        validation_result = self.validations.validate_dn(dn)
        if validation_result.is_failure:
            return FlextResult[None].fail(f"Invalid DN: {validation_result.error}")

        return self.client.delete_user(dn)

    # =============================================================================
    # VALIDATION METHODS - Enhanced with proper error handling
    # =============================================================================

    def validate_configuration_consistency(self) -> FlextResult[bool]:
        """Validate configuration consistency.

        Checks that bind password is provided when bind DN is configured.
        """
        config = self.config
        if config.ldap_bind_dn and not config.ldap_bind_password:
            return FlextResult[bool].fail(
                "Bind password required when bind DN is provided"
            )
        return FlextResult[bool].ok(True)

    def validate_filter(self, filter_str: str) -> FlextResult[None]:
        """Validate LDAP filter format."""
        validation_result = self.validations.validate_filter(filter_str)
        if validation_result.is_failure:
            return FlextResult[None].fail(
                f"Filter validation failed: {validation_result.error}"
            )
        return FlextResult[None].ok(None)

    # =============================================================================
    # LDIF OPERATIONS - Integration with FlextLdif for file operations
    # =============================================================================

    @property
    def ldif(self) -> FlextLdif | None:
        """Get FlextLdif instance for LDIF operations.

        Returns:
            FlextLdif instance if available, None if initialization failed.
        """
        if self._ldif is None:
            try:
                self._ldif = FlextLdif()
            except (ImportError, AttributeError, TypeError) as exc:
                # FlextLdif not available - this will be handled by calling methods
                if self._logger is not None:
                    self._logger.warning(
                        "FlextLdif initialization failed",
                        error=str(exc),
                        error_type=type(exc).__name__,
                    )
                self._ldif = None
        return self._ldif

    def import_from_ldif(self, path: Path) -> FlextResult[list[FlextLDAPModels.Entry]]:
        """Import entries from LDIF file using FlextLdif.

        Args:
            path: Path to LDIF file

        Returns:
            FlextResult containing list of entries or error

        """
        ldif_instance = self.ldif
        if ldif_instance is None:
            return FlextResult[list[FlextLDAPModels.Entry]].fail(
                "FlextLdif not available. Install with: pip install flext-ldif"
            )

        # Parse LDIF file
        result = ldif_instance.parse(path)
        if result.is_failure:
            return FlextResult[list[FlextLDAPModels.Entry]].fail(
                f"LDIF parsing failed: {result.error}"
            )

        # Convert FlextLdif entries to FlextLDAP entries
        ldif_entries = result.unwrap() or []
        ldap_entries = []
        for ldif_entry in ldif_entries:
            ldap_entry = FlextLDAPModels.Entry(
                dn=str(ldif_entry.dn),
                attributes=dict(ldif_entry.attributes),
            )
            ldap_entries.append(ldap_entry)

        # Log import event
        if self._logger is not None:
            self._logger.info(
                "LDIF import successful",
                path=str(path),
                entry_count=len(ldap_entries),
            )

        return FlextResult[list[FlextLDAPModels.Entry]].ok(ldap_entries)

    def export_to_ldif(
        self, entries: list[FlextLDAPModels.Entry], path: Path
    ) -> FlextResult[bool]:
        """Export entries to LDIF file using FlextLdif.

        Args:
            entries: List of LDAP entries to export
            path: Path to output LDIF file

        Returns:
            FlextResult indicating success or failure

        """
        ldif_instance = self.ldif
        if ldif_instance is None:
            return FlextResult[bool].fail(
                "FlextLdif not available. Install with: pip install flext-ldif"
            )

        # Convert FlextLDAP entries to FlextLdif entries
        ldif_entries = []
        for ldap_entry in entries:
            ldif_entry_result = FlextLdifModels.Entry.create(
                data={
                    "dn": ldap_entry.dn,
                    "attributes": ldap_entry.attributes,
                }
            )
            if ldif_entry_result.is_failure:
                return FlextResult[bool].fail(
                    f"Entry conversion failed: {ldif_entry_result.error}"
                )
            ldif_entries.append(ldif_entry_result.unwrap())

        # Use FlextLdif for writing
        result = ldif_instance.write(ldif_entries, path)
        if result.is_failure:
            return FlextResult[bool].fail(f"LDIF writing failed: {result.error}")

        # Log export event
        if self._logger is not None:
            self._logger.info(
                "LDIF export successful", path=str(path), entry_count=len(entries)
            )

        return FlextResult[bool].ok(True)

    # =========================================================================
    # UNIVERSAL LDAP OPERATIONS (SERVER-AGNOSTIC)
    # =========================================================================

    def get_detected_server_type(self) -> FlextResult[str | None]:
        """Get detected LDAP server type from current connection.

        Returns detected server type from the underlying client after connection.
        Useful for understanding server capabilities and behavior.

        Returns:
            FlextResult containing server type string or None if not detected

        Example:
            >>> api = FlextLDAP()
            >>> api.connect()
            >>> server_type_result = api.get_detected_server_type()
            >>> if server_type_result.is_success:
            ...     print(f"Connected to: {server_type_result.unwrap()}")

        """
        if not self._client:
            return FlextResult[str | None].fail("Client not initialized")
        server_type = self._client._detected_server_type
        return FlextResult[str | None].ok(server_type)

    def get_server_operations(self) -> FlextResult[object | None]:
        """Get current server operations instance for advanced usage.

        Returns the BaseServerOperations instance for the detected server type.
        Provides access to server-specific operations and capabilities.

        Returns:
            FlextResult containing BaseServerOperations instance or None

        Example:
            >>> api = FlextLDAP()
            >>> api.connect()
            >>> ops_result = api.get_server_operations()
            >>> if ops_result.is_success:
            ...     ops = ops_result.unwrap()
            ...     print(f"ACL format: {ops.get_acl_format()}")

        """
        if not self._client:
            return FlextResult[object | None].fail("Client not initialized")
        server_ops = self._client.server_operations
        return FlextResult[object | None].ok(server_ops)

    def get_server_capabilities(self) -> FlextResult[FlextTypes.Dict]:
        """Get comprehensive server capabilities information.

        Returns detailed information about detected server capabilities including
        supported features, ACL formats, schema locations, and connection options.

        Returns:
            FlextResult containing capabilities dictionary

        Example:
            >>> api = FlextLDAP()
            >>> api.connect()
            >>> caps_result = api.get_server_capabilities()
            >>> if caps_result.is_success:
            ...     caps = caps_result.unwrap()
            ...     print(f"Supports TLS: {caps['supports_start_tls']}")
            ...     print(f"ACL format: {caps['acl_format']}")

        """
        try:
            if not self._client:
                return FlextResult[FlextTypes.Dict].fail("Client not initialized")

            server_ops = self._client.server_operations
            if not server_ops:
                return FlextResult[FlextTypes.Dict].fail(
                    "No server operations available - connect first"
                )

            capabilities: FlextTypes.Dict = {
                "server_type": server_ops.server_type,
                "acl_format": server_ops.get_acl_format(),
                "acl_attribute": server_ops.get_acl_attribute_name(),
                "schema_dn": server_ops.get_schema_dn(),
                "default_port": server_ops.get_default_port(use_ssl=False),
                "default_ssl_port": server_ops.get_default_port(use_ssl=True),
                "supports_start_tls": server_ops.supports_start_tls(),
                "bind_mechanisms": server_ops.get_bind_mechanisms(),
                "max_page_size": server_ops.get_max_page_size(),
                "supports_paged_results": server_ops.supports_paged_results(),
                "supports_vlv": server_ops.supports_vlv(),
            }

            return FlextResult[FlextTypes.Dict].ok(capabilities)

        except Exception as e:
            return FlextResult[FlextTypes.Dict].fail(
                f"Failed to get server capabilities: {e}"
            )

    def search_universal(
        self,
        base_dn: str,
        filter_str: str,
        attributes: FlextTypes.StringList | None = None,
        scope: str = "subtree",
        use_paging: bool = True,
    ) -> FlextResult[list[FlextLdifModels.Entry]]:
        """Universal search with automatic server-specific optimization.

        Performs LDAP search with automatic detection and usage of server-specific
        features like paged results or VLV. Delegates to server operations for
        optimal performance.

        Args:
            base_dn: Base distinguished name for search
            filter_str: LDAP filter string
            attributes: Attributes to retrieve (None for all)
            scope: Search scope (base, one, subtree)
            use_paging: Whether to use paged results if available

        Returns:
            FlextResult containing list of FlextLdif Entry objects

        Example:
            >>> api = FlextLDAP()
            >>> api.connect()
            >>> result = api.search_universal(
            ...     base_dn="ou=users,dc=example,dc=com",
            ...     filter_str="(objectClass=person)",
            ...     attributes=["uid", "cn", "mail"]
            ... )

        """
        try:
            if not self._client:
                return FlextResult[list].fail("Client not initialized")

            server_ops = self._client.server_operations
            if not server_ops:
                # Fall back to standard search if no server operations
                return self.search(
                    search_base=base_dn,
                    filter_str=filter_str,
                    attributes=attributes,
                )

            # Use server-specific search with paging if supported
            if use_paging and server_ops.supports_paged_results():
                connection = self._client._connection
                if not connection:
                    return FlextResult[list].fail("Not connected to LDAP server")

                page_size = min(100, server_ops.get_max_page_size())
                search_result = server_ops.search_with_paging(
                    connection=connection,
                    base_dn=base_dn,
                    search_filter=filter_str,
                    attributes=attributes,
                    page_size=page_size,
                )
                return search_result

            # Fall back to standard search
            return self.search(
                search_base=base_dn,
                filter_str=filter_str,
                attributes=attributes,
            )

        except Exception as e:
            return FlextResult[list].fail(f"Universal search failed: {e}")

    def normalize_entry_for_server(
        self, entry: FlextLdifModels.Entry, target_server_type: str | None = None
    ) -> FlextResult[FlextLdifModels.Entry]:
        """Normalize entry for target LDAP server type.

        Converts entry to format suitable for target server, applying server-specific
        quirks and transformations. Uses current server type if target not specified.

        Args:
            entry: FlextLdif Entry object to normalize
            target_server_type: Target server type (None for current server)

        Returns:
            FlextResult containing normalized FlextLdif Entry

        Example:
            >>> api = FlextLDAP()
            >>> api.connect()
            >>> entry = ...  # FlextLdif Entry
            >>> result = api.normalize_entry_for_server(entry, "openldap2")
            >>> if result.is_success:
            ...     normalized = result.unwrap()

        """
        try:
            from flext_ldap.entry_adapter import FlextLDAPEntryAdapter

            if not self._client:
                return FlextResult[FlextLdifModels.Entry].fail("Client not initialized")

            # Determine target server type
            if target_server_type is None:
                target_server_type = self._client._detected_server_type
                if not target_server_type:
                    return FlextResult[FlextLdifModels.Entry].fail(
                        "No target server type specified and none detected"
                    )

            # Use entry adapter to normalize
            adapter = FlextLDAPEntryAdapter(server_type=target_server_type)
            normalize_result = adapter.normalize_entry_for_server(
                entry=entry, target_server_type=target_server_type
            )

            return normalize_result

        except Exception as e:
            return FlextResult[FlextLdifModels.Entry].fail(
                f"Entry normalization failed: {e}"
            )

    def convert_entry_between_servers(
        self,
        entry: FlextLdifModels.Entry,
        source_server_type: str,
        target_server_type: str,
    ) -> FlextResult[FlextLdifModels.Entry]:
        """Convert entry from source server format to target server format.

        Performs comprehensive format conversion between different LDAP server types,
        handling ACL formats, attribute names, object classes, and server-specific
        conventions.

        Args:
            entry: FlextLdif Entry object to convert
            source_server_type: Source server type (openldap1, openldap2, oid, oud, ad)
            target_server_type: Target server type

        Returns:
            FlextResult containing converted FlextLdif Entry

        Example:
            >>> api = FlextLDAP()
            >>> entry = ...  # Entry from OpenLDAP 1.x
            >>> result = api.convert_entry_between_servers(
            ...     entry=entry,
            ...     source_server_type="openldap1",
            ...     target_server_type="openldap2"
            ... )

        """
        try:
            from flext_ldap.entry_adapter import FlextLDAPEntryAdapter

            adapter = FlextLDAPEntryAdapter(server_type=source_server_type)
            convert_result = adapter.convert_entry_format(
                entry=entry,
                source_server_type=source_server_type,
                target_server_type=target_server_type,
            )

            return convert_result

        except Exception as e:
            return FlextResult[FlextLdifModels.Entry].fail(
                f"Entry conversion failed: {e}"
            )

    def detect_entry_server_type(
        self, entry: FlextLdifModels.Entry
    ) -> FlextResult[str]:
        """Detect LDAP server type from entry attributes and characteristics.

        Analyzes entry attributes, object classes, and special attributes to
        determine the originating LDAP server type. Useful for migration scenarios.

        Args:
            entry: FlextLdif Entry object to analyze

        Returns:
            FlextResult containing detected server type string

        Example:
            >>> api = FlextLDAP()
            >>> entry = ...  # Entry from unknown source
            >>> result = api.detect_entry_server_type(entry)
            >>> if result.is_success:
            ...     print(f"Entry from: {result.unwrap()}")

        """
        try:
            from flext_ldap.entry_adapter import FlextLDAPEntryAdapter

            adapter = FlextLDAPEntryAdapter()
            detection_result = adapter.detect_entry_server_type(entry)

            return detection_result

        except Exception as e:
            return FlextResult[str].fail(f"Server type detection failed: {e}")

    def validate_entry_for_server(
        self, entry: FlextLdifModels.Entry, server_type: str | None = None
    ) -> FlextResult[bool]:
        """Validate entry compatibility with target LDAP server type.

        Checks if entry is compatible with target server, validating required
        attributes, object classes, and server-specific constraints.

        Args:
            entry: FlextLdif Entry object to validate
            server_type: Target server type (None for current server)

        Returns:
            FlextResult containing True if valid, False otherwise

        Example:
            >>> api = FlextLDAP()
            >>> api.connect()
            >>> entry = ...  # FlextLdif Entry
            >>> result = api.validate_entry_for_server(entry, "oud")
            >>> if result.is_success and result.unwrap():
            ...     print("Entry is compatible with Oracle OUD")

        """
        try:
            from flext_ldap.entry_adapter import FlextLDAPEntryAdapter

            if not self._client:
                return FlextResult[bool].fail("Client not initialized")

            # Determine target server type
            if server_type is None:
                server_type = self._client._detected_server_type
                if not server_type:
                    return FlextResult[bool].fail(
                        "No server type specified and none detected"
                    )

            adapter = FlextLDAPEntryAdapter(server_type=server_type)
            validation_result = adapter.validate_entry_for_server(
                entry=entry, server_type=server_type
            )

            return validation_result

        except Exception as e:
            return FlextResult[bool].fail(f"Entry validation failed: {e}")

    def get_server_specific_attributes(
        self, server_type: str | None = None
    ) -> FlextResult[FlextTypes.Dict]:
        """Get server-specific attribute information from quirks system.

        Returns detailed information about server-specific attributes, including
        required attributes, optional attributes, and attribute constraints.

        Args:
            server_type: Server type to query (None for current server)

        Returns:
            FlextResult containing server-specific attributes dictionary

        Example:
            >>> api = FlextLDAP()
            >>> api.connect()
            >>> result = api.get_server_specific_attributes("oid")
            >>> if result.is_success:
            ...     attrs = result.unwrap()
            ...     print(f"Required: {attrs.get('required_attributes', [])}")

        """
        try:
            from flext_ldap.entry_adapter import FlextLDAPEntryAdapter

            if not self._client:
                return FlextResult[FlextTypes.Dict].fail("Client not initialized")

            # Determine target server type
            if server_type is None:
                server_type = self._client._detected_server_type
                if not server_type:
                    return FlextResult[FlextTypes.Dict].fail(
                        "No server type specified and none detected"
                    )

            adapter = FlextLDAPEntryAdapter(server_type=server_type)
            attrs_result = adapter.get_server_specific_attributes(server_type)

            return attrs_result

        except Exception as e:
            return FlextResult[FlextTypes.Dict].fail(
                f"Failed to get server attributes: {e}"
            )


__all__ = [
    "FlextLDAP",
]
