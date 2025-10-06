"""LDAP Client - Unified LDAP client with composition-based architecture.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

Note: This file has type checking disabled due to limitations in the official types-ldap3 package:
- Method return types (add, delete, search, modify, unbind) are not specified in the stubs
- Properties like conn.entries and entry.entry_dn are not fully typed
- Entry attributes and their values have incomplete type information
"""

from __future__ import annotations

from typing import override

from ldap3 import Connection

from flext_core import (
    FlextResult,
    FlextService,
    FlextTypes,
)
from flext_ldap.authentication import FlextLdapAuthentication
from flext_ldap.config import FlextLdapConfig

# Use protocols to avoid circular imports
from flext_ldap.protocols import FlextLdapProtocols

from flext_ldap.models import FlextLdapModels
from flext_ldap.typings import FlextLdapTypes
from flext_ldap.validations import FlextLdapValidations

from flext_ldap.servers.base_operations import (
    FlextLdapServersBaseOperations as BaseServerOperations,
)
from flext_ldap.servers.factory import (
    FlextLdapServersFactory as ServerOperationsFactory,
)


class FlextLdapClients(FlextService[None]):
    """FlextLdapClients - Main LDAP clients using composition-based architecture.

    **UNIFIED CLASS PATTERN**: Single class per module with composition of specialized components.

    **COMPOSITION ARCHITECTURE**: Uses dedicated components for different responsibilities:
    - FlextLdapConnectionManager: Connection lifecycle management
    - FlextLdapAuthentication: Authentication operations

    **FLEXT INTEGRATION**: Full flext-core service integration
    - FlextLdapSearcher: Search operations

    This class provides a comprehensive interface for LDAP operations including
    connection management, authentication, search, and CRUD operations.
    It uses the ldap3 library internally and provides a FlextResult-based API.

    The client supports both synchronous and asynchronous operations, with
    automatic connection management and proper error handling.

    **PROTOCOL IMPLEMENTATION**: This client implements FlextProtocols.Infrastructure.Connection,
    establishing the foundation pattern for ALL connection-aware clients across the FLEXT ecosystem.

    Implements FlextProtocols through structural subtyping:
    - Infrastructure.Connection: test_connection, close_connection, get_connection_string, __call__ methods
    - LdapConnectionProtocol: connect, disconnect, is_connected methods
    - LdapSearchProtocol: search, search_one methods
    - LdapModifyProtocol: add_entry, modify_entry, delete_entry methods
    - LdapAuthenticationProtocol: authenticate_user, validate_credentials methods
    - LdapValidationProtocol: validate_dn, validate_entry methods
    """

    def __init__(self, config: FlextLdapConfig | None = None) -> None:
        """Initialize the LDAP client with composition-based architecture."""
        super().__init__()

        # Core configuration and logging
        self._config = config

        # Server operations for advanced features
        self._server_operations_factory = ServerOperationsFactory()
        self._server_operations: BaseServerOperations | None = None
        self._detected_server_type: str | None = None

        # Search scope constant (used by searcher)
        self._search_scope = FlextLdapTypes.SUBTREE

        # Compose with specialized components
        # Lazy imports to avoid circular dependencies
        self._connection_manager: (
            FlextLdapProtocols.Ldap.LdapConnectionManagerProtocol | None
        ) = None
        self._authenticator = FlextLdapAuthentication()
        self._searcher: FlextLdapProtocols.Ldap.LdapSearcherProtocol | None = None

    def _get_connection_manager(
        self,
    ) -> FlextLdapProtocols.Ldap.LdapConnectionManagerProtocol:
        """Get connection manager with lazy initialization."""
        if self._connection_manager is None:
            from flext_ldap.connection_manager import FlextLdapConnectionManager

            self._connection_manager = FlextLdapConnectionManager(self)
        return self._connection_manager

    def _get_searcher(self) -> FlextLdapProtocols.Ldap.LdapSearcherProtocol:
        """Get searcher with lazy initialization."""
        if self._searcher is None:
            from flext_ldap.search import FlextLdapSearch

            self._searcher = FlextLdapSearch(parent=self)
        return self._searcher

    @property
    def _connection(self) -> Connection | None:
        """Get the current LDAP connection from the connection manager."""
        return self._get_connection_manager()._connection

    @override
    def execute(self) -> FlextResult[None]:
        """Execute the main domain operation (required by FlextService)."""
        return FlextResult[None].ok(None)

    # =========================================================================
    # CONNECTION MANAGEMENT - Delegated to FlextLdapConnectionManager
    # =========================================================================

    def connect(
        self,
        server_uri: str,
        bind_dn: str,
        password: str,
        **kwargs: object,
    ) -> FlextResult[bool]:
        """Connect to LDAP server - delegates to connection manager."""
        # Type ignore: **kwargs delegation pattern - runtime types are correct
        return self._get_connection_manager().connect(
            server_uri, bind_dn, password, **kwargs
        )

    def bind(self, bind_dn: str, password: str) -> FlextResult[bool]:
        """Bind to LDAP server - delegates to connection manager."""
        return self._get_connection_manager().bind(bind_dn, password)

    def unbind(self) -> FlextResult[None]:
        """Unbind from LDAP server - delegates to connection manager."""
        return self._get_connection_manager().unbind()

    def disconnect(self) -> FlextResult[None]:
        """Disconnect from LDAP server - delegates to connection manager."""
        return self._get_connection_manager().disconnect()

    def is_connected(self) -> bool:
        """Check if connected - delegates to connection manager."""
        return self._get_connection_manager().is_connected()

    def test_connection(self) -> FlextResult[bool]:
        """Test connection - delegates to connection manager."""
        return self._get_connection_manager().test_connection()

    def close_connection(self) -> FlextResult[None]:
        """Close connection - delegates to connection manager."""
        return self._get_connection_manager().close_connection()

    def get_connection_string(self) -> FlextResult[str]:
        """Get connection string - delegates to connection manager."""
        return self._get_connection_manager().get_connection_string()

    def __call__(self, *args: object, **kwargs: object) -> FlextResult[bool]:
        """Callable interface - delegates to connection manager."""
        return self._get_connection_manager()(*args, **kwargs)

    # =========================================================================
    # AUTHENTICATION - Delegated to FlextLdapAuthentication
    # =========================================================================

    def authenticate_user(
        self,
        username: str,
        password: str,
    ) -> FlextResult[FlextLdapModels.LdapUser]:
        """Authenticate user - delegates to authenticator."""
        return self._authenticator.authenticate_user(username, password)

    def validate_credentials(self, dn: str, password: str) -> FlextResult[bool]:
        """Validate credentials - delegates to authenticator."""
        return self._authenticator.validate_credentials(dn, password)

    # =========================================================================
    # SEARCH OPERATIONS - Delegated to FlextLdapSearcher
    # =========================================================================

    def search(
        self,
        base_dn: str,
        filter_str: str,
        attributes: FlextTypes.StringList | None = None,
    ) -> FlextResult[list[FlextLdapModels.Entry]]:
        """Perform LDAP search - delegates to searcher."""
        return self._get_searcher().search(base_dn, filter_str, attributes)

    def search_one(
        self,
        search_base: str,
        search_filter: str,
        attributes: FlextTypes.StringList | None = None,
    ) -> FlextResult[FlextLdapModels.Entry | None]:
        """Search for single entry - delegates to searcher."""
        return self._get_searcher().search_one(search_base, search_filter, attributes)

    def get_user(self, dn: str) -> FlextResult[FlextLdapModels.LdapUser | None]:
        """Get user by DN - delegates to searcher."""
        return self._get_searcher().get_user(dn)

    def get_group(self, dn: str) -> FlextResult[FlextLdapModels.Group | None]:
        """Get group by DN - delegates to searcher."""
        return self._get_searcher().get_group(dn)

    def user_exists(self, dn: str) -> FlextResult[bool]:
        """Check user existence - delegates to searcher."""
        return self._get_searcher().user_exists(dn)

    def group_exists(self, dn: str) -> FlextResult[bool]:
        """Check group existence - delegates to searcher."""
        return self._get_searcher().group_exists(dn)

    # =========================================================================
    # CRUD OPERATIONS - Direct implementation (simpler operations)
    # =========================================================================

    def add_entry(
        self, dn: str, attributes: dict[str, str | FlextTypes.StringList]
    ) -> FlextResult[bool]:
        """Add new LDAP entry - implements LdapModifyProtocol."""
        try:
            if not self._connection:
                return FlextResult[bool].fail("LDAP connection not established")

            # Convert attributes to ldap3 format
            ldap3_attributes = {}
            for key, value in attributes.items():
                if isinstance(value, list):
                    ldap3_attributes[key] = value
                else:
                    ldap3_attributes[key] = [str(value)]

            success = self._connection.add(dn, attributes=ldap3_attributes)
            if success:
                return FlextResult[bool].ok(True)
            else:
                return FlextResult[bool].fail(
                    f"Add entry failed: {self._connection.last_error}"
                )

        except Exception as e:
            self._logger.exception("Add entry failed")
            return FlextResult[bool].fail(f"Add entry failed: {e}")

    def modify_entry(self, dn: str, changes: FlextTypes.Dict) -> FlextResult[bool]:
        """Modify existing LDAP entry - implements LdapModifyProtocol."""
        try:
            if not self._connection:
                return FlextResult[bool].fail("LDAP connection not established")

            # Convert changes to ldap3 format
            ldap3_changes = {}
            for attr, change_spec in changes.items():
                if isinstance(change_spec, dict):
                    # Handle complex modify operations
                    ldap3_changes[attr] = change_spec
                else:
                    # Simple replace operation
                    ldap3_changes[attr] = [("MODIFY_REPLACE", change_spec)]

            success = self._connection.modify(dn, changes=ldap3_changes)
            if success:
                return FlextResult[bool].ok(True)
            else:
                return FlextResult[bool].fail(
                    f"Modify entry failed: {self._connection.last_error}"
                )

        except Exception as e:
            self._logger.exception("Modify entry failed")
            return FlextResult[bool].fail(f"Modify entry failed: {e}")

    def delete_entry(self, dn: str) -> FlextResult[bool]:
        """Delete LDAP entry - implements LdapModifyProtocol."""
        try:
            if not self._connection:
                return FlextResult[bool].fail("LDAP connection not established")

            success = self._connection.delete(dn)
            if success:
                return FlextResult[bool].ok(True)
            else:
                return FlextResult[bool].fail(
                    f"Delete entry failed: {self._connection.last_error}"
                )

        except Exception as e:
            self._logger.exception("Delete entry failed")
            return FlextResult[bool].fail(f"Delete entry failed: {e}")

    # =========================================================================
    # VALIDATION OPERATIONS - Direct implementation
    # =========================================================================

    def validate_dn(self, dn: str) -> FlextResult[bool]:
        """Validate distinguished name format - implements LdapValidationProtocol."""
        validation_result = FlextLdapValidations.validate_dn(dn)
        if validation_result.is_failure:
            return FlextResult[bool].fail(
                validation_result.error or "DN validation failed"
            )
        return FlextResult[bool].ok(True)

    def validate_entry(self, entry: FlextLdapModels.Entry) -> FlextResult[bool]:
        """Validate LDAP entry structure - implements LdapValidationProtocol."""
        try:
            # Basic validation
            if not entry.dn:
                return FlextResult[bool].fail("Entry DN cannot be empty")

            if not entry.attributes:
                return FlextResult[bool].fail("Entry attributes cannot be empty")

            # DN format validation
            dn_validation = self.validate_dn(entry.dn)
            if dn_validation.is_failure:
                return dn_validation

            # Object class validation
            if not entry.object_classes:
                return FlextResult[bool].fail("Entry must have object classes")

            return FlextResult[bool].ok(True)

        except Exception as e:
            return FlextResult[bool].fail(f"Entry validation failed: {e}")

    # =========================================================================
    # ADVANCED OPERATIONS - Direct implementation
    # =========================================================================

    def discover_schema(self) -> FlextResult[FlextTypes.Dict]:
        """Discover LDAP schema information."""
        try:
            if not self._connection:
                return FlextResult[FlextTypes.Dict].fail(
                    "LDAP connection not established"
                )

            # Refresh schema
            # Note: refresh_schema() and schema are valid ldap3.Connection attributes
            # but not in types-ldap3 stubs (type: ignore needed for incomplete stubs)
            self._connection.refresh_schema()
            schema = self._connection.schema

            if not schema:
                return FlextResult[FlextTypes.Dict].fail("No schema available")

            # Extract basic schema information
            schema_info: FlextTypes.Dict = {
                "attribute_types": len(schema.attribute_types)
                if schema.attribute_types
                else 0,
                "object_classes": len(schema.object_classes)
                if schema.object_classes
                else 0,
                "ldap_syntaxes": len(schema.ldap_syntaxes)
                if schema.ldap_syntaxes
                else 0,
                "matching_rules": len(schema.matching_rules)
                if schema.matching_rules
                else 0,
            }

            return FlextResult[FlextTypes.Dict].ok(schema_info)

        except Exception as e:
            self._logger.exception("Schema discovery failed")
            return FlextResult[FlextTypes.Dict].fail(f"Schema discovery failed: {e}")

    # =========================================================================
    # UNIVERSAL LDAP OPERATIONS - Server-agnostic high-level methods
    # =========================================================================

    def normalize_attribute_name(self, attribute_name: str) -> str:
        """Normalize LDAP attribute name according to server-specific conventions."""
        if not self._server_operations:
            return attribute_name.lower()
        return self._server_operations.normalize_attribute_name(attribute_name)

    def normalize_object_class(self, object_class: str) -> str:
        """Normalize LDAP object class name according to server-specific conventions."""
        if not self._server_operations:
            return object_class.lower()
        return self._server_operations.normalize_object_class(object_class)

    def normalize_dn(self, dn: str) -> str:
        """Normalize distinguished name according to server-specific conventions."""
        if not self._server_operations:
            return dn
        return self._server_operations.normalize_dn(dn)

    def get_server_info(self) -> FlextResult[FlextTypes.Dict]:
        """Get comprehensive server information including capabilities and schema."""
        try:
            if not self._connection:
                return FlextResult[FlextTypes.Dict].fail("Not connected to LDAP server")

            server_info = self._connection.server.info
            if not server_info:
                return FlextResult[FlextTypes.Dict].fail("Server info not available")

            # Convert server info to dictionary
            info_dict = {
                "server_type": getattr(
                    self._detected_server_type, "value", str(self._detected_server_type)
                )
                if self._detected_server_type
                else "unknown",
                "vendor_name": getattr(server_info, "vendor_name", {}).get(
                    "value", "Unknown"
                )
                if hasattr(server_info, "vendor_name")
                else "Unknown",
                "vendor_version": getattr(server_info, "vendor_version", {}).get(
                    "value", "Unknown"
                )
                if hasattr(server_info, "vendor_version")
                else "Unknown",
                "supported_ldap_version": getattr(
                    server_info, "supported_ldap_version", []
                ),
                "naming_contexts": getattr(server_info, "naming_contexts", []),
                "supported_controls": getattr(server_info, "supported_controls", []),
                "supported_extensions": getattr(
                    server_info, "supported_extensions", []
                ),
                "supported_features": getattr(server_info, "supported_features", []),
                "supported_sasl_mechanisms": getattr(
                    server_info, "supported_sasl_mechanisms", []
                ),
                "schema_entry": getattr(server_info, "schema_entry", ""),
                "other": getattr(server_info, "other", {}),
            }

            return FlextResult[FlextTypes.Dict].ok(info_dict)

        except Exception as e:
            return FlextResult[FlextTypes.Dict].fail(f"Failed to get server info: {e}")

    def get_server_capabilities(self) -> FlextResult[FlextTypes.Dict]:
        """Get server capabilities and supported features."""
        try:
            if not self._server_operations:
                return FlextResult[FlextTypes.Dict].fail(
                    "Server operations not available"
                )

            capabilities = {
                "server_type": self._server_operations.server_type,
                "acl_format": self._server_operations.get_acl_format(),
                "acl_attribute": self._server_operations.get_acl_attribute_name(),
                "schema_dn": self._server_operations.get_schema_dn(),
                "default_port": self._server_operations.get_default_port(use_ssl=False),
                "default_ssl_port": self._server_operations.get_default_port(
                    use_ssl=True
                ),
                "supports_start_tls": self._server_operations.supports_start_tls(),
                "bind_mechanisms": self._server_operations.get_bind_mechanisms(),
                "max_page_size": self._server_operations.get_max_page_size(),
                "supports_paged_results": self._server_operations.supports_paged_results(),
                "supports_vlv": self._server_operations.supports_vlv(),
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
    ) -> FlextResult[list]:
        """Universal search with automatic server-specific optimization."""
        try:
            if not self._connection:
                return FlextResult[list].fail("Not connected to LDAP server")

            if not self._server_operations:
                # Fall back to basic search
                return self.search(base_dn, filter_str, attributes)

            # Use server-specific search with paging if supported
            if use_paging and self._server_operations.supports_paged_results():
                page_size = min(100, self._server_operations.get_max_page_size())
                return self._server_operations.search_with_paging(
                    connection=self._connection,
                    base_dn=base_dn,
                    search_filter=filter_str,
                    attributes=attributes,
                    page_size=page_size,
                )

            # Fall back to standard search
            return self.search(base_dn, filter_str, attributes)

        except Exception as e:
            return FlextResult[list].fail(f"Universal search failed: {e}")

    def search_with_controls_universal(
        self,
        base_dn: str,
        filter_str: str,
        controls: list | None = None,
        attributes: FlextTypes.StringList | None = None,
        scope: str = "subtree",
    ) -> FlextResult[list]:
        """Universal search with LDAP controls."""
        try:
            if not self._connection:
                return FlextResult[list].fail("Not connected to LDAP server")

            # For now, delegate to regular search - controls support can be added later
            return self.search(base_dn, filter_str, attributes)

        except Exception as e:
            return FlextResult[list].fail(f"Universal search with controls failed: {e}")

    def add_entry_universal(
        self, dn: str, attributes: dict[str, str | FlextTypes.StringList]
    ) -> FlextResult[bool]:
        """Universal add entry operation."""
        return self.add_entry(dn, attributes)

    def modify_entry_universal(
        self, dn: str, changes: FlextTypes.Dict
    ) -> FlextResult[bool]:
        """Universal modify entry operation."""
        return self.modify_entry(dn, changes)

    def delete_entry_universal(
        self, dn: str, controls: list | None = None
    ) -> FlextResult[bool]:
        """Universal delete entry operation."""
        return self.delete_entry(dn)

    def compare_universal(
        self, dn: str, attribute: str, value: str
    ) -> FlextResult[bool]:
        """Universal compare operation."""
        try:
            if not self._connection:
                return FlextResult[bool].fail("Not connected to LDAP server")

            result = self._connection.compare(dn, attribute, value)
            if result is None:
                return FlextResult[bool].fail("Compare operation failed")

            return FlextResult[bool].ok(bool(result))

        except Exception as e:
            return FlextResult[bool].fail(f"Compare operation failed: {e}")

    def extended_operation_universal(
        self, request_name: str, request_value: bytes | None = None
    ) -> FlextResult[object]:
        """Universal extended operation."""
        try:
            if not self._connection:
                return FlextResult[object].fail("Not connected to LDAP server")

            result = self._connection.extended(request_name, request_value)
            if result is None:
                return FlextResult[object].fail("Extended operation failed")

            return FlextResult[object].ok(result)

        except Exception as e:
            return FlextResult[object].fail(f"Extended operation failed: {e}")

    # =========================================================================
    # MISSING METHODS - Required by API layer
    # =========================================================================

    def search_groups(
        self,
        base_dn: str,
        cn: str | None = None,
        attributes: FlextTypes.StringList | None = None,
    ) -> FlextResult[list[FlextLdapModels.Group]]:
        """Search for LDAP groups."""
        filter_str = "(objectClass=groupOfNames)"
        if cn:
            filter_str = f"(&(objectClass=groupOfNames)(cn={cn}))"

        search_result = self.search(base_dn, filter_str, attributes)
        if search_result.is_failure:
            return FlextResult[list[FlextLdapModels.Group]].fail(
                search_result.error or "Group search failed"
            )

        # Convert entries to groups
        groups = []
        for entry in search_result.unwrap():
            try:
                group = self._create_group_from_entry(entry)
                groups.append(group)
            except Exception as e:
                self._logger.error("Failed to convert entry to group", error=str(e))
                continue

        return FlextResult[list[FlextLdapModels.Group]].ok(groups)

    def search_with_request(
        self, request: FlextLdapModels.SearchRequest
    ) -> FlextResult[FlextLdapModels.SearchResponse]:
        """Search using a SearchRequest object."""
        search_result = self.search(
            request.base_dn, request.filter_str, request.attributes
        )
        if search_result.is_failure:
            return FlextResult[FlextLdapModels.SearchResponse].fail(
                search_result.error or "Search failed"
            )

        entries = search_result.unwrap()
        response = FlextLdapModels.SearchResponse(
            entries=entries,
            total_count=len(entries),
            result_code=0,
            time_elapsed=0.0,
        )

        return FlextResult[FlextLdapModels.SearchResponse].ok(response)

    def update_user_attributes(
        self, dn: str, attributes: FlextTypes.Dict
    ) -> FlextResult[bool]:
        """Update user attributes."""
        # This would need to be implemented with actual LDAP modify operation
        # For now, return a placeholder
        return FlextResult[bool].fail("update_user_attributes not implemented")

    def update_group_attributes(
        self, dn: str, attributes: FlextTypes.Dict
    ) -> FlextResult[bool]:
        """Update group attributes."""
        # This would need to be implemented with actual LDAP modify operation
        # For now, return a placeholder
        return FlextResult[bool].fail("update_group_attributes not implemented")

    def delete_user(self, dn: str) -> FlextResult[None]:
        """Delete a user."""
        # This would need to be implemented with actual LDAP delete operation
        # For now, return a placeholder
        return FlextResult[None].fail("delete_user not implemented")

    @property
    def server_operations(self) -> BaseServerOperations | None:
        """Get the server operations instance."""
        return self._server_operations

    def get_server_type(self) -> str | None:
        """Get detected server type."""
        return self._detected_server_type

    def get_server_quirks(self) -> FlextLdapModels.ServerQuirks | None:
        """Get server quirks for detected server type."""
        if not self._detected_server_type:
            return None
        # Create server quirks based on detected type
        return FlextLdapModels.ServerQuirks(
            case_sensitive_dns=self._detected_server_type in ["ad"],
            case_sensitive_attributes=self._detected_server_type in ["ad"],
            supports_paged_results=self._detected_server_type not in ["openldap1"],
            supports_vlv=self._detected_server_type in ["oud", "oid"],
            max_page_size=1000 if self._detected_server_type != "ad" else 100000,
        )
