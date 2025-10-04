"""LDAP Client - Unified LDAP client with composition-based architecture.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

Note: This file has type checking disabled due to limitations in the official types-ldap3 package:
- Method return types (add, delete, search, modify, unbind) are not specified in the stubs
- Properties like conn.entries and entry.entry_dn are not fully typed
- Entry attributes and their values have incomplete type information
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from ldap3 import Connection, Server

from flext_core import (
    FlextLogger,
    FlextProtocols,
    FlextResult,
    FlextService,
    FlextTypes,
)
from flext_ldap.authentication import FlextLdapAuthentication
from flext_ldap.connection_manager import FlextLdapConnectionManager
from flext_ldap.searcher import FlextLdapSearcher

if TYPE_CHECKING:
    from flext_ldap.config import FlextLdapConfig

# Import all the required modules for composition
from flext_ldap.models import FlextLdapModels
from flext_ldap.typings import FlextLdapTypes
from flext_ldap.validations import FlextLdapValidations

# Server operations imports
from flext_ldap.servers.base_operations import BaseServerOperations
from flext_ldap.servers.factory import ServerOperationsFactory


class FlextLdapClient(FlextService[None], FlextProtocols.Infrastructure.Connection):
    """FlextLdapClient - Main LDAP client using composition-based architecture.

    **UNIFIED CLASS PATTERN**: Single class per module with composition of specialized components.

    **COMPOSITION ARCHITECTURE**: Uses dedicated components for different responsibilities:
    - FlextLdapConnectionManager: Connection lifecycle management
    - FlextLdapAuthentication: Authentication operations
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
        # Type annotation: FlextLogger is not Optional (override from FlextService)
        self._logger: FlextLogger  # type: ignore[misc]
        self._logger = FlextLogger(__name__)

        # Server operations for advanced features
        self._server_operations_factory = ServerOperationsFactory()
        self._server_operations: BaseServerOperations | None = None
        self._detected_server_type: str | None = None

        # Search scope constant (used by searcher)
        self._search_scope = FlextLdapTypes.SUBTREE

        # Compose with specialized components
        self._connection_manager = FlextLdapConnectionManager(self)
        self._authenticator = FlextLdapAuthentication()
        self._searcher = FlextLdapSearcher(self)

        # Legacy compatibility attributes (will be removed in future versions)
        self._connection: Connection | None = None
        self._server: Server | None = None

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
        return self._connection_manager.connect(server_uri, bind_dn, password, **kwargs)  # type: ignore[arg-type]

    def bind(self, bind_dn: str, password: str) -> FlextResult[bool]:
        """Bind to LDAP server - delegates to connection manager."""
        return self._connection_manager.bind(bind_dn, password)

    def unbind(self) -> FlextResult[None]:
        """Unbind from LDAP server - delegates to connection manager."""
        return self._connection_manager.unbind()

    def disconnect(self) -> FlextResult[None]:
        """Disconnect from LDAP server - delegates to connection manager."""
        return self._connection_manager.disconnect()

    def is_connected(self) -> bool:
        """Check if connected - delegates to connection manager."""
        return self._connection_manager.is_connected()

    def test_connection(self) -> FlextResult[bool]:
        """Test connection - delegates to connection manager."""
        return self._connection_manager.test_connection()

    def close_connection(self) -> FlextResult[None]:
        """Close connection - delegates to connection manager."""
        return self._connection_manager.close_connection()

    def get_connection_string(self) -> str:
        """Get connection string - delegates to connection manager."""
        return self._connection_manager.get_connection_string()

    def __call__(self, *args: object, **kwargs: object) -> FlextResult[bool]:
        """Callable interface - delegates to connection manager."""
        return self._connection_manager(*args, **kwargs)

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
        return self._searcher.search(base_dn, filter_str, attributes)

    def search_one(
        self,
        search_base: str,
        search_filter: str,
        attributes: FlextTypes.StringList | None = None,
    ) -> FlextResult[FlextLdapModels.Entry | None]:
        """Search for single entry - delegates to searcher."""
        return self._searcher.search_one(search_base, search_filter, attributes)

    def get_user(self, dn: str) -> FlextResult[FlextLdapModels.LdapUser | None]:
        """Get user by DN - delegates to searcher."""
        return self._searcher.get_user(dn)

    def get_group(self, dn: str) -> FlextResult[FlextLdapModels.Group | None]:
        """Get group by DN - delegates to searcher."""
        return self._searcher.get_group(dn)

    def user_exists(self, dn: str) -> FlextResult[bool]:
        """Check user existence - delegates to searcher."""
        return self._searcher.user_exists(dn)

    def group_exists(self, dn: str) -> FlextResult[bool]:
        """Check group existence - delegates to searcher."""
        return self._searcher.group_exists(dn)

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
            self._connection.refresh_schema()  # type: ignore[attr-defined]
            schema = self._connection.schema  # type: ignore[attr-defined]

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
    # LEGACY COMPATIBILITY METHODS - Will be removed in future versions
    # =========================================================================

    def _create_user_from_entry(self, entry: object) -> FlextLdapModels.LdapUser:
        """Create user from LDAP entry - legacy compatibility method."""
        # This method exists for backward compatibility with existing code
        # In the future, this should be moved to a factory or builder pattern
        if not hasattr(entry, "dn") or not hasattr(entry, "attributes"):
            raise ValueError("Invalid LDAP entry format")

        # Extract basic attributes
        dn = str(getattr(entry, "dn", ""))
        attributes = getattr(entry, "attributes", {})

        # Create user model
        user = FlextLdapModels.LdapUser(
            dn=dn,
            uid=attributes.get("uid", [""])[0]
            if isinstance(attributes.get("uid"), list)
            else attributes.get("uid", ""),
            cn=attributes.get("cn", [""])[0]
            if isinstance(attributes.get("cn"), list)
            else attributes.get("cn", ""),
            sn=attributes.get("sn", [""])[0]
            if isinstance(attributes.get("sn"), list)
            else attributes.get("sn", ""),
            mail=attributes.get("mail", [""])[0]
            if isinstance(attributes.get("mail"), list)
            else attributes.get("mail", ""),
            user_password=None,  # Never expose passwords
        )

        return user

    def _create_group_from_entry(self, entry: object) -> FlextLdapModels.Group:
        """Create group from LDAP entry - legacy compatibility method."""
        # Similar to _create_user_from_entry
        if not hasattr(entry, "dn") or not hasattr(entry, "attributes"):
            raise ValueError("Invalid LDAP entry format")

        dn = str(getattr(entry, "dn", ""))
        attributes = getattr(entry, "attributes", {})

        group = FlextLdapModels.Group(
            dn=dn,
            cn=attributes.get("cn", [""])[0]
            if isinstance(attributes.get("cn"), list)
            else attributes.get("cn", ""),
            description=attributes.get("description", [""])[0]
            if isinstance(attributes.get("description"), list)
            else attributes.get("description", ""),
            member=attributes.get("member", [])
            if isinstance(attributes.get("member"), list)
            else [attributes.get("member", "")],
        )

        return group
