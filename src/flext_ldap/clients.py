"""LDAP Client - Unified LDAP client with composition-based architecture.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

Note: This file has type checking disabled due to limitations in the official types-ldap3 package:
- Method return types (add, delete, search, modify, unbind) are not specified in the stubs
- Properties like conn.entries and entry.entry_dn are not fully typed
- Entry attributes and their values have incomplete type information
"""

from __future__ import annotations

from typing import Literal, cast, override

from flext_core import FlextCore
from ldap3 import (
    ALL,
    MODIFY_ADD,
    MODIFY_DELETE,
    MODIFY_REPLACE,
    Connection,
    Server,
)

from flext_ldap.authentication import FlextLdapAuthentication
from flext_ldap.config import FlextLdapConfig
from flext_ldap.constants import FlextLdapConstants
from flext_ldap.models import FlextLdapModels
from flext_ldap.protocols import FlextLdapProtocols
from flext_ldap.search import FlextLdapSearch
from flext_ldap.servers.base_operations import (
    FlextLdapServersBaseOperations as BaseServerOperations,
)
from flext_ldap.servers.factory import (
    FlextLdapServersFactory as ServerOperationsFactory,
)
from flext_ldap.validations import FlextLdapValidations


class FlextLdapClients(FlextCore.Service[None]):
    """FlextLdapClients - Main LDAP clients using composition-based architecture.

    **UNIFIED CLASS PATTERN**: Single class per module with composition of specialized components.

    **COMPOSITION ARCHITECTURE**: Uses dedicated components for different responsibilities:
    - FlextLdapConnectionManager: Connection lifecycle management
    - FlextLdapAuthentication: Authentication operations

    **FLEXT INTEGRATION**: Full flext-core service integration
    - FlextLdapSearcher: Search operations

    This class provides a comprehensive interface for LDAP operations including
    connection management, authentication, search, and CRUD operations.
    It uses the ldap3 library internally and provides a FlextCore.Result-based API.

    The client supports both synchronous and asynchronous operations, with
    automatic connection management and proper error handling.

    **PROTOCOL IMPLEMENTATION**: This client implements FlextCore.Protocols.Infrastructure.Connection,
    establishing the foundation pattern for ALL connection-aware clients across the FLEXT ecosystem.

    Implements FlextCore.Protocols through structural subtyping:
    - Infrastructure.Connection: test_connection, close_connection, get_connection_string, __call__ methods
    - LdapConnectionProtocol: connect, disconnect, is_connected methods
    - LdapSearchProtocol: search, search_one methods
    - LdapModifyProtocol: add_entry, modify_entry, delete_entry methods
    - LdapAuthenticationProtocol: authenticate_user, validate_credentials methods
    - LdapValidationProtocol: validate_dn, validate_entry methods
    """

    def __init__(self, config: FlextLdapConfig | None = None) -> None:
        """Initialize the LDAP client - consolidated implementation without delegation bloat."""
        super().__init__()

        # Core configuration and logging
        self._ldap_config = config

        # Direct connection state (no delegation layer)
        self._connection: Connection | None = None
        self._server: Server | None = None

        # Server operations for advanced features
        self._server_operations_factory = ServerOperationsFactory()
        self._server_operations: BaseServerOperations | None = None
        self._detected_server_type: str | None = None

        # Search scope constant
        self._search_scope: Literal["BASE", "LEVEL", "SUBTREE"] = (
            FlextLdapConstants.LiteralTypes.SEARCH_SCOPE_SUBTREE
        )

        # Lazy-loaded components for search and authentication (substantial logic modules)
        self._searcher: FlextLdapProtocols.Ldap.LdapSearcherProtocol | None = None
        self._authenticator: (
            FlextLdapProtocols.Ldap.LdapAuthenticationProtocol | None
        ) = None

    def _get_searcher(self) -> FlextLdapProtocols.Ldap.LdapSearcherProtocol:
        """Get searcher with lazy initialization."""
        if self._searcher is None:
            searcher = FlextLdapSearch(parent=self)
            # Set connection context if connection exists
            if self._connection:
                searcher.set_connection_context(self._connection)
            self._searcher = cast(
                "FlextLdapProtocols.Ldap.LdapSearcherProtocol", searcher
            )
        # Type checker knows it's not None after the check above
        return self._searcher

    def _get_authenticator(self) -> FlextLdapProtocols.Ldap.LdapAuthenticationProtocol:
        """Get authenticator with lazy initialization."""
        if self._authenticator is None:
            auth = FlextLdapAuthentication()
            auth.set_connection_context(
                self._connection,
                self._server,
                cast("FlextLdapModels.Config", self._ldap_config),
            )
            self._authenticator = cast(
                "FlextLdapProtocols.Ldap.LdapAuthenticationProtocol", auth
            )
        # Type checker knows it's not None after the check above
        return self._authenticator

    @property
    def connection(self) -> Connection | None:
        """Get the current LDAP connection."""
        return self._connection

    @override
    def execute(self) -> FlextCore.Result[None]:
        """Execute the main domain operation (required by FlextCore.Service)."""
        return FlextCore.Result[None].ok(None)

    # =========================================================================
    # CONNECTION MANAGEMENT - Direct implementation (no delegation bloat)
    # =========================================================================

    def connect(
        self,
        server_uri: str,
        bind_dn: str,
        password: str,
        *,
        auto_discover_schema: bool = True,
        connection_options: dict[str, object] | None = None,
    ) -> FlextCore.Result[bool]:
        """Connect and bind to LDAP server with universal compatibility.

        Args:
            server_uri: LDAP server URI (e.g., 'ldap://localhost:389').
            bind_dn: Distinguished Name for binding.
            password: Password for binding.
            auto_discover_schema: Whether to automatically discover schema.
            connection_options: Additional connection options.

        Returns:
            FlextCore.Result[bool]: Success result or error.

        """
        try:
            # Use centralized server URI validation
            uri_validation = FlextLdapValidations.validate_server_uri(server_uri)
            if uri_validation.is_failure:
                return FlextCore.Result[bool].fail(
                    uri_validation.error or "Server URI validation failed",
                )

            # Use centralized DN validation for bind_dn
            bind_dn_validation = FlextLdapValidations.validate_dn(bind_dn, "Bind DN")
            if bind_dn_validation.is_failure:
                return FlextCore.Result[bool].fail(
                    bind_dn_validation.error or "Bind DN validation failed",
                )

            # Use centralized password validation
            password_validation = FlextLdapValidations.validate_password(password)
            if password_validation.is_failure:
                return FlextCore.Result[bool].fail(
                    password_validation.error or "Password validation failed",
                )

            self.logger.info("Connecting to LDAP server: %s", server_uri)

            # Apply connection options if provided
            if connection_options:
                # Cast connection options to proper types for Server constructor
                server_kwargs = {}
                for key, value in connection_options.items():
                    if key == "port" and value is not None:
                        server_kwargs[key] = int(str(value))
                    elif key == "use_ssl" and value is not None:
                        server_kwargs[key] = bool(value)
                    elif (key == "get_info" and value is not None) or (
                        key == "mode" and value is not None
                    ):
                        server_kwargs[key] = str(value)
                    else:
                        server_kwargs[key] = value
                # Set get_info to ALL if auto_discover_schema is True and not explicitly set
                if auto_discover_schema and "get_info" not in server_kwargs:
                    server_kwargs["get_info"] = ALL
                self._server = Server(server_uri, **server_kwargs)
            # Set get_info to ALL if auto_discover_schema is True
            elif auto_discover_schema:
                self._server = Server(server_uri, get_info=ALL)
            else:
                self._server = Server(server_uri)

            # Create connection with auto-bind
            self._connection = Connection(
                self._server,
                bind_dn,
                password,
                auto_bind=True,
            )

            if not self._connection.bound:
                return FlextCore.Result[bool].fail("Failed to bind to LDAP server")

            self.logger.info("Successfully connected to LDAP server")

            # Update searcher and authenticator with new connection if they exist
            if self._searcher is not None:
                self._searcher.set_connection_context(self._connection)
            if self._authenticator is not None:
                self._authenticator.set_connection_context(
                    self._connection,
                    self._server,
                    cast("FlextLdapModels.Config", self._ldap_config),
                )

            # Auto-detect server type
            detection_result = self._server_operations_factory.create_from_connection(
                self._connection,
            )
            if detection_result.is_success:
                self._server_operations = detection_result.unwrap()
                self._detected_server_type = (
                    self._server_operations.server_type
                    if self._server_operations
                    else None
                )
                self.logger.info(
                    "Auto-detected LDAP server type: %s",
                    self._detected_server_type,
                )
            else:
                # Fallback to generic server operations
                generic_result = (
                    self._server_operations_factory.create_from_server_type("generic")
                )
                if generic_result.is_success:
                    self._server_operations = generic_result.unwrap()
                    self._detected_server_type = "generic"

            # Perform schema discovery if requested
            if auto_discover_schema:
                discovery_result = self.discover_schema()
                if discovery_result.is_failure:
                    self.logger.warning(
                        "Schema discovery failed: %s",
                        discovery_result.error,
                    )

            return FlextCore.Result[bool].ok(True)

        except Exception as e:
            self.logger.exception("Connection failed")
            return FlextCore.Result[bool].fail(f"Connection failed: {e}")

    def bind(self, bind_dn: str, password: str) -> FlextCore.Result[bool]:
        """Bind to LDAP server with specified credentials."""
        try:
            if not self._connection:
                return FlextCore.Result[bool].fail("LDAP connection not established")

            # Create new connection with provided credentials
            if not self._server:
                return FlextCore.Result[bool].fail("No server connection established")

            self._connection = Connection(
                self._server,
                bind_dn,
                password,
                auto_bind=True,
            )

            if not self._connection.bound:
                return FlextCore.Result[bool].fail("Bind failed - invalid credentials")

            return FlextCore.Result[bool].ok(True)

        except Exception as e:
            self.logger.exception("Bind operation failed")
            return FlextCore.Result[bool].fail(f"Bind failed: {e}")

    def unbind(self) -> FlextCore.Result[None]:
        """Unbind from LDAP server."""
        try:
            if not self._connection:
                return FlextCore.Result[None].ok(None)  # Idempotent

            if self._connection.bound:
                self._connection.unbind()
                self.logger.info("Unbound from LDAP server")

            self._connection = None
            self._server = None
            return FlextCore.Result[None].ok(None)

        except Exception as e:
            self.logger.exception("Unbind failed")
            return FlextCore.Result[None].fail(f"Unbind failed: {e}")

    def is_connected(self) -> bool:
        """Check if connected to LDAP server."""
        return self._connection is not None and self._connection.bound

    def test_connection(self) -> FlextCore.Result[bool]:
        """Test LDAP connection."""
        if not self.is_connected():
            return FlextCore.Result[bool].fail("LDAP connection not established")

        try:
            if self._connection:
                self._connection.search(
                    "",
                    FlextLdapConstants.Defaults.DEFAULT_SEARCH_FILTER,
                    self._search_scope,
                    attributes=["objectClass"],
                )
            return FlextCore.Result[bool].ok(True)
        except Exception as e:
            return FlextCore.Result[bool].fail(f"Connection test failed: {e}")

    def get_connection_string(self) -> FlextCore.Result[str]:
        """Get sanitized LDAP connection string."""
        if self._server and hasattr(self._server, "host"):
            protocol = "ldaps" if getattr(self._server, "ssl", False) else "ldap"
            host = self._server.host
            port = self._server.port
            return FlextCore.Result[str].ok(f"{protocol}://{host}:{port}")

        if self._ldap_config and hasattr(self._ldap_config, "ldap_server_uri"):
            return FlextCore.Result[str].ok(str(self._ldap_config.ldap_server_uri))

        return FlextCore.Result[str].ok("ldap://not-connected")

    def __call__(
        self, *args: str, **kwargs: FlextCore.Types.Dict
    ) -> FlextCore.Result[bool]:
        """Callable interface for connection."""
        if len(args) >= FlextLdapConstants.Validation.MIN_CONNECTION_ARGS:
            server_uri, bind_dn, password = str(args[0]), str(args[1]), str(args[2])

            # Extract known parameters with proper types
            auto_discover_schema_val: bool = True
            connection_options_val: dict[str, object] | None = None

            if "auto_discover_schema" in kwargs:
                auto_discover_schema_val = bool(kwargs["auto_discover_schema"])

            if "connection_options" in kwargs:
                conn_opts = kwargs["connection_options"]
                if isinstance(conn_opts, dict):
                    connection_options_val = conn_opts
                else:
                    connection_options_val = None

            return self.connect(
                server_uri=server_uri,
                bind_dn=bind_dn,
                password=password,
                auto_discover_schema=auto_discover_schema_val,
                connection_options=connection_options_val,
            )

        return FlextCore.Result[bool].fail(
            "Invalid connection arguments. Expected: (server_uri, bind_dn, password)",
        )

    # =========================================================================
    # AUTHENTICATION - Delegated to FlextLdapAuthentication
    # =========================================================================

    def authenticate_user(
        self,
        username: str,
        password: str,
    ) -> FlextCore.Result[FlextLdapModels.LdapUser]:
        """Authenticate user - delegates to authenticator."""
        return self._get_authenticator().authenticate_user(username, password)

    def validate_credentials(self, dn: str, password: str) -> FlextCore.Result[bool]:
        """Validate credentials - delegates to authenticator."""
        return self._get_authenticator().validate_credentials(dn, password)

    # =========================================================================
    # SEARCH OPERATIONS - Delegated to FlextLdapSearcher
    # =========================================================================

    def search(
        self,
        base_dn: str,
        filter_str: str,
        attributes: FlextCore.Types.StringList | None = None,
        scope: Literal["BASE", "LEVEL", "SUBTREE"] = "SUBTREE",
        page_size: int = 0,
        paged_cookie: bytes | None = None,
    ) -> FlextCore.Result[list[FlextLdapModels.Entry]]:
        """Perform LDAP search - delegates to searcher."""
        return self._get_searcher().search(
            base_dn, filter_str, attributes, scope, page_size, paged_cookie
        )

    def search_one(
        self,
        search_base: str,
        filter_str: str,
        attributes: FlextCore.Types.StringList | None = None,
    ) -> FlextCore.Result[FlextLdapModels.Entry | None]:
        """Search for single entry - delegates to searcher."""
        return self._get_searcher().search_one(search_base, filter_str, attributes)

    def get_user(self, dn: str) -> FlextCore.Result[FlextLdapModels.LdapUser | None]:
        """Get user by DN - delegates to searcher."""
        return self._get_searcher().get_user(dn)

    def get_group(self, dn: str) -> FlextCore.Result[FlextLdapModels.Group | None]:
        """Get group by DN - delegates to searcher."""
        return self._get_searcher().get_group(dn)

    def user_exists(self, dn: str) -> FlextCore.Result[bool]:
        """Check user existence - delegates to searcher."""
        return self._get_searcher().user_exists(dn)

    def group_exists(self, dn: str) -> FlextCore.Result[bool]:
        """Check group existence - delegates to searcher."""
        return self._get_searcher().group_exists(dn)

    # =========================================================================
    # CRUD OPERATIONS - Direct implementation (simpler operations)
    # =========================================================================

    def add_entry(
        self,
        dn: str,
        attributes: dict[str, str | FlextCore.Types.StringList],
    ) -> FlextCore.Result[bool]:
        """Add new LDAP entry - implements LdapModifyProtocol.

        Handles undefined attributes gracefully by filtering them out and retrying.
        This makes the API extensible to work with any LDAP schema without limitations.
        """
        try:
            if not self.connection:
                return FlextCore.Result[bool].fail("LDAP connection not established")

            # Convert attributes to ldap3 format
            ldap3_attributes = {}
            for key, value in attributes.items():
                if isinstance(value, list):
                    ldap3_attributes[key] = value
                else:
                    ldap3_attributes[key] = [str(value)]

            # Try to add entry, handling undefined attributes gracefully
            success = False
            attempted_attributes = ldap3_attributes.copy()
            removed_attributes = []
            max_retries = 20  # Limit retries to avoid infinite loops
            retry_count = 0

            while not success and retry_count < max_retries:
                try:
                    # Extract object class from attributes if present, otherwise use default
                    object_class = attempted_attributes.get("objectClass", ["top"])
                    if isinstance(object_class, list):
                        object_class = object_class[0] if object_class else "top"
                    success = self.connection.add(
                        dn, object_class=object_class, attributes=attempted_attributes
                    )
                    if success:
                        if removed_attributes:
                            self.logger.debug(
                                f"Entry added successfully after removing undefined attributes: {removed_attributes}"
                            )
                        return FlextCore.Result[bool].ok(True)

                    # Check if error is about undefined attribute
                    error_msg = str(self.connection.last_error).lower()
                    if (
                        "undefined attribute" in error_msg
                        or "invalid attribute" in error_msg
                    ):
                        # Extract attribute name from error message
                        # Format: "Undefined attribute type department"
                        error_parts = str(self.connection.last_error).split()
                        if len(error_parts) > 0:
                            # Get last word which is usually the attribute name
                            problem_attr = error_parts[-1].strip()
                            if problem_attr in attempted_attributes:
                                self.logger.debug(
                                    f"Removing undefined attribute '{problem_attr}' and retrying"
                                )
                                del attempted_attributes[problem_attr]
                                removed_attributes.append(problem_attr)
                                retry_count += 1
                                continue

                    # If we can't identify the problem attribute or other error, fail
                    return FlextCore.Result[bool].fail(
                        f"Add entry failed: {self.connection.last_error}",
                    )

                except Exception as e:
                    # Some LDAP servers raise exceptions for undefined attributes
                    error_str = str(e).lower()
                    if (
                        "undefined attribute" in error_str
                        or "invalid attribute" in error_str
                    ):
                        # Try to extract attribute name from exception message
                        error_parts = str(e).split()
                        if len(error_parts) > 0:
                            problem_attr = error_parts[-1].strip()
                            if problem_attr in attempted_attributes:
                                self.logger.debug(
                                    f"Exception on undefined attribute '{problem_attr}', removing and retrying"
                                )
                                del attempted_attributes[problem_attr]
                                removed_attributes.append(problem_attr)
                                retry_count += 1
                                continue
                    # Re-raise if not an attribute error
                    raise

            # If we exhausted retries
            if retry_count >= max_retries:
                return FlextCore.Result[bool].fail(
                    f"Add entry failed after {max_retries} retries removing attributes"
                )

            return FlextCore.Result[bool].fail(
                f"Add entry failed: {self.connection.last_error}",
            )

        except Exception as e:
            self.logger.exception("Add entry failed")
            return FlextCore.Result[bool].fail(f"Add entry failed: {e}")

    def modify_entry(
        self, dn: str, changes: FlextLdapModels.EntryChanges
    ) -> FlextCore.Result[bool]:
        """Modify existing LDAP entry - implements LdapModifyProtocol."""
        try:
            if not self.connection:
                return FlextCore.Result[bool].fail("LDAP connection not established")

            # Convert changes to ldap3 format
            # ldap3 expects: {'attr': [(MODIFY_OP, [values])]}
            ldap3_changes: dict[str, object] = {}
            changes_dict: dict[str, object] = (
                changes.model_dump()
                if hasattr(changes, "model_dump")
                else dict[str, object](changes)
            )
            for attr, change_spec in changes_dict.items():
                # Check if already in ldap3 tuple format: [(operation, values)]
                if (
                    isinstance(change_spec, list)
                    and change_spec
                    and isinstance(change_spec[0], tuple)
                ):
                    # Already in correct format
                    ldap3_changes[attr] = change_spec
                elif isinstance(change_spec, dict):
                    # Handle dict[str, object] format (complex operations)
                    # Convert dict operations to proper tuple format for ldap3
                    operations = []
                    for op_name, op_value in change_spec.items():
                        if op_name == "MODIFY_ADD":
                            operations.append((
                                MODIFY_ADD,
                                [op_value]
                                if not isinstance(op_value, list)
                                else op_value,
                            ))
                        elif op_name == "MODIFY_DELETE":
                            operations.append((
                                MODIFY_DELETE,
                                [op_value]
                                if not isinstance(op_value, list)
                                else op_value,
                            ))
                        elif op_name == "MODIFY_REPLACE":
                            operations.append((
                                MODIFY_REPLACE,
                                [op_value]
                                if not isinstance(op_value, list)
                                else op_value,
                            ))
                        elif op_name == "MODIFY_INCREMENT":
                            # MODIFY_INCREMENT not available in this ldap3 version, use MODIFY_REPLACE
                            operations.append((
                                MODIFY_REPLACE,
                                [op_value]
                                if not isinstance(op_value, list)
                                else op_value,
                            ))
                    ldap3_changes[attr] = operations
                else:
                    # Simple value - wrap as MODIFY_REPLACE
                    ldap3_changes[attr] = [
                        (
                            MODIFY_REPLACE,
                            change_spec
                            if isinstance(change_spec, list)
                            else [change_spec],
                        )
                    ]

            success = self.connection.modify(
                dn,
                changes=cast(
                    "dict[str, list[tuple[int, list[str] | str]]]", ldap3_changes
                ),
            )
            if success:
                return FlextCore.Result[bool].ok(True)
            return FlextCore.Result[bool].fail(
                f"Modify entry failed: {self.connection.last_error}",
            )

        except Exception as e:
            self.logger.exception("Modify entry failed")
            return FlextCore.Result[bool].fail(f"Modify entry failed: {e}")

    def delete_entry(self, dn: str) -> FlextCore.Result[bool]:
        """Delete LDAP entry - implements LdapModifyProtocol."""
        try:
            if not self.connection:
                return FlextCore.Result[bool].fail("LDAP connection not established")

            success = self.connection.delete(dn)
            if success:
                return FlextCore.Result[bool].ok(True)
            return FlextCore.Result[bool].fail(
                f"Delete entry failed: {self.connection.last_error}",
            )

        except Exception as e:
            self.logger.exception("Delete entry failed")
            return FlextCore.Result[bool].fail(f"Delete entry failed: {e}")

    # =========================================================================
    # CONVENIENCE METHODS - Alias to main methods for backward compatibility
    # =========================================================================

    def add(
        self,
        dn: str,
        attributes: dict[str, str | FlextCore.Types.StringList],
    ) -> FlextCore.Result[bool]:
        """Add new LDAP entry (convenience alias for add_entry).

        Args:
            dn: Distinguished name for new entry
            attributes: Entry attributes

        Returns:
            FlextCore.Result indicating success

        """
        return self.add_entry(dn, attributes)

    def delete(self, dn: str) -> FlextCore.Result[bool]:
        """Delete LDAP entry (convenience alias for delete_entry).

        Args:
            dn: Distinguished name of entry to delete

        Returns:
            FlextCore.Result indicating success

        """
        return self.delete_entry(dn)

    def add_entry_universal(
        self,
        dn: str,
        attributes: dict[str, str | FlextCore.Types.StringList],
    ) -> FlextCore.Result[bool]:
        """Add new LDAP entry with universal format support (alias for add_entry).

        Args:
            dn: Distinguished name for new entry
            attributes: Entry attributes

        Returns:
            FlextCore.Result indicating success

        """
        return self.add_entry(dn, attributes)

    def delete_entry_universal(self, dn: str) -> FlextCore.Result[bool]:
        """Delete LDAP entry with universal format support (alias for delete_entry).

        Args:
            dn: Distinguished name of entry to delete

        Returns:
            FlextCore.Result indicating success

        """
        return self.delete_entry(dn)

    def get_server_type(self) -> str | None:
        """Get the detected server type.

        Returns:
            Server type string or None if not detected

        """
        return self._detected_server_type

    def modify_entry_universal(
        self, dn: str, changes: FlextLdapModels.EntryChanges
    ) -> FlextCore.Result[bool]:
        """Modify LDAP entry with universal format support (alias for modify_entry).

        Args:
            dn: Distinguished name of entry to modify
            changes: Attribute changes to apply

        Returns:
            FlextCore.Result indicating success

        """
        return self.modify_entry(dn, changes)

    def delete_group(self, dn: str) -> FlextCore.Result[bool]:
        """Delete LDAP group entry.

        Args:
            dn: Distinguished name of group to delete

        Returns:
            FlextCore.Result indicating success

        """
        return self.delete_entry(dn)

    # =========================================================================
    # VALIDATION OPERATIONS - Direct implementation
    # =========================================================================

    def validate_dn(self, dn: str) -> FlextCore.Result[bool]:
        """Validate distinguished name format - implements LdapValidationProtocol."""
        validation_result = FlextLdapValidations.validate_dn(dn)
        if validation_result.is_failure:
            return FlextCore.Result[bool].fail(
                validation_result.error or "DN validation failed",
            )
        return FlextCore.Result[bool].ok(True)

    def validate_entry(self, entry: FlextLdapModels.Entry) -> FlextCore.Result[bool]:
        """Validate LDAP entry structure - implements LdapValidationProtocol."""
        try:
            # Basic validation
            if not entry.dn:
                return FlextCore.Result[bool].fail("Entry DN cannot be empty")

            if not entry.attributes:
                return FlextCore.Result[bool].fail("Entry attributes cannot be empty")

            # DN format validation
            dn_validation = self.validate_dn(entry.dn)
            if dn_validation.is_failure:
                return dn_validation

            # Object class validation
            if not entry.object_classes:
                return FlextCore.Result[bool].fail("Entry must have object classes")

            return FlextCore.Result[bool].ok(True)

        except Exception as e:
            return FlextCore.Result[bool].fail(f"Entry validation failed: {e}")

    # =========================================================================
    # ADVANCED OPERATIONS - Direct implementation
    # =========================================================================

    def discover_schema(self) -> FlextCore.Result[FlextCore.Types.Dict]:
        """Discover LDAP schema information."""
        try:
            if not self.connection:
                return FlextCore.Result[FlextCore.Types.Dict].fail(
                    "LDAP connection not established",
                )

            # Get schema (automatically loaded with connection)
            # Note: schema may not be available on all connection types
            try:
                schema = getattr(self.connection, "schema", None)
                if not schema:
                    return FlextCore.Result[FlextCore.Types.Dict].fail(
                        "Schema not available on this connection type",
                    )
            except AttributeError:
                return FlextCore.Result[FlextCore.Types.Dict].fail(
                    "Schema attribute not available on connection",
                )

            # Extract basic schema information
            schema_info: FlextCore.Types.Dict = {
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

            return FlextCore.Result[FlextCore.Types.Dict].ok(schema_info)

        except Exception as e:
            self.logger.exception("Schema discovery failed")
            return FlextCore.Result[FlextCore.Types.Dict].fail(
                f"Schema discovery failed: {e}"
            )

    # =========================================================================
    # UNIVERSAL LDAP OPERATIONS - Server-agnostic high-level methods
    # =========================================================================

    def normalize_attribute_name(self, attribute_name: str) -> str:
        """Normalize LDAP attribute name according to server-specific conventions."""
        if not self.server_operations:
            return attribute_name.lower()
        return self.server_operations.normalize_attribute_name(attribute_name)

    def normalize_object_class(self, object_class: str) -> str:
        """Normalize LDAP object class name according to server-specific conventions."""
        if not self.server_operations:
            return object_class.lower()
        return self.server_operations.normalize_object_class(object_class)

    def normalize_dn(self, dn: str) -> str:
        """Normalize distinguished name according to server-specific conventions."""
        if not self.server_operations:
            return dn
        return self.server_operations.normalize_dn(dn)

    def get_server_info(self) -> FlextCore.Result[FlextCore.Types.Dict]:
        """Get comprehensive server information including capabilities and schema."""
        try:
            if not self.connection:
                return FlextCore.Result[FlextCore.Types.Dict].fail(
                    "LDAP connection not established",
                )

            server_info = self.connection.server.info
            if not server_info:
                return FlextCore.Result[FlextCore.Types.Dict].fail(
                    "Server info not available"
                )

            # Convert server info to dictionary
            info_dict = {
                "server_type": getattr(
                    self._detected_server_type,
                    "value",
                    str(self._detected_server_type),
                )
                if self._detected_server_type
                else "unknown",
                "vendor_name": getattr(server_info, "vendor_name", {}).get(
                    "value",
                    "Unknown",
                )
                if hasattr(server_info, "vendor_name")
                else "Unknown",
                "vendor_version": getattr(server_info, "vendor_version", {}).get(
                    "value",
                    "Unknown",
                )
                if hasattr(server_info, "vendor_version")
                else "Unknown",
                "supported_ldap_version": getattr(
                    server_info,
                    "supported_ldap_version",
                    [],
                ),
                "naming_contexts": getattr(server_info, "naming_contexts", []),
                "supported_controls": getattr(server_info, "supported_controls", []),
                "supported_extensions": getattr(
                    server_info,
                    "supported_extensions",
                    [],
                ),
                "supported_features": getattr(server_info, "supported_features", []),
                "supported_sasl_mechanisms": getattr(
                    server_info,
                    "supported_sasl_mechanisms",
                    [],
                ),
                "schema_entry": getattr(server_info, "schema_entry", ""),
                "other": getattr(server_info, "other", {}),
            }

            return FlextCore.Result[FlextCore.Types.Dict].ok(info_dict)

        except Exception as e:
            return FlextCore.Result[FlextCore.Types.Dict].fail(
                f"Failed to get server info: {e}"
            )

    def get_server_capabilities(self) -> FlextCore.Result[FlextCore.Types.Dict]:
        """Get server capabilities and supported features."""
        try:
            if not self.server_operations:
                return FlextCore.Result[FlextCore.Types.Dict].fail(
                    "Server operations not available",
                )

            capabilities: dict[str, object] = {
                "server_type": self.server_operations.server_type,
                "acl_format": self.server_operations.get_acl_format(),
                "acl_attribute": self.server_operations.get_acl_attribute_name(),
                "schema_dn": self.server_operations.get_schema_dn(),
                "default_port": self.server_operations.get_default_port(use_ssl=False),
                "default_ssl_port": self.server_operations.get_default_port(
                    use_ssl=True,
                ),
                "supports_start_tls": self.server_operations.supports_start_tls(),
                "bind_mechanisms": self.server_operations.get_bind_mechanisms(),
                "max_page_size": self.server_operations.get_max_page_size(),
                "supports_paged_results": self.server_operations.supports_paged_results(),
                "supports_vlv": self.server_operations.supports_vlv(),
            }

            return FlextCore.Result[FlextCore.Types.Dict].ok(capabilities)

        except Exception as e:
            return FlextCore.Result[FlextCore.Types.Dict].fail(
                f"Failed to get server capabilities: {e}",
            )

    def search_universal(
        self,
        base_dn: str,
        filter_str: str,
        attributes: FlextCore.Types.StringList | None = None,
        scope: Literal["BASE", "LEVEL", "SUBTREE"] = "SUBTREE",
        *,
        use_paging: bool = True,
    ) -> FlextCore.Result[list[FlextLdapModels.Entry]]:
        """Universal search with automatic server-specific optimization."""
        try:
            if not self.connection:
                return FlextCore.Result[list[FlextLdapModels.Entry]].fail(
                    "LDAP connection not established"
                )

            if not self.server_operations:
                # Fall back to basic search
                return self.search(base_dn, filter_str, attributes, scope)

            # Use server-specific search with paging if supported
            if use_paging and self.server_operations.supports_paged_results():
                page_size = min(
                    FlextLdapConstants.Connection.DEFAULT_SEARCH_PAGE_SIZE,
                    self.server_operations.get_max_page_size(),
                )
                return self.server_operations.search_with_paging(
                    connection=self.connection,
                    base_dn=base_dn,
                    search_filter=filter_str,
                    attributes=attributes,
                    scope=scope,
                    page_size=page_size,
                )

            # Fall back to standard search
            return self.search(base_dn, filter_str, attributes, scope)
        except Exception as e:
            return FlextCore.Result[list[FlextLdapModels.Entry]].fail(
                f"Universal search failed: {e}"
            )

    def compare_universal(
        self,
        dn: str,
        attribute: str,
        value: str,
    ) -> FlextCore.Result[bool]:
        """Universal compare operation."""
        try:
            if not self.connection:
                return FlextCore.Result[bool].fail("LDAP connection not established")

            result = self.connection.compare(dn, attribute, value)
            if result is None:
                return FlextCore.Result[bool].fail("Compare operation failed")

            return FlextCore.Result[bool].ok(bool(result))

        except Exception as e:
            return FlextCore.Result[bool].fail(f"Compare operation failed: {e}")

    def extended_operation_universal(
        self,
        request_name: str,
        request_value: bytes | None = None,
    ) -> FlextCore.Result[FlextCore.Types.Dict]:
        """Universal extended operation."""
        try:
            if not self.connection:
                return FlextCore.Result[FlextCore.Types.Dict].fail(
                    "LDAP connection not established",
                )

            result = self.connection.extended(request_name, request_value)
            if result is None:
                return FlextCore.Result[FlextCore.Types.Dict].fail(
                    "Extended operation failed"
                )

            # Convert result to dict format for consistency
            return FlextCore.Result[FlextCore.Types.Dict].ok({"result": result})

        except Exception as e:
            return FlextCore.Result[FlextCore.Types.Dict].fail(
                f"Extended operation failed: {e}"
            )

    # =========================================================================
    # MISSING METHODS - Required by API layer
    # =========================================================================

    def search_users(
        self,
        base_dn: str,
        filter_str: str | None = None,
        attributes: FlextCore.Types.StringList | None = None,
    ) -> FlextCore.Result[list[FlextLdapModels.Entry]]:
        """Search for LDAP users with smart defaults.

        Args:
            base_dn: LDAP search base DN
            filter_str: Optional custom filter (defaults to person objects)
            attributes: List of attributes to retrieve

        Returns:
            FlextCore.Result with list of user Entry models

        """
        # Default to searching for person objects
        search_filter = filter_str or "(objectClass=person)"

        search_result = self.search(base_dn, search_filter, attributes)
        if search_result.is_failure:
            return FlextCore.Result[list[FlextLdapModels.Entry]].fail(
                search_result.error or "User search failed",
            )

        return search_result

    def search_groups(
        self,
        base_dn: str,
        cn: str | None = None,
        attributes: FlextCore.Types.StringList | None = None,
    ) -> FlextCore.Result[list[FlextLdapModels.Group]]:
        """Search for LDAP groups."""
        filter_str = "(objectClass=groupOfNames)"
        if cn:
            filter_str = f"(&(objectClass=groupOfNames)(cn={cn}))"

        search_result = self.search(base_dn, filter_str, attributes)
        if search_result.is_failure:
            return FlextCore.Result[list[FlextLdapModels.Group]].fail(
                search_result.error or "Group search failed",
            )

        # Convert entries to groups
        groups = []
        for entry in search_result.unwrap():
            try:
                group = self._create_group_from_entry(entry)
                groups.append(group)
            except Exception as e:
                self.logger.exception("Failed to convert entry to group", error=str(e))
                continue

        return FlextCore.Result[list[FlextLdapModels.Group]].ok(groups)

    def _create_group_from_entry(
        self,
        entry: FlextLdapModels.Entry,
    ) -> FlextLdapModels.Group:
        """Create a Group object from an LDAP entry.

        Args:
            entry: LDAP entry to convert

        Returns:
            Group object

        """
        # Extract group information from entry
        dn = entry.dn
        cn_attr = entry["cn"]
        cn = str(cn_attr) if cn_attr else ""
        members_attr = entry["member"]
        # Ensure members is a list
        members = (
            members_attr
            if isinstance(members_attr, list)
            else [members_attr]
            if members_attr
            else []
        )

        return FlextLdapModels.Group(
            dn=dn,
            cn=cn,
            member_dns=members,
        )

    def search_with_request(
        self,
        request: FlextLdapModels.SearchRequest,
    ) -> FlextCore.Result[FlextLdapModels.SearchResponse]:
        """Search using a SearchRequest object."""
        search_result = self.search(
            request.base_dn,
            request.filter_str,
            request.attributes,
        )
        if search_result.is_failure:
            return FlextCore.Result[FlextLdapModels.SearchResponse].fail(
                search_result.error or "Search failed",
            )

        entries = search_result.unwrap()
        response = FlextLdapModels.SearchResponse(
            entries=entries,
            total_count=len(entries),
            result_code=0,
            time_elapsed=0.0,
        )

        return FlextCore.Result[FlextLdapModels.SearchResponse].ok(response)

    def update_user_attributes(
        self,
        dn: str,
        attributes: FlextCore.Types.Dict,
    ) -> FlextCore.Result[bool]:
        """Update user attributes using LDAP modify operation.

        Args:
            dn: Distinguished name of the user to update
            attributes: Dictionary of attribute name to new value mappings

        Returns:
            FlextCore.Result[bool]: Success if attributes were updated

        """
        try:
            # Validate DN
            dn_validation = FlextLdapValidations.validate_dn(dn)
            if dn_validation.is_failure:
                return FlextCore.Result[bool].fail(
                    dn_validation.error or "Invalid DN",
                )

            # Validate attributes dict[str, object] is not empty
            if not attributes:
                return FlextCore.Result[bool].fail("No attributes provided for update")

            # Convert to modify changes format (MODIFY_REPLACE for all)
            changes_dict: FlextCore.Types.Dict = {}
            for attr_name, attr_value in attributes.items():
                changes_dict[attr_name] = [("MODIFY_REPLACE", attr_value)]

            # Convert dict to EntryChanges model
            changes = FlextLdapModels.EntryChanges(**changes_dict)

            # Use existing modify_entry method
            return self.modify_entry(dn, changes)

        except Exception as e:
            self.logger.exception("Update user attributes failed", error=str(e), dn=dn)
            return FlextCore.Result[bool].fail(f"Update user attributes failed: {e}")

    def update_group_attributes(
        self,
        dn: str,
        attributes: FlextCore.Types.Dict,
    ) -> FlextCore.Result[bool]:
        """Update group attributes using LDAP modify operation.

        Args:
            dn: Distinguished name of the group to update
            attributes: Dictionary of attribute name to new value mappings

        Returns:
            FlextCore.Result[bool]: Success if attributes were updated

        """
        try:
            # Validate DN
            dn_validation = FlextLdapValidations.validate_dn(dn)
            if dn_validation.is_failure:
                return FlextCore.Result[bool].fail(
                    dn_validation.error or "Invalid DN",
                )

            # Validate attributes dict[str, object] is not empty
            if not attributes:
                return FlextCore.Result[bool].fail("No attributes provided for update")

            # Convert to modify changes format (MODIFY_REPLACE for all)
            changes_dict: FlextCore.Types.Dict = {}
            for attr_name, attr_value in attributes.items():
                changes_dict[attr_name] = [("MODIFY_REPLACE", attr_value)]

            # Convert dict to EntryChanges model
            changes = FlextLdapModels.EntryChanges(**changes_dict)

            # Use existing modify_entry method
            return self.modify_entry(dn, changes)

        except Exception as e:
            self.logger.exception("Update group attributes failed", error=str(e), dn=dn)
            return FlextCore.Result[bool].fail(f"Update group attributes failed: {e}")

    def delete_user(self, dn: str) -> FlextCore.Result[None]:
        """Delete a user from LDAP directory.

        Args:
            dn: Distinguished name of the user to delete

        Returns:
            FlextCore.Result[None]: Success if user was deleted

        """
        try:
            # Validate DN
            dn_validation = FlextLdapValidations.validate_dn(dn)
            if dn_validation.is_failure:
                return FlextCore.Result[None].fail(
                    dn_validation.error or "Invalid DN",
                )

            # Use existing delete_entry method
            delete_result = self.delete_entry(dn)
            if delete_result.is_failure:
                return FlextCore.Result[None].fail(
                    delete_result.error or "Delete user failed",
                )

            self.logger.info("User deleted successfully", user_dn=dn)
            return FlextCore.Result[None].ok(None)

        except Exception as e:
            self.logger.exception("Delete user failed", error=str(e), dn=dn)
            return FlextCore.Result[None].fail(f"Delete user failed: {e}")

    def create_user(
        self,
        user_request: FlextLdapModels.CreateUserRequest,
    ) -> FlextCore.Result[FlextLdapModels.LdapUser | None]:
        """Create a new user in LDAP directory."""
        # Convert CreateUserRequest to attributes dict
        attributes = user_request.to_attributes()

        # Add entry
        add_result = self.add_entry(user_request.dn, attributes)
        if add_result.is_failure:
            return FlextCore.Result[FlextLdapModels.LdapUser | None].fail(
                add_result.error or "Failed to create user",
            )

        # Return created user by fetching it
        return self.get_user(user_request.dn)

    def create_group(
        self,
        group_request: FlextLdapModels.CreateGroupRequest,
    ) -> FlextCore.Result[FlextLdapModels.Group | None]:
        """Create a new group in LDAP directory."""
        # Convert CreateGroupRequest to attributes dict
        attributes = group_request.to_attributes()

        # Add entry
        add_result = self.add_entry(group_request.dn, attributes)
        if add_result.is_failure:
            return FlextCore.Result[FlextLdapModels.Group | None].fail(
                add_result.error or "Failed to create group",
            )

        # Return created group by fetching it
        return self.get_group(group_request.dn)

    def add_member(self, group_dn: str, member_dn: str) -> FlextCore.Result[bool]:
        """Add a member to a group."""
        # Use modify_entry to add member
        changes_dict: FlextCore.Types.Dict = {
            "member": [(2, member_dn)]
        }  # 2 = ADD operation in ldap3
        changes = FlextLdapModels.EntryChanges(**changes_dict)
        return self.modify_entry(group_dn, changes)

    def remove_member(self, group_dn: str, member_dn: str) -> FlextCore.Result[bool]:
        """Remove a member from a group."""
        # Use modify_entry to remove member
        changes_dict: FlextCore.Types.Dict = {
            "member": [(1, member_dn)]
        }  # 1 = DELETE operation in ldap3
        changes = FlextLdapModels.EntryChanges(**changes_dict)
        return self.modify_entry(group_dn, changes)

    def get_members(
        self, group_dn: str
    ) -> FlextCore.Result[FlextCore.Types.StringList]:
        """Get all members of a group."""
        # Get the group and extract members
        group_result = self.get_group(group_dn)
        if group_result.is_failure:
            return FlextCore.Result[FlextCore.Types.StringList].fail(
                group_result.error or "Failed to get group",
            )

        group = group_result.unwrap()
        if not group or not hasattr(group, "member_dns"):
            return FlextCore.Result[FlextCore.Types.StringList].ok([])

        members: FlextCore.Types.StringList = (
            group.member_dns
            if isinstance(group.member_dns, list)
            else [group.member_dns]
        )
        return FlextCore.Result[FlextCore.Types.StringList].ok(members)

    @property
    def server_operations(self) -> BaseServerOperations | None:
        """Get the server operations instance."""
        return self._server_operations

    @property
    def server_type(self) -> str | None:
        """Get detected server type."""
        return self._detected_server_type

    def get_server_quirks(self) -> FlextLdapModels.ServerQuirks | None:
        """Get server quirks for detected server type."""
        if not self._detected_server_type:
            return None
        # Create server quirks based on detected type
        return FlextLdapModels.ServerQuirks(
            server_type=FlextLdapModels.LdapServerType(
                self._detected_server_type or "generic",
            ),
            case_sensitive_dns=self._detected_server_type == "ad",
            case_sensitive_attributes=self._detected_server_type == "ad",
            supports_paged_results=self._detected_server_type != "openldap1",
            supports_vlv=self._detected_server_type in {"oud", "oid"},
            max_page_size=FlextLdapConstants.Connection.MAX_PAGE_SIZE_GENERIC
            if self._detected_server_type != "ad"
            else FlextLdapConstants.Connection.MAX_PAGE_SIZE_AD,
        )
