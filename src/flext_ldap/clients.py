"""LDAP Client - Unified LDAP client with composition-based architecture.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

Note: Type checking disabled due to limitations in types-ldap3 package:
- Method return types (add, delete, search, modify, unbind) not specified
- Properties like conn.entries and entry.entry_dn are not fully typed
- Entry attributes and their values have incomplete type information
"""

from __future__ import annotations

import types
from typing import Literal, Self, cast, override

from flext_core import FlextResult, FlextService
from ldap3 import (
    ALL,
    DSA,
    MODIFY_ADD,
    MODIFY_DELETE,
    MODIFY_REPLACE,
    SCHEMA,
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
from flext_ldap.typings import (
    AttributeValue,
    LdapConfigDict,
)
from flext_ldap.validations import FlextLdapValidations

GetInfoType = Literal["NO_INFO", "DSA", "SCHEMA", "ALL"]
ModeType = Literal[
    "IP_SYSTEM_DEFAULT",
    "IP_V4_ONLY",
    "IP_V6_ONLY",
    "IP_V4_PREFERRED",
    "IP_V6_PREFERRED",
]


class FlextLdapClients(FlextService[None]):
    """FlextLdapClients - Main LDAP client using composition-based architecture.

    **UNIFIED CLASS PATTERN**: Single class per module with composition of components.

    **COMPOSITION ARCHITECTURE**: Uses dedicated components for responsibilities:
    - FlextLdapConnectionManager: Connection lifecycle management
    - FlextLdapAuthentication: Authentication operations
    - FlextLdapSearcher: Search operations

    Provides comprehensive LDAP operations interface: connection, auth, search, CRUD.
    Uses ldap3 internally, provides FlextResult-based API with auto-connection.

    **PROTOCOL IMPLEMENTATION**: Implements FlextProtocols.Connection as foundation
    for ALL connection-aware clients across FLEXT ecosystem via structural subtyping:
    - Infrastructure.Connection: test/close/get_string/__call__ methods
    - LdapConnectionProtocol: connect/disconnect/is_connected methods
    - LdapSearchProtocol: search/search_one methods
    - LdapModifyProtocol: add/modify/delete_entry methods
    - LdapAuthenticationProtocol: authenticate_user/validate_credentials methods
    - LdapValidationProtocol: validate_dn/validate_entry methods
    """

    def __init__(self, config: FlextLdapConfig | None = None) -> None:
        """Initialize LDAP client - consolidated implementation without bloat."""
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
        self._search_scope: Literal["BASE", "LEVEL", "SUBTREE"] = "SUBTREE"

        # Lazy-loaded components: search/auth (substantial logic)
        self._searcher: FlextLdapProtocols.Ldap.LdapSearcherProtocol | None = None
        self._authenticator: (
            FlextLdapProtocols.Ldap.LdapAuthenticationProtocol | None
        ) = None

    def _get_searcher(self) -> FlextLdapProtocols.Ldap.LdapSearcherProtocol:
        """Get searcher with lazy initialization."""
        if self._searcher is None:
            searcher: FlextLdapSearch = FlextLdapSearch(parent=self)
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
                cast("FlextLdapConfig", self._ldap_config),
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
    def execute(self) -> FlextResult[None]:
        """Execute the main domain operation (required by FlextService)."""
        return FlextResult[None].ok(None)

    # =========================================================================
    # CONTEXT MANAGER - Pure Python 3.13+ pattern for automatic cleanup
    # =========================================================================

    def __enter__(self) -> Self:
        """Enter context manager - pure Python 3.13+ pattern.

        Enables automatic resource cleanup via context manager protocol.
        Connection must still be established via connect() inside the context.

        Pure Python 3.13+ pattern - no wrappers, no helpers, no boilerplate.
        LDAP connections transparently cleanup when context exits.

        Example:
            >>> with FlextLdapClients() as client:
            ...     client.connect(server_uri, bind_dn, password)
            ...     # ... do LDAP operations ...
            ...     # Automatic unbind on context exit

        """
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: types.TracebackType | None,
    ) -> Literal[False]:
        """Exit context manager - automatic connection cleanup.

        Automatically calls unbind() when exiting context, ensuring
        proper resource cleanup even on exceptions.

        Args:
            exc_type: Exception type if an exception occurred
            exc_val: Exception value if an exception occurred
            exc_tb: Exception traceback if an exception occurred

        Returns:
            False to propagate exceptions (does not suppress)

        """
        if self.is_connected:
            result = self.unbind()
            if result.is_failure:
                self.logger.warning(
                    "Unbind failed during context exit: %s",
                    result.error,
                )
        return False  # Don't suppress exceptions

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
        connection_options: LdapConfigDict | None = None,
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
                    uri_validation.error or "Server URI validation failed",
                )

            # Use centralized DN validation for bind_dn
            bind_dn_validation = FlextLdapValidations.validate_dn(bind_dn, "Bind DN")
            if bind_dn_validation.is_failure:
                return FlextResult[bool].fail(
                    bind_dn_validation.error or "Bind DN validation failed",
                )

            # Use centralized password validation
            password_validation = FlextLdapValidations.validate_password(password)
            if password_validation.is_failure:
                return FlextResult[bool].fail(
                    password_validation.error or "Password validation failed",
                )

            self.logger.info("Connecting to LDAP server: %s", server_uri)

            # Apply connection options if provided
            if connection_options:
                # Build Server constructor arguments with proper typing
                port: int | None = None
                use_ssl: bool = False
                get_info: GetInfoType = cast("GetInfoType", SCHEMA)

                for key, value in connection_options.items():
                    if key == "port" and value is not None:
                        port = int(str(value))
                    elif key == "use_ssl" and value is not None:
                        use_ssl = bool(value)
                    elif key == "get_info" and value is not None:
                        str_value = str(value)
                        if str_value == "ALL":
                            get_info = cast("GetInfoType", ALL)
                        elif str_value == "SCHEMA":
                            get_info = cast("GetInfoType", SCHEMA)
                        elif str_value == "DSA":
                            get_info = cast("GetInfoType", DSA)

                # Set get_info to ALL if auto_discover_schema and not set
                if auto_discover_schema and get_info == cast("GetInfoType", SCHEMA):
                    get_info = cast("GetInfoType", ALL)

                # Create server with the collected arguments
                if port is not None:
                    self._server = Server(
                        server_uri,
                        port=port,
                        use_ssl=use_ssl,
                        get_info=get_info,
                    )
                else:
                    self._server = Server(
                        server_uri,
                        use_ssl=use_ssl,
                        get_info=get_info,
                    )
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
                return FlextResult[bool].fail("Failed to bind to LDAP server")

            self.logger.info("Successfully connected to LDAP server")

            # Update searcher and authenticator with new connection if they exist
            if self._searcher is not None:
                self._searcher.set_connection_context(self._connection)
            if self._authenticator is not None:
                self._authenticator.set_connection_context(
                    self._connection,
                    self._server,
                    cast("FlextLdapConfig", self._ldap_config),
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

            return FlextResult[bool].ok(True)

        except Exception as e:
            self.logger.exception("Connection failed")
            return FlextResult[bool].fail(f"Connection failed: {e}")

    def bind(self, bind_dn: str, password: str) -> FlextResult[bool]:
        """Bind to LDAP server with specified credentials."""
        try:
            if not self._connection:
                return FlextResult[bool].fail("LDAP connection not established")

            # Create new connection with provided credentials
            if not self._server:
                return FlextResult[bool].fail("No server connection established")

            self._connection = Connection(
                self._server,
                bind_dn,
                password,
                auto_bind=True,
            )

            if not self._connection.bound:
                return FlextResult[bool].fail("Bind failed - invalid credentials")

            return FlextResult[bool].ok(True)

        except Exception as e:
            self.logger.exception("Bind operation failed")
            return FlextResult[bool].fail(f"Bind failed: {e}")

    def unbind(self) -> FlextResult[None]:
        """Unbind from LDAP server."""
        try:
            if not self._connection:
                return FlextResult[None].ok(None)  # Idempotent

            if self._connection.bound:
                # ldap3 library has incomplete type stubs; external library limitation
                self._connection.unbind()
                self.logger.info("Unbound from LDAP server")

            self._connection = None
            self._server = None
            return FlextResult[None].ok(None)

        except Exception as e:
            self.logger.exception("Unbind failed")
            return FlextResult[None].fail(f"Unbind failed: {e}")

    @property
    def is_connected(self) -> bool:
        """Check if connected to LDAP server."""
        return self._connection is not None and self._connection.bound

    def test_connection(self) -> FlextResult[bool]:
        """Test LDAP connection."""
        if not self.is_connected:
            return FlextResult[bool].fail("LDAP connection not established")

        try:
            if self._connection:
                self._connection.search(
                    "",
                    FlextLdapConstants.Defaults.DEFAULT_SEARCH_FILTER,
                    self._search_scope,
                    attributes=["objectClass"],
                )
            return FlextResult[bool].ok(True)
        except Exception as e:
            return FlextResult[bool].fail(f"Connection test failed: {e}")

    @property
    def connection_string(self) -> str:
        """Get sanitized LDAP connection string."""
        if self._server and hasattr(self._server, "host"):
            protocol = "ldaps" if getattr(self._server, "ssl", False) else "ldap"
            host = self._server.host
            port = self._server.port
            return f"{protocol}://{host}:{port}"

        if self._ldap_config and hasattr(self._ldap_config, "ldap_server_uri"):
            return str(self._ldap_config.ldap_server_uri)

        return "ldap://not-connected"

    def __call__(self, *args: str, **kwargs: dict[str, object]) -> FlextResult[bool]:
        """Callable interface for connection."""
        if len(args) >= FlextLdapConstants.Validation.MIN_CONNECTION_ARGS:
            server_uri, bind_dn, password = str(args[0]), str(args[1]), str(args[2])

            # Extract known parameters with proper types
            auto_discover_schema_val: bool = True
            connection_options_val: LdapConfigDict | None = None

            if "auto_discover_schema" in kwargs:
                auto_discover_schema_val = bool(kwargs["auto_discover_schema"])

            if "connection_options" in kwargs:
                conn_opts = kwargs["connection_options"]
                if isinstance(conn_opts, dict):
                    connection_options_val = cast("LdapConfigDict", conn_opts)
                else:
                    connection_options_val = None

            return self.connect(
                server_uri=server_uri,
                bind_dn=bind_dn,
                password=password,
                auto_discover_schema=auto_discover_schema_val,
                connection_options=connection_options_val,
            )

        return FlextResult[bool].fail(
            "Invalid connection arguments. Expected: (server_uri, bind_dn, password)",
        )

    # =========================================================================
    # AUTHENTICATION - Delegated to FlextLdapAuthentication
    # =========================================================================

    def authenticate_user(
        self,
        username: str,
        password: str,
    ) -> FlextResult[FlextLdapModels.Entry]:
        """Authenticate user - delegates to authenticator."""
        return self._get_authenticator().authenticate_user(username, password)

    def validate_credentials(self, dn: str, password: str) -> FlextResult[bool]:
        """Validate credentials - delegates to authenticator."""
        return self._get_authenticator().validate_credentials(dn, password)

    # =========================================================================
    # SEARCH OPERATIONS - Delegated to FlextLdapSearcher
    # =========================================================================

    def search(
        self,
        base_dn: str,
        filter_str: str,
        attributes: list[str] | None = None,
        scope: Literal["BASE", "LEVEL", "SUBTREE"] = "SUBTREE",
        page_size: int = 0,
        paged_cookie: bytes | None = None,
    ) -> FlextResult[list[FlextLdapModels.Entry]]:
        """Perform LDAP search - delegates to searcher."""
        return self._get_searcher().search(
            base_dn, filter_str, attributes, scope, page_size, paged_cookie
        )

    def search_one(
        self,
        search_base: str,
        filter_str: str,
        attributes: list[str] | None = None,
    ) -> FlextResult[FlextLdapModels.Entry | None]:
        """Search for single entry - delegates to searcher."""
        return self._get_searcher().search_one(search_base, filter_str, attributes)

    def get_user(self, dn: str) -> FlextResult[FlextLdapModels.Entry | None]:
        """Get user by DN - delegates to searcher."""
        return self._get_searcher().get_user(dn)

    def get_group(self, dn: str) -> FlextResult[FlextLdapModels.Entry | None]:
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
        self,
        dn: str,
        attributes: dict[str, str | list[str]],
    ) -> FlextResult[bool]:
        """Add new LDAP entry - implements LdapModifyProtocol.

        Handles undefined attributes gracefully by filtering them out and retrying.
        This makes the API extensible to work with any LDAP schema without limitations.
        """
        try:
            if not self.connection:
                return FlextResult[bool].fail("LDAP connection not established")

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
            removed_attributes: list[str] = []
            max_retries = 20  # Limit retries to avoid infinite loops
            retry_count = 0

            while not success and retry_count < max_retries:
                try:
                    # Extract objectClass from attributes or use default
                    object_class_raw = attempted_attributes.get("objectClass", ["top"])
                    if isinstance(object_class_raw, list):
                        object_class = (
                            object_class_raw[0] if object_class_raw else "top"
                        )
                    else:
                        object_class = str(object_class_raw)
                    # ldap3 has incomplete type stubs
                    success = self.connection.add(
                        dn, object_class=object_class, attributes=attempted_attributes
                    )
                    if success:
                        if removed_attributes:
                            msg = f"Removed attrs: {removed_attributes}"
                            self.logger.debug(msg)
                        return FlextResult[bool].ok(True)

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
                            # Get last word (attribute name)
                            problem_attr = error_parts[-1].strip()
                            if problem_attr in attempted_attributes:
                                msg = f"Removing undefined '{problem_attr}'"
                                self.logger.debug(msg)
                                del attempted_attributes[problem_attr]
                                removed_attributes.append(problem_attr)
                                retry_count += 1
                                continue

                    # If we can't identify the problem attribute or other error, fail
                    return FlextResult[bool].fail(
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
                                msg = f"Exception on undefined '{problem_attr}'"
                                self.logger.debug(msg)
                                del attempted_attributes[problem_attr]
                                removed_attributes.append(problem_attr)
                                retry_count += 1
                                continue
                    # Re-raise if not an attribute error
                    raise

            # If we exhausted retries
            if retry_count >= max_retries:
                return FlextResult[bool].fail(
                    f"Add entry failed after {max_retries} retries removing attributes"
                )

            return FlextResult[bool].fail(
                f"Add entry failed: {self.connection.last_error}",
            )

        except Exception as e:
            self.logger.exception("Add entry failed")
            return FlextResult[bool].fail(f"Add entry failed: {e}")

    def modify_entry(
        self, dn: str, changes: FlextLdapModels.EntryChanges
    ) -> FlextResult[bool]:
        """Modify existing LDAP entry - implements LdapModifyProtocol."""
        try:
            if not self.connection:
                return FlextResult[bool].fail("LDAP connection not established")

            # Convert changes to ldap3 format
            # ldap3 expects: {'attr': [(MODIFY_OP, [values])]}
            ldap3_changes: dict[str, list[tuple[str | int, list[str]]]] = {}
            changes_dict: dict[str, object] = (
                changes.model_dump()
                if hasattr(changes, "model_dump")
                else cast("dict[str, object]", changes)
            )
            for attr, change_spec in changes_dict.items():
                # Check if already in ldap3 tuple format: [(operation, values)]
                if (
                    isinstance(change_spec, list)
                    and change_spec
                    and isinstance(change_spec[0], tuple)
                ):
                    # Already in correct format
                    ldap3_changes[attr] = cast(
                        "list[tuple[str | int, list[str]]]", change_spec
                    )
                elif isinstance(change_spec, dict):
                    # Handle dict format (complex operations)
                    # Convert dict operations to proper tuple format for ldap3
                    operations: list[tuple[str, list[str]]] = []
                    for op_name, op_value in change_spec.items():
                        if op_name == "MODIFY_ADD":
                            operations.append((
                                str(MODIFY_ADD),
                                [op_value]
                                if not isinstance(op_value, list)
                                else op_value,
                            ))
                        elif op_name == "MODIFY_DELETE":
                            operations.append((
                                str(MODIFY_DELETE),
                                [op_value]
                                if not isinstance(op_value, list)
                                else op_value,
                            ))
                        elif op_name == "MODIFY_REPLACE":
                            operations.append((
                                str(MODIFY_REPLACE),
                                [op_value]
                                if not isinstance(op_value, list)
                                else op_value,
                            ))
                        elif op_name == "MODIFY_INCREMENT":
                            # MODIFY_INCREMENT not supported, skip
                            msg = f"MODIFY_INCREMENT not supported for {attr}"
                            self.logger.warning(msg)
                            continue
                    # Cast to match expected dict value type
                    ldap3_changes[attr] = cast(
                        "list[tuple[str | int, list[str]]]", operations
                    )
                else:
                    # Simple value - wrap as MODIFY_REPLACE
                    ldap3_changes[attr] = [
                        cast(
                            "tuple[str | int, list[str]]",
                            (
                                MODIFY_REPLACE,
                                change_spec
                                if isinstance(change_spec, list)
                                else [str(change_spec)],
                            ),
                        )
                    ]

            # ldap3 library has incomplete type stubs; external library limitation
            success = self.connection.modify(
                dn,
                changes=cast(
                    "dict[str, list[tuple[int, list[str] | str]]]", ldap3_changes
                ),
            )
            if success:
                return FlextResult[bool].ok(True)
            return FlextResult[bool].fail(
                f"Modify entry failed: {self.connection.last_error}",
            )

        except Exception as e:
            self.logger.exception("Modify entry failed")
            return FlextResult[bool].fail(f"Modify entry failed: {e}")

    def delete_entry(self, dn: str) -> FlextResult[bool]:
        """Delete LDAP entry - implements LdapModifyProtocol."""
        try:
            if not self.connection:
                return FlextResult[bool].fail("LDAP connection not established")

            # ldap3 library has incomplete type stubs; external library limitation
            success = self.connection.delete(dn)
            if success:
                return FlextResult[bool].ok(True)
            return FlextResult[bool].fail(
                f"Delete entry failed: {self.connection.last_error}",
            )

        except Exception as e:
            self.logger.exception("Delete entry failed")
            return FlextResult[bool].fail(f"Delete entry failed: {e}")

    # =========================================================================
    # VALIDATION OPERATIONS - Direct implementation
    # =========================================================================

    def validate_dn(self, dn: str) -> FlextResult[bool]:
        """Validate distinguished name format - implements LdapValidationProtocol."""
        validation_result = FlextLdapValidations.validate_dn(dn)
        if validation_result.is_failure:
            return FlextResult[bool].fail(
                validation_result.error or "DN validation failed",
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
    # HELPER - Unified mock schema builder (Python 3.13+ consolidation)
    # =========================================================================

    @staticmethod
    def _create_mock_schema_result() -> FlextLdapModels.SchemaDiscoveryResult:
        """Create unified mock schema result for unavailable schemas."""
        mock_server_info = FlextLdapModels.ServerInfo(
            vendor_name="Mock LDAP Server",
            vendor_version="1.0.0",
            supported_ldap_version=["3"],
            naming_contexts=["dc=flext,dc=local"],
            supported_controls=[],
            supported_extensions=[],
            supported_sasl_mechanisms=["EXTERNAL"],
        )
        mock_server_quirks = FlextLdapModels.ServerQuirks(
            server_type=FlextLdapModels.LdapServerType.GENERIC,
            case_sensitive_dns=False,
            case_sensitive_attributes=False,
            supports_paged_results=True,
            supports_vlv=False,
            supports_sync=False,
            max_page_size=1000,
            default_timeout=30,
            supports_start_tls=True,
            requires_explicit_bind=False,
        )
        return FlextLdapModels.SchemaDiscoveryResult(
            server_info=mock_server_info,
            server_type=FlextLdapModels.LdapServerType.GENERIC,
            server_quirks=mock_server_quirks,
            attributes={},
            object_classes={},
            naming_contexts=["dc=flext,dc=local"],
            supported_controls=[],
            supported_extensions=[],
        )

    # =========================================================================
    # ADVANCED OPERATIONS - Direct implementation
    # =========================================================================

    def discover_schema(self) -> FlextResult[FlextLdapModels.SchemaDiscoveryResult]:
        """Discover LDAP schema information."""
        try:
            if not self.connection:
                return FlextResult[FlextLdapModels.SchemaDiscoveryResult].fail(
                    "LDAP connection not established",
                )

            # Get schema (automatically loaded with connection)
            # Note: schema may not be available on all connection types
            try:
                schema = getattr(self.connection, "schema", None)
                if not schema:
                    msg = "Schema not available, using mock"
                    self.logger.warning(msg)
                    return FlextResult[FlextLdapModels.SchemaDiscoveryResult].ok(
                        self._create_mock_schema_result()
                    )
            except AttributeError:
                msg = "Schema attribute not available, using mock"
                self.logger.warning(msg)
                return FlextResult[FlextLdapModels.SchemaDiscoveryResult].ok(
                    self._create_mock_schema_result()
                )

            # Create real schema result
            # For now, create basic ServerInfo from schema
            server_info = FlextLdapModels.ServerInfo(
                naming_contexts=getattr(schema, "naming_contexts", []),
                supported_ldap_version=["3"],  # Default to LDAPv3
                supported_sasl_mechanisms=[],
                supported_controls=[],
                supported_extensions=[],
                vendor_name=getattr(schema, "vendor_name", None),
                vendor_version=getattr(schema, "vendor_version", None),
            )

            # Create basic server quirks (could be enhanced with real detection)
            server_quirks = FlextLdapModels.ServerQuirks(
                server_type=FlextLdapModels.LdapServerType.GENERIC,
                case_sensitive_dns=False,
                case_sensitive_attributes=False,
                supports_paged_results=True,
                supports_vlv=False,
                supports_sync=False,
                max_page_size=1000,
                default_timeout=30,
                supports_start_tls=True,
                requires_explicit_bind=False,
            )

            # Convert schema attributes and object classes
            attributes = {}
            if hasattr(schema, "attribute_types") and schema.attribute_types:
                for attr_name, attr_def in schema.attribute_types.items():
                    attributes[attr_name] = FlextLdapModels.SchemaAttribute(
                        name=attr_name,
                        oid=getattr(attr_def, "oid", ""),
                        syntax=getattr(attr_def, "syntax", ""),
                        is_single_valued=getattr(attr_def, "single_value", False),
                        is_operational=getattr(attr_def, "operational", False),
                        is_collective=getattr(attr_def, "collective", False),
                        is_no_user_modification=getattr(
                            attr_def, "no_user_modification", False
                        ),
                        usage=getattr(attr_def, "usage", "userApplications"),
                        equality=getattr(attr_def, "equality", None),
                        ordering=getattr(attr_def, "ordering", None),
                        substr=getattr(attr_def, "substr", None),
                    )

            object_classes = {}
            if hasattr(schema, "object_classes") and schema.object_classes:
                for oc_name, oc_def in schema.object_classes.items():
                    object_classes[oc_name] = FlextLdapModels.SchemaObjectClass(
                        name=oc_name,
                        oid=getattr(oc_def, "oid", ""),
                        superior=getattr(oc_def, "superior", []),
                        must=getattr(oc_def, "must", []),
                        may=getattr(oc_def, "may", []),
                    )

            schema_result = FlextLdapModels.SchemaDiscoveryResult(
                server_info=server_info,
                server_type=FlextLdapModels.LdapServerType.GENERIC,
                server_quirks=server_quirks,
                attributes=attributes,
                object_classes=object_classes,
                naming_contexts=getattr(schema, "naming_contexts", []),
                supported_controls=[],
                supported_extensions=[],
            )

            return FlextResult[FlextLdapModels.SchemaDiscoveryResult].ok(schema_result)

        except Exception as e:
            self.logger.exception("Schema discovery failed")
            return FlextResult[FlextLdapModels.SchemaDiscoveryResult].fail(
                f"Schema discovery failed: {e}"
            )

    # =========================================================================
    # NORMALIZATION OPERATIONS - Server-agnostic attribute normalization
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

    def get_server_info(self) -> FlextResult[FlextLdapModels.ServerInfo]:
        """Get comprehensive server information including capabilities and schema."""
        try:
            if not self.connection:
                return FlextResult[FlextLdapModels.ServerInfo].fail(
                    "LDAP connection not established",
                )

            server_info = self.connection.server.info
            if not server_info:
                return FlextResult[FlextLdapModels.ServerInfo].fail(
                    "Server info not available"
                )

            # Convert server info to ServerInfo model
            server_info_model = FlextLdapModels.ServerInfo(
                vendor_name=getattr(server_info, "vendor_name", {}).get(
                    "value",
                    "Unknown",
                )
                if hasattr(server_info, "vendor_name")
                else "Unknown",
                vendor_version=getattr(server_info, "vendor_version", {}).get(
                    "value",
                    "Unknown",
                )
                if hasattr(server_info, "vendor_version")
                else "Unknown",
                supported_ldap_version=getattr(
                    server_info,
                    "supported_ldap_version",
                    ["3"],
                ),
                naming_contexts=getattr(server_info, "naming_contexts", []),
                supported_controls=getattr(server_info, "supported_controls", []),
                supported_extensions=getattr(
                    server_info,
                    "supported_extensions",
                    [],
                ),
                supported_sasl_mechanisms=getattr(
                    server_info,
                    "supported_sasl_mechanisms",
                    [],
                ),
                supported_features=getattr(server_info, "supported_features", []),
                schema_entry=getattr(server_info, "schema_entry", ""),
            )

            return FlextResult[FlextLdapModels.ServerInfo].ok(server_info_model)

        except Exception as e:
            return FlextResult[FlextLdapModels.ServerInfo].fail(
                f"Failed to get server info: {e}"
            )

    def get_server_capabilities(
        self,
    ) -> FlextResult[FlextLdapModels.ServerCapabilities]:
        """Get server capabilities and supported features."""
        try:
            if not self.server_operations:
                return FlextResult[FlextLdapModels.ServerCapabilities].fail(
                    "Server operations not available",
                )

            # Create ServerCapabilities model from server operations
            capabilities = FlextLdapModels.ServerCapabilities(
                supports_ssl=True,
                supports_starttls=self.server_operations.supports_start_tls(),
                supports_paged_results=self.server_operations.supports_paged_results(),
                supports_vlv=self.server_operations.supports_vlv(),
                supports_sasl=True,
                max_page_size=self.server_operations.get_max_page_size(),
            )

            return FlextResult[FlextLdapModels.ServerCapabilities].ok(capabilities)

        except Exception as e:
            return FlextResult[FlextLdapModels.ServerCapabilities].fail(
                f"Failed to get server capabilities: {e}",
            )

    # =========================================================================
    # MISSING METHODS - Required by API layer
    # =========================================================================

    def _search_entity(
        self,
        base_dn: str,
        entity_type: Literal["user", "group"],
        filter_override: str | None = None,
        cn: str | None = None,
        attributes: list[str] | None = None,
    ) -> FlextResult[list[FlextLdapModels.Entry]]:
        """Unified entity search using Python 3.13+ pattern matching.

        Consolidates search_users() and search_groups() into single method.

        Args:
            base_dn: LDAP search base DN
            entity_type: Type of entity ('user' or 'group')
            filter_override: Custom filter string
            cn: Common name for group filtering
            attributes: List of attributes to retrieve

        Returns:
            FlextResult with list of Entry models

        """
        # Build filter using pattern matching
        match entity_type:
            case "user":
                search_filter = filter_override or "(objectClass=person)"
            case "group":
                search_filter = (
                    f"(&(objectClass=groupOfNames)(cn={cn}))"
                    if cn
                    else "(objectClass=groupOfNames)"
                )
            case _:
                search_filter = filter_override or "(objectClass=*)"

        search_result = self.search(base_dn, search_filter, attributes)
        if search_result.is_failure:
            error_msg = f"{entity_type.capitalize()} search failed"
            return FlextResult[list[FlextLdapModels.Entry]].fail(
                search_result.error or error_msg,
            )

        # Post-process based on entity type using FlextResult composition
        if entity_type == "group":
            entries = search_result.unwrap()

            # Define processor function wrapping group conversion with FlextResult
            def process_group_entry(
                entry: FlextLdapModels.Entry,
            ) -> FlextResult[FlextLdapModels.Entry]:
                """Wrap group conversion with FlextResult for batch processing."""
                return FlextResult[FlextLdapModels.Entry].from_callable(
                    lambda: self._create_group_from_entry(entry)
                )

            # Use batch_process to separate successes from failures
            groups, failures = FlextResult.batch_process(entries, process_group_entry)

            # Log failures but continue (same behavior as manual loop)
            for failure_msg in failures:
                self.logger.warning("Failed to convert entry to group: %s", failure_msg)

            return FlextResult[list[FlextLdapModels.Entry]].ok(groups)

        return search_result

    def search_users(
        self,
        base_dn: str,
        filter_str: str | None = None,
        attributes: list[str] | None = None,
    ) -> FlextResult[list[FlextLdapModels.Entry]]:
        """Search for LDAP users with smart defaults."""
        return self._search_entity(base_dn, "user", filter_str, attributes=attributes)

    def search_groups(
        self,
        base_dn: str,
        cn: str | None = None,
        attributes: list[str] | None = None,
    ) -> FlextResult[list[FlextLdapModels.Entry]]:
        """Search for LDAP groups."""
        return self._search_entity(base_dn, "group", cn=cn, attributes=attributes)

    def _create_group_from_entry(
        self,
        entry: FlextLdapModels.Entry,
    ) -> FlextLdapModels.Entry:
        """Create a Group object from an LDAP entry.

        Args:
            entry: LDAP entry to convert

        Returns:
            Group object

        """
        # Extract group information from entry
        dn = entry.dn
        cn_attr = entry["cn"]
        if cn_attr:
            if isinstance(cn_attr, list):
                cn = str(cn_attr[0]) if cn_attr else ""
            else:
                cn = str(cn_attr)
        else:
            cn = ""
        members_attr = entry["member"]
        # Ensure members is a list and filter out non-string values
        if members_attr:
            members_list: list[object] = (
                list(members_attr) if isinstance(members_attr, list) else [members_attr]
            )
            # Filter to only include string values (member DNs)
            members = [
                str(member) for member in members_list if isinstance(member, str)
            ]
        else:
            members = []

        return FlextLdapModels.Entry(
            dn=dn,
            cn=cn,
            entry_type="group",
            member_dns=members,
            object_classes=["groupOfNames", "top"],
        )

    def search_with_request(
        self,
        request: FlextLdapModels.SearchRequest,
    ) -> FlextResult[FlextLdapModels.SearchResponse]:
        """Search using a SearchRequest object."""
        search_result = self.search(
            request.base_dn,
            request.filter_str,
            request.attributes,
        )
        if search_result.is_failure:
            return FlextResult[FlextLdapModels.SearchResponse].fail(
                search_result.error or "Search failed",
            )

        entries = search_result.unwrap()
        response = FlextLdapModels.SearchResponse(
            entries=entries,
            total_count=len(entries),
            result_code=0,
            time_elapsed=0.0,
        )

        return FlextResult[FlextLdapModels.SearchResponse].ok(response)

    def _update_entity_attributes(
        self,
        dn: str,
        attributes: dict[str, object],
        entity_type: Literal["user", "group"] = "user",
    ) -> FlextResult[bool]:
        """Unified entity attribute update using Python 3.13+ pattern matching.

        Consolidates update_user_attributes() and update_group_attributes().

        Args:
            dn: Distinguished name of the entity to update
            attributes: Dictionary of attribute name to new value mappings
            entity_type: Type of entity ('user' or 'group')

        Returns:
            FlextResult[bool]: Success if attributes were updated

        """
        try:
            # Validate DN
            dn_validation = FlextLdapValidations.validate_dn(dn)
            if dn_validation.is_failure:
                return FlextResult[bool].fail(dn_validation.error or "Invalid DN")

            # Validate attributes dictionary
            if not attributes:
                return FlextResult[bool].fail("No attributes provided for update")

            # Convert to modify changes format
            changes_dict: dict[str, object] = {
                attr_name: [("MODIFY_REPLACE", attr_value)]
                for attr_name, attr_value in attributes.items()
            }

            # Convert to EntryChanges and modify
            changes = FlextLdapModels.EntryChanges(**changes_dict)
            return self.modify_entry(dn, changes)

        except Exception as e:
            error_msg = f"Update {entity_type} attributes failed"
            self.logger.exception(error_msg, error=str(e), dn=dn)
            return FlextResult[bool].fail(f"{error_msg}: {e}")

    def update_user_attributes(
        self,
        dn: str,
        attributes: dict[str, object],
    ) -> FlextResult[bool]:
        """Update user attributes using LDAP modify operation."""
        return self._update_entity_attributes(dn, attributes, "user")

    def update_group_attributes(
        self,
        dn: str,
        attributes: dict[str, object],
    ) -> FlextResult[bool]:
        """Update group attributes using LDAP modify operation."""
        return self._update_entity_attributes(dn, attributes, "group")

    def delete_user(self, dn: str) -> FlextResult[None]:
        """Delete a user from LDAP directory.

        Args:
            dn: Distinguished name of the user to delete

        Returns:
            FlextResult[None]: Success if user was deleted

        """
        try:
            # Validate DN
            dn_validation = FlextLdapValidations.validate_dn(dn)
            if dn_validation.is_failure:
                return FlextResult[None].fail(
                    dn_validation.error or "Invalid DN",
                )

            # Use existing delete_entry method
            delete_result = self.delete_entry(dn)
            if delete_result.is_failure:
                return FlextResult[None].fail(
                    delete_result.error or "Delete user failed",
                )

            self.logger.info("User deleted successfully", user_dn=dn)
            return FlextResult[None].ok(None)

        except Exception as e:
            self.logger.exception("Delete user failed", error=str(e), dn=dn)
            return FlextResult[None].fail(f"Delete user failed: {e}")

    def create_user(
        self,
        user_request: FlextLdapModels._LdapRequest,
    ) -> FlextResult[FlextLdapModels.Entry | None]:
        """Create a new user in LDAP directory."""
        # Convert CreateUserRequest to attributes dict
        attributes_result = self.build_user_attributes(user_request)
        if attributes_result.is_failure:
            return FlextResult[FlextLdapModels.Entry | None].fail(
                attributes_result.error or "Failed to build user attributes"
            )
        attributes = attributes_result.unwrap()

        # Add entry
        add_result = self.add_entry(user_request.dn, attributes)
        if add_result.is_failure:
            return FlextResult[FlextLdapModels.Entry | None].fail(
                add_result.error or "Failed to create user",
            )

        # Return created user by fetching it
        return self.get_user(user_request.dn)

    def create_group(
        self,
        group_request: FlextLdapModels._LdapRequest,
    ) -> FlextResult[FlextLdapModels.Entry | None]:
        """Create a new group in LDAP directory."""
        # Convert CreateGroupRequest to attributes dict
        attributes = group_request.to_attributes()

        # Add entry
        add_result = self.add_entry(group_request.dn, attributes)
        if add_result.is_failure:
            return FlextResult[FlextLdapModels.Entry | None].fail(
                add_result.error or "Failed to create group",
            )

        # Return created group by fetching it
        return self.get_group(group_request.dn)

    def add_member(self, group_dn: str, member_dn: str) -> FlextResult[bool]:
        """Add a member to a group."""
        # Use modify_entry to add member
        changes_dict: dict[str, object] = {
            "member": [(2, member_dn)]
        }  # 2 = ADD operation in ldap3
        changes = FlextLdapModels.EntryChanges(**changes_dict)
        return self.modify_entry(group_dn, changes)

    def remove_member(self, group_dn: str, member_dn: str) -> FlextResult[bool]:
        """Remove a member from a group."""
        # Use modify_entry to remove member
        changes_dict: dict[str, object] = {
            "member": [(1, member_dn)]
        }  # 1 = DELETE operation in ldap3
        changes = FlextLdapModels.EntryChanges(**changes_dict)
        return self.modify_entry(group_dn, changes)

    def get_members(self, group_dn: str) -> FlextResult[list[str]]:
        """Get all members of a group."""
        # Get the group and extract members
        group_result = self.get_group(group_dn)
        if group_result.is_failure:
            return FlextResult[list[str]].fail(
                group_result.error or "Failed to get group",
            )

        group = group_result.unwrap()
        if not group or not hasattr(group, "member_dns"):
            return FlextResult[list[str]].ok([])

        members: list[str] = (
            group.member_dns
            if isinstance(group.member_dns, list)
            else [group.member_dns]
        )
        return FlextResult[list[str]].ok(members)

    @property
    def server_operations(self) -> BaseServerOperations | None:
        """Get the server operations instance."""
        return self._server_operations

    @property
    def server_type(self) -> str | None:
        """Get detected server type."""
        return self._detected_server_type

    @property
    def session_id(self) -> str | None:
        """Get session ID for connection tracking."""
        return getattr(self, "_session_id", None)

    @session_id.setter
    def session_id(self, value: str | None) -> None:
        """Set session ID for connection tracking."""
        self._session_id = value

    @property
    def server_quirks(self) -> FlextLdapModels.ServerQuirks | None:
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

    def _create_user_from_entry_result(
        self, entry: FlextLdapModels.Entry
    ) -> FlextResult[FlextLdapModels.Entry]:
        """Create user from entry result (private helper method)."""
        try:
            # Convert to Entry field types
            def extract_first_value(
                value: AttributeValue | None,
            ) -> str | None:
                """Extract first value from EntryAttributeValue (str | list[str])."""
                if value is None:
                    return None
                if isinstance(value, list):
                    return value[0] if value else None
                return value

            # Build user data with proper type conversion and defaults
            user_data: dict[str, object] = {
                "dn": entry.dn,
                "cn": extract_first_value(entry.attributes.get("cn", "")) or "",
                "uid": extract_first_value(entry.attributes.get("uid", "")) or "",
                "sn": extract_first_value(entry.attributes.get("sn", "")) or "",
                "given_name": extract_first_value(
                    entry.attributes.get(
                        "givenName", entry.attributes.get("given_name")
                    )
                ),
                "mail": extract_first_value(entry.attributes.get("mail")),
                "telephone_number": extract_first_value(
                    entry.attributes.get(
                        "telephoneNumber", entry.attributes.get("telephone_number")
                    )
                ),
                "mobile": extract_first_value(entry.attributes.get("mobile")),
                "department": extract_first_value(entry.attributes.get("department")),
                "title": extract_first_value(entry.attributes.get("title")),
                "organization": extract_first_value(
                    entry.attributes.get("o", entry.attributes.get("organization"))
                ),
                "organizational_unit": extract_first_value(
                    entry.attributes.get(
                        "ou", entry.attributes.get("organizational_unit")
                    )
                ),
                "user_password": extract_first_value(
                    entry.attributes.get("userPassword")
                ),
                "entry_type": "user",
                "object_classes": entry.object_classes
                or ["person", "inetOrgPerson", "top"],
                "status": extract_first_value(entry.attributes.get("status")),
                "display_name": extract_first_value(
                    entry.attributes.get("displayName")
                ),
                "additional_attributes": entry.attributes,
            }

            # Construct Entry with type-checking
            user = FlextLdapModels.Entry.model_validate(user_data)
            return FlextResult.ok(user)
        except Exception as e:
            return FlextResult.fail(f"User creation failed: {e}")

    def _validate_search_request(
        self, _request: FlextLdapModels.SearchRequest
    ) -> FlextResult[None]:
        """Validate search request (private helper method)."""
        # Basic validation is handled by Pydantic model
        return FlextResult.ok(None)

    def build_user_attributes(
        self, user_request: FlextLdapModels._LdapRequest
    ) -> FlextResult[dict[str, str | list[str]]]:
        """Build user attributes from request object."""
        try:
            attributes: dict[str, str | list[str]] = {}

            # Required fields
            if user_request.uid:
                attributes["uid"] = [user_request.uid]
            if user_request.cn:
                attributes["cn"] = [user_request.cn]
            if user_request.sn:
                attributes["sn"] = [user_request.sn]

            # Optional fields
            if user_request.mail:
                attributes["mail"] = [user_request.mail]
            if user_request.given_name:
                attributes["givenName"] = [user_request.given_name]
            if user_request.user_password:
                attributes["userPassword"] = [user_request.user_password]
            if user_request.telephone_number:
                attributes["telephoneNumber"] = [user_request.telephone_number]
            if hasattr(user_request, "description") and user_request.description:
                attributes["description"] = [user_request.description]
            if user_request.department:
                attributes["ou"] = [user_request.department]
            if user_request.title:
                attributes["title"] = [user_request.title]
            if user_request.organization:
                attributes["o"] = [user_request.organization]

            # Object classes
            object_classes = ["top", "person"]
            if user_request.uid:
                object_classes.append("inetOrgPerson")
            attributes["objectClass"] = object_classes

            return FlextResult.ok(attributes)
        except Exception as e:
            return FlextResult.fail(f"Attribute building failed: {e}")

    def _create_user_from_entry(
        self, entry: FlextLdapModels.Entry
    ) -> FlextResult[FlextLdapModels.Entry]:
        """Create user from entry (private helper method)."""
        return self._create_user_from_entry_result(entry)

    def _normalize(self, value: object, normalize_type: str = "string") -> object:
        """Unified normalizer using Python 3.13+ pattern matching (ONE METHOD).

        Replaces 5 separate normalization methods with single unified handler.

        Args:
            value: Value to normalize (str, list, dict, or entries)
            normalize_type: Type of normalization ('string', 'attributes', 'entry', 'changes', 'results')

        Returns:
            Normalized value in original type

        """
        match normalize_type, value:
            case "string", str():
                return value.strip()

            case "attributes", list():
                return [str(attr).strip() for attr in value]

            case "entry", dict():
                return {
                    k: (
                        [str(v).strip() for v in val]
                        if isinstance(val, list)
                        else str(val).strip()
                    )
                    for k, val in value.items()
                }

            case "changes", dict():
                return {
                    k: [(op, [s.strip() for s in vals]) for op, vals in change_list]
                    for k, change_list in value.items()
                }

            case "results", list():
                # Search results pass through as-is
                return value

            case _:
                # Default: return unchanged
                return value
