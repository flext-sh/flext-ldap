"""Unified LDAP client with composition-based architecture.

Provides complete LDAP client functionality with server-specific operations,
connection management, and Clean Architecture separation of concerns.

Note: types-ldap3 package has incomplete type stubs for some methods and
properties (add, delete, search, modify, conn.entries, entry.entry_dn).

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import types
from typing import Literal, Self, cast, override

from flext_core import (
    FlextDecorators,
    FlextResult,
    FlextRuntime,
    FlextService,
)
from flext_ldif import FlextLdifConstants, FlextLdifModels, FlextLdifUtilities
from ldap3 import (
    Connection,
    Server,
)
from ldap3.core.exceptions import (
    LDAPAttributeError,
    LDAPBindError,
    LDAPCommunicationError,
    LDAPInvalidDnError,
    LDAPInvalidFilterError,
    LDAPInvalidScopeError,
    LDAPNoSuchAttributeResult,
    LDAPNoSuchObjectResult,
    LDAPObjectClassError,
    LDAPObjectError,
    LDAPOperationsErrorResult,
    LDAPPasswordIsMandatoryError,
    LDAPResponseTimeoutError,
    LDAPSocketOpenError,
    LDAPStartTLSError,
    LDAPUserNameIsMandatoryError,
)
from pydantic import Field, ValidationError

from flext_ldap.config import FlextLdapConfig
from flext_ldap.constants import FlextLdapConstants
from flext_ldap.models import FlextLdapModels
from flext_ldap.protocols import FlextLdapProtocols
from flext_ldap.servers.base_operations import FlextLdapServersBaseOperations
from flext_ldap.servers.factory import FlextLdapServersFactory
from flext_ldap.services.authentication import FlextLdapAuthentication
from flext_ldap.services.entry_adapter import FlextLdapEntryAdapter
from flext_ldap.services.search import FlextLdapSearch
from flext_ldap.services.validations import FlextLdapValidations
from flext_ldap.typings import FlextLdapTypes
from flext_ldap.utilities import FlextLdapUtilities


# =========================================================================
# INTERNAL UTILITIES - DN/Attribute Conversion Helpers
# =========================================================================
class FlextLdapClients(FlextService[None]):
    """FlextLdapClients - Main LDAP client using composition-based architecture.

    UNIFIED CLASS PATTERN: Single class per module with composition of components.

    COMPOSITION ARCHITECTURE: Uses dedicated components for responsibilities:
    - FlextLdapConnectionManager: Connection lifecycle management
    - FlextLdapAuthentication: Authentication operations
    - FlextLdapSearcher: Search operations

    Provides complete LDAP operations interface: connection, auth, search, CRUD.
    Uses ldap3 internally, provides FlextResult-based API with auto-connection.

    PROTOCOL IMPLEMENTATION: Implements FlextProtocols.Connection as foundation
    for ALL connection-aware clients across FLEXT ecosystem via structural subtyping:
    - Infrastructure.Connection: test/close/get_string/__call__ methods
    - LdapConnectionProtocol: connect/disconnect/is_connected methods
    - LdapSearchProtocol: search/search_one methods
    - LdapModifyProtocol: add/modify/delete_entry methods
    - LdapAuthenticationProtocol: authenticate_user/validate_credentials methods
    - LdapValidationProtocol: validate_dn/validate_entry methods
    """

    # Pydantic field declaration (required for validate_assignment=True)
    s_mode: FlextLdapConstants.Types.QuirksMode = Field(
        default=FlextLdapConstants.Types.QuirksMode.AUTOMATIC,
        description="Server-specific LDIF quirks handling mode for entry transformation",
    )

    def __init__(
        self,
        config: FlextLdapConfig | None = None,
        *,
        _quirks_mode: FlextLdapConstants.Types.QuirksMode = FlextLdapConstants.Types.QuirksMode.AUTOMATIC,
    ) -> None:
        """Initialize LDAP client - consolidated implementation without bloat.

        Args:
            config: LDAP configuration (uses global if None)
            _quirks_mode: Server quirks mode (AUTOMATIC, OID, OUD, or RFC)

        """
        super().__init__()

        # Core configuration and logging
        self._ldap_config = config
        # s_mode is auto-initialized by Field default above

        # Direct connection state (no delegation layer)
        self._connection: Connection | None = None
        self._server: Server | None = None

        # Server type detection for configuration
        self._detected_server_type: str | None = None

        # Search scope constant - use literal string for type safety
        self._search_scope: FlextLdapConstants.Types.Ldap3Scope = "SUBTREE"

        # Lazy-loaded components: search/auth (substantial logic)
        self._searcher: FlextLdapProtocols.Ldap.LdapSearcherProtocol | None = None
        self._authenticator: (
            FlextLdapProtocols.Ldap.LdapAuthenticationProtocol | None
        ) = None

    def _get_searcher(self) -> FlextLdapProtocols.Ldap.LdapSearcherProtocol:
        """Get searcher using functional lazy initialization with FlextRuntime.

        Uses FlextRuntime.safe_get_attribute for thread-safe lazy loading
        and functional composition for connection setup.
        """
        # Functional lazy initialization using FlextRuntime (DRY principle)
        searcher = FlextRuntime.safe_get_attribute(self, "_searcher", None)

        if searcher is None:
            # Functional composition: create and configure searcher
            searcher = FlextLdapSearch()
            if self._connection:
                searcher.set_connection_context(self._connection)
            self._searcher = cast(
                "FlextLdapProtocols.Ldap.LdapSearcherProtocol",
                searcher,
            )

        return searcher

    def _get_authenticator(self) -> FlextLdapProtocols.Ldap.LdapAuthenticationProtocol:
        """Get authenticator using functional lazy initialization with FlextRuntime.

        Uses FlextRuntime.safe_get_attribute for thread-safe lazy loading
        and functional composition for connection context setup.
        """
        # Functional lazy initialization using FlextRuntime (DRY principle)
        authenticator = FlextRuntime.safe_get_attribute(self, "_authenticator", None)

        if authenticator is None:
            # Functional composition: create and configure authenticator
            auth = FlextLdapAuthentication()
            auth.set_connection_context(
                self._connection,
                self._server,
                cast("FlextLdapConfig", self._ldap_config),
            )
            authenticator = cast(
                "FlextLdapProtocols.Ldap.LdapAuthenticationProtocol",
                auth,
            )
            self._authenticator = authenticator

        return authenticator

    @property
    def connection(self) -> Connection | None:
        """Get the current LDAP connection using functional property access.

        Returns the active LDAP connection or None if not connected.
        Uses FlextRuntime.safe_get_attribute for safe property access.
        """
        # Functional property access with safe fallback
        return FlextRuntime.safe_get_attribute(self, "_connection", None)

    @property
    def quirks_mode(self) -> FlextLdapConstants.Types.QuirksMode:
        """Get current quirks mode using functional property access.

        Returns the active server-specific quirks handling mode.
        Uses FlextRuntime.safe_get_attribute for safe property access.
        """
        # Functional property access with safe fallback
        mode = FlextRuntime.safe_get_attribute(self, "s_mode", None)
        if isinstance(mode, FlextLdapConstants.Types.QuirksMode):
            return mode
        return FlextLdapConstants.Types.QuirksMode.STRICT

    @property
    def quirks_mode_description(self) -> str:
        """Get human-readable description using functional composition.

        Returns human-readable description of current quirks mode.
        Uses functional approach with dictionary lookup and safe fallback.
        """

        # Functional description lookup with safe fallback
        def get_description(mode: FlextLdapConstants.Types.QuirksMode) -> str:
            """Get description for a given quirks mode."""
            descriptions = {
                FlextLdapConstants.Types.QuirksMode.AUTOMATIC: "Auto-detect server type and apply quirks",
                FlextLdapConstants.Types.QuirksMode.SERVER: "Use explicit server type with quirks",
                FlextLdapConstants.Types.QuirksMode.RFC: "RFC-compliant only, no extensions",
                FlextLdapConstants.Types.QuirksMode.RELAXED: "Permissive mode, accept anything",
            }
            return descriptions.get(mode, FlextLdapConstants.ErrorStrings.UNKNOWN_ERROR)

        # Functional composition: get mode then get description
        current_mode = self.quirks_mode
        return get_description(current_mode)

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
        ... client.connect(server_uri, bind_dn, password)
        ... #... do LDAP operations...
        ... # Automatic unbind on context exit

        """
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        _exc_tb: types.TracebackType | None,
    ) -> Literal[False]:
        """Exit context manager - automatic connection cleanup.

        Automatically calls unbind() when exiting context, ensuring
        proper resource cleanup even on exceptions.

        Args:
        exc_type: Exception type if an exception occurred
        exc_val: Exception value if an exception occurred
        _exc_tb: Exception traceback if an exception occurred - intentionally unused

        Returns:
        False to propagate exceptions (does not suppress)

        """
        if self.is_connected:
            # Type narrowing: if is_connected is True, connection exists
            if self._connection is None:
                error_msg = "Connection should exist when is_connected is True"
                raise RuntimeError(error_msg)
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

    # Connection Management Helper Methods

    def _validate_connection_params(
        self,
        server_uri: str,
        bind_dn: FlextLdifModels.DistinguishedName | str,
        password: str,
    ) -> FlextResult[str]:
        """Validate connection parameters and return bind_dn string."""
        uri_validation = FlextLdapUtilities.Validation.validate_ldap_uri(
            "Server URI",
            server_uri,
        )
        if uri_validation.is_failure:
            return FlextResult[str].fail(
                uri_validation.error or "Server URI validation failed",
            )

        bind_dn_str = str(getattr(bind_dn, "value", bind_dn))
        bind_dn_validation = FlextLdapValidations.validate_dn(bind_dn_str, "Bind DN")
        if bind_dn_validation.is_failure:
            return FlextResult[str].fail(
                bind_dn_validation.error or "Bind DN validation failed",
            )

        password_validation = FlextLdapUtilities.Validation.validate_password(
            "Password",
            password,
        )
        if password_validation.is_failure:
            return FlextResult[str].fail(
                password_validation.error or "Password validation failed",
            )

        return FlextResult[str].ok(bind_dn_str)

    def _parse_connection_options(
        self,
        connection_options: dict[str, object],
        *,
        auto_discover_schema: bool,
    ) -> tuple[int | None, bool, FlextLdapConstants.Types.GetInfoType]:
        """Parse connection options into Server parameters."""
        port: int | None = None
        use_ssl: bool = False
        get_info: FlextLdapConstants.Types.GetInfoType = (
            FlextLdapConstants.Types.GetInfoType.SCHEMA
        )

        if isinstance(connection_options, dict) and connection_options:
            for key, value in connection_options.items():
                if key == "port" and value is not None:
                    port = int(str(value))
                elif key == "use_ssl" and value is not None:
                    use_ssl = bool(value)
                elif key == "get_info" and value is not None:
                    str_value = str(value)
                    get_info_map = {
                        FlextLdapConstants.Types.GetInfoType.ALL.value: FlextLdapConstants.Types.GetInfoType.ALL,
                        FlextLdapConstants.Types.GetInfoType.SCHEMA.value: FlextLdapConstants.Types.GetInfoType.SCHEMA,
                        FlextLdapConstants.Types.GetInfoType.DSA.value: FlextLdapConstants.Types.GetInfoType.DSA,
                        FlextLdapConstants.Types.GetInfoType.NO_INFO.value: FlextLdapConstants.Types.GetInfoType.NO_INFO,
                    }
                    get_info = get_info_map.get(
                        str_value, FlextLdapConstants.Types.GetInfoType.SCHEMA
                    )

        if (
            auto_discover_schema
            and get_info == FlextLdapConstants.Types.GetInfoType.SCHEMA
        ):
            get_info = FlextLdapConstants.Types.GetInfoType.ALL

        return port, use_ssl, get_info

    def _create_ldap_server(
        self,
        server_uri: str,
        *,
        auto_discover_schema: bool,
        connection_options: dict[str, object] | None,
    ) -> Server:
        """Create LDAP Server instance with appropriate configuration."""
        if (
            connection_options
            and isinstance(connection_options, dict)
            and connection_options
        ):
            port, use_ssl, get_info = self._parse_connection_options(
                connection_options,
                auto_discover_schema=auto_discover_schema,
            )
            # Convert enum to ldap3-compatible literal using constant mapping
            get_info_literal = FlextLdapConstants.Types.GET_INFO_TO_LDAP3[get_info]
            if port is not None:
                return Server(
                    server_uri,
                    port=port,
                    use_ssl=use_ssl,
                    get_info=get_info_literal,
                )
            return Server(
                server_uri,
                use_ssl=use_ssl,
                get_info=get_info_literal,
            )
        if auto_discover_schema:
            # Convert enum constant to ldap3-compatible literal
            return Server(
                server_uri,
                get_info=FlextLdapConstants.Types.GET_INFO_TO_LDAP3[
                    FlextLdapConstants.Types.GetInfoType.ALL
                ],
            )
        return Server(server_uri)

    def _bind_and_verify_connection(
        self,
        server: Server,
        bind_dn_str: str,
        password: str,
    ) -> FlextResult[Connection]:
        """Create and bind LDAP connection, verify successful binding."""
        # Use auto_bind=False to capture specific bind error messages
        connection = Connection(server, bind_dn_str, password, auto_bind=False)
        try:
            bind_result = connection.bind()
            if not bind_result:
                error_msg = connection.last_error or "Bind returned False"
                return FlextResult[Connection].fail(f"Bind failed: {error_msg}")
            return FlextResult[Connection].ok(connection)
        except (LDAPBindError, LDAPCommunicationError) as e:
            return FlextResult[Connection].fail(f"Bind error: {e}")

    def _update_dependent_services(self) -> None:
        """Update searcher and authenticator with new connection."""
        if self._searcher is not None and self._connection is not None:
            self._searcher.set_connection_context(self._connection)
        if self._authenticator is not None and self._connection is not None:
            self._authenticator.set_connection_context(
                self._connection,
                self._server,
                cast("FlextLdapConfig", self._ldap_config),
            )

    def _auto_detect_server_type(self) -> None:
        """Auto-detect server type from Root DSE."""
        try:
            root_dse_result = self._get_root_dse_attributes()
            if root_dse_result.is_success:
                root_dse = root_dse_result.unwrap()
                self._detected_server_type = (
                    FlextLdapUtilities.ServerDetection.detect_server_type_from_root_dse(
                        root_dse,
                    )
                )
                self.logger.info(
                    "Auto-detected LDAP server type: %s",
                    self._detected_server_type,
                )
            else:
                self._detected_server_type = FlextLdifConstants.LdapServers.GENERIC
                self.logger.debug("Could not detect server type, using generic")
        except Exception as e:
            self._detected_server_type = FlextLdifConstants.LdapServers.GENERIC
            self.logger.debug("Server detection failed, using generic: %s", e)

    @FlextDecorators.log_operation("LDAP Connection")
    @FlextDecorators.track_performance("LDAP Connection")
    @FlextDecorators.retry(max_attempts=3, backoff_strategy="exponential")
    @FlextDecorators.timeout(timeout_seconds=30.0)
    def connect(
        self,
        request: FlextLdapModels.ConnectionRequest,
    ) -> FlextResult[bool]:
        """Connect and bind to LDAP server with universal compatibility.

        Refactored to use ConnectionRequest model (6 parameters → 1 model).
        Reduces complexity and improves maintainability with Pydantic validation.

        Args:
            request: Connection request with server_uri, bind_dn, password,
                     auto_discover_schema, connection_options, quirks_mode.

        Returns:
            FlextResult[bool]: Success result or error.

        Example:
            >>> request = FlextLdapModels.ConnectionRequest(
            ...     server_uri="ldap://localhost:389",
            ...     bind_dn="cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com",
            ...     password="secret",
            ... )
            >>> result = client.connect(request)

        """
        try:
            # Step 1: Validate all connection parameters (Pydantic already validated)
            validation_result = self._validate_connection_params(
                request.server_uri,
                request.bind_dn,
                request.password,
            )
            if validation_result.is_failure:
                return FlextResult[bool].fail(validation_result.error)

            bind_dn_str = validation_result.unwrap()

            # Step 2: Store quirks mode if provided
            if request.quirks_mode is not None:
                self.logger.debug("Quirks mode updated to: %s", request.quirks_mode)

            self.logger.debug("Connecting to LDAP server: %s", request.server_uri)

            # Step 3: Create server instance
            self._server = self._create_ldap_server(
                request.server_uri,
                auto_discover_schema=request.auto_discover_schema,
                connection_options=request.connection_options,
            )

            # Step 4: Create and bind connection
            connection_result = self._bind_and_verify_connection(
                self._server,
                bind_dn_str,
                request.password,
            )
            if connection_result.is_failure:
                return FlextResult[bool].fail(connection_result.error)

            self._connection = connection_result.unwrap()
            self.logger.info("Successfully connected to LDAP server")

            # Step 5: Update dependent services
            self._update_dependent_services()

            # Step 6: Auto-detect server type
            self._auto_detect_server_type()

            return FlextResult[bool].ok(True)

        except (
            LDAPSocketOpenError,
            LDAPCommunicationError,
            LDAPBindError,
            LDAPStartTLSError,
            LDAPResponseTimeoutError,
            ValidationError,
        ) as e:
            self.logger.exception("Connection failed")
            return FlextResult[bool].fail(f"Connection failed: {e}")

    def _get_root_dse_attributes(self) -> FlextResult[dict[str, object]]:
        """Get Root DSE attributes for server detection."""
        try:
            if (
                not getattr(self._connection, "bound", False)
                if self._connection
                else False
            ):
                return FlextResult[dict[str, object]].fail(
                    FlextLdapConstants.ErrorMessages.CONNECTION_NOT_BOUND
                )

            # Type narrowing: connection is not None here
            connection = cast("Connection", self._connection)
            search_result = connection.search(
                search_base="",
                search_filter=FlextLdapConstants.Filters.ALL_ENTRIES_FILTER,
                search_scope=cast(
                    "FlextLdapConstants.Types.Ldap3Scope",
                    FlextLdapConstants.Scopes.BASE_LDAP3,
                ),
                attributes=["*", "+"],
                size_limit=1,
            )

            if not search_result or not connection.entries:
                return FlextResult[dict[str, object]].fail(
                    FlextLdapConstants.ErrorMessages.NO_ROOT_DSE_FOUND
                )

            entry = connection.entries[0]
            attrs: dict[str, object] = {}
            for attr in entry.entry_attributes:
                attrs[attr] = entry[attr].value

            return FlextResult[dict[str, object]].ok(attrs)

        except Exception as e:
            return FlextResult[dict[str, object]].fail(
                f"Root DSE retrieval failed: {e}",
            )

    @FlextDecorators.log_operation("LDAP Bind")
    @FlextDecorators.track_performance("LDAP Bind")
    @FlextDecorators.retry(max_attempts=2, backoff_strategy="linear")
    @FlextDecorators.timeout(timeout_seconds=15.0)
    def bind(
        self,
        bind_dn: FlextLdifModels.DistinguishedName | str,
        password: str,
    ) -> FlextResult[bool]:
        """Bind to LDAP server with specified credentials."""
        try:
            if not self._connection:
                return FlextResult[bool].fail(
                    FlextLdapConstants.ErrorMessages.LDAP_CONNECTION_NOT_ESTABLISHED
                )

            # Create new connection with provided credentials
            if not self._server:
                return FlextResult[bool].fail(
                    FlextLdapConstants.ErrorMessages.SERVER_CONNECTION_NOT_ESTABLISHED
                )

            bind_dn_str = (
                bind_dn.value
                if isinstance(bind_dn, FlextLdifModels.DistinguishedName)
                else bind_dn
            )
            # Use auto_bind=False to capture specific error messages
            self._connection = Connection(
                self._server,
                bind_dn_str,
                password,
                auto_bind=False,
            )

            # Explicitly bind and check result
            bind_result = self._connection.bind()
            if not bind_result:
                error_msg = (
                    self._connection.last_error or "Bind failed - invalid credentials"
                )
                return FlextResult[bool].fail(error_msg)

            return FlextResult[bool].ok(True)

        except (
            LDAPBindError,
            LDAPPasswordIsMandatoryError,
            LDAPUserNameIsMandatoryError,
            LDAPCommunicationError,
        ) as e:
            self.logger.exception("Bind operation failed")
            return FlextResult[bool].fail(f"Bind failed: {e}")

    def unbind(self) -> FlextResult[None]:
        """Unbind from LDAP server."""
        try:
            if not self._connection:
                return FlextResult[None].ok(None)  # Idempotent

            if self._connection.bound:
                # Cast to Protocol type for proper type checking with ldap3
                typed_conn = cast(
                    "FlextLdapTypes.Ldap3Protocols.Connection",
                    self._connection,
                )
                typed_conn.unbind()
                self.logger.debug("Unbound from LDAP server")

            self._connection = None
            self._server = None

            # CRITICAL: Reset cached components to prevent them from using stale connections
            # The searcher and authenticator cache their own connection references
            # If we don't reset them, they'll try to use the closed connection
            self._searcher = None
            self._authenticator = None

            return FlextResult[None].ok(None)

        except LDAPCommunicationError as e:
            self.logger.exception("Unbind failed")
            return FlextResult[None].fail(f"Unbind failed: {e}")

    @property
    def is_connected(self) -> bool:
        """Check if connected to LDAP server."""
        return self._connection is not None and self._connection.bound

    def test_connection(self) -> FlextResult[bool]:
        """Test LDAP connection."""
        if not self.is_connected:
            return FlextResult[bool].fail(
                FlextLdapConstants.ErrorMessages.LDAP_CONNECTION_NOT_ESTABLISHED
            )

        try:
            if self._connection:
                # Test connection by reading root DSE with BASE scope
                search_result = self._connection.search(
                    "",  # Root DSE
                    FlextLdapConstants.Defaults.DEFAULT_SEARCH_FILTER,
                    "BASE",  # BASE scope for root DSE
                    attributes=[FlextLdapConstants.LdapAttributeNames.OBJECT_CLASS],
                )
                if not search_result:
                    error_msg = (
                        self._connection.last_error or "Connection test search failed"
                    )
                    return FlextResult[bool].fail(error_msg)
            return FlextResult[bool].ok(True)
        except (
            LDAPCommunicationError,
            LDAPResponseTimeoutError,
            LDAPInvalidFilterError,
            LDAPInvalidScopeError,
        ) as e:
            return FlextResult[bool].fail(f"Connection test failed: {e}")

    @property
    def connection_string(self) -> str:
        """Get sanitized LDAP connection string."""
        if self._server and hasattr(self._server, "host"):
            protocol = (
                FlextLdapConstants.Protocol.LDAPS
                if FlextRuntime.safe_get_attribute(self._server, "ssl", False)
                else FlextLdapConstants.Protocol.LDAP
            )
            host = self._server.host
            port = self._server.port
            return f"{protocol}://{host}:{port}"

        if self._ldap_config and hasattr(self._ldap_config, "ldap_server_uri"):
            return str(self._ldap_config.ldap_server_uri)

        return "ldap://not-connected"

    def __call__(self, *args: str, **kwargs: dict[str, object]) -> FlextResult[bool]:
        """Callable interface for connection - creates ConnectionRequest and delegates."""
        if len(args) >= FlextLdapConstants.Validation.MIN_CONNECTION_ARGS:
            server_uri, bind_dn, password = str(args[0]), str(args[1]), str(args[2])

            # Extract optional parameters with proper types
            auto_discover_schema_val: bool = True
            connection_options_val: dict[str, object] | None = None
            quirks_mode_val: str | None = None

            if "auto_discover_schema" in kwargs:
                auto_discover_schema_val = bool(kwargs["auto_discover_schema"])

            if "connection_options" in kwargs:
                conn_opts = kwargs["connection_options"]
                if FlextRuntime.is_dict_like(conn_opts):
                    connection_options_val = conn_opts

            if "quirks_mode" in kwargs:
                quirks_mode_val = (
                    str(kwargs["quirks_mode"]) if kwargs["quirks_mode"] else None
                )

            # Create ConnectionRequest model and delegate to connect()
            request = FlextLdapModels.ConnectionRequest(
                server_uri=server_uri,
                bind_dn=bind_dn,
                password=password,
                auto_discover_schema=auto_discover_schema_val,
                connection_options=connection_options_val,
                quirks_mode=quirks_mode_val,
            )
            return self.connect(request)

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
    ) -> FlextResult[FlextLdifModels.Entry]:
        """Authenticate user - delegates to authenticator."""
        return self._get_authenticator().authenticate_user(username, password)

    @FlextDecorators.log_operation("LDAP Credential Validation")
    @FlextDecorators.track_performance("LDAP Credential Validation")
    @FlextDecorators.timeout(timeout_seconds=10.0)
    def validate_credentials(
        self,
        dn: FlextLdifModels.DistinguishedName | str,
        password: str,
    ) -> FlextResult[bool]:
        """Validate credentials - delegates to authenticator."""
        dn_str = str(getattr(dn, "value", dn) if hasattr(dn, "value") else dn)
        return self._get_authenticator().validate_credentials(dn_str, password)

    # =========================================================================
    # SEARCH OPERATIONS - Delegated to FlextLdapSearcher
    # =========================================================================

    @FlextDecorators.log_operation("LDAP Search")
    @FlextDecorators.track_performance("LDAP Search")
    @FlextDecorators.retry(max_attempts=2, backoff_strategy="linear")
    @FlextDecorators.timeout(timeout_seconds=60)
    def search(
        self,
        request: FlextLdapModels.SearchRequest,
    ) -> FlextResult[list[FlextLdifModels.Entry] | FlextLdifModels.Entry | None]:
        """Perform LDAP search - delegates to searcher.

        Refactored to use SearchRequest model (8 parameters → 1 model).
        Reduces complexity and improves maintainability with Pydantic validation.

        Args:
            request: Search request with base_dn, filter_str, attributes, scope,
                     page_size, paged_cookie, single, quirks_mode.

        Returns:
            FlextResult with list of entries or single entry based on request.single.

        Example:
            >>> request = FlextLdapModels.SearchRequest(
            ...     base_dn="dc=example,dc=com",
            ...     filter_str="(objectClass=person)",
            ...     scope="subtree",
            ... )
            >>> result = client.search(request)

        """
        # Use provided quirks_mode or fall back to instance quirks_mode
        effectives_mode = cast(
            "FlextLdapConstants.Types.QuirksMode",
            request.quirks_mode or self.s_mode,
        )

        # Get or create searcher with FRESH connection context for each search
        # This ensures we always have the current connection state and prevents stale references
        searcher = self._get_searcher()

        # CRITICAL: Always refresh connection context before search
        # Connection state can change between calls, so we must verify it's current
        if self._connection is not None:
            searcher.set_connection_context(self._connection)
        else:
            return FlextResult[
                list[FlextLdifModels.Entry] | FlextLdifModels.Entry | None
            ].fail("No LDAP connection available for search operation")

        searcher.sets_mode(effectives_mode)

        # Convert scope to lowercase for searcher compatibility
        normalized_scope_str = (
            request.scope.lower() if isinstance(request.scope, str) else request.scope
        )
        # Cast to Ldap3Scope for type checker
        normalized_scope = cast(
            "FlextLdapConstants.Types.Ldap3Scope",
            normalized_scope_str,
        )

        base_dn_str = (
            request.base_dn.value
            if isinstance(request.base_dn, FlextLdifModels.DistinguishedName)
            else request.base_dn
        )
        # Ensure page_size is int (default 0 if None)
        page_size_val = request.page_size if request.page_size is not None else 0
        search_result = searcher.search(
            base_dn_str,
            request.filter_str,
            request.attributes,
            normalized_scope,
            page_size_val,
            request.paged_cookie,
        )

        if search_result.is_failure:
            return cast(
                "FlextResult[list[FlextLdifModels.Entry] | FlextLdifModels.Entry | None]",
                search_result,
            )

        # Handle single result request
        if request.single:
            entries = search_result.unwrap()
            if entries and len(entries) > 0:
                return FlextResult[
                    list[FlextLdifModels.Entry] | FlextLdifModels.Entry | None
                ].ok(entries[0])
            return FlextResult[
                list[FlextLdifModels.Entry] | FlextLdifModels.Entry | None
            ].ok(None)

        return cast(
            "FlextResult[list[FlextLdifModels.Entry] | FlextLdifModels.Entry | None]",
            search_result,
        )

    def search_one(
        self,
        search_base: str,
        filter_str: str,
        attributes: list[str] | None = None,
        *,
        quirks_mode: FlextLdapConstants.Types.QuirksMode | None = None,
    ) -> FlextResult[FlextLdifModels.Entry | None]:
        """Search for single entry - delegates to searcher.

        Args:
            search_base: Search base DN
            filter_str: LDAP filter string
            attributes: Attributes to retrieve
            quirks_mode: Override default quirks mode for this search

        Returns:
            FlextResult with single entry or None

        """
        # Use provided quirks_mode or fall back to instance quirks_mode
        effectives_mode = quirks_mode or self.s_mode

        # Pass quirks information to searcher
        searcher = self._get_searcher()
        searcher.sets_mode(effectives_mode)

        if not self._connection:
            return FlextResult[FlextLdifModels.Entry | None].fail(
                FlextLdapConstants.ErrorMessages.LDAP_CONNECTION_NOT_ESTABLISHED,
            )
        return searcher.search_one(search_base, filter_str, attributes)

    def _get_entry_by_dn(
        self,
        dn: FlextLdifModels.DistinguishedName | str,
    ) -> FlextResult[FlextLdifModels.Entry | None]:
        """Get entry by DN - generic implementation for get_user/get_group."""
        if not self._connection:
            return FlextResult[FlextLdifModels.Entry | None].fail(
                FlextLdapConstants.ErrorMessages.LDAP_CONNECTION_NOT_ESTABLISHED,
            )
        dn_str = dn.value if isinstance(dn, FlextLdifModels.DistinguishedName) else dn
        return self._get_searcher().search_one(
            dn_str,
            FlextLdapConstants.Defaults.DEFAULT_SEARCH_FILTER,
            attributes=["*"],
        )

    def get_user(
        self,
        dn: FlextLdifModels.DistinguishedName | str,
    ) -> FlextResult[FlextLdifModels.Entry | None]:
        """Get user by DN - delegates to _get_entry_by_dn()."""
        return self._get_entry_by_dn(dn)

    def get_group(
        self,
        dn: FlextLdifModels.DistinguishedName | str,
    ) -> FlextResult[FlextLdifModels.Entry | None]:
        """Get group by DN - delegates to _get_entry_by_dn()."""
        return self._get_entry_by_dn(dn)

    def user_exists(
        self,
        dn: FlextLdifModels.DistinguishedName | str,
    ) -> FlextResult[bool]:
        """Check user existence - uses get_user."""
        result = self.get_user(dn)
        if result.is_failure:
            error = result.error or FlextLdapConstants.ErrorStrings.UNKNOWN_ERROR
            if "LDAP connection" in error or "DN cannot be empty" in error:
                return FlextResult[bool].fail(error)
            return FlextResult[bool].ok(False)
        return FlextResult[bool].ok(result.unwrap() is not None)

    def group_exists(
        self,
        dn: FlextLdifModels.DistinguishedName | str,
    ) -> FlextResult[bool]:
        """Check group existence - uses get_group."""
        result = self.get_group(dn)
        if result.is_failure:
            error = result.error or FlextLdapConstants.ErrorStrings.UNKNOWN_ERROR
            if "LDAP connection" in error or "DN cannot be empty" in error:
                return FlextResult[bool].fail(error)
            return FlextResult[bool].ok(False)
        return FlextResult[bool].ok(result.unwrap() is not None)

    # =========================================================================
    # CRUD OPERATIONS - Direct implementation (simpler operations)
    # =========================================================================

    # Add Entry Helper Methods

    def _convert_attributes_to_ldap3_format(
        self,
        attributes: FlextLdifModels.LdifAttributes | dict[str, str | list[str]],
    ) -> dict[str, list[str]]:
        """Convert attributes to ldap3 format (dict with list values)."""
        attrs_dict: dict[str, str | list[str]]
        if isinstance(attributes, FlextLdifModels.LdifAttributes):
            attrs_dict = cast("dict[str, str | list[str]]", attributes.attributes)
        else:
            attrs_dict = attributes

        ldap3_attributes: dict[str, list[str]] = {}
        for key, value in attrs_dict.items():
            if FlextRuntime.is_list_like(value):
                # Convert list-like object to list of strings
                if isinstance(value, list):
                    ldap3_attributes[key] = [str(item) for item in value]
                else:
                    # Handle other sequence types
                    ldap3_attributes[key] = [str(value)]
            else:
                ldap3_attributes[key] = [str(value)]
        return ldap3_attributes

    def _attempt_add_entry(
        self,
        dn_str: str,
        attempted_attributes: dict[str, list[str]],
    ) -> bool:
        """Attempt to add entry with current attributes."""
        object_class_raw = attempted_attributes.get(
            FlextLdapConstants.LdapAttributeNames.OBJECT_CLASS,
            [FlextLdapConstants.Defaults.OBJECT_CLASS_TOP],
        )
        if FlextRuntime.is_list_like(object_class_raw):
            object_class = (
                str(object_class_raw[0])
                if object_class_raw
                else FlextLdapConstants.Defaults.OBJECT_CLASS_TOP
            )
        else:
            object_class = str(object_class_raw)

        typed_conn = cast(
            "FlextLdapTypes.Ldap3Protocols.Connection",
            self.connection,
        )
        attrs = cast(
            "dict[str, str | list[str]] | None",
            attempted_attributes,
        )
        return typed_conn.add(dn_str, object_class=object_class, attributes=attrs)

    def _extract_undefined_attribute(
        self,
        error_msg: str,
        attempted_attributes: dict[str, list[str]],
    ) -> str | None:
        """Extract attribute name from undefined attribute error."""
        error_parts = error_msg.split()
        if len(error_parts) > 0:
            problem_attr = error_parts[-1].strip()
            if problem_attr in attempted_attributes:
                return problem_attr
        return None

    def _handle_undefined_attribute_error(
        self,
        attempted_attributes: dict[str, list[str]],
        removed_attributes: list[str],
    ) -> bool:
        """Handle undefined attribute error by removing problematic attribute."""
        if not self.connection:
            return False

        error_msg = str(self.connection.last_error).lower()
        if (
            "undefined attribute" not in error_msg
            and "invalid attribute" not in error_msg
        ):
            return False

        problem_attr = self._extract_undefined_attribute(
            str(self.connection.last_error),
            attempted_attributes,
        )
        if problem_attr:
            self.logger.debug("Removing undefined '%s'", problem_attr)
            del attempted_attributes[problem_attr]
            removed_attributes.append(problem_attr)
            return True
        return False

    @FlextDecorators.log_operation("LDAP Add Entry")
    @FlextDecorators.track_performance("LDAP Add Entry")
    @FlextDecorators.timeout(timeout_seconds=30.0)
    def add_entry(
        self,
        dn: FlextLdifModels.DistinguishedName | str,
        attributes: FlextLdifModels.LdifAttributes | dict[str, str | list[str]],
        *,
        quirks_mode: FlextLdapConstants.Types.QuirksMode | None = None,
    ) -> FlextResult[bool]:
        """Add new LDAP entry - implements LdapModifyProtocol.

        Handles undefined attributes gracefully by filtering them out and retrying.
        This makes the API extensible to work with any LDAP schema without limitations.

        Args:
            dn: Distinguished name for new entry
            attributes: Entry attributes (FlextLdifModels.LdifAttributes or dict)
            quirks_mode: Override default quirks mode for this operation

        Returns:
            FlextResult[bool]: Success if entry was added

        """
        try:
            if not self.connection:
                return FlextResult[bool].fail(
                    FlextLdapConstants.ErrorMessages.LDAP_CONNECTION_NOT_ESTABLISHED
                )

            # Determine effective quirks mode
            effectives_mode = quirks_mode or self.s_mode

            # Convert attributes to ldap3 format
            ldap3_attributes = self._convert_attributes_to_ldap3_format(attributes)

            # Convert DN to string
            dn_str = (
                dn.value if isinstance(dn, FlextLdifModels.DistinguishedName) else dn
            )

            # Retry logic with undefined attribute handling
            attempted_attributes = ldap3_attributes.copy()
            removed_attributes: list[str] = []
            max_retries = (
                1 if effectives_mode == FlextLdapConstants.Types.QuirksMode.RFC else 20
            )
            retry_count = 0

            self.logger.debug(
                "Adding entry with quirks_mode: %s (effective: %s)",
                quirks_mode,
                effectives_mode,
            )

            while retry_count < max_retries:
                try:
                    success = self._attempt_add_entry(dn_str, attempted_attributes)
                    if success:
                        if removed_attributes:
                            self.logger.debug("Removed attrs: %s", removed_attributes)
                        return FlextResult[bool].ok(True)

                    # Try to handle undefined attribute error
                    if self._handle_undefined_attribute_error(
                        attempted_attributes,
                        removed_attributes,
                    ):
                        retry_count += 1
                        continue

                    # Unknown error
                    return FlextResult[bool].fail(
                        f"Add entry failed: {self.connection.last_error}",
                    )

                except (LDAPAttributeError, LDAPObjectClassError) as e:
                    error_str = str(e).lower()
                    if (
                        "undefined attribute" in error_str
                        or "invalid attribute" in error_str
                    ):
                        problem_attr = self._extract_undefined_attribute(
                            str(e),
                            attempted_attributes,
                        )
                        if problem_attr:
                            self.logger.debug(
                                "Exception on undefined '%s'", problem_attr
                            )
                            del attempted_attributes[problem_attr]
                            removed_attributes.append(problem_attr)
                            retry_count += 1
                            continue
                    raise

            # Exhausted retries
            return FlextResult[bool].fail(
                f"Add entry failed after {max_retries} retries removing attributes",
            )

        except (
            LDAPCommunicationError,
            LDAPAttributeError,
            LDAPInvalidDnError,
            LDAPObjectError,
            LDAPObjectClassError,
            LDAPOperationsErrorResult,
            ValidationError,
        ) as e:
            self.logger.exception("Add entry failed")
            return FlextResult[bool].fail(f"Add entry failed: {e}")

    # Modify Entry Helper Methods

    def _convert_changes_to_dict(
        self,
        changes: FlextLdapModels.EntryChanges,
    ) -> dict[str, object]:
        """Convert EntryChanges to dict format."""
        if hasattr(changes, "model_dump"):
            return changes.model_dump()
        if hasattr(changes, "items"):
            return dict(changes)
        # Fallback: cast to dict (changes should always have model_dump() or items())
        return cast("dict[str, object]", changes)

    def _parse_change_spec_to_ldap3(
        self,
        change_spec: object,
    ) -> list[tuple[str | int, list[str]]]:
        """Parse change spec to ldap3 tuple format."""
        # Already in ldap3 tuple format
        if (
            isinstance(change_spec, list)
            and change_spec
            and isinstance(change_spec[0], tuple)
        ):
            return cast("list[tuple[str | int, list[str]]]", change_spec)

        # Dict format (complex operations)
        if isinstance(change_spec, dict):
            operations: list[tuple[str | int, list[str]]] = []
            for op_name, op_value in change_spec.items():
                if op_name in {
                    FlextLdapConstants.ModifyOperation.ADD,
                    FlextLdapConstants.ModifyOperation.DELETE,
                    FlextLdapConstants.ModifyOperation.REPLACE,
                }:
                    values = op_value if isinstance(op_value, list) else [str(op_value)]
                    operations.append((op_name, values))
            return operations

        # Simple value format (default to REPLACE)
        values = change_spec if isinstance(change_spec, list) else [str(change_spec)]
        return [(FlextLdapConstants.ModifyOperation.REPLACE, values)]

    def _build_ldap3_changes(
        self,
        changes_dict: dict[str, object],
    ) -> dict[str, list[tuple[str | int, list[str]]]]:
        """Build ldap3 changes dict from FlextLdapModels.EntryChanges."""
        ldap3_changes: dict[str, list[tuple[str | int, list[str]]]] = {}
        for attr, change_spec in changes_dict.items():
            ldap3_changes[attr] = self._parse_change_spec_to_ldap3(change_spec)
        return ldap3_changes

    @FlextDecorators.log_operation("LDAP Modify Entry")
    @FlextDecorators.track_performance("LDAP Modify Entry")
    @FlextDecorators.timeout(timeout_seconds=30.0)
    def modify_entry(
        self,
        dn: FlextLdifModels.DistinguishedName | str,
        changes: FlextLdapModels.EntryChanges,
        *,
        quirks_mode: FlextLdapConstants.Types.QuirksMode | None = None,
    ) -> FlextResult[bool]:
        """Modify existing LDAP entry - implements LdapModifyProtocol.

        Args:
            dn: Distinguished name of entry to modify
            changes: Entry changes to apply
            quirks_mode: Override default quirks mode for this operation

        Returns:
            FlextResult[bool]: Success if entry was modified

        """
        try:
            if not self.connection:
                return FlextResult[bool].fail(
                    FlextLdapConstants.ErrorMessages.LDAP_CONNECTION_NOT_ESTABLISHED
                )

            # Use provided quirks_mode or fall back to instance quirks_mode
            effectives_mode = quirks_mode or self.s_mode

            self.logger.debug(
                "Modifying entry with quirks_mode: %s (effective: %s)",
                quirks_mode,
                effectives_mode,
            )

            # Convert DN to string
            dn_str = (
                dn.value if isinstance(dn, FlextLdifModels.DistinguishedName) else dn
            )

            # Convert changes to ldap3 format using helper methods
            changes_dict = self._convert_changes_to_dict(changes)
            ldap3_changes = self._build_ldap3_changes(changes_dict)

            # Cast to Protocol type for proper type checking with ldap3
            typed_conn = cast(
                "FlextLdapTypes.Ldap3Protocols.Connection",
                self.connection,
            )

            # Cast ldap3_changes to expected protocol type (ldap3 accepts both str and int)
            changes_for_modify = cast(
                "dict[str, list[tuple[int, list[str]]]]",
                ldap3_changes,
            )

            # Execute modify operation
            success = typed_conn.modify(dn_str, changes_for_modify)
            if success:
                return FlextResult[bool].ok(True)

            return FlextResult[bool].fail(
                f"Modify entry failed: {self.connection.last_error}",
            )

        except (
            LDAPCommunicationError,
            LDAPAttributeError,
            LDAPInvalidDnError,
            LDAPNoSuchAttributeResult,
            LDAPNoSuchObjectResult,
            LDAPOperationsErrorResult,
            ValidationError,
        ) as e:
            self.logger.exception("Modify entry failed")
            return FlextResult[bool].fail(f"Modify entry failed: {e}")

    @FlextDecorators.log_operation("LDAP Delete Entry")
    @FlextDecorators.track_performance("LDAP Delete Entry")
    @FlextDecorators.timeout(timeout_seconds=30.0)
    def delete_entry(
        self,
        dn: FlextLdifModels.DistinguishedName | str,
        *,
        quirks_mode: FlextLdapConstants.Types.QuirksMode | None = None,
    ) -> FlextResult[bool]:
        """Delete LDAP entry - implements LdapModifyProtocol.

        Args:
            dn: Distinguished name of entry to delete
            quirks_mode: Override default quirks mode for this operation

        Returns:
            FlextResult[bool]: Success if entry was deleted

        """
        try:
            if not self.connection:
                return FlextResult[bool].fail(
                    FlextLdapConstants.ErrorMessages.LDAP_CONNECTION_NOT_ESTABLISHED
                )

            # Use provided quirks_mode or fall back to instance quirks_mode
            effectives_mode = quirks_mode or self.s_mode

            self.logger.debug(
                "Deleting entry with quirks_mode: %s (effective: %s)",
                quirks_mode,
                effectives_mode,
            )

            # Cast to Protocol type for proper type checking with ldap3
            typed_conn = cast(
                "FlextLdapTypes.Ldap3Protocols.Connection",
                self.connection,
            )
            # Convert DN to string using flext-ldif
            dn_str = (
                dn.value if isinstance(dn, FlextLdifModels.DistinguishedName) else dn
            )
            success = typed_conn.delete(dn_str)
            if success:
                return FlextResult[bool].ok(True)
            return FlextResult[bool].fail(
                f"Delete entry failed: {self.connection.last_error}",
            )

        except (
            LDAPCommunicationError,
            LDAPInvalidDnError,
            LDAPOperationsErrorResult,
        ) as e:
            self.logger.exception("Delete entry failed")
            return FlextResult[bool].fail(f"Delete entry failed: {e}")

    # =========================================================================
    # VALIDATION OPERATIONS - Direct implementation
    # =========================================================================

    def validate_entry(
        self,
        entry: FlextLdifModels.Entry,
        *,
        quirks_mode: FlextLdapConstants.Types.QuirksMode | None = None,
    ) -> FlextResult[bool]:
        """Validate LDAP entry structure using flext-ldif.

        Args:
            entry: Entry to validate
            quirks_mode: Override default quirks mode for validation

        Returns:
            FlextResult[bool]: Success if entry is valid

        """
        effectives_mode = quirks_mode or self.s_mode

        # Basic validation (skip in relaxed mode)
        if effectives_mode != FlextLdapConstants.Types.QuirksMode.RELAXED:
            if not entry.dn:
                return FlextResult[bool].fail(
                    FlextLdapConstants.ErrorMessages.ENTRY_DN_EMPTY
                )

            if not entry.attributes:
                return FlextResult[bool].fail(
                    FlextLdapConstants.ErrorMessages.ENTRY_ATTRIBUTES_EMPTY
                )

            # DN format validation using flext-ldif
            dn_validation = FlextLdapValidations.validate_dn(entry.dn.value, "Entry DN")
            if dn_validation.is_failure:
                return dn_validation

            # Object class validation
            object_classes = (
                entry.attributes.get(FlextLdapConstants.LdapAttributeNames.OBJECT_CLASS)
                if entry.attributes
                else None
            )
            if not object_classes:
                return FlextResult[bool].fail(
                    FlextLdapConstants.ErrorMessages.ENTRY_MUST_HAVE_OBJECTCLASSES
                )

        return FlextResult[bool].ok(True)

    # =========================================================================
    # ADVANCED OPERATIONS - Direct implementation
    # =========================================================================

    # =========================================================================
    # NORMALIZATION OPERATIONS - Server-agnostic attribute normalization
    # =========================================================================

    def get_server_info(self) -> FlextResult[FlextLdapModels.ServerInfo]:
        """Get server information including capabilities and schema."""
        try:
            if not self.connection:
                return FlextResult[FlextLdapModels.ServerInfo].fail(
                    FlextLdapConstants.ErrorMessages.LDAP_CONNECTION_NOT_ESTABLISHED,
                )

            server_info = self.connection.server.info
            if not server_info:
                return FlextResult[FlextLdapModels.ServerInfo].fail(
                    "Server info not available",
                )

            # Convert server info to ServerInfo model
            server_info_model = FlextLdapModels.ServerInfo(
                vendor_name=getattr(server_info, "vendor_name", {}).get(
                    "value",
                    FlextLdapConstants.ErrorStrings.UNKNOWN_ERROR,
                )
                if hasattr(server_info, "vendor_name")
                else FlextLdapConstants.ErrorStrings.UNKNOWN,
                vendor_version=getattr(server_info, "vendor_version", {}).get(
                    "value",
                    FlextLdapConstants.ErrorStrings.UNKNOWN_ERROR,
                )
                if hasattr(server_info, "vendor_version")
                else FlextLdapConstants.ErrorStrings.UNKNOWN,
                supported_ldap_version=getattr(
                    server_info,
                    "supported_ldap_version",
                    [FlextLdapConstants.DefaultValues.LDAP_VERSION],
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
            )

            return FlextResult[FlextLdapModels.ServerInfo].ok(server_info_model)

        except (
            LDAPCommunicationError,
            AttributeError,
            ValidationError,
        ) as e:
            return FlextResult[FlextLdapModels.ServerInfo].fail(
                f"Failed to get server info: {e}",
            )

    # =========================================================================
    # MISSING METHODS - Required by API layer
    # =========================================================================

    def search_users(
        self,
        base_dn: str,
        filter_str: str | None = None,
        attributes: list[str] | None = None,
    ) -> FlextResult[list[FlextLdifModels.Entry]]:
        """Search for LDAP users."""
        search_filter = filter_str or FlextLdapConstants.Filters.ALL_USERS_FILTER
        # Create SearchRequest model for search()
        search_request = FlextLdapModels.SearchRequest(
            base_dn=base_dn,
            filter_str=search_filter,
            attributes=attributes,
            single=False,
        )
        result = self.search(search_request)
        if result.is_failure:
            return FlextResult[list[FlextLdifModels.Entry]].fail(
                result.error or "Search failed",
            )
        entries_raw = result.unwrap()
        # Normalize to list: handle list, single entry, or None
        if entries_raw is None:
            entries = []
        elif isinstance(entries_raw, list):
            entries = entries_raw
        else:
            entries = [entries_raw]
        return FlextResult[list[FlextLdifModels.Entry]].ok(entries)

    def search_groups(
        self,
        base_dn: str,
        cn: str | None = None,
        attributes: list[str] | None = None,
    ) -> FlextResult[list[FlextLdifModels.Entry]]:
        """Search for LDAP groups."""
        search_filter = (
            f"(&(objectClass=groupOfNames)(cn={cn}))"
            if cn
            else FlextLdapConstants.Filters.DEFAULT_GROUP_FILTER
        )
        # Create SearchRequest model for search()
        search_request = FlextLdapModels.SearchRequest(
            base_dn=base_dn,
            filter_str=search_filter,
            attributes=attributes,
            single=False,
        )
        result = self.search(search_request)
        if result.is_failure:
            return FlextResult[list[FlextLdifModels.Entry]].fail(
                result.error or "Search failed",
            )
        entries_raw = result.unwrap()
        # Normalize to list: handle list, single entry, or None
        if entries_raw is None:
            entries = []
        elif isinstance(entries_raw, list):
            entries = entries_raw
        else:
            entries = [entries_raw]
        return FlextResult[list[FlextLdifModels.Entry]].ok(entries)

    def search_with_request(
        self,
        request: FlextLdapModels.SearchRequest,
    ) -> FlextResult[FlextLdapModels.SearchResponse]:
        """Search using a SearchRequest object."""
        # Directly pass request to search() since it now accepts SearchRequest
        search_result = self.search(request)
        if search_result.is_failure:
            return FlextResult[FlextLdapModels.SearchResponse].fail(
                search_result.error or "Search failed",
            )

        result_value = search_result.unwrap()
        # Ensure we have a list for SearchResponse
        if isinstance(result_value, list):
            entries = result_value
        elif result_value is not None:
            # Single entry, wrap in list
            entries = [result_value]
        else:
            entries = []

        response = FlextLdapModels.SearchResponse(
            entries=entries,
            total_count=len(entries),
            result_code=0,
            time_elapsed=0.0,
        )

        return FlextResult[FlextLdapModels.SearchResponse].ok(response)

    def _update_entry_attributes(
        self,
        dn: str,
        attributes: dict[str, object],
    ) -> FlextResult[bool]:
        """Update entry attributes - generic implementation for update_user/update_group_attributes."""
        if not attributes:
            return FlextResult[bool].fail(
                FlextLdapConstants.ErrorMessages.NO_ATTRIBUTES_PROVIDED
            )
        changes_dict: dict[str, object] = {
            attr_name: [
                (
                    2,  # MODIFY_REPLACE operation code in LDAP
                    attr_value if isinstance(attr_value, list) else [str(attr_value)],
                ),
            ]
            for attr_name, attr_value in attributes.items()
        }
        changes = FlextLdapModels.EntryChanges(**changes_dict)
        return self.modify_entry(dn, changes)

    def update_user_attributes(
        self,
        dn: str,
        attributes: dict[str, object],
    ) -> FlextResult[bool]:
        """Update user attributes - delegates to _update_entry_attributes()."""
        return self._update_entry_attributes(dn, attributes)

    def update_group_attributes(
        self,
        dn: str,
        attributes: dict[str, object],
    ) -> FlextResult[bool]:
        """Update group attributes - delegates to _update_entry_attributes()."""
        return self._update_entry_attributes(dn, attributes)

    @property
    def server_type(self) -> str | None:
        """Get the detected server type."""
        return self._detected_server_type

    @property
    def session_id(self) -> str | None:
        """Get session ID for connection tracking."""
        return getattr(self, "_session_id", None)

    @property
    def servers(self) -> FlextLdapModels.ServerQuirks | None:
        """Get server quirks for detected server type."""
        if not self._detected_server_type:
            return None
        # Create server quirks based on detected type
        try:
            return FlextLdapModels.ServerQuirks(
                server_type=self._detected_server_type
                or FlextLdapConstants.Defaults.SERVER_TYPE,
                # Use default case_sensitive_dns=True from model
            )
        except Exception as e:
            # This should not happen in normal operation, but log it
            self.logger.warning(f"Failed to create server quirks: {e}")
            return None

    def _validate_search_request(
        self,
        _request: FlextLdapModels.SearchRequest,
    ) -> FlextResult[None]:
        """Validate search request (private helper method)."""
        # Basic validation is handled by Pydantic model
        return FlextResult.ok(None)

    def _create_user_from_entry(
        self,
        entry: FlextLdifModels.Entry,
    ) -> FlextResult[FlextLdifModels.Entry]:
        """Create user from entry (private helper method)."""
        # Simply return the entry wrapped in FlextResult
        return FlextResult[FlextLdifModels.Entry].ok(entry)

    # Normalize Helper Methods

    def _normalize_string(self, value: str | list[object] | dict[str, object]) -> str:
        """Normalize value to string."""
        return value.strip() if isinstance(value, str) else str(value)

    def _normalize_attributes(
        self, value: str | list[object] | dict[str, object]
    ) -> str | list[object] | dict[str, object]:
        """Normalize value to list of attribute strings."""
        if isinstance(value, list):
            return [str(attr).strip() for attr in value]
        return [str(value)]

    def _normalize_entry(
        self, value: str | list[object] | dict[str, object]
    ) -> str | list[object] | dict[str, object]:
        """Normalize entry dict."""
        if not isinstance(value, dict):
            error_type = type(value).__name__
            msg = f"Expected dict for entry normalization, got {error_type}"
            raise TypeError(msg)
        return {
            k: (
                [str(v).strip() for v in val]
                if isinstance(val, list)
                else str(val).strip()
            )
            for k, val in value.items()
        }

    def _normalize_changes(
        self, value: str | list[object] | dict[str, object]
    ) -> dict[str, object]:
        """Normalize changes dict."""
        if not isinstance(value, dict):
            error_type = type(value).__name__
            msg = f"Expected dict for changes normalization, got {error_type}"
            raise TypeError(msg)
        return {
            k: (
                [(op, [s.strip() for s in vals]) for op, vals in change_list]
                if isinstance(change_list, list)
                and all(
                    isinstance(op, tuple)
                    and len(op)
                    == FlextLdapConstants.AclParsing.MODIFY_OPERATION_TUPLE_LENGTH
                    for op in change_list
                )
                else change_list
            )
            for k, change_list in value.items()
        }

    def _normalize_results(
        self, value: str | list[object] | dict[str, object]
    ) -> list[object]:
        """Normalize results to list."""
        if isinstance(value, list):
            return value
        return [value] if value is not None else []

    def _normalize(
        self,
        value: str | list[object] | dict[str, object],
        normalize_type: str = FlextLdapConstants.DefaultValues.NORMALIZE_TYPE_STRING,
    ) -> str | list[object] | dict[str, object]:
        """Unified normalizer using Python 3.13+ pattern matching (ONE METHOD).

        Replaces 5 separate normalization methods with single unified handler.

        Args:
        value: Value to normalize (str, list, dict, or entries)
        normalize_type: Type of normalization ('string', 'attributes', 'entry', 'changes', 'results')

        Returns:
        Normalized value in original type

        """
        match normalize_type:
            case "string":
                return self._normalize_string(value)
            case "attributes":
                return self._normalize_attributes(value)
            case "entry":
                return self._normalize_entry(value)
            case "changes":
                return self._normalize_changes(value)
            case "results":
                return self._normalize_results(value)
            case _:
                return value

    def get_servers_info(self) -> FlextResult[dict[str, object]]:
        """Get quirks information for the current LDAP server connection.

        Returns server-specific quirks information including special handling
        requirements, attribute mappings, and capability flags for the currently
        connected LDAP server type.

        Returns:
            FlextResult containing server quirks information

        """
        try:
            if not self.connection:
                return FlextResult[dict[str, object]].fail(
                    FlextLdapConstants.ErrorMessages.LDAP_CONNECTION_NOT_ESTABLISHED,
                )

            server_info: dict[str, object] = {
                "server_type": self._detected_server_type
                or FlextLdapConstants.Defaults.SERVER_TYPE,
                "quirks_mode": self.quirks_mode,  # Property, not method
                "case_sensitive_attributes": self._detected_server_type
                == FlextLdapConstants.ServerTypes.AD,
            }

            return FlextResult[dict[str, object]].ok(server_info)
        except Exception as e:
            return FlextResult[dict[str, object]].fail(
                f"Failed to get server info: {e}",
            )

    def _get_server_operations(self) -> FlextResult[FlextLdapServersBaseOperations]:
        """Get server operations instance for the detected server type."""
        factory = FlextLdapServersFactory()
        server_type = (
            self._detected_server_type or FlextLdapConstants.Defaults.SERVER_TYPE
        )
        return factory.create_from_server_type(server_type)

    def discover_schema(self) -> FlextResult[FlextLdifModels.SchemaDiscoveryResult]:
        """Discover LDAP schema from the connected server.

        Returns:
            FlextResult containing schema discovery results

        """
        if not self.connection:
            return FlextResult[FlextLdifModels.SchemaDiscoveryResult].fail(
                FlextLdapConstants.ErrorMessages.LDAP_CONNECTION_NOT_ESTABLISHED,
            )

        ops_result = self._get_server_operations()
        if ops_result.is_failure:
            return FlextResult[FlextLdifModels.SchemaDiscoveryResult].fail(
                ops_result.error
            )
        return ops_result.unwrap().discover_schema(self.connection)

    def validate_dn(self, dn: str) -> FlextResult[bool]:
        """Validate DN format without LDAP server connection.

        Args:
            dn: DN string to validate

        Returns:
            FlextResult containing validation result

        """
        try:
            # Use flext-ldif DN validation
            return FlextResult[bool].ok(FlextLdifUtilities.DN().validate(dn))
        except Exception:
            return FlextResult[bool].ok(False)

    def get_server_attributes(self, capability: str) -> FlextResult[list[str]]:
        """Get server-specific attributes for a given capability using server operations.

        Args:
            capability: Capability name (e.g., 'acl', 'schema', 'operational')

        Returns:
            FlextResult with list of attribute names for this capability

        """
        ops_result = self._get_server_operations()
        if ops_result.is_failure:
            return FlextResult[list[str]].fail(ops_result.error)

        ops = ops_result.unwrap()

        # Map capability to server-specific attributes
        if capability == "acl":
            acl_attr = ops.get_acl_attribute_name()
            return FlextResult[list[str]].ok([acl_attr])
        if capability == "schema":
            schema_dn = ops.get_schema_dn()
            return FlextResult[list[str]].ok([schema_dn])
        if capability == "operational":
            # Return common operational attributes
            return FlextResult[list[str]].ok([
                "modifyTimestamp",
                "createTimestamp",
                "creatorsName",
                "modifiersName",
            ])

        return FlextResult[list[str]].fail(
            f"Unknown capability: {capability}",
        )

    def transform_entry_for_server(
        self,
        entry: FlextLdifModels.Entry,
        target_server_type: str,
    ) -> FlextResult[FlextLdifModels.Entry]:
        """Transform entry for target server using FlextLdapEntryAdapter service.

        Args:
            entry: Entry to transform
            target_server_type: Target server type

        Returns:
            FlextResult with transformed entry

        """
        adapter = FlextLdapEntryAdapter(server_type=target_server_type)
        return adapter.normalize_entry_for_server(entry, target_server_type)
