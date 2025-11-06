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

from flext_core import FlextResult, FlextService
from flext_ldif import FlextLdifConstants, FlextLdifModels
from ldap3 import (
    Connection,
    Server,
)
from ldap3.core.exceptions import (
    LDAPAttributeError,
    LDAPBindError,
    LDAPChangeError,
    LDAPCommunicationError,
    LDAPInvalidDnError,
    LDAPInvalidFilterError,
    LDAPInvalidScopeError,
    LDAPObjectClassError,
    LDAPObjectError,
    LDAPOperationsErrorResult,
    LDAPPasswordIsMandatoryError,
    LDAPResponseTimeoutError,
    LDAPSocketOpenError,
    LDAPStartTLSError,
    LDAPUserNameIsMandatoryError,
)
from pydantic import ValidationError

from flext_ldap.config import FlextLdapConfig
from flext_ldap.constants import FlextLdapConstants
from flext_ldap.models import FlextLdapModels
from flext_ldap.protocols import FlextLdapProtocols
from flext_ldap.services.authentication import FlextLdapAuthentication
from flext_ldap.services.search import FlextLdapSearch
from flext_ldap.services.validations import FlextLdapValidations
from flext_ldap.typings import FlextLdapTypes


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

    def __init__(
        self,
        config: FlextLdapConfig | None = None,
        *,
        quirks_mode: FlextLdapConstants.Types.QuirksMode = FlextLdapConstants.Types.QuirksMode.AUTOMATIC,
    ) -> None:
        """Initialize LDAP client - consolidated implementation without bloat.

        Args:
            config: LDAP configuration (uses global if None)
            quirks_mode: Server quirks mode (AUTOMATIC, OID, OUD, or RFC)

        Args:
            config: Optional LDAP configuration
            quirks_mode: Quirks handling mode (automatic, server, rfc, relaxed)

        """
        super().__init__()

        # Core configuration and logging
        self._ldap_config = config
        self.s_mode: FlextLdapConstants.Types.QuirksMode = (
            quirks_mode or FlextLdapConstants.Types.QuirksMode.AUTOMATIC
        )

        # Direct connection state (no delegation layer)
        self._connection: Connection | None = None
        self._server: Server | None = None

        # Server type detection for configuration
        self._detected_server_type: str | None = None

        # Search scope constant - use string literal for Literal type compatibility
        self._search_scope: FlextLdapConstants.Types.Ldap3Scope = "SUBTREE"

        # Lazy-loaded components: search/auth (substantial logic)
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
                "FlextLdapProtocols.Ldap.LdapSearcherProtocol",
                searcher,
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
                "FlextLdapProtocols.Ldap.LdapAuthenticationProtocol",
                auth,
            )
        # Type checker knows it's not None after the check above
        return self._authenticator

    @property
    def connection(self) -> Connection | None:
        """Get the current LDAP connection."""
        return self._connection

    @property
    def quirks_mode(self) -> FlextLdapConstants.Types.QuirksMode:
        """Get current quirks mode for LDAP operations."""
        return self.s_mode

    @property
    def quirks_mode_description(self) -> str:
        """Get human-readable description of current quirks mode."""
        descriptions = {
            FlextLdapConstants.Types.QuirksMode.AUTOMATIC: "Auto-detect server type and apply quirks",
            FlextLdapConstants.Types.QuirksMode.SERVER: "Use explicit server type with quirks",
            FlextLdapConstants.Types.QuirksMode.RFC: "RFC-compliant only, no extensions",
            FlextLdapConstants.Types.QuirksMode.RELAXED: "Permissive mode, accept anything",
        }
        return descriptions.get(
            self.s_mode,
            FlextLdapConstants.ErrorStrings.UNKNOWN_ERROR,
        )

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
        bind_dn: FlextLdifModels.DistinguishedName | str,
        password: str,
        *,
        auto_discover_schema: bool = True,
        connection_options: dict[str, object] | None = None,
        quirks_mode: FlextLdapConstants.Types.QuirksMode | None = None,
    ) -> FlextResult[bool]:
        """Connect and bind to LDAP server with universal compatibility.

        Args:
        server_uri: LDAP server URI (e.g., 'ldap://localhost:389').
        bind_dn: Distinguished Name for binding.
        password: Password for binding.
        auto_discover_schema: Whether to automatically discover schema.
        connection_options: Additional connection options.
        quirks_mode: Override default quirks mode for this connection.

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
            bind_dn_str = (
                bind_dn.value
                if isinstance(bind_dn, FlextLdifModels.DistinguishedName)
                else bind_dn
            )
            bind_dn_validation = FlextLdapValidations.validate_dn(
                bind_dn_str,
                "Bind DN",
            )
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

            # Store quirks mode if provided, otherwise use default
            if quirks_mode is not None:
                self.s_mode = quirks_mode
                self.logger.debug("Quirks mode updated to: %s", quirks_mode)

            self.logger.debug("Connecting to LDAP server: %s", server_uri)

            # Apply connection options if provided
            if connection_options:
                # Build Server constructor arguments with proper typing
                port: int | None = None
                use_ssl: bool = False
                get_info: FlextLdapConstants.Types.GetInfoType = cast(
                    "FlextLdapConstants.Types.GetInfoType",
                    FlextLdapConstants.Types.GetInfoType.SCHEMA,
                )

                for key, value in connection_options.items():
                    if key == "port" and value is not None:
                        port = int(str(value))
                    elif key == "use_ssl" and value is not None:
                        use_ssl = bool(value)
                    elif key == "get_info" and value is not None:
                        str_value = str(value)
                        # Use FlextLdapConstants.GetInfoType for string comparisons
                        if str_value == FlextLdapConstants.Types.GetInfoType.ALL.value:
                            get_info = FlextLdapConstants.Types.GetInfoType.ALL
                        elif (
                            str_value
                            == FlextLdapConstants.Types.GetInfoType.SCHEMA.value
                        ):
                            get_info = FlextLdapConstants.Types.GetInfoType.SCHEMA
                        elif (
                            str_value == FlextLdapConstants.Types.GetInfoType.DSA.value
                        ):
                            get_info = FlextLdapConstants.Types.GetInfoType.DSA
                        elif (
                            str_value
                            == FlextLdapConstants.Types.GetInfoType.NO_INFO.value
                        ):
                            get_info = FlextLdapConstants.Types.GetInfoType.NO_INFO
                        else:
                            # Default to SCHEMA if unknown
                            get_info = FlextLdapConstants.Types.GetInfoType.SCHEMA

                # Set get_info to ALL if auto_discover_schema and not set
                if (
                    auto_discover_schema
                    and get_info == FlextLdapConstants.Types.GetInfoType.SCHEMA
                ):
                    get_info = FlextLdapConstants.Types.GetInfoType.ALL

                # Create server with the collected arguments
                if port is not None:
                    self._server = Server(
                        server_uri,
                        port=port,
                        use_ssl=use_ssl,
                        get_info=cast(
                            "Literal['ALL', 'DSA', 'NO_INFO', 'SCHEMA']",
                            get_info.value,
                        ),
                    )
                else:
                    self._server = Server(
                        server_uri,
                        use_ssl=use_ssl,
                        get_info=cast(
                            "Literal['ALL', 'DSA', 'NO_INFO', 'SCHEMA']",
                            get_info.value,
                        ),
                    )
            # Set get_info to ALL if auto_discover_schema is True
            elif auto_discover_schema:
                self._server = Server(
                    server_uri,
                    get_info=cast(
                        "Literal['ALL', 'DSA', 'NO_INFO', 'SCHEMA']",
                        FlextLdapConstants.Types.GetInfoType.ALL.value,
                    ),
                )
            else:
                self._server = Server(server_uri)

            # Create connection with auto-bind
            bind_dn_str = (
                bind_dn.value
                if isinstance(bind_dn, FlextLdifModels.DistinguishedName)
                else bind_dn
            )
            self._connection = Connection(
                self._server,
                bind_dn_str,
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

            # Auto-detect server type from Root DSE
            try:
                root_dse_result = self._get_root_dse_attributes()
                if root_dse_result.is_success:
                    root_dse = root_dse_result.unwrap()
                    self._detected_server_type = self._detect_server_type_from_root_dse(
                        root_dse,
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
            if not self._connection or not self._connection.bound:
                return FlextResult[dict[str, object]].fail("Connection not bound")

            search_result = self._connection.search(
                search_base="",
                search_filter=FlextLdapConstants.Filters.ALL_ENTRIES_FILTER,
                search_scope=cast(
                    "FlextLdapConstants.Types.Ldap3Scope",
                    FlextLdapConstants.Scopes.BASE_LDAP3,
                ),
                attributes=["*", "+"],
                size_limit=1,
            )

            if not search_result or not self._connection.entries:
                return FlextResult[dict[str, object]].fail("No Root DSE found")

            entry = self._connection.entries[0]
            attrs: dict[str, object] = {}
            for attr in entry.entry_attributes:
                attrs[attr] = entry[attr].value

            return FlextResult[dict[str, object]].ok(attrs)

        except Exception as e:
            return FlextResult[dict[str, object]].fail(
                f"Root DSE retrieval failed: {e}",
            )

    def _detect_server_type_from_root_dse(self, root_dse: dict[str, object]) -> str:
        """Detect server type from Root DSE attributes using flext-ldif constants."""
        if not root_dse:
            return FlextLdifConstants.LdapServers.GENERIC

        # Check vendor name
        vendor_name = str(
            root_dse.get(FlextLdapConstants.RootDseAttributes.VENDOR_NAME, ""),
        ).lower()

        if FlextLdapConstants.VendorNames.ORACLE in vendor_name:
            # Check for OUD-specific attributes
            config_context = str(
                root_dse.get(FlextLdapConstants.RootDseAttributes.CONFIG_CONTEXT, ""),
            ).lower()
            if FlextLdapConstants.SchemaDns.CONFIG in config_context:
                return FlextLdifConstants.LdapServers.ORACLE_OUD
            return FlextLdifConstants.LdapServers.ORACLE_OID

        if FlextLdapConstants.VendorNames.OPENLDAP in vendor_name:
            vendor_version = str(
                root_dse.get(FlextLdapConstants.RootDseAttributes.VENDOR_VERSION, ""),
            )
            if vendor_version.startswith(
                FlextLdapConstants.VersionPrefixes.VERSION_1_PREFIX,
            ):
                return FlextLdifConstants.LdapServers.OPENLDAP_1
            return FlextLdifConstants.LdapServers.OPENLDAP_2

        if (
            hasattr(
                root_dse,
                FlextLdapConstants.RootDseAttributes.ROOT_DOMAIN_NAMING_CONTEXT,
            )
            or FlextLdapConstants.RootDseAttributes.ROOT_DOMAIN_NAMING_CONTEXT
            in root_dse
        ):
            return FlextLdifConstants.LdapServers.ACTIVE_DIRECTORY

        if FlextLdapConstants.RootDseAttributes.CONFIG_CONTEXT in root_dse:
            return FlextLdifConstants.LdapServers.ORACLE_OID

        return FlextLdifConstants.LdapServers.GENERIC

    def bind(
        self,
        bind_dn: FlextLdifModels.DistinguishedName | str,
        password: str,
    ) -> FlextResult[bool]:
        """Bind to LDAP server with specified credentials."""
        try:
            if not self._connection:
                return FlextResult[bool].fail("LDAP connection not established")

            # Create new connection with provided credentials
            if not self._server:
                return FlextResult[bool].fail("No server connection established")

            bind_dn_str = (
                bind_dn.value
                if isinstance(bind_dn, FlextLdifModels.DistinguishedName)
                else bind_dn
            )
            self._connection = Connection(
                self._server,
                bind_dn_str,
                password,
                auto_bind=True,
            )

            if not self._connection.bound:
                return FlextResult[bool].fail("Bind failed - invalid credentials")

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
            return FlextResult[bool].fail("LDAP connection not established")

        try:
            if self._connection:
                self._connection.search(
                    "",
                    FlextLdapConstants.Defaults.DEFAULT_SEARCH_FILTER,
                    self._search_scope,
                    attributes=[FlextLdapConstants.LdapAttributeNames.OBJECT_CLASS],
                )
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
                if getattr(self._server, "ssl", False)
                else FlextLdapConstants.Protocol.LDAP
            )
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

    def validate_credentials(
        self,
        dn: FlextLdifModels.DistinguishedName | str,
        password: str,
    ) -> FlextResult[bool]:
        """Validate credentials - delegates to authenticator."""
        dn_str = dn.value if isinstance(dn, FlextLdifModels.DistinguishedName) else dn
        return self._get_authenticator().validate_credentials(dn_str, password)

    # =========================================================================
    # SEARCH OPERATIONS - Delegated to FlextLdapSearcher
    # =========================================================================

    def search(
        self,
        base_dn: FlextLdifModels.DistinguishedName | str,
        filter_str: str,
        attributes: list[str] | None = None,
        scope: FlextLdapConstants.Types.Ldap3Scope = "SUBTREE",
        page_size: int = 0,
        paged_cookie: bytes | None = None,
        *,
        single: bool = False,
        quirks_mode: FlextLdapConstants.Types.QuirksMode | None = None,
    ) -> FlextResult[list[FlextLdifModels.Entry] | FlextLdifModels.Entry | None]:
        """Perform LDAP search - delegates to searcher.

        Args:
            base_dn: Search base DN
            filter_str: LDAP filter string
            attributes: Attributes to retrieve
            scope: Search scope (BASE, LEVEL, SUBTREE)
            page_size: Page size for paged results
            paged_cookie: Cookie for paged results continuation
            single: If True, return first entry only. If False, return list of entries.
            quirks_mode: Override default quirks mode for this search

        Returns:
            FlextResult with list of entries or single entry based on single parameter.

        """
        # Use provided quirks_mode or fall back to instance quirks_mode
        effectives_mode = quirks_mode or self.s_mode

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
        normalized_scope_str = scope.lower() if isinstance(scope, str) else scope
        # Cast to Ldap3Scope for type checker
        normalized_scope = cast(
            "FlextLdapConstants.Types.Ldap3Scope",
            normalized_scope_str,
        )

        base_dn_str = (
            base_dn.value
            if isinstance(base_dn, FlextLdifModels.DistinguishedName)
            else base_dn
        )
        search_result = searcher.search(
            base_dn_str,
            filter_str,
            attributes,
            normalized_scope,
            page_size,
            paged_cookie,
        )

        if search_result.is_failure:
            return cast(
                "FlextResult[list[FlextLdifModels.Entry] | FlextLdifModels.Entry | None]",
                search_result,
            )

        # Handle single result request
        if single:
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
                "LDAP connection not established",
            )
        return searcher.search_one(search_base, filter_str, attributes)

    def get_user(
        self,
        dn: FlextLdifModels.DistinguishedName | str,
    ) -> FlextResult[FlextLdifModels.Entry | None]:
        """Get user by DN - uses search_one."""
        if not self._connection:
            return FlextResult[FlextLdifModels.Entry | None].fail(
                "LDAP connection not established",
            )
        dn_str = dn.value if isinstance(dn, FlextLdifModels.DistinguishedName) else dn
        return self._get_searcher().search_one(
            dn_str,
            FlextLdapConstants.Defaults.DEFAULT_SEARCH_FILTER,
            attributes=["*"],
        )

    def get_group(
        self,
        dn: FlextLdifModels.DistinguishedName | str,
    ) -> FlextResult[FlextLdifModels.Entry | None]:
        """Get group by DN - uses search_one."""
        if not self._connection:
            return FlextResult[FlextLdifModels.Entry | None].fail(
                "LDAP connection not established",
            )
        dn_str = dn.value if isinstance(dn, FlextLdifModels.DistinguishedName) else dn
        return self._get_searcher().search_one(
            dn_str,
            FlextLdapConstants.Defaults.DEFAULT_SEARCH_FILTER,
            attributes=["*"],
        )

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
                return FlextResult[bool].fail("LDAP connection not established")

            # Use provided quirks_mode or fall back to instance quirks_mode
            effectives_mode = quirks_mode or self.s_mode

            # Extract dict from LdifAttributes if needed
            attrs_dict: dict[str, str | list[str]]
            if isinstance(attributes, FlextLdifModels.LdifAttributes):
                # LdifAttributes wraps dict[str, list[str]]
                attrs_dict = cast("dict[str, str | list[str]]", attributes.attributes)
            else:
                attrs_dict = attributes

            # Convert DN to string if needed
            dn_str = (
                dn.value if isinstance(dn, FlextLdifModels.DistinguishedName) else dn
            )

            # Convert attributes to ldap3 format
            ldap3_attributes = {}
            for key, value in attrs_dict.items():
                if isinstance(value, list):
                    ldap3_attributes[key] = value
                else:
                    ldap3_attributes[key] = [str(value)]

            # Try to add entry, handling undefined attributes gracefully
            success = False
            attempted_attributes = ldap3_attributes.copy()
            removed_attributes: list[str] = []
            # Limit retries unless in "relaxed" mode
            max_retries = (
                1 if effectives_mode == FlextLdapConstants.Types.QuirksMode.RFC else 20
            )
            retry_count = 0

            self.logger.debug(
                "Adding entry with quirks_mode: %s (effective: %s)",
                quirks_mode,
                effectives_mode,
            )

            while not success and retry_count < max_retries:
                try:
                    # Extract objectClass from attributes or use default
                    object_class_raw = attempted_attributes.get(
                        FlextLdapConstants.LdapAttributeNames.OBJECT_CLASS,
                        [FlextLdapConstants.Defaults.OBJECT_CLASS_TOP],
                    )
                    if isinstance(object_class_raw, list):
                        object_class = (
                            object_class_raw[0]
                            if object_class_raw
                            else FlextLdapConstants.Defaults.OBJECT_CLASS_TOP
                        )
                    else:
                        object_class = str(object_class_raw)
                    # Cast to Protocol type for proper type checking with ldap3
                    typed_conn = cast(
                        "FlextLdapTypes.Ldap3Protocols.Connection",
                        self.connection,
                    )
                    # Cast attributes to match Protocol signature
                    attrs = cast(
                        "dict[str, str | list[str]] | None",
                        attempted_attributes,
                    )
                    success = typed_conn.add(
                        dn_str,
                        object_class=object_class,
                        attributes=attrs,
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

                except (
                    LDAPAttributeError,
                    LDAPObjectClassError,
                ) as e:
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
                    f"Add entry failed after {max_retries} retries removing attributes",
                )

            return FlextResult[bool].fail(
                f"Add entry failed: {self.connection.last_error}",
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
                return FlextResult[bool].fail("LDAP connection not established")

            # Use provided quirks_mode or fall back to instance quirks_mode
            effectives_mode = quirks_mode or self.s_mode

            self.logger.debug(
                "Modifying entry with quirks_mode: %s (effective: %s)",
                quirks_mode,
                effectives_mode,
            )

            # Convert changes to ldap3 format
            # ldap3 expects: {'attr': [(MODIFY_OP, [values])]}
            ldap3_changes: dict[str, list[tuple[str | int, list[str]]]] = {}
            changes_dict: dict[str, object] = (
                changes.model_dump()
                if hasattr(changes, "model_dump")
                else dict(changes)
                if hasattr(changes, "items")
                else changes
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
                        "list[tuple[str | int, list[str]]]",
                        change_spec,
                    )
                elif isinstance(change_spec, dict):
                    # Handle dict format (complex operations)
                    # Convert dict operations to proper tuple format for ldap3
                    operations: list[tuple[str, list[str]]] = []
                    for op_name, op_value in change_spec.items():
                        # Use FlextLdapConstants.ModifyOperation constants
                        if op_name in {
                            FlextLdapConstants.ModifyOperation.MODIFY_ADD_STR,
                            FlextLdapConstants.ModifyOperation.ADD,
                        }:
                            operations.append((
                                FlextLdapConstants.ModifyOperation.ADD,
                                [op_value]
                                if not isinstance(op_value, list)
                                else op_value,
                            ))
                        elif op_name in {
                            FlextLdapConstants.ModifyOperation.MODIFY_DELETE_STR,
                            FlextLdapConstants.ModifyOperation.DELETE,
                        }:
                            operations.append((
                                FlextLdapConstants.ModifyOperation.DELETE,
                                [op_value]
                                if not isinstance(op_value, list)
                                else op_value,
                            ))
                        elif op_name in {
                            FlextLdapConstants.ModifyOperation.MODIFY_REPLACE_STR,
                            FlextLdapConstants.ModifyOperation.REPLACE,
                        }:
                            operations.append((
                                FlextLdapConstants.ModifyOperation.REPLACE,
                                [op_value]
                                if not isinstance(op_value, list)
                                else op_value,
                            ))
                        elif (
                            op_name
                            == FlextLdapConstants.ModifyOperation.MODIFY_INCREMENT_STR
                        ):
                            # MODIFY_INCREMENT not supported, skip
                            msg = f"MODIFY_INCREMENT not supported for {attr}"
                            self.logger.warning(msg)
                            continue
                    # Cast to match expected dict value type
                    ldap3_changes[attr] = cast(
                        "list[tuple[str | int, list[str]]]",
                        operations,
                    )
                else:
                    # Simple value - wrap as MODIFY_REPLACE
                    ldap3_changes[attr] = [
                        cast(
                            "tuple[str | int, list[str]]",
                            (
                                2,  # MODIFY_REPLACE operation code in LDAP
                                change_spec
                                if isinstance(change_spec, list)
                                else [str(change_spec)],
                            ),
                        ),
                    ]

            # Use direct ldap3 modify (server-specific handling simplified)
            # Cast to Protocol type for proper type checking with ldap3
            typed_conn = cast(
                "FlextLdapTypes.Ldap3Protocols.Connection",
                self.connection,
            )
            # Cast changes directly to match Protocol signature
            dn_str = (
                dn.value if isinstance(dn, FlextLdifModels.DistinguishedName) else dn
            )
            success = typed_conn.modify(
                dn_str,
                changes=cast("dict[str, list[tuple[int, list[str]]]]", ldap3_changes),
            )
            if success:
                return FlextResult[bool].ok(True)
            return FlextResult[bool].fail(
                f"Modify entry failed: {self.connection.last_error}",
            )

        except (
            LDAPCommunicationError,
            LDAPChangeError,
            LDAPInvalidDnError,
            LDAPAttributeError,
            LDAPOperationsErrorResult,
            ValidationError,
        ) as e:
            self.logger.exception("Modify entry failed")
            return FlextResult[bool].fail(f"Modify entry failed: {e}")

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
                return FlextResult[bool].fail("LDAP connection not established")

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
                return FlextResult[bool].fail("Entry DN cannot be empty")

            if not entry.attributes:
                return FlextResult[bool].fail("Entry attributes cannot be empty")

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
                return FlextResult[bool].fail("Entry must have object classes")

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
                    "LDAP connection not established",
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
        result = self.search(base_dn, search_filter, attributes, single=False)
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
        result = self.search(base_dn, search_filter, attributes, single=False)
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
        search_result = self.search(
            request.base_dn,
            request.filter_str,
            request.attributes,
        )
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

    def update_user_attributes(
        self,
        dn: str,
        attributes: dict[str, object],
    ) -> FlextResult[bool]:
        """Update user attributes using LDAP modify operation."""
        if not attributes:
            return FlextResult[bool].fail("No attributes provided for update")
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

    def update_group_attributes(
        self,
        dn: str,
        attributes: dict[str, object],
    ) -> FlextResult[bool]:
        """Update group attributes using LDAP modify operation."""
        if not attributes:
            return FlextResult[bool].fail("No attributes provided for update")
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
        return FlextLdapModels.ServerQuirks(
            server_type=FlextLdifConstants.LdapServerType(
                self._detected_server_type or FlextLdapConstants.Defaults.SERVER_TYPE,
            ),
            case_sensitive_dns=self._detected_server_type
            == FlextLdapConstants.ServerTypes.AD,
            case_sensitive_attributes=self._detected_server_type
            == FlextLdapConstants.ServerTypes.AD,
            supports_paged_results=self._detected_server_type
            != FlextLdapConstants.ServerTypes.OPENLDAP1,
            supports_vlv=self._detected_server_type
            in {FlextLdapConstants.ServerTypes.OUD, FlextLdapConstants.ServerTypes.OID},
            max_page_size=FlextLdapConstants.Connection.MAX_PAGE_SIZE_GENERIC
            if self._detected_server_type != FlextLdapConstants.ServerTypes.AD
            else FlextLdapConstants.Connection.MAX_PAGE_SIZE_AD,
        )

    def _create_user_from_entry_result(
        self,
        entry: FlextLdifModels.Entry,
    ) -> FlextResult[FlextLdifModels.Entry]:
        """Create user from entry result (private helper method).

        Modern Entry API: Entry is already validated by Pydantic during construction.
        This method simply validates the entry is well-formed and returns it.
        """
        try:
            # Validate entry structure is correct (dn and attributes)
            if not entry.dn or not entry.dn.value:
                return FlextResult.fail("Entry must have a valid DN")

            if not entry.attributes or not entry.attributes.attributes:
                return FlextResult.fail("Entry must have attributes")

            # Entry is already valid - return it
            return FlextResult.ok(entry)
        except (AttributeError, ValueError) as e:
            return FlextResult.fail(f"User creation failed: {e}")

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
        return self._create_user_from_entry_result(entry)

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
                if isinstance(value, str):
                    return value.strip()
                return str(value)

            case "attributes":
                if isinstance(value, list):
                    return [str(attr).strip() for attr in value]
                return [str(value)]

            case "entry":
                if isinstance(value, dict):
                    return {
                        k: (
                            [str(v).strip() for v in val]
                            if isinstance(val, list)
                            else str(val).strip()
                        )
                        for k, val in value.items()
                    }
                return {}

            case "changes":
                if isinstance(value, dict):
                    return {
                        k: (
                            [
                                (op, [s.strip() for s in vals])
                                for op, vals in change_list
                            ]
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
                return {}

            case "results":
                if isinstance(value, list):
                    return value
                return [value] if value is not None else []

            case _:
                # Default: return unchanged
                return value


__all__ = ["FlextLdapClients"]
