"""LDAP Connection Manager - Handles LDAP connection lifecycle.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Literal

from flext_core import FlextResult, FlextTypes
from ldap3 import Connection, Server

from flext_ldap.constants import FlextLdapConstants
from flext_ldap.typings import FlextLdapTypes
from flext_ldap.validations import FlextLdapValidations

if TYPE_CHECKING:
    from flext_ldap.clients import FlextLdapClients


class FlextLdapConnectionManager:
    """LDAP Connection Manager - Handles LDAP connection lifecycle management.

    **UNIFIED CLASS PATTERN**: Single class per module with nested helpers only.

    This class manages the complete LDAP connection lifecycle including:
    - Server connection establishment
    - Credential binding/unbinding
    - Connection state management
    - Server type auto-detection
    - Schema discovery
    - Connection testing and validation

    **PROTOCOL COMPLIANCE**: Implements Infrastructure.Connection protocol methods.
    """

    def __init__(self, parent: FlextLdapClients) -> None:
        """Initialize connection manager with parent client reference.

        Args:
            parent: Parent FlextLdapClients instance for shared state access.

        """
        self._parent = parent
        self._connection: Connection | None = None
        self._server: Server | None = None

    def connect(
        self,
        server_uri: str,
        bind_dn: str,
        password: str,
        *,
        auto_discover_schema: bool = True,
        connection_options: FlextTypes.Dict | None = None,
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

            self._parent.logger.info("Connecting to LDAP server: %s", server_uri)

            # Apply connection options if provided with proper type checking
            if connection_options:
                # Extract and validate server options with proper type validation
                port_value = connection_options.get("port")
                port: int | None = port_value if isinstance(port_value, int) else None

                use_ssl_value = connection_options.get("use_ssl")
                use_ssl = use_ssl_value if isinstance(use_ssl_value, bool) else False

                get_info_value = connection_options.get("get_info")
                # Valid get_info values for ldap3 - use proper type narrowing
                get_info: Literal[
                    FlextLdapConstants.LiteralTypes.CONNECTION_INFO_ALL,
                    FlextLdapConstants.LiteralTypes.CONNECTION_INFO_DSA,
                    FlextLdapConstants.LiteralTypes.CONNECTION_INFO_NO_INFO,
                    FlextLdapConstants.LiteralTypes.CONNECTION_INFO_SCHEMA,
                ]
                if isinstance(get_info_value, str) and get_info_value in {
                    "NO_INFO",
                    "DSA",
                    "SCHEMA",
                    "ALL",
                }:
                    get_info = get_info_value  # Narrowed by isinstance and in check
                else:
                    get_info = "DSA"

                mode_value = connection_options.get("mode")
                # Valid mode values for ldap3 - use proper type narrowing
                mode: Literal[
                    FlextLdapConstants.LiteralTypes.IP_MODE_SYSTEM_DEFAULT,
                    FlextLdapConstants.LiteralTypes.IP_MODE_V4_ONLY,
                    FlextLdapConstants.LiteralTypes.IP_MODE_V4_PREFERRED,
                    FlextLdapConstants.LiteralTypes.IP_MODE_V6_ONLY,
                    FlextLdapConstants.LiteralTypes.IP_MODE_V6_PREFERRED,
                ]
                if isinstance(mode_value, str) and mode_value in {
                    FlextLdapConstants.LiteralTypes.IP_MODE_SYSTEM_DEFAULT,
                    FlextLdapConstants.LiteralTypes.IP_MODE_V4_ONLY,
                    FlextLdapConstants.LiteralTypes.IP_MODE_V6_ONLY,
                    FlextLdapConstants.LiteralTypes.IP_MODE_V4_PREFERRED,
                    FlextLdapConstants.LiteralTypes.IP_MODE_V6_PREFERRED,
                }:
                    mode = mode_value  # Narrowed by isinstance and in check
                else:
                    mode = FlextLdapConstants.LiteralTypes.IP_MODE_SYSTEM_DEFAULT

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

            self._parent.logger.info("Successfully connected to LDAP server")

            # Auto-detect server type and create server operations instance
            detection_result = (
                self._parent.server_operations_factory.create_from_connection(
                    self._connection
                )
            )
            if detection_result.is_success:
                self._parent.server_operations = detection_result.unwrap()
                self._parent.detected_server_type = (
                    self._parent.server_operations.server_type
                    if self._parent.server_operations
                    else None
                )
                self._parent.logger.info(
                    "Auto-detected LDAP server type: %s",
                    self._parent.detected_server_type,
                )
            else:
                self._parent.logger.warning(
                    "Server type detection failed, using generic operations: %s",
                    detection_result.error,
                )
                # Fallback to generic server operations
                generic_result = (
                    self._parent.server_operations_factory.create_from_server_type(
                        "generic"
                    )
                )
                if generic_result.is_success:
                    self._parent.server_operations = generic_result.unwrap()
                    self._parent.detected_server_type = "generic"

            # Perform schema discovery if requested
            if auto_discover_schema:
                discovery_result = self._parent.discover_schema()
                if discovery_result.is_failure:
                    self._parent.logger.warning(
                        "Schema discovery failed: %s", discovery_result.error
                    )
                    # Continue without schema discovery

            return FlextResult[bool].ok(True)

        except Exception as e:
            self._parent.logger.exception("Connection failed")
            return FlextResult[bool].fail(f"Connection failed: {e}")

    def bind(self, bind_dn: str, password: str) -> FlextResult[bool]:
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
            self._parent.logger.exception("Bind operation failed")
            return FlextResult[bool].fail(f"Bind failed: {e}")

    def unbind(self) -> FlextResult[None]:
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
                self._parent.logger.info("Unbound from LDAP server")

            self._connection = None
            self._server = None
            return FlextResult[None].ok(None)

        except Exception as e:
            self._parent.logger.exception("Unbind failed")
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

    def close_connection(self) -> FlextResult[None]:
        """Close LDAP connection.

        Returns:
            FlextResult indicating success or error.

        """
        return self.unbind()

    def disconnect(self) -> FlextResult[None]:
        """Disconnect from LDAP server - implements LdapConnectionProtocol.

        Alias for close_connection to match protocol interface.

        Returns:
            FlextResult[None]: Disconnect success status

        """
        return self.close_connection()

    def get_connection_string(self) -> FlextResult[str]:
        """Get sanitized LDAP connection string for Infrastructure.Connection protocol.

        Returns connection string with credentials removed for security.
        Part of FlextProtocols.Infrastructure.Connection protocol implementation.

        Returns:
            FlextResult[str]: Sanitized LDAP connection string (e.g., 'ldap://host:port')

        """
        if self._server and hasattr(self._server, "host"):
            # Return sanitized URI without credentials
            protocol = "ldaps" if getattr(self._server, "ssl", False) else "ldap"
            host = self._server.host
            port = self._server.port
            return FlextResult[str].ok(f"{protocol}://{host}:{port}")

        if self._parent.config and hasattr(self._parent.config, "server_uri"):
            # Return config URI (should already be sanitized)
            return FlextResult[str].ok(str(self._parent.config.server_uri))

        return FlextResult[str].ok("ldap://not-connected")

    def __call__(self, *args: object, **kwargs: object) -> FlextResult[bool]:
        """Callable interface for Infrastructure.Connection protocol.

        Delegates to connect() method when called with connection parameters.

        Args:
            *args: Positional arguments (server_uri, bind_dn, password)
            **kwargs: Keyword arguments passed to connect()

        Returns:
            FlextResult[bool]: Connection result

        """
        if len(args) >= 3:
            server_uri, bind_dn, password = str(args[0]), str(args[1]), str(args[2])
            return self.connect(
                server_uri=server_uri,
                bind_dn=bind_dn,
                password=password,
                **kwargs,
            )

        return FlextResult[bool].fail(
            "Invalid connection arguments. Expected: (server_uri, bind_dn, password)"
        )
