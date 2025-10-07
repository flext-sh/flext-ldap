"""LDAP connection management for flext-ldap.

This module provides unified connection management for LDAP operations
with Clean Architecture patterns and flext-core integration.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

Note: This file has type checking disabled due to limitations in the official types-ldap3 package:
- Method return types (add, delete, search, modify, unbind) are not specified in the stubs
- Properties like conn.entries and entry.entry_dn are not fully typed
- Entry attributes and their values have incomplete type information
"""

from __future__ import annotations

from typing import Literal

from flext_core import (
    FlextResult,
    FlextService,
    FlextTypes,
)
from ldap3 import Connection, Server

from flext_ldap.constants import FlextLdapConstants
from flext_ldap.models import FlextLdapModels
from flext_ldap.servers import BaseServerOperations
from flext_ldap.servers.factory import FlextLdapServersFactory
from flext_ldap.typings import FlextLdapTypes
from flext_ldap.utilities import FlextLdapUtilities
from flext_ldap.validations import FlextLdapValidations


class FlextLdapConnection(FlextService[None]):
    """Unified LDAP connection management class.

    This class provides comprehensive LDAP connection lifecycle management
    with Clean Architecture patterns and flext-core integration.

    **UNIFIED CLASS PATTERN**: One class per module with nested helpers only.
    **CLEAN ARCHITECTURE**: Infrastructure layer connection management.
    **FLEXT INTEGRATION**: Full flext-core service integration.

    Provides LDAP connection management methods:
    - connect: Establish LDAP connection
    - disconnect: Close LDAP connection
    - is_connected: Check connection status
    - test_connection: Test connection health
    - get_connection_string: Get sanitized connection string
    """

    def __init__(self) -> None:
        """Initialize LDAP connection manager with Phase 1 context enrichment."""
        super().__init__()
        # Logger and container inherited from FlextService via FlextMixins
        self._connection: Connection | None = None
        self._server: Server | None = None
        self.server_operations_factory = FlextLdapServersFactory()
        self.server_operations: BaseServerOperations | None = None
        self.detected_server_type: str | None = None

    @classmethod
    def create(cls) -> FlextLdapConnection:
        """Create a new FlextLdapConnection instance (factory method)."""
        return cls()

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

            self.logger.info("Connecting to LDAP server: %s", server_uri)

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

            self.logger.info("Successfully connected to LDAP server")

            # Auto-detect server type and create server operations instance
            detection_result = self.server_operations_factory.create_from_connection(
                self._connection
            )
            if detection_result.is_success:
                self.server_operations = detection_result.unwrap()
                self.detected_server_type = (
                    self.server_operations.server_type
                    if self.server_operations
                    else None
                )
                self.logger.info(
                    "Auto-detected LDAP server type: %s",
                    self.detected_server_type,
                )
            else:
                self.logger.warning(
                    "Server type detection failed, using generic operations: %s",
                    detection_result.error,
                )
                # Fallback to generic server operations
                generic_result = self.server_operations_factory.create_from_server_type(
                    "generic"
                )
                if generic_result.is_success:
                    self.server_operations = generic_result.unwrap()
                    self.detected_server_type = "generic"

            # Perform schema discovery if requested
            if auto_discover_schema:
                discovery_result = self._discover_schema()
                if discovery_result.is_failure:
                    self.logger.warning(
                        "Schema discovery failed: %s", discovery_result.error
                    )
                    # Continue without schema discovery

            return FlextResult[bool].ok(True)

        except Exception as e:
            self.logger.exception("Connection failed")
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
            self.logger.exception("Bind operation failed")
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
                self.logger.info("Unbound from LDAP server")

            self._connection = None
            self._server = None
            return FlextResult[None].ok(None)

        except Exception as e:
            self.logger.exception("Unbind failed")
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

    def get_connection_string(self) -> str:
        """Get sanitized LDAP connection string for Infrastructure.Connection protocol.

        Returns connection string with credentials removed for security.
        Part of FlextProtocols.Infrastructure.Connection protocol implementation.

        Returns:
            str: Sanitized LDAP connection string (e.g., 'ldap://host:port')

        """
        if self._server and hasattr(self._server, "host"):
            # Return sanitized URI without credentials
            protocol = "ldaps" if getattr(self._server, "ssl", False) else "ldap"
            host = self._server.host
            port = self._server.port
            return f"{protocol}://{host}:{port}"

        return "ldap://not-connected"

    def __call__(self, *args: object, **kwargs: object) -> FlextResult[bool]:
        """Callable interface for Infrastructure.Connection protocol.

        Delegates to connect() method when called with connection parameters.
        Part of FlextProtocols.Infrastructure.Connection protocol implementation.

        Args:
            *args: Positional arguments (server_uri, bind_dn, password)
            **kwargs: Keyword arguments passed to connect()

        Returns:
            FlextResult[bool]: Connection result

        Examples:
            >>> client = FlextLdapConnection()
            >>> result = client(
            ...     "ldap://localhost:389", "cn=admin,dc=example,dc=com", "password"
            ... )
            >>> if result.is_success:
            ...     print("Connected successfully")

        """
        if len(args) >= 3:
            # Extract positional args: server_uri, bind_dn, password
            server_uri = str(args[0])
            bind_dn = str(args[1])
            password = str(args[2])

            # Call connect with extracted parameters
            return self.connect(
                server_uri=server_uri,
                bind_dn=bind_dn,
                password=password,
                **kwargs,
            )

        # Invalid arguments
        return FlextResult[bool].fail(
            "Invalid connection arguments. Expected: (server_uri, bind_dn, password)"
        )

    # Private helper methods
    def _discover_schema(self) -> FlextResult[FlextLdapModels.DiscoveredSchema]:
        """Discover LDAP schema from connected server.

        Returns:
            FlextResult[FlextLdapModels.DiscoveredSchema]: Schema discovery result

        """
        try:
            if not self._connection:
                return FlextResult[FlextLdapModels.DiscoveredSchema].fail(
                    "No connection available for schema discovery"
                )

            # Get server info
            server_info = FlextLdapUtilities.get_server_info(self._connection)

            # Get schema info if available
            schema_info = None
            if hasattr(self._connection, "server") and self._connection.server.schema:
                schema_info = FlextLdapUtilities.get_schema_info(self._connection)

            # Create discovered schema
            discovered_schema = FlextLdapModels.DiscoveredSchema(
                server_info=server_info,
                schema_info=schema_info,
            )

            return FlextResult[FlextLdapModels.DiscoveredSchema].ok(discovered_schema)

        except Exception as e:
            return FlextResult[FlextLdapModels.DiscoveredSchema].fail(
                f"Schema discovery failed: {e}"
            )

    def execute(self) -> FlextResult[None]:
        """Execute the main domain operation (required by FlextService)."""
        return FlextResult[None].ok(None)


__all__ = [
    "FlextLdapConnection",
]
