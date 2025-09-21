"""Connection domain service for LDAP operations.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from contextlib import asynccontextmanager
from typing import TYPE_CHECKING

from flext_core import FlextDomainService, FlextResult
from flext_ldap import FlextExceptions
from flext_ldap.validations import FlextLdapValidations

if TYPE_CHECKING:
    from collections.abc import AsyncIterator

    from flext_ldap.clients import FlextLdapClient


class FlextLdapConnectionService(FlextDomainService[None]):
    """Domain service for LDAP connection operations.

    This service encapsulates all connection-related business logic and operations
    following Domain-Driven Design patterns. It provides a clean interface
    for connection management while maintaining proper separation of concerns.

    Attributes:
        _client: LDAP client for infrastructure operations.

    """

    # Constants for validation
    MAX_PORT_PARTS: int = 2
    MAX_PORT_NUMBER: int = 65535

    def __init__(self, client: FlextLdapClient) -> None:
        """Initialize connection service with LDAP client.

        Args:
            client: LDAP client for performing infrastructure operations.

        """
        super().__init__()
        self._client = client
        self._session_id = "flext_ldap_session"

    def execute(self) -> FlextResult[None]:
        """Execute the main domain service operation.

        Returns:
            FlextResult[dict[str, str]]: Success result with service information.

        Returns basic service information for the connection service.

        """
        return FlextResult[None].ok(None)

    @property
    def session_id(self) -> str:
        """Get current session ID."""
        return self._session_id

    async def connect(
        self,
        server_uri: str,
        bind_dn: str,
        bind_password: str,
    ) -> FlextResult[str]:
        """Connect to LDAP server and establish session using explicit async/await pattern.

        Args:
            server_uri: LDAP server URI (ldap:// or ldaps://).
            bind_dn: Distinguished name for authentication.
            bind_password: Password for authentication.

        Returns:
            FlextResult[str]: Success with session ID or error result.

        """
        # Validate connection parameters
        param_validation = self._validate_connection_params(
            server_uri,
            bind_dn,
            bind_password,
        )
        if param_validation.is_failure:
            return FlextResult[str].fail(
                f"Connection to {server_uri} failed: {param_validation.error}",
            )

        # Validate DN format
        dn_validation = FlextLdapValidations.validate_dn(bind_dn)
        if dn_validation.is_failure:
            return FlextResult[str].fail(
                f"Connection to {server_uri} failed: {dn_validation.error}",
            )

        # Perform LDAP connection
        connection_result = await self._perform_ldap_connection(
            server_uri,
            bind_dn,
            bind_password,
        )
        if connection_result.is_failure:
            return FlextResult[str].fail(
                f"Connection to {server_uri} failed: {connection_result.error}",
            )

        # Return session ID
        return FlextResult[str].ok(self.session_id)

    def _validate_connection_params(
        self,
        server_uri: str,
        bind_dn: str,
        bind_password: str,
    ) -> FlextResult[None]:
        """Validate connection parameters using FlextResult patterns.

        Returns:
            FlextResult[None]: Success result if validation passes.

        """
        if not server_uri or not server_uri.strip():
            return FlextResult[None].fail("Server URI cannot be empty")
        if not bind_dn or not bind_dn.strip():
            return FlextResult[None].fail("Bind DN cannot be empty")
        if not bind_password:
            return FlextResult[None].fail("Bind password cannot be empty")
        if not (server_uri.startswith(("ldap://", "ldaps://"))):
            return FlextResult[None].fail(
                "Server URI must start with ldap:// or ldaps://",
            )
        return FlextResult[None].ok(None)

    async def _perform_ldap_connection(
        self,
        server_uri: str,
        bind_dn: str,
        bind_password: str,
    ) -> FlextResult[None]:
        """Perform actual LDAP connection through client.

        Returns:
            FlextResult[None]: Success result if connection succeeds.

        """
        try:
            # Use client to establish connection
            return await self._client.connect(server_uri, bind_dn, bind_password)
        except Exception as e:
            return FlextResult[None].fail(f"LDAP connection failed: {e}")

    async def disconnect(self, session_id: str | None = None) -> FlextResult[None]:
        """Disconnect from LDAP server.

        Args:
            session_id: Session ID to disconnect (optional, currently unused)

        Returns:
            FlextResult indicating success or error

        """
        # NO API compatibility maintained - parameter ignored
        # Currently not used by the service layer implementation
        _ = session_id  # Acknowledge parameter to silence linter
        return await self._client.unbind()

    @asynccontextmanager
    async def connection(
        self,
        server_uri: str,
        bind_dn: str,
        bind_password: str,
    ) -> AsyncIterator[str]:
        """Context manager for LDAP connection using monadic workflow.

        Args:
            server_uri: LDAP server URI
            bind_dn: Distinguished name for binding
            bind_password: Password for binding

        Yields:
            Session ID for use within context

        Raises:
            ConnectionError: If connection fails.

        """
        # Monadic workflow: connect >> extract session >> yield session >> cleanup
        connect_result = await self.connect(server_uri, bind_dn, bind_password)

        # Use monadic approach to handle connection result
        session_result = (connect_result >> (FlextResult[str].ok)).with_context(
            lambda err: f"Connection context failed: {err}",
        )

        if session_result.is_failure:
            error_msg = session_result.error or "Connection failed"
            raise FlextExceptions.ConnectionError(error_msg)

        session_id = session_result.value
        try:
            yield session_id
        finally:
            await self.disconnect(session_id)

    async def test_connection(
        self,
        server_uri: str,
        bind_dn: str,
        bind_password: str,
    ) -> FlextResult[bool]:
        """Test LDAP connection without maintaining the session.

        Args:
            server_uri: LDAP server URI
            bind_dn: Distinguished name for binding
            bind_password: Password for binding

        Returns:
            FlextResult[bool]: True if connection successful, False otherwise

        """
        # Attempt connection
        connect_result = await self.connect(server_uri, bind_dn, bind_password)
        if connect_result.is_failure:
            return FlextResult[bool].ok(data=False)

        # Immediately disconnect
        disconnect_result = await self.disconnect()
        if disconnect_result.is_failure:
            # Connection succeeded but disconnect failed - still consider it a successful test
            return FlextResult[bool].ok(data=True)

        return FlextResult[bool].ok(data=True)

    def validate_server_uri(self, server_uri: str) -> FlextResult[None]:
        """Validate LDAP server URI format.

        Args:
            server_uri: Server URI to validate

        Returns:
            FlextResult[None]: Success if valid, failure with error message if invalid

        """
        if not server_uri or not server_uri.strip():
            return FlextResult[None].fail("Server URI cannot be empty")

        if not (server_uri.startswith(("ldap://", "ldaps://"))):
            return FlextResult[None].fail(
                "Server URI must start with ldap:// or ldaps://",
            )

        # Additional validation for URI format
        try:
            # Basic URI structure validation
            if "://" not in server_uri:
                return FlextResult[None].fail("Invalid URI format")

            # Check for port if specified
            if ":" in server_uri.split("://")[1]:
                parts = server_uri.split("://")[1].split(":")
                if len(parts) > self.MAX_PORT_PARTS:
                    return FlextResult[None].fail("Invalid port specification")
                try:
                    port = int(parts[1].split("/")[0])
                    if port < 1 or port > self.MAX_PORT_NUMBER:
                        return FlextResult[None].fail(
                            "Port must be between 1 and 65535",
                        )
                except ValueError:
                    return FlextResult[None].fail("Invalid port number")

            return FlextResult[None].ok(None)

        except Exception as e:
            return FlextResult[None].fail(f"URI validation failed: {e}")

    def get_connection_info(self) -> FlextResult[dict[str, str]]:
        """Get current connection information.

        Returns:
            FlextResult[dict]: Connection information or error

        """
        try:
            # Return basic info since client doesn't provide detailed connection info method
            basic_info = {
                "session_id": self.session_id,
                "status": "connected"
                if hasattr(self._client, "_connection")
                else "disconnected",
                "client_type": type(self._client).__name__,
            }
            return FlextResult[dict[str, str]].ok(basic_info)

        except Exception as e:
            return FlextResult[dict[str, str]].fail(
                f"Failed to get connection info: {e}",
            )

    def is_connected(self) -> FlextResult[bool]:
        """Check if currently connected to LDAP server.

        Returns:
            FlextResult[bool]: True if connected, False otherwise

        """
        try:
            # Check connection status through client
            is_connected = self._client.is_connected()
            return FlextResult[bool].ok(is_connected)

        except Exception as e:
            return FlextResult[bool].fail(f"Connection status check failed: {e}")

    async def reconnect(
        self,
        server_uri: str,
        bind_dn: str,
        bind_password: str,
    ) -> FlextResult[str]:
        """Reconnect to LDAP server (disconnect if connected, then connect).

        Args:
            server_uri: LDAP server URI
            bind_dn: Distinguished name for binding
            bind_password: Password for binding

        Returns:
            FlextResult[str]: Session ID if successful, error otherwise

        """
        # Check if currently connected
        connection_check = self.is_connected()
        if connection_check.is_success and connection_check.value:
            # Disconnect first
            disconnect_result = await self.disconnect()
            if disconnect_result.is_failure:
                return FlextResult[str].fail(
                    f"Failed to disconnect before reconnecting: {disconnect_result.error}",
                )

        # Connect
        connect_result = await self.connect(server_uri, bind_dn, bind_password)
        return connect_result.with_context(lambda err: f"Reconnection failed: {err}")
