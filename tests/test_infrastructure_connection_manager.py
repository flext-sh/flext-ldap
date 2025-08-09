"""Tests for FLEXT-LDAP Infrastructure Connection Manager.

Comprehensive test suite for the FlextLDAPConnectionManager class, validating
LDAP connection management using FLEXT patterns with proper error handling,
configuration management, and connection lifecycle operations.

This test module ensures the connection manager provides reliable LDAP
connectivity while following Clean Architecture patterns and maintaining
proper separation between infrastructure and application layers.

Test Coverage:
    - Connection manager initialization and configuration
    - LDAP connection creation with various parameters
    - Connection validation and health checking
    - Connection cleanup and resource management
    - Error handling for connection failures
    - FlextResult pattern validation for all operations
    - Mock-based testing for reliable unit tests

Architecture:
    Tests validate the connection manager's role in the Clean Architecture
    infrastructure layer, ensuring proper abstraction of LDAP connectivity
    concerns and integration with flext-core patterns.

Author: FLEXT Development Team

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

from unittest.mock import Mock, patch

import pytest
from flext_core import FlextResult

from flext_ldap.infrastructure.connection_manager import FlextLDAPConnectionManager


class TestFlextLDAPConnectionManagerInitialization:
    """Test suite for connection manager initialization and configuration.

    Validates that the connection manager properly initializes with
    various configuration parameters and maintains proper state.
    """

    def test_connection_manager_basic_initialization(self) -> None:
        """Test basic connection manager initialization."""
        manager = FlextLDAPConnectionManager(host="localhost", port=389, use_ssl=False)

        assert manager.host == "localhost"
        assert manager.port == 389
        assert manager.use_ssl is False

    def test_connection_manager_ssl_initialization(self) -> None:
        """Test connection manager initialization with SSL."""
        manager = FlextLDAPConnectionManager(
            host="ldap.example.com", port=636, use_ssl=True
        )

        assert manager.host == "ldap.example.com"
        assert manager.port == 636
        assert manager.use_ssl is True

    def test_connection_manager_default_ssl_parameter(self) -> None:
        """Test that use_ssl defaults to True."""
        manager = FlextLDAPConnectionManager(host="localhost", port=389)

        assert manager.host == "localhost"
        assert manager.port == 389
        assert manager.use_ssl is True  # Default value

    def test_connection_manager_with_different_host_types(self) -> None:
        """Test connection manager with different host specifications."""
        # IP address
        manager1 = FlextLDAPConnectionManager(host="192.168.1.10", port=389)
        assert manager1.host == "192.168.1.10"

        # Hostname
        manager2 = FlextLDAPConnectionManager(host="ldap.corporate.com", port=389)
        assert manager2.host == "ldap.corporate.com"

        # Localhost
        manager3 = FlextLDAPConnectionManager(host="127.0.0.1", port=389)
        assert manager3.host == "127.0.0.1"

    def test_connection_manager_with_different_ports(self) -> None:
        """Test connection manager with different port configurations."""
        # Standard LDAP port
        manager1 = FlextLDAPConnectionManager(host="localhost", port=389)
        assert manager1.port == 389

        # Standard LDAPS port
        manager2 = FlextLDAPConnectionManager(host="localhost", port=636)
        assert manager2.port == 636

        # Custom port
        manager3 = FlextLDAPConnectionManager(host="localhost", port=10389)
        assert manager3.port == 10389


class TestConnectionCreation:
    """Test suite for LDAP connection creation functionality.

    Validates connection creation with proper configuration, error handling,
    and FlextResult pattern usage with comprehensive mocking for reliability.
    """

    @patch("flext_ldap.infrastructure.connection_manager.FlextLdapSimpleClient")
    @patch("flext_ldap.infrastructure.connection_manager.FlextLdapConnectionConfig")
    async def test_successful_connection_creation(
        self, mock_config_class: Mock, mock_client_class: Mock
    ) -> None:
        """Test successful LDAP connection creation."""
        # Setup mocks
        mock_config = Mock()
        mock_config_class.return_value = mock_config

        mock_client = Mock()
        mock_client_class.return_value = mock_client

        # Mock successful connection
        mock_client.connect.return_value = FlextResult.ok("connection_id")

        # Create manager and test connection
        manager = FlextLDAPConnectionManager(host="localhost", port=389, use_ssl=False)
        result = await manager.create_connection()

        # Validate result
        assert result.is_success
        assert result.data is mock_client

        # Validate configuration was created correctly
        mock_config_class.assert_called_once_with(
            host="localhost", port=389, use_ssl=False
        )

        # Validate client was created with config
        mock_client_class.assert_called_once_with(mock_config)

        # Validate connection test was performed
        mock_client.connect.assert_called_once()

    @patch("flext_ldap.infrastructure.connection_manager.FlextLdapSimpleClient")
    @patch("flext_ldap.infrastructure.connection_manager.FlextLdapConnectionConfig")
    async def test_connection_creation_with_ssl(
        self, mock_config_class: Mock, mock_client_class: Mock
    ) -> None:
        """Test LDAP connection creation with SSL configuration."""
        # Setup mocks
        mock_config = Mock()
        mock_config_class.return_value = mock_config

        mock_client = Mock()
        mock_client_class.return_value = mock_client
        mock_client.connect.return_value = FlextResult.ok("connection_id")

        # Create SSL manager and test connection
        manager = FlextLDAPConnectionManager(
            host="ldaps.example.com", port=636, use_ssl=True
        )
        result = await manager.create_connection()

        # Validate result
        assert result.is_success
        assert result.data is mock_client

        # Validate SSL configuration
        mock_config_class.assert_called_once_with(
            host="ldaps.example.com", port=636, use_ssl=True
        )

    @patch("flext_ldap.infrastructure.connection_manager.FlextLdapSimpleClient")
    @patch("flext_ldap.infrastructure.connection_manager.FlextLdapConnectionConfig")
    async def test_connection_creation_failure_on_connect(
        self, mock_config_class: Mock, mock_client_class: Mock
    ) -> None:
        """Test connection creation failure during connection test."""
        # Setup mocks
        mock_config = Mock()
        mock_config_class.return_value = mock_config

        mock_client = Mock()
        mock_client_class.return_value = mock_client

        # Mock connection failure
        mock_client.connect.return_value = FlextResult.fail("Connection timeout")

        # Test connection creation
        manager = FlextLDAPConnectionManager(host="unreachable.example.com", port=389)
        result = await manager.create_connection()

        # Validate failure result
        assert not result.is_success
        assert "Connection test failed: Connection timeout" in result.error

        # Ensure connection test was attempted
        mock_client.connect.assert_called_once()

    @patch("flext_ldap.infrastructure.connection_manager.FlextLdapSimpleClient")
    @patch("flext_ldap.infrastructure.connection_manager.FlextLdapConnectionConfig")
    async def test_connection_creation_exception_handling(
        self, mock_config_class: Mock, mock_client_class: Mock
    ) -> None:
        """Test connection creation exception handling."""
        # Setup mocks to raise exception
        mock_config_class.side_effect = ValueError("Invalid configuration")

        # Test connection creation
        manager = FlextLDAPConnectionManager(host="localhost", port=389)
        result = await manager.create_connection()

        # Validate exception handling
        assert not result.is_success
        assert "Failed to create LDAP connection: Invalid configuration" in result.error

    @patch("flext_ldap.infrastructure.connection_manager.FlextLdapSimpleClient")
    @patch("flext_ldap.infrastructure.connection_manager.FlextLdapConnectionConfig")
    async def test_connection_creation_client_instantiation_error(
        self, mock_config_class: Mock, mock_client_class: Mock
    ) -> None:
        """Test connection creation with client instantiation error."""
        # Setup mocks
        mock_config = Mock()
        mock_config_class.return_value = mock_config

        # Client creation raises exception
        mock_client_class.side_effect = OSError("Cannot create client")

        # Test connection creation
        manager = FlextLDAPConnectionManager(host="localhost", port=389)
        result = await manager.create_connection()

        # Validate exception handling
        assert not result.is_success
        assert "Failed to create LDAP connection: Cannot create client" in result.error


class TestConnectionClosure:
    """Test suite for LDAP connection closure functionality.

    Validates proper connection cleanup, resource management, and
    error handling during connection termination operations.
    """

    async def test_successful_connection_closure(self) -> None:
        """Test successful LDAP connection closure."""
        # Create mock connection
        mock_connection = Mock()
        mock_connection.disconnect.return_value = FlextResult.ok(None)

        # Create manager and test closure
        manager = FlextLDAPConnectionManager(host="localhost", port=389)
        result = await manager.close_connection(mock_connection)

        # Validate result
        assert result.is_success
        assert result.data is None

        # Validate disconnect was called
        mock_connection.disconnect.assert_called_once()

    async def test_connection_closure_failure(self) -> None:
        """Test connection closure failure handling."""
        # Create mock connection with disconnect failure
        mock_connection = Mock()
        mock_connection.disconnect.return_value = FlextResult.fail("Disconnect timeout")

        # Create manager and test closure
        manager = FlextLDAPConnectionManager(host="localhost", port=389)
        result = await manager.close_connection(mock_connection)

        # Validate failure handling
        assert not result.is_success
        assert "Disconnect failed: Disconnect timeout" in result.error

        # Validate disconnect was attempted
        mock_connection.disconnect.assert_called_once()

    async def test_connection_closure_exception_handling(self) -> None:
        """Test connection closure exception handling."""
        # Create mock connection that raises exception
        mock_connection = Mock()
        mock_connection.disconnect.side_effect = TypeError("Invalid connection type")

        # Create manager and test closure
        manager = FlextLDAPConnectionManager(host="localhost", port=389)
        result = await manager.close_connection(mock_connection)

        # Validate exception handling
        assert not result.is_success
        assert (
            "Failed to close LDAP connection: Invalid connection type" in result.error
        )

    async def test_connection_closure_with_os_error(self) -> None:
        """Test connection closure with OS-level error."""
        # Create mock connection that raises OSError
        mock_connection = Mock()
        mock_connection.disconnect.side_effect = OSError("Network connection lost")

        # Create manager and test closure
        manager = FlextLDAPConnectionManager(host="localhost", port=389)
        result = await manager.close_connection(mock_connection)

        # Validate OS error handling
        assert not result.is_success
        assert (
            "Failed to close LDAP connection: Network connection lost" in result.error
        )


class TestConnectionValidation:
    """Test suite for LDAP connection validation functionality.

    Validates connection health checking, status verification, and
    proper error handling for connection validation operations.
    """

    async def test_successful_connection_validation_active(self) -> None:
        """Test successful validation of active connection."""
        # Create mock connection that is connected
        mock_connection = Mock()
        mock_connection.is_connected.return_value = True

        # Create manager and test validation
        manager = FlextLDAPConnectionManager(host="localhost", port=389)
        result = await manager.validate_connection(mock_connection)

        # Validate result
        assert result.is_success
        assert result.data is True

        # Validate is_connected was called
        mock_connection.is_connected.assert_called_once()

    async def test_successful_connection_validation_inactive(self) -> None:
        """Test successful validation of inactive connection."""
        # Create mock connection that is not connected
        mock_connection = Mock()
        mock_connection.is_connected.return_value = False

        # Create manager and test validation
        manager = FlextLDAPConnectionManager(host="localhost", port=389)
        result = await manager.validate_connection(mock_connection)

        # Validate result
        assert result.is_success
        assert result.data is False

        # Validate is_connected was called
        mock_connection.is_connected.assert_called_once()

    async def test_connection_validation_exception_handling(self) -> None:
        """Test connection validation exception handling."""
        # Create mock connection that raises exception
        mock_connection = Mock()
        mock_connection.is_connected.side_effect = ValueError(
            "Connection state unknown"
        )

        # Create manager and test validation
        manager = FlextLDAPConnectionManager(host="localhost", port=389)
        result = await manager.validate_connection(mock_connection)

        # Validate exception handling
        assert not result.is_success
        assert (
            "Failed to validate LDAP connection: Connection state unknown"
            in result.error
        )

    async def test_connection_validation_with_type_error(self) -> None:
        """Test connection validation with type error."""
        # Create mock connection that raises TypeError
        mock_connection = Mock()
        mock_connection.is_connected.side_effect = TypeError(
            "Invalid connection object"
        )

        # Create manager and test validation
        manager = FlextLDAPConnectionManager(host="localhost", port=389)
        result = await manager.validate_connection(mock_connection)

        # Validate type error handling
        assert not result.is_success
        assert (
            "Failed to validate LDAP connection: Invalid connection object"
            in result.error
        )

    async def test_connection_validation_with_os_error(self) -> None:
        """Test connection validation with OS error."""
        # Create mock connection that raises OSError
        mock_connection = Mock()
        mock_connection.is_connected.side_effect = OSError("Socket operation failed")

        # Create manager and test validation
        manager = FlextLDAPConnectionManager(host="localhost", port=389)
        result = await manager.validate_connection(mock_connection)

        # Validate OS error handling
        assert not result.is_success
        assert (
            "Failed to validate LDAP connection: Socket operation failed"
            in result.error
        )


class TestFlextResultPatternCompliance:
    """Test suite for FlextResult pattern compliance validation.

    Validates that all connection manager operations properly follow
    the FlextResult pattern for consistent error handling and type safety.
    """

    @patch("flext_ldap.infrastructure.connection_manager.FlextLdapSimpleClient")
    @patch("flext_ldap.infrastructure.connection_manager.FlextLdapConnectionConfig")
    async def test_create_connection_returns_flext_result(
        self, mock_config_class: Mock, mock_client_class: Mock
    ) -> None:
        """Test that create_connection returns proper FlextResult."""
        # Setup successful mocks
        mock_config = Mock()
        mock_config_class.return_value = mock_config

        mock_client = Mock()
        mock_client_class.return_value = mock_client
        mock_client.connect.return_value = FlextResult.ok("connection_id")

        # Test connection creation
        manager = FlextLDAPConnectionManager(host="localhost", port=389)
        result = await manager.create_connection()

        # Validate FlextResult properties
        assert hasattr(result, "is_success")
        assert hasattr(result, "data")
        assert hasattr(result, "error")
        assert result.is_success is True
        assert result.error is None

    async def test_close_connection_returns_flext_result(self) -> None:
        """Test that close_connection returns proper FlextResult."""
        # Create successful mock
        mock_connection = Mock()
        mock_connection.disconnect.return_value = FlextResult.ok(None)

        # Test connection closure
        manager = FlextLDAPConnectionManager(host="localhost", port=389)
        result = await manager.close_connection(mock_connection)

        # Validate FlextResult properties
        assert hasattr(result, "is_success")
        assert hasattr(result, "data")
        assert hasattr(result, "error")
        assert result.is_success is True
        assert result.error is None

    async def test_validate_connection_returns_flext_result(self) -> None:
        """Test that validate_connection returns proper FlextResult."""
        # Create successful mock
        mock_connection = Mock()
        mock_connection.is_connected.return_value = True

        # Test connection validation
        manager = FlextLDAPConnectionManager(host="localhost", port=389)
        result = await manager.validate_connection(mock_connection)

        # Validate FlextResult properties
        assert hasattr(result, "is_success")
        assert hasattr(result, "data")
        assert hasattr(result, "error")
        assert result.is_success is True
        assert result.error is None
        assert result.data is True


class TestEdgeCasesAndErrorScenarios:
    """Test suite for edge cases and comprehensive error scenario coverage.

    Validates robust behavior under various edge conditions, ensuring
    proper error handling and graceful degradation in failure scenarios.
    """

    def test_connection_manager_with_extreme_port_values(self) -> None:
        """Test connection manager with extreme port values."""
        # Very low port (should work but might need privileges)
        manager1 = FlextLDAPConnectionManager(host="localhost", port=1)
        assert manager1.port == 1

        # High port within valid range
        manager2 = FlextLDAPConnectionManager(host="localhost", port=65535)
        assert manager2.port == 65535

        # Standard ports should work fine
        manager3 = FlextLDAPConnectionManager(host="localhost", port=389)
        assert manager3.port == 389

    def test_connection_manager_with_special_hostnames(self) -> None:
        """Test connection manager with special hostname formats."""
        # IPv6 localhost
        manager1 = FlextLDAPConnectionManager(host="::1", port=389)
        assert manager1.host == "::1"

        # Empty hostname (edge case - might cause issues later but initialization should work)
        manager2 = FlextLDAPConnectionManager(host="", port=389)
        assert manager2.host == ""

        # Long hostname
        long_hostname = (
            "very-long-hostname-that-might-cause-issues.subdomain.example.com"
        )
        manager3 = FlextLDAPConnectionManager(host=long_hostname, port=389)
        assert manager3.host == long_hostname

    @patch("flext_ldap.infrastructure.connection_manager.FlextLdapSimpleClient")
    @patch("flext_ldap.infrastructure.connection_manager.FlextLdapConnectionConfig")
    async def test_multiple_exception_types_in_connection_creation(
        self, mock_config_class: Mock, mock_client_class: Mock
    ) -> None:
        """Test handling of different exception types during connection creation."""
        manager = FlextLDAPConnectionManager(host="localhost", port=389)

        # Test ValueError handling
        mock_config_class.side_effect = ValueError("Configuration error")
        result1 = await manager.create_connection()
        assert not result1.is_success
        assert "Configuration error" in result1.error

        # Reset mock and test TypeError
        mock_config_class.side_effect = TypeError("Type mismatch")
        result2 = await manager.create_connection()
        assert not result2.is_success
        assert "Type mismatch" in result2.error

        # Reset mock and test OSError
        mock_config_class.side_effect = OSError("OS level error")
        result3 = await manager.create_connection()
        assert not result3.is_success
        assert "OS level error" in result3.error

    async def test_connection_operations_with_none_connection(self) -> None:
        """Test connection operations with None connection object."""
        manager = FlextLDAPConnectionManager(host="localhost", port=389)

        # This should raise AttributeError when trying to call methods on None
        with pytest.raises(AttributeError):
            await manager.close_connection(None)

        with pytest.raises(AttributeError):
            await manager.validate_connection(None)
