"""FLEXT-LDAP Infrastructure Client Tests - Protocol Implementation Validation.

Enterprise-grade test suite for FlextLdapSimpleClient infrastructure layer,
validating LDAP protocol implementation, connection management, and
infrastructure-level operations with proper error handling.

This test module ensures the infrastructure layer correctly implements
LDAP protocol operations, manages connections reliably, and provides
proper abstraction between domain logic and LDAP protocol details.

Test Coverage:
    - Client initialization and configuration
    - Connection establishment and management
    - LDAP protocol operation execution
    - Error handling and recovery mechanisms
    - Connection pooling and resource management
    - Infrastructure-level data conversion

Architecture:
    Tests validate Clean Architecture infrastructure layer compliance,
    ensuring proper separation between protocol implementation and
    domain logic with reliable error propagation.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

from unittest.mock import MagicMock, Mock, patch

import pytest
from flext_core import FlextResult

from flext_ldap.config import FlextLdapAuthConfig
from flext_ldap.ldap_infrastructure import (
    FlextLdapConnectionConfig,
    FlextLdapSimpleClient,
)


# FBT smell elimination constants - SOLID DRY Principle
class TestOperationResult:
    """Test operation result constants - eliminates FBT003 positional booleans."""

    SUCCESS = True
    FAILURE = False


class TestFlextLdapSimpleClient:
    """Test suite for FlextLdapSimpleClient infrastructure implementation.

    Comprehensive testing of the LDAP infrastructure client covering
    initialization, configuration, connection management, and protocol
    operations with proper error handling and resource management.

    Tests ensure the infrastructure layer correctly abstracts LDAP
    protocol complexities while providing reliable operations to
    higher architectural layers.
    """

    def test_init_default(self) -> None:
        """Test client initialization with default configuration settings.

        Validates that the client properly initializes with default settings
        and correctly sets up internal state including connection manager,
        data converter, and configuration handling.
        """
        client = FlextLdapSimpleClient()
        assert client._current_connection is None
        assert client._connection_manager is not None
        assert client._converter is not None
        assert client._config is None

    def test_init_with_config(self) -> None:
        """Test client initialization with custom configuration.

        Validates that the client properly accepts and stores custom
        configuration settings for LDAP connection parameters.
        """
        config = FlextLdapConnectionConfig(
            host="localhost",
            port=389,
            use_ssl=False,
        )
        client = FlextLdapSimpleClient(config)
        assert client._config == config

    def test_is_connected_false(self) -> None:
        """Test connection status reporting for disconnected client.

        Validates that connection status correctly returns False when
        no active LDAP connection has been established.
        """
        client = FlextLdapSimpleClient()
        assert not client.is_connected()

    def test_connect_success(self) -> None:
        """Test successful LDAP connection."""
        config = FlextLdapConnectionConfig(
            host="localhost",
            port=389,
            use_ssl=False,
        )

        # Mock the connection manager to return success
        with patch.object(FlextLdapSimpleClient, "__init__", return_value=None):
            client = FlextLdapSimpleClient.__new__(FlextLdapSimpleClient)
            client._config = config
            client._connection_manager = MagicMock()
            client._converter = MagicMock()
            client._current_connection = None

            # Mock successful connection
            mock_connection = MagicMock()
            mock_connection.closed = False
            client._connection_manager.get_connection = MagicMock(
                return_value=FlextResult.ok(mock_connection)
            )

            result = client.connect(config)  # sync call

            assert result.success
            assert client._current_connection == mock_connection

    def test_connect_failure(self) -> None:
        """Test LDAP connection failure."""
        config = FlextLdapConnectionConfig(
            host="invalid.server.com",
            port=389,
            use_ssl=False,
        )

        with patch.object(FlextLdapSimpleClient, "__init__", return_value=None):
            client = FlextLdapSimpleClient.__new__(FlextLdapSimpleClient)
            client._config = None
            client._connection_manager = MagicMock()
            client._converter = MagicMock()
            client._current_connection = None

            # Mock failed connection
            client._connection_manager.get_connection = MagicMock(
                return_value=FlextResult.fail("Connection failed")
            )

            result = client.connect(config)  # sync call

            assert result.is_failure
            assert client._current_connection is None

    def test_connect_no_config(self) -> None:
        """Test connect with no configuration."""
        client = FlextLdapSimpleClient()
        result = client.connect()  # sync call

        assert result.is_failure
        assert "No connection configuration provided" in result.error

    @pytest.mark.asyncio
    async def test_search_success(self) -> None:
        """Test successful LDAP search."""
        with patch.object(FlextLdapSimpleClient, "__init__", return_value=None):
            client = FlextLdapSimpleClient.__new__(FlextLdapSimpleClient)
            client._converter = MagicMock()

            # Mock connected state
            mock_connection = MagicMock()
            mock_connection.closed = False
            mock_connection.search.return_value = True

            # Mock search results
            mock_entry = MagicMock()
            mock_entry.entry_dn = "cn=test,dc=example,dc=com"
            mock_entry.entry_attributes_as_dict = {
                "cn": ["test"],
                "mail": ["test@example.com"],
            }
            mock_connection.entries = [mock_entry]
            mock_connection.result = None

            client._current_connection = mock_connection
            client._converter.from_ldap.side_effect = lambda x: x

            result = await client.search("dc=example,dc=com", "(cn=test)")

            assert result.success
            assert len(result.data) == 1
            assert result.data[0]["dn"] == "cn=test,dc=example,dc=com"

    @pytest.mark.asyncio
    async def test_search_not_connected(self) -> None:
        """Test search when not connected."""
        client = FlextLdapSimpleClient()
        result = await client.search("dc=example,dc=com", "(cn=test)")

        assert result.is_failure
        assert "Not connected" in result.error

    @pytest.mark.asyncio
    async def test_search_failure(self) -> None:
        """Test search failure."""
        with patch.object(FlextLdapSimpleClient, "__init__", return_value=None):
            client = FlextLdapSimpleClient.__new__(FlextLdapSimpleClient)

            # Mock connected state with search failure
            mock_connection = MagicMock()
            mock_connection.closed = False
            mock_connection.search.return_value = False
            mock_connection.result = "Search failed"

            client._current_connection = mock_connection

            result = await client.search("dc=example,dc=com", "(cn=test)")

            assert result.is_failure
            assert "Search failed" in result.error

    @pytest.mark.asyncio
    async def test_add_success(self) -> None:
        """Test successful LDAP add operation."""
        with patch.object(FlextLdapSimpleClient, "__init__", return_value=None):
            client = FlextLdapSimpleClient.__new__(FlextLdapSimpleClient)
            client._converter = MagicMock()

            # Mock connected state
            mock_connection = MagicMock()
            mock_connection.closed = False
            mock_connection.add.return_value = True
            mock_connection.result = None

            client._current_connection = mock_connection
            client._converter.to_ldap.side_effect = str

            result = await client.add(
                "cn=test,dc=example,dc=com",
                ["person", "inetOrgPerson"],
                {"cn": "test", "sn": "user"},
            )

            assert result.success
            assert result.data is True

    @pytest.mark.asyncio
    async def test_add_not_connected(self) -> None:
        """Test add when not connected."""
        client = FlextLdapSimpleClient()
        result = await client.add(
            "cn=test,dc=example,dc=com", ["person"], {"cn": "test"}
        )

        assert result.is_failure
        assert "Not connected" in result.error

    @pytest.mark.asyncio
    async def test_modify_success(self) -> None:
        """Test successful LDAP modify operation."""
        with patch.object(FlextLdapSimpleClient, "__init__", return_value=None):
            client = FlextLdapSimpleClient.__new__(FlextLdapSimpleClient)
            client._converter = MagicMock()

            # Mock connected state
            mock_connection = MagicMock()
            mock_connection.closed = False
            mock_connection.modify.return_value = True
            mock_connection.result = None

            client._current_connection = mock_connection
            client._converter.to_ldap.side_effect = str

            result = await client.modify(
                "cn=test,dc=example,dc=com", {"mail": "newemail@example.com"}
            )

            assert result.success
            assert result.data is True

    @pytest.mark.asyncio
    async def test_delete_success(self) -> None:
        """Test successful LDAP delete operation."""
        with patch.object(FlextLdapSimpleClient, "__init__", return_value=None):
            client = FlextLdapSimpleClient.__new__(FlextLdapSimpleClient)

            # Mock connected state
            mock_connection = MagicMock()
            mock_connection.closed = False
            mock_connection.delete.return_value = True
            mock_connection.result = None

            client._current_connection = mock_connection

            result = await client.delete("cn=test,dc=example,dc=com")

            assert result.success
            assert result.data is True

    @pytest.mark.asyncio
    async def test_disconnect_success(self) -> None:
        """Test successful disconnect."""
        with patch.object(FlextLdapSimpleClient, "__init__", return_value=None):
            client = FlextLdapSimpleClient.__new__(FlextLdapSimpleClient)
            client._connection_manager = MagicMock()

            # Mock connected state
            mock_connection = MagicMock()
            client._current_connection = mock_connection

            from unittest.mock import Mock

            client._connection_manager.close_connection = Mock(
                return_value=FlextResult.ok(TestOperationResult.SUCCESS)
            )

            result = client.disconnect()

            assert result.success
            assert client._current_connection is None

    @pytest.mark.asyncio
    async def test_disconnect_not_connected(self) -> None:
        """Test disconnect when not connected."""
        client = FlextLdapSimpleClient()
        result = client.disconnect()  # sync call

        assert result.success  # Should succeed even if not connected

    def test_is_connected_with_connection(self) -> None:
        """Test is_connected returns True when connected."""
        with patch.object(FlextLdapSimpleClient, "__init__", return_value=None):
            client = FlextLdapSimpleClient.__new__(FlextLdapSimpleClient)

            # Mock connected state
            mock_connection = MagicMock()
            mock_connection.closed = False
            client._current_connection = mock_connection

            assert client.is_connected()

    def test_is_connected_with_closed_connection(self) -> None:
        """Test is_connected returns False when connection is closed."""
        with patch.object(FlextLdapSimpleClient, "__init__", return_value=None):
            client = FlextLdapSimpleClient.__new__(FlextLdapSimpleClient)

            # Mock closed connection
            mock_connection = MagicMock()
            mock_connection.closed = True
            client._current_connection = mock_connection

            assert not client.is_connected()


class TestFlextLdapConnectionConfig:
    """Test suite for FlextLdapConnectionConfig."""

    def test_default_values(self) -> None:
        """Test default configuration values."""
        config = FlextLdapConnectionConfig(host="localhost")

        assert config.server == "localhost"
        assert config.port == 389
        assert config.use_ssl is False
        assert config.timeout_seconds == 30
        assert config.pool_size == 10
        assert config.enable_connection_pooling is True

    def test_custom_values(self) -> None:
        """Test custom configuration values."""
        config = FlextLdapConnectionConfig(
            host="secure.example.com",
            port=636,
            use_ssl=True,
            timeout_seconds=60,
            pool_size=20,
        )

        assert config.server == "secure.example.com"
        assert config.port == 636
        assert config.use_ssl is True
        assert config.timeout_seconds == 60
        assert config.pool_size == 20


class TestFactoryFunctions:
    """Test suite for factory functions."""

    def test_create_ldap_client(self) -> None:
        """Test create_ldap_client factory function."""
        from flext_ldap.ldap_infrastructure import create_ldap_client

        client = create_ldap_client(
            "ldap://localhost", "cn=admin,dc=example,dc=com", "admin"
        )

        assert isinstance(client, FlextLdapSimpleClient)
        assert client._config is not None
        assert client._config.server == "localhost"
        assert client._config.port == 389
        assert not client._config.use_ssl

    def test_create_ldap_converter(self) -> None:
        """Test create_ldap_converter factory function."""
        from flext_ldap.ldap_infrastructure import (
            FlextLdapConverter,
            create_ldap_converter,
        )

        converter = create_ldap_converter()

        assert isinstance(converter, FlextLdapConverter)


class TestFlextLdapSimpleClientAuth:
    """Test suite for FlextLdapSimpleClient authentication methods."""

    @pytest.fixture
    def ldap_client(self) -> FlextLdapSimpleClient:
        """Create LDAP client instance for testing."""
        config = FlextLdapConnectionConfig(
            host="localhost",
            port=389,
            use_ssl=False,
        )
        return FlextLdapSimpleClient(config)

    @pytest.fixture
    def auth_config(self) -> FlextLdapAuthConfig:
        """Create auth config for testing."""
        from pydantic import SecretStr

        return FlextLdapAuthConfig(
            bind_dn="cn=admin,dc=example,dc=com", bind_password=SecretStr("admin123")
        )

    @pytest.mark.asyncio
    async def test_connect_with_auth_success(
        self,
        ldap_client: FlextLdapSimpleClient,
        auth_config: FlextLdapAuthConfig,
    ) -> None:
        """Test successful authentication."""
        # Mock the connection manager and client methods
        mock_connection = Mock()
        mock_connection.unbind = Mock()

        with patch.object(
            ldap_client._connection_manager, "_create_connection"
        ) as mock_create:
            mock_create.return_value = FlextResult.ok(mock_connection)
            ldap_client._current_connection = mock_connection

            result = await ldap_client.connect_with_auth(auth_config)

            assert result.is_success
            assert result.data is True

    @pytest.mark.asyncio
    async def test_connect_with_auth_no_config(
        self,
        auth_config: FlextLdapAuthConfig,
    ) -> None:
        """Test authentication without connection config."""
        client = FlextLdapSimpleClient()  # No config

        result = await client.connect_with_auth(auth_config)

        assert not result.is_success
        assert "Connection configuration required" in result.error

    @pytest.mark.asyncio
    async def test_connect_with_auth_connection_failure(
        self,
        ldap_client: FlextLdapSimpleClient,
        auth_config: FlextLdapAuthConfig,
    ) -> None:
        """Test authentication with connection failure."""
        with patch.object(
            ldap_client._connection_manager, "_create_connection"
        ) as mock_create:
            mock_create.return_value = FlextResult.fail("Connection failed")

            result = await ldap_client.connect_with_auth(auth_config)

            assert not result.is_success
            assert "Authentication failed: Connection failed" in result.error

    @pytest.mark.asyncio
    async def test_connect_with_auth_ldap_exception(
        self,
        ldap_client: FlextLdapSimpleClient,
        auth_config: FlextLdapAuthConfig,
    ) -> None:
        """Test authentication with LDAP exception."""
        from ldap3.core.exceptions import LDAPException

        with patch.object(
            ldap_client._connection_manager, "_create_connection"
        ) as mock_create:
            mock_create.side_effect = LDAPException("LDAP error")

            result = await ldap_client.connect_with_auth(auth_config)

            assert not result.is_success
            assert "LDAP authentication failed" in result.error

    @pytest.mark.asyncio
    async def test_connect_with_auth_runtime_error(
        self,
        ldap_client: FlextLdapSimpleClient,
        auth_config: FlextLdapAuthConfig,
    ) -> None:
        """Test authentication with runtime error."""
        with patch.object(
            ldap_client._connection_manager, "_create_connection"
        ) as mock_create:
            mock_create.side_effect = RuntimeError("Runtime error")

            result = await ldap_client.connect_with_auth(auth_config)

            assert not result.is_success
            assert "Authentication setup failed: Runtime error" in result.error
