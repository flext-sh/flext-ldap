"""Tests for LDAP client infrastructure module.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from flext_core import FlextResult
from flext_ldap.ldap_infrastructure import FlextLdapClient, FlextLdapConnectionConfig


class TestFlextLdapClient:
    """Test suite for LDAP infrastructure client."""

    def test_init_default(self) -> None:
        """Test client initialization with default config."""
        client = FlextLdapClient()
        assert client._current_connection is None
        assert client._connection_manager is not None
        assert client._converter is not None
        assert client._config is None

    def test_init_with_config(self) -> None:
        """Test client initialization with config."""
        config = FlextLdapConnectionConfig(
            server_url="ldap://localhost",
            bind_dn="cn=admin,dc=example,dc=com",
            password="admin"
        )
        client = FlextLdapClient(config)
        assert client._config == config

    def test_is_connected_false(self) -> None:
        """Test is_connected returns False when not connected."""
        client = FlextLdapClient()
        assert not client.is_connected()

    @pytest.mark.asyncio
    async def test_connect_success(self) -> None:
        """Test successful LDAP connection."""
        config = FlextLdapConnectionConfig(
            server_url="ldap://localhost",
            bind_dn="cn=admin,dc=example,dc=com",
            password="admin"
        )

        # Mock the connection manager to return success
        with patch.object(FlextLdapClient, "__init__", return_value=None):
            client = FlextLdapClient.__new__(FlextLdapClient)
            client._config = config
            client._connection_manager = MagicMock()
            client._converter = MagicMock()
            client._current_connection = None

            # Mock successful connection
            mock_connection = MagicMock()
            mock_connection.closed = False
            client._connection_manager.get_connection = AsyncMock(
                return_value=FlextResult.ok(mock_connection)
            )

            result = await client.connect(config)

            assert result.is_success
            assert client._current_connection == mock_connection

    @pytest.mark.asyncio
    async def test_connect_failure(self) -> None:
        """Test LDAP connection failure."""
        config = FlextLdapConnectionConfig(
            server_url="ldap://invalid",
            bind_dn="cn=admin,dc=example,dc=com",
            password="wrong"
        )

        with patch.object(FlextLdapClient, "__init__", return_value=None):
            client = FlextLdapClient.__new__(FlextLdapClient)
            client._config = None
            client._connection_manager = MagicMock()
            client._converter = MagicMock()
            client._current_connection = None

            # Mock failed connection
            client._connection_manager.get_connection = AsyncMock(
                return_value=FlextResult.fail("Connection failed")
            )

            result = await client.connect(config)

            assert result.is_failure
            assert client._current_connection is None

    def test_connect_no_config(self) -> None:
        """Test connect with no configuration."""
        client = FlextLdapClient()
        result = client.connect()

        assert result.is_failure
        assert "No connection configuration provided" in result.error

    @pytest.mark.asyncio
    async def test_search_success(self) -> None:
        """Test successful LDAP search."""
        with patch.object(FlextLdapClient, "__init__", return_value=None):
            client = FlextLdapClient.__new__(FlextLdapClient)
            client._converter = MagicMock()

            # Mock connected state
            mock_connection = MagicMock()
            mock_connection.closed = False
            mock_connection.search.return_value = True

            # Mock search results
            mock_entry = MagicMock()
            mock_entry.entry_dn = "cn=test,dc=example,dc=com"
            mock_entry.entry_attributes_as_dict = {"cn": ["test"], "mail": ["test@example.com"]}
            mock_connection.entries = [mock_entry]
            mock_connection.result = None

            client._current_connection = mock_connection
            client._converter.from_ldap.side_effect = lambda x: x

            result = await client.search("dc=example,dc=com", "(cn=test)")

            assert result.is_success
            assert len(result.data) == 1
            assert result.data[0]["dn"] == "cn=test,dc=example,dc=com"

    @pytest.mark.asyncio
    async def test_search_not_connected(self) -> None:
        """Test search when not connected."""
        client = FlextLdapClient()
        result = await client.search("dc=example,dc=com", "(cn=test)")

        assert result.is_failure
        assert "Not connected" in result.error

    @pytest.mark.asyncio
    async def test_search_failure(self) -> None:
        """Test search failure."""
        with patch.object(FlextLdapClient, "__init__", return_value=None):
            client = FlextLdapClient.__new__(FlextLdapClient)

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
        with patch.object(FlextLdapClient, "__init__", return_value=None):
            client = FlextLdapClient.__new__(FlextLdapClient)
            client._converter = MagicMock()

            # Mock connected state
            mock_connection = MagicMock()
            mock_connection.closed = False
            mock_connection.add.return_value = True
            mock_connection.result = None

            client._current_connection = mock_connection
            client._converter.to_ldap.side_effect = lambda x: str(x)

            result = await client.add(
                "cn=test,dc=example,dc=com",
                ["person", "inetOrgPerson"],
                {"cn": "test", "sn": "user"}
            )

            assert result.is_success
            assert result.data is True

    @pytest.mark.asyncio
    async def test_add_not_connected(self) -> None:
        """Test add when not connected."""
        client = FlextLdapClient()
        result = await client.add(
            "cn=test,dc=example,dc=com",
            ["person"],
            {"cn": "test"}
        )

        assert result.is_failure
        assert "Not connected" in result.error

    @pytest.mark.asyncio
    async def test_modify_success(self) -> None:
        """Test successful LDAP modify operation."""
        with patch.object(FlextLdapClient, "__init__", return_value=None):
            client = FlextLdapClient.__new__(FlextLdapClient)
            client._converter = MagicMock()

            # Mock connected state
            mock_connection = MagicMock()
            mock_connection.closed = False
            mock_connection.modify.return_value = True
            mock_connection.result = None

            client._current_connection = mock_connection
            client._converter.to_ldap.side_effect = lambda x: str(x)

            result = await client.modify(
                "cn=test,dc=example,dc=com",
                {"mail": "newemail@example.com"}
            )

            assert result.is_success
            assert result.data is True

    @pytest.mark.asyncio
    async def test_delete_success(self) -> None:
        """Test successful LDAP delete operation."""
        with patch.object(FlextLdapClient, "__init__", return_value=None):
            client = FlextLdapClient.__new__(FlextLdapClient)

            # Mock connected state
            mock_connection = MagicMock()
            mock_connection.closed = False
            mock_connection.delete.return_value = True
            mock_connection.result = None

            client._current_connection = mock_connection

            result = await client.delete("cn=test,dc=example,dc=com")

            assert result.is_success
            assert result.data is True

    @pytest.mark.asyncio
    async def test_disconnect_success(self) -> None:
        """Test successful disconnect."""
        with patch.object(FlextLdapClient, "__init__", return_value=None):
            client = FlextLdapClient.__new__(FlextLdapClient)
            client._connection_manager = MagicMock()

            # Mock connected state
            mock_connection = MagicMock()
            client._current_connection = mock_connection

            client._connection_manager.close_connection = AsyncMock(
                return_value=FlextResult.ok(True)
            )

            result = await client.disconnect()

            assert result.is_success
            assert client._current_connection is None

    def test_disconnect_not_connected(self) -> None:
        """Test disconnect when not connected."""
        client = FlextLdapClient()
        result = client.disconnect()

        assert result.is_success  # Should succeed even if not connected

    def test_is_connected_with_connection(self) -> None:
        """Test is_connected returns True when connected."""
        with patch.object(FlextLdapClient, "__init__", return_value=None):
            client = FlextLdapClient.__new__(FlextLdapClient)

            # Mock connected state
            mock_connection = MagicMock()
            mock_connection.closed = False
            client._current_connection = mock_connection

            assert client.is_connected()

    def test_is_connected_with_closed_connection(self) -> None:
        """Test is_connected returns False when connection is closed."""
        with patch.object(FlextLdapClient, "__init__", return_value=None):
            client = FlextLdapClient.__new__(FlextLdapClient)

            # Mock closed connection
            mock_connection = MagicMock()
            mock_connection.closed = True
            client._current_connection = mock_connection

            assert not client.is_connected()


class TestFlextLdapConnectionConfig:
    """Test suite for FlextLdapConnectionConfig."""

    def test_default_values(self) -> None:
        """Test default configuration values."""
        config = FlextLdapConnectionConfig(server_url="ldap://localhost")

        assert config.server_url == "ldap://localhost"
        assert config.bind_dn is None
        assert config.password is None
        assert config.use_ssl is False
        assert config.tls_config is None
        assert config.connection_timeout == 10
        assert config.pool_size == 5

    def test_custom_values(self) -> None:
        """Test custom configuration values."""
        config = FlextLdapConnectionConfig(
            server="secure.example.com",
            port=636,
            use_ssl=True,
            timeout_seconds=30,
            pool_size=10
        )

        assert config.server == "secure.example.com"
        assert config.port == 636
        assert config.use_ssl is True
        assert config.timeout_seconds == 30
        assert config.pool_size == 10


class TestFactoryFunctions:
    """Test suite for factory functions."""

    def test_create_ldap_client(self) -> None:
        """Test create_ldap_client factory function."""
        from flext_ldap.ldap_infrastructure import create_ldap_client

        client = create_ldap_client(
            "ldap://localhost",
            "cn=admin,dc=example,dc=com",
            "admin"
        )

        assert isinstance(client, FlextLdapClient)
        assert client._config is not None
        assert client._config.server_url == "ldap://localhost"
        assert client._config.bind_dn == "cn=admin,dc=example,dc=com"
        assert client._config.password == "admin"

    def test_create_ldap_converter(self) -> None:
        """Test create_ldap_converter factory function."""
        from flext_ldap.ldap_infrastructure import (
            FlextLdapConverter,
            create_ldap_converter,
        )

        converter = create_ldap_converter()

        assert isinstance(converter, FlextLdapConverter)
