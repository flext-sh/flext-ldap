"""Basic tests for FlextLdapClient without LDAP connections.

This module provides comprehensive tests for FlextLdapClient focusing on
basic functionality, error handling, and edge cases that don't require
actual LDAP server connections.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from unittest.mock import MagicMock

import pytest
from pydantic import ValidationError

from flext_ldap import FlextLdapClient, FlextLdapModels


class TestFlextLdapClientInit:
    """Test FlextLdapClient initialization."""

    def test_init_without_config(self) -> None:
        """Test initialization without config."""
        client = FlextLdapClient()
        assert client._connection is None
        assert client._server is None
        assert client._config is None
        assert client._logger is not None
        assert client._discovered_schema is None
        assert client._is_schema_discovered is False

    def test_init_with_config(self) -> None:
        """Test initialization with config."""
        config = FlextLdapModels.ConnectionConfig(
            server="ldap://localhost",
            bind_dn="cn=admin,dc=example,dc=com",
            bind_password="password",
        )
        client = FlextLdapClient(config=config)
        assert client._connection is None
        assert client._server is None
        assert client._config == config
        assert client._logger is not None

    def test_init_with_invalid_config(self) -> None:
        """Test initialization with invalid config."""
        # This should not raise an exception, just store the config
        config = FlextLdapModels.ConnectionConfig(
            server="invalid://server",
            bind_dn="invalid",
            bind_password="",
        )
        client = FlextLdapClient(config=config)
        assert client._config == config


class TestFlextLdapClientBasicMethods:
    """Test basic methods that don't require connections."""

    def test_is_connected_false(self) -> None:
        """Test is_connected returns False when not connected."""
        client = FlextLdapClient()
        assert client.is_connected() is False

    def test_is_connected_true(self) -> None:
        """Test is_connected returns True when connected."""
        client = FlextLdapClient()
        # Mock a connection
        client._connection = MagicMock()
        client._connection.bound = True
        assert client.is_connected() is True

    def test_is_connected_false_when_unbound(self) -> None:
        """Test is_connected returns False when connection is unbound."""
        client = FlextLdapClient()
        client._connection = MagicMock()
        client._connection.bound = False
        assert client.is_connected() is False

    def test_is_schema_discovered_false(self) -> None:
        """Test is_schema_discovered returns False when not discovered."""
        client = FlextLdapClient()
        assert client.is_schema_discovered() is False

    def test_is_schema_discovered_true(self) -> None:
        """Test is_schema_discovered returns True when discovered."""
        client = FlextLdapClient()
        client._is_schema_discovered = True
        assert client.is_schema_discovered() is True

    def test_get_server_info_not_connected(self) -> None:
        """Test get_server_info when not connected."""
        client = FlextLdapClient()
        info = client.get_server_info()
        assert info == {"connected": False, "server": None}

    def test_get_server_info_connected(self) -> None:
        """Test get_server_info when connected."""
        client = FlextLdapClient()
        client._server = MagicMock()
        client._server.host = "localhost"
        client._server.port = 389
        client._connection = MagicMock()
        client._connection.bound = True

        info = client.get_server_info()
        assert info["connected"] is True
        assert info["server"] is not None

    def test_get_server_type_not_connected(self) -> None:
        """Test get_server_type when not connected."""
        client = FlextLdapClient()
        server_type = client.get_server_type()
        assert server_type == FlextLdapModels.LdapServerType.UNKNOWN

    def test_get_server_type_connected(self) -> None:
        """Test get_server_type when connected."""
        client = FlextLdapClient()
        client._connection = MagicMock()
        client._connection.bound = True
        client._server_quirks = FlextLdapModels.ServerQuirks(
            server_type=FlextLdapModels.LdapServerType.OPENLDAP
        )

        server_type = client.get_server_type()
        assert server_type == FlextLdapModels.LdapServerType.OPENLDAP

    def test_get_server_quirks_not_connected(self) -> None:
        """Test get_server_quirks when not connected."""
        client = FlextLdapClient()
        quirks = client.get_server_quirks()
        assert quirks is None

    def test_get_server_quirks_connected(self) -> None:
        """Test get_server_quirks when connected."""
        client = FlextLdapClient()
        client._connection = MagicMock()
        client._connection.bound = True
        expected_quirks = FlextLdapModels.ServerQuirks(
            server_type=FlextLdapModels.LdapServerType.OPENLDAP
        )
        client._server_quirks = expected_quirks

        quirks = client.get_server_quirks()
        assert quirks == expected_quirks

    def test_get_server_capabilities_not_connected(self) -> None:
        """Test get_server_capabilities when not connected."""
        client = FlextLdapClient()
        capabilities = client.get_server_capabilities()

        assert capabilities["connected"] is False
        assert capabilities["schema_discovered"] is False
        assert (
            capabilities["server_info"] is not None
        )  # Returns dict with connected=False
        assert capabilities["server_type"] is not None
        assert capabilities["server_quirks"] is None

    def test_get_server_capabilities_connected(self) -> None:
        """Test get_server_capabilities when connected."""
        client = FlextLdapClient()
        client._connection = MagicMock()
        client._connection.bound = True
        client._is_schema_discovered = True

        capabilities = client.get_server_capabilities()

        assert capabilities["connected"] is True
        assert capabilities["schema_discovered"] is True
        assert capabilities["server_info"] is not None
        assert capabilities["server_type"] is not None


class TestFlextLdapClientErrorHandling:
    """Test error handling in FlextLdapClient."""

    @pytest.mark.asyncio
    async def test_connect_without_server_uri(self) -> None:
        """Test connect without server URI."""
        client = FlextLdapClient()

        result = await client.connect("", "bind_dn", "password")
        assert result.is_failure
        assert "Server URI cannot be empty" in result.error

    @pytest.mark.asyncio
    async def test_connect_without_bind_dn(self) -> None:
        """Test connect without bind DN."""
        client = FlextLdapClient()

        result = await client.connect("ldap://localhost", "", "password")
        assert result.is_failure
        assert "Bind DN cannot be empty" in result.error

    @pytest.mark.asyncio
    async def test_connect_without_password(self) -> None:
        """Test connect without password."""
        client = FlextLdapClient()

        result = await client.connect("ldap://localhost", "bind_dn", "")
        assert result.is_failure
        assert "Password cannot be empty" in result.error

    @pytest.mark.asyncio
    async def test_bind_without_connection(self) -> None:
        """Test bind without connection."""
        client = FlextLdapClient()

        result = await client.bind("bind_dn", "password")
        assert result.is_failure
        assert "No connection established" in result.error

    @pytest.mark.asyncio
    async def test_unbind_without_connection(self) -> None:
        """Test unbind without connection - should be idempotent."""
        client = FlextLdapClient()

        # Unbinding when not connected should succeed (idempotent operation)
        result = await client.unbind()
        assert result.is_success

    @pytest.mark.asyncio
    async def test_close_connection_without_connection(self) -> None:
        """Test close_connection without connection - should be idempotent."""
        client = FlextLdapClient()

        # Closing connection when not connected should succeed (idempotent operation)
        result = await client.close_connection()
        assert result.is_success

    @pytest.mark.asyncio
    async def test_search_without_connection(self) -> None:
        """Test search without connection."""
        client = FlextLdapClient()

        request = FlextLdapModels.SearchRequest(
            base_dn="dc=example,dc=com",
            filter_str="(objectClass=*)",
            scope="subtree",
        )
        result = await client.search_with_request(request)
        assert result.is_failure
        assert "No connection established" in result.error

    @pytest.mark.asyncio
    async def test_authenticate_user_without_connection(self) -> None:
        """Test authenticate_user without connection."""
        client = FlextLdapClient()

        result = await client.authenticate_user("user", "password")
        assert result.is_failure
        assert "No connection established" in result.error

    @pytest.mark.asyncio
    async def test_get_user_without_connection(self) -> None:
        """Test get_user without connection."""
        client = FlextLdapClient()

        result = await client.get_user("cn=user,dc=example,dc=com")
        assert result.is_failure
        assert "No connection established" in result.error

    @pytest.mark.asyncio
    async def test_get_group_without_connection(self) -> None:
        """Test get_group without connection."""
        client = FlextLdapClient()

        result = await client.get_group("cn=group,dc=example,dc=com")
        assert result.is_failure
        assert "No connection established" in result.error

    @pytest.mark.asyncio
    async def test_create_user_without_connection(self) -> None:
        """Test create_user without connection."""
        client = FlextLdapClient()

        user_data = FlextLdapModels.LdapUser(
            dn="cn=user,dc=example,dc=com", cn="user", sn="User"
        )

        result = await client.create_user(user_data)
        assert result.is_failure
        assert "No connection established" in result.error

    @pytest.mark.asyncio
    async def test_create_group_without_connection(self) -> None:
        """Test create_group without connection."""
        client = FlextLdapClient()

        group_data = FlextLdapModels.Group(dn="cn=group,dc=example,dc=com", cn="group")

        result = await client.create_group(group_data)
        assert result.is_failure
        assert "No connection established" in result.error

    @pytest.mark.asyncio
    async def test_user_exists_without_connection(self) -> None:
        """Test user_exists without connection."""
        client = FlextLdapClient()

        result = await client.user_exists("cn=user,dc=example,dc=com")
        assert result.is_failure
        assert "No connection established" in result.error


class TestFlextLdapClientValidation:
    """Test input validation in FlextLdapClient."""

    def test_search_with_empty_base_dn(self) -> None:
        """Test search with empty base DN - validation happens at model level."""
        # Pydantic validates the model before we even call the client method
        with pytest.raises(ValidationError) as exc_info:
            FlextLdapModels.SearchRequest(
                base_dn="", search_filter="(objectClass=*)", scope="SUBTREE"
            )
        assert "DN cannot be empty" in str(exc_info.value)

    def test_search_with_empty_filter(self) -> None:
        """Test search with empty filter - validation happens at model level."""
        # Pydantic validates the model before we even call the client method
        with pytest.raises(ValidationError) as exc_info:
            FlextLdapModels.SearchRequest(
                base_dn="dc=example,dc=com", search_filter="", scope="SUBTREE"
            )
        assert "cannot be empty" in str(exc_info.value)

    @pytest.mark.asyncio
    async def test_get_user_with_empty_dn(self) -> None:
        """Test get_user with empty DN."""
        client = FlextLdapClient()

        result = await client.get_user("")
        assert result.is_failure
        assert "DN cannot be empty" in result.error

    @pytest.mark.asyncio
    async def test_get_group_with_empty_dn(self) -> None:
        """Test get_group with empty DN."""
        client = FlextLdapClient()

        result = await client.get_group("")
        assert result.is_failure
        assert "DN cannot be empty" in result.error

    def test_create_user_with_empty_dn(self) -> None:
        """Test create_user with empty DN."""
        # The LdapUser model validates DN and doesn't allow empty values
        with pytest.raises(Exception):  # ValidationError from Pydantic
            FlextLdapModels.LdapUser(dn="", cn="user", sn="User")

    def test_create_group_with_empty_dn(self) -> None:
        """Test create_group with empty DN."""
        # The Group model validates DN and doesn't allow empty values
        with pytest.raises(Exception):  # ValidationError from Pydantic
            FlextLdapModels.Group(dn="", cn="group")


class TestFlextLdapClientSchemaDiscovery:
    """Test schema discovery functionality."""

    @pytest.mark.asyncio
    async def test_discover_schema_without_connection(self) -> None:
        """Test discover_schema without connection."""
        client = FlextLdapClient()

        result = await client.discover_schema()
        assert result.is_failure
        assert "No connection established" in result.error

    @pytest.mark.asyncio
    async def test_discover_schema_success(self) -> None:
        """Test discover_schema returns successful result."""
        client = FlextLdapClient()
        client._connection = MagicMock()
        client._connection.bound = True
        client._connection.search.return_value = True
        client._connection.entries = []

        result = await client.discover_schema()
        assert result.is_success
        assert result.value is not None
        assert hasattr(result.value, "server_info")
        assert hasattr(result.value, "server_type")


class TestFlextLdapClientNormalization:
    """Test DN and attribute normalization."""

    def test_normalize_dn_basic(self) -> None:
        """Test basic DN normalization."""
        client = FlextLdapClient()

        # Test basic normalization (returns as-is when no schema discovery)
        dn = "CN=User,DC=example,DC=com"
        normalized = client.normalize_dn(dn)
        assert normalized == dn

    def test_normalize_dn_already_normalized(self) -> None:
        """Test DN that's already normalized."""
        client = FlextLdapClient()

        dn = "cn=user,dc=example,dc=com"
        normalized = client.normalize_dn(dn)
        assert normalized == dn

    def test_normalize_dn_empty(self) -> None:
        """Test normalize_dn with empty string."""
        client = FlextLdapClient()

        normalized = client.normalize_dn("")
        assert not normalized

    def test_normalize_attribute_name_basic(self) -> None:
        """Test basic attribute name normalization."""
        client = FlextLdapClient()

        attr_name = "CN"
        normalized = client.normalize_attribute_name(attr_name)
        assert normalized == attr_name

    def test_normalize_attribute_name_already_normalized(self) -> None:
        """Test attribute name that's already normalized."""
        client = FlextLdapClient()

        attr_name = "cn"
        normalized = client.normalize_attribute_name(attr_name)
        assert normalized == attr_name

    def test_normalize_attribute_name_empty(self) -> None:
        """Test normalize_attribute_name with empty string."""
        client = FlextLdapClient()

        normalized = client.normalize_attribute_name("")
        assert not normalized


class TestFlextLdapClientExecute:
    """Test execute method."""

    def test_execute_success(self) -> None:
        """Test execute method returns success."""
        client = FlextLdapClient()

        result = client.execute()
        assert result.is_success
        assert result.value is None


if __name__ == "__main__":
    pytest.main([__file__])
