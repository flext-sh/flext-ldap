"""Comprehensive tests for FlextLdapClient.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from unittest.mock import MagicMock, patch

import pytest

from flext_ldap.clients import FlextLdapClient
from flext_ldap.models import FlextLdapModels


class TestFlextLdapClientInit:
    """Test FlextLdapClient initialization."""

    def test_init_without_config(self) -> None:
        """Test initialization without config."""
        client = FlextLdapClient()
        assert client._connection is None
        assert client._server is None
        assert client._config is None

    def test_init_with_config(self) -> None:
        """Test initialization with config."""
        config = FlextLdapModels.ConnectionConfig(
            server="ldap://localhost",
            bind_dn="cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com",
            bind_password="password",
        )
        client = FlextLdapClient(config=config)
        assert client._connection is None
        assert client._server is None
        assert client._config == config


class TestFlextLdapClientConnection:
    """Test connection management."""

    @pytest.mark.asyncio
    async def test_connect_success(self) -> None:
        """Test successful connection."""
        client = FlextLdapClient()

        with (
            patch("flext_ldap.clients.Server"),
            patch("flext_ldap.clients.Connection") as mock_conn,
        ):
            mock_conn_instance = MagicMock()
            mock_conn_instance.bind.return_value = True
            mock_conn.return_value = mock_conn_instance

            result = await client.connect(
                "ldap://localhost:389", "cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com", "password"
            )

            assert result.is_success
            assert client._connection is not None

    @pytest.mark.asyncio
    async def test_connect_bind_failure(self) -> None:
        """Test connection with bind failure."""
        client = FlextLdapClient()

        with (
            patch("flext_ldap.clients.Server"),
            patch("flext_ldap.clients.Connection") as mock_conn,
        ):
            mock_conn_instance = MagicMock()
            mock_conn_instance.bind.return_value = False
            mock_conn_instance.last_error = "Invalid credentials"
            mock_conn.return_value = mock_conn_instance

            result = await client.connect(
                "ldap://localhost:389", "cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com", "wrong_password"
            )

            assert result.is_failure
            assert result.error is not None and "Invalid credentials" in result.error

    @pytest.mark.asyncio
    async def test_bind_success(self) -> None:
        """Test bind operation."""
        client = FlextLdapClient()

        with (
            patch("flext_ldap.clients.Server"),
            patch("flext_ldap.clients.Connection") as mock_conn,
        ):
            mock_conn_instance = MagicMock()
            mock_conn_instance.bind.return_value = True
            mock_conn.return_value = mock_conn_instance

            # First connect
            await client.connect(
                "ldap://localhost", "cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com", "pass"
            )

            # Then bind
            result = await client.bind("cn=user,dc=example,dc=com", "userpass")
            assert result.is_success

    @pytest.mark.asyncio
    async def test_unbind(self) -> None:
        """Test unbind operation."""
        client = FlextLdapClient()

        with (
            patch("flext_ldap.clients.Server"),
            patch("flext_ldap.clients.Connection") as mock_conn,
        ):
            mock_conn_instance = MagicMock()
            mock_conn_instance.bind.return_value = True
            mock_conn.return_value = mock_conn_instance

            await client.connect(
                "ldap://localhost", "cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com", "pass"
            )

            result = await client.unbind()
            assert result.is_success
            assert client._connection is None

    def test_is_connected(self) -> None:
        """Test connection status check."""
        client = FlextLdapClient()
        assert not client.is_connected()

        client._connection = MagicMock()
        assert client.is_connected()


class TestFlextLdapClientAuthentication:
    """Test authentication operations."""

    @pytest.mark.asyncio
    async def test_authenticate_user_success(self) -> None:
        """Test successful user authentication."""
        client = FlextLdapClient()

        with (
            patch("flext_ldap.clients.Server"),
            patch("flext_ldap.clients.Connection") as mock_conn,
        ):
            # Setup main connection
            mock_main_conn = MagicMock()
            mock_main_conn.bind.return_value = True
            mock_main_conn.search.return_value = True
            mock_main_conn.entries = [
                MagicMock(entry_dn="cn=testuser,dc=example,dc=com")
            ]

            # Setup user auth connection
            mock_user_conn = MagicMock()
            mock_user_conn.bind.return_value = True

            mock_conn.side_effect = [mock_main_conn, mock_user_conn]

            await client.connect(
                "ldap://localhost", "cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com", "pass"
            )

            result = await client.authenticate_user("testuser", "userpass")
            assert result.is_success

    @pytest.mark.asyncio
    async def test_authenticate_user_not_found(self) -> None:
        """Test authentication when user not found."""
        client = FlextLdapClient()

        with (
            patch("flext_ldap.clients.Server"),
            patch("flext_ldap.clients.Connection") as mock_conn,
        ):
            mock_conn_instance = MagicMock()
            mock_conn_instance.bind.return_value = True
            mock_conn_instance.search.return_value = True
            mock_conn_instance.entries = []
            mock_conn.return_value = mock_conn_instance

            await client.connect(
                "ldap://localhost", "cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com", "pass"
            )

            result = await client.authenticate_user("nonexistent", "pass")
            assert result.is_failure
            assert result.error is not None and "not found" in result.error.lower()


class TestFlextLdapClientSearch:
    """Test search operations."""

    @pytest.mark.asyncio
    async def test_search_users_success(self) -> None:
        """Test successful user search."""
        client = FlextLdapClient()

        with (
            patch("flext_ldap.clients.Server"),
            patch("flext_ldap.clients.Connection") as mock_conn,
        ):
            mock_entry = MagicMock()
            mock_entry.entry_dn = "cn=testuser,dc=example,dc=com"
            mock_entry.entry_attributes = ["cn", "uid", "mail"]
            mock_entry.__getitem__.side_effect = lambda _: MagicMock(value="test")

            mock_conn_instance = MagicMock()
            mock_conn_instance.bind.return_value = True
            mock_conn_instance.search.return_value = True
            mock_conn_instance.entries = [mock_entry]
            mock_conn.return_value = mock_conn_instance

            await client.connect(
                "ldap://localhost", "cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com", "pass"
            )

            result = await client.search_users("dc=example,dc=com", "(uid=*)")
            assert result.is_success

    @pytest.mark.asyncio
    async def test_search_groups_success(self) -> None:
        """Test successful group search."""
        client = FlextLdapClient()

        with (
            patch("flext_ldap.clients.Server"),
            patch("flext_ldap.clients.Connection") as mock_conn,
        ):
            mock_entry = MagicMock()
            mock_entry.entry_dn = "cn=testgroup,dc=example,dc=com"
            mock_entry.entry_attributes = ["cn", "gidNumber"]
            mock_entry.__getitem__.side_effect = lambda _: MagicMock(value="test")

            mock_conn_instance = MagicMock()
            mock_conn_instance.bind.return_value = True
            mock_conn_instance.search.return_value = True
            mock_conn_instance.entries = [mock_entry]
            mock_conn.return_value = mock_conn_instance

            await client.connect(
                "ldap://localhost", "cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com", "pass"
            )

            result = await client.search_groups("dc=example,dc=com", "(cn=*)")
            assert result.is_success


class TestFlextLdapClientCRUD:
    """Test CRUD operations."""

    @pytest.mark.asyncio
    async def test_get_user_success(self) -> None:
        """Test get user operation."""
        client = FlextLdapClient()

        with (
            patch("flext_ldap.clients.Server"),
            patch("flext_ldap.clients.Connection") as mock_conn,
        ):
            mock_entry = MagicMock()
            mock_entry.entry_dn = "cn=testuser,dc=example,dc=com"
            mock_entry.entry_attributes = ["cn", "uid", "sn", "givenName", "mail"]

            def mock_getitem(key: str) -> MagicMock:
                values = {
                    "cn": MagicMock(value="Test User"),
                    "uid": MagicMock(value="testuser"),
                    "sn": MagicMock(value="User"),
                    "givenName": MagicMock(value="Test"),
                    "mail": MagicMock(value="test@example.com"),
                }
                return values.get(key, MagicMock(value=None))

            mock_entry.__getitem__ = mock_getitem

            mock_conn_instance = MagicMock()
            mock_conn_instance.bind.return_value = True
            mock_conn_instance.search.return_value = True
            mock_conn_instance.entries = [mock_entry]
            mock_conn.return_value = mock_conn_instance

            await client.connect(
                "ldap://localhost", "cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com", "pass"
            )

            result = await client.get_user("cn=testuser,dc=example,dc=com")
            assert result.is_success

    @pytest.mark.asyncio
    async def test_get_group_success(self) -> None:
        """Test get group operation."""
        client = FlextLdapClient()

        with (
            patch("flext_ldap.clients.Server"),
            patch("flext_ldap.clients.Connection") as mock_conn,
        ):
            mock_entry = MagicMock()
            mock_entry.entry_dn = "cn=testgroup,dc=example,dc=com"
            mock_entry.entry_attributes = ["cn", "gidNumber"]

            def mock_getitem(key: str) -> MagicMock:
                values = {
                    "cn": MagicMock(value="testgroup"),
                    "gidNumber": MagicMock(value="1000"),
                }
                return values.get(key, MagicMock(value=None))

            mock_entry.__getitem__ = mock_getitem

            mock_conn_instance = MagicMock()
            mock_conn_instance.bind.return_value = True
            mock_conn_instance.search.return_value = True
            mock_conn_instance.entries = [mock_entry]
            mock_conn.return_value = mock_conn_instance

            await client.connect(
                "ldap://localhost", "cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com", "pass"
            )

            result = await client.get_group("cn=testgroup,dc=example,dc=com")
            assert result.is_success

    @pytest.mark.asyncio
    async def test_delete_user_no_connection(self) -> None:
        """Test delete user without connection."""
        client = FlextLdapClient()

        result = await client.delete_user("cn=testuser,dc=example,dc=com")
        assert result.is_failure
        assert result.error is not None and "No connection" in result.error

    @pytest.mark.asyncio
    async def test_delete_group_no_connection(self) -> None:
        """Test delete group without connection."""
        client = FlextLdapClient()

        result = await client.delete_group("cn=testgroup,dc=example,dc=com")
        assert result.is_failure
        assert result.error is not None and "No connection" in result.error


class TestFlextLdapClientLowLevel:
    """Test low-level LDAP operations."""

    @pytest.mark.asyncio
    async def test_add_no_connection(self) -> None:
        """Test add operation without connection."""
        client = FlextLdapClient()

        result = await client.add("cn=test,dc=example,dc=com", {"cn": "test"})
        assert result.is_failure
        assert result.error is not None and "No connection" in result.error

    @pytest.mark.asyncio
    async def test_modify_no_connection(self) -> None:
        """Test modify operation without connection."""
        client = FlextLdapClient()

        result = await client.modify(
            "cn=test,dc=example,dc=com", {"mail": [("MODIFY_REPLACE", ["new@example.com"])]}
        )
        assert result.is_failure
        assert result.error is not None and "No connection" in result.error

    @pytest.mark.asyncio
    async def test_delete_no_connection(self) -> None:
        """Test delete operation without connection."""
        client = FlextLdapClient()

        result = await client.delete("cn=test,dc=example,dc=com")
        assert result.is_failure
        assert result.error is not None and "No connection" in result.error

    @pytest.mark.asyncio
    async def test_add_member_no_connection(self) -> None:
        """Test add member operation without connection."""
        client = FlextLdapClient()

        result = await client.add_member(
            "cn=group,dc=example,dc=com", "cn=user,dc=example,dc=com"
        )
        assert result.is_failure
        assert result.error is not None and "No connection" in result.error


class TestFlextLdapClientUpdate:
    """Test update operations."""

    @pytest.mark.asyncio
    async def test_update_user_attributes_no_connection(self) -> None:
        """Test update user attributes without connection."""
        client = FlextLdapClient()

        result = await client.update_user_attributes(
            "cn=testuser,dc=example,dc=com", {"mail": "new@example.com"}
        )
        assert result.is_failure
        assert result.error is not None and "No connection" in result.error

    @pytest.mark.asyncio
    async def test_update_group_attributes_no_connection(self) -> None:
        """Test update group attributes without connection."""
        client = FlextLdapClient()

        result = await client.update_group_attributes(
            "cn=testgroup,dc=example,dc=com", {"description": "New description"}
        )
        assert result.is_failure
        assert result.error is not None and "No connection" in result.error

    @pytest.mark.asyncio
    async def test_update_user_deprecated(self) -> None:
        """Test deprecated update_user method."""
        client = FlextLdapClient()

        result = await client.update_user(
            "cn=testuser,dc=example,dc=com", {"mail": "new@example.com"}
        )
        assert result.is_failure
        assert result.error is not None and "No connection" in result.error


class TestFlextLdapClientHelpers:
    """Test helper methods."""

    def test_create_user_from_entry(self) -> None:
        """Test _create_user_from_entry helper."""
        client = FlextLdapClient()

        mock_entry = MagicMock()
        mock_entry.entry_dn = "cn=testuser,dc=example,dc=com"
        mock_entry.entry_attributes = ["cn", "uid", "sn", "givenName", "mail"]

        def mock_getitem(key: str) -> MagicMock:
            values = {
                "cn": MagicMock(value="Test User"),
                "uid": MagicMock(value="testuser"),
                "sn": MagicMock(value="User"),
                "givenName": MagicMock(value="Test"),
                "mail": MagicMock(value="test@example.com"),
                "telephoneNumber": MagicMock(value="123-456-7890"),
                "mobile": MagicMock(value="098-765-4321"),
                "departmentNumber": MagicMock(value="IT"),
                "title": MagicMock(value="Developer"),
                "o": MagicMock(value="Example Corp"),
                "ou": MagicMock(value="Engineering"),
            }
            return values.get(key, MagicMock(value=None))

        mock_entry.__getitem__ = mock_getitem

        user = client._create_user_from_entry(mock_entry)
        assert user.dn == "cn=testuser,dc=example,dc=com"
        assert user.cn == "Test User"
        assert user.uid == "testuser"

    def test_create_group_from_entry(self) -> None:
        """Test _create_group_from_entry helper."""
        client = FlextLdapClient()

        mock_entry = MagicMock()
        mock_entry.entry_dn = "cn=testgroup,dc=example,dc=com"
        mock_entry.entry_attributes = ["cn", "gidNumber", "description", "member"]

        def mock_getitem(key: str) -> MagicMock:
            mock_attr = MagicMock()
            values_map = {
                "cn": "testgroup",
                "gidNumber": "1000",
                "description": "Test group",
                "member": ["cn=user1,dc=example,dc=com", "cn=user2,dc=example,dc=com"],
            }
            mock_attr.value = values_map.get(key)
            return mock_attr

        mock_entry.__getitem__ = mock_getitem

        group = client._create_group_from_entry(mock_entry)
        assert group.dn == "cn=testgroup,dc=example,dc=com"
        assert group.cn == "testgroup"
        assert group.gid_number == 1000


class TestFlextLdapClientTestConnection:
    """Test connection testing."""

    def test_test_connection_no_connection(self) -> None:
        """Test connection test without active connection."""
        client = FlextLdapClient()

        result = client.test_connection()
        assert result.is_failure
        assert result.error is not None and "Not connected" in result.error

    def test_test_connection_with_connection(self) -> None:
        """Test connection test with active connection."""
        client = FlextLdapClient()
        client._connection = MagicMock()

        result = client.test_connection()
        assert result.is_success
