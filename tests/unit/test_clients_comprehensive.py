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
            mock_conn_instance.bound = False  # Simulate failed bind
            mock_conn_instance.last_error = "Invalid credentials"
            mock_conn.return_value = mock_conn_instance

            result = await client.connect(
                "ldap://localhost:389", "cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com", "wrong_password"
            )

            assert not result.is_success
            assert result.error is not None and "Failed to bind to LDAP server" in result.error

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
            
            # Create a proper mock entry with valid email
            mock_entry = MagicMock()
            mock_entry.entry_dn = "cn=testuser,dc=example,dc=com"
            
            # Mock the email attribute with a proper email format
            mock_email_attr = MagicMock()
            mock_email_attr.value = "testuser@example.com"
            mock_entry.mail = mock_email_attr
            
            # Mock other required attributes
            mock_cn_attr = MagicMock()
            mock_cn_attr.value = "Test User"
            mock_entry.cn = mock_cn_attr
            
            mock_uid_attr = MagicMock()
            mock_uid_attr.value = "testuser"
            mock_entry.uid = mock_uid_attr
            
            mock_sn_attr = MagicMock()
            mock_sn_attr.value = "User"
            mock_entry.sn = mock_sn_attr
            
            mock_main_conn.entries = [mock_entry]

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
            assert not result.is_success
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
            
            # Set up attributes directly on the mock entry
            mock_cn_attr = MagicMock()
            mock_cn_attr.value = "Test User"
            mock_entry.cn = mock_cn_attr
            
            mock_uid_attr = MagicMock()
            mock_uid_attr.value = "testuser"
            mock_entry.uid = mock_uid_attr
            
            mock_mail_attr = MagicMock()
            mock_mail_attr.value = "testuser@example.com"
            mock_entry.mail = mock_mail_attr

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

            # Set up attributes directly on the mock entry
            mock_cn_attr = MagicMock()
            mock_cn_attr.value = "Test User"
            mock_entry.cn = mock_cn_attr
            
            mock_uid_attr = MagicMock()
            mock_uid_attr.value = "testuser"
            mock_entry.uid = mock_uid_attr
            
            mock_sn_attr = MagicMock()
            mock_sn_attr.value = "User"
            mock_entry.sn = mock_sn_attr
            
            mock_given_name_attr = MagicMock()
            mock_given_name_attr.value = "Test"
            mock_entry.givenName = mock_given_name_attr
            
            mock_mail_attr = MagicMock()
            mock_mail_attr.value = "test@example.com"
            mock_entry.mail = mock_mail_attr

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
        assert not result.is_success
        assert result.error is not None and "No connection" in result.error

    @pytest.mark.asyncio
    async def test_delete_group_no_connection(self) -> None:
        """Test delete group without connection."""
        client = FlextLdapClient()

        result = await client.delete_group("cn=testgroup,dc=example,dc=com")
        assert not result.is_success
        assert result.error is not None and "No connection" in result.error


class TestFlextLdapClientLowLevel:
    """Test low-level LDAP operations."""

    @pytest.mark.asyncio
    async def test_add_no_connection(self) -> None:
        """Test add operation without connection."""
        client = FlextLdapClient()

        result = await client.add("cn=test,dc=example,dc=com", {"cn": "test"})
        assert not result.is_success
        assert result.error is not None and "No connection" in result.error

    @pytest.mark.asyncio
    async def test_modify_no_connection(self) -> None:
        """Test modify operation without connection."""
        client = FlextLdapClient()

        result = await client.modify(
            "cn=test,dc=example,dc=com", {"mail": [("MODIFY_REPLACE", ["new@example.com"])]}
        )
        assert not result.is_success
        assert result.error is not None and "No connection" in result.error

    @pytest.mark.asyncio
    async def test_delete_no_connection(self) -> None:
        """Test delete operation without connection."""
        client = FlextLdapClient()

        result = await client.delete("cn=test,dc=example,dc=com")
        assert not result.is_success
        assert result.error is not None and "No connection" in result.error

    @pytest.mark.asyncio
    async def test_add_member_no_connection(self) -> None:
        """Test add member operation without connection."""
        client = FlextLdapClient()

        result = await client.add_member(
            "cn=group,dc=example,dc=com", "cn=user,dc=example,dc=com"
        )
        assert not result.is_success
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
        assert not result.is_success
        assert result.error is not None and "No connection" in result.error

    @pytest.mark.asyncio
    async def test_update_group_attributes_no_connection(self) -> None:
        """Test update group attributes without connection."""
        client = FlextLdapClient()

        result = await client.update_group_attributes(
            "cn=testgroup,dc=example,dc=com", {"description": "New description"}
        )
        assert not result.is_success
        assert result.error is not None and "No connection" in result.error

    @pytest.mark.asyncio
    async def test_update_user_deprecated(self) -> None:
        """Test deprecated update_user method."""
        client = FlextLdapClient()

        result = await client.update_user(
            "cn=testuser,dc=example,dc=com", {"mail": "new@example.com"}
        )
        assert not result.is_success
        assert result.error is not None and "No connection" in result.error


class TestFlextLdapClientHelpers:
    """Test helper methods."""

    def test_create_user_from_entry(self) -> None:
        """Test _create_user_from_entry helper."""
        client = FlextLdapClient()

        mock_entry = MagicMock()
        mock_entry.entry_dn = "cn=testuser,dc=example,dc=com"
        mock_entry.entry_attributes = ["cn", "uid", "sn", "givenName", "mail"]

        # Set up attributes directly on the mock entry
        mock_cn_attr = MagicMock()
        mock_cn_attr.value = "Test User"
        mock_entry.cn = mock_cn_attr
        
        mock_uid_attr = MagicMock()
        mock_uid_attr.value = "testuser"
        mock_entry.uid = mock_uid_attr
        
        mock_sn_attr = MagicMock()
        mock_sn_attr.value = "User"
        mock_entry.sn = mock_sn_attr
        
        mock_given_name_attr = MagicMock()
        mock_given_name_attr.value = "Test"
        mock_entry.givenName = mock_given_name_attr
        
        mock_mail_attr = MagicMock()
        mock_mail_attr.value = "test@example.com"
        mock_entry.mail = mock_mail_attr
        
        mock_telephone_number_attr = MagicMock()
        mock_telephone_number_attr.value = "123-456-7890"
        mock_entry.telephoneNumber = mock_telephone_number_attr
        
        mock_mobile_attr = MagicMock()
        mock_mobile_attr.value = "098-765-4321"
        mock_entry.mobile = mock_mobile_attr
        
        mock_department_number_attr = MagicMock()
        mock_department_number_attr.value = "IT"
        mock_entry.departmentNumber = mock_department_number_attr
        
        mock_title_attr = MagicMock()
        mock_title_attr.value = "Developer"
        mock_entry.title = mock_title_attr
        
        mock_o_attr = MagicMock()
        mock_o_attr.value = "Example Corp"
        mock_entry.o = mock_o_attr
        
        mock_ou_attr = MagicMock()
        mock_ou_attr.value = "Engineering"
        mock_entry.ou = mock_ou_attr

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

        # Set up attributes directly on the mock entry
        mock_cn_attr = MagicMock()
        mock_cn_attr.value = "testgroup"
        mock_entry.cn = mock_cn_attr
        
        mock_gid_number_attr = MagicMock()
        mock_gid_number_attr.value = "1000"
        mock_entry.gidNumber = mock_gid_number_attr
        
        mock_description_attr = MagicMock()
        mock_description_attr.value = "Test group"
        mock_entry.description = mock_description_attr

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
        assert not result.is_success
        assert result.error is not None and "Not connected" in result.error

    def test_test_connection_with_connection(self) -> None:
        """Test connection test with active connection."""
        client = FlextLdapClient()
        client._connection = MagicMock()

        result = client.test_connection()
        assert result.is_success
