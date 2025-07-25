"""Tests for LDAP infrastructure client in FLEXT-LDAP."""

from unittest.mock import MagicMock, patch
from uuid import uuid4

import pytest
from flext_core import FlextResult
from ldap3.core.exceptions import LDAPException

from flext_ldap.domain.value_objects import FlextLdapCreateUserRequest
from flext_ldap.infrastructure.ldap_client import FlextLdapInfrastructureClient


class TestFlextLdapInfrastructureClient:
    """Test FlextLdapInfrastructureClient."""

    @pytest.fixture
    def ldap_client(self) -> FlextLdapInfrastructureClient:
        """Create LDAP client instance."""
        return FlextLdapInfrastructureClient()

    @pytest.fixture
    def mock_connection(self) -> MagicMock:
        """Create mock LDAP connection."""
        mock_conn = MagicMock()
        mock_conn.bound = True
        mock_conn.user = "cn=admin,dc=example,dc=org"
        mock_conn.server = MagicMock()
        mock_conn.server.info = None
        mock_conn.result = {"description": "success"}
        return mock_conn

    def test_initialization(self, ldap_client: FlextLdapInfrastructureClient) -> None:
        """Test client initialization."""
        assert ldap_client._connections == {}
        assert ldap_client._uuid_to_dn == {}
        assert ldap_client._dn_to_uuid == {}

    def test_uuid_dn_mapping(self, ldap_client: FlextLdapInfrastructureClient) -> None:
        """Test UUID to DN mapping functionality."""
        entity_uuid = str(uuid4())
        dn = "uid=test,ou=users,dc=example,dc=org"

        # Register mapping
        ldap_client._register_uuid_dn_mapping(entity_uuid, dn)

        # Verify mapping
        assert ldap_client._get_dn_from_uuid(entity_uuid) == dn
        assert ldap_client._uuid_to_dn[entity_uuid] == dn
        assert ldap_client._dn_to_uuid[dn] == entity_uuid

    def test_resolve_user_identifier_with_dn(
        self,
        ldap_client: FlextLdapInfrastructureClient,
    ) -> None:
        """Test resolving user identifier when it's already a DN."""
        dn = "uid=test,ou=users,dc=example,dc=org"
        result = ldap_client._resolve_user_identifier(dn)

        assert result.success is True
        assert result.data == dn

    def test_resolve_user_identifier_with_uuid(
        self,
        ldap_client: FlextLdapInfrastructureClient,
    ) -> None:
        """Test resolving user identifier from UUID."""
        entity_uuid = str(uuid4())
        dn = "uid=test,ou=users,dc=example,dc=org"

        # Register mapping first
        ldap_client._register_uuid_dn_mapping(entity_uuid, dn)

        result = ldap_client._resolve_user_identifier(entity_uuid)

        assert result.success is True
        assert result.data == dn

    def test_resolve_user_identifier_not_found(
        self,
        ldap_client: FlextLdapInfrastructureClient,
    ) -> None:
        """Test resolving non-existent UUID."""
        entity_uuid = str(uuid4())
        result = ldap_client._resolve_user_identifier(entity_uuid)

        assert result.success is False
        assert result.error is not None
        assert "not found" in result.error

    def test_resolve_group_identifier(
        self,
        ldap_client: FlextLdapInfrastructureClient,
    ) -> None:
        """Test resolving group identifier."""
        group_uuid = str(uuid4())
        dn = "cn=admins,ou=groups,dc=example,dc=org"

        # Register mapping
        ldap_client._register_uuid_dn_mapping(group_uuid, dn)

        result = ldap_client._resolve_group_identifier(group_uuid)
        assert result == dn

    def test_resolve_group_identifier_not_found(
        self,
        ldap_client: FlextLdapInfrastructureClient,
    ) -> None:
        """Test resolving non-existent group UUID."""
        group_uuid = str(uuid4())
        result = ldap_client._resolve_group_identifier(group_uuid)
        assert result is None

    @patch("ldap3.Connection")
    @patch("ldap3.Server")
    async def test_connect_success(
        self,
        mock_server: MagicMock,
        mock_connection: MagicMock,
        ldap_client: FlextLdapInfrastructureClient,
    ) -> None:
        """Test successful basic connection."""
        # Setup mocks
        mock_server_instance = MagicMock()
        mock_server.return_value = mock_server_instance

        mock_conn_instance = MagicMock()
        mock_connection.return_value = mock_conn_instance

        result = await ldap_client.connect(
            server_url="ldap://localhost:389",
            bind_dn="cn=admin,dc=example,dc=org",
            password="password",
        )

        assert result.success is True
        assert result.data == "ldap://localhost:389:cn=admin,dc=example,dc=org"

    @patch("ldap3.Connection")
    async def test_connect_failure(
        self,
        mock_connection: MagicMock,
        ldap_client: FlextLdapInfrastructureClient,
    ) -> None:
        """Test connection failure."""
        mock_connection.side_effect = LDAPException("Connection failed")

        result = await ldap_client.connect(
            server_url="ldap://invalid:389",
            bind_dn="cn=admin,dc=example,dc=org",
            password="password",
        )

        assert result.success is False
        assert result.error is not None
        assert "LDAP connection failed" in result.error

    @patch("ldap3.Connection")
    @patch("ldap3.Server")
    async def test_connect_with_pool_success(
        self,
        mock_server: MagicMock,
        mock_connection: MagicMock,
        ldap_client: FlextLdapInfrastructureClient,
    ) -> None:
        """Test successful connection with pool creation."""
        # Setup mocks
        mock_server_instance = MagicMock()
        mock_server.return_value = mock_server_instance

        mock_conn_instance = MagicMock()
        mock_connection.return_value = mock_conn_instance

        # Test parameters
        server_urls = ["ldap://server1:389", "ldap://server2:389"]
        bind_dn = "cn=admin,dc=example,dc=org"
        password = "password"

        with patch("ldap3.ServerPool") as mock_pool:
            mock_pool_instance = MagicMock()
            mock_pool.return_value = mock_pool_instance

            result = await ldap_client.connect_with_pool(
                server_urls=server_urls,
                bind_dn=bind_dn,
                password=password,
                pool_name="test_pool",
            )

        assert result.success is True
        assert result.data is not None
        assert result.data.startswith("pool:test_pool:")

    @patch("ldap3.Connection")
    async def test_connect_with_pool_failure(
        self,
        mock_connection: MagicMock,
        ldap_client: FlextLdapInfrastructureClient,
    ) -> None:
        """Test connection with pool creation failure."""
        mock_connection.side_effect = LDAPException("Connection failed")

        with patch("ldap3.ServerPool"):
            result = await ldap_client.connect_with_pool(
                server_urls=["ldap://invalid:389"],
                bind_dn="cn=admin,dc=example,dc=org",
                password="password",
            )

        assert result.success is False
        assert result.error is not None
        assert "LDAP pool connection failed" in result.error

    async def test_disconnect_success(
        self,
        ldap_client: FlextLdapInfrastructureClient,
        mock_connection: MagicMock,
    ) -> None:
        """Test successful disconnection."""
        connection_id = "test_connection"
        ldap_client._connections[connection_id] = mock_connection

        result = await ldap_client.disconnect(connection_id)

        assert result.success is True
        mock_connection.unbind.assert_called_once()
        assert connection_id not in ldap_client._connections

    async def test_disconnect_not_found(
        self,
        ldap_client: FlextLdapInfrastructureClient,
    ) -> None:
        """Test disconnecting non-existent connection."""
        result = await ldap_client.disconnect("non_existent")

        assert result.success is False
        assert result.error is not None
        assert "Connection not found" in result.error

    async def test_search_success(
        self,
        ldap_client: FlextLdapInfrastructureClient,
        mock_connection: MagicMock,
    ) -> None:
        """Test successful LDAP search."""
        connection_id = "test_connection"
        ldap_client._connections[connection_id] = mock_connection

        # Setup mock search results
        mock_connection.search.return_value = True
        mock_connection.entries = [
            MagicMock(entry_dn="uid=user1,ou=users,dc=example,dc=org"),
            MagicMock(entry_dn="uid=user2,ou=users,dc=example,dc=org"),
        ]

        result = await ldap_client.search(
            connection_id=connection_id,
            base_dn="ou=users,dc=example,dc=org",
            search_filter="(objectClass=inetOrgPerson)",
            attributes=["uid", "cn", "mail"],
        )

        assert result.success is True
        assert result.data is not None
        assert len(result.data) == 2
        mock_connection.search.assert_called_once()

    async def test_search_connection_not_found(
        self,
        ldap_client: FlextLdapInfrastructureClient,
    ) -> None:
        """Test search with non-existent connection."""
        result = await ldap_client.search(
            connection_id="non_existent",
            base_dn="ou=users,dc=example,dc=org",
            search_filter="(objectClass=inetOrgPerson)",
        )

        assert result.success is False
        assert result.error is not None
        assert "Connection not found" in result.error

    async def test_search_ldap_exception(
        self,
        ldap_client: FlextLdapInfrastructureClient,
        mock_connection: MagicMock,
    ) -> None:
        """Test search with LDAP exception."""
        connection_id = "test_connection"
        ldap_client._connections[connection_id] = mock_connection

        mock_connection.search.side_effect = LDAPException("Search failed")

        result = await ldap_client.search(
            connection_id=connection_id,
            base_dn="ou=users,dc=example,dc=org",
            search_filter="(objectClass=inetOrgPerson)",
        )

        assert result.success is False
        assert result.error is not None
        assert "LDAP search failed" in result.error

    async def test_add_entry_success(
        self,
        ldap_client: FlextLdapInfrastructureClient,
        mock_connection: MagicMock,
    ) -> None:
        """Test successful entry addition."""
        connection_id = "test_connection"
        ldap_client._connections[connection_id] = mock_connection

        mock_connection.add.return_value = True

        attributes = {
            "objectClass": ["inetOrgPerson"],
            "uid": ["testuser"],
            "cn": ["Test User"],
            "sn": ["User"],
        }

        result = await ldap_client.add_entry(
            connection_id=connection_id,
            dn="uid=testuser,ou=users,dc=example,dc=org",
            attributes=attributes,
        )

        assert result.success is True
        mock_connection.add.assert_called_once()

    async def test_add_entry_failure(
        self,
        ldap_client: FlextLdapInfrastructureClient,
        mock_connection: MagicMock,
    ) -> None:
        """Test failed entry addition."""
        connection_id = "test_connection"
        ldap_client._connections[connection_id] = mock_connection

        mock_connection.add.return_value = False
        mock_connection.result = {"description": "Entry already exists"}

        result = await ldap_client.add_entry(
            connection_id=connection_id,
            dn="uid=testuser,ou=users,dc=example,dc=org",
            attributes={"objectClass": ["inetOrgPerson"]},
        )

        assert result.success is False
        assert result.error is not None
        assert "Add failed" in result.error

    async def test_modify_entry_success(
        self,
        ldap_client: FlextLdapInfrastructureClient,
        mock_connection: MagicMock,
    ) -> None:
        """Test successful entry modification."""
        connection_id = "test_connection"
        ldap_client._connections[connection_id] = mock_connection

        mock_connection.modify.return_value = True

        modifications = {
            "mail": "newemail@example.org",
            "telephoneNumber": "+1234567890",
        }

        result = await ldap_client.modify_entry(
            connection_id=connection_id,
            dn="uid=testuser,ou=users,dc=example,dc=org",
            changes=modifications,
        )

        assert result.success is True
        mock_connection.modify.assert_called_once()

    async def test_delete_entry_success(
        self,
        ldap_client: FlextLdapInfrastructureClient,
        mock_connection: MagicMock,
    ) -> None:
        """Test successful entry deletion."""
        connection_id = "test_connection"
        ldap_client._connections[connection_id] = mock_connection

        mock_connection.delete.return_value = True

        result = await ldap_client.delete_entry(
            connection_id=connection_id,
            dn="uid=testuser,ou=users,dc=example,dc=org",
        )

        assert result.success is True
        mock_connection.delete.assert_called_once()

    def test_get_connection_info_success(
        self,
        ldap_client: FlextLdapInfrastructureClient,
        mock_connection: MagicMock,
    ) -> None:
        """Test getting connection information."""
        connection_id = "test_connection"
        ldap_client._connections[connection_id] = mock_connection

        result = ldap_client.get_connection_info(connection_id)

        assert result.success is True
        assert result.data is not None
        assert "server" in result.data
        assert "bound" in result.data
        assert "user" in result.data

    def test_get_connection_info_not_found(
        self,
        ldap_client: FlextLdapInfrastructureClient,
    ) -> None:
        """Test getting info for non-existent connection."""
        result = ldap_client.get_connection_info("non_existent")

        assert result.success is False
        assert result.error is not None
        assert "Connection not found" in result.error

    async def test_create_user_success(
        self,
        ldap_client: FlextLdapInfrastructureClient,
        mock_connection: MagicMock,
    ) -> None:
        """Test successful user creation."""
        # Mock connection entity
        mock_conn_entity = MagicMock()
        mock_conn_entity.server_url = "ldap://localhost:389"
        mock_conn_entity.bind_dn = "cn=admin,dc=example,dc=org"

        # Create connection ID that method will use
        connection_id = "ldap://localhost:389:cn=admin,dc=example,dc=org"
        ldap_client._connections[connection_id] = mock_connection

        mock_connection.add.return_value = True

        # Create request
        request = FlextLdapCreateUserRequest(
            dn="uid=testuser,ou=users,dc=example,dc=org",
            uid="testuser",
            cn="Test User",
            sn="User",
            mail="test@example.org",
        )

        result = await ldap_client.create_user(mock_conn_entity, request)

        assert result.success is True
        assert result.data is not None
        assert result.data.uid == "testuser"
        assert result.data.mail == "test@example.org"
        mock_connection.add.assert_called_once()

    async def test_find_user_by_dn_success(
        self,
        ldap_client: FlextLdapInfrastructureClient,
    ) -> None:
        """Test finding user by DN."""
        # Mock connection entity
        mock_conn_entity = MagicMock()
        mock_conn_entity.server_url = "ldap://localhost:389"
        mock_conn_entity.bind_dn = "cn=admin,dc=example,dc=org"

        # Mock search result data in the correct format
        search_results = [
            {
                "dn": "uid=testuser,ou=users,dc=example,dc=org",
                "attributes": {
                    "uid": ["testuser"],
                    "cn": ["Test User"],
                    "sn": ["User"],
                    "mail": ["test@example.org"],
                    "objectClass": ["inetOrgPerson"],
                },
            },
        ]

        # Mock the search method to return our test data
        with patch.object(
            ldap_client,
            "search",
            return_value=FlextResult.ok(search_results),
        ) as mock_search:
            result = await ldap_client.find_user_by_dn(
                mock_conn_entity,
                "uid=testuser,ou=users,dc=example,dc=org",
            )

            assert result.success is True
            assert result.data is not None
            assert result.data.uid == "testuser"
            assert result.data.cn == "Test User"
            assert result.data.mail == "test@example.org"
            mock_search.assert_called_once()

    async def test_find_user_by_uid_success(
        self,
        ldap_client: FlextLdapInfrastructureClient,
    ) -> None:
        """Test finding user by UID."""
        # Mock connection entity
        mock_conn_entity = MagicMock()
        mock_conn_entity.server_url = "ldap://localhost:389"
        mock_conn_entity.bind_dn = "cn=admin,dc=example,dc=org"

        # Mock search result data in the correct format
        search_results = [
            {
                "dn": "uid=testuser,ou=users,dc=example,dc=org",
                "attributes": {
                    "uid": ["testuser"],
                    "cn": ["Test User"],
                    "sn": ["User"],
                    "mail": ["test@example.org"],
                    "objectClass": ["inetOrgPerson"],
                },
            },
        ]

        # Mock the search method to return our test data
        with patch.object(
            ldap_client,
            "search",
            return_value=FlextResult.ok(search_results),
        ) as mock_search:
            result = await ldap_client.find_user_by_uid(
                mock_conn_entity,
                "testuser",
            )

            assert result.success is True
            assert result.data is not None
            assert result.data.uid == "testuser"
            assert result.data.cn == "Test User"
            assert result.data.mail == "test@example.org"
            mock_search.assert_called_once()

    async def test_create_group_success(
        self,
        ldap_client: FlextLdapInfrastructureClient,
        mock_connection: MagicMock,
    ) -> None:
        """Test successful group creation."""
        # Mock connection entity
        mock_conn_entity = MagicMock()
        mock_conn_entity.server_url = "ldap://localhost:389"
        mock_conn_entity.bind_dn = "cn=admin,dc=example,dc=org"

        # Create connection ID that method will use
        connection_id = "ldap://localhost:389:cn=admin,dc=example,dc=org"
        ldap_client._connections[connection_id] = mock_connection

        mock_connection.add.return_value = True

        result = await ldap_client.create_group(
            mock_conn_entity,
            dn="cn=testgroup,ou=groups,dc=example,dc=org",
            cn="testgroup",
            members=["uid=user1,ou=users,dc=example,dc=org"],
        )

        assert result.success is True
        assert result.data is not None
        assert result.data.cn == "testgroup"
        mock_connection.add.assert_called_once()

    async def test_add_member_to_group_success(
        self,
        ldap_client: FlextLdapInfrastructureClient,
        mock_connection: MagicMock,
    ) -> None:
        """Test successfully adding member to group."""
        # Mock connection entity
        mock_conn_entity = MagicMock()
        mock_conn_entity.server_url = "ldap://localhost:389"
        mock_conn_entity.bind_dn = "cn=admin,dc=example,dc=org"

        # Create connection ID that method will use
        connection_id = "ldap://localhost:389:cn=admin,dc=example,dc=org"
        ldap_client._connections[connection_id] = mock_connection

        mock_connection.modify.return_value = True

        result = await ldap_client.add_member_to_group(
            mock_conn_entity,
            group_dn="cn=testgroup,ou=groups,dc=example,dc=org",
            member_dn="uid=newuser,ou=users,dc=example,dc=org",
        )

        assert result.success is True
        mock_connection.modify.assert_called_once()

    async def test_delete_group_success(
        self,
        ldap_client: FlextLdapInfrastructureClient,
        mock_connection: MagicMock,
    ) -> None:
        """Test successful group deletion."""
        # Mock connection entity
        mock_conn_entity = MagicMock()
        mock_conn_entity.server_url = "ldap://localhost:389"
        mock_conn_entity.bind_dn = "cn=admin,dc=example,dc=org"

        # Create connection ID that method will use
        connection_id = "ldap://localhost:389:cn=admin,dc=example,dc=org"
        ldap_client._connections[connection_id] = mock_connection

        mock_connection.delete.return_value = True

        result = await ldap_client.delete_group(
            mock_conn_entity,
            group_dn="cn=testgroup,ou=groups,dc=example,dc=org",
        )

        assert result.success is True
        mock_connection.delete.assert_called_once()

    async def test_update_user_success(
        self,
        ldap_client: FlextLdapInfrastructureClient,
        mock_connection: MagicMock,
    ) -> None:
        """Test successful user update."""
        # Mock connection entity
        mock_conn_entity = MagicMock()
        mock_conn_entity.server_url = "ldap://localhost:389"
        mock_conn_entity.bind_dn = "cn=admin,dc=example,dc=org"

        # Create connection ID that method will use
        connection_id = "ldap://localhost:389:cn=admin,dc=example,dc=org"
        ldap_client._connections[connection_id] = mock_connection

        # Register UUID->DN mapping
        user_uuid = str(uuid4())
        dn = "uid=testuser,ou=users,dc=example,dc=org"
        ldap_client._register_uuid_dn_mapping(user_uuid, dn)

        mock_connection.modify.return_value = True

        # Test updates
        updates = {
            "mail": "newemail@example.org",
            "telephoneNumber": "+1234567890",
        }

        result = await ldap_client.update_user(
            mock_conn_entity,
            user_uuid,
            updates,
        )

        assert result.success is True
        mock_connection.modify.assert_called_once()

    async def test_update_user_uuid_not_found(
        self,
        ldap_client: FlextLdapInfrastructureClient,
    ) -> None:
        """Test updating user with non-existent UUID."""
        mock_conn_entity = MagicMock()
        mock_conn_entity.server_url = "ldap://localhost:389"
        mock_conn_entity.bind_dn = "cn=admin,dc=example,dc=org"

        user_uuid = str(uuid4())
        updates = {"mail": "test@example.org"}

        result = await ldap_client.update_user(
            mock_conn_entity,
            user_uuid,
            updates,
        )

        assert result.success is False
        assert result.error is not None
        assert "not found" in result.error

    async def test_delete_user_success(
        self,
        ldap_client: FlextLdapInfrastructureClient,
        mock_connection: MagicMock,
    ) -> None:
        """Test successful user deletion by UUID."""
        # Mock connection entity
        mock_conn_entity = MagicMock()
        mock_conn_entity.server_url = "ldap://localhost:389"
        mock_conn_entity.bind_dn = "cn=admin,dc=example,dc=org"

        # Create connection ID that method will use
        connection_id = "ldap://localhost:389:cn=admin,dc=example,dc=org"
        ldap_client._connections[connection_id] = mock_connection

        # Register UUID->DN mapping
        user_uuid = str(uuid4())
        dn = "uid=testuser,ou=users,dc=example,dc=org"
        ldap_client._register_uuid_dn_mapping(user_uuid, dn)

        mock_connection.delete.return_value = True

        result = await ldap_client.delete_user(
            mock_conn_entity,
            user_uuid,
        )

        assert result.success is True
        mock_connection.delete.assert_called_once()

    async def test_lock_user_success(
        self,
        ldap_client: FlextLdapInfrastructureClient,
        mock_connection: MagicMock,
    ) -> None:
        """Test successful user account locking."""
        # Mock connection entity
        mock_conn_entity = MagicMock()
        mock_conn_entity.server_url = "ldap://localhost:389"
        mock_conn_entity.bind_dn = "cn=admin,dc=example,dc=org"

        # Create connection ID that method will use
        connection_id = "ldap://localhost:389:cn=admin,dc=example,dc=org"
        ldap_client._connections[connection_id] = mock_connection

        # Register UUID->DN mapping
        user_uuid = str(uuid4())
        dn = "uid=testuser,ou=users,dc=example,dc=org"
        ldap_client._register_uuid_dn_mapping(user_uuid, dn)

        mock_connection.modify.return_value = True

        result = await ldap_client.lock_user(
            mock_conn_entity,
            user_uuid,
        )

        assert result.success is True
        mock_connection.modify.assert_called_once()

    async def test_unlock_user_success(
        self,
        ldap_client: FlextLdapInfrastructureClient,
        mock_connection: MagicMock,
    ) -> None:
        """Test successful user account unlocking."""
        # Mock connection entity
        mock_conn_entity = MagicMock()
        mock_conn_entity.server_url = "ldap://localhost:389"
        mock_conn_entity.bind_dn = "cn=admin,dc=example,dc=org"

        # Create connection ID that method will use
        connection_id = "ldap://localhost:389:cn=admin,dc=example,dc=org"
        ldap_client._connections[connection_id] = mock_connection

        # Register UUID->DN mapping
        user_uuid = str(uuid4())
        dn = "uid=testuser,ou=users,dc=example,dc=org"
        ldap_client._register_uuid_dn_mapping(user_uuid, dn)

        mock_connection.modify.return_value = True

        result = await ldap_client.unlock_user(
            mock_conn_entity,
            user_uuid,
        )

        assert result.success is True
        mock_connection.modify.assert_called_once()

    async def test_list_users_success(
        self,
        ldap_client: FlextLdapInfrastructureClient,
    ) -> None:
        """Test successful user listing."""
        # Mock connection entity
        mock_conn_entity = MagicMock()
        mock_conn_entity.server_url = "ldap://localhost:389"
        mock_conn_entity.bind_dn = "cn=admin,dc=example,dc=org"

        # Mock search result data
        search_results = [
            {
                "dn": "uid=user1,ou=users,dc=example,dc=org",
                "attributes": {
                    "uid": ["user1"],
                    "cn": ["User One"],
                    "sn": ["One"],
                    "mail": ["user1@example.org"],
                    "objectClass": ["inetOrgPerson"],
                },
            },
            {
                "dn": "uid=user2,ou=users,dc=example,dc=org",
                "attributes": {
                    "uid": ["user2"],
                    "cn": ["User Two"],
                    "sn": ["Two"],
                    "mail": ["user2@example.org"],
                    "objectClass": ["inetOrgPerson"],
                },
            },
        ]

        # Mock the search method
        with patch.object(
            ldap_client,
            "search",
            return_value=FlextResult.ok(search_results),
        ) as mock_search:
            result = await ldap_client.list_users(
                mock_conn_entity,
                base_dn="ou=users,dc=example,dc=org",
                limit=10,
            )

            assert result.success is True
            assert result.data is not None
            assert len(result.data) == 2
            assert result.data[0].uid == "user1"
            assert result.data[1].uid == "user2"
            mock_search.assert_called_once()

    async def test_find_group_by_dn_success(
        self,
        ldap_client: FlextLdapInfrastructureClient,
    ) -> None:
        """Test finding group by DN."""
        # Mock connection entity
        mock_conn_entity = MagicMock()
        mock_conn_entity.server_url = "ldap://localhost:389"
        mock_conn_entity.bind_dn = "cn=admin,dc=example,dc=org"

        # Mock search result data
        search_results = [
            {
                "dn": "cn=testgroup,ou=groups,dc=example,dc=org",
                "attributes": {
                    "cn": ["testgroup"],
                    "member": ["uid=user1,ou=users,dc=example,dc=org"],
                    "objectClass": ["groupOfNames"],
                },
            },
        ]

        # Mock the search method
        with patch.object(
            ldap_client,
            "search",
            return_value=FlextResult.ok(search_results),
        ) as mock_search:
            result = await ldap_client.find_group_by_dn(
                mock_conn_entity,
                "cn=testgroup,ou=groups,dc=example,dc=org",
            )

            assert result.success is True
            assert result.data is not None
            assert result.data.cn == "testgroup"
            mock_search.assert_called_once()
