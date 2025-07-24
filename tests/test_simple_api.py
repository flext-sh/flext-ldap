"""Tests for FLEXT-LDAP Simple API."""

from __future__ import annotations

from unittest.mock import AsyncMock, patch
from uuid import uuid4

import pytest

# 🚨 ARCHITECTURAL COMPLIANCE: Using flext_core root imports
from flext_core import FlextResult

from flext_ldap.domain.entities import FlextLdapConnection, FlextLdapUser
from flext_ldap.simple_api import FlextLdapAPI, create_ldap_api

# Backward compatibility aliases
LDAPAPI = FlextLdapAPI
flext_ldap_create_api = create_ldap_api


@pytest.fixture
def mock_ldap_client() -> AsyncMock:
    """Create mock LDAP infrastructure client."""
    client = AsyncMock()
    client.connect = AsyncMock(return_value=FlextResult.ok("conn_id_123"))
    client.disconnect = AsyncMock(return_value=FlextResult.ok(True))
    return client


@pytest.fixture
def ldap_api(mock_ldap_client: AsyncMock) -> LDAPAPI:
    """Create LDAP API with mocked LDAP client."""
    with (
        patch(
            "flext_ldap.infrastructure.ldap_client.FlextLdapInfrastructureClient",
            return_value=mock_ldap_client,
        ),
        patch("flext_ldap.client.FlextLdapClient") as mock_client_class,
    ):
        mock_client_instance = AsyncMock()
        mock_client_instance.is_connected.return_value = True
        mock_client_class.return_value = mock_client_instance

        api = LDAPAPI()
        api._ldap_client = mock_ldap_client
        return api


@pytest.fixture
def sample_connection() -> FlextLdapConnection:
    """Create sample LDAP connection."""
    return FlextLdapConnection(
        id=str(uuid4()),
        server_url="ldap://test.example.com",
        bind_dn="cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com",
    )


class TestLDAPAPI:
    """Test LDAP API functionality."""

    def test_init(self) -> None:
        """Test LDAP API initialization."""
        with (
            patch(
                "flext_ldap.infrastructure.ldap_client.FlextLdapInfrastructureClient",
            ),
            patch("flext_ldap.client.FlextLdapClient"),
        ):
            api = LDAPAPI()
            assert api._ldap_client is not None
            assert api._connections == {}
            assert api._active_connection is None
            assert api._active_connection_id is None

    @pytest.mark.asyncio
    async def test_create_connection(
        self,
        ldap_api: LDAPAPI,
        mock_ldap_client: AsyncMock,
        sample_connection: FlextLdapConnection,
    ) -> None:
        """Test creating LDAP connection."""
        mock_ldap_client.connect.return_value = FlextResult.ok("conn_id_123")

        result = await ldap_api.create_connection(
            server_uri="ldap://test.example.com",
            bind_dn="cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com",
            password="secret",
            use_ssl=False,
        )

        assert result.success
        assert result.data is not None
        assert isinstance(result.data, FlextLdapConnection)
        assert result.data.server_url == "ldap://test.example.com"
        assert result.data.bind_dn == "cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com"

        # Verify connection provider was used
        assert ldap_api._active_connection is not None
        assert ldap_api._active_connection_id is not None

    @pytest.mark.asyncio
    async def test_connect_existing_connection(
        self,
        ldap_api: LDAPAPI,
        sample_connection: FlextLdapConnection,
    ) -> None:
        """Test connecting to existing LDAP server."""
        # Add connection to API's connection store
        server_uri = "ldap://test.example.com"
        ldap_api._connections[server_uri] = sample_connection

        result = await ldap_api.connect(server_uri)

        assert result.success
        assert result.data == sample_connection
        assert ldap_api._active_connection == sample_connection

    @pytest.mark.asyncio
    async def test_connect_nonexistent_connection(
        self,
        ldap_api: LDAPAPI,
    ) -> None:
        """Test connecting to nonexistent server."""
        result = await ldap_api.connect("ldap://nonexistent.example.com")

        assert not result.success
        assert result.error is not None
        assert "Connection not found" in result.error

    @pytest.mark.asyncio
    async def test_disconnect(
        self,
        ldap_api: LDAPAPI,
        mock_ldap_client: AsyncMock,
        sample_connection: FlextLdapConnection,
    ) -> None:
        """Test disconnecting from LDAP server."""
        # Set up active connection
        ldap_api._active_connection = sample_connection
        ldap_api._active_connection_id = "conn_id_123"
        mock_ldap_client.disconnect.return_value = FlextResult.ok(True)

        result = await ldap_api.disconnect()

        assert result.success
        assert result.data is True
        assert ldap_api._active_connection is None

    @pytest.mark.asyncio
    async def test_disconnect_no_active_connection(
        self,
        ldap_api: LDAPAPI,
    ) -> None:
        """Test disconnecting when no active connection."""
        result = await ldap_api.disconnect()

        assert result.success
        assert result.data is True

    def test_get_active_connection(
        self,
        ldap_api: LDAPAPI,
        sample_connection: FlextLdapConnection,
    ) -> None:
        """Test getting active connection."""
        # Initially no active connection
        result = ldap_api.get_active_connection()
        assert result.success
        assert result.data is None

        # Set active connection
        ldap_api._active_connection = sample_connection
        result = ldap_api.get_active_connection()
        assert result.success
        assert result.data == sample_connection

    @pytest.mark.asyncio
    async def test_create_user(
        self,
        ldap_api: LDAPAPI,
        mock_ldap_client: AsyncMock,
        sample_connection: FlextLdapConnection,
    ) -> None:
        """Test creating LDAP user."""
        # Set up active connection
        ldap_api._active_connection = sample_connection

        user = FlextLdapUser(
            id=str(uuid4()),
            dn="cn=john,ou=people,dc=test,dc=com",
            uid="john",
            cn="John Doe",
            sn="Doe",
        )
        mock_ldap_client.create_user.return_value = FlextResult.ok(user)

        result = await ldap_api.create_user(
            dn="cn=john,ou=people,dc=test,dc=com",
            uid="john",
            cn="John Doe",
            sn="Doe",
        )

        assert result.success
        assert result.data == user
        mock_ldap_client.create_user.assert_called_once()

    @pytest.mark.asyncio
    async def test_create_user_no_connection(
        self,
        ldap_api: LDAPAPI,
    ) -> None:
        """Test creating user without active connection."""
        result = await ldap_api.create_user(
            dn="cn=john,ou=people,dc=test,dc=com",
            uid="john",
            cn="John Doe",
            sn="Doe",
        )

        assert not result.success
        assert result.error is not None
        assert "No active LDAP connection" in result.error

    @pytest.mark.asyncio
    async def test_find_user_by_dn(
        self,
        ldap_api: LDAPAPI,
        mock_ldap_client: AsyncMock,
        sample_connection: FlextLdapConnection,
    ) -> None:
        """Test finding LDAP user by DN."""
        # Set up active connection
        ldap_api._active_connection = sample_connection

        user = FlextLdapUser(
            id=str(uuid4()),
            dn="cn=john,ou=people,dc=test,dc=com",
            uid="john",
            cn="John Doe",
            sn="Doe",
        )
        mock_ldap_client.find_user_by_dn.return_value = FlextResult.ok(user)

        result = await ldap_api.find_user_by_dn("cn=john,ou=people,dc=test,dc=com")

        assert result.success
        assert result.data == user
        mock_ldap_client.find_user_by_dn.assert_called_once_with(
            sample_connection,
            "cn=john,ou=people,dc=test,dc=com",
        )

    @pytest.mark.asyncio
    async def test_find_user_by_uid(
        self,
        ldap_api: LDAPAPI,
        mock_ldap_client: AsyncMock,
        sample_connection: FlextLdapConnection,
    ) -> None:
        """Test finding LDAP user by UID."""
        # Set up active connection
        ldap_api._active_connection = sample_connection

        user = FlextLdapUser(
            id=str(uuid4()),
            dn="cn=john,ou=people,dc=test,dc=com",
            uid="john",
            cn="John Doe",
            sn="Doe",
        )
        mock_ldap_client.find_user_by_uid.return_value = FlextResult.ok(user)

        result = await ldap_api.find_user_by_uid("john")

        assert result.success
        assert result.data == user
        mock_ldap_client.find_user_by_uid.assert_called_once_with(
            sample_connection,
            "john",
        )

    @pytest.mark.asyncio
    async def test_list_users(
        self,
        ldap_api: LDAPAPI,
        mock_ldap_client: AsyncMock,
        sample_connection: FlextLdapConnection,
    ) -> None:
        """Test listing users."""
        # Set up active connection
        ldap_api._active_connection = sample_connection

        users = [
            FlextLdapUser(
                id=str(uuid4()),
                dn="cn=john,ou=people,dc=test,dc=com",
                uid="john",
                cn="John Doe",
                sn="Doe",
            ),
            FlextLdapUser(
                id=str(uuid4()),
                dn="cn=jane,ou=people,dc=test,dc=com",
                uid="jane",
                cn="Jane Smith",
                sn="Smith",
            ),
        ]
        mock_ldap_client.list_users.return_value = FlextResult.ok(users)

        result = await ldap_api.list_users(
            base_dn="ou=people,dc=test,dc=com",
            limit=50,
        )

        assert result.success
        assert result.data == users
        mock_ldap_client.list_users.assert_called_once_with(
            sample_connection,
            "ou=people,dc=test,dc=com",
            50,
        )

    @pytest.mark.asyncio
    async def test_delete_user(
        self,
        ldap_api: LDAPAPI,
        mock_ldap_client: AsyncMock,
        sample_connection: FlextLdapConnection,
    ) -> None:
        """Test deleting LDAP user."""
        # Set up active connection
        ldap_api._active_connection = sample_connection

        mock_ldap_client.delete_user.return_value = FlextResult.ok(True)

        result = await ldap_api.delete_user("cn=john,ou=people,dc=test,dc=com")

        assert result.success
        assert result.data is True
        mock_ldap_client.delete_user.assert_called_once_with(
            sample_connection,
            "cn=john,ou=people,dc=test,dc=com",
        )


class TestFactoryFunction:
    """Test the factory function."""

    def test_create_ldap_api(self) -> None:
        """Test creating LDAP API through factory function."""
        with (
            patch(
                "flext_ldap.infrastructure.ldap_client.FlextLdapInfrastructureClient",
            ),
            patch("flext_ldap.client.FlextLdapClient"),
        ):
            api = create_ldap_api()
            assert isinstance(api, LDAPAPI)
            assert api._ldap_client is not None
            assert api._connections == {}
            assert api._active_connection is None
            assert api._active_connection_id is None
