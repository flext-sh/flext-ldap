"""Tests for FLEXT-LDAP Simple API."""

from unittest.mock import ANY, AsyncMock, Mock
from uuid import uuid4

import pytest

from flext_core.domain.types import ServiceResult
from flext_ldap.domain.entities import LDAPConnection, LDAPUser
from flext_ldap.domain.value_objects import CreateUserRequest
from flext_ldap.simple_api import LDAPAPI, create_ldap_api


@pytest.fixture
def mock_container() -> Mock:
    """Create mock dependency injection container."""
    return Mock()


@pytest.fixture
def mock_user_service() -> AsyncMock:
    """Create mock user service."""
    return AsyncMock()


@pytest.fixture
def mock_connection_service() -> AsyncMock:
    """Create mock connection service."""
    return AsyncMock()


@pytest.fixture
def ldap_api(
    mock_container: Mock,
    mock_user_service: AsyncMock,
    mock_connection_service: AsyncMock,
) -> LDAPAPI:
    """Create LDAP API with mocked services."""
    api = LDAPAPI()
    api._container = mock_container
    api._user_service = mock_user_service
    api._connection_service = mock_connection_service
    return api


class TestLDAPAPI:
    """Test LDAP API functionality."""

    def test_init(self) -> None:
        """Test LDAP API initialization."""
        api = LDAPAPI()
        assert api._container is not None
        assert api._user_service is None
        assert api._connection_service is None

    def test_user_service_lazy_loading(self, mock_container) -> None:
        """Test lazy loading of user service."""
        mock_user_service = Mock()
        mock_container.resolve.return_value = mock_user_service

        api = LDAPAPI()
        api._container = mock_container

        # First access should resolve from container
        service = api.user_service
        assert service == mock_user_service
        mock_container.resolve.assert_called_once()

        # Second access should return cached service
        service2 = api.user_service
        assert service2 == mock_user_service
        # Should not call resolve again
        assert mock_container.resolve.call_count == 1

    def test_connection_service_lazy_loading(self, mock_container) -> None:
        """Test lazy loading of connection service."""
        mock_connection_service = Mock()
        mock_container.resolve.return_value = mock_connection_service

        api = LDAPAPI()
        api._container = mock_container

        # First access should resolve from container
        service = api.connection_service
        assert service == mock_connection_service
        mock_container.resolve.assert_called_once()

        # Second access should return cached service
        service2 = api.connection_service
        assert service2 == mock_connection_service
        # Should not call resolve again
        assert mock_container.resolve.call_count == 1

    @pytest.mark.asyncio
    async def test_create_connection(self, ldap_api, mock_connection_service) -> None:
        """Test creating LDAP connection."""
        connection_id = uuid4()
        connection = LDAPConnection(
            id=connection_id,
            server_url="ldap://test.com",
            bind_dn="cn=admin,dc=test,dc=com",
        )

        mock_connection_service.create_connection.return_value = ServiceResult.ok(
            connection,
        )

        result = await ldap_api.create_connection(
            server_uri="ldap://test.com",
            bind_dn="cn=admin,dc=test,dc=com",
            pool_name="test_pool",
            pool_size=5,
        )

        assert result.success
        assert result.value == connection
        mock_connection_service.create_connection.assert_called_once_with(
            server_uri="ldap://test.com",
            bind_dn="cn=admin,dc=test,dc=com",
        )

    @pytest.mark.asyncio
    async def test_connect(self, ldap_api, mock_connection_service) -> None:
        """Test connecting to LDAP server."""
        connection_id = uuid4()
        connection = LDAPConnection(
            id=connection_id,
            server_url="ldap://test.com",
            bind_dn="cn=admin,dc=test,dc=com",
        )

        mock_connection_service.connect.return_value = ServiceResult.ok(connection)

        result = await ldap_api.connect(connection_id)

        assert result.success
        assert result.value == connection
        mock_connection_service.connect.assert_called_once_with(connection_id)

    @pytest.mark.asyncio
    async def test_disconnect(self, ldap_api, mock_connection_service) -> None:
        """Test disconnecting from LDAP server."""
        connection_id = uuid4()
        connection = LDAPConnection(
            id=connection_id,
            server_url="ldap://test.com",
            bind_dn="cn=admin,dc=test,dc=com",
        )

        mock_connection_service.disconnect.return_value = ServiceResult.ok(connection)

        result = await ldap_api.disconnect(connection_id)

        assert result.success
        assert result.value == connection
        mock_connection_service.disconnect.assert_called_once_with(connection_id)

    @pytest.mark.asyncio
    async def test_bind(self, ldap_api, mock_connection_service) -> None:
        """Test binding to LDAP server."""
        connection_id = uuid4()
        connection = LDAPConnection(
            id=connection_id,
            server_url="ldap://test.com",
            bind_dn="cn=admin,dc=test,dc=com",
        )

        mock_connection_service.bind.return_value = ServiceResult.ok(connection)

        result = await ldap_api.bind(connection_id)

        assert result.success
        assert result.value == connection
        mock_connection_service.bind.assert_called_once_with(connection_id)

    @pytest.mark.asyncio
    async def test_create_user(self, ldap_api, mock_user_service) -> None:
        """Test creating LDAP user."""
        user_id = uuid4()
        user = LDAPUser(
            id=user_id,
            dn="cn=john,ou=people,dc=test,dc=com",
            uid="john",
            cn="John Doe",
            sn="Doe",
        )

        mock_user_service.create_user.return_value = ServiceResult.ok(user)

        result = await ldap_api.create_user(
            dn="cn=john,ou=people,dc=test,dc=com",
            uid="john",
            cn="John Doe",
            sn="Doe",
            mail="john@test.com",
            phone="123-456-7890",
            ou="people",
            department="IT",
            title="Developer",
            object_classes=["inetOrgPerson"],
        )

        assert result.success
        assert result.value == user
        # Verify that create_user was called with a CreateUserRequest object
        mock_user_service.create_user.assert_called_once_with(ANY)
        # Get the actual call arguments
        actual_request = mock_user_service.create_user.call_args[0][0]
        assert isinstance(actual_request, CreateUserRequest)
        assert actual_request.dn == "cn=john,ou=people,dc=test,dc=com"
        assert actual_request.uid == "john"
        assert actual_request.cn == "John Doe"

    @pytest.mark.asyncio
    async def test_get_user(self, ldap_api, mock_user_service) -> None:
        """Test getting user by ID."""
        user_id = uuid4()
        user = LDAPUser(
            id=user_id,
            dn="cn=john,ou=people,dc=test,dc=com",
            uid="john",
            cn="John Doe",
            sn="Doe",
        )

        mock_user_service.get_user.return_value = ServiceResult.ok(user)

        result = await ldap_api.get_user(user_id)

        assert result.success
        assert result.value == user
        mock_user_service.get_user.assert_called_once_with(user_id)

    @pytest.mark.asyncio
    async def test_find_user_by_dn(self, ldap_api, mock_user_service) -> None:
        """Test finding user by DN."""
        user_id = uuid4()
        user = LDAPUser(
            id=user_id,
            dn="cn=john,ou=people,dc=test,dc=com",
            uid="john",
            cn="John Doe",
            sn="Doe",
        )

        mock_user_service.find_user_by_dn.return_value = ServiceResult.ok(user)

        result = await ldap_api.find_user_by_dn("cn=john,ou=people,dc=test,dc=com")

        assert result.success
        assert result.value == user
        mock_user_service.find_user_by_dn.assert_called_once_with(
            "cn=john,ou=people,dc=test,dc=com",
        )

    @pytest.mark.asyncio
    async def test_find_user_by_uid(self, ldap_api, mock_user_service) -> None:
        """Test finding user by UID."""
        user_id = uuid4()
        user = LDAPUser(
            id=user_id,
            dn="cn=john,ou=people,dc=test,dc=com",
            uid="john",
            cn="John Doe",
            sn="Doe",
        )

        mock_user_service.find_user_by_uid.return_value = ServiceResult.ok(user)

        result = await ldap_api.find_user_by_uid("john")

        assert result.success
        assert result.value == user
        mock_user_service.find_user_by_uid.assert_called_once_with("john")

    @pytest.mark.asyncio
    async def test_update_user(self, ldap_api, mock_user_service) -> None:
        """Test updating user."""
        user_id = uuid4()
        user = LDAPUser(
            id=user_id,
            dn="cn=john,ou=people,dc=test,dc=com",
            uid="john",
            cn="John Doe",
            sn="Doe",
        )

        updates = {"mail": "newemail@test.com", "title": "Senior Developer"}
        mock_user_service.update_user.return_value = ServiceResult.ok(user)

        result = await ldap_api.update_user(user_id, updates)

        assert result.success
        assert result.value == user
        mock_user_service.update_user.assert_called_once_with(user_id, updates)

    @pytest.mark.asyncio
    async def test_lock_user(self, ldap_api, mock_user_service) -> None:
        """Test locking user account."""
        user_id = uuid4()
        user = LDAPUser(
            id=user_id,
            dn="cn=john,ou=people,dc=test,dc=com",
            uid="john",
            cn="John Doe",
            sn="Doe",
        )

        mock_user_service.lock_user.return_value = ServiceResult.ok(user)

        result = await ldap_api.lock_user(user_id)

        assert result.success
        assert result.value == user
        mock_user_service.lock_user.assert_called_once_with(user_id)

    @pytest.mark.asyncio
    async def test_unlock_user(self, ldap_api, mock_user_service) -> None:
        """Test unlocking user account."""
        user_id = uuid4()
        user = LDAPUser(
            id=user_id,
            dn="cn=john,ou=people,dc=test,dc=com",
            uid="john",
            cn="John Doe",
            sn="Doe",
        )

        mock_user_service.unlock_user.return_value = ServiceResult.ok(user)

        result = await ldap_api.unlock_user(user_id)

        assert result.success
        assert result.value == user
        mock_user_service.unlock_user.assert_called_once_with(user_id)

    @pytest.mark.asyncio
    async def test_delete_user(self, ldap_api, mock_user_service) -> None:
        """Test deleting user."""
        user_id = uuid4()

        mock_user_service.delete_user.return_value = ServiceResult.ok(True)

        result = await ldap_api.delete_user(user_id)

        assert result.success
        assert result.value is True
        mock_user_service.delete_user.assert_called_once_with(user_id)

    @pytest.mark.asyncio
    async def test_list_users(self, ldap_api, mock_user_service) -> None:
        """Test listing users."""
        users = [
            LDAPUser(
                id=uuid4(),
                dn="cn=john,ou=people,dc=test,dc=com",
                uid="john",
                cn="John Doe",
                sn="Doe",
            ),
            LDAPUser(
                id=uuid4(),
                dn="cn=jane,ou=people,dc=test,dc=com",
                uid="jane",
                cn="Jane Smith",
                sn="Smith",
            ),
        ]

        mock_user_service.list_users.return_value = ServiceResult.ok(users)

        result = await ldap_api.list_users(ou="people", limit=50)

        assert result.success
        assert result.value == users
        mock_user_service.list_users.assert_called_once_with(ou="people", limit=50)


class TestFactoryFunction:
    """Test the factory function."""

    def test_create_ldap_api(self) -> None:
        """Test creating LDAP API through factory function."""
        api = create_ldap_api()
        assert isinstance(api, LDAPAPI)
        assert api._container is not None
        assert api._user_service is None
        assert api._connection_service is None
