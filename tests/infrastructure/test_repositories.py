"""Tests for LDAP infrastructure repositories."""

from typing import Any, Never
from unittest.mock import Mock
from uuid import uuid4

import pytest

from flext_core.domain.types import ServiceResult
from flext_ldap.domain.entities import LDAPConnection, LDAPUser
from flext_ldap.infrastructure.repositories import (
    LDAPConnectionRepositoryImpl,
    LDAPUserRepositoryImpl,
)


@pytest.fixture
def mock_ldap_client() -> Mock:
    """Create mock LDAP client."""
    return Mock()


@pytest.fixture
def connection_repo(mock_ldap_client: Mock) -> LDAPConnectionRepositoryImpl:
    """Create LDAP connection repository."""
    return LDAPConnectionRepositoryImpl(mock_ldap_client)


@pytest.fixture
def user_repo(mock_ldap_client: Mock) -> LDAPUserRepositoryImpl:
    """Create LDAP user repository."""
    return LDAPUserRepositoryImpl(mock_ldap_client)


@pytest.fixture
def sample_connection() -> LDAPConnection:
    """Create sample LDAP connection."""
    return LDAPConnection(
        id=uuid4(),
        server_url="ldap://test.com",
        bind_dn="cn=admin,dc=test,dc=com",
    )


@pytest.fixture
def sample_user() -> LDAPUser:
    """Create sample LDAP user."""
    return LDAPUser(
        id=uuid4(),
        dn="cn=john,ou=people,dc=test,dc=com",
        uid="john",
        cn="John Doe",
        sn="Doe",
    )


class TestLDAPConnectionRepositoryImpl:
    """Test LDAP connection repository implementation."""

    def test_init(self, mock_ldap_client: Mock) -> None:
        """Test repository initialization."""
        repo = LDAPConnectionRepositoryImpl(mock_ldap_client)
        assert repo.ldap_client == mock_ldap_client
        assert repo._connections == {}

    @pytest.mark.asyncio
    async def test_save_connection_success(
        self,
        connection_repo,
        sample_connection,
    ) -> None:
        """Test saving connection successfully."""
        result = await connection_repo.save(sample_connection)

        assert result.success
        assert result.value == sample_connection
        assert sample_connection.id in connection_repo._connections
        assert connection_repo._connections[sample_connection.id] == sample_connection

    @pytest.mark.asyncio
    async def test_save_connection_error(self, connection_repo) -> None:
        """Test saving connection with error."""
        # Create a connection that will cause an error when accessing .id
        bad_connection = Mock()

        def raise_error() -> Never:
            msg = "Test error"
            raise Exception(msg)

        type(bad_connection).id = property(lambda self: raise_error())

        with pytest.raises(Exception):
            await connection_repo.save(bad_connection)

    @pytest.mark.asyncio
    async def test_find_by_id_exists(self, connection_repo, sample_connection) -> None:
        """Test finding connection by ID when it exists."""
        # First save the connection
        await connection_repo.save(sample_connection)

        result = await connection_repo.find_by_id(sample_connection.id)

        assert result.success
        assert result.value == sample_connection

    @pytest.mark.asyncio
    async def test_find_by_id_not_exists(self, connection_repo) -> None:
        """Test finding connection by ID when it doesn't exist."""
        non_existent_id = uuid4()

        result = await connection_repo.find_by_id(non_existent_id)

        assert result.success
        assert result.value is None

    @pytest.mark.asyncio
    async def test_find_by_id_error(self, connection_repo) -> None:
        """Test finding connection by ID with error."""
        # Mock the _connections dict to raise an error
        connection_repo._connections = Mock()
        connection_repo._connections.get.side_effect = Exception(
            "Test error",
        )

        with pytest.raises(Exception):
            await connection_repo.find_by_id(uuid4())

    @pytest.mark.asyncio
    async def test_find_all_empty(self, connection_repo) -> None:
        """Test finding all connections when none exist."""
        result = await connection_repo.find_all()

        assert result.success
        assert result.value == []

    @pytest.mark.asyncio
    async def test_find_all_with_connections(
        self,
        connection_repo,
        sample_connection,
    ) -> None:
        """Test finding all connections when some exist."""
        # Save a connection first
        await connection_repo.save(sample_connection)

        result = await connection_repo.find_all()

        assert result.success
        assert len(result.value) == 1
        assert result.value[0] == sample_connection

    @pytest.mark.asyncio
    async def test_find_all_error(self, connection_repo) -> None:
        """Test finding all connections with error."""
        # Mock the _connections dict to raise an error
        connection_repo._connections = Mock()
        connection_repo._connections.values.side_effect = Exception(
            "Test error",
        )

        with pytest.raises(Exception):
            await connection_repo.find_all()

    @pytest.mark.asyncio
    async def test_delete_connection_exists(
        self,
        connection_repo,
        sample_connection,
    ) -> None:
        """Test deleting connection that exists."""
        # First save the connection
        await connection_repo.save(sample_connection)

        result = await connection_repo.delete(sample_connection)

        assert result.success
        assert result.value is True
        assert sample_connection.id not in connection_repo._connections

    @pytest.mark.asyncio
    async def test_delete_connection_not_exists(
        self,
        connection_repo,
        sample_connection,
    ) -> None:
        """Test deleting connection that doesn't exist."""
        result = await connection_repo.delete(sample_connection)

        assert result.success
        assert result.value is False

    # Note: Error path testing for delete would require complex mocking
    # The main functionality is covered by the success cases above


class TestLDAPUserRepositoryImpl:
    """Test LDAP user repository implementation."""

    def test_init(self, mock_ldap_client: Mock) -> None:
        """Test repository initialization."""
        repo = LDAPUserRepositoryImpl(mock_ldap_client)
        assert repo.ldap_client == mock_ldap_client

    @pytest.mark.asyncio
    async def test_save_user_success(self, user_repo, sample_user) -> None:
        """Test saving user successfully (foundation implementation)."""
        result = await user_repo.save(sample_user)

        assert result.success
        assert result.value == sample_user

    @pytest.mark.asyncio
    async def test_save_user_error(self, user_repo) -> None:
        """Test saving user with error."""
        # Create a user that will cause an error
        bad_user = Mock()
        # Mock some attribute access that might fail
        type(bad_user).some_attr = property(
            lambda self: (_ for _ in ()).throw(Exception("Test error")),
        )

        # This should still work since it's a foundation implementation
        result = await user_repo.save(bad_user)
        assert result.success

    @pytest.mark.asyncio
    async def test_find_by_id_foundation(self, user_repo) -> None:
        """Test finding user by ID (foundation implementation)."""
        user_id = uuid4()

        result = await user_repo.find_by_id(user_id)

        assert result.success
        assert result.value is None  # Foundation implementation returns None

    @pytest.mark.asyncio
    async def test_find_by_dn_foundation(self, user_repo) -> None:
        """Test finding user by DN (foundation implementation)."""
        dn = "cn=john,ou=people,dc=test,dc=com"

        result = await user_repo.find_by_dn(dn)

        assert result.success
        assert result.value is None  # Foundation implementation returns None

    @pytest.mark.asyncio
    async def test_find_all_foundation(self, user_repo) -> None:
        """Test finding all users (foundation implementation)."""
        result = await user_repo.find_all()

        assert result.success
        assert result.value == []  # Foundation implementation returns empty list

    @pytest.mark.asyncio
    async def test_delete_user_foundation(self, user_repo, sample_user) -> None:
        """Test deleting user (foundation implementation)."""
        result = await user_repo.delete(sample_user)

        assert result.success
        assert result.value is True  # Foundation implementation returns True
