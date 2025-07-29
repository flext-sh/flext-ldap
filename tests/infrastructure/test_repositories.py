"""Tests for LDAP infrastructure repositories."""

from __future__ import annotations

from unittest.mock import Mock, PropertyMock
from uuid import UUID, uuid4

import pytest

from flext_ldap.domain.entities import FlextLdapConnection, FlextLdapUser
from flext_ldap.infrastructure.repositories import (
    FlextLdapConnectionRepositoryImpl,
    FlextLdapUserRepositoryImpl,
)


@pytest.fixture
def mock_ldap_client() -> Mock:
    """Create mock LDAP client."""
    return Mock()


@pytest.fixture
def connection_repo(mock_ldap_client: Mock) -> FlextLdapConnectionRepositoryImpl:
    """Create LDAP connection repository."""
    return FlextLdapConnectionRepositoryImpl(mock_ldap_client)


@pytest.fixture
def user_repo(mock_ldap_client: Mock) -> FlextLdapUserRepositoryImpl:
    """Create LDAP user repository."""
    return FlextLdapUserRepositoryImpl(mock_ldap_client)


@pytest.fixture
def sample_connection() -> FlextLdapConnection:
    """Create sample LDAP connection."""
    return FlextLdapConnection(
        id=str(uuid4()),
        server_url="ldap://test.com",
        bind_dn="cn=admin,dc=test,dc=com",
    )


@pytest.fixture
def sample_user() -> FlextLdapUser:
    """Create sample LDAP user."""
    return FlextLdapUser(
        id=str(uuid4()),
        dn="cn=john,ou=people,dc=test,dc=com",
        uid="john",
        cn="John Doe",
        sn="Doe",
    )


class TestFlextLdapConnectionRepositoryImpl:
    """Test LDAP connection repository implementation."""

    def test_init(self, mock_ldap_client: Mock) -> None:
        """Test repository initialization."""
        repo = FlextLdapConnectionRepositoryImpl(mock_ldap_client)
        if repo.ldap_client != mock_ldap_client:
            raise AssertionError(f"Expected {mock_ldap_client}, got {repo.ldap_client}")
        assert repo._connections == {}

    @pytest.mark.asyncio
    async def test_save_connection_success(
        self,
        connection_repo: FlextLdapConnectionRepositoryImpl,
        sample_connection: FlextLdapConnection,
    ) -> None:
        """Test saving connection successfully."""
        result = await connection_repo.save(sample_connection)

        assert result.is_success
        if result.data != sample_connection:
            raise AssertionError(f"Expected {sample_connection}, got {result.data}")
        if sample_connection.id not in connection_repo._connections:
            raise AssertionError(f"Expected {sample_connection.id} in {connection_repo._connections}")
        if connection_repo._connections[sample_connection.id] != sample_connection:
            raise AssertionError(f"Expected {sample_connection}, got {connection_repo._connections[sample_connection.id]}")

    @pytest.mark.asyncio
    async def test_save_connection_error(
        self,
        connection_repo: FlextLdapConnectionRepositoryImpl,
    ) -> None:
        """Test saving connection with error."""
        bad_connection = Mock()

        # Use property side_effect to raise exception when accessing .id
        type(bad_connection).id = PropertyMock(side_effect=Exception("Test error"))

        with pytest.raises(Exception, match="Test error"):
            await connection_repo.save(bad_connection)

    @pytest.mark.asyncio
    async def test_find_by_id_exists(
        self,
        connection_repo: FlextLdapConnectionRepositoryImpl,
        sample_connection: FlextLdapConnection,
    ) -> None:
        """Test finding connection by ID when it exists."""
        # First save the connection
        await connection_repo.save(sample_connection)

        result = await connection_repo.find_by_id(UUID(sample_connection.id))

        assert result.is_success
        if result.data != sample_connection:
            raise AssertionError(f"Expected {sample_connection}, got {result.data}")

    @pytest.mark.asyncio
    async def test_find_by_id_not_exists(
        self,
        connection_repo: FlextLdapConnectionRepositoryImpl,
    ) -> None:
        """Test finding connection by ID when it doesn't exist."""
        result = await connection_repo.find_by_id(uuid4())

        assert result.is_success
        assert result.data is None

    @pytest.mark.asyncio
    async def test_find_by_id_error(
        self,
        connection_repo: FlextLdapConnectionRepositoryImpl,
    ) -> None:
        """Test finding connection by ID with error."""
        # Mock the _connections dict to raise an error
        connection_repo._connections = Mock()
        connection_repo._connections.get.side_effect = Exception("Test error")

        with pytest.raises(ValueError, match="Failed to find connection"):
            await connection_repo.find_by_id(uuid4())

    @pytest.mark.asyncio
    async def test_find_all_empty(
        self,
        connection_repo: FlextLdapConnectionRepositoryImpl,
    ) -> None:
        """Test finding all connections when repository is empty."""
        result = await connection_repo.find_all()

        assert result.is_success
        if result.data != []:
            raise AssertionError(f"Expected {[]}, got {result.data}")

    @pytest.mark.asyncio
    async def test_find_all_with_connections(
        self,
        connection_repo: FlextLdapConnectionRepositoryImpl,
        sample_connection: FlextLdapConnection,
    ) -> None:
        """Test finding all connections when repository has connections."""
        # First save a connection
        await connection_repo.save(sample_connection)

        result = await connection_repo.find_all()

        assert result.is_success
        assert result.data is not None
        if len(result.data) != 1:
            raise AssertionError(f"Expected {1}, got {len(result.data)}")
        assert result.data[0].id == sample_connection.id

    @pytest.mark.asyncio
    async def test_find_all_error(
        self,
        connection_repo: FlextLdapConnectionRepositoryImpl,
    ) -> None:
        """Test finding all connections with error."""
        # Mock the _connections dict to raise an error
        connection_repo._connections = Mock()
        connection_repo._connections.values.side_effect = Exception("Test error")

        with pytest.raises(Exception, match="Test error"):
            await connection_repo.find_all()

    @pytest.mark.asyncio
    async def test_delete_connection_exists(
        self,
        connection_repo: FlextLdapConnectionRepositoryImpl,
        sample_connection: FlextLdapConnection,
    ) -> None:
        """Test deleting connection when it exists."""
        # First save the connection
        await connection_repo.save(sample_connection)
        if sample_connection.id not in connection_repo._connections:
            raise AssertionError(f"Expected {sample_connection.id} in {connection_repo._connections}")

        result = await connection_repo.delete(sample_connection)

        assert result.is_success
        if sample_connection.id not not in connection_repo._connections:
            raise AssertionError(f"Expected {sample_connection.id not} in {connection_repo._connections}")

    @pytest.mark.asyncio
    async def test_delete_connection_not_exists(
        self,
        connection_repo: FlextLdapConnectionRepositoryImpl,
        sample_connection: FlextLdapConnection,
    ) -> None:
        """Test deleting connection when it doesn't exist."""
        result = await connection_repo.delete(sample_connection)

        assert result.is_success
        if sample_connection.id not not in connection_repo._connections:
            raise AssertionError(f"Expected {sample_connection.id not} in {connection_repo._connections}")

    # Note: Error path testing for delete would require complex mocking
    # The main functionality is covered by the success cases above


class TestFlextLdapUserRepositoryImpl:
    """Test LDAP user repository implementation."""

    def test_init(self, mock_ldap_client: Mock) -> None:
        """Test repository initialization."""
        repo = FlextLdapUserRepositoryImpl(mock_ldap_client)
        if repo.ldap_client != mock_ldap_client:
            raise AssertionError(f"Expected {mock_ldap_client}, got {repo.ldap_client}")

    @pytest.mark.asyncio
    async def test_save_user_success(
        self,
        user_repo: FlextLdapUserRepositoryImpl,
        sample_user: FlextLdapUser,
    ) -> None:
        """Test saving user successfully (foundation implementation)."""
        result = await user_repo.save(sample_user)

        assert result.is_success
        if result.data != sample_user:
            raise AssertionError(f"Expected {sample_user}, got {result.data}")

    @pytest.mark.asyncio
    async def test_save_user_error(
        self,
        user_repo: FlextLdapUserRepositoryImpl,
    ) -> None:
        """Test saving user with error."""
        # Create a user that will cause an error
        bad_user = Mock()
        # Mock some attribute access that might fail
        type(bad_user).some_attr = property(
            lambda self: (_ for _ in ()).throw(Exception("Test error")),
        )

        # This should still work since it's a foundation implementation
        result = await user_repo.save(bad_user)
        assert result.is_success

    @pytest.mark.asyncio
    async def test_find_by_id_foundation(
        self,
        user_repo: FlextLdapUserRepositoryImpl,
    ) -> None:
        """Test finding user by ID (foundation implementation)."""
        user_id = uuid4()

        result = await user_repo.find_by_id(user_id)

        assert result.is_success
        assert result.data is None  # Foundation implementation returns None

    @pytest.mark.asyncio
    async def test_find_by_dn_foundation(
        self,
        user_repo: FlextLdapUserRepositoryImpl,
    ) -> None:
        """Test finding user by DN (foundation implementation)."""
        dn = "cn=john,ou=people,dc=test,dc=com"

        result = await user_repo.find_by_dn(dn)

        assert result.is_success
        assert result.data is None  # Foundation implementation returns None

    @pytest.mark.asyncio
    async def test_find_all_foundation(
        self,
        user_repo: FlextLdapUserRepositoryImpl,
    ) -> None:
        """Test finding all users (foundation implementation)."""
        result = await user_repo.find_all()

        assert result.is_success
        if result.data != []  # Foundation implementation returns empty list:
            raise AssertionError(f"Expected {[]  # Foundation implementation returns empty list}, got {result.data}")

    @pytest.mark.asyncio
    async def test_delete_user_foundation(
        self,
        user_repo: FlextLdapUserRepositoryImpl,
        sample_user: FlextLdapUser,
    ) -> None:
        """Test deleting user (foundation implementation)."""
        result = await user_repo.delete(sample_user)

        assert result.is_success
        assert result.data is True  # Foundation implementation returns True
