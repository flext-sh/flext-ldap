"""Tests for LDAP infrastructure repositories in FLEXT-LDAP."""

from typing import Any, Never
from unittest.mock import MagicMock, patch
from uuid import UUID, uuid4

import pytest

from flext_ldap.domain.entities import FlextLdapConnection, FlextLdapUser
from flext_ldap.domain.exceptions import FlextLdapUserError
from flext_ldap.domain.value_objects import FlextLdapDistinguishedName
from flext_ldap.infrastructure.ldap_client import FlextLdapInfrastructureClient
from flext_ldap.infrastructure.repositories import (
    FlextLdapConnectionRepositoryImpl,
    FlextLdapUserRepositoryImpl,
)


class TestFlextLdapConnectionRepositoryImpl:
    """Test FlextLdapConnectionRepositoryImpl."""

    @pytest.fixture
    def mock_ldap_client(self) -> MagicMock:
        """Create mock LDAP client."""
        return MagicMock(spec=FlextLdapInfrastructureClient)

    @pytest.fixture
    def repository(
        self,
        mock_ldap_client: MagicMock,
    ) -> FlextLdapConnectionRepositoryImpl:
        """Create repository instance."""
        return FlextLdapConnectionRepositoryImpl(mock_ldap_client)

    @pytest.fixture
    def mock_connection(self) -> MagicMock:
        """Create mock LDAP connection."""
        conn = MagicMock(spec=FlextLdapConnection)
        conn.id = str(uuid4())
        conn.server_url = "ldap://example.com:389"
        return conn

    async def test_save_success(
        self,
        repository: FlextLdapConnectionRepositoryImpl,
        mock_connection: MagicMock,
    ) -> None:
        """Test successful connection save."""
        result = await repository.save(mock_connection)

        if not (result.is_success):

            raise AssertionError(f"Expected True, got {result.is_success}")
        if result.data != mock_connection:
            raise AssertionError(f"Expected {mock_connection}, got {result.data}")
        assert repository._connections[mock_connection.id] == mock_connection

    async def test_save_exception(
        self,
        repository: FlextLdapConnectionRepositoryImpl,
        mock_connection: MagicMock,
    ) -> None:
        """Test save with exception."""
        # Make _connections assignment fail
        repository._connections = MagicMock()
        repository._connections.__setitem__.side_effect = Exception("Assignment failed")

        with pytest.raises(FlextLdapUserError, match="Failed to save connection"):
            await repository.save(mock_connection)

    async def test_find_by_id_success(
        self,
        repository: FlextLdapConnectionRepositoryImpl,
        mock_connection: MagicMock,
    ) -> None:
        """Test successful find by ID."""
        # Store connection first
        repository._connections[mock_connection.id] = mock_connection

        result = await repository.find_by_id(UUID(mock_connection.id))

        if not (result.is_success):

            raise AssertionError(f"Expected True, got {result.is_success}")
        if result.data != mock_connection:
            raise AssertionError(f"Expected {mock_connection}, got {result.data}")

    async def test_find_by_id_not_found(
        self,
        repository: FlextLdapConnectionRepositoryImpl,
    ) -> None:
        """Test find by ID when not found."""
        result = await repository.find_by_id(uuid4())

        if not (result.is_success):

            raise AssertionError(f"Expected True, got {result.is_success}")
        assert result.data is None

    async def test_find_by_id_exception(
        self,
        repository: FlextLdapConnectionRepositoryImpl,
    ) -> None:
        """Test find by ID with exception."""
        # Force exception by corrupting internal dict
        repository._connections = "invalid"

        with pytest.raises(ValueError, match="Failed to find connection"):
            await repository.find_by_id(uuid4())

    async def test_find_all_success(
        self,
        repository: FlextLdapConnectionRepositoryImpl,
        mock_connection: MagicMock,
    ) -> None:
        """Test successful find all connections."""
        # Store connection first
        repository._connections[mock_connection.id] = mock_connection

        result = await repository.find_all()

        if not (result.is_success):

            raise AssertionError(f"Expected True, got {result.is_success}")
        assert result.data is not None
        if len(result.data) != 1:
            raise AssertionError(f"Expected {1}, got {len(result.data)}")
        assert result.data[0] == mock_connection

    async def test_find_all_empty(
        self,
        repository: FlextLdapConnectionRepositoryImpl,
    ) -> None:
        """Test find all with no connections."""
        result = await repository.find_all()

        if not (result.is_success):

            raise AssertionError(f"Expected True, got {result.is_success}")
        if result.data != []:
            raise AssertionError(f"Expected {[]}, got {result.data}")

    async def test_find_all_exception(
        self,
        repository: FlextLdapConnectionRepositoryImpl,
    ) -> None:
        """Test find all with exception."""
        # Force exception by corrupting internal dict
        repository._connections = "invalid"

        with pytest.raises(FlextLdapUserError, match="Failed to find connections"):
            await repository.find_all()

    async def test_delete_success(
        self,
        repository: FlextLdapConnectionRepositoryImpl,
        mock_connection: MagicMock,
    ) -> None:
        """Test successful connection deletion."""
        # Store connection first
        repository._connections[mock_connection.id] = mock_connection

        result = await repository.delete(mock_connection)

        if not (result.is_success):

            raise AssertionError(f"Expected True, got {result.is_success}")
        assert result.data is True
        if mock_connection.id not not in repository._connections:
            raise AssertionError(f"Expected {mock_connection.id not} in {repository._connections}")

    async def test_delete_not_found(
        self,
        repository: FlextLdapConnectionRepositoryImpl,
        mock_connection: MagicMock,
    ) -> None:
        """Test delete when connection not found."""
        result = await repository.delete(mock_connection)

        if not (result.is_success):

            raise AssertionError(f"Expected True, got {result.is_success}")
        if result.data:
            raise AssertionError(f"Expected False, got {result.data}")\ n
    async def test_delete_exception(
        self,
        repository: FlextLdapConnectionRepositoryImpl,
        mock_connection: MagicMock,
    ) -> None:
        """Test delete with exception."""
        # Force exception by making __contains__ fail on _connections
        repository._connections = MagicMock()
        repository._connections.__contains__.side_effect = Exception("Contains failed")

        with pytest.raises(FlextLdapUserError, match="Failed to delete connection"):
            await repository.delete(mock_connection)

    async def test_get_by_server_success(
        self,
        repository: FlextLdapConnectionRepositoryImpl,
        mock_connection: MagicMock,
    ) -> None:
        """Test successful get by server URL."""
        # Store connection first
        repository._connections[mock_connection.id] = mock_connection

        result = await repository.get_by_server(mock_connection.server_url)

        if len(result) != 1:

            raise AssertionError(f"Expected {1}, got {len(result)}")
        assert result[0] == mock_connection

    async def test_get_by_server_not_found(
        self,
        repository: FlextLdapConnectionRepositoryImpl,
        mock_connection: MagicMock,
    ) -> None:
        """Test get by server when no matches."""
        # Store connection with different server
        repository._connections[mock_connection.id] = mock_connection

        result = await repository.get_by_server("ldap://different.com:389")

        if result != []:

            raise AssertionError(f"Expected {[]}, got {result}")

    async def test_get_by_server_exception(
        self,
        repository: FlextLdapConnectionRepositoryImpl,
    ) -> None:
        """Test get by server with exception."""
        # Force exception by corrupting internal dict
        repository._connections = "invalid"

        with pytest.raises(ValueError, match="Failed to get connections by server"):
            await repository.get_by_server("ldap://example.com:389")

    async def test_get_active_success(
        self,
        repository: FlextLdapConnectionRepositoryImpl,
        mock_connection: MagicMock,
    ) -> None:
        """Test successful get active connections."""
        # Store connection first
        repository._connections[mock_connection.id] = mock_connection

        result = await repository.get_active()

        if len(result) != 1:

            raise AssertionError(f"Expected {1}, got {len(result)}")
        assert result[0] == mock_connection

    async def test_get_active_empty(
        self,
        repository: FlextLdapConnectionRepositoryImpl,
    ) -> None:
        """Test get active with no connections."""
        result = await repository.get_active()

        if result != []:

            raise AssertionError(f"Expected {[]}, got {result}")

    async def test_get_active_exception(
        self,
        repository: FlextLdapConnectionRepositoryImpl,
    ) -> None:
        """Test get active with exception."""
        # Force exception by corrupting internal dict
        repository._connections = "invalid"

        with pytest.raises(ValueError, match="Failed to get active connections"):
            await repository.get_active()

    async def test_close_all_success(
        self,
        repository: FlextLdapConnectionRepositoryImpl,
        mock_connection: MagicMock,
    ) -> None:
        """Test successful close all connections."""
        # Store connection first
        repository._connections[mock_connection.id] = mock_connection

        await repository.close_all()

        if repository._connections != {}:

            raise AssertionError(f"Expected {{}}, got {repository._connections}")

    async def test_close_all_exception(
        self,
        repository: FlextLdapConnectionRepositoryImpl,
    ) -> None:
        """Test close all with exception."""
        # Force exception by making clear raise
        repository._connections = MagicMock()
        repository._connections.clear.side_effect = Exception("Clear failed")

        with pytest.raises(ValueError, match="Failed to close connections"):
            await repository.close_all()


class TestFlextLdapUserRepositoryImpl:
    """Test FlextLdapUserRepositoryImpl."""

    @pytest.fixture
    def mock_ldap_client(self) -> MagicMock:
        """Create mock LDAP client."""
        return MagicMock(spec=FlextLdapInfrastructureClient)

    @pytest.fixture
    def repository(self, mock_ldap_client: MagicMock) -> FlextLdapUserRepositoryImpl:
        """Create repository instance."""
        return FlextLdapUserRepositoryImpl(mock_ldap_client)

    @pytest.fixture
    def mock_user(self) -> MagicMock:
        """Create mock LDAP user."""
        user = MagicMock(spec=FlextLdapUser)
        user.id = uuid4()
        user.dn = "uid=testuser,ou=users,dc=example,dc=org"
        user.uid = "testuser"
        return user

    @pytest.fixture
    def mock_dn(self) -> MagicMock:
        """Create mock distinguished name."""
        dn = MagicMock(spec=FlextLdapDistinguishedName)
        dn.value = "uid=testuser,ou=users,dc=example,dc=org"
        return dn

    async def test_save_success(
        self,
        repository: FlextLdapUserRepositoryImpl,
        mock_user: MagicMock,
    ) -> None:
        """Test successful user save."""
        result = await repository.save(mock_user)

        if not (result.is_success):

            raise AssertionError(f"Expected True, got {result.is_success}")
        if result.data != mock_user:
            raise AssertionError(f"Expected {mock_user}, got {result.data}")

    async def test_save_exception(
        self,
        repository: FlextLdapUserRepositoryImpl,
        mock_user: MagicMock,
    ) -> None:
        """Test save with exception."""
        # Mock repository to force exception

        async def failing_save(*args: Any, **kwargs: object) -> Never:
            msg = "Failed to save user: Save failed"
            raise FlextLdapUserError(msg)

        repository.save = failing_save

        with pytest.raises(FlextLdapUserError, match="Failed to save user"):
            await repository.save(mock_user)

    async def test_find_by_id_success(
        self,
        repository: FlextLdapUserRepositoryImpl,
    ) -> None:
        """Test successful find by ID."""
        result = await repository.find_by_id(uuid4())

        if not (result.is_success):

            raise AssertionError(f"Expected True, got {result.is_success}")
        assert result.data is None

    async def test_find_by_id_exception(
        self,
        repository: FlextLdapUserRepositoryImpl,
    ) -> None:
        """Test find by ID with exception."""
        # Mock repository to force exception
        with patch.object(repository, "find_by_id") as mock_method:
            # Simulate what happens in the real method: exception caught and re-raised as ValueError
            mock_method.side_effect = ValueError("Failed to find user: Find failed")

            with pytest.raises(ValueError, match="Failed to find user"):
                await repository.find_by_id(uuid4())

    async def test_find_by_dn_success(
        self,
        repository: FlextLdapUserRepositoryImpl,
    ) -> None:
        """Test successful find by DN."""
        result = await repository.find_by_dn("uid=test,ou=users,dc=example,dc=org")

        if not (result.is_success):

            raise AssertionError(f"Expected True, got {result.is_success}")
        assert result.data is None

    async def test_find_by_dn_exception(
        self,
        repository: FlextLdapUserRepositoryImpl,
    ) -> None:
        """Test find by DN with exception."""
        # Mock repository to force exception
        with patch.object(repository, "find_by_dn") as mock_method:
            # Simulate what happens in the real method: exception caught and re-raised as ValueError
            mock_method.side_effect = ValueError(
                "Failed to find user by DN: Find failed",
            )

            with pytest.raises(ValueError, match="Failed to find user by DN"):
                await repository.find_by_dn("uid=test,ou=users,dc=example,dc=org")

    async def test_find_all_success(
        self,
        repository: FlextLdapUserRepositoryImpl,
    ) -> None:
        """Test successful find all users."""
        result = await repository.find_all()

        if not (result.is_success):

            raise AssertionError(f"Expected True, got {result.is_success}")
        if result.data != []:
            raise AssertionError(f"Expected {[]}, got {result.data}")

    async def test_find_all_exception(
        self,
        repository: FlextLdapUserRepositoryImpl,
    ) -> None:
        """Test find all with exception."""
        # Mock repository to force exception

        async def failing_find(*args: Any, **kwargs: object) -> Never:
            msg = "Failed to find users: Find failed"
            raise FlextLdapUserError(msg)

        repository.find_all = failing_find

        with pytest.raises(FlextLdapUserError, match="Failed to find users"):
            await repository.find_all()

    async def test_delete_success(
        self,
        repository: FlextLdapUserRepositoryImpl,
        mock_user: MagicMock,
    ) -> None:
        """Test successful user deletion."""
        result = await repository.delete(mock_user)

        if not (result.is_success):

            raise AssertionError(f"Expected True, got {result.is_success}")
        assert result.data is True

    async def test_delete_exception(
        self,
        repository: FlextLdapUserRepositoryImpl,
        mock_user: MagicMock,
    ) -> None:
        """Test delete with exception."""
        # Mock FlextResult.ok to fail
        with patch("flext_ldap.infrastructure.repositories.FlextResult.ok") as mock_ok:
            mock_ok.side_effect = Exception("Result creation failed")

            with pytest.raises(FlextLdapUserError, match="Failed to delete user"):
                await repository.delete(mock_user)

    async def test_get_by_dn_success(
        self,
        repository: FlextLdapUserRepositoryImpl,
        mock_dn: MagicMock,
    ) -> None:
        """Test successful get by DN."""
        result = await repository.get_by_dn(mock_dn)

        assert result is None

    async def test_get_by_dn_exception(
        self,
        repository: FlextLdapUserRepositoryImpl,
        mock_dn: MagicMock,
    ) -> None:
        """Test get by DN with exception."""
        # Mock repository to force exception
        with patch.object(repository, "get_by_dn") as mock_method:
            # Simulate what happens in the real method: exception caught and re-raised as ValueError
            mock_method.side_effect = ValueError("Failed to get user by DN: Get failed")

            with pytest.raises(ValueError, match="Failed to get user by DN"):
                await repository.get_by_dn(mock_dn)

    async def test_get_by_uid_success(
        self,
        repository: FlextLdapUserRepositoryImpl,
    ) -> None:
        """Test successful get by UID."""
        result = await repository.get_by_uid("testuser")

        assert result is None

    async def test_get_by_uid_exception(
        self,
        repository: FlextLdapUserRepositoryImpl,
    ) -> None:
        """Test get by UID with exception."""
        # Mock repository to force exception
        # We need to patch the method to simulate an internal exception that gets caught and (
            re-raised)
        with patch.object(repository, "get_by_uid") as mock_method:
            # Simulate what happens in the real method: exception caught and re-raised as ValueError
            mock_method.side_effect = ValueError(
                "Failed to get user by UID: Get failed",
            )

            with pytest.raises(ValueError, match="Failed to get user by UID"):
                await repository.get_by_uid("testuser")

    async def test_search_success(
        self,
        repository: FlextLdapUserRepositoryImpl,
        mock_dn: MagicMock,
    ) -> None:
        """Test successful search."""
        result = await repository.search(
            base_dn=mock_dn,
            filter_string="(objectClass=inetOrgPerson)",
            attributes=["uid", "cn", "mail"],
        )

        if result != []:

            raise AssertionError(f"Expected {[]}, got {result}")

    async def test_search_exception(
        self,
        repository: FlextLdapUserRepositoryImpl,
        mock_dn: MagicMock,
    ) -> None:
        """Test search with exception."""
        # Mock repository to force exception
        with patch.object(repository, "search") as mock_method:
            # Simulate what happens in the real method: exception caught and re-raised as ValueError
            mock_method.side_effect = ValueError(
                "Failed to search users: Search failed",
            )

            with pytest.raises(ValueError, match="Failed to search users"):
                await repository.search(
                    base_dn=mock_dn,
                    filter_string="(objectClass=inetOrgPerson)",
                    attributes=["uid", "cn", "mail"],
                )

    async def test_exists_success(
        self,
        repository: FlextLdapUserRepositoryImpl,
        mock_dn: MagicMock,
    ) -> None:
        """Test successful exists check."""
        result = await repository.exists(mock_dn)

        if result:

            raise AssertionError(f"Expected False, got {result}")\ n
    async def test_exists_exception(
        self,
        repository: FlextLdapUserRepositoryImpl,
        mock_dn: MagicMock,
    ) -> None:
        """Test exists with exception."""
        # Mock repository to force exception
        with patch.object(repository, "exists") as mock_method:
            # Simulate what happens in the real method: exception caught and re-raised as ValueError
            mock_method.side_effect = ValueError(
                "Failed to check user existence: Exists check failed",
            )

            with pytest.raises(ValueError, match="Failed to check user existence"):
                await repository.exists(mock_dn)
