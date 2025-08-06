"""Tests for FLEXT-LDAP Infrastructure Repositories.

Pragmatic test suite focusing on Repository pattern implementation,
SOLID principles, and Clean Architecture boundaries validation.

Test Coverage Focus:
    - Repository pattern implementation validation
    - CRUD operations with FlextResult pattern
    - Error handling and edge cases
    - Mock-based testing for LDAP client integration
    - Clean Architecture layer separation

Author: FLEXT Development Team

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

import uuid
from unittest.mock import AsyncMock, Mock

import pytest
from flext_core import FlextResult

from flext_ldap.domain.exceptions import FlextLdapUserError
from flext_ldap.entities import FlextLdapConnection, FlextLdapUser
from flext_ldap.infrastructure.repositories import (
    FlextLdapConnectionRepositoryImpl,
    FlextLdapUserRepositoryImpl,
)
from flext_ldap.values import FlextLdapDistinguishedName


class TestFlextLdapConnectionRepositoryImpl:
    """Test suite for LDAP connection repository implementation."""

    def test_repository_initialization(self) -> None:
        """Test repository initialization with LDAP client."""
        mock_client = Mock()
        repo = FlextLdapConnectionRepositoryImpl(mock_client)

        assert repo.ldap_client is mock_client
        assert isinstance(repo._connections, dict)
        assert len(repo._connections) == 0

    async def test_save_connection_success(self) -> None:
        """Test successful connection saving."""
        mock_client = Mock()
        repo = FlextLdapConnectionRepositoryImpl(mock_client)

        # Create test connection
        connection_id = str(uuid.uuid4())
        connection = FlextLdapConnection(
            id=connection_id,
            host="ldap.example.com",
            port=389,
            use_ssl=False,
            is_connected=False
        )

        result = await repo.save(connection)

        # Validate FlextResult pattern
        assert result.is_success
        assert result.data is connection

        # Validate storage
        assert len(repo._connections) == 1
        assert repo._connections[connection_id] is connection

    async def test_save_connection_exception_handling(self) -> None:
        """Test connection saving exception handling."""
        mock_client = Mock()
        repo = FlextLdapConnectionRepositoryImpl(mock_client)

        # Mock connection that raises exception during save
        mock_connection = Mock()
        mock_connection.id = None  # Invalid ID to trigger exception

        with pytest.raises(FlextLdapUserError, match="Failed to save connection"):
            await repo.save(mock_connection)

    async def test_find_by_id_success(self) -> None:
        """Test successful connection lookup by ID."""
        mock_client = Mock()
        repo = FlextLdapConnectionRepositoryImpl(mock_client)

        # Add test connection
        connection_id = uuid.uuid4()
        connection = FlextLdapConnection(
            id=str(connection_id),
            host="ldap.example.com",
            port=389,
            use_ssl=False,
            is_connected=False
        )
        repo._connections[str(connection_id)] = connection

        result = await repo.find_by_id(connection_id)

        assert result.is_success
        assert result.data is connection

    async def test_find_by_id_not_found(self) -> None:
        """Test connection lookup when ID not found."""
        mock_client = Mock()
        repo = FlextLdapConnectionRepositoryImpl(mock_client)

        non_existent_id = uuid.uuid4()
        result = await repo.find_by_id(non_existent_id)

        assert result.is_success
        assert result.data is None

    async def test_find_all_empty(self) -> None:
        """Test finding all connections when repository is empty."""
        mock_client = Mock()
        repo = FlextLdapConnectionRepositoryImpl(mock_client)

        result = await repo.find_all()

        assert result.is_success
        assert isinstance(result.data, list)
        assert len(result.data) == 0

    async def test_find_all_with_connections(self) -> None:
        """Test finding all connections with multiple stored connections."""
        mock_client = Mock()
        repo = FlextLdapConnectionRepositoryImpl(mock_client)

        # Add multiple connections
        connections = []
        for i in range(3):
            conn_id = str(uuid.uuid4())
            connection = FlextLdapConnection(
                id=conn_id,
                host=f"ldap{i}.example.com",
                port=389,
                use_ssl=False,
                is_connected=False
            )
            repo._connections[conn_id] = connection
            connections.append(connection)

        result = await repo.find_all()

        assert result.is_success
        assert isinstance(result.data, list)
        assert len(result.data) == 3

        # Validate all connections present
        result_connections = result.data
        for connection in connections:
            assert connection in result_connections

    async def test_delete_connection_exists(self) -> None:
        """Test deleting existing connection."""
        mock_client = Mock()
        repo = FlextLdapConnectionRepositoryImpl(mock_client)

        # Add connection
        connection_id = str(uuid.uuid4())
        connection = FlextLdapConnection(
            id=connection_id,
            host="ldap.example.com",
            port=389,
            use_ssl=False,
            is_connected=False
        )
        repo._connections[connection_id] = connection

        result = await repo.delete(connection)

        assert result.is_success
        assert result.data is True
        assert len(repo._connections) == 0

    async def test_delete_connection_not_exists(self) -> None:
        """Test deleting non-existent connection."""
        mock_client = Mock()
        repo = FlextLdapConnectionRepositoryImpl(mock_client)

        connection = FlextLdapConnection(
            id=str(uuid.uuid4()),
            host="ldap.example.com",
            port=389,
            use_ssl=False,
            is_connected=False
        )

        result = await repo.delete(connection)

        assert result.is_success
        assert result.data is False


class TestFlextLdapUserRepositoryImpl:
    """Test suite for LDAP user repository implementation."""

    def test_user_repository_initialization(self) -> None:
        """Test user repository initialization."""
        mock_client = Mock()
        repo = FlextLdapUserRepositoryImpl(mock_client)

        assert repo.ldap_client is mock_client

    async def test_save_user_success(self) -> None:
        """Test successful user saving."""
        mock_client = Mock()
        mock_client.add_entry = AsyncMock(return_value=FlextResult.ok(True))

        repo = FlextLdapUserRepositoryImpl(mock_client)

        # Create test user
        user = FlextLdapUser(
            dn=FlextLdapDistinguishedName(value="cn=testuser,ou=users,dc=example,dc=com"),
            cn="testuser",
            uid="testuser",
            sn="Test"
        )

        result = await repo.save(user)

        assert result.is_success
        mock_client.add_entry.assert_called_once()

    async def test_save_user_ldap_error(self) -> None:
        """Test user saving with LDAP client error."""
        mock_client = Mock()
        mock_client.add_entry = AsyncMock(
            return_value=FlextResult.fail("LDAP add failed")
        )

        repo = FlextLdapUserRepositoryImpl(mock_client)

        user = FlextLdapUser(
            dn=FlextLdapDistinguishedName(value="cn=testuser,ou=users,dc=example,dc=com"),
            cn="testuser",
            uid="testuser",
            sn="Test"
        )

        result = await repo.save(user)

        assert not result.is_success
        assert "LDAP add failed" in result.error

    async def test_find_by_dn_success(self) -> None:
        """Test successful user lookup by DN."""
        mock_client = Mock()

        # Mock LDAP get_entry result
        mock_entry = {
            "dn": "cn=testuser,ou=users,dc=example,dc=com",
            "attributes": {
                "cn": ["testuser"],
                "uid": ["testuser"],
                "sn": ["Test"]
            }
        }
        mock_client.get_entry = AsyncMock(
            return_value=FlextResult.ok(mock_entry)
        )

        repo = FlextLdapUserRepositoryImpl(mock_client)

        # Use string DN as per implementation
        dn_str = "cn=testuser,ou=users,dc=example,dc=com"
        result = await repo.find_by_dn(dn_str)

        assert result.is_success
        assert isinstance(result.data, FlextLdapUser)
        user = result.data
        assert user.cn == "testuser"
        assert user.uid == "testuser"

    async def test_find_by_dn_not_found(self) -> None:
        """Test user lookup when DN not found."""
        mock_client = Mock()
        mock_client.get_entry = AsyncMock(return_value=FlextResult.fail("Entry not found"))

        repo = FlextLdapUserRepositoryImpl(mock_client)

        dn_str = "cn=nonexistent,ou=users,dc=example,dc=com"
        result = await repo.find_by_dn(dn_str)

        assert not result.is_success
        assert "Entry not found" in result.error

    async def test_find_by_uid_success(self) -> None:
        """Test successful user lookup by UID."""
        mock_client = Mock()

        # Mock LDAP search result
        mock_entry = {
            "dn": "cn=testuser,ou=users,dc=example,dc=com",
            "attributes": {
                "cn": ["testuser"],
                "uid": ["testuser"],
                "sn": ["Test"]
            }
        }
        mock_client.search = AsyncMock(
            return_value=FlextResult.ok([mock_entry])
        )

        repo = FlextLdapUserRepositoryImpl(mock_client)

        result = await repo.find_by_uid("testuser")

        assert result.is_success
        assert isinstance(result.data, FlextLdapUser)
        user = result.data
        assert user.uid == "testuser"

    async def test_find_all_users_success(self) -> None:
        """Test finding all users."""
        mock_client = Mock()

        # Mock multiple user entries
        mock_entries = [
            {
                "dn": "cn=user1,ou=users,dc=example,dc=com",
                "attributes": {
                    "cn": ["user1"],
                    "uid": ["user1"],
                    "sn": ["User1"]
                }
            },
            {
                "dn": "cn=user2,ou=users,dc=example,dc=com",
                "attributes": {
                    "cn": ["user2"],
                    "uid": ["user2"],
                    "sn": ["User2"]
                }
            }
        ]
        mock_client.search = AsyncMock(
            return_value=FlextResult.ok(mock_entries)
        )

        repo = FlextLdapUserRepositoryImpl(mock_client)

        result = await repo.find_all()

        assert result.is_success
        assert isinstance(result.data, list)
        assert len(result.data) == 2

        users = result.data
        assert all(isinstance(user, FlextLdapUser) for user in users)
        assert users[0].uid == "user1"
        assert users[1].uid == "user2"

    async def test_delete_user_success(self) -> None:
        """Test successful user deletion."""
        mock_client = Mock()
        mock_client.delete_entry = AsyncMock(return_value=FlextResult.ok(True))

        repo = FlextLdapUserRepositoryImpl(mock_client)

        user = FlextLdapUser(
            dn=FlextLdapDistinguishedName(value="cn=testuser,ou=users,dc=example,dc=com"),
            cn="testuser",
            uid="testuser",
            sn="Test"
        )

        result = await repo.delete(user)

        assert result.is_success
        mock_client.delete_entry.assert_called_once()

    async def test_repository_exception_handling(self) -> None:
        """Test repository exception handling."""
        mock_client = Mock()
        mock_client.search = AsyncMock(side_effect=RuntimeError("Connection failed"))

        repo = FlextLdapUserRepositoryImpl(mock_client)

        with pytest.raises(FlextLdapUserError, match="Failed to find user by DN"):
            await repo.find_by_dn(
                FlextLdapDistinguishedName(value="cn=test,ou=users,dc=example,dc=com")
            )

    async def test_user_conversion_from_ldap_entry(self) -> None:
        """Test conversion from LDAP entry to FlextLdapUser."""
        mock_client = Mock()
        repo = FlextLdapUserRepositoryImpl(mock_client)

        # Test the private conversion method
        ldap_entry = {
            "dn": "cn=testuser,ou=users,dc=example,dc=com",
            "attributes": {
                "cn": ["testuser"],
                "uid": ["testuser"],
                "sn": ["Test"],
                "givenName": ["Test"],
                "mail": ["test@example.com"]
            }
        }

        user = repo._convert_ldap_entry_to_user(ldap_entry)

        assert isinstance(user, FlextLdapUser)
        assert user.cn == "testuser"
        assert user.uid == "testuser"
        assert user.sn == "Test"
        assert str(user.dn) == "cn=testuser,ou=users,dc=example,dc=com"

    def test_clean_architecture_boundaries(self) -> None:
        """Test Clean Architecture layer boundaries are respected."""
        mock_client = Mock()

        # Connection repository should only depend on infrastructure client
        conn_repo = FlextLdapConnectionRepositoryImpl(mock_client)
        assert hasattr(conn_repo, "ldap_client")

        # User repository should only depend on infrastructure client
        user_repo = FlextLdapUserRepositoryImpl(mock_client)
        assert hasattr(user_repo, "ldap_client")

        # Repositories should implement domain interfaces
        from flext_ldap.domain.repositories import (
            FlextLdapConnectionRepository,
            FlextLdapUserRepository,
        )

        assert isinstance(conn_repo, FlextLdapConnectionRepository)
        assert isinstance(user_repo, FlextLdapUserRepository)
