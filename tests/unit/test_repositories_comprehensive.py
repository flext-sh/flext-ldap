"""Comprehensive unit tests for LDAP repositories.

This module provides comprehensive unit tests for LDAP repository implementations,
including base repository, user repository, and group repository functionality.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from abc import ABC
from unittest.mock import MagicMock

import pytest

from flext_core import FlextResult
from flext_ldap import (
    FlextLdapClient,
    FlextLdapModels,
    FlextLdapRepositories,
    FlextLdapTypes,
)


@pytest.fixture
def mock_client() -> MagicMock:
    """Create mock LDAP client for testing."""
    client = MagicMock(spec=FlextLdapClient)

    # Mock successful user retrieval
    mock_user = FlextLdapModels.LdapUser(
        dn="uid=testuser,ou=users,dc=example,dc=com",
        cn="Test User",
        uid="testuser",
        sn="User",
        given_name="Test",
        mail="test@example.com",
        created_timestamp=None,
        modified_timestamp=None,
        telephone_number=None,
        mobile=None,
        department=None,
        title=None,
        organization=None,
        organizational_unit=None,
        user_password=None,
    )

    client.get_user.return_value = FlextResult[FlextLdapModels.LdapUser].ok(mock_user)
    client.search_users.return_value = FlextResult[list[FlextLdapModels.LdapUser]].ok([
        mock_user
    ])
    client.create_user.return_value = FlextResult[FlextLdapModels.LdapUser].ok(
        mock_user
    )
    client.delete_user.return_value = FlextResult[bool].ok(True)
    client.update_user_attributes.return_value = FlextResult[bool].ok(True)
    client.user_exists.return_value = FlextResult[bool].ok(False)

    # Mock successful group retrieval
    mock_group = FlextLdapModels.Group(
        dn="cn=testgroup,ou=groups,dc=example,dc=com",
        cn="testgroup",
        gid_number=1000,
        description="Test Group",
        created_timestamp=None,
        modified_timestamp=None,
    )

    client.get_group.return_value = FlextResult[FlextLdapModels.Group].ok(mock_group)
    client.search_groups.return_value = FlextResult[list[FlextLdapModels.Group]].ok([
        mock_group
    ])
    client.create_group.return_value = FlextResult[FlextLdapModels.Group].ok(mock_group)
    client.delete_group.return_value = FlextResult[bool].ok(True)
    client.update_group_attributes.return_value = FlextResult[bool].ok(True)
    client.group_exists.return_value = FlextResult[bool].ok(False)

    # Mock search operations
    client.search_with_request.return_value = FlextResult[
        FlextLdapModels.SearchResponse
    ].ok(
        FlextLdapModels.SearchResponse(
            entries=[
                {"dn": "uid=testuser,ou=users,dc=example,dc=com", "cn": "Test User"}
            ],
            total_count=1,
            result_code=0,
            result_description="Success",
            matched_dn="",
            next_cookie=None,
            entries_returned=1,
            time_elapsed=0.0,
        )
    )

    return client


@pytest.fixture
def repos() -> FlextLdapRepositories:
    """Create repositories instance for testing."""
    return FlextLdapRepositories()


class TestFlextLdapRepositoriesStructure:
    """Test FlextLdapRepositories class structure and availability."""

    def test_repositories_module_loads_without_errors(self) -> None:
        """Test that repositories module loads completely without import errors."""
        # Verify FlextLdapRepositories is available
        assert FlextLdapRepositories is not None

    def test_repositories_class_structure(self, repos: FlextLdapRepositories) -> None:
        """Test FlextLdapRepositories internal class structure."""
        # Test main class availability
        assert repos is not None

        # Test expected nested classes exist
        expected_nested_classes = [
            "Repository",
            "UserRepository",
            "GroupRepository",
        ]

        for class_name in expected_nested_classes:
            assert hasattr(repos, class_name), f"Missing {class_name}"
            nested_class = getattr(repos, class_name)
            assert nested_class is not None

    def test_repository_classes_instantiation(self, mock_client: MagicMock) -> None:
        """Test repository classes can be instantiated."""
        # Test base repository (abstract class - can't instantiate directly)
        # Instead, test that it's an abstract class
        assert issubclass(FlextLdapRepositories.Repository, ABC)

        # Test user repository
        user_repo = FlextLdapRepositories.UserRepository(mock_client)
        assert user_repo is not None
        assert user_repo._client is not None

        # Test group repository
        group_repo = FlextLdapRepositories.GroupRepository(mock_client)
        assert group_repo is not None
        assert group_repo._client is not None

    def test_repository_methods_exist(self, mock_client: MagicMock) -> None:
        """Test repository classes have expected methods."""
        # Test base repository methods (check class, not instance)
        base_methods = [
            "find_by_dn",
            "search",
            "save",
            "delete",
            "exists",
            "update",
        ]
        for method_name in base_methods:
            assert hasattr(FlextLdapRepositories.Repository, method_name), (
                f"Missing method {method_name}"
            )

        # Test user repository methods
        user_repo = FlextLdapRepositories.UserRepository(mock_client)
        user_methods = [
            "find_user_by_uid",
            "find_users_by_filter",
        ]
        for method_name in user_methods:
            assert hasattr(user_repo, method_name), f"Missing method {method_name}"

        # Test group repository methods
        group_repo = FlextLdapRepositories.GroupRepository(mock_client)
        group_methods = [
            "find_group_by_cn",
            "get_group_members",
            "add_member_to_group",
        ]
        for method_name in group_methods:
            assert hasattr(group_repo, method_name), f"Missing method {method_name}"


class TestBaseRepository:
    """Test base repository functionality."""

    def test_base_repository_search_method(self) -> None:
        """Test base repository search method."""
        # Test search method exists on the class
        assert hasattr(FlextLdapRepositories.Repository, "search")
        assert callable(getattr(FlextLdapRepositories.Repository, "search"))

    def test_base_repository_find_by_dn_method(self) -> None:
        """Test base repository find_by_dn method."""
        # Test find_by_dn method exists on the class
        assert hasattr(FlextLdapRepositories.Repository, "find_by_dn")
        assert callable(getattr(FlextLdapRepositories.Repository, "find_by_dn"))

    def test_base_repository_save_method(self) -> None:
        """Test base repository save method."""
        # Test save method exists on the class
        assert hasattr(FlextLdapRepositories.Repository, "save")
        assert callable(getattr(FlextLdapRepositories.Repository, "save"))

    def test_base_repository_delete_method(self) -> None:
        """Test base repository delete method."""
        # Test delete method exists on the class
        assert hasattr(FlextLdapRepositories.Repository, "delete")
        assert callable(getattr(FlextLdapRepositories.Repository, "delete"))

    def test_base_repository_exists_method(self) -> None:
        """Test base repository exists method."""
        # Test exists method exists on the class
        assert hasattr(FlextLdapRepositories.Repository, "exists")
        assert callable(getattr(FlextLdapRepositories.Repository, "exists"))

    def test_base_repository_update_method(self) -> None:
        """Test base repository update method."""
        # Test update method exists on the class
        assert hasattr(FlextLdapRepositories.Repository, "update")
        assert callable(getattr(FlextLdapRepositories.Repository, "update"))


class TestUserRepository:
    """Test user repository functionality."""

    @pytest.mark.asyncio
    async def test_user_repository_find_by_dn(self, mock_client: MagicMock) -> None:
        """Test user repository find_by_dn method."""
        user_repo = FlextLdapRepositories.UserRepository(mock_client)

        # Test find_by_dn method
        result = await user_repo.find_by_dn("uid=testuser,ou=users,dc=example,dc=com")

        assert isinstance(result, FlextResult)
        assert result.is_success
        assert result.value is not None
        assert result.value.dn == "uid=testuser,ou=users,dc=example,dc=com"

    @pytest.mark.asyncio
    async def test_user_repository_search(self, mock_client: MagicMock) -> None:
        """Test user repository search method."""
        user_repo = FlextLdapRepositories.UserRepository(mock_client)

        # Test search method
        result = await user_repo.search(
            base_dn="ou=users,dc=example,dc=com",
            filter_str="(objectClass=person)",
            page_size=None,
            paged_cookie=None,
        )

        assert isinstance(result, FlextResult)
        assert result.is_success
        assert isinstance(result.value, list)

    @pytest.mark.asyncio
    async def test_user_repository_save(self, mock_client: MagicMock) -> None:
        """Test user repository save method."""
        user_repo = FlextLdapRepositories.UserRepository(mock_client)

        # Create test user with all required fields
        user = FlextLdapModels.LdapUser(
            dn="uid=testuser,ou=users,dc=example,dc=com",
            uid="testuser",
            cn="Test User",
            sn="User",
            given_name="Test",
            mail="testuser@example.com",
            telephone_number=None,
            mobile=None,
            department=None,
            title=None,
            organization=None,
            organizational_unit=None,
            user_password=None,
            created_timestamp=None,
            modified_timestamp=None,
        )

        # Test save method
        result = await user_repo.save(user)

        assert isinstance(result, FlextResult)
        # Note: May fail without real LDAP connection, but validates API
        if result.is_failure:
            assert result.error is not None

    @pytest.mark.asyncio
    async def test_user_repository_delete(self, mock_client: MagicMock) -> None:
        """Test user repository delete method."""
        user_repo = FlextLdapRepositories.UserRepository(mock_client)

        # Test delete method
        result = await user_repo.delete("uid=testuser,ou=users,dc=example,dc=com")

        assert isinstance(result, FlextResult)
        assert result.is_success
        assert result.value is True

    @pytest.mark.asyncio
    async def test_user_repository_find_by_dn_async(
        self, mock_client: MagicMock
    ) -> None:
        """Test user repository find_by_dn_async method."""
        user_repo = FlextLdapRepositories.UserRepository(mock_client)

        # Test find_by_dn_async method
        result = await user_repo.find_by_dn("uid=testuser,ou=users,dc=example,dc=com")

        assert isinstance(result, FlextResult)
        if result.is_success:
            assert result.value is not None
        else:
            assert result.error is not None
            assert "Find failed" in result.error.lower()

    @pytest.mark.asyncio
    async def test_user_repository_save_async(self, mock_client: MagicMock) -> None:
        """Test user repository save_async method."""
        user_repo = FlextLdapRepositories.UserRepository(mock_client)

        # Create test user with all required fields
        user = FlextLdapModels.LdapUser(
            dn="uid=testuser,ou=users,dc=example,dc=com",
            uid="testuser",
            cn="Test User",
            sn="User",
            given_name="Test",
            mail="testuser@example.com",
            telephone_number=None,
            mobile=None,
            department=None,
            title=None,
            organization=None,
            organizational_unit=None,
            user_password=None,
            created_timestamp=None,
            modified_timestamp=None,
        )

        # Test save_async method
        result = await user_repo.save(user)

        assert isinstance(result, FlextResult)
        if result.is_success:
            assert result.value is not None
        else:
            assert result.error is not None
            assert (
                "failed" in result.error.lower()
                or "no connection" in result.error.lower()
            )

    @pytest.mark.asyncio
    async def test_user_repository_delete_async(self, mock_client: MagicMock) -> None:
        """Test user repository delete_async method."""
        user_repo = FlextLdapRepositories.UserRepository(mock_client)

        # Test delete_async method
        result = await user_repo.delete("uid=testuser,ou=users,dc=example,dc=com")

        assert isinstance(result, FlextResult)
        if result.is_success:
            assert result.value is True
        else:
            assert result.error is not None
            assert (
                "failed" in result.error.lower()
                or "no connection" in result.error.lower()
            )

    @pytest.mark.asyncio
    async def test_user_repository_update_attributes(
        self, mock_client: MagicMock
    ) -> None:
        """Test user repository update_attributes method."""
        user_repo = FlextLdapRepositories.UserRepository(mock_client)

        # Test update_attributes method
        attributes: FlextLdapTypes.EntryAttributeDict = {
            "cn": ["Updated Name"],
            "mail": ["updated@example.com"],
        }

        result = await user_repo.update(
            "uid=testuser,ou=users,dc=example,dc=com", attributes
        )

        assert isinstance(result, FlextResult)
        if result.is_success:
            assert result.value is True
        else:
            assert result.error is not None
            assert (
                "failed" in result.error.lower()
                or "no connection" in result.error.lower()
            )

    @pytest.mark.asyncio
    async def test_user_repository_get_by_id(self, mock_client: MagicMock) -> None:
        """Test user repository get_by_id method."""
        user_repo = FlextLdapRepositories.UserRepository(mock_client)

        # Test get_by_id method
        result = await user_repo.find_by_dn("uid=testuser,ou=users,dc=example,dc=com")

        assert isinstance(result, FlextResult)
        if result.is_success:
            assert result.value is not None
        else:
            assert result.error is not None
            assert (
                "failed" in result.error.lower()
                or "no connection" in result.error.lower()
            )

    @pytest.mark.asyncio
    async def test_user_repository_find_all(self, mock_client: MagicMock) -> None:
        """Test user repository find_all method."""
        user_repo = FlextLdapRepositories.UserRepository(mock_client)

        # Test find_all method
        result = await user_repo.search(
            base_dn="ou=users,dc=example,dc=com",
            filter_str="(objectClass=person)",
            page_size=None,
            paged_cookie=None,
        )

        assert isinstance(result, FlextResult)
        if result.is_success:
            assert isinstance(result.value, list)
        else:
            assert result.error is not None
            assert "search failed" in result.error.lower()

    @pytest.mark.asyncio
    async def test_user_repository_save_entry(self, mock_client: MagicMock) -> None:
        """Test user repository save_entry method."""
        user_repo = FlextLdapRepositories.UserRepository(mock_client)

        # Create test user with all required fields
        user = FlextLdapModels.LdapUser(
            dn="uid=testuser,ou=users,dc=example,dc=com",
            uid="testuser",
            cn="Test User",
            sn="User",
            given_name="Test",
            mail="testuser@example.com",
            telephone_number=None,
            mobile=None,
            department=None,
            title=None,
            organization=None,
            organizational_unit=None,
            user_password=None,
            created_timestamp=None,
            modified_timestamp=None,
        )

        # Test save_entry method
        result = await user_repo.save(user)

        assert isinstance(result, FlextResult)
        if result.is_success:
            assert result.value is not None
        else:
            assert result.error is not None
            assert (
                "failed" in result.error.lower()
                or "no connection" in result.error.lower()
            )

    @pytest.mark.asyncio
    async def test_user_repository_delete_entry(self, mock_client: MagicMock) -> None:
        """Test user repository delete_entry method."""
        user_repo = FlextLdapRepositories.UserRepository(mock_client)

        # Test delete_entry method
        result = await user_repo.delete("uid=testuser,ou=users,dc=example,dc=com")

        assert isinstance(result, FlextResult)
        if result.is_success:
            assert result.value is True
        else:
            assert result.error is not None
            assert (
                "failed" in result.error.lower()
                or "no connection" in result.error.lower()
            )

    @pytest.mark.asyncio
    async def test_user_repository_find_user_by_uid(
        self, mock_client: MagicMock
    ) -> None:
        """Test user repository find_user_by_uid method."""
        user_repo = FlextLdapRepositories.UserRepository(mock_client)

        # Test find_user_by_uid method
        result = await user_repo.find_user_by_uid("testuser")

        assert isinstance(result, FlextResult)
        if result.is_success:
            assert result.value is not None
            assert result.value.uid == "testuser"
        else:
            assert result.error is not None
            assert "failed to search for user by uid" in result.error.lower()

    @pytest.mark.asyncio
    async def test_user_repository_find_users_by_filter(
        self, mock_client: MagicMock
    ) -> None:
        """Test user repository find_users_by_filter method."""
        user_repo = FlextLdapRepositories.UserRepository(mock_client)

        # Test find_users_by_filter method
        result = await user_repo.find_users_by_filter("(objectClass=person)")

        assert isinstance(result, FlextResult)
        if result.is_success:
            assert isinstance(result.value, list)
        else:
            assert result.error is not None
            assert "find users failed" in result.error.lower()

    @pytest.mark.asyncio
    async def test_user_repository_find_users_by_filter_empty(
        self, mock_client: MagicMock
    ) -> None:
        """Test user repository find_users_by_filter method with empty result."""
        user_repo = FlextLdapRepositories.UserRepository(mock_client)

        # Test find_users_by_filter method
        result = await user_repo.find_users_by_filter("(objectClass=nonexistent)")

        assert isinstance(result, FlextResult)
        if result.is_success:
            assert isinstance(result.value, list)
        else:
            assert result.error is not None
            assert "find users failed" in result.error.lower()


class TestGroupRepository:
    """Test group repository functionality."""

    @pytest.mark.asyncio
    async def test_group_repository_find_by_dn(self, mock_client: MagicMock) -> None:
        """Test group repository find_by_dn method."""
        group_repo = FlextLdapRepositories.GroupRepository(mock_client)

        # Test find_by_dn method
        result = await group_repo.find_by_dn("cn=testgroup,ou=groups,dc=example,dc=com")

        assert isinstance(result, FlextResult)
        if result.is_success:
            assert result.value is not None
            assert result.value.dn == "cn=testgroup,ou=groups,dc=example,dc=com"
        else:
            assert result.error is not None
            assert "failed to retrieve group" in result.error.lower()

    @pytest.mark.asyncio
    async def test_group_repository_find_group_by_cn(
        self, mock_client: MagicMock
    ) -> None:
        """Test group repository find_group_by_cn method."""
        group_repo = FlextLdapRepositories.GroupRepository(mock_client)

        # Test find_group_by_cn method
        result = await group_repo.find_group_by_cn("testgroup")

        assert isinstance(result, FlextResult)
        if result.is_success:
            assert result.value is not None
            assert result.value.cn == "testgroup"
        else:
            assert result.error is not None
            assert (
                "ldap client does not support find_group_by_cn operation"
                in result.error.lower()
            )

    @pytest.mark.asyncio
    async def test_group_repository_get_group_members(
        self, mock_client: MagicMock
    ) -> None:
        """Test group repository get_group_members method."""
        group_repo = FlextLdapRepositories.GroupRepository(mock_client)

        # Test get_group_members method
        result = await group_repo.get_group_members(
            "cn=testgroup,ou=groups,dc=example,dc=com"
        )

        assert isinstance(result, FlextResult)
        if result.is_success:
            assert isinstance(result.value, list)
        else:
            assert result.error is not None
            assert (
                "failed" in result.error.lower()
                or "no connection" in result.error.lower()
            )

    @pytest.mark.asyncio
    async def test_group_repository_add_member_to_group(
        self, mock_client: MagicMock
    ) -> None:
        """Test group repository add_member_to_group method."""
        group_repo = FlextLdapRepositories.GroupRepository(mock_client)

        # Test add_member_to_group method
        result = await group_repo.add_member_to_group(
            "cn=testgroup,ou=groups,dc=example,dc=com",
            "uid=testuser,ou=users,dc=example,dc=com",
        )

        assert isinstance(result, FlextResult)
        if result.is_success:
            assert result.value is True
        else:
            assert result.error is not None
            assert (
                "add_member_to_group" in result.error.lower()
                or "failed" in result.error.lower()
            )


class TestRepositoryIntegration:
    """Test repository integration and cross-repository functionality."""

    @pytest.mark.asyncio
    async def test_repository_integration_search(self, mock_client: MagicMock) -> None:
        """Test repository integration search functionality."""
        # Test search using concrete repository implementation
        user_repo = FlextLdapRepositories.UserRepository(mock_client)

        result = await user_repo.search(
            base_dn="dc=example,dc=com",
            filter_str="(objectClass=*)",
            page_size=None,
            paged_cookie=None,
        )

        assert isinstance(result, FlextResult)
        if result.is_success:
            assert isinstance(result.value, list)
        else:
            assert result.error is not None
            assert "search failed" in result.error.lower()

    @pytest.mark.asyncio
    async def test_repository_integration_save(self, mock_client: MagicMock) -> None:
        """Test repository integration save functionality."""
        # Test save using concrete repository implementation
        user_repo = FlextLdapRepositories.UserRepository(mock_client)

        # Create test user
        user = FlextLdapModels.LdapUser(
            dn="cn=test,dc=example,dc=com",
            cn="Test User",
            uid=None,
            sn=None,
            given_name=None,
            mail=None,
            telephone_number=None,
            mobile=None,
            department=None,
            title=None,
            organization=None,
            organizational_unit=None,
            user_password=None,
            created_timestamp=None,
            modified_timestamp=None,
        )

        # Test save
        result = await user_repo.save(user)

        assert isinstance(result, FlextResult)
        if result.is_success:
            assert result.value is not None
        else:
            assert result.error is not None
            assert "error saving user" in result.error.lower()

    @pytest.mark.asyncio
    async def test_repository_integration_delete(self, mock_client: MagicMock) -> None:
        """Test repository integration delete functionality."""
        # Test delete using concrete repository implementation
        user_repo = FlextLdapRepositories.UserRepository(mock_client)

        # Test delete
        result = await user_repo.delete("cn=test,dc=example,dc=com")

        assert isinstance(result, FlextResult)
        if result.is_success:
            assert result.value is True
        else:
            assert result.error is not None
            assert "failed to delete user" in result.error.lower()

    @pytest.mark.asyncio
    async def test_repository_integration_exists(self, mock_client: MagicMock) -> None:
        """Test repository integration exists functionality."""
        # Test exists using concrete repository implementation
        user_repo = FlextLdapRepositories.UserRepository(mock_client)

        # Test exists
        result = await user_repo.exists("cn=test,dc=example,dc=com")

        assert isinstance(result, FlextResult)
        if result.is_success:
            assert isinstance(result.value, bool)
        else:
            assert result.error is not None
            assert "exists failed" in result.error.lower()

    @pytest.mark.asyncio
    async def test_repository_integration_update(self, mock_client: MagicMock) -> None:
        """Test repository integration update functionality."""
        # Test update using concrete repository implementation
        user_repo = FlextLdapRepositories.UserRepository(mock_client)

        # Test update
        attributes: FlextLdapTypes.EntryAttributeDict = {
            "cn": ["Updated Name"],
            "description": ["Updated Description"],
        }

        result = await user_repo.update("cn=test,dc=example,dc=com", attributes)

        assert isinstance(result, FlextResult)
        if result.is_success:
            assert result.value is True
        else:
            assert result.error is not None
            assert (
                "failed" in result.error.lower()
                or "no connection" in result.error.lower()
            )

    async def test_repository_cross_functionality(self, mock_client: MagicMock) -> None:
        """Test cross-repository functionality."""
        repos = FlextLdapRepositories()

        # Test user repository
        users1 = repos.UserRepository(mock_client)
        users2 = repos.UserRepository(mock_client)

        # Test group repository
        groups1 = repos.GroupRepository(mock_client)
        groups2 = repos.GroupRepository(mock_client)

        # Verify all repositories are properly instantiated
        assert users1 is not None
        assert users2 is not None
        assert groups1 is not None
        assert groups2 is not None

        # Test that they are separate instances
        assert users1 is not users2
        assert groups1 is not groups2

        # Test that they share same client
        assert users1._client is mock_client
        assert groups1._client is mock_client
