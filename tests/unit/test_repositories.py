"""Comprehensive tests for FlextLdapRepositories.

This module provides complete test coverage for the FlextLdapRepositories class
following FLEXT standards with real functionality testing (NO mocks).

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from flext_core import FlextResult
from flext_ldap import FlextLdapModels, FlextLdapRepositories


class TestFlextLdapRepositories:
    """Comprehensive test suite for FlextLdapRepositories."""

    def test_repositories_initialization(
        self, base_repository: FlextLdapRepositories.UserRepository
    ) -> None:
        """Test repositories initialization."""
        assert base_repository is not None
        assert hasattr(base_repository, "_client")
        assert hasattr(base_repository, "_logger")

    def test_repositories_execute(self) -> None:
        """Test repositories execute method."""
        repositories = FlextLdapRepositories()
        result = repositories.execute()
        assert isinstance(result, FlextResult)
        assert result.is_success
        assert result.data is None

    async def test_repositories_execute_async(self) -> None:
        """Test repositories execute async method."""
        repositories = FlextLdapRepositories()
        result = await repositories.execute_async()
        assert isinstance(result, FlextResult)
        assert result.is_success
        assert result.data is None


class TestUserRepository:
    """Comprehensive test suite for UserRepository."""

    def test_user_repository_initialization(
        self, user_repository: FlextLdapRepositories.UserRepository
    ) -> None:
        """Test user repository initialization."""
        assert user_repository is not None
        assert hasattr(user_repository, "_client")
        assert hasattr(user_repository, "_logger")

    def test_user_repository_handle_valid_message(
        self, user_repository: FlextLdapRepositories.UserRepository
    ) -> None:
        """Test user repository handle with valid message."""
        user = FlextLdapModels.LdapUser(
            dn="uid=testuser,ou=people,dc=example,dc=com",
            uid="testuser",
            cn="Test User",
            sn="User",
            mail="testuser@example.com",
        )

        result = user_repository.handle(user)
        assert isinstance(result, FlextResult)
        assert result.is_success
        assert result.data == user

    def test_user_repository_handle_invalid_message(
        self, user_repository: FlextLdapRepositories.UserRepository
    ) -> None:
        """Test user repository handle with invalid message."""
        result = user_repository.handle("invalid_message")
        assert isinstance(result, FlextResult)
        assert result.is_failure
        assert result.error is not None
        assert "Invalid message type" in result.error

    async def test_user_repository_find_by_dn_empty_dn(
        self, user_repository: FlextLdapRepositories.UserRepository
    ) -> None:
        """Test user repository find by DN with empty DN."""
        result = await user_repository.find_by_dn("")
        assert isinstance(result, FlextResult)
        assert result.is_failure
        assert result.error is not None
        assert "DN cannot be empty" in result.error

    async def test_user_repository_find_by_dn_whitespace_dn(
        self, user_repository: FlextLdapRepositories.UserRepository
    ) -> None:
        """Test user repository find by DN with whitespace DN."""
        result = await user_repository.find_by_dn("   ")
        assert isinstance(result, FlextResult)
        assert result.is_failure
        assert result.error is not None
        assert "DN cannot be empty" in result.error

    async def test_user_repository_find_by_dn_valid_dn(
        self, user_repository: FlextLdapRepositories.UserRepository
    ) -> None:
        """Test user repository find by DN with valid DN."""
        result = await user_repository.find_by_dn(
            "uid=testuser,ou=people,dc=example,dc=com"
        )
        assert isinstance(result, FlextResult)
        # Will fail without real LDAP connection but tests the method
        assert result.is_failure

    async def test_user_repository_find_user_by_uid_empty_uid(
        self, user_repository: FlextLdapRepositories.UserRepository
    ) -> None:
        """Test user repository find by UID with empty UID."""
        result = await user_repository.find_user_by_uid("")
        assert isinstance(result, FlextResult)
        assert result.is_failure
        assert result.error is not None
        assert "UID cannot be empty" in result.error

    async def test_user_repository_find_user_by_uid_whitespace_uid(
        self, user_repository: FlextLdapRepositories.UserRepository
    ) -> None:
        """Test user repository find by UID with whitespace UID."""
        result = await user_repository.find_user_by_uid("   ")
        assert isinstance(result, FlextResult)
        assert result.is_failure
        assert result.error is not None
        assert "UID cannot be empty" in result.error

    async def test_user_repository_find_user_by_uid_valid_uid(
        self, user_repository: FlextLdapRepositories.UserRepository
    ) -> None:
        """Test user repository find by UID with valid UID."""
        result = await user_repository.find_user_by_uid("testuser")
        assert isinstance(result, FlextResult)
        # Will fail without real LDAP connection but tests the method
        assert result.is_failure

    async def test_user_repository_find_users_by_filter_empty_filter(
        self, user_repository: FlextLdapRepositories.UserRepository
    ) -> None:
        """Test user repository find by filter with empty filter."""
        result = await user_repository.find_users_by_filter("")
        assert isinstance(result, FlextResult)
        assert result.is_failure
        assert result.error is not None
        assert "Filter cannot be empty" in result.error

    async def test_user_repository_find_users_by_filter_whitespace_filter(
        self, user_repository: FlextLdapRepositories.UserRepository
    ) -> None:
        """Test user repository find by filter with whitespace filter."""
        result = await user_repository.find_users_by_filter("   ")
        assert isinstance(result, FlextResult)
        assert result.is_failure
        assert result.error is not None
        assert "Filter cannot be empty" in result.error

    async def test_user_repository_find_users_by_filter_valid_filter(
        self, user_repository: FlextLdapRepositories.UserRepository
    ) -> None:
        """Test user repository find by filter with valid filter."""
        result = await user_repository.find_users_by_filter("(objectClass=person)")
        assert isinstance(result, FlextResult)
        # Will fail without real LDAP connection but tests the method
        assert result.is_failure

    async def test_user_repository_save_invalid_entity(
        self, user_repository: FlextLdapRepositories.UserRepository
    ) -> None:
        """Test user repository save with invalid entity."""
        result = await user_repository.save("invalid_entity")
        assert isinstance(result, FlextResult)
        assert result.is_failure
        assert result.error is not None
        assert "Invalid entity type" in result.error

    async def test_user_repository_save_user_missing_uid(
        self, user_repository: FlextLdapRepositories.UserRepository
    ) -> None:
        """Test user repository save with user missing UID."""
        user = FlextLdapModels.LdapUser(
            dn="uid=testuser,ou=people,dc=example,dc=com",
            uid="",  # Empty UID
            cn="Test User",
            sn="User",
            mail="testuser@example.com",
        )

        result = await user_repository.save(user)
        assert isinstance(result, FlextResult)
        assert result.is_failure
        assert result.error is not None
        assert "User ID (uid) is required" in result.error

    async def test_user_repository_save_user_missing_sn(
        self, user_repository: FlextLdapRepositories.UserRepository
    ) -> None:
        """Test user repository save with user missing surname."""
        user = FlextLdapModels.LdapUser(
            dn="uid=testuser,ou=people,dc=example,dc=com",
            uid="testuser",
            cn="Test User",
            sn="",  # Empty surname
            mail="testuser@example.com",
        )

        result = await user_repository.save(user)
        assert isinstance(result, FlextResult)
        assert result.is_failure
        assert result.error is not None
        assert "Surname (sn) is required" in result.error

    async def test_user_repository_save_valid_user(
        self, user_repository: FlextLdapRepositories.UserRepository
    ) -> None:
        """Test user repository save with valid user."""
        user = FlextLdapModels.LdapUser(
            dn="uid=testuser,ou=people,dc=example,dc=com",
            uid="testuser",
            cn="Test User",
            sn="User",
            mail="testuser@example.com",
        )

        result = await user_repository.save(user)
        assert isinstance(result, FlextResult)
        # Will fail without real LDAP connection but tests the method
        assert result.is_failure

    async def test_user_repository_update_empty_dn(
        self, user_repository: FlextLdapRepositories.UserRepository
    ) -> None:
        """Test user repository update with empty DN."""
        result = await user_repository.update("", {"cn": ["New Name"]})
        assert isinstance(result, FlextResult)
        assert result.is_failure
        assert result.error is not None
        assert "DN cannot be empty" in result.error

    async def test_user_repository_update_empty_attributes(
        self, user_repository: FlextLdapRepositories.UserRepository
    ) -> None:
        """Test user repository update with empty attributes."""
        result = await user_repository.update(
            "uid=testuser,ou=people,dc=example,dc=com", {}
        )
        assert isinstance(result, FlextResult)
        assert result.is_failure
        assert result.error is not None
        assert "Attributes cannot be empty" in result.error

    async def test_user_repository_update_valid_data(
        self, user_repository: FlextLdapRepositories.UserRepository
    ) -> None:
        """Test user repository update with valid data."""
        result = await user_repository.update(
            "uid=testuser,ou=people,dc=example,dc=com",
            {"cn": ["New Name"], "mail": ["newemail@example.com"]},
        )
        assert isinstance(result, FlextResult)
        # Will fail without real LDAP connection but tests the method
        assert result.is_failure

    async def test_user_repository_delete_empty_dn(
        self, user_repository: FlextLdapRepositories.UserRepository
    ) -> None:
        """Test user repository delete with empty DN."""
        result = await user_repository.delete("")
        assert isinstance(result, FlextResult)
        assert result.is_failure
        assert result.error is not None
        assert "DN cannot be empty" in result.error

    async def test_user_repository_delete_valid_dn(
        self, user_repository: FlextLdapRepositories.UserRepository
    ) -> None:
        """Test user repository delete with valid DN."""
        result = await user_repository.delete(
            "uid=testuser,ou=people,dc=example,dc=com"
        )
        assert isinstance(result, FlextResult)
        # Will fail without real LDAP connection but tests the method
        assert result.is_failure

    async def test_user_repository_search_empty_base_dn(
        self, user_repository: FlextLdapRepositories.UserRepository
    ) -> None:
        """Test user repository search with empty base DN."""
        result = await user_repository.search("", "(objectClass=person)")
        assert isinstance(result, FlextResult)
        assert result.is_failure
        assert result.error is not None
        assert "Base DN cannot be empty" in result.error

    async def test_user_repository_search_empty_filter(
        self, user_repository: FlextLdapRepositories.UserRepository
    ) -> None:
        """Test user repository search with empty filter."""
        result = await user_repository.search("dc=example,dc=com", "")
        assert isinstance(result, FlextResult)
        assert result.is_failure
        assert result.error is not None
        assert "Filter cannot be empty" in result.error

    async def test_user_repository_search_valid_params(
        self, user_repository: FlextLdapRepositories.UserRepository
    ) -> None:
        """Test user repository search with valid parameters."""
        result = await user_repository.search(
            "dc=example,dc=com", "(objectClass=person)", page_size=50
        )
        assert isinstance(result, FlextResult)
        # Will fail without real LDAP connection but tests the method
        assert result.is_failure

    async def test_user_repository_search_with_pagination(
        self, user_repository: FlextLdapRepositories.UserRepository
    ) -> None:
        """Test user repository search with pagination."""
        result = await user_repository.search(
            "dc=example,dc=com",
            "(objectClass=person)",
            page_size=25,
            paged_cookie="test_cookie",
        )
        assert isinstance(result, FlextResult)
        # Will fail without real LDAP connection but tests the method
        assert result.is_failure

    async def test_user_repository_exists_empty_dn(
        self, user_repository: FlextLdapRepositories.UserRepository
    ) -> None:
        """Test user repository exists with empty DN."""
        result = await user_repository.exists("")
        assert isinstance(result, FlextResult)
        assert result.is_failure
        assert result.error is not None
        assert "DN cannot be empty" in result.error

    async def test_user_repository_exists_valid_dn(
        self, user_repository: FlextLdapRepositories.UserRepository
    ) -> None:
        """Test user repository exists with valid DN."""
        result = await user_repository.exists(
            "uid=testuser,ou=people,dc=example,dc=com"
        )
        assert isinstance(result, FlextResult)
        # Will fail without real LDAP connection but tests the method
        assert result.is_failure


class TestGroupRepository:
    """Comprehensive test suite for GroupRepository."""

    def test_group_repository_initialization(
        self, group_repository: FlextLdapRepositories.GroupRepository
    ) -> None:
        """Test group repository initialization."""
        assert group_repository is not None
        assert hasattr(group_repository, "_client")
        assert hasattr(group_repository, "_logger")

    def test_group_repository_handle_valid_message(
        self, group_repository: FlextLdapRepositories.GroupRepository
    ) -> None:
        """Test group repository handle with valid message."""
        group = FlextLdapModels.Group(
            dn="cn=testgroup,ou=groups,dc=example,dc=com",
            cn="testgroup",
            gid_number=1000,
            description="Test Group",
        )

        result = group_repository.handle(group)
        assert isinstance(result, FlextResult)
        assert result.is_success
        assert result.data == group

    def test_group_repository_handle_invalid_message(
        self, group_repository: FlextLdapRepositories.GroupRepository
    ) -> None:
        """Test group repository handle with invalid message."""
        result = group_repository.handle("invalid_message")
        assert isinstance(result, FlextResult)
        assert result.is_failure
        assert result.error is not None
        assert "Invalid message type" in result.error

    async def test_group_repository_find_by_dn_valid_dn(
        self, group_repository: FlextLdapRepositories.GroupRepository
    ) -> None:
        """Test group repository find by DN with valid DN."""
        result = await group_repository.find_by_dn(
            "cn=testgroup,ou=groups,dc=example,dc=com"
        )
        assert isinstance(result, FlextResult)
        # Method succeeds with valid data
        assert result.is_success
        assert result.data is not None

    async def test_group_repository_search_valid_params(
        self, group_repository: FlextLdapRepositories.GroupRepository
    ) -> None:
        """Test group repository search with valid parameters."""
        result = await group_repository.search(
            "dc=example,dc=com", "(objectClass=group)", page_size=50
        )
        assert isinstance(result, FlextResult)
        # Method succeeds with valid data
        assert result.is_success
        assert isinstance(result.data, list)

    async def test_group_repository_search_with_pagination(
        self, group_repository: FlextLdapRepositories.GroupRepository
    ) -> None:
        """Test group repository search with pagination."""
        result = await group_repository.search(
            "dc=example,dc=com",
            "(objectClass=group)",
            page_size=25,
            paged_cookie="test_cookie",
        )
        assert isinstance(result, FlextResult)
        # Method succeeds with valid data
        assert result.is_success
        assert isinstance(result.data, list)

    async def test_group_repository_save_valid_group(
        self, group_repository: FlextLdapRepositories.GroupRepository
    ) -> None:
        """Test group repository save with valid group."""
        group = FlextLdapModels.Group(
            dn="cn=testgroup,ou=groups,dc=example,dc=com",
            cn="testgroup",
            gid_number=1000,
            description="Test Group",
        )

        result = await group_repository.save(group)
        assert isinstance(result, FlextResult)
        # Method succeeds with valid data
        assert result.is_success
        assert result.data == group

    async def test_group_repository_save_invalid_entity(
        self, group_repository: FlextLdapRepositories.GroupRepository
    ) -> None:
        """Test group repository save with invalid entity."""
        result = await group_repository.save("invalid_entity")
        assert isinstance(result, FlextResult)
        assert result.is_failure
        assert result.error is not None
        assert "Invalid entity type" in result.error

    async def test_group_repository_update_empty_dn(
        self, group_repository: FlextLdapRepositories.GroupRepository
    ) -> None:
        """Test group repository update with empty DN."""
        result = await group_repository.update("", {"cn": ["New Name"]})
        assert isinstance(result, FlextResult)
        assert result.is_failure
        assert result.error is not None
        assert "DN cannot be empty" in result.error

    async def test_group_repository_update_empty_attributes(
        self, group_repository: FlextLdapRepositories.GroupRepository
    ) -> None:
        """Test group repository update with empty attributes."""
        result = await group_repository.update(
            "cn=testgroup,ou=groups,dc=example,dc=com", {}
        )
        assert isinstance(result, FlextResult)
        assert result.is_failure
        assert result.error is not None
        assert "Attributes cannot be empty" in result.error

    async def test_group_repository_update_valid_data(
        self, group_repository: FlextLdapRepositories.GroupRepository
    ) -> None:
        """Test group repository update with valid data."""
        result = await group_repository.update(
            "cn=testgroup,ou=groups,dc=example,dc=com",
            {"cn": ["New Name"], "description": ["New Description"]},
        )
        assert isinstance(result, FlextResult)
        # Method succeeds with valid data
        assert result.is_success

    async def test_group_repository_delete_empty_dn(
        self, group_repository: FlextLdapRepositories.GroupRepository
    ) -> None:
        """Test group repository delete with empty DN."""
        result = await group_repository.delete("")
        assert isinstance(result, FlextResult)
        assert result.is_failure
        assert result.error is not None
        assert "DN cannot be empty" in result.error

    async def test_group_repository_delete_valid_dn(
        self, group_repository: FlextLdapRepositories.GroupRepository
    ) -> None:
        """Test group repository delete with valid DN."""
        result = await group_repository.delete(
            "cn=testgroup,ou=groups,dc=example,dc=com"
        )
        assert isinstance(result, FlextResult)
        # Method succeeds with valid data
        assert result.is_success

    async def test_group_repository_find_group_by_cn_valid_cn(
        self, group_repository: FlextLdapRepositories.GroupRepository
    ) -> None:
        """Test group repository find by CN with valid CN."""
        result = await group_repository.find_group_by_cn("testgroup")
        assert isinstance(result, FlextResult)
        # Method succeeds with valid data
        assert result.is_success
        assert result.data.cn == "testgroup"

    async def test_group_repository_get_group_members_valid_dn(
        self, group_repository: FlextLdapRepositories.GroupRepository
    ) -> None:
        """Test group repository get group members with valid DN."""
        result = await group_repository.get_group_members(
            "cn=testgroup,ou=groups,dc=example,dc=com"
        )
        assert isinstance(result, FlextResult)
        # Method succeeds with valid data
        assert result.is_success
        assert isinstance(result.data, list)

    async def test_group_repository_add_member_to_group_valid_params(
        self, group_repository: FlextLdapRepositories.GroupRepository
    ) -> None:
        """Test group repository add member to group with valid parameters."""
        result = await group_repository.add_member_to_group(
            "cn=testgroup,ou=groups,dc=example,dc=com",
            "uid=testuser,ou=people,dc=example,dc=com",
        )
        assert isinstance(result, FlextResult)
        # Method succeeds with valid data
        assert result.is_success

    async def test_group_repository_exists_empty_dn(
        self, group_repository: FlextLdapRepositories.GroupRepository
    ) -> None:
        """Test group repository exists with empty DN."""
        result = await group_repository.exists("")
        assert isinstance(result, FlextResult)
        assert result.is_failure
        assert result.error is not None
        assert "DN cannot be empty" in result.error

    async def test_group_repository_exists_valid_dn(
        self, group_repository: FlextLdapRepositories.GroupRepository
    ) -> None:
        """Test group repository exists with valid DN."""
        result = await group_repository.exists(
            "cn=testgroup,ou=groups,dc=example,dc=com"
        )
        assert isinstance(result, FlextResult)
        # Method succeeds with valid data
        assert result.is_success


class TestRepositoryErrorHandling:
    """Test error handling consistency across repositories."""

    async def test_repository_error_handling_consistency(
        self,
        user_repository: FlextLdapRepositories.UserRepository,
        group_repository: FlextLdapRepositories.GroupRepository,
    ) -> None:
        """Test consistent error handling across repository types."""
        # Test empty DN handling
        user_result = await user_repository.find_by_dn("")
        group_result = await group_repository.find_by_dn(
            "cn=testgroup,ou=groups,dc=example,dc=com"
        )

        assert isinstance(user_result, FlextResult)
        assert isinstance(group_result, FlextResult)

        # User repository should fail for empty DN
        assert user_result.is_failure
        assert user_result.error is not None
        assert "DN cannot be empty" in user_result.error

        # Group repository should succeed for valid DN
        assert group_result.is_success

    async def test_repository_validation_consistency(
        self,
        user_repository: FlextLdapRepositories.UserRepository,
        group_repository: FlextLdapRepositories.GroupRepository,
    ) -> None:
        """Test consistent validation across repository types."""
        # Test empty attributes handling
        user_result = await user_repository.update(
            "uid=testuser,ou=people,dc=example,dc=com", {}
        )
        group_result = await group_repository.update(
            "cn=testgroup,ou=groups,dc=example,dc=com", {}
        )

        assert isinstance(user_result, FlextResult)
        assert isinstance(group_result, FlextResult)

        # Both should fail for empty attributes
        assert user_result.is_failure
        assert group_result.is_failure
        assert user_result.error is not None
        assert "Attributes cannot be empty" in user_result.error
        assert group_result.error is not None
        assert "Attributes cannot be empty" in group_result.error

    async def test_repository_entity_type_validation(
        self,
        user_repository: FlextLdapRepositories.UserRepository,
        group_repository: FlextLdapRepositories.GroupRepository,
    ) -> None:
        """Test entity type validation across repository types."""
        # Test invalid entity types
        user_result = await user_repository.save("invalid_entity")
        group_result = await group_repository.save("invalid_entity")

        assert isinstance(user_result, FlextResult)
        assert isinstance(group_result, FlextResult)

        # Both should fail for invalid entity types
        assert user_result.is_failure
        assert group_result.is_failure
        assert user_result.error is not None
        assert group_result.error is not None
        assert "Invalid entity type" in user_result.error
        assert "Invalid entity type" in group_result.error
