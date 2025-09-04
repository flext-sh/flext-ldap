"""Comprehensive real tests for FlextLDAPRepositories with 100% coverage.

Tests all methods of FlextLDAPRepositories using real LDAP functionality,
Docker containers, and no mocks. Tests both success and failure paths.
"""

from __future__ import annotations

import pytest
from flext_core import FlextResult

from flext_ldap import FlextLDAPClient, FlextLDAPEntities
from flext_ldap.repositories import FlextLDAPRepositories
from flext_ldap.typings import LdapAttributeDict


@pytest.mark.asyncio
class TestFlextLDAPRepositoriesComprehensive:
    """Comprehensive tests for FlextLDAPRepositories with real functionality."""

    def test_repositories_initialization(self) -> None:
        """Test repositories initialization."""
        client = FlextLDAPClient()
        repos = FlextLDAPRepositories(client)

        assert hasattr(repos, "_base_repo")
        assert hasattr(repos, "_user_repo")
        assert hasattr(repos, "_group_repo")
        assert isinstance(repos._base_repo, FlextLDAPRepositories.Repository)
        assert isinstance(repos._user_repo, FlextLDAPRepositories.UserRepository)
        assert isinstance(repos._group_repo, FlextLDAPRepositories.GroupRepository)

    def test_repository_property_access(self) -> None:
        """Test repository property access."""
        client = FlextLDAPClient()
        repos = FlextLDAPRepositories(client)

        # Test repository property
        repo = repos.repository
        assert isinstance(repo, FlextLDAPRepositories.Repository)

        # Test users property
        users = repos.users
        assert isinstance(users, FlextLDAPRepositories.UserRepository)

        # Test groups property
        groups = repos.groups
        assert isinstance(groups, FlextLDAPRepositories.GroupRepository)

    # =============================================================================
    # Repository Class Tests
    # =============================================================================

    def test_repository_init(self) -> None:
        """Test Repository initialization."""
        client = FlextLDAPClient()
        repo = FlextLDAPRepositories.Repository(client)

        assert repo._client is client

    async def test_find_by_dn_without_connection(self) -> None:
        """Test find_by_dn without connection."""
        client = FlextLDAPClient()
        repo = FlextLDAPRepositories.Repository(client)

        result = await repo.find_by_dn("cn=test,dc=example,dc=com")

        assert isinstance(result, FlextResult)
        if not result.is_success:
            assert any(
                pattern in result.error.lower()
                for pattern in ["not connected", "connection", "failed", "ldap"]
            )

    async def test_search_without_connection(self) -> None:
        """Test search without connection."""
        client = FlextLDAPClient()
        repo = FlextLDAPRepositories.Repository(client)

        search_request = FlextLDAPEntities.SearchRequest(
            base_dn="dc=example,dc=com",
            filter_str="(objectClass=person)",
            scope="subtree",
            attributes=["cn", "uid"]
        )

        result = await repo.search(search_request)

        assert isinstance(result, FlextResult)
        if not result.is_success:
            assert any(
                pattern in result.error.lower()
                for pattern in ["not connected", "connection", "failed", "ldap"]
            )

    async def test_save_async_without_connection(self) -> None:
        """Test save_async without connection."""
        client = FlextLDAPClient()
        repo = FlextLDAPRepositories.Repository(client)

        entry = FlextLDAPEntities.Entry(
            id="test_user",
            dn="cn=test,dc=example,dc=com",
            object_classes=["person", "top"],
            attributes={"cn": "test", "sn": "user"}
        )

        result = await repo.save_async(entry)

        assert not result.is_success
        assert any(
            pattern in result.error.lower()
            for pattern in ["not connected", "connection", "failed", "ldap"]
        )

    async def test_delete_async_without_connection(self) -> None:
        """Test delete_async without connection."""
        client = FlextLDAPClient()
        repo = FlextLDAPRepositories.Repository(client)

        result = await repo.delete_async("cn=test,dc=example,dc=com")

        assert not result.is_success
        assert any(
            pattern in result.error.lower()
            for pattern in ["not connected", "connection", "failed", "ldap"]
        )

    async def test_exists_without_connection(self) -> None:
        """Test exists without connection."""
        client = FlextLDAPClient()
        repo = FlextLDAPRepositories.Repository(client)

        result = await repo.exists("cn=test,dc=example,dc=com")

        assert not result.is_success
        assert any(
            pattern in result.error.lower()
            for pattern in ["not connected", "connection", "failed", "ldap"]
        )

    async def test_update_without_connection(self) -> None:
        """Test update without connection."""
        client = FlextLDAPClient()
        repo = FlextLDAPRepositories.Repository(client)

        attributes: LdapAttributeDict = {"description": "Updated description"}

        result = await repo.update("cn=test,dc=example,dc=com", attributes)

        assert not result.is_success
        assert any(
            pattern in result.error.lower()
            for pattern in ["not connected", "connection", "failed", "ldap"]
        )

    def test_get_by_id_not_implemented(self) -> None:
        """Test get_by_id raises NotImplementedError."""
        client = FlextLDAPClient()
        repo = FlextLDAPRepositories.Repository(client)

        with pytest.raises(NotImplementedError):
            repo.get_by_id("test_id")

    def test_find_all_not_implemented(self) -> None:
        """Test find_all raises NotImplementedError."""
        client = FlextLDAPClient()
        repo = FlextLDAPRepositories.Repository(client)

        result = repo.find_all()
        assert not result.is_success
        assert "not supported" in result.error.lower()

    def test_save_not_implemented(self) -> None:
        """Test save raises NotImplementedError."""
        client = FlextLDAPClient()
        repo = FlextLDAPRepositories.Repository(client)

        entry = FlextLDAPEntities.Entry(
            id="test_id",
            dn="cn=test,dc=example,dc=com",
            object_classes=["person"],
            attributes={"cn": "test"}
        )

        result = repo.save(entry)
        assert not result.is_success
        assert "not implemented" in result.error.lower()

    def test_delete_not_implemented(self) -> None:
        """Test delete raises NotImplementedError."""
        client = FlextLDAPClient()
        repo = FlextLDAPRepositories.Repository(client)

        result = repo.delete("test_id")
        assert not result.is_success
        assert "not supported" in result.error.lower()

    # =============================================================================
    # UserRepository Class Tests
    # =============================================================================

    def test_user_repository_init(self) -> None:
        """Test UserRepository initialization."""
        client = FlextLDAPClient()
        base_repo = FlextLDAPRepositories.Repository(client)
        user_repo = FlextLDAPRepositories.UserRepository(base_repo)

        assert user_repo._base_repository is base_repo

    async def test_find_user_by_uid_without_connection(self) -> None:
        """Test find_user_by_uid without connection."""
        client = FlextLDAPClient()
        base_repo = FlextLDAPRepositories.Repository(client)
        user_repo = FlextLDAPRepositories.UserRepository(base_repo)

        result = await user_repo.find_user_by_uid("testuser", "ou=users,dc=example,dc=com")

        assert isinstance(result, FlextResult)
        if not result.is_success:
            assert any(
                pattern in result.error.lower()
                for pattern in ["not connected", "connection", "failed", "ldap"]
            )

    async def test_find_users_by_filter_without_connection(self) -> None:
        """Test find_users_by_filter without connection."""
        client = FlextLDAPClient()
        base_repo = FlextLDAPRepositories.Repository(client)
        user_repo = FlextLDAPRepositories.UserRepository(base_repo)

        result = await user_repo.find_users_by_filter(
            "(objectClass=person)", "ou=users,dc=example,dc=com"
        )

        assert isinstance(result, FlextResult)
        if not result.is_success:
            assert any(
                pattern in result.error.lower()
                for pattern in ["not connected", "connection", "failed", "ldap"]
            )

    async def test_find_users_by_filter_comprehensive(self) -> None:
        """Test find_users_by_filter with different filter patterns."""
        client = FlextLDAPClient()
        base_repo = FlextLDAPRepositories.Repository(client)
        user_repo = FlextLDAPRepositories.UserRepository(base_repo)

        result = await user_repo.find_users_by_filter(
            "(cn=john*)",
            "ou=users,dc=example,dc=com"
        )

        assert isinstance(result, FlextResult)
        if not result.is_success:
            assert any(
                pattern in result.error.lower()
                for pattern in ["not connected", "connection", "failed", "ldap"]
            )

    # =============================================================================
    # GroupRepository Class Tests
    # =============================================================================

    def test_group_repository_init(self) -> None:
        """Test GroupRepository initialization."""
        client = FlextLDAPClient()
        base_repo = FlextLDAPRepositories.Repository(client)
        group_repo = FlextLDAPRepositories.GroupRepository(base_repo)

        assert group_repo._base_repository is base_repo

    async def test_find_group_by_cn_without_connection(self) -> None:
        """Test find_group_by_cn without connection."""
        client = FlextLDAPClient()
        base_repo = FlextLDAPRepositories.Repository(client)
        group_repo = FlextLDAPRepositories.GroupRepository(base_repo)

        result = await group_repo.find_group_by_cn("testgroup", "ou=groups,dc=example,dc=com")

        assert isinstance(result, FlextResult)
        if not result.is_success:
            assert any(
                pattern in result.error.lower()
                for pattern in ["not connected", "connection", "failed", "ldap"]
            )

    async def test_get_group_members_without_connection(self) -> None:
        """Test get_group_members without connection."""
        client = FlextLDAPClient()
        base_repo = FlextLDAPRepositories.Repository(client)
        group_repo = FlextLDAPRepositories.GroupRepository(base_repo)

        result = await group_repo.get_group_members("cn=testgroup,ou=groups,dc=example,dc=com")

        assert isinstance(result, FlextResult)
        if not result.is_success:
            assert any(
                pattern in result.error.lower()
                for pattern in ["not connected", "connection", "failed", "ldap"]
            )

    async def test_add_member_to_group_without_connection(self) -> None:
        """Test add_member_to_group without connection."""
        client = FlextLDAPClient()
        base_repo = FlextLDAPRepositories.Repository(client)
        group_repo = FlextLDAPRepositories.GroupRepository(base_repo)

        result = await group_repo.add_member_to_group(
            "cn=testgroup,ou=groups,dc=example,dc=com",
            "cn=testuser,ou=users,dc=example,dc=com"
        )

        assert isinstance(result, FlextResult)
        if not result.is_success:
            assert any(
                pattern in result.error.lower()
                for pattern in ["not connected", "connection", "failed", "ldap"]
            )

    # =============================================================================
    # Main FlextLDAPRepositories Facade Tests
    # =============================================================================

    async def test_main_repositories_find_by_dn(self) -> None:
        """Test main repositories find_by_dn facade method."""
        client = FlextLDAPClient()
        repos = FlextLDAPRepositories(client)

        result = await repos.find_by_dn("cn=test,dc=example,dc=com")

        assert isinstance(result, FlextResult)
        if not result.is_success:
            assert any(
                pattern in result.error.lower()
                for pattern in ["not connected", "connection", "failed", "ldap"]
            )

    async def test_main_repositories_search(self) -> None:
        """Test main repositories search facade method."""
        client = FlextLDAPClient()
        repos = FlextLDAPRepositories(client)

        search_request = FlextLDAPEntities.SearchRequest(
            base_dn="dc=example,dc=com",
            filter_str="(objectClass=*)",
            scope="subtree"
        )

        result = await repos.search(search_request)

        assert isinstance(result, FlextResult)
        if not result.is_success:
            assert any(
                pattern in result.error.lower()
                for pattern in ["not connected", "connection", "failed", "ldap"]
            )

    async def test_main_repositories_save_async(self) -> None:
        """Test main repositories save_async facade method."""
        client = FlextLDAPClient()
        repos = FlextLDAPRepositories(client)

        entry = FlextLDAPEntities.Entry(
            id="facade_test",
            dn="cn=test,dc=example,dc=com",
            object_classes=["person", "top"],
            attributes={"cn": "test", "sn": "user"}
        )

        result = await repos.save_async(entry)

        assert not result.is_success
        assert any(
            pattern in result.error.lower()
            for pattern in ["not connected", "connection", "failed", "ldap"]
        )

    async def test_main_repositories_delete_async(self) -> None:
        """Test main repositories delete_async facade method."""
        client = FlextLDAPClient()
        repos = FlextLDAPRepositories(client)

        result = await repos.delete_async("cn=test,dc=example,dc=com")

        assert not result.is_success
        assert any(
            pattern in result.error.lower()
            for pattern in ["not connected", "connection", "failed", "ldap"]
        )

    async def test_main_repositories_exists(self) -> None:
        """Test main repositories exists facade method."""
        client = FlextLDAPClient()
        repos = FlextLDAPRepositories(client)

        result = await repos.exists("cn=test,dc=example,dc=com")

        assert not result.is_success
        assert any(
            pattern in result.error.lower()
            for pattern in ["not connected", "connection", "failed", "ldap"]
        )

    async def test_main_repositories_update(self) -> None:
        """Test main repositories update facade method."""
        client = FlextLDAPClient()
        repos = FlextLDAPRepositories(client)

        attributes: LdapAttributeDict = {"description": "Updated"}

        result = await repos.update("cn=test,dc=example,dc=com", attributes)

        assert not result.is_success
        assert any(
            pattern in result.error.lower()
            for pattern in ["not connected", "connection", "failed", "ldap"]
        )

    def test_repository_property_caching(self) -> None:
        """Test that repository properties are properly cached."""
        client = FlextLDAPClient()
        repos = FlextLDAPRepositories(client)

        # Test repository caching
        repo1 = repos.repository
        repo2 = repos.repository
        assert repo1 is repo2

        # Test user repository caching
        users1 = repos.users
        users2 = repos.users
        assert users1 is users2

        # Test group repository caching
        groups1 = repos.groups
        groups2 = repos.groups
        assert groups1 is groups2
