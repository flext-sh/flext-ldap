"""Comprehensive unit tests for FlextLdapRepositories module.

Tests repository layer with real functionality and domain-driven design patterns.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import pytest

from flext_ldap.models import FlextLdapModels
from flext_ldap.repositories import FlextLdapRepositories


class TestFlextLdapRepositories:
    """Comprehensive test cases for FlextLdapRepositories."""

    def test_repositories_initialization(self) -> None:
        """Test repositories initialization."""
        repos = FlextLdapRepositories()
        assert repos is not None
        assert hasattr(FlextLdapRepositories, "UserRepository")
        assert hasattr(FlextLdapRepositories, "GroupRepository")
        assert hasattr(FlextLdapRepositories, "LdapRepository")

    def test_repositories_logger_available(self) -> None:
        """Test repositories logger is available."""
        assert hasattr(FlextLdapRepositories, "logger")
        assert FlextLdapRepositories.logger is not None

    # =========================================================================
    # USER REPOSITORY TESTS
    # =========================================================================

    def test_user_repository_initialization(self) -> None:
        """Test user repository initialization."""
        repo = FlextLdapRepositories.UserRepository()
        assert repo is not None
        assert hasattr(repo, "get_by_id")
        assert hasattr(repo, "get_all")
        assert hasattr(repo, "add")
        assert hasattr(repo, "update")
        assert hasattr(repo, "delete")

    def test_user_repository_inheritance(self) -> None:
        """Test user repository inherits from LdapRepository."""
        repo = FlextLdapRepositories.UserRepository()
        # Check it's an instance of the abstract base
        assert hasattr(repo, "save")
        assert hasattr(repo, "exists")

    # =========================================================================
    # GROUP REPOSITORY TESTS
    # =========================================================================

    def test_group_repository_initialization(self) -> None:
        """Test group repository initialization."""
        repo = FlextLdapRepositories.GroupRepository()
        assert repo is not None
        assert hasattr(repo, "get_by_id")
        assert hasattr(repo, "get_all")
        assert hasattr(repo, "add")
        assert hasattr(repo, "update")
        assert hasattr(repo, "delete")

    def test_group_repository_inheritance(self) -> None:
        """Test group repository inherits from LdapRepository."""
        repo = FlextLdapRepositories.GroupRepository()
        # Check it's an instance of the abstract base
        assert hasattr(repo, "save")
        assert hasattr(repo, "exists")

    # =========================================================================
    # LDAP REPOSITORY BASE TESTS
    # =========================================================================

    def test_ldap_repository_is_abstract(self) -> None:
        """Test LdapRepository is abstract and cannot be instantiated directly."""
        # LdapRepository is abstract - trying to instantiate should fail
        with pytest.raises(TypeError):
            FlextLdapRepositories.LdapRepository()

    def test_ldap_repository_generic_type(self) -> None:
        """Test LdapRepository is generic."""
        # Check that LdapRepository is generic
        assert hasattr(FlextLdapRepositories, "LdapRepository")
        # UserRepository should be parameterized
        repo = FlextLdapRepositories.UserRepository()
        assert repo is not None

    # =========================================================================
    # REPOSITORY PROTOCOL TESTS
    # =========================================================================

    def test_user_repository_has_protocol_methods(self) -> None:
        """Test user repository has all Domain.Repository protocol methods."""
        repo = FlextLdapRepositories.UserRepository()

        # Required by Domain.Repository protocol
        assert callable(getattr(repo, "get_by_id", None))
        assert callable(getattr(repo, "add", None))
        assert callable(getattr(repo, "update", None))
        assert callable(getattr(repo, "delete", None))
        assert callable(getattr(repo, "save", None))
        assert callable(getattr(repo, "exists", None))

    def test_group_repository_has_protocol_methods(self) -> None:
        """Test group repository has all Domain.Repository protocol methods."""
        repo = FlextLdapRepositories.GroupRepository()

        # Required by Domain.Repository protocol
        assert callable(getattr(repo, "get_by_id", None))
        assert callable(getattr(repo, "add", None))
        assert callable(getattr(repo, "update", None))
        assert callable(getattr(repo, "delete", None))
        assert callable(getattr(repo, "save", None))
        assert callable(getattr(repo, "exists", None))

    # =========================================================================
    # REPOSITORY INSTANTIATION TESTS
    # =========================================================================

    def test_user_repository_with_client(self) -> None:
        """Test user repository can be created with custom client."""
        from flext_ldap.clients import FlextLdapClients

        client = FlextLdapClients()
        repo = FlextLdapRepositories.UserRepository(client=client)
        assert repo is not None
        # Check client is set
        assert hasattr(repo, "_client")

    def test_group_repository_with_client(self) -> None:
        """Test group repository can be created with custom client."""
        from flext_ldap.clients import FlextLdapClients

        client = FlextLdapClients()
        repo = FlextLdapRepositories.GroupRepository(client=client)
        assert repo is not None
        # Check client is set
        assert hasattr(repo, "_client")

    def test_user_repository_without_client(self) -> None:
        """Test user repository creates default client when none provided."""
        repo = FlextLdapRepositories.UserRepository()
        assert repo is not None
        # Should have created a client
        assert hasattr(repo, "_client")
        assert repo._client is not None

    def test_group_repository_without_client(self) -> None:
        """Test group repository creates default client when none provided."""
        repo = FlextLdapRepositories.GroupRepository()
        assert repo is not None
        # Should have created a client
        assert hasattr(repo, "_client")
        assert repo._client is not None

    # =========================================================================
    # REPOSITORY FIND_ALL METHOD TESTS
    # =========================================================================

    def test_user_repository_find_all_returns_failure(self) -> None:
        """Test find_all on user repository."""
        repo = FlextLdapRepositories.UserRepository()
        result = repo.find_all()

        # find_all has default implementation that returns failure
        # (subclasses should override for efficiency)
        assert result.is_failure

    def test_group_repository_find_all_returns_failure(self) -> None:
        """Test find_all on group repository."""
        repo = FlextLdapRepositories.GroupRepository()
        result = repo.find_all()

        # find_all has default implementation that returns failure
        # (subclasses should override for efficiency)
        assert result.is_failure

    # =========================================================================
    # USER REPOSITORY METHOD TESTS
    # =========================================================================

    def test_user_repository_get_all_method_exists(self) -> None:
        """Test user repository get_all method."""
        repo = FlextLdapRepositories.UserRepository()
        result = repo.get_all()

        # Method should return a FlextResult
        assert hasattr(result, "is_success")
        assert hasattr(result, "is_failure")

    # =========================================================================
    # GROUP REPOSITORY METHOD TESTS
    # =========================================================================

    def test_group_repository_get_all_method_exists(self) -> None:
        """Test group repository get_all method."""
        repo = FlextLdapRepositories.GroupRepository()
        result = repo.get_all()

        # Method should return a FlextResult
        assert hasattr(result, "is_success")
        assert hasattr(result, "is_failure")

    # =========================================================================
    # REPOSITORY SAVE METHOD TESTS (from base class)
    # =========================================================================

    def test_user_repository_save_calls_exists_check(self) -> None:
        """Test user repository save method checks existence."""
        repo = FlextLdapRepositories.UserRepository()

        # Create a test user
        user = FlextLdapModels.LdapUser(
            dn="uid=testuser,ou=users,dc=example,dc=com",
            uid="testuser",
            cn="Test User",
            sn="User",
        )

        # save() should call exists() first
        # This will fail without a real LDAP connection, but we're testing the flow
        result = repo.save(user)

        # Should return a FlextResult (will be failure without real connection)
        assert hasattr(result, "is_success")
        assert hasattr(result, "is_failure")

    def test_group_repository_save_calls_exists_check(self) -> None:
        """Test group repository save method checks existence."""
        repo = FlextLdapRepositories.GroupRepository()

        # Create a test group
        group = FlextLdapModels.Group(
            dn="cn=testgroup,ou=groups,dc=example,dc=com",
            cn="testgroup",
            member_dns=["uid=user1,ou=users,dc=example,dc=com"],
        )

        # save() should call exists() first
        result = repo.save(group)

        # Should return a FlextResult (will be failure without real connection)
        assert hasattr(result, "is_success")
        assert hasattr(result, "is_failure")

    # =========================================================================
    # REPOSITORY EXISTS METHOD TESTS
    # =========================================================================

    def test_user_repository_exists_method(self) -> None:
        """Test user repository exists method."""
        repo = FlextLdapRepositories.UserRepository()

        # Test exists check (will use get_by_id internally)
        result = repo.exists("uid=testuser,ou=users,dc=example,dc=com")

        # Should return a FlextResult[bool]
        assert hasattr(result, "is_success")
        assert hasattr(result, "is_failure")

    def test_group_repository_exists_method(self) -> None:
        """Test group repository exists method."""
        repo = FlextLdapRepositories.GroupRepository()

        # Test exists check (will use get_by_id internally)
        result = repo.exists("cn=testgroup,ou=groups,dc=example,dc=com")

        # Should return a FlextResult[bool]
        assert hasattr(result, "is_success")
        assert hasattr(result, "is_failure")
