"""Tests for LDAP infrastructure repositories."""

from __future__ import annotations

import pytest
from flext_ldap.base import FlextLdapRepository
from flext_ldap.entities import FlextLdapUser


class TestFlextLdapRepository:
    """Test suite for FlextLdapRepository."""

    @pytest.fixture
    def repository(self) -> FlextLdapRepository:
        """Create a repository for testing."""
        return FlextLdapRepository()

    @pytest.fixture
    def sample_user(self) -> FlextLdapUser:
        """Create a sample user for testing."""
        return FlextLdapUser(
            id="testuser",
            dn="cn=testuser,ou=users,dc=example,dc=com",
            uid="testuser",
            cn="Test User",
            sn="User",
            mail="testuser@example.com",
        )

    def test_init(self, repository: FlextLdapRepository) -> None:
        """Test repository initialization."""
        assert repository._storage == {}

    def test_save_success(
        self, repository: FlextLdapRepository, sample_user: FlextLdapUser
    ) -> None:
        """Test successful save operation."""
        result = repository.save(sample_user)

        assert result.is_success
        assert sample_user.id in repository._storage
        assert repository._storage[sample_user.id] == sample_user

    def test_save_with_validation(self, repository: FlextLdapRepository) -> None:
        """Test save with entity validation."""

        # Create a user with validation method - FBT eliminated
        class ValidationConfig:
            """Constants for validation behavior - eliminates FBT smells."""

            SHOULD_FAIL = True
            SHOULD_PASS = False

        class ValidatingUser:
            def __init__(
                self, id: str, *, should_fail: bool = ValidationConfig.SHOULD_PASS
            ) -> None:
                self.id = id
                self.should_fail = should_fail

            def validate_domain_rules(self) -> None:
                if self.should_fail:
                    msg = "Validation failed"
                    raise ValueError(msg)

        # Test successful validation
        user = ValidatingUser("valid_user")
        result = repository.save(user)  # type: ignore[arg-type]
        assert result.is_success

        # Test failed validation
        invalid_user = ValidatingUser(
            "invalid_user", should_fail=ValidationConfig.SHOULD_FAIL
        )
        result = repository.save(invalid_user)  # type: ignore[arg-type]
        assert result.is_failure
        assert "Validation failed" in result.error

    def test_find_by_id_exists(
        self, repository: FlextLdapRepository, sample_user: FlextLdapUser
    ) -> None:
        """Test finding existing entity by ID."""
        repository.save(sample_user)

        result = repository.find_by_id(sample_user.id)
        assert result.is_success
        assert result.data == sample_user

    def test_find_by_id_not_exists(self, repository: FlextLdapRepository) -> None:
        """Test finding non-existing entity by ID."""
        result = repository.find_by_id("nonexistent")
        assert result.is_success
        assert result.data is None

    def test_delete_exists(
        self, repository: FlextLdapRepository, sample_user: FlextLdapUser
    ) -> None:
        """Test deleting existing entity."""
        repository.save(sample_user)

        result = repository.delete(sample_user.id)
        assert result.is_success
        assert sample_user.id not in repository._storage

    def test_delete_not_exists(self, repository: FlextLdapRepository) -> None:
        """Test deleting non-existing entity."""
        result = repository.delete("nonexistent")
        assert result.is_failure
        assert "not found" in result.error

    @pytest.mark.asyncio
    async def test_find_where_match(
        self, repository: FlextLdapRepository, sample_user: FlextLdapUser
    ) -> None:
        """Test finding entities matching conditions."""
        repository.save(sample_user)

        results = await repository.find_where(uid="testuser")
        assert len(results) == 1
        assert results[0] == sample_user

    @pytest.mark.asyncio
    async def test_find_where_no_match(
        self, repository: FlextLdapRepository, sample_user: FlextLdapUser
    ) -> None:
        """Test finding entities with no matches."""
        repository.save(sample_user)

        results = await repository.find_where(uid="nonexistent")
        assert len(results) == 0

    @pytest.mark.asyncio
    async def test_find_where_multiple_conditions(
        self, repository: FlextLdapRepository, sample_user: FlextLdapUser
    ) -> None:
        """Test finding entities with multiple conditions."""
        repository.save(sample_user)

        results = await repository.find_where(uid="testuser", cn="Test User")
        assert len(results) == 1
        assert results[0] == sample_user

        # Should not match if one condition fails
        results = await repository.find_where(uid="testuser", cn="Wrong Name")
        assert len(results) == 0

    @pytest.mark.asyncio
    async def test_find_by_attribute(
        self, repository: FlextLdapRepository, sample_user: FlextLdapUser
    ) -> None:
        """Test finding entities by single attribute."""
        repository.save(sample_user)

        results = await repository.find_by_attribute("mail", "testuser@example.com")
        assert len(results) == 1
        assert results[0] == sample_user

    @pytest.mark.asyncio
    async def test_list_all_empty(self, repository: FlextLdapRepository) -> None:
        """Test listing all entities when repository is empty."""
        results = await repository.list_all()
        assert len(results) == 0

    @pytest.mark.asyncio
    async def test_list_all_with_data(
        self, repository: FlextLdapRepository, sample_user: FlextLdapUser
    ) -> None:
        """Test listing all entities with data."""
        repository.save(sample_user)

        results = await repository.list_all()
        assert len(results) == 1
        assert results[0] == sample_user

    @pytest.mark.asyncio
    async def test_list_all_with_pagination(
        self, repository: FlextLdapRepository
    ) -> None:
        """Test listing entities with pagination."""
        # Create multiple users
        users = []
        for i in range(5):
            user = FlextLdapUser(
                id=f"user{i}",
                dn=f"cn=user{i},ou=users,dc=example,dc=com",
                uid=f"user{i}",
                cn=f"User {i}",
                sn="User",
            )
            users.append(user)
            repository.save(user)

        # Test limit
        results = await repository.list_all(limit=3)
        assert len(results) == 3

        # Test offset
        results = await repository.list_all(limit=2, offset=2)
        assert len(results) == 2

    @pytest.mark.asyncio
    async def test_count_empty(self, repository: FlextLdapRepository) -> None:
        """Test counting entities in empty repository."""
        count = await repository.count()
        assert count == 0

    @pytest.mark.asyncio
    async def test_count_with_data(
        self, repository: FlextLdapRepository, sample_user: FlextLdapUser
    ) -> None:
        """Test counting entities with data."""
        repository.save(sample_user)

        count = await repository.count()
        assert count == 1

    @pytest.mark.asyncio
    async def test_count_with_conditions(self, repository: FlextLdapRepository) -> None:
        """Test counting entities with filter conditions."""
        # Create multiple users
        for i in range(3):
            user = FlextLdapUser(
                id=f"user{i}",
                dn=f"cn=user{i},ou=users,dc=example,dc=com",
                uid=f"user{i}",
                cn=f"User {i}",
                sn="User" if i < 2 else "Admin",  # Different sn for last user
            )
            repository.save(user)

        # Count all
        count = await repository.count()
        assert count == 3

        # Count with filter
        count = await repository.count(sn="User")
        assert count == 2

    def test_validate_entity_success(
        self, repository: FlextLdapRepository, sample_user: FlextLdapUser
    ) -> None:
        """Test entity validation success."""
        result = repository._validate_entity(sample_user)
        assert result.is_success

    def test_validate_entity_with_validation_method(
        self, repository: FlextLdapRepository
    ) -> None:
        """Test entity validation with validation method."""

        class ValidatingEntity:
            def validate_domain_rules(self) -> None:
                msg = "Test validation error"
                raise ValueError(msg)

        entity = ValidatingEntity()
        result = repository._validate_entity(entity)  # type: ignore[arg-type]
        assert result.is_failure
        assert "Test validation error" in result.error

    def test_multiple_users_operations(self, repository: FlextLdapRepository) -> None:
        """Test operations with multiple users."""
        # Create and save multiple users
        users = []
        for i in range(3):
            user = FlextLdapUser(
                id=f"user{i}",
                dn=f"cn=user{i},ou=users,dc=example,dc=com",
                uid=f"user{i}",
                cn=f"User {i}",
                sn="User",
            )
            users.append(user)
            result = repository.save(user)
            assert result.is_success

        # Verify all users are saved
        assert len(repository._storage) == 3

        # Find each user
        for user in users:
            result = repository.find_by_id(user.id)
            assert result.is_success
            assert result.data == user

        # Delete one user
        result = repository.delete(users[1].id)
        assert result.is_success
        assert len(repository._storage) == 2

        # Verify deleted user is not found
        result = repository.find_by_id(users[1].id)
        assert result.is_success
        assert result.data is None
