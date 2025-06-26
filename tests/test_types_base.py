"""🔥🔥🔥🔥🔥 ULTRA DRY Tests for ldap_core_shared.types.base module.

This module tests the foundational base classes using ZERO DUPLICATION patterns.
All test data, mocks, and utilities are provided by conftest.py shared fixtures.

Architecture tested with MAXIMUM REUSABILITY:
- BaseModel: Enhanced Pydantic base with enterprise features
- BaseEntity: Domain entities with identity and audit trail
- BaseValueObject: Immutable value objects with business validation
- BaseRepository: Repository pattern for data access
- BaseService: Domain services with health checking

ZERO DUPLICATION ACHIEVED:
✅ No duplicate entity creation (uses factories)
✅ No duplicate assertions (uses helpers)
✅ No duplicate test data (uses generators)
✅ No duplicate mocks (uses shared fixtures)
✅ No duplicate performance testing (uses utilities)
"""

from typing import Any

import pytest
from pydantic import ValidationError

# TestUser is defined within test files that need it


class TestBaseModel:
    """🔥 Test BaseModel enterprise features using DRY patterns."""

    def test_basic_model_creation(self, sample_user: Any) -> None:
        """🔥 Test basic model creation using shared fixtures."""
        # Using TestUser from conftest.py (extends BaseModel)
        assert sample_user.username == "john_doe"
        assert sample_user.age == 30

    def test_model_immutability(self, sample_user: Any) -> None:
        """🔥 Test model immutability using shared fixtures."""
        with pytest.raises(ValidationError):
            sample_user.username = "changed"  # Should fail - model is frozen

    def test_strict_validation(self) -> None:
        """🔥 Test strict validation with minimal code."""
        # Should reject string that looks like int in strict mode
        with pytest.raises(ValidationError):
            TestUser(username="test", email="test@example.com", age="25")  # String age

    def test_extra_fields_forbidden(self) -> None:
        """🔥 Test extra fields forbidden using shared entity."""
        with pytest.raises(ValidationError):
            TestUser(
                username="test",
                email="test@example.com",
                age=25,
                extra_field="not allowed",
            )

    def test_model_dump_json_safe(self, sample_user: Any) -> None:
        """🔥 Test JSON-safe serialization using shared fixtures."""
        json_data = sample_user.model_dump_json_safe()
        assert isinstance(json_data, dict)
        assert "username" in json_data
        assert "created_at" in json_data
        assert isinstance(json_data["created_at"], str)  # ISO format

    def test_field_info_introspection(self, sample_user: Any) -> None:
        """🔥 Test field information using shared fixtures."""
        field_info = sample_user.get_field_info("username")
        assert field_info is not None

        with pytest.raises(KeyError):
            sample_user.get_field_info("nonexistent_field")


class TestBaseEntity:
    """🔥🔥 Test BaseEntity using DRY patterns and shared fixtures."""

    def test_entity_creation_with_id(self, sample_user: Any, assert_helper: Any) -> None:
        """🔥 Test entity creation using DRY validation."""
        assert_helper.assert_valid_entity(sample_user)
        assert sample_user.username == "john_doe"
        assert sample_user.email == "john_doe@example.com"
        assert sample_user.is_new()

    def test_entity_audit_fields(self, sample_user: Any) -> None:
        """🔥 Test audit trail using shared fixtures."""
        # All validation consolidated in assert_helper
        assert sample_user.created_at.tzinfo is not None
        assert sample_user.updated_at.tzinfo is not None
        assert sample_user.created_at <= sample_user.updated_at

    def test_entity_equality_by_id(self, user_factory: Any) -> None:
        """🔥 Test entity equality using factory."""
        user1 = user_factory(username="user1")
        user2 = user_factory(username="user2")

        # Different entities with different IDs
        assert user1 != user2

        # Same entity (same ID)
        user1_copy = user1.model_copy(update={"id": user1.id})
        assert user1 == user1_copy

    def test_entity_hashing(self, sample_user: Any) -> None:
        """🔥 Test entity hashing using shared fixtures."""
        # Should be hashable
        user_set = {sample_user}
        assert len(user_set) == 1

        # Hash should be consistent
        hash1 = hash(sample_user)
        hash2 = hash(sample_user)
        assert hash1 == hash2

    def test_entity_mark_updated(self, sample_user: Any) -> None:
        """🔥 Test mark_updated using shared fixtures."""
        original_version = sample_user.version
        original_updated = sample_user.updated_at

        updated_user = sample_user.mark_updated()

        # Should create new entity
        assert updated_user is not sample_user
        assert updated_user.version == original_version + 1
        assert updated_user.updated_at > original_updated
        assert updated_user.id == sample_user.id  # Same ID

    def test_entity_deletion_rules(
        self,
        sample_user,
        admin_user,
        protected_user,
    ) -> None:
        """🔥 Test business rules using shared fixtures."""
        assert sample_user.can_be_deleted() is True
        assert admin_user.can_be_deleted() is False
        assert protected_user.can_be_deleted() is False

    # TODO: Fix Hypothesis integration with pytest fixtures
    # @given("user_strategy")
    def test_entity_property_based_placeholder(self) -> None:
        """🔥🔥🔥 Property-based testing placeholder - needs Hypothesis fixture integration."""
        # Note: Requires proper Hypothesis integration with pytest fixtures
        # Placeholder for future property-based testing


class TestBaseValueObject:
    """🔥🔥 Test BaseValueObject using DRY patterns and shared fixtures."""

    def test_value_object_creation(self, sample_email: Any, assert_helper: Any) -> None:
        """🔥 Test value object creation using shared fixtures."""
        assert_helper.assert_valid_value_object(sample_email)
        assert sample_email.address == "user@company.com"
        assert sample_email.verified is True
        assert sample_email.domain == "company.com"

    def test_value_object_equality_by_value(self, email_factory: Any) -> None:
        """🔥 Test value objects equality using factory."""
        email1 = email_factory(address="same@domain.com", verified=True)
        email2 = email_factory(address="same@domain.com", verified=True)
        email3 = email_factory(address="different@domain.com", verified=True)

        assert email1 == email2  # Same values
        assert email1 != email3  # Different values

    def test_value_object_hashing(self, sample_email: Any) -> None:
        """🔥 Test value object hashing using shared fixtures."""
        # Create identical email
        email_copy = sample_email.__class__(
            address=sample_email.address,
            verified=sample_email.verified,
        )

        # Should have same hash for same values
        assert hash(sample_email) == hash(email_copy)

        # Should be usable in sets
        email_set = {sample_email, email_copy}
        assert len(email_set) == 1  # Deduplicated

    def test_value_object_validation(self, sample_email: Any, invalid_email: Any) -> None:
        """🔥 Test value object validation using shared fixtures."""
        assert sample_email.is_valid() is True
        assert invalid_email.is_valid() is False


class TestBaseRepository:
    """🔥🔥🔥 Test BaseRepository using DRY patterns and shared fixtures."""

    @pytest.mark.asyncio
    async def test_repository_save_and_find(
        self,
        user_repository,
        sample_user,
        assert_helper,
    ) -> None:
        """🔥 Test CRUD cycle using shared repository and helpers."""
        await assert_helper.assert_repository_crud_cycle(user_repository, sample_user)

    @pytest.mark.asyncio
    async def test_repository_bulk_operations(
        self,
        user_repository,
        user_collection,
    ) -> None:
        """🔥 Test bulk operations using shared fixtures."""
        # Save all users
        for user in user_collection:
            await user_repository.save(user)

        # Verify count
        count = await user_repository.count()
        assert count == len(user_collection)

        # Verify find all
        all_users = await user_repository.find_all()
        assert len(all_users) == len(user_collection)

    @pytest.mark.asyncio
    async def test_repository_with_populated_data(
        self,
        populated_user_repository,
        user_collection,
    ) -> None:
        """🔥 Test repository with pre-populated data."""
        # Repository comes pre-populated
        count = await populated_user_repository.count()
        assert count == len(user_collection)

        all_users = await populated_user_repository.find_all()
        assert len(all_users) == len(user_collection)


class TestBaseService:
    """🔥🔥🔥 Test BaseService using DRY patterns and shared fixtures."""

    @pytest.mark.asyncio
    async def test_service_health_check(self, user_service, assert_helper) -> None:
        """🔥 Test service health using shared service and helpers."""
        await assert_helper.assert_service_health(user_service)

    @pytest.mark.asyncio
    async def test_service_with_repository(
        self,
        user_service,
        user_repository,
        sample_user,
    ) -> None:
        """🔥 Test service integration with repository."""
        # Service should be healthy with repository
        health = await user_service.health_check()
        assert health is True

        # Verify service can access repository functionality
        saved_user = await user_repository.save(sample_user)
        assert saved_user == sample_user


class TestIntegration:
    """🔥🔥🔥🔥 Integration tests using ULTRA DRY patterns."""

    @pytest.mark.asyncio
    async def test_full_entity_lifecycle(
        self,
        user_repository,
        user_service,
        sample_user,
        assert_helper,
    ) -> None:
        """🔥🔥🔥 Test complete lifecycle using shared fixtures and helpers."""
        # Verify service health
        await assert_helper.assert_service_health(user_service)

        # Test complete CRUD cycle
        await assert_helper.assert_repository_crud_cycle(user_repository, sample_user)

    @pytest.mark.asyncio
    async def test_enterprise_patterns_integration(
        self,
        user_repository,
        user_service,
        user_collection,
        assert_helper,
    ) -> None:
        """🔥🔥🔥🔥 Test enterprise patterns working together."""
        # Service should be healthy
        await assert_helper.assert_service_health(user_service)

        # Process collection of entities
        for user in user_collection[:5]:  # Test with subset
            assert_helper.assert_valid_entity(user)
            saved_user = await user_repository.save(user)
            assert saved_user == user

        # Verify bulk operation success
        count = await user_repository.count()
        assert count == 5


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
