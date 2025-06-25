"""Comprehensive tests for generic type patterns and implementations.

This module tests the generic type patterns that enable reusable, type-safe
implementations while eliminating code duplication through inheritance.

Test categories:
- Result pattern for error handling
- Option pattern for null safety
- Repository pattern implementation
- Service pattern implementation
- Specification pattern for business rules
- Async iterator patterns
- Generic type composition and interaction
"""

from __future__ import annotations

import uuid

import pytest
from hypothesis import given
from hypothesis import strategies as st

from ldap_core_shared.types.base import BaseEntity, BaseValueObject
from ldap_core_shared.types.generics import (
    AsyncIteratorWrapper,
    Option,
    Repository,
    Result,
    Service,
    Specification,
)

# ===== TEST FIXTURES AND IMPLEMENTATIONS =====


class TestEntity(BaseEntity):
    """Test entity for generic testing."""

    name: str
    value: int = 0
    active: bool = True

    def can_be_deleted(self) -> bool:
        """Simple business rule for deletion."""
        return not self.active or self.value == 0


class TestValueObject(BaseValueObject):
    """Test value object for generic testing."""

    x: float
    y: float

    def is_valid(self) -> bool:
        """Validate coordinates."""
        return -180 <= self.x <= 180 and -90 <= self.y <= 90


class TestSpecification(Specification[TestEntity]):
    """Test specification implementation."""

    def __init__(self, min_value: int) -> None:
        """Initialize with minimum value requirement."""
        self._min_value = min_value

    def is_satisfied_by(self, candidate: TestEntity) -> bool:
        """Check if entity satisfies minimum value requirement."""
        return candidate.value >= self._min_value

    def and_(self, other: Specification[TestEntity]) -> Specification[TestEntity]:
        """Combine with AND logic."""
        return AndSpecification(self, other)

    def or_(self, other: Specification[TestEntity]) -> Specification[TestEntity]:
        """Combine with OR logic."""
        return OrSpecification(self, other)

    def not_(self) -> Specification[TestEntity]:
        """Negate specification."""
        return NotSpecification(self)


class AndSpecification(Specification[TestEntity]):
    """AND combination of specifications."""

    def __init__(
        self,
        left: Specification[TestEntity],
        right: Specification[TestEntity],
    ) -> None:
        """Initialize with two specifications."""
        self._left = left
        self._right = right

    def is_satisfied_by(self, candidate: TestEntity) -> bool:
        """Check if both specifications are satisfied."""
        return self._left.is_satisfied_by(candidate) and self._right.is_satisfied_by(
            candidate,
        )

    def and_(self, other: Specification[TestEntity]) -> Specification[TestEntity]:
        """Combine with another specification."""
        return AndSpecification(self, other)

    def or_(self, other: Specification[TestEntity]) -> Specification[TestEntity]:
        """Combine with OR logic."""
        return OrSpecification(self, other)

    def not_(self) -> Specification[TestEntity]:
        """Negate specification."""
        return NotSpecification(self)


class OrSpecification(Specification[TestEntity]):
    """OR combination of specifications."""

    def __init__(
        self,
        left: Specification[TestEntity],
        right: Specification[TestEntity],
    ) -> None:
        """Initialize with two specifications."""
        self._left = left
        self._right = right

    def is_satisfied_by(self, candidate: TestEntity) -> bool:
        """Check if either specification is satisfied."""
        return self._left.is_satisfied_by(candidate) or self._right.is_satisfied_by(
            candidate,
        )

    def and_(self, other: Specification[TestEntity]) -> Specification[TestEntity]:
        """Combine with AND logic."""
        return AndSpecification(self, other)

    def or_(self, other: Specification[TestEntity]) -> Specification[TestEntity]:
        """Combine with another specification."""
        return OrSpecification(self, other)

    def not_(self) -> Specification[TestEntity]:
        """Negate specification."""
        return NotSpecification(self)


class NotSpecification(Specification[TestEntity]):
    """NOT negation of specification."""

    def __init__(self, spec: Specification[TestEntity]) -> None:
        """Initialize with specification to negate."""
        self._spec = spec

    def is_satisfied_by(self, candidate: TestEntity) -> bool:
        """Check if specification is NOT satisfied."""
        return not self._spec.is_satisfied_by(candidate)

    def and_(self, other: Specification[TestEntity]) -> Specification[TestEntity]:
        """Combine with AND logic."""
        return AndSpecification(self, other)

    def or_(self, other: Specification[TestEntity]) -> Specification[TestEntity]:
        """Combine with OR logic."""
        return OrSpecification(self, other)

    def not_(self) -> Specification[TestEntity]:
        """Double negation returns original."""
        return self._spec


# ===== RESULT PATTERN TESTS =====


class TestResultPattern:
    """Test suite for Result pattern implementation."""

    def test_success_result_creation(self) -> None:
        """Test creating successful Result."""
        result = Result.success(42)

        assert result.is_success()
        assert not result.is_error()
        assert result.unwrap() == 42

    def test_error_result_creation(self) -> None:
        """Test creating error Result."""
        result = Result.error("Something went wrong")

        assert result.is_error()
        assert not result.is_success()
        assert result.unwrap_error() == "Something went wrong"

    def test_result_constructor_validation(self) -> None:
        """Test Result constructor validates input."""
        # Both value and error should raise ValueError
        with pytest.raises(ValueError, match="exactly one of value or error"):
            Result(value=42, error="error")

        # Neither value nor error should raise ValueError
        with pytest.raises(ValueError, match="exactly one of value or error"):
            Result()

    def test_unwrap_success(self) -> None:
        """Test unwrapping success value."""
        result = Result.success("test_value")
        assert result.unwrap() == "test_value"

    def test_unwrap_error_on_success(self) -> None:
        """Test unwrapping error on success Result raises ValueError."""
        result = Result.success(42)

        with pytest.raises(
            ValueError,
            match="Called unwrap_error\\(\\) on success Result",
        ):
            result.unwrap_error()

    def test_unwrap_error(self) -> None:
        """Test unwrapping error value."""
        result = Result.error("test_error")
        assert result.unwrap_error() == "test_error"

    def test_unwrap_on_error(self) -> None:
        """Test unwrapping value on error Result raises ValueError."""
        result = Result.error("error")

        with pytest.raises(ValueError, match="Called unwrap\\(\\) on error Result"):
            result.unwrap()

    def test_unwrap_or_with_success(self) -> None:
        """Test unwrap_or with success Result."""
        result = Result.success(42)
        assert result.unwrap_or(99) == 42

    def test_unwrap_or_with_error(self) -> None:
        """Test unwrap_or with error Result."""
        result = Result.error("error")
        assert result.unwrap_or(99) == 99

    def test_map_success(self) -> None:
        """Test mapping over success Result."""
        result = Result.success(5)
        mapped = result.map(lambda x: x * 2)

        assert mapped.is_success()
        assert mapped.unwrap() == 10

    def test_map_error(self) -> None:
        """Test mapping over error Result."""
        result = Result.error("original_error")
        mapped = result.map(lambda x: x * 2)

        assert mapped.is_error()
        assert mapped.unwrap_error() == "original_error"

    def test_map_with_exception(self) -> None:
        """Test mapping function that raises exception."""
        result = Result.success(5)

        def failing_function(x: int) -> int:
            msg = "Function failed"
            raise ValueError(msg)

        mapped = result.map(failing_function)

        assert mapped.is_error()
        assert isinstance(mapped.unwrap_error(), ValueError)

    def test_flat_map_success(self) -> None:
        """Test flat mapping over success Result."""
        result = Result.success(5)

        def double_if_positive(x: int) -> Result[int, str]:
            if x > 0:
                return Result.success(x * 2)
            return Result.error("Negative number")

        mapped = result.flat_map(double_if_positive)

        assert mapped.is_success()
        assert mapped.unwrap() == 10

    def test_flat_map_success_to_error(self) -> None:
        """Test flat mapping success that returns error."""
        result = Result.success(-5)

        def double_if_positive(x: int) -> Result[int, str]:
            if x > 0:
                return Result.success(x * 2)
            return Result.error("Negative number")

        mapped = result.flat_map(double_if_positive)

        assert mapped.is_error()
        assert mapped.unwrap_error() == "Negative number"

    def test_flat_map_error(self) -> None:
        """Test flat mapping over error Result."""
        result = Result.error("original_error")

        def double_if_positive(x: int) -> Result[int, str]:
            return Result.success(x * 2)

        mapped = result.flat_map(double_if_positive)

        assert mapped.is_error()
        assert mapped.unwrap_error() == "original_error"

    @given(value=st.integers())
    def test_result_properties(self, value: int) -> None:
        """Property-based test for Result behavior."""
        success_result = Result.success(value)
        error_result = Result.error("error")

        # Success properties
        assert success_result.is_success()
        assert not success_result.is_error()
        assert success_result.unwrap() == value
        assert success_result.unwrap_or(999) == value

        # Error properties
        assert error_result.is_error()
        assert not error_result.is_success()
        assert error_result.unwrap_or(999) == 999


# ===== OPTION PATTERN TESTS =====


class TestOptionPattern:
    """Test suite for Option pattern implementation."""

    def test_some_creation(self) -> None:
        """Test creating Some Option."""
        option = Option.some(42)

        assert option.is_some()
        assert not option.is_none()
        assert option.unwrap() == 42

    def test_none_creation(self) -> None:
        """Test creating None Option."""
        option = Option.none()

        assert option.is_none()
        assert not option.is_some()

    def test_unwrap_some(self) -> None:
        """Test unwrapping Some value."""
        option = Option.some("test_value")
        assert option.unwrap() == "test_value"

    def test_unwrap_none(self) -> None:
        """Test unwrapping None Option raises ValueError."""
        option = Option.none()

        with pytest.raises(ValueError, match="Called unwrap\\(\\) on None Option"):
            option.unwrap()

    def test_unwrap_or_with_some(self) -> None:
        """Test unwrap_or with Some Option."""
        option = Option.some(42)
        assert option.unwrap_or(99) == 42

    def test_unwrap_or_with_none(self) -> None:
        """Test unwrap_or with None Option."""
        option = Option.none()
        assert option.unwrap_or(99) == 99

    def test_map_some(self) -> None:
        """Test mapping over Some Option."""
        option = Option.some(5)
        mapped = option.map(lambda x: x * 2)

        assert mapped.is_some()
        assert mapped.unwrap() == 10

    def test_map_none(self) -> None:
        """Test mapping over None Option."""
        option = Option.none()
        mapped = option.map(lambda x: x * 2)

        assert mapped.is_none()

    def test_flat_map_some(self) -> None:
        """Test flat mapping over Some Option."""
        option = Option.some(5)

        def double_if_positive(x: int) -> Option[int]:
            if x > 0:
                return Option.some(x * 2)
            return Option.none()

        mapped = option.flat_map(double_if_positive)

        assert mapped.is_some()
        assert mapped.unwrap() == 10

    def test_flat_map_some_to_none(self) -> None:
        """Test flat mapping Some that returns None."""
        option = Option.some(-5)

        def double_if_positive(x: int) -> Option[int]:
            if x > 0:
                return Option.some(x * 2)
            return Option.none()

        mapped = option.flat_map(double_if_positive)

        assert mapped.is_none()

    def test_flat_map_none(self) -> None:
        """Test flat mapping over None Option."""
        option = Option.none()

        def double_if_positive(x: int) -> Option[int]:
            return Option.some(x * 2)

        mapped = option.flat_map(double_if_positive)

        assert mapped.is_none()

    @given(value=st.integers())
    def test_option_properties(self, value: int) -> None:
        """Property-based test for Option behavior."""
        some_option = Option.some(value)
        none_option = Option.none()

        # Some properties
        assert some_option.is_some()
        assert not some_option.is_none()
        assert some_option.unwrap() == value
        assert some_option.unwrap_or(999) == value

        # None properties
        assert none_option.is_none()
        assert not none_option.is_some()
        assert none_option.unwrap_or(999) == 999


# ===== REPOSITORY PATTERN TESTS =====


class TestRepositoryPattern:
    """Test suite for Repository pattern implementation."""

    @pytest.fixture
    def repository(self) -> Repository[TestEntity]:
        """Provide repository instance for tests."""
        return Repository[TestEntity]()

    @pytest.fixture
    def sample_entity(self) -> TestEntity:
        """Provide sample entity for tests."""
        return TestEntity(name="Test Entity", value=42)

    async def test_repository_save_and_find(
        self,
        repository: Repository[TestEntity],
        sample_entity: TestEntity,
    ) -> None:
        """Test repository save and find operations."""
        # Save entity
        saved_entity = await repository.save(sample_entity)
        assert saved_entity == sample_entity

        # Find by ID
        found_entity = await repository.find_by_id(sample_entity.id)
        assert found_entity == sample_entity
        assert found_entity is not None

    async def test_repository_find_by_id_not_found(
        self,
        repository: Repository[TestEntity],
    ) -> None:
        """Test finding non-existent entity returns None."""
        non_existent_id = uuid.uuid4()
        found_entity = await repository.find_by_id(non_existent_id)
        assert found_entity is None

    async def test_repository_delete(
        self,
        repository: Repository[TestEntity],
        sample_entity: TestEntity,
    ) -> None:
        """Test repository delete operation."""
        # Save entity first
        await repository.save(sample_entity)

        # Delete entity
        deleted = await repository.delete(sample_entity)
        assert deleted is True

        # Verify entity is gone
        found_entity = await repository.find_by_id(sample_entity.id)
        assert found_entity is None

    async def test_repository_delete_non_existent(
        self,
        repository: Repository[TestEntity],
        sample_entity: TestEntity,
    ) -> None:
        """Test deleting non-existent entity returns False."""
        deleted = await repository.delete(sample_entity)
        assert deleted is False

    async def test_repository_find_all(
        self,
        repository: Repository[TestEntity],
    ) -> None:
        """Test finding all entities."""
        # Initially empty
        all_entities = await repository.find_all()
        assert len(all_entities) == 0

        # Add entities
        entity1 = TestEntity(name="Entity 1", value=1)
        entity2 = TestEntity(name="Entity 2", value=2)

        await repository.save(entity1)
        await repository.save(entity2)

        # Find all
        all_entities = await repository.find_all()
        assert len(all_entities) == 2
        assert entity1 in all_entities
        assert entity2 in all_entities

    async def test_repository_count(
        self,
        repository: Repository[TestEntity],
    ) -> None:
        """Test counting entities."""
        # Initially empty
        count = await repository.count()
        assert count == 0

        # Add entities
        entity1 = TestEntity(name="Entity 1")
        entity2 = TestEntity(name="Entity 2")

        await repository.save(entity1)
        assert await repository.count() == 1

        await repository.save(entity2)
        assert await repository.count() == 2


# ===== SERVICE PATTERN TESTS =====


class TestServicePattern:
    """Test suite for Service pattern implementation."""

    @pytest.fixture
    def repository(self) -> Repository[TestEntity]:
        """Provide repository instance for tests."""
        return Repository[TestEntity]()

    @pytest.fixture
    def service(self, repository: Repository[TestEntity]) -> Service[TestEntity]:
        """Provide service instance for tests."""
        return Service[TestEntity](repository)

    @pytest.fixture
    def sample_entity(self) -> TestEntity:
        """Provide sample entity for tests."""
        return TestEntity(name="Test Entity", value=42)

    async def test_service_health_check(self, service: Service[TestEntity]) -> None:
        """Test service health check."""
        health = await service.health_check()
        assert health is True

    async def test_service_get_by_id_found(
        self,
        service: Service[TestEntity],
        sample_entity: TestEntity,
    ) -> None:
        """Test getting entity by ID when found."""
        # Save entity first
        await service._repository.save(sample_entity)

        # Get by ID
        option = await service.get_by_id(sample_entity.id)
        assert option.is_some()
        assert option.unwrap() == sample_entity

    async def test_service_get_by_id_not_found(
        self,
        service: Service[TestEntity],
    ) -> None:
        """Test getting entity by ID when not found."""
        non_existent_id = uuid.uuid4()
        option = await service.get_by_id(non_existent_id)
        assert option.is_none()

    async def test_service_create_success(
        self,
        service: Service[TestEntity],
        sample_entity: TestEntity,
    ) -> None:
        """Test successful entity creation."""
        result = await service.create(sample_entity)

        assert result.is_success()
        created_entity = result.unwrap()
        assert created_entity == sample_entity

        # Verify entity was saved
        found_entity = await service._repository.find_by_id(sample_entity.id)
        assert found_entity == sample_entity

    async def test_service_create_validation_failure(
        self,
        service: Service[TestEntity],
    ) -> None:
        """Test entity creation with validation failure."""
        # Create entity that fails validation (active=True means can't be deleted)
        invalid_entity = TestEntity(name="Invalid", value=10, active=True)

        result = await service.create(invalid_entity)

        assert result.is_error()
        assert "validation failed" in result.unwrap_error()

    async def test_service_update_success(
        self,
        service: Service[TestEntity],
        sample_entity: TestEntity,
    ) -> None:
        """Test successful entity update."""
        # Save entity first
        await service._repository.save(sample_entity)

        # Update entity
        updated_entity = sample_entity.model_copy(update={"name": "Updated Name"})
        result = await service.update(updated_entity)

        assert result.is_success()
        returned_entity = result.unwrap()
        assert returned_entity.name == "Updated Name"
        assert returned_entity.version == 2

    async def test_service_update_not_found(
        self,
        service: Service[TestEntity],
        sample_entity: TestEntity,
    ) -> None:
        """Test updating non-existent entity."""
        result = await service.update(sample_entity)

        assert result.is_error()
        assert "not found" in result.unwrap_error()

    async def test_service_delete_success(
        self,
        service: Service[TestEntity],
        sample_entity: TestEntity,
    ) -> None:
        """Test successful entity deletion."""
        # Save entity first
        await service._repository.save(sample_entity)

        # Delete entity
        result = await service.delete(sample_entity.id)

        assert result.is_success()
        assert result.unwrap() is True

        # Verify entity is gone
        found_entity = await service._repository.find_by_id(sample_entity.id)
        assert found_entity is None

    async def test_service_delete_not_found(
        self,
        service: Service[TestEntity],
    ) -> None:
        """Test deleting non-existent entity."""
        non_existent_id = uuid.uuid4()
        result = await service.delete(non_existent_id)

        assert result.is_error()
        assert "not found" in result.unwrap_error()

    async def test_service_delete_cannot_be_deleted(
        self,
        service: Service[TestEntity],
    ) -> None:
        """Test deleting entity that cannot be deleted."""
        # Create entity that cannot be deleted (active=True and value>0)
        undeletable_entity = TestEntity(name="Undeletable", value=10, active=True)
        await service._repository.save(undeletable_entity)

        result = await service.delete(undeletable_entity.id)

        assert result.is_error()
        assert "cannot be deleted" in result.unwrap_error()


# ===== SPECIFICATION PATTERN TESTS =====


class TestSpecificationPattern:
    """Test suite for Specification pattern implementation."""

    def test_simple_specification(self) -> None:
        """Test simple specification evaluation."""
        spec = TestSpecification(min_value=10)

        valid_entity = TestEntity(name="Valid", value=15)
        invalid_entity = TestEntity(name="Invalid", value=5)

        assert spec.is_satisfied_by(valid_entity)
        assert not spec.is_satisfied_by(invalid_entity)

    def test_and_specification(self) -> None:
        """Test AND combination of specifications."""
        min_value_spec = TestSpecification(min_value=10)
        TestSpecification(min_value=-100)  # Acts as max by negating

        class MaxValueSpec(Specification[TestEntity]):
            def __init__(self, max_value: int) -> None:
                self._max_value = max_value

            def is_satisfied_by(self, candidate: TestEntity) -> bool:
                return candidate.value <= self._max_value

            def and_(
                self,
                other: Specification[TestEntity],
            ) -> Specification[TestEntity]:
                return AndSpecification(self, other)

            def or_(
                self,
                other: Specification[TestEntity],
            ) -> Specification[TestEntity]:
                return OrSpecification(self, other)

            def not_(self) -> Specification[TestEntity]:
                return NotSpecification(self)

        max_spec = MaxValueSpec(max_value=50)
        combined_spec = min_value_spec.and_(max_spec)

        valid_entity = TestEntity(name="Valid", value=25)  # 10 <= 25 <= 50
        invalid_low = TestEntity(name="TooLow", value=5)  # 5 < 10
        invalid_high = TestEntity(name="TooHigh", value=60)  # 60 > 50

        assert combined_spec.is_satisfied_by(valid_entity)
        assert not combined_spec.is_satisfied_by(invalid_low)
        assert not combined_spec.is_satisfied_by(invalid_high)

    def test_or_specification(self) -> None:
        """Test OR combination of specifications."""
        low_value_spec = TestSpecification(min_value=100)  # High threshold

        class NegativeValueSpec(Specification[TestEntity]):
            def is_satisfied_by(self, candidate: TestEntity) -> bool:
                return candidate.value < 0

            def and_(
                self,
                other: Specification[TestEntity],
            ) -> Specification[TestEntity]:
                return AndSpecification(self, other)

            def or_(
                self,
                other: Specification[TestEntity],
            ) -> Specification[TestEntity]:
                return OrSpecification(self, other)

            def not_(self) -> Specification[TestEntity]:
                return NotSpecification(self)

        negative_spec = NegativeValueSpec()
        combined_spec = low_value_spec.or_(negative_spec)

        high_value_entity = TestEntity(name="High", value=150)  # Satisfies first spec
        negative_entity = TestEntity(name="Negative", value=-5)  # Satisfies second spec
        middle_entity = TestEntity(name="Middle", value=50)  # Satisfies neither

        assert combined_spec.is_satisfied_by(high_value_entity)
        assert combined_spec.is_satisfied_by(negative_entity)
        assert not combined_spec.is_satisfied_by(middle_entity)

    def test_not_specification(self) -> None:
        """Test NOT negation of specification."""
        spec = TestSpecification(min_value=10)
        negated_spec = spec.not_()

        valid_for_original = TestEntity(name="HighValue", value=15)
        invalid_for_original = TestEntity(name="LowValue", value=5)

        # Negated spec should have opposite results
        assert not negated_spec.is_satisfied_by(valid_for_original)
        assert negated_spec.is_satisfied_by(invalid_for_original)

    def test_double_negation(self) -> None:
        """Test double negation returns to original."""
        spec = TestSpecification(min_value=10)
        double_negated = spec.not_().not_()

        entity = TestEntity(name="Test", value=15)

        # Double negation should behave like original
        assert spec.is_satisfied_by(entity) == double_negated.is_satisfied_by(entity)

    def test_complex_specification_composition(self) -> None:
        """Test complex composition of specifications."""
        min_spec = TestSpecification(min_value=10)

        class ActiveSpec(Specification[TestEntity]):
            def is_satisfied_by(self, candidate: TestEntity) -> bool:
                return candidate.active

            def and_(
                self,
                other: Specification[TestEntity],
            ) -> Specification[TestEntity]:
                return AndSpecification(self, other)

            def or_(
                self,
                other: Specification[TestEntity],
            ) -> Specification[TestEntity]:
                return OrSpecification(self, other)

            def not_(self) -> Specification[TestEntity]:
                return NotSpecification(self)

        active_spec = ActiveSpec()

        # (min_value >= 10 AND active) OR NOT active
        complex_spec = (min_spec.and_(active_spec)).or_(active_spec.not_())

        active_high = TestEntity(
            name="ActiveHigh",
            value=20,
            active=True,
        )  # Satisfies first part
        active_low = TestEntity(
            name="ActiveLow",
            value=5,
            active=True,
        )  # Doesn't satisfy first part
        inactive_high = TestEntity(
            name="InactiveHigh",
            value=20,
            active=False,
        )  # Satisfies second part
        inactive_low = TestEntity(
            name="InactiveLow",
            value=5,
            active=False,
        )  # Satisfies second part

        assert complex_spec.is_satisfied_by(active_high)
        assert not complex_spec.is_satisfied_by(active_low)
        assert complex_spec.is_satisfied_by(inactive_high)
        assert complex_spec.is_satisfied_by(inactive_low)


# ===== ASYNC ITERATOR WRAPPER TESTS =====


class TestAsyncIteratorWrapper:
    """Test suite for AsyncIteratorWrapper implementation."""

    async def async_range(self, n: int) -> AsyncIterator[int]:
        """Helper to create async iterator."""
        for i in range(n):
            yield i

    async def test_filter_operation(self) -> None:
        """Test filtering async iterator."""
        wrapper = AsyncIteratorWrapper(self.async_range(10))

        filtered_items = []
        async for item in wrapper.filter(lambda x: x % 2 == 0):
            filtered_items.append(item)

        assert filtered_items == [0, 2, 4, 6, 8]

    async def test_map_operation(self) -> None:
        """Test mapping async iterator."""
        wrapper = AsyncIteratorWrapper(self.async_range(5))

        mapped_items = []
        async for item in wrapper.map(lambda x: x * 2):
            mapped_items.append(item)

        assert mapped_items == [0, 2, 4, 6, 8]

    async def test_take_operation(self) -> None:
        """Test taking limited items from async iterator."""
        wrapper = AsyncIteratorWrapper(self.async_range(10))

        taken_items = []
        async for item in wrapper.take(3):
            taken_items.append(item)

        assert taken_items == [0, 1, 2]

    async def test_take_more_than_available(self) -> None:
        """Test taking more items than available."""
        wrapper = AsyncIteratorWrapper(self.async_range(3))

        taken_items = []
        async for item in wrapper.take(10):
            taken_items.append(item)

        assert taken_items == [0, 1, 2]

    async def test_to_list_operation(self) -> None:
        """Test converting async iterator to list."""
        wrapper = AsyncIteratorWrapper(self.async_range(5))
        items = await wrapper.to_list()

        assert items == [0, 1, 2, 3, 4]

    async def test_batch_operation(self) -> None:
        """Test batching async iterator."""
        wrapper = AsyncIteratorWrapper(self.async_range(7))

        batches = []
        async for batch in wrapper.batch(3):
            batches.append(batch)

        assert batches == [[0, 1, 2], [3, 4, 5], [6]]

    async def test_batch_exact_size(self) -> None:
        """Test batching with exact size matches."""
        wrapper = AsyncIteratorWrapper(self.async_range(6))

        batches = []
        async for batch in wrapper.batch(2):
            batches.append(batch)

        assert batches == [[0, 1], [2, 3], [4, 5]]

    async def test_empty_iterator(self) -> None:
        """Test operations on empty iterator."""

        async def empty_iterator() -> AsyncIterator[int]:
            return
            yield  # Make it a generator function

        wrapper = AsyncIteratorWrapper(empty_iterator())

        # All operations should handle empty iterator gracefully
        filtered = await AsyncIteratorWrapper(wrapper.filter(lambda x: True)).to_list()
        mapped = await AsyncIteratorWrapper(wrapper.map(lambda x: x * 2)).to_list()
        taken = await AsyncIteratorWrapper(wrapper.take(5)).to_list()
        batched = [batch async for batch in wrapper.batch(2)]

        assert filtered == []
        assert mapped == []
        assert taken == []
        assert batched == []


# ===== INTEGRATION TESTS =====


class TestGenericPatternIntegration:
    """Integration tests for generic patterns working together."""

    async def test_service_with_result_and_option_patterns(self) -> None:
        """Test service using Result and Option patterns together."""
        repository = Repository[TestEntity]()
        service = Service[TestEntity](repository)

        # Create entity
        entity = TestEntity(name="Integration Test", value=42)
        create_result = await service.create(entity)

        assert create_result.is_success()
        created_entity = create_result.unwrap()

        # Get entity using Option pattern
        get_option = await service.get_by_id(created_entity.id)
        assert get_option.is_some()
        assert get_option.unwrap() == created_entity

        # Update entity using Result pattern
        updated_entity = created_entity.model_copy(update={"name": "Updated"})
        update_result = await service.update(updated_entity)

        assert update_result.is_success()
        final_entity = update_result.unwrap()
        assert final_entity.name == "Updated"
        assert final_entity.version == 2

    async def test_repository_with_specifications(self) -> None:
        """Test repository with specification pattern filtering."""
        repository = Repository[TestEntity]()

        # Add test entities
        entities = [
            TestEntity(name="Low", value=5, active=True),
            TestEntity(name="Medium", value=15, active=True),
            TestEntity(name="High", value=25, active=False),
            TestEntity(name="VeryHigh", value=35, active=True),
        ]

        for entity in entities:
            await repository.save(entity)

        # Create specifications
        min_value_spec = TestSpecification(min_value=10)

        class ActiveSpec(Specification[TestEntity]):
            def is_satisfied_by(self, candidate: TestEntity) -> bool:
                return candidate.active

            def and_(
                self,
                other: Specification[TestEntity],
            ) -> Specification[TestEntity]:
                return AndSpecification(self, other)

            def or_(
                self,
                other: Specification[TestEntity],
            ) -> Specification[TestEntity]:
                return OrSpecification(self, other)

            def not_(self) -> Specification[TestEntity]:
                return NotSpecification(self)

        active_spec = ActiveSpec()
        combined_spec = min_value_spec.and_(active_spec)

        # Filter entities using specification
        all_entities = await repository.find_all()
        filtered_entities = [
            e for e in all_entities if combined_spec.is_satisfied_by(e)
        ]

        # Should match Medium (15, active) and VeryHigh (35, active)
        assert len(filtered_entities) == 2
        assert "Medium" in [e.name for e in filtered_entities]
        assert "VeryHigh" in [e.name for e in filtered_entities]

    async def test_async_iterator_with_repository(self) -> None:
        """Test async iterator patterns with repository data."""
        repository = Repository[TestEntity]()

        # Add test entities
        for i in range(10):
            entity = TestEntity(name=f"Entity{i}", value=i)
            await repository.save(entity)

        # Create async iterator from repository data
        async def entity_iterator() -> AsyncIterator[TestEntity]:
            entities = await repository.find_all()
            for entity in entities:
                yield entity

        wrapper = AsyncIteratorWrapper(entity_iterator())

        # Filter and map entities
        high_value_names = []
        async for name in wrapper.filter(lambda e: e.value >= 5).map(lambda e: e.name):
            high_value_names.append(name)

        # Should get entities with value >= 5
        expected_names = [f"Entity{i}" for i in range(5, 10)]
        assert len(high_value_names) == 5
        assert all(name in expected_names for name in high_value_names)


# ===== PROPERTY-BASED TESTS =====


class TestGenericPatternProperties:
    """Property-based tests for generic patterns."""

    @given(value=st.integers())
    def test_result_map_identity(self, value: int) -> None:
        """Property test: mapping with identity function should preserve value."""
        result = Result.success(value)
        mapped = result.map(lambda x: x)

        assert mapped.is_success()
        assert mapped.unwrap() == value

    @given(value=st.integers())
    def test_option_map_identity(self, value: int) -> None:
        """Property test: mapping Option with identity should preserve value."""
        option = Option.some(value)
        mapped = option.map(lambda x: x)

        assert mapped.is_some()
        assert mapped.unwrap() == value

    @given(values=st.lists(st.integers(), min_size=0, max_size=20))
    async def test_async_iterator_to_list_preserves_order(
        self,
        values: list[int],
    ) -> None:
        """Property test: async iterator should preserve order when converted to list."""

        async def value_iterator() -> AsyncIterator[int]:
            for value in values:
                yield value

        wrapper = AsyncIteratorWrapper(value_iterator())
        result = await wrapper.to_list()

        assert result == values

    @given(
        values=st.lists(st.integers(), min_size=1, max_size=10),
        take_count=st.integers(min_value=0, max_value=15),
    )
    async def test_take_operation_properties(
        self,
        values: list[int],
        take_count: int,
    ) -> None:
        """Property test: take operation should respect count limits."""

        async def value_iterator() -> AsyncIterator[int]:
            for value in values:
                yield value

        wrapper = AsyncIteratorWrapper(value_iterator())
        taken = await AsyncIteratorWrapper(wrapper.take(take_count)).to_list()

        expected_count = min(len(values), take_count)
        assert len(taken) == expected_count
        assert taken == values[:expected_count]
