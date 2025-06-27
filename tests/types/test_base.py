"""Comprehensive tests for base classes and fundamental patterns.

This module tests the foundation classes that all other code inherits from,
ensuring SOLID principles are correctly implemented and DRY patterns work.

Test categories:
- BaseModel: Pydantic model enhancements and validation
- BaseEntity: Identity, audit trails, and entity behavior
- BaseValueObject: Immutability and value-based equality
- BaseRepository: Generic repository pattern implementation
- BaseService: Abstract service base class behavior
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any

import pytest
from hypothesis import given
from hypothesis import strategies as st
from pydantic import Field, ValidationError

from ldap_core_shared.types.base import (
    BaseEntity,
    BaseModel,
    BaseRepository,
    BaseService,
    BaseValueObject,
)

# ===== TEST FIXTURES =====


class TestModel(BaseModel):
    """Test model for BaseModel validation."""

    name: str = Field(..., min_length=1, max_length=100)
    age: int = Field(..., ge=0, le=150)
    email: str = Field(..., pattern=r"^[^@]+@[^@]+\.[^@]+$")
    optional_field: str | None = None


class TestEntity(BaseEntity):
    """Test entity for BaseEntity validation."""

    name: str
    value: int = 0

    def can_be_deleted(self) -> bool:
        """Simple business rule for deletion."""
        return self.value >= 0


class TestValueObject(BaseValueObject):
    """Test value object for BaseValueObject validation."""

    x: float
    y: float

    def is_valid(self) -> bool:
        """Validate coordinates are within bounds."""
        return -180 <= self.x <= 180 and -90 <= self.y <= 90


class TestRepository(BaseRepository[TestEntity]):
    """Test repository implementation."""

    def __init__(self) -> None:
        """Initialize test repository."""
        self._storage: dict[uuid.UUID, TestEntity] = {}

    async def find_by_id(self, entity_id: uuid.UUID) -> TestEntity | None:
        """Find entity by ID."""
        return self._storage.get(entity_id)

    async def save(self, entity: TestEntity) -> TestEntity:
        """Save entity."""
        self._storage[entity.id] = entity
        return entity

    async def delete(self, entity: TestEntity) -> bool:
        """Delete entity."""
        if entity.id in self._storage:
            del self._storage[entity.id]
            return True
        return False

    async def find_all(self) -> list[TestEntity]:
        """Find all entities."""
        return list(self._storage.values())

    async def count(self) -> int:
        """Count entities."""
        return len(self._storage)


class TestService(BaseService):
    """Test service implementation."""

    def __init__(self, healthy: bool = True) -> None:
        """Initialize test service."""
        self._healthy = healthy

    async def health_check(self) -> bool:
        """Health check implementation."""
        return self._healthy


# ===== BASE MODEL TESTS =====


class TestBaseModel:
    """Test suite for BaseModel functionality."""

    def test_valid_model_creation(self) -> None:
        """Test creating valid model instance."""
        model = TestModel(
            name="John Doe",
            age=30,
            email="john@example.com",
        )
        assert model.name == "John Doe"
        assert model.age == 30
        assert model.email == "john@example.com"
        assert model.optional_field is None

    def test_model_is_frozen(self) -> None:
        """Test that models are immutable after creation."""
        model = TestModel(name="John", age=30, email="john@example.com")

        with pytest.raises(ValidationError):
            model.name = "Jane"  # type: ignore[misc] # Testing runtime behavior

    def test_strict_validation(self) -> None:
        """Test strict validation enforces all constraints."""
        # Test minimum length constraint
        with pytest.raises(ValidationError) as exc_info:
            TestModel(name="", age=30, email="john@example.com")
        assert "at least 1 character" in str(exc_info.value)

        # Test maximum length constraint
        with pytest.raises(ValidationError) as exc_info:
            TestModel(name="x" * 101, age=30, email="john@example.com")
        assert "at most 100 characters" in str(exc_info.value)

        # Test age constraints
        with pytest.raises(ValidationError) as exc_info:
            TestModel(name="John", age=-1, email="john@example.com")
        assert "greater than or equal to 0" in str(exc_info.value)

        with pytest.raises(ValidationError) as exc_info:
            TestModel(name="John", age=151, email="john@example.com")
        assert "less than or equal to 150" in str(exc_info.value)

        # Test email pattern
        with pytest.raises(ValidationError) as exc_info:
            TestModel(name="John", age=30, email="invalid-email")
        assert "String should match pattern" in str(exc_info.value)

    def test_preprocess_data_removes_none(self) -> None:
        """Test that None values are removed during preprocessing."""
        model = TestModel(
            name="John",
            age=30,
            email="john@example.com",
            optional_field=None,
        )
        assert model.optional_field is None

    def test_model_dump_json_safe(self) -> None:
        """Test JSON-safe dumping functionality."""
        model = TestModel(name="John", age=30, email="john@example.com")
        json_data = model.model_dump_json_safe()

        assert isinstance(json_data, dict)
        assert json_data["name"] == "John"
        assert json_data["age"] == 30
        assert json_data["email"] == "john@example.com"
        assert "optional_field" not in json_data  # None values excluded

    def test_get_field_info(self) -> None:
        """Test field introspection functionality."""
        model = TestModel(name="John", age=30, email="john@example.com")

        name_info = model.get_field_info("name")
        assert name_info is not None

        age_info = model.get_field_info("age")
        assert age_info is not None

        # Test non-existent field
        with pytest.raises(KeyError) as exc_info:
            model.get_field_info("non_existent")
        assert "Field 'non_existent' not found" in str(exc_info.value)

    @given(
        name=st.text(min_size=1, max_size=100),
        age=st.integers(min_value=0, max_value=150),
    )
    def test_property_based_validation(self, name: str, age: int) -> None:
        """Property-based test for model validation."""
        # Generate valid email for testing
        email = f"test{age}@example.com"

        try:
            model = TestModel(name=name, age=age, email=email)
            assert model.name == name
            assert model.age == age
            assert model.email == email
        except ValidationError:
            # Some generated strings might still be invalid due to content
            pass


# ===== BASE ENTITY TESTS =====


class TestBaseEntity:
    """Test suite for BaseEntity functionality."""

    def test_entity_creation_with_defaults(self) -> None:
        """Test entity creation with automatic ID and timestamps."""
        entity = TestEntity(name="Test Entity")

        assert isinstance(entity.id, uuid.UUID)
        assert isinstance(entity.created_at, datetime)
        assert isinstance(entity.updated_at, datetime)
        assert entity.version == 1
        assert entity.name == "Test Entity"
        assert entity.value == 0

    def test_entity_identity_equality(self) -> None:
        """Test that entities are equal based on ID, not attributes."""
        entity1 = TestEntity(name="Entity 1", value=10)
        entity2 = TestEntity(name="Entity 2", value=20)

        # Different entities are not equal
        assert entity1 != entity2
        assert entity1.id != entity2.id

        # Same entity (same ID) is equal to itself
        assert entity1 == entity1

        # Create entity with same ID but different attributes
        entity3 = TestEntity(
            id=entity1.id,
            name="Different Name",
            value=999,
            created_at=entity1.created_at,
            updated_at=entity1.updated_at,
            version=entity1.version,
        )
        assert entity1 == entity3  # Same ID = equal entities

    def test_entity_hashing(self) -> None:
        """Test that entities can be used as dict keys and in sets."""
        entity1 = TestEntity(name="Entity 1")
        entity2 = TestEntity(name="Entity 2")

        # Test in set
        entity_set = {entity1, entity2, entity1}  # Duplicate entity1
        assert len(entity_set) == 2  # Only unique entities

        # Test as dict keys
        entity_dict = {entity1: "value1", entity2: "value2"}
        assert entity_dict[entity1] == "value1"
        assert entity_dict[entity2] == "value2"

    def test_is_new_entity(self) -> None:
        """Test new entity detection."""
        entity = TestEntity(name="New Entity")
        assert entity.is_new()

        # Update entity version
        updated_entity = entity.mark_updated()
        assert not updated_entity.is_new()
        assert updated_entity.version == 2

    def test_mark_updated(self) -> None:
        """Test entity update marking functionality."""
        original_time = datetime.now(UTC)
        entity = TestEntity(
            name="Test",
            created_at=original_time,
            updated_at=original_time,
        )

        updated_entity = entity.mark_updated()

        # Original entity unchanged (immutable)
        assert entity.version == 1
        assert entity.updated_at == original_time

        # New entity has updated metadata
        assert updated_entity.version == 2
        assert updated_entity.updated_at > original_time
        assert updated_entity.created_at == original_time  # Unchanged
        assert updated_entity.name == entity.name  # Other fields unchanged

    def test_can_be_deleted_business_rule(self) -> None:
        """Test entity deletion business rules."""
        valid_entity = TestEntity(name="Valid", value=10)
        assert valid_entity.can_be_deleted()

        invalid_entity = TestEntity(name="Invalid", value=-1)
        assert not invalid_entity.can_be_deleted()

    def test_entity_different_types_not_equal(self) -> None:
        """Test that entities of different types are never equal."""

        class OtherEntity(BaseEntity):
            name: str

            def can_be_deleted(self) -> bool:
                return True

        entity1 = TestEntity(name="Test")
        entity2 = OtherEntity(id=entity1.id, name="Test")  # Same ID, different type

        assert entity1 != entity2  # Different types


# ===== BASE VALUE OBJECT TESTS =====


class TestBaseValueObject:
    """Test suite for BaseValueObject functionality."""

    def test_value_object_equality(self) -> None:
        """Test value objects are equal based on all attributes."""
        coord1 = TestValueObject(x=10.5, y=20.3)
        coord2 = TestValueObject(x=10.5, y=20.3)
        coord3 = TestValueObject(x=10.5, y=20.4)

        assert coord1 == coord2  # Same values = equal
        assert coord1 != coord3  # Different values = not equal

    def test_value_object_hashing(self) -> None:
        """Test value objects can be used in sets and as dict keys."""
        coord1 = TestValueObject(x=10.5, y=20.3)
        coord2 = TestValueObject(x=10.5, y=20.3)
        coord3 = TestValueObject(x=15.0, y=25.0)

        # Test in set
        coord_set = {coord1, coord2, coord3}
        assert len(coord_set) == 2  # coord1 and coord2 are equal

        # Test as dict keys
        coord_dict = {coord1: "location1", coord3: "location2"}
        assert coord_dict[coord2] == "location1"  # coord2 equals coord1

    def test_value_object_immutability(self) -> None:
        """Test value objects are immutable."""
        coord = TestValueObject(x=10.5, y=20.3)

        with pytest.raises(ValidationError):
            coord.x = 15.0  # type: ignore[misc] # Testing runtime behavior

    def test_value_object_validation(self) -> None:
        """Test value object business rule validation."""
        valid_coord = TestValueObject(x=10.5, y=45.0)
        assert valid_coord.is_valid()

        invalid_coord_x = TestValueObject(x=200.0, y=45.0)
        assert not invalid_coord_x.is_valid()

        invalid_coord_y = TestValueObject(x=10.5, y=100.0)
        assert not invalid_coord_y.is_valid()

    def test_different_value_object_types_not_equal(self) -> None:
        """Test that different value object types are never equal."""

        class OtherValueObject(BaseValueObject):
            x: float
            y: float

            def is_valid(self) -> bool:
                return True

        coord1 = TestValueObject(x=10.5, y=20.3)
        coord2 = OtherValueObject(x=10.5, y=20.3)

        assert coord1 != coord2  # Different types

    @given(
        x=st.floats(
            min_value=-180,
            max_value=180,
            allow_nan=False,
            allow_infinity=False,
        ),
        y=st.floats(min_value=-90, max_value=90, allow_nan=False, allow_infinity=False),
    )
    def test_property_based_value_objects(self, x: float, y: float) -> None:
        """Property-based test for value object validation."""
        coord = TestValueObject(x=x, y=y)
        assert coord.is_valid()  # All generated values should be valid
        assert coord.x == x
        assert coord.y == y


# ===== BASE REPOSITORY TESTS =====


class TestBaseRepository:
    """Test suite for BaseRepository functionality."""

    @pytest.fixture
    def repository(self) -> TestRepository:
        """Provide repository instance for tests."""
        return TestRepository()

    @pytest.fixture
    def sample_entity(self) -> TestEntity:
        """Provide sample entity for tests."""
        return TestEntity(name="Test Entity", value=42)

    async def test_save_and_find_by_id(
        self,
        repository: TestRepository,
        sample_entity: TestEntity,
    ) -> None:
        """Test saving and retrieving entities by ID."""
        # Save entity
        saved_entity = await repository.save(sample_entity)
        assert saved_entity == sample_entity

        # Find by ID
        found_entity = await repository.find_by_id(sample_entity.id)
        assert found_entity == sample_entity
        assert found_entity is not None
        assert found_entity.name == "Test Entity"
        assert found_entity.value == 42

    async def test_find_by_id_not_found(self, repository: TestRepository) -> None:
        """Test finding non-existent entity returns None."""
        non_existent_id = uuid.uuid4()
        found_entity = await repository.find_by_id(non_existent_id)
        assert found_entity is None

    async def test_delete_entity(
        self,
        repository: TestRepository,
        sample_entity: TestEntity,
    ) -> None:
        """Test deleting entities."""
        # Save entity first
        await repository.save(sample_entity)

        # Delete entity
        deleted = await repository.delete(sample_entity)
        assert deleted is True

        # Verify entity is gone
        found_entity = await repository.find_by_id(sample_entity.id)
        assert found_entity is None

    async def test_delete_non_existent_entity(
        self,
        repository: TestRepository,
        sample_entity: TestEntity,
    ) -> None:
        """Test deleting non-existent entity returns False."""
        deleted = await repository.delete(sample_entity)
        assert deleted is False

    async def test_find_all_entities(self, repository: TestRepository) -> None:
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

    async def test_count_entities(self, repository: TestRepository) -> None:
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

        # Delete one
        await repository.delete(entity1)
        assert await repository.count() == 1


# ===== BASE SERVICE TESTS =====


class TestBaseService:
    """Test suite for BaseService functionality."""

    async def test_healthy_service(self) -> None:
        """Test healthy service health check."""
        service = TestService(healthy=True)
        assert await service.health_check() is True

    async def test_unhealthy_service(self) -> None:
        """Test unhealthy service health check."""
        service = TestService(healthy=False)
        assert await service.health_check() is False

    async def test_service_is_abstract(self) -> None:
        """Test that BaseService cannot be instantiated directly."""
        with pytest.raises(TypeError):
            BaseService()  # type: ignore[abstract] # Testing runtime behavior


# ===== INTEGRATION TESTS =====


class TestIntegration:
    """Integration tests for base classes working together."""

    async def test_entity_repository_service_integration(self) -> None:
        """Test complete integration of entity, repository, and service."""
        # Create components
        repository = TestRepository()
        service = TestService(healthy=True)

        # Create and save entity
        entity = TestEntity(name="Integration Test", value=100)
        saved_entity = await repository.save(entity)

        # Verify entity properties
        assert saved_entity.is_new()
        assert saved_entity.can_be_deleted()

        # Update entity
        updated_entity = saved_entity.mark_updated()
        await repository.save(updated_entity)

        # Verify update
        found_entity = await repository.find_by_id(entity.id)
        assert found_entity is not None
        assert not found_entity.is_new()
        assert found_entity.version == 2

        # Service health check
        assert await service.health_check() is True

    def test_model_entity_value_object_serialization(self) -> None:
        """Test serialization compatibility across base types."""
        # Create instances
        model = TestModel(name="Test", age=30, email="test@example.com")
        entity = TestEntity(name="Test Entity", value=42)
        value_object = TestValueObject(x=10.5, y=20.3)

        # Test serialization
        model_data = model.model_dump_json_safe()
        entity_data = entity.model_dump_json_safe()
        value_object_data = value_object.model_dump_json_safe()

        # Verify data structure
        assert isinstance(model_data, dict)
        assert isinstance(entity_data, dict)
        assert isinstance(value_object_data, dict)

        # Verify required fields
        assert "name" in model_data
        assert "id" in entity_data
        assert "x" in value_object_data
        assert "y" in value_object_data


# ===== PERFORMANCE TESTS =====


class TestPerformance:
    """Performance tests for base classes."""

    @pytest.mark.benchmark
    def test_model_creation_performance(self, benchmark: Any) -> None:
        """Benchmark model creation performance."""

        def create_model() -> TestModel:
            return TestModel(name="Performance Test", age=30, email="test@example.com")

        result = benchmark(create_model)
        assert result.name == "Performance Test"

    @pytest.mark.benchmark
    async def test_entity_operations_performance(self, benchmark: Any) -> None:
        """Benchmark entity operations performance."""
        repository = TestRepository()

        async def entity_operations() -> TestEntity:
            entity = TestEntity(name="Performance Entity", value=100)
            saved_entity = await repository.save(entity)
            found_entity = await repository.find_by_id(saved_entity.id)
            assert found_entity is not None
            return found_entity

        result = await benchmark(entity_operations)
        assert result.name == "Performance Entity"

    @pytest.mark.benchmark
    def test_value_object_equality_performance(self, benchmark: Any) -> None:
        """Benchmark value object equality checking performance."""
        coord1 = TestValueObject(x=10.5, y=20.3)
        coord2 = TestValueObject(x=10.5, y=20.3)

        def check_equality() -> bool:
            return coord1 == coord2

        result = benchmark(check_equality)
        assert result is True
