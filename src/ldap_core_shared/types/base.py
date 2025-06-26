"""Base classes implementing fundamental patterns for LDAP Core Shared.

This module provides the foundation classes that all other modules inherit from,
ensuring consistent behavior and eliminating code duplication across the library.

Design principles:
- DRY: Single source of truth for common functionality
- SOLID: Each class has a single, well-defined responsibility
- Type Safety: All classes are fully typed and validated
"""

from __future__ import annotations

import uuid
from abc import ABC, abstractmethod
from datetime import datetime, timezone
from typing import Any, ClassVar, Generic, TypeVar, final

from pydantic import BaseModel as PydanticBaseModel
from pydantic import ConfigDict, Field, model_validator
from typing_extensions import Self

# Generic type variables for reusable patterns
TEntity = TypeVar("TEntity", bound="BaseEntity")
TValueObject = TypeVar("TValueObject", bound="BaseValueObject")
TRepository = TypeVar("TRepository", bound="BaseRepository[Any]")


class BaseModel(PydanticBaseModel):
    r"""Enhanced Pydantic base model with enterprise features.

    This class serves as the foundation for all data models in the library,
    providing consistent validation, serialization, and behavior.

    Features:
    - Strict validation by default
    - Immutable after creation (frozen)
    - JSON serialization with proper handling of complex types
    - Automatic field validation and transformation
    - Enterprise logging integration

    Example:
        >>> class UserModel(BaseModel):
        ...     name: str = Field(..., min_length=1, max_length=255)
        ...     email: str = Field(..., pattern=r"^[^@]+@[^@]+\\.[^@]+$")
        ...     created_at: datetime = Field(default_factory=datetime.now)
        >>>
        >>> user = UserModel(name="John Doe", email="john@example.com")
        >>> assert user.name == "John Doe"
        >>> user.name = "Jane"  # Raises ValidationError - model is frozen
    """

    # Enterprise-grade configuration
    model_config = ConfigDict(
        # Validation settings
        strict=True,
        validate_assignment=True,
        validate_default=True,
        validate_return=True,
        # Immutability for data integrity
        frozen=True,
        # Performance optimizations
        use_enum_values=True,
        cache_strings=True,
        # JSON handling
        json_encoders={
            datetime: lambda v: v.isoformat(),
            uuid.UUID: str,
        },
        # Extra field handling
        extra="forbid",
        # String processing
        str_strip_whitespace=True,
        str_min_length=0,
    )

    @model_validator(mode="before")
    @classmethod
    def _preprocess_data(cls, data: Any) -> Any:
        """Preprocess and validate incoming data.

        This method provides a central point for data transformation
        before validation, ensuring consistent handling across all models.

        Args:
            data: Raw input data to be validated

        Returns:
            Preprocessed data ready for validation
        """
        if not isinstance(data, dict):
            return data

        # Remove None values to allow defaults to take effect
        return {k: v for k, v in data.items() if v is not None}

    @final
    def model_dump_json_safe(self) -> dict[str, Any]:
        """Dump model to JSON-safe dictionary.

        This method ensures that all complex types are properly serialized
        to JSON-compatible formats, preventing serialization errors.

        Returns:
            Dictionary with JSON-safe values
        """
        return self.model_dump(mode="json", exclude_none=True)

    @final
    def get_field_info(self, field_name: str) -> Any:
        """Get field information for introspection.

        Args:
            field_name: Name of the field to inspect

        Returns:
            Field information including constraints and metadata

        Raises:
            KeyError: If field doesn't exist
        """
        if field_name not in self.model_fields:
            msg = f"Field '{field_name}' not found in {self.__class__.__name__}"
            raise KeyError(msg)
        return self.model_fields[field_name]


class BaseEntity(BaseModel, ABC):
    """Abstract base class for domain entities with identity.

    Entities are objects that have identity and can change over time.
    They are distinguished by their ID rather than their attributes.

    Features:
    - Unique identity across the system
    - Audit trail with creation and modification timestamps
    - Equality based on identity, not attributes
    - Abstract methods for core entity operations

    Example:
        >>> class User(BaseEntity):
        ...     name: str
        ...     email: str
        ...
        ...     def can_be_deleted(self) -> bool:
        ...         return True  # Simple business rule
        >>>
        >>> user1 = User(name="John", email="john@test.com")
        >>> user2 = User(name="Jane", email="jane@test.com")
        >>> assert user1.id != user2.id  # Different entities
    """

    # Unique identifier for entity
    id: uuid.UUID = Field(
        default_factory=uuid.uuid4,
        description="Unique identifier for this entity",
        json_schema_extra={"example": "123e4567-e89b-12d3-a456-426614174000"},
    )

    # Audit trail fields
    created_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="Timestamp when entity was created",
        json_schema_extra={"example": "2025-01-01T00:00:00Z"},
    )

    updated_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="Timestamp when entity was last updated",
        json_schema_extra={"example": "2025-01-01T12:00:00Z"},
    )

    # Version for optimistic locking
    version: int = Field(
        default=1,
        ge=1,
        description="Version number for optimistic locking",
        json_schema_extra={"example": 1},
    )

    @final
    def __eq__(self, other: object) -> bool:
        """Entities are equal if they have the same ID and type."""
        if not isinstance(other, BaseEntity):
            return False
        return self.id == other.id and type(self) is type(other)

    @final
    def __hash__(self) -> int:
        """Hash based on entity ID for use in sets and as dict keys."""
        return hash((self.id, type(self)))

    @final
    def is_new(self) -> bool:
        """Check if this is a new entity (not persisted yet)."""
        return self.version == 1

    @abstractmethod
    def can_be_deleted(self) -> bool:
        """Check if entity can be safely deleted.

        This method must be implemented by concrete entities to define
        their specific business rules for deletion.

        Returns:
            True if entity can be deleted, False otherwise
        """

    @final
    def mark_updated(self) -> Self:
        """Create a new instance with updated timestamp and version.

        Since entities are immutable, this returns a new instance
        with incremented version and updated timestamp.

        Returns:
            New entity instance with updated metadata
        """
        return self.model_copy(
            update={
                "updated_at": datetime.now(timezone.utc),
                "version": self.version + 1,
            },
        )


class BaseValueObject(BaseModel, ABC):
    r"""Abstract base class for domain value objects.

    Value objects are immutable objects that are defined by their attributes
    rather than their identity. Two value objects with the same attributes
    are considered equal.

    Features:
    - Immutable by design
    - Equality based on all attributes
    - No identity - compared by value
    - Self-validating with business rules

    Example:
        >>> class Email(BaseValueObject):
        ...     value: str = Field(..., pattern=r"^[^@]+@[^@]+\\.[^@]+$")
        ...
        ...     def get_domain(self) -> str:
        ...         return self.value.split("@")[1]
        >>>
        >>> email1 = Email(value="test@example.com")
        >>> email2 = Email(value="test@example.com")
        >>> assert email1 == email2  # Same value = equal objects
    """

    @final
    def __eq__(self, other: object) -> bool:
        """Value objects are equal if all their attributes are equal."""
        if not isinstance(other, self.__class__):
            return False
        return self.model_dump() == other.model_dump()

    @final
    def __hash__(self) -> int:
        """Hash based on all attribute values."""
        return hash(tuple(sorted(self.model_dump().items())))

    @abstractmethod
    def is_valid(self) -> bool:
        """Check if value object satisfies all business rules.

        This method must be implemented by concrete value objects to define
        their specific validation logic beyond basic field validation.

        Returns:
            True if value object is valid according to business rules
        """


class BaseRepository(ABC, Generic[TEntity]):
    """Abstract base class for repository pattern implementation.

    Repositories provide a collection-like interface for accessing entities,
    hiding the details of data persistence and retrieval.

    Features:
    - Generic type support for type safety
    - Async operations for performance
    - Consistent interface across all repositories
    - Transaction support for data integrity

    Example:
        >>> class UserRepository(BaseRepository[User]):
        ...     async def find_by_id(self, entity_id: uuid.UUID) -> User | None:
        ...         # Implementation specific to User storage
        ...         pass
        ...
        ...     async def save(self, entity: User) -> User:
        ...         # Implementation specific to User storage
        ...         pass
    """

    # Type information for runtime introspection
    entity_type: ClassVar[type[Any]]

    @abstractmethod
    async def find_by_id(self, entity_id: uuid.UUID) -> TEntity | None:
        """Find entity by its unique identifier.

        Args:
            entity_id: Unique identifier of the entity

        Returns:
            Entity if found, None otherwise
        """

    @abstractmethod
    async def save(self, entity: TEntity) -> TEntity:
        """Save entity to persistent storage.

        Args:
            entity: Entity to save

        Returns:
            Saved entity with updated metadata
        """

    @abstractmethod
    async def delete(self, entity: TEntity) -> bool:
        """Delete entity from persistent storage.

        Args:
            entity: Entity to delete

        Returns:
            True if entity was deleted, False if not found
        """

    @abstractmethod
    async def find_all(self) -> list[TEntity]:
        """Find all entities of this type.

        Returns:
            List of all entities (use with caution for large datasets)
        """

    @abstractmethod
    async def count(self) -> int:
        """Count total number of entities.

        Returns:
            Total count of entities in storage
        """


class BaseService(ABC):
    """Abstract base class for domain services.

    Services contain business logic that doesn't naturally fit into
    entities or value objects, often coordinating between multiple
    entities or external systems.

    Features:
    - Stateless operation
    - Clear separation of concerns
    - Dependency injection support
    - Async operations for performance

    Example:
        >>> class UserService(BaseService):
        ...     def __init__(self, user_repo: UserRepository):
        ...         self._user_repo = user_repo
        ...
        ...     async def create_user(self, name: str, email: str) -> User:
        ...         # Business logic for user creation
        ...         user = User(name=name, email=email)
        ...         return await self._user_repo.save(user)
    """

    @abstractmethod
    async def health_check(self) -> bool:
        """Check if service is healthy and operational.

        Returns:
            True if service is healthy, False otherwise
        """
