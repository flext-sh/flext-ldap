"""Generic type patterns for LDAP Core Shared.

This module provides generic type patterns that enable reusable, type-safe
implementations across the library. These generics eliminate code duplication
while maintaining strict type safety.

Design principles:
- DRY: Single implementation for common patterns
- Type Safety: Full generic type support with constraints
- SOLID: Supports dependency inversion through generic interfaces
- Flexibility: Easy to extend and customize for specific use cases
"""

from __future__ import annotations

from collections.abc import AsyncIterator, Callable
from typing import (
    TYPE_CHECKING,
    Any,
    Generic,
    Protocol,
    TypeVar,
    runtime_checkable,
)

from flext_ldap.types.base import (
    BaseEntity,
    BaseRepository,
    BaseService,
    BaseValueObject,
)

if TYPE_CHECKING:
    import uuid

# ===== BASIC GENERIC TYPE VARIABLES =====

#: Generic type variable for any type
T = TypeVar("T")

#: Generic type variable for input types
TInput = TypeVar("TInput")

#: Generic type variable for output types
TOutput = TypeVar("TOutput")

#: Generic type variable for key types
TKey = TypeVar("TKey")

#: Generic type variable for value types
TValue = TypeVar("TValue")

#: Generic type variable for error types
TError = TypeVar("TError", bound=Exception)

# ===== ENTITY AND VALUE OBJECT GENERICS =====

#: Generic entity type variable
TEntity = TypeVar("TEntity", bound=BaseEntity)

#: Generic value object type variable
TValueObject = TypeVar("TValueObject", bound=BaseValueObject)

#: Generic repository type variable
TRepository = TypeVar("TRepository", bound=BaseRepository[Any])

#: Generic service type variable
TService = TypeVar("TService", bound=BaseService)

# ===== RESULT PATTERN GENERICS =====


class Result(Generic[T, TError]):
    """Generic Result type for error handling without exceptions.

    This class implements the Result pattern, providing a type-safe way
    to handle operations that might fail without using exceptions.

    Features:
    - Type-safe success and error handling
    - Chainable operations with map and flat_map
    - No performance overhead of exceptions
    - Clear error propagation

    Example:
        >>> def divide(a: int, b: int) -> Result[float, str]:
        ...     if b == 0:
        ...         return Result.error("Division by zero")
        ...     return Result.success(a / b)
        >>>
        >>> result = divide(10, 2)
        >>> if result.is_success():
        ...     print(f"Result: {result.unwrap()}")
        >>> else:
        ...     print(f"Error: {result.unwrap_error()}")

    """

    def __init__(self, value: T | None = None, error: TError | None = None) -> None:
        """Initialize Result with either a value or an error.

        Args:
            value: Success value (mutually exclusive with error)
            error: Error value (mutually exclusive with value)

        Raises:
            ValueError: If both value and error are provided or both are None

        """
        if (value is None and error is None) or (
            value is not None and error is not None
        ):
            msg = "Result must have exactly one of value or error"
            raise ValueError(msg)

        self._value = value
        self._error = error

    @classmethod
    def success(cls, value: T) -> Result[T, TError]:
        """Create a successful Result.

        Args:
            value: The success value

        Returns:
            Result containing the success value

        """
        return cls(value=value)

    @classmethod
    def error(cls, error: TError) -> Result[T, TError]:
        """Create an error Result.

        Args:
            error: The error value

        Returns:
            Result containing the error

        """
        return cls(error=error)

    def is_success(self) -> bool:
        """Check if this Result represents success.

        Returns:
            True if Result contains a success value

        """
        return self._value is not None

    def is_error(self) -> bool:
        """Check if this Result represents an error.

        Returns:
            True if Result contains an error value

        """
        return self._error is not None

    def unwrap(self) -> T:
        """Extract the success value.

        Returns:
            The success value

        Raises:
            ValueError: If Result contains an error

        """
        if self._value is None:
            msg = "Called unwrap() on error Result"
            raise ValueError(msg)
        return self._value

    def unwrap_error(self) -> TError:
        """Extract the error value.

        Returns:
            The error value

        Raises:
            ValueError: If Result contains a success value

        """
        if self._error is None:
            msg = "Called unwrap_error() on success Result"
            raise ValueError(msg)
        return self._error

    def unwrap_or(self, default: T) -> T:
        """Extract the success value or return a default.

        Args:
            default: Default value to return if Result is an error

        Returns:
            Success value if available, otherwise default

        """
        return self._value if self._value is not None else default

    def map(self, func: Callable[[T], TOutput]) -> Result[TOutput, TError]:
        """Transform the success value if present.

        Args:
            func: Function to apply to the success value

        Returns:
            New Result with transformed value or original error

        """
        if self.is_success():
            try:
                return Result.success(func(self.unwrap()))
            except Exception as e:
                return Result.error(e)  # type: ignore[arg-type]
        return Result.error(self.unwrap_error())

    def flat_map(
        self,
        func: Callable[[T], Result[TOutput, TError]],
    ) -> Result[TOutput, TError]:
        """Transform the success value with a function that returns a Result.

        Args:
            func: Function that takes success value and returns a Result

        Returns:
            Result returned by func or original error

        """
        if self.is_success():
            return func(self.unwrap())
        return Result.error(self.unwrap_error())


# ===== OPTION PATTERN GENERICS =====


class Option(Generic[T]):
    """Generic Option type for handling nullable values type-safely.

    This class implements the Option pattern, providing a type-safe way
    to handle values that might be None without null pointer exceptions.

    Features:
    - Type-safe None handling
    - Chainable operations
    - Clear intention when values might be missing
    - No unexpected None access

    Example:
        >>> def find_user(user_id: int) -> Option[str]:
        ...     users = {1: "Alice", 2: "Bob"}
        ...     if user_id in users:
        ...         return Option.some(users[user_id])
        ...     return Option.none()
        >>>
        >>> user = find_user(1)
        >>> if user.is_some():
        ...     print(f"Found: {user.unwrap()}")
        >>> else:
        ...     print("User not found")

    """

    def __init__(self, value: T | None = None) -> None:
        """Initialize Option with optional value.

        Args:
            value: The value to wrap, or None for empty Option

        """
        self._value = value

    @classmethod
    def some(cls, value: T) -> Option[T]:
        """Create an Option containing a value.

        Args:
            value: The value to wrap

        Returns:
            Option containing the value

        """
        return cls(value)

    @classmethod
    def none(cls) -> Option[T]:
        """Create an empty Option.

        Returns:
            Empty Option

        """
        return cls()

    def is_some(self) -> bool:
        """Check if Option contains a value.

        Returns:
            True if Option contains a value

        """
        return self._value is not None

    def is_none(self) -> bool:
        """Check if Option is empty.

        Returns:
            True if Option is empty

        """
        return self._value is None

    def unwrap(self) -> T:
        """Extract the contained value.

        Returns:
            The contained value

        Raises:
            ValueError: If Option is empty

        """
        if self._value is None:
            msg = "Called unwrap() on None Option"
            raise ValueError(msg)
        return self._value

    def unwrap_or(self, default: T) -> T:
        """Extract the value or return a default.

        Args:
            default: Default value to return if Option is empty

        Returns:
            Contained value if present, otherwise default

        """
        return self._value if self._value is not None else default

    def map(self, func: Callable[[T], TOutput]) -> Option[TOutput]:
        """Transform the contained value if present.

        Args:
            func: Function to apply to the contained value

        Returns:
            New Option with transformed value or empty Option

        """
        if self.is_some():
            return Option.some(func(self.unwrap()))
        return Option.none()

    def flat_map(self, func: Callable[[T], Option[TOutput]]) -> Option[TOutput]:
        """Transform the value with a function that returns an Option.

        Args:
            func: Function that takes value and returns an Option

        Returns:
            Option returned by func or empty Option

        """
        if self.is_some():
            return func(self.unwrap())
        return Option.none()


# ===== REPOSITORY PATTERN GENERICS =====


class Repository(BaseRepository[TEntity], Generic[TEntity]):
    """Generic repository implementation with common functionality.

    This class provides a base implementation of the repository pattern
    with common operations that can be extended for specific entities.

    Features:
    - Generic CRUD operations
    - Type-safe entity handling
    - Async operations for performance
    - Extensible for custom queries
    """

    def __init__(self) -> None:
        """Initialize repository."""
        self._entities: dict[uuid.UUID, TEntity] = {}

    async def find_by_id(self, entity_id: uuid.UUID) -> TEntity | None:
        """Find entity by ID.

        Args:
            entity_id: Unique identifier of the entity

        Returns:
            Entity if found, None otherwise

        """
        return self._entities.get(entity_id)

    async def save(self, entity: TEntity) -> TEntity:
        """Save entity to storage.

        Args:
            entity: Entity to save

        Returns:
            Saved entity

        """
        self._entities[entity.id] = entity
        return entity

    async def delete(self, entity: TEntity) -> bool:
        """Delete entity from storage.

        Args:
            entity: Entity to delete

        Returns:
            True if entity was deleted

        """
        if entity.id in self._entities:
            del self._entities[entity.id]
            return True
        return False

    async def find_all(self) -> list[TEntity]:
        """Find all entities.

        Returns:
            List of all entities

        """
        return list(self._entities.values())

    async def count(self) -> int:
        """Count total entities.

        Returns:
            Total number of entities

        """
        return len(self._entities)


# ===== SERVICE PATTERN GENERICS =====


class Service(BaseService, Generic[TEntity]):
    """Generic service implementation with common business logic.

    This class provides a base implementation for domain services
    with common patterns for entity management and business rules.
    """

    def __init__(self, repository: Repository[TEntity]) -> None:
        """Initialize service with repository.

        Args:
            repository: Repository for entity persistence

        """
        self._repository = repository

    async def health_check(self) -> bool:
        """Check service health.

        Returns:
            True if service is healthy

        """
        try:
            await self._repository.count()
            return True
        except Exception:
            return False

    async def get_by_id(self, entity_id: uuid.UUID) -> Option[TEntity]:
        """Get entity by ID using Option pattern.

        Args:
            entity_id: Unique identifier of the entity

        Returns:
            Option containing entity if found

        """
        entity = await self._repository.find_by_id(entity_id)
        return Option.some(entity) if entity else Option.none()

    async def create(self, entity: TEntity) -> Result[TEntity, Exception]:
        """Create new entity using Result pattern.

        Args:
            entity: Entity to create

        Returns:
            Result containing created entity or error message

        """
        try:
            if not entity.can_be_deleted():  # Basic validation
                return Result.error(ValueError("Entity validation failed"))

            saved_entity = await self._repository.save(entity)
            return Result.success(saved_entity)
        except Exception as e:
            return Result.error(e)

    async def update(self, entity: TEntity) -> Result[TEntity, Exception]:
        """Update existing entity.

        Args:
            entity: Entity to update

        Returns:
            Result containing updated entity or error message

        """
        try:
            existing = await self._repository.find_by_id(entity.id)
            if not existing:
                return Result.error(ValueError("Entity not found"))

            updated_entity = entity.mark_updated()
            saved_entity = await self._repository.save(updated_entity)  # type: ignore[arg-type]
            return Result.success(saved_entity)
        except Exception as e:
            return Result.error(e)

    async def delete(self, entity_id: uuid.UUID) -> Result[bool, Exception]:
        """Delete entity by ID.

        Args:
            entity_id: Unique identifier of entity to delete

        Returns:
            Result containing success status or error message

        """
        try:
            entity = await self._repository.find_by_id(entity_id)
            if not entity:
                return Result.error(ValueError("Entity not found"))

            if not entity.can_be_deleted():
                return Result.error(ValueError("Entity cannot be deleted"))

            success = await self._repository.delete(entity)
            return Result.success(success)
        except Exception as e:
            return Result.error(e)


# ===== SPECIFICATION PATTERN GENERICS =====


@runtime_checkable
class Specification(Protocol[T]):
    """Generic specification pattern for business rules.

    This protocol defines the interface for specification objects
    that encapsulate business rules and can be combined logically.
    """

    def is_satisfied_by(self, candidate: T) -> bool:
        """Check if candidate satisfies this specification.

        Args:
            candidate: Object to check against specification

        Returns:
            True if candidate satisfies specification

        """

    def and_(self, other: Specification[T]) -> Specification[T]:
        """Combine with another specification using AND logic.

        Args:
            other: Specification to combine with

        Returns:
            Combined specification

        """

    def or_(self, other: Specification[T]) -> Specification[T]:
        """Combine with another specification using OR logic.

        Args:
            other: Specification to combine with

        Returns:
            Combined specification

        """

    def not_(self) -> Specification[T]:
        """Negate this specification.

        Returns:
            Negated specification

        """


# ===== ITERATOR PATTERN GENERICS =====


class AsyncIteratorWrapper(Generic[T]):
    """Generic wrapper for async iteration patterns.

    This class provides utility methods for working with async iterators
    in a type-safe manner, supporting common operations like filtering,
    mapping, and batching.
    """

    def __init__(self, iterator: AsyncIterator[T]) -> None:
        """Initialize wrapper with async iterator.

        Args:
            iterator: Async iterator to wrap

        """
        self._iterator = iterator

    async def filter(self, predicate: Callable[[T], bool]) -> AsyncIterator[T]:
        """Filter items based on predicate.

        Args:
            predicate: Function to test each item

        Yields:
            Items that satisfy the predicate

        """
        async for item in self._iterator:
            if predicate(item):
                yield item

    async def map(self, func: Callable[[T], TOutput]) -> AsyncIterator[TOutput]:
        """Transform items using function.

        Args:
            func: Function to transform each item

        Yields:
            Transformed items

        """
        async for item in self._iterator:
            yield func(item)

    async def take(self, count: int) -> AsyncIterator[T]:
        """Take only the first N items.

        Args:
            count: Number of items to take

        Yields:
            First N items from iterator

        """
        taken = 0
        async for item in self._iterator:
            if taken >= count:
                break
            yield item
            taken += 1

    async def to_list(self) -> list[T]:
        """Collect all items into a list.

        Returns:
            List containing all items from iterator

        """
        return [item async for item in self._iterator]

    async def batch(self, size: int) -> AsyncIterator[list[T]]:
        """Group items into batches of specified size.

        Args:
            size: Maximum size of each batch

        Yields:
            Lists of items, each with at most 'size' items

        """
        batch: list[T] = []
        async for item in self._iterator:
            batch.append(item)
            if len(batch) >= size:
                yield batch
                batch = []

        # Yield remaining items if any
        if batch:
            yield batch


# ===== TYPE ALIASES FOR COMMON GENERIC PATTERNS =====

# Type aliases cannot use TypeVars directly - remove these problematic aliases

# Type aliases with TypeVars cannot be used at module level

# Predicate type alias also cannot use TypeVar at module level

# Mapper type alias also cannot use TypeVar at module level


#: Generic async function type alias
AsyncFunc = Callable[..., Any]  # Should be Awaitable but keeping simple
