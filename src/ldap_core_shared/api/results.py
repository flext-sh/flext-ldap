"""LDAP Result Pattern Module - Consistent Error Handling.

This module contains the Result[T] pattern extracted from the monolithic api.py.
It provides consistent error handling across all LDAP operations.

DESIGN PATTERN: RESULT PATTERN + VALUE OBJECT
- Type-safe error handling
- No exceptions for business failures
- Rich context for debugging
"""

from __future__ import annotations

from typing import Any, Generic, TypeVar

from pydantic import BaseModel, ConfigDict, Field

T = TypeVar("T")


class Result(BaseModel, Generic[T]):
    """Unified Result Container Value Object.

    DESIGN PATTERN: VALUE OBJECT + RESULT PATTERN
    ===========================================

    This class implements the Result pattern to provide consistent, type-safe
    error handling across the entire LDAP API. It encapsulates both successful
    results and error conditions in a single, composable type.

    RESPONSIBILITIES:
    - Encapsulate operation results (success or failure)
    - Provide type-safe access to result data
    - Carry execution context and performance metrics
    - Enable functional error handling patterns
    - Maintain consistent error information structure

    BENEFITS:
    - No exceptions for expected failures (e.g., "user not found")
    - Type-safe result handling with generic data types
    - Consistent error structure across all operations
    - Built-in performance monitoring (execution times)
    - Rich context for debugging and monitoring

    USAGE PATTERNS:
    - Success handling:
        >>> result = await ldap.find_user("john.doe")
        >>> if result.success:
        ...     user = result.data  # Type-safe access
        ...     print(f"Found user: {user['name']}")
        ... else:
        ...     print(f"Error: {result.error}")

    - Functional composition:
        >>> users = await ldap.search("dc=company,dc=com", "(objectClass=user)")
        >>> if users.success:
        ...     for user in users.data:
        ...         # Process each user...
        ...         pass

    - Performance monitoring:
        >>> result = await ldap.complex_operation()
        >>> print(f"Operation took {result.execution_time_ms}ms")
        >>> if result.execution_time_ms > 1000:
        ...     logger.warn("Slow operation detected", **result.context)

    INTEGRATION:
    All facade operations return Result[T] objects for consistent error handling
    throughout the LDAP API. This eliminates exceptions for expected business
    logic failures while preserving exceptions for system errors.
    """

    model_config = ConfigDict(arbitrary_types_allowed=True)

    # Core result data
    success: bool                                    # Operation succeeded
    data: T                                          # Result data (typed)
    error: str | None = None                         # Error message if failed
    error_code: str | None = None                    # Error code if failed

    # Performance and context information
    execution_time_ms: float = 0.0                  # Execution time in milliseconds
    context: dict[str, Any] = Field(default_factory=dict)  # Additional context

    @classmethod
    def ok(cls, data: T, execution_time_ms: float = 0.0, **context) -> Result[T]:
        """Create successful result.

        FACTORY METHOD: Creates Result object for successful operations.

        Args:
            data: The successful operation result data
            execution_time_ms: Operation execution time for performance monitoring
            **context: Additional context information for debugging/monitoring

        Returns:
            Result[T] instance representing successful operation

        Example:
            >>> result = Result.ok(user_data, execution_time_ms=150.5,
            ...                    cache_hit=True, source="ldap_primary")
        """
        return cls(
            success=True,
            data=data,
            execution_time_ms=execution_time_ms,
            context=context,
        )

    @classmethod
    def fail(cls, message: str, code: str | None = None,
              execution_time_ms: float = 0.0, default_data: T | None = None) -> Result[T]:
        """Create failed result.

        FACTORY METHOD: Creates Result object for failed operations.

        Args:
            message: Human-readable error message
            code: Optional error code for programmatic handling
            execution_time_ms: Operation execution time for performance monitoring
            default_data: Optional default data to include with failure

        Returns:
            Result[T] instance representing failed operation

        Example:
            >>> result = Result.fail("User not found", code="USER_NOT_FOUND",
            ...                      execution_time_ms=75.2)
        """
        return cls(
            success=False,
            data=default_data,  # type: ignore
            error=message,
            error_code=code,
            execution_time_ms=execution_time_ms,
        )

    @classmethod
    def from_exception(cls, exc: Exception, default_data: T | None = None,
                      execution_time_ms: float = 0.0) -> Result[T]:
        """Create result from exception.

        FACTORY METHOD: Converts exceptions into Result objects for consistent
        error handling patterns.

        Args:
            exc: The exception to convert
            default_data: Optional default data for partial failures
            execution_time_ms: Operation execution time

        Returns:
            Result[T] instance representing exception as failure

        Example:
            >>> try:
            ...     # Some LDAP operation
            ...     pass
            >>> except LDAPException as e:
            ...     return Result.from_exception(e)
        """
        error_code = getattr(exc, "error_code", None)
        return cls.fail(
            message=str(exc),
            code=error_code,
            execution_time_ms=execution_time_ms,
            default_data=default_data,
        )
