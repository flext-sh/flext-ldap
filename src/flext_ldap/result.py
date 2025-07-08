# Copyright (c) 2025 FLEXT
# SPDX-License-Identifier: MIT

"""Result pattern for LDAP operations."""

from __future__ import annotations

from typing import TypeVar

T = TypeVar("T")


class Result[T]:
    """Result pattern for operations that can succeed or fail."""

    def __init__(self, value: T | None = None, error: str | None = None) -> None:
        """Initialize result."""
        self._value = value
        self._error = error

    @classmethod
    def success(cls, value: T) -> Result[T]:
        """Create successful result.

        Returns:
            Result[T]: A success result containing the value.

        """
        return cls(value=value)

    @classmethod
    def failure(cls, error: str) -> Result[T]:
        """Create failed result.

        Returns:
            Result[T]: A failure result containing the error message.

        """
        return cls(error=error)

    @property
    def is_success(self) -> bool:
        """Check if result is successful."""
        return self._error is None

    @property
    def value(self) -> T:
        """Get result value.

        Raises:
            ValueError: If the result is a failure.

        """
        if self._error is not None:
            msg = f"Result is failure: {self._error}"
            raise ValueError(msg)
        return self._value  # type: ignore[return-value]

    @property
    def error(self) -> str | None:
        """Get error message."""
        return self._error
