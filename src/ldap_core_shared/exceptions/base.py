"""🚨 Base LDAP Exception Classes.

Foundation exception classes for the LDAP Core Shared library.
Provides structured error handling with context and Python 3.9+ compatibility.
"""

from __future__ import annotations

from typing import Any, Optional


class LDAPError(Exception):
    """🚨 Base exception for all LDAP-related errors.

    Provides structured error information with context for enterprise debugging.
    All LDAP exceptions inherit from this base class.

    Attributes:
        message: Human-readable error message
        error_code: Optional LDAP error code
        context: Additional error context information
        original_error: Original exception that caused this error (if any)
    """

    def __init__(
        self,
        message: str,
        *,
        error_code: Optional[str] = None,
        context: Optional[dict[str, Any]] = None,
        original_error: Optional[Exception] = None,
    ) -> None:
        """Initialize LDAP error with structured information.

        Args:
            message: Human-readable error description
            error_code: Optional LDAP protocol error code
            context: Additional context information
            original_error: Original exception that caused this error
        """
        super().__init__(message)
        self.message = message
        self.error_code = error_code
        self.context = context or {}
        self.original_error = original_error

    def __str__(self) -> str:
        """Return string representation of the error."""
        parts = [self.message]

        if self.error_code:
            parts.append(f"[Code: {self.error_code}]")

        if self.context:
            context_str = ", ".join(f"{k}={v}" for k, v in self.context.items())
            parts.append(f"[Context: {context_str}]")

        return " ".join(parts)

    def __repr__(self) -> str:
        """Return detailed representation of the error."""
        return (
            f"{self.__class__.__name__}("
            f"message={self.message!r}, "
            f"error_code={self.error_code!r}, "
            f"context={self.context!r}, "
            f"original_error={self.original_error!r})"
        )

    def add_context(self, **kwargs: Any) -> LDAPError:
        """Add additional context to the error.

        Args:
            **kwargs: Context key-value pairs to add

        Returns:
            Self for method chaining
        """
        self.context.update(kwargs)
        return self

    def with_context(self, **kwargs: Any) -> LDAPError:
        """Create a new error instance with additional context.

        Args:
            **kwargs: Context key-value pairs to add

        Returns:
            New error instance with merged context
        """
        new_context = {**self.context, **kwargs}
        return self.__class__(
            message=self.message,
            error_code=self.error_code,
            context=new_context,
            original_error=self.original_error,
        )
