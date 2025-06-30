"""🚨 DEPRECATED - Use core.exceptions instead.

This module is deprecated. All exceptions have been consolidated
into the comprehensive system in core.exceptions.

Use imports like:
    from flext_ldap.core.exceptions import LDAPCoreError, ValidationError
"""

from __future__ import annotations

import warnings
from typing import Any

from flext_ldapions import (
    AuthenticationError as CoreAuthenticationError,
)
from flext_ldapions import (
    LDAPConnectionError as CoreConnectionError,
)

# Import from the unified exception system
from flext_ldapions import (
    LDAPCoreError,
)
from flext_ldapions import (
    ValidationError as CoreValidationError,
)


# Backward compatibility aliases with deprecation warnings
class LDAPError(LDAPCoreError):
    """DEPRECATED: Use LDAPCoreError from core.exceptions instead."""

    def __init__(
        self,
        message: str,
        *,
        error_code: str | None = None,
        context: dict[str, Any] | None = None,
        original_error: Exception | None = None,
    ) -> None:
        warnings.warn(
            "LDAPError is deprecated. Use LDAPCoreError from core.exceptions instead.",
            DeprecationWarning,
            stacklevel=2,
        )
        # Convert to new format
        context_obj = context or {}
        super().__init__(
            message=message,
            error_code=error_code,
            context=context_obj,
            cause=original_error,
        )


class LDAPConnectionError(CoreConnectionError):
    """DEPRECATED: Use ConnectionError from core.exceptions instead."""

    def __init__(
        self,
        message: str,
        *,
        error_code: str | None = None,
        context: dict[str, Any] | None = None,
        original_error: Exception | None = None,
    ) -> None:
        warnings.warn(
            "ConnectionError is deprecated. Use ConnectionError from core.exceptions instead.",
            DeprecationWarning,
            stacklevel=2,
        )
        super().__init__(message=message, error_code=error_code, context=context or {})


class AuthenticationError(CoreAuthenticationError):
    """DEPRECATED: Use AuthenticationError from core.exceptions instead."""

    def __init__(
        self,
        message: str,
        *,
        error_code: str | None = None,
        context: dict[str, Any] | None = None,
        original_error: Exception | None = None,
    ) -> None:
        warnings.warn(
            "AuthenticationError is deprecated. Use AuthenticationError from core.exceptions instead.",
            DeprecationWarning,
            stacklevel=2,
        )
        super().__init__(message=message, error_code=error_code, context=context or {})


class ValidationError(CoreValidationError):
    """DEPRECATED: Use ValidationError from core.exceptions instead."""

    def __init__(
        self,
        message: str,
        *,
        error_code: str | None = None,
        context: dict[str, Any] | None = None,
        original_error: Exception | None = None,
    ) -> None:
        warnings.warn(
            "ValidationError is deprecated. Use ValidationError from core.exceptions instead.",
            DeprecationWarning,
            stacklevel=2,
        )
        super().__init__(message=message, error_code=error_code, context=context or {})
