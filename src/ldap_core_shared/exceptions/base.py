"""🚨 DEPRECATED - Use core.exceptions instead.

This module is deprecated. All exceptions have been consolidated
into the comprehensive system in core.exceptions.

Use imports like:
    from ldap_core_shared.core.exceptions import LDAPCoreError, ValidationError
"""

from __future__ import annotations

import warnings
from typing import Any, Optional

from ldap_core_shared.core.exceptions import (
    AuthenticationError as CoreAuthenticationError,
)
from ldap_core_shared.core.exceptions import (
    ConnectionError as CoreConnectionError,
)

# Import from the unified exception system
from ldap_core_shared.core.exceptions import (
    LDAPCoreError,
)
from ldap_core_shared.core.exceptions import (
    ValidationError as CoreValidationError,
)


# Backward compatibility aliases with deprecation warnings
class LDAPError(LDAPCoreError):
    """DEPRECATED: Use LDAPCoreError from core.exceptions instead."""

    def __init__(self, message: str, *, error_code: Optional[str] = None,
                 context: Optional[dict[str, Any]] = None,
                 original_error: Optional[Exception] = None) -> None:
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


class ConnectionError(CoreConnectionError):
    """DEPRECATED: Use ConnectionError from core.exceptions instead."""

    def __init__(self, message: str, *, error_code: Optional[str] = None,
                 context: Optional[dict[str, Any]] = None,
                 original_error: Optional[Exception] = None) -> None:
        warnings.warn(
            "ConnectionError is deprecated. Use ConnectionError from core.exceptions instead.",
            DeprecationWarning,
            stacklevel=2,
        )
        super().__init__(message=message, error_code=error_code, context=context or {})


class AuthenticationError(CoreAuthenticationError):
    """DEPRECATED: Use AuthenticationError from core.exceptions instead."""

    def __init__(self, message: str, *, error_code: Optional[str] = None,
                 context: Optional[dict[str, Any]] = None,
                 original_error: Optional[Exception] = None) -> None:
        warnings.warn(
            "AuthenticationError is deprecated. Use AuthenticationError from core.exceptions instead.",
            DeprecationWarning,
            stacklevel=2,
        )
        super().__init__(message=message, error_code=error_code, context=context or {})


class ValidationError(CoreValidationError):
    """DEPRECATED: Use ValidationError from core.exceptions instead."""

    def __init__(self, message: str, *, error_code: Optional[str] = None,
                 context: Optional[dict[str, Any]] = None,
                 original_error: Optional[Exception] = None) -> None:
        warnings.warn(
            "ValidationError is deprecated. Use ValidationError from core.exceptions instead.",
            DeprecationWarning,
            stacklevel=2,
        )
        super().__init__(message=message, error_code=error_code, context=context or {})
