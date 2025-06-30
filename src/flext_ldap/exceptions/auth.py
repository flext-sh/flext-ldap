"""🔐 Authentication-related LDAP Exceptions.

Exception classes for LDAP authentication and authorization errors.
"""

from __future__ import annotations

from typing import Any

from flext_ldap.exceptions.base import LDAPError


class AuthenticationError(LDAPError):
    """🔐 Exception for LDAP authentication failures.

    Raised when bind operations fail due to invalid credentials or authentication issues.
    """

    def __init__(
        self,
        message: str,
        *,
        bind_dn: str | None = None,
        auth_method: str | None = None,
        error_code: str | None = None,
        context: dict[str, Any] | None = None,
        original_error: Exception | None = None,
    ) -> None:
        """Initialize authentication error.

        Args:
            message: Error description
            bind_dn: DN used for authentication attempt
            auth_method: Authentication method used (SIMPLE, SASL, etc.)
            error_code: LDAP error code
            context: Additional context
            original_error: Underlying LDAP exception
        """
        auth_context = context or {}
        if bind_dn:
            # Only store DN, never password for security
            auth_context["bind_dn"] = bind_dn
        if auth_method:
            auth_context["auth_method"] = auth_method

        super().__init__(
            message=message,
            error_code=error_code,
            context=auth_context,
            original_error=original_error,
        )


class AuthorizationError(LDAPError):
    """🚫 Exception for LDAP authorization (permission) failures.

    Raised when authenticated user lacks permission for requested operation.
    """

    def __init__(
        self,
        message: str,
        *,
        operation: str | None = None,
        target_dn: str | None = None,
        required_permission: str | None = None,
        **kwargs: Any,
    ) -> None:
        """Initialize authorization error.

        Args:
            message: Error description
            operation: Operation that was denied
            target_dn: DN of target object
            required_permission: Permission that was required
            **kwargs: Additional arguments for LDAPError
        """
        context = kwargs.get("context", {})
        if operation:
            context["operation"] = operation
        if target_dn:
            context["target_dn"] = target_dn
        if required_permission:
            context["required_permission"] = required_permission

        kwargs["context"] = context
        super().__init__(message, **kwargs)


class InvalidCredentialsError(AuthenticationError):
    """❌ Exception for invalid username/password combinations."""

    def __init__(
        self,
        message: str = "Invalid credentials provided",
        **kwargs: Any,
    ) -> None:
        """Initialize invalid credentials error.

        Args:
            message: Error description
            **kwargs: Additional arguments for AuthenticationError
        """
        super().__init__(message, error_code="49", **kwargs)  # LDAP_INVALID_CREDENTIALS


class AccountLockedError(AuthenticationError):
    """🔒 Exception for locked user accounts."""

    def __init__(
        self,
        message: str = "User account is locked",
        **kwargs: Any,
    ) -> None:
        """Initialize account locked error.

        Args:
            message: Error description
            **kwargs: Additional arguments for AuthenticationError
        """
        super().__init__(message, error_code="775", **kwargs)  # LDAP_ACCOUNT_LOCKED
