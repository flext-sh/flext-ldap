"""🔌 Connection-related LDAP Exceptions.

Exception classes for LDAP connection and network-related errors.
"""

from __future__ import annotations

from typing import Any, Optional

from ldap_core_shared.exceptions.base import LDAPError


class ConnectionError(LDAPError):
    """🔌 Exception for LDAP connection failures.

    Raised when connection to LDAP server fails, times out, or is lost.
    """

    def __init__(
        self,
        message: str,
        *,
        host: Optional[str] = None,
        port: Optional[int] = None,
        error_code: Optional[str] = None,
        context: Optional[dict[str, Any]] = None,
        original_error: Optional[Exception] = None,
    ) -> None:
        """Initialize connection error.

        Args:
            message: Error description
            host: LDAP server hostname
            port: LDAP server port
            error_code: LDAP error code
            context: Additional context
            original_error: Underlying network/connection exception
        """
        connection_context = context or {}
        if host:
            connection_context["host"] = host
        if port:
            connection_context["port"] = port

        super().__init__(
            message=message,
            error_code=error_code,
            context=connection_context,
            original_error=original_error,
        )


class TimeoutError(ConnectionError):
    """⏱️ Exception for LDAP operation timeouts."""

    def __init__(
        self,
        message: str,
        *,
        timeout_seconds: Optional[float] = None,
        operation: Optional[str] = None,
        **kwargs: Any,
    ) -> None:
        """Initialize timeout error.

        Args:
            message: Error description
            timeout_seconds: Timeout value that was exceeded
            operation: Operation that timed out
            **kwargs: Additional arguments for ConnectionError
        """
        context = kwargs.get("context", {})
        if timeout_seconds:
            context["timeout_seconds"] = timeout_seconds
        if operation:
            context["operation"] = operation

        kwargs["context"] = context
        super().__init__(message, **kwargs)


class SSLError(ConnectionError):
    """🔒 Exception for SSL/TLS connection failures."""

    def __init__(
        self,
        message: str,
        *,
        certificate_error: Optional[str] = None,
        **kwargs: Any,
    ) -> None:
        """Initialize SSL error.

        Args:
            message: Error description
            certificate_error: Certificate validation error details
            **kwargs: Additional arguments for ConnectionError
        """
        context = kwargs.get("context", {})
        if certificate_error:
            context["certificate_error"] = certificate_error

        kwargs["context"] = context
        super().__init__(message, **kwargs)
