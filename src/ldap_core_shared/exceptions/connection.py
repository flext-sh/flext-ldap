"""🔌 Connection-related LDAP Exceptions.

Exception classes for LDAP connection and network-related errors.
"""

from __future__ import annotations

from typing import Any

from ldap_core_shared.exceptions.base import LDAPError


class LDAPConnectionError(LDAPError):
    """🔌 Exception for LDAP connection failures.

    Raised when connection to LDAP server fails, times out, or is lost.
    """

    def __init__(
        self,
        message: str,
        *,
        host: str | None = None,
        port: int | None = None,
        error_code: str | None = None,
        context: dict[str, Any] | None = None,
        original_error: Exception | None = None,
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


class ConnectionPoolError(ConnectionError):
    """🏊 Exception for connection pool management failures."""

    def __init__(
        self,
        message: str,
        *,
        pool_size: int | None = None,
        active_connections: int | None = None,
        pool_status: str | None = None,
        **kwargs: Any,
    ) -> None:
        """Initialize connection pool error.

        Args:
            message: Error description
            pool_size: Maximum pool size
            active_connections: Number of active connections
            pool_status: Current pool status
            **kwargs: Additional arguments for ConnectionError

        """
        context = kwargs.get("context", {})
        if pool_size is not None:
            context["pool_size"] = pool_size
        if active_connections is not None:
            context["active_connections"] = active_connections
        if pool_status:
            context["pool_status"] = pool_status

        kwargs["context"] = context
        super().__init__(message, **kwargs)


class ConnectionTimeoutError(ConnectionError):
    """⏱️ Exception for connection timeout failures."""

    def __init__(
        self,
        message: str,
        *,
        timeout_seconds: float | None = None,
        operation: str | None = None,
        connection_attempts: int | None = None,
        **kwargs: Any,
    ) -> None:
        """Initialize connection timeout error.

        Args:
            message: Error description
            timeout_seconds: Timeout value that was exceeded
            operation: Operation that timed out
            connection_attempts: Number of connection attempts made
            **kwargs: Additional arguments for ConnectionError

        """
        context = kwargs.get("context", {})
        if timeout_seconds is not None:
            context["timeout_seconds"] = timeout_seconds
        if operation:
            context["operation"] = operation
        if connection_attempts is not None:
            context["connection_attempts"] = connection_attempts

        kwargs["context"] = context
        super().__init__(message, **kwargs)


class AuthenticationError(ConnectionError):
    """🔐 Exception for LDAP authentication failures."""

    def __init__(
        self,
        message: str,
        *,
        bind_dn: str | None = None,
        auth_method: str | None = None,
        failure_reason: str | None = None,
        **kwargs: Any,
    ) -> None:
        """Initialize authentication error.

        Args:
            message: Error description
            bind_dn: DN used for binding
            auth_method: Authentication method used
            failure_reason: Specific reason for authentication failure
            **kwargs: Additional arguments for ConnectionError

        """
        context = kwargs.get("context", {})
        if bind_dn:
            context["bind_dn"] = bind_dn
        if auth_method:
            context["auth_method"] = auth_method
        if failure_reason:
            context["failure_reason"] = failure_reason

        kwargs["context"] = context
        super().__init__(message, **kwargs)


class LDAPTimeoutError(LDAPConnectionError):
    """⏱️ Exception for LDAP operation timeouts."""

    def __init__(
        self,
        message: str,
        *,
        timeout_seconds: float | None = None,
        operation: str | None = None,
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
        certificate_error: str | None = None,
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
