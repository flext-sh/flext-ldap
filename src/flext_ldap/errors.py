"""FLEXT LDAP Error Hierarchy - Following docs/patterns/error-observability.md.

Implements the FLEXT error patterns with semantic classification,
rich context preservation, and proper observability integration.

This module defines LDAP-specific errors following the FlextError
hierarchy from the FLEXT patterns documentation.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from typing import TYPE_CHECKING, ClassVar, TypeVar

from flext_core import FlextResult, get_logger

if TYPE_CHECKING:
    from flext_core.typings import FlextTypes

T = TypeVar("T")


@dataclass
class FlextLdapErrorContext:
    """Parameter Object pattern for error context - SOLID Single Responsibility."""

    error_code: str | None = None
    correlation_id: str | None = None
    context: FlextTypes.Core.JsonDict | None = None
    cause: Exception | None = None
    recoverable: bool | None = None
    alert_level: str = "error"


logger = get_logger(__name__)


class FlextLdapErrorCode(StrEnum):
    """LDAP-specific error codes following FLEXT patterns."""

    # LDAP Business Errors (3xxx)
    LDAP_ENTRY_NOT_FOUND = "FLEXT_3001"
    LDAP_ENTRY_ALREADY_EXISTS = "FLEXT_3002"
    LDAP_VALIDATION_ERROR = "FLEXT_3003"
    LDAP_SCHEMA_VIOLATION = "FLEXT_3004"
    LDAP_FILTER_INVALID = "FLEXT_3005"
    LDAP_DN_INVALID = "FLEXT_3006"

    # LDAP Technical Errors (4xxx)
    LDAP_CONNECTION_ERROR = "FLEXT_4001"
    LDAP_AUTHENTICATION_ERROR = "FLEXT_4002"
    LDAP_TIMEOUT_ERROR = "FLEXT_4003"
    LDAP_PROTOCOL_ERROR = "FLEXT_4004"
    LDAP_SERVER_ERROR = "FLEXT_4005"
    LDAP_NETWORK_ERROR = "FLEXT_4006"


class FlextLdapError(Exception):
    """Base LDAP exception following FLEXT error patterns.

    Implements semantic error classification, rich context preservation,
    and automatic observability integration as defined in
    docs/patterns/error-observability.md.
    """

    __error_family__: ClassVar[str] = "LDAP"
    __error_type__: ClassVar[str] = "GENERIC"

    def __init__(
        self,
        message: str,
        *,
        error_context: FlextLdapErrorContext | None = None,
        **kwargs: object,
    ) -> None:
        """Initialize FLEXT LDAP error with Parameter Object pattern - SOLID compliance."""
        super().__init__(message)

        # Use Parameter Object pattern or defaults
        ctx = error_context or FlextLdapErrorContext()

        self.message = message
        self.error_code = ctx.error_code or self._generate_error_code()
        self.correlation_id = ctx.correlation_id or str(uuid.uuid4())
        self.context = ctx.context or {}
        self.cause = ctx.cause
        self.recoverable = (
            ctx.recoverable if ctx.recoverable is not None else self._is_recoverable()
        )
        self.alert_level = ctx.alert_level
        self.timestamp = datetime.now(tz=UTC)

        # Store any additional kwargs for extensibility
        self.additional_context = kwargs

        # Add LDAP-specific context
        self.context.update(
            {
                "error_family": self.__error_family__,
                "error_type": self.__error_type__,
            },
        )

        # Automatic observability integration
        self._log_error()
        self._emit_metrics()
        self._create_trace_span()

    def _generate_error_code(self) -> str:
        """Generate error code based on error type."""
        return f"FLEXT_{self.__error_family__}_{self.__error_type__}"

    def _is_recoverable(self) -> bool:
        """Determine if error is recoverable (default implementation)."""
        return False

    def _log_error(self) -> None:
        """Log error with structured context."""
        logger.error(
            self.message,
            extra={
                "error_code": self.error_code,
                "correlation_id": self.correlation_id,
                "error_type": self.__error_type__,
                "recoverable": self.recoverable,
                "alert_level": self.alert_level,
                **self.context,
            },
        )

    def _emit_metrics(self) -> None:
        """Emit error metrics (placeholder for actual metrics implementation)."""
        # In a full implementation, this would emit metrics to the observability system

    def _create_trace_span(self) -> None:
        """Create trace span for error (placeholder for actual tracing implementation)."""
        # In a full implementation, this would create spans in the tracing system

    def to_result(self) -> FlextResult[None]:
        """Convert exception to FlextResult for consistent handling."""
        # Simplified return without error_code to avoid Any typing issues
        return FlextResult[None].fail(self.message)

    def to_bool_result(self) -> FlextResult[bool]:
        """Convert exception to FlextResult[bool] for boolean operations."""
        # Simplified return without error_code to avoid Any typing issues
        return FlextResult[bool].fail(self.message)

    def to_typed_result(self, _result_type: type[T]) -> FlextResult[T]:
        """Convert exception to FlextResult[T] for typed operations.

        Args:
            _result_type: The expected result type (prefixed with underscore - type checking only)

        """
        # Simplified return without error_code to avoid Any typing issues
        return FlextResult[T].fail(self.message)

    def to_dict(self) -> FlextTypes.Core.JsonDict:
        """Serialize exception for cross-service communication."""
        return {
            "error_type": self.__class__.__name__,
            "message": self.message,
            "error_code": self.error_code,
            "correlation_id": self.correlation_id,
            "context": self.context,
            "recoverable": self.recoverable,
            "alert_level": self.alert_level,
            "timestamp": self.timestamp.isoformat(),
        }


class FlextLdapBusinessError(FlextLdapError):
    """LDAP business logic violations requiring user action."""

    __error_type__ = "BUSINESS"

    def _is_recoverable(self) -> bool:
        """Business errors typically require user intervention."""
        return False


class FlextLdapTechnicalError(FlextLdapError):
    """LDAP technical/infrastructure errors potentially recoverable."""

    __error_type__ = "TECHNICAL"

    def _is_recoverable(self) -> bool:
        """Technical errors often recoverable with retry."""
        return True


# LDAP Domain-Specific Errors following FLEXT patterns
class FlextLdapConnection:
    """Namespace for LDAP connection-related errors."""

    class LdapConnectionError(FlextLdapTechnicalError):
        """LDAP server connection failures."""

        __error_type__ = "CONNECTION"

        def __init__(
            self,
            message: str,
            *,
            server: str | None = None,
            port: int | None = None,
            cause: Exception | None = None,
        ) -> None:
            error_context = FlextLdapErrorContext(
                error_code=FlextLdapErrorCode.LDAP_CONNECTION_ERROR,
                context={"server": server, "port": port},
                cause=cause,
                recoverable=True,
                alert_level="warning",
            )
            super().__init__(message, error_context=error_context)

    class AuthenticationError(FlextLdapTechnicalError):
        """LDAP authentication failures."""

        __error_type__ = "AUTHENTICATION"

        def __init__(
            self,
            message: str,
            *,
            bind_dn: str | None = None,
            cause: Exception | None = None,
        ) -> None:
            error_context = FlextLdapErrorContext(
                error_code=FlextLdapErrorCode.LDAP_AUTHENTICATION_ERROR,
                context={"bind_dn": bind_dn},
                cause=cause,
                recoverable=False,
                alert_level="warning",
            )
            super().__init__(message, error_context=error_context)

    class LdapTimeoutError(FlextLdapTechnicalError):
        """LDAP operation timeout errors."""

        __error_type__ = "TIMEOUT"

        def __init__(
            self,
            message: str,
            *,
            operation: str | None = None,
            timeout_seconds: int | None = None,
            cause: Exception | None = None,
        ) -> None:
            super().__init__(
                message,
                error_code=FlextLdapErrorCode.LDAP_TIMEOUT_ERROR,
                context={"operation": operation, "timeout_seconds": timeout_seconds},
                cause=cause,
                recoverable=True,
                alert_level="warning",
            )


class FlextLdapData:
    """Namespace for LDAP data-related errors."""

    class ValidationError(FlextLdapBusinessError):
        """LDAP data validation failures."""

        __error_type__ = "VALIDATION"

        def __init__(
            self,
            message: str,
            *,
            field_name: str | None = None,
            field_value: object = None,
            cause: Exception | None = None,
        ) -> None:
            super().__init__(
                message,
                error_code=FlextLdapErrorCode.LDAP_VALIDATION_ERROR,
                context={
                    "field_name": field_name,
                    "field_value": str(field_value) if field_value else None,
                },
                cause=cause,
                recoverable=False,
                alert_level="error",
            )

    class SchemaViolationError(FlextLdapBusinessError):
        """LDAP schema constraint violations."""

        __error_type__ = "SCHEMA_VIOLATION"

        def __init__(
            self,
            message: str,
            *,
            object_class: str | None = None,
            attribute: str | None = None,
            cause: Exception | None = None,
        ) -> None:
            super().__init__(
                message,
                error_code=FlextLdapErrorCode.LDAP_SCHEMA_VIOLATION,
                context={"object_class": object_class, "attribute": attribute},
                cause=cause,
                recoverable=False,
                alert_level="error",
            )

    class EntryNotFoundError(FlextLdapBusinessError):
        """LDAP entry not found errors."""

        __error_type__ = "ENTRY_NOT_FOUND"

        def __init__(
            self,
            message: str,
            *,
            dn: str | None = None,
            search_filter: str | None = None,
            cause: Exception | None = None,
        ) -> None:
            super().__init__(
                message,
                error_code=FlextLdapErrorCode.LDAP_ENTRY_NOT_FOUND,
                context={"dn": dn, "search_filter": search_filter},
                cause=cause,
                recoverable=False,
                alert_level="info",
            )

    class EntryAlreadyExistsError(FlextLdapBusinessError):
        """LDAP entry already exists errors."""

        __error_type__ = "ENTRY_ALREADY_EXISTS"

        def __init__(
            self,
            message: str,
            *,
            dn: str | None = None,
            cause: Exception | None = None,
        ) -> None:
            super().__init__(
                message,
                error_code=FlextLdapErrorCode.LDAP_ENTRY_ALREADY_EXISTS,
                context={"dn": dn},
                cause=cause,
                recoverable=False,
                alert_level="warning",
            )


class FlextLdapProtocol:
    """Namespace for LDAP protocol-related errors."""

    class FilterError(FlextLdapBusinessError):
        """Invalid LDAP search filter errors."""

        __error_type__ = "FILTER_INVALID"

        def __init__(
            self,
            message: str,
            *,
            filter_string: str | None = None,
            cause: Exception | None = None,
        ) -> None:
            super().__init__(
                message,
                error_code=FlextLdapErrorCode.LDAP_FILTER_INVALID,
                context={"filter_string": filter_string},
                cause=cause,
                recoverable=False,
                alert_level="error",
            )

    class DNError(FlextLdapBusinessError):
        """Invalid distinguished name errors."""

        __error_type__ = "DN_INVALID"

        def __init__(
            self,
            message: str,
            *,
            dn: str | None = None,
            cause: Exception | None = None,
        ) -> None:
            super().__init__(
                message,
                error_code=FlextLdapErrorCode.LDAP_DN_INVALID,
                context={"dn": dn},
                cause=cause,
                recoverable=False,
                alert_level="error",
            )


# Backward compatibility aliases for existing code - Direct access patterns
FlextLdapConnectionError = FlextLdapConnection.LdapConnectionError
FlextLdapAuthenticationError = FlextLdapConnection.AuthenticationError
FlextLdapTimeoutError = FlextLdapConnection.LdapTimeoutError

# Direct imports already available via FlextLdapConnectionError/FlextLdapTimeoutError
# Removed shadowing aliases that conflict with Python builtins

# Dynamic attribute assignment removed - use direct class references instead
# FlextLdapConnection.ConnectionError -> FlextLdapConnection.LdapConnectionError
# FlextLdapConnection.TimeoutError -> FlextLdapConnection.LdapTimeoutError
FlextLdapValidationError = FlextLdapData.ValidationError
FlextLdapNotFoundError = FlextLdapData.EntryNotFoundError
FlextLdapDuplicateError = FlextLdapData.EntryAlreadyExistsError

__all__ = [
    "FlextLdapAuthenticationError",
    "FlextLdapBusinessError",
    "FlextLdapConnection",
    "FlextLdapConnectionError",
    "FlextLdapData",
    "FlextLdapDuplicateError",
    "FlextLdapError",
    "FlextLdapErrorCode",
    "FlextLdapNotFoundError",
    "FlextLdapProtocol",
    "FlextLdapTechnicalError",
    "FlextLdapTimeoutError",
    "FlextLdapValidationError",
]
