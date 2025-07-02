"""Core Exception Classes for LDAP Core Shared.

This module provides a standardized exception hierarchy for all LDAP operations,
ensuring consistent error handling across the entire codebase with enterprise-grade
error reporting, context preservation, and debugging capabilities.

Exception Hierarchy:
    LDAPCoreError
    ├── ValidationError
    │   ├── SchemaValidationError
    │   ├── ConfigurationValidationError
    │   └── DataValidationError
    ├── ConnectionError
    │   ├── ServerConnectionError
    │   ├── AuthenticationError
    │   └── PoolExhaustedError
    ├── OperationError
    │   ├── SchemaOperationError
    │   ├── SearchOperationError
    │   └── ModificationOperationError
    ├── EncodingError
    │   ├── ASN1EncodingError
    │   ├── ASN1DecodingError
    │   └── CharsetEncodingError
    └── SAMLError
        ├── MechanismError
        ├── AuthenticationFlowError
        └── SecurityLayerError

Features:
    - Structured error context with operation details
    - Error code classification for programmatic handling
    - Nested exception support with cause chains
    - Debugging information with stack traces
    - Enterprise logging integration
    - Internationalization support for error messages

Usage Example:
    >>> from flext_ldap.core.exceptions import SchemaValidationError
    >>>
    >>> try:
    ...     # Schema operation
    ...     pass
    ... except Exception as e:
    ...     raise SchemaValidationError(
    ...         message="Schema validation failed",
    ...         error_code="SCHEMA_001",
    ...         context={"schema_file": "test.schema", "line": 42},
    ...         cause=e
    ...     )

Standards:
    - PEP 8 compliant naming and structure
    - Type hints for all methods and attributes
    - Comprehensive docstrings with examples
    - Structured logging integration
"""

from __future__ import annotations

import traceback
from datetime import datetime
from enum import Enum
from typing import Any, Protocol
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field


class Logger(Protocol):
    """Protocol for logger instances to support common logging interfaces."""

    def debug(self, message: str, *args: Any, **kwargs: Any) -> None:
        """Log debug message."""
        ...

    def info(self, message: str, *args: Any, **kwargs: Any) -> None:
        """Log info message."""
        ...

    def warning(self, message: str, *args: Any, **kwargs: Any) -> None:
        """Log warning message."""
        ...

    def error(self, message: str, *args: Any, **kwargs: Any) -> None:
        """Log error message."""
        ...

    def critical(self, message: str, *args: Any, **kwargs: Any) -> None:
        """Log critical message."""
        ...


class ErrorSeverity(Enum):
    """Error severity levels for categorization and handling."""

    LOW = "low"  # Minor issues, warnings
    MEDIUM = "medium"  # Recoverable errors
    HIGH = "high"  # Serious errors requiring attention
    CRITICAL = "critical"  # System-threatening errors


class ErrorCategory(Enum):
    """Error category for classification and routing."""

    VALIDATION = "validation"  # Data/configuration validation errors
    CONNECTION = "connection"  # Network and connection errors
    OPERATION = "operation"  # LDAP operation errors
    ENCODING = "encoding"  # ASN.1 and data encoding errors
    AUTHENTICATION = "authentication"  # SASL and auth errors
    SYSTEM = "system"  # System and infrastructure errors
    CONFIGURATION = "configuration"  # Configuration and setup errors


class ErrorContext(BaseModel):
    """Structured error context for debugging and analysis."""

    model_config = ConfigDict(strict=True, extra="allow")

    operation: str | None = Field(default=None, description="Operation being performed")
    component: str | None = Field(
        default=None,
        description="Component where error occurred",
    )
    resource: str | None = Field(default=None, description="Resource being accessed")
    user: str | None = Field(default=None, description="User performing operation")
    session_id: str | None = Field(default=None, description="Session identifier")
    timestamp: datetime = Field(
        default_factory=datetime.now,
        description="Error occurrence time",
    )
    additional_data: dict[str, Any] = Field(
        default_factory=dict,
        description="Additional context data",
    )

    def __getattr__(self, name: str) -> Any:
        """Allow dynamic attribute access for extra fields.

        Args:
            name: Attribute name

        Returns:
            Attribute value from extra fields

        Raises:
            AttributeError: If attribute not found

        """
        if hasattr(self, "__pydantic_extra__") and name in self.__pydantic_extra__:
            return self.__pydantic_extra__[name]
        if hasattr(self, "__dict__") and name in self.__dict__:
            return self.__dict__[name]
        msg = f"'{self.__class__.__name__}' object has no attribute '{name}'"
        raise AttributeError(msg)


class LDAPCoreError(Exception):
    """Base exception class for all LDAP Core operations.

    Provides standardized error handling with structured context,
    error codes, and comprehensive debugging information.
    """

    def __init__(
        self,
        message: str,
        error_code: str | None = None,
        severity: ErrorSeverity = ErrorSeverity.MEDIUM,
        category: ErrorCategory = ErrorCategory.SYSTEM,
        context: dict[str, Any] | ErrorContext | None = None,
        cause: Exception | None = None,
        user_message: str | None = None,
    ) -> None:
        """Initialize LDAP Core error.

        Args:
            message: Technical error message for developers
            error_code: Unique error code for programmatic handling
            severity: Error severity level
            category: Error category for classification
            context: Additional context information
            cause: Original exception that caused this error
            user_message: User-friendly error message

        """
        super().__init__(message)

        self.message = message
        self.severity = severity
        self.category = category
        self.error_code = error_code or self._generate_error_code()
        self.user_message = user_message or self._generate_user_message()
        self.cause = cause
        self.error_id = str(uuid4())

        # Convert context to ErrorContext if needed
        if isinstance(context, dict):
            self.context = ErrorContext(**context)
        elif context is None:
            self.context = ErrorContext()
        else:
            self.context = context

        # Capture stack trace
        self.stack_trace = traceback.format_exc() if cause else None

    def _generate_error_code(self) -> str:
        """Generate error code based on exception class."""
        class_name = self.__class__.__name__
        category_prefix = self.category.value.upper()[:3]
        return f"{category_prefix}_{class_name.upper()}_001"

    def _generate_user_message(self) -> str:
        """Generate user-friendly error message."""
        return f"An error occurred during {self.category.value} operation. Please contact support with error code {self.error_code}."

    def to_dict(self) -> dict[str, Any]:
        """Convert error to dictionary for logging/serialization.

        Returns:
            Dictionary representation of error

        """
        return {
            "error_id": self.error_id,
            "error_code": self.error_code,
            "message": self.message,
            "user_message": self.user_message,
            "severity": self.severity.value,
            "category": self.category.value,
            "context": self.context.model_dump(),
            "cause": str(self.cause) if self.cause else None,
            "stack_trace": self.stack_trace,
            "timestamp": self.context.timestamp.isoformat(),
        }

    def __str__(self) -> str:
        """String representation with error code and message."""
        return f"[{self.error_code}] {self.message}"

    def __repr__(self) -> str:
        """Detailed string representation for debugging."""
        return (
            f"{self.__class__.__name__}("
            f"error_code='{self.error_code}', "
            f"message='{self.message}', "
            f"severity={self.severity.value}, "
            f"category={self.category.value}"
            f")"
        )


class ValidationError(LDAPCoreError):
    """Base class for validation errors."""

    def __init__(
        self,
        message: str,
        error_code: str | None = None,
        severity: ErrorSeverity = ErrorSeverity.MEDIUM,
        context: dict[str, Any] | ErrorContext | None = None,
        cause: Exception | None = None,
        validation_failures: list[str] | None = None,
    ) -> None:
        """Initialize validation error.

        Args:
            message: Error message
            error_code: Unique error code
            severity: Error severity
            context: Error context
            cause: Original exception
            validation_failures: List of specific validation failures

        """
        super().__init__(
            message=message,
            error_code=error_code,
            severity=severity,
            category=ErrorCategory.VALIDATION,
            context=context,
            cause=cause,
        )
        self.validation_failures = validation_failures or []


class SchemaValidationError(ValidationError):
    """Schema validation specific errors."""

    def __init__(
        self,
        message: str,
        schema_file: str | None = None,
        line_number: int | None = None,
        **kwargs: Any,
    ) -> None:
        """Initialize schema validation error.

        Args:
            message: Error message
            schema_file: Schema file where error occurred
            line_number: Line number in schema file
            **kwargs: Additional arguments for parent class

        """
        context = kwargs.get("context", {})
        if isinstance(context, dict):
            context.update(
                {
                    "schema_file": schema_file,
                    "line_number": line_number,
                },
            )

        super().__init__(message, context=context, **kwargs)


class ConfigurationValidationError(ValidationError):
    """Configuration validation specific errors."""

    def __init__(
        self,
        message: str,
        config_section: str | None = None,
        config_key: str | None = None,
        **kwargs: Any,
    ) -> None:
        """Initialize configuration validation error.

        Args:
            message: Error message
            config_section: Configuration section with error
            config_key: Configuration key with error
            **kwargs: Additional arguments for parent class

        """
        context = kwargs.get("context", {})
        if isinstance(context, dict):
            context.update(
                {
                    "config_section": config_section,
                    "config_key": config_key,
                },
            )

        super().__init__(message, context=context, **kwargs)


class LDAPConnectionError(LDAPCoreError):
    """Base class for connection-related errors."""

    def __init__(
        self,
        message: str,
        server_uri: str | None = None,
        **kwargs: Any,
    ) -> None:
        """Initialize connection error.

        Args:
            message: Error message
            server_uri: LDAP server URI
            **kwargs: Additional arguments for parent class

        """
        context = kwargs.pop("context", {})
        if isinstance(context, dict):
            context.update({"server_uri": server_uri})

        super().__init__(
            message=message,
            category=ErrorCategory.CONNECTION,
            context=context,
            **kwargs,
        )


class ServerLDAPConnectionError(LDAPConnectionError):
    """LDAP server connection specific errors."""

    def __init__(
        self,
        message: str,
        server_uri: str | None = None,
        timeout: float | None = None,
        **kwargs: Any,
    ) -> None:
        """Initialize server connection error.

        Args:
            message: Error message
            server_uri: LDAP server URI
            timeout: Connection timeout value
            **kwargs: Additional arguments for parent class

        """
        context = kwargs.pop("context", {})
        if isinstance(context, dict):
            context.update({"timeout": timeout})

        super().__init__(message, server_uri=server_uri, context=context, **kwargs)


class AuthenticationError(LDAPConnectionError):
    """Authentication specific errors."""

    def __init__(
        self,
        message: str,
        mechanism: str | None = None,
        username: str | None = None,
        **kwargs: Any,
    ) -> None:
        """Initialize authentication error.

        Args:
            message: Error message
            mechanism: SASL mechanism used
            username: Username for authentication
            **kwargs: Additional arguments for parent class

        """
        context = kwargs.pop("context", {})
        if isinstance(context, dict):
            context.update(
                {
                    "mechanism": mechanism,
                    "username": username,
                },
            )

        # Remove category from kwargs to avoid conflict
        kwargs.pop("category", None)

        super().__init__(
            message=message,
            context=context,
            **kwargs,
        )

        # Override the category after initialization
        self.category = ErrorCategory.AUTHENTICATION


class PoolExhaustedError(LDAPConnectionError):
    """Connection pool exhaustion errors."""

    def __init__(
        self,
        message: str,
        pool_size: int | None = None,
        active_connections: int | None = None,
        **kwargs: Any,
    ) -> None:
        """Initialize pool exhausted error.

        Args:
            message: Error message
            pool_size: Maximum pool size
            active_connections: Current active connections
            **kwargs: Additional arguments for parent class

        """
        context = kwargs.get("context", {})
        if isinstance(context, dict):
            context.update(
                {
                    "pool_size": pool_size,
                    "active_connections": active_connections,
                },
            )

        super().__init__(
            message,
            context=context,
            severity=ErrorSeverity.HIGH,
            **kwargs,
        )


class OperationError(LDAPCoreError):
    """Base class for LDAP operation errors."""

    def __init__(
        self,
        message: str,
        operation_type: str | None = None,
        **kwargs: Any,
    ) -> None:
        """Initialize operation error.

        Args:
            message: Error message
            operation_type: Type of LDAP operation
            **kwargs: Additional arguments for parent class

        """
        context = kwargs.pop("context", {})
        if isinstance(context, dict):
            context.update({"operation_type": operation_type})

        super().__init__(
            message=message,
            category=ErrorCategory.OPERATION,
            context=context,
            **kwargs,
        )


class OperationTimeoutError(OperationError):
    """Operation timeout specific errors."""

    def __init__(
        self,
        message: str,
        timeout_seconds: float | None = None,
        operation_type: str | None = None,
        **kwargs: Any,
    ) -> None:
        """Initialize operation timeout error.

        Args:
            message: Error message
            timeout_seconds: Timeout duration that was exceeded
            operation_type: Type of operation that timed out
            **kwargs: Additional arguments for parent class

        """
        # Create context with timeout-specific information
        context = kwargs.pop("context", {})
        if isinstance(context, dict):
            context.update(
                {
                    "timeout_seconds": timeout_seconds,
                    "operation_type": operation_type,
                },
            )

        super().__init__(
            message=message,
            operation_type=operation_type,
            error_code="OPERATION_TIMEOUT",
            severity=ErrorSeverity.MEDIUM,
            context=context,
            **kwargs,
        )


class SchemaOperationError(OperationError):
    """Schema operation specific errors."""

    def __init__(
        self,
        message: str,
        schema_name: str | None = None,
        operation_id: str | None = None,
        **kwargs: Any,
    ) -> None:
        """Initialize schema operation error.

        Args:
            message: Error message
            schema_name: Name of schema being operated on
            operation_id: Unique operation identifier
            **kwargs: Additional arguments for parent class

        """
        context = kwargs.get("context", {})
        if isinstance(context, dict):
            context.update(
                {
                    "schema_name": schema_name,
                    "operation_id": operation_id,
                },
            )

        super().__init__(message, operation_type="schema", context=context, **kwargs)


class EncodingError(LDAPCoreError):
    """Base class for encoding/decoding errors."""

    def __init__(
        self,
        message: str,
        encoding_type: str | None = None,
        **kwargs: Any,
    ) -> None:
        """Initialize encoding error.

        Args:
            message: Error message
            encoding_type: Type of encoding (BER, DER, etc.)
            **kwargs: Additional arguments for parent class

        """
        context = kwargs.get("context", {})
        if isinstance(context, dict):
            context.update({"encoding_type": encoding_type})

        super().__init__(
            message=message,
            category=ErrorCategory.ENCODING,
            context=context,
            **kwargs,
        )


class ASN1EncodingError(EncodingError):
    """ASN.1 encoding specific errors."""

    def __init__(
        self,
        message: str,
        element_type: str | None = None,
        tag_number: int | None = None,
        **kwargs: Any,
    ) -> None:
        """Initialize ASN.1 encoding error.

        Args:
            message: Error message
            element_type: ASN.1 element type
            tag_number: ASN.1 tag number
            **kwargs: Additional arguments for parent class

        """
        context = kwargs.get("context", {})
        if isinstance(context, dict):
            context.update(
                {
                    "element_type": element_type,
                    "tag_number": tag_number,
                },
            )

        super().__init__(message, encoding_type="ASN.1", context=context, **kwargs)


class ASN1DecodingError(EncodingError):
    """ASN.1 decoding specific errors."""

    def __init__(
        self,
        message: str,
        data_offset: int | None = None,
        data_length: int | None = None,
        **kwargs: Any,
    ) -> None:
        """Initialize ASN.1 decoding error.

        Args:
            message: Error message
            data_offset: Offset in data where error occurred
            data_length: Total data length
            **kwargs: Additional arguments for parent class

        """
        context = kwargs.get("context", {})
        if isinstance(context, dict):
            context.update(
                {
                    "data_offset": data_offset,
                    "data_length": data_length,
                },
            )

        super().__init__(message, encoding_type="ASN.1", context=context, **kwargs)


class SAMLError(LDAPCoreError):
    """Base class for SASL/SAML related errors."""

    def __init__(
        self,
        message: str,
        mechanism: str | None = None,
        **kwargs: Any,
    ) -> None:
        """Initialize SAML error.

        Args:
            message: Error message
            mechanism: SASL mechanism name
            **kwargs: Additional arguments for parent class

        """
        context = kwargs.get("context", {})
        if isinstance(context, dict):
            context.update({"mechanism": mechanism})

        super().__init__(
            message=message,
            category=ErrorCategory.AUTHENTICATION,
            context=context,
            **kwargs,
        )


class MechanismError(SAMLError):
    """SASL mechanism specific errors."""

    def __init__(
        self,
        message: str,
        mechanism: str | None = None,
        step: str | None = None,
        **kwargs: Any,
    ) -> None:
        """Initialize mechanism error.

        Args:
            message: Error message
            mechanism: SASL mechanism name
            step: Authentication step where error occurred
            **kwargs: Additional arguments for parent class

        """
        context = kwargs.get("context", {})
        if isinstance(context, dict):
            context.update({"step": step})

        super().__init__(message, mechanism=mechanism, context=context, **kwargs)


# Exception utilities
def handle_exception(
    operation: str,
    exception: Exception,
    context: dict[str, Any] | None = None,
    severity: ErrorSeverity = ErrorSeverity.MEDIUM,
) -> LDAPCoreError:
    """Convert generic exception to standardized LDAP Core error.

    Args:
        operation: Operation being performed
        exception: Original exception
        context: Additional context
        severity: Error severity level

    Returns:
        Standardized LDAP Core error

    """
    error_context = ErrorContext(operation=operation)
    if context:
        error_context.additional_data.update(context)

    return LDAPCoreError(
        message=f"Operation '{operation}' failed: {exception!s}",
        severity=severity,
        context=error_context,
        cause=exception,
    )


def log_exception(
    logger: Logger,
    exception: LDAPCoreError,
    include_stack_trace: bool = True,
) -> None:
    """Log exception with structured information.

    Args:
        logger: Logger instance
        exception: LDAP Core error to log
        include_stack_trace: Whether to include stack trace

    """
    log_data = exception.to_dict()

    if not include_stack_trace:
        log_data.pop("stack_trace", None)

    # Log based on severity
    if exception.severity == ErrorSeverity.CRITICAL:
        logger.critical("Critical error occurred", extra=log_data)
    elif exception.severity == ErrorSeverity.HIGH:
        logger.error("High severity error occurred", extra=log_data)
    elif exception.severity == ErrorSeverity.MEDIUM:
        logger.warning("Error occurred", extra=log_data)
    else:
        logger.info("Low severity error occurred", extra=log_data)


# Export all exception classes
__all__ = [
    "ASN1DecodingError",
    "ASN1EncodingError",
    "AuthenticationError",
    "ConfigurationValidationError",
    # Connection errors
    "ConnectionError",
    # Encoding errors
    "EncodingError",
    "ErrorCategory",
    "ErrorContext",
    "ErrorSeverity",
    # Base classes
    "LDAPCoreError",
    "MechanismError",
    # Operation errors
    "OperationError",
    "OperationTimeoutError",
    "PoolExhaustedError",
    # SASL errors
    "SAMLError",
    "SchemaOperationError",
    "SchemaValidationError",
    # Validation errors
    "ValidationError",
    # Utilities
    "handle_exception",
    "log_exception",
]
