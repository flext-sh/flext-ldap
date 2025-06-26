"""Generic exception hierarchy for LDAP migration projects.

This module provides a comprehensive exception hierarchy that can be used
by any LDAP migration project to ensure consistent error handling and reporting.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, Optional

logger = logging.getLogger(__name__)


class LDAPMigrationError(Exception):
    """Base exception for all LDAP migration-related errors."""

    def __init__(
        self,
        message: str,
        operation: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
    ) -> None:
        super().__init__(message)
        self.operation = operation
        self.details = details or {}

    def __str__(self) -> str:
        """Return formatted string representation of the migration error."""
        result = super().__str__()
        if self.operation:
            result = f"[{self.operation}] {result}"
        return result


class LDAPConnectionError(LDAPMigrationError):
    """LDAP connection-related errors."""

    def __init__(
        self,
        message: str,
        host: Optional[str] = None,
        port: Optional[int] = None,
        **kwargs: Any,
    ) -> None:
        super().__init__(message, "Connection", kwargs)
        self.host = host
        self.port = port


class LDAPSchemaError(LDAPMigrationError):
    """Schema processing-related errors."""

    def __init__(
        self,
        message: str,
        element_name: Optional[str] = None,
        element_type: Optional[str] = None,
        **kwargs: Any,
    ) -> None:
        super().__init__(message, "Schema", kwargs)
        self.element_name = element_name
        self.element_type = element_type


class LDIFProcessingError(LDAPMigrationError):
    """LDIF processing-related errors."""

    def __init__(
        self,
        message: str,
        file_path: Optional[str] = None,
        line_number: Optional[int] = None,
        **kwargs: Any,
    ) -> None:
        super().__init__(message, "LDIF", kwargs)
        self.file_path = file_path
        self.line_number = line_number


class MigrationConfigurationError(LDAPMigrationError):
    """Configuration-related errors."""

    def __init__(
        self,
        message: str,
        config_field: Optional[str] = None,
        **kwargs: Any,
    ) -> None:
        super().__init__(message, "Configuration", kwargs)
        self.config_field = config_field


class MigrationValidationError(LDAPMigrationError):
    """Validation-related errors."""

    def __init__(
        self,
        message: str,
        validation_type: Optional[str] = None,
        **kwargs: Any,
    ) -> None:
        super().__init__(message, "Validation", kwargs)
        self.validation_type = validation_type


class ProcessorError(LDAPMigrationError):
    """Processor-related errors."""

    def __init__(
        self,
        message: str,
        processor_type: Optional[str] = None,
        **kwargs: Any,
    ) -> None:
        super().__init__(message, "Processor", kwargs)
        self.processor_type = processor_type


class HierarchyError(LDAPMigrationError):
    """Hierarchy processing-related errors."""

    def __init__(
        self,
        message: str,
        dn: Optional[str] = None,
        parent_dn: Optional[str] = None,
        **kwargs: Any,
    ) -> None:
        super().__init__(message, "Hierarchy", kwargs)
        self.dn = dn
        self.parent_dn = parent_dn


class ACLProcessingError(LDAPMigrationError):
    """ACL processing-related errors."""

    def __init__(
        self,
        message: str,
        acl_type: Optional[str] = None,
        acl_value: Optional[str] = None,
        **kwargs: Any,
    ) -> None:
        super().__init__(message, "ACL", kwargs)
        self.acl_type = acl_type
        self.acl_value = acl_value


class PathValidationError(MigrationValidationError):
    """Path validation-specific error."""

    def __init__(
        self,
        message: str,
        path: Optional[str] = None,
        **kwargs: Any,
    ) -> None:
        super().__init__(message, "PathValidation", kwargs)
        self.path = path


class ConfigValidationError(MigrationValidationError):
    """Configuration validation-specific error."""

    def __init__(
        self,
        message: str,
        config_key: Optional[str] = None,
        expected_type: Optional[str] = None,
        **kwargs: Any,
    ) -> None:
        super().__init__(message, "ConfigValidation", kwargs)
        self.config_key = config_key
        self.expected_type = expected_type


def create_detailed_error(
    base_exception: Exception,
    operation: str,
    context: Optional[Dict[str, Any]] = None,
) -> LDAPMigrationError:
    """Create a detailed migration error from a base exception.
    
    Args:
        base_exception: The original exception
        operation: The operation that was being performed
        context: Additional context information
        
    Returns:
        LDAPMigrationError with detailed information
    """
    message = str(base_exception)
    details = context or {}
    details["original_exception_type"] = type(base_exception).__name__
    
    return LDAPMigrationError(
        message=message,
        operation=operation,
        details=details,
    )


def log_migration_error(error: LDAPMigrationError, level: str = "error") -> None:
    """Log a migration error with structured information.
    
    Args:
        error: The migration error to log
        level: Log level (debug, info, warning, error, critical)
    """
    log_func = getattr(logger, level.lower(), logger.error)
    
    log_func(f"Migration error: {error}")
    
    if error.operation:
        log_func(f"  Operation: {error.operation}")
    
    if error.details:
        for key, value in error.details.items():
            log_func(f"  {key}: {value}")
    
    # Log specific attributes for different error types
    if isinstance(error, LDAPConnectionError):
        if error.host:
            log_func(f"  Host: {error.host}")
        if error.port:
            log_func(f"  Port: {error.port}")
    
    elif isinstance(error, LDAPSchemaError):
        if error.element_name:
            log_func(f"  Element: {error.element_name}")
        if error.element_type:
            log_func(f"  Type: {error.element_type}")
    
    elif isinstance(error, LDIFProcessingError):
        if error.file_path:
            log_func(f"  File: {error.file_path}")
        if error.line_number:
            log_func(f"  Line: {error.line_number}")


def handle_migration_exception(
    operation: str,
    exception: Exception,
    context: Optional[Dict[str, Any]] = None,
    reraise: bool = True,
) -> Optional[LDAPMigrationError]:
    """Handle and optionally re-raise migration exceptions.
    
    Args:
        operation: The operation that failed
        exception: The exception that occurred
        context: Additional context information
        reraise: Whether to re-raise the exception
        
    Returns:
        LDAPMigrationError if not re-raising, None otherwise
        
    Raises:
        LDAPMigrationError: If reraise is True
    """
    if isinstance(exception, LDAPMigrationError):
        migration_error = exception
    else:
        migration_error = create_detailed_error(exception, operation, context)
    
    log_migration_error(migration_error)
    
    if reraise:
        raise migration_error
    
    return migration_error