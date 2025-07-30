"""LDAP Domain Exceptions - Version 0.7.0.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

Domain-specific exceptions for LDAP operations inheriting from flext-core.
"""

from __future__ import annotations

from flext_core.exceptions import (
    FlextAlreadyExistsError,
    FlextConnectionError,
    FlextError,
    FlextNotFoundError,
    FlextOperationError,
    FlextValidationError,
)

__all__ = [
    "FlextLdapConnectionError",
    # New FlextLdap prefixed exceptions
    "FlextLdapDomainError",
    "FlextLdapDuplicateError",
    "FlextLdapEntityError",
    "FlextLdapGroupError",
    "FlextLdapNotFoundError",
    "FlextLdapOperationError",
    "FlextLdapServiceError",
    "FlextLdapUserError",
    "FlextLdapValidationError",
    "LDAPConnectionError",
    # Backward compatibility aliases
    "LDAPDomainError",
    "LDAPDuplicateError",
    "LDAPEntityError",
    "LDAPGroupError",
    "LDAPNotFoundError",
    "LDAPOperationError",
    "LDAPServiceError",
    "LDAPUserError",
    "LDAPValidationError",
]


class FlextLdapDomainError(FlextError):
    """Base exception for LDAP domain errors."""

    def __init__(self, message: str = "LDAP domain error", **kwargs: object) -> None:
        """Initialize LDAP domain error with context."""
        super().__init__(message, error_code="LDAP_DOMAIN_ERROR", context=kwargs)


class FlextLdapEntityError(FlextLdapDomainError):
    """Errors related to LDAP entity operations."""

    def __init__(self, message: str = "LDAP entity error", **kwargs: object) -> None:
        """Initialize LDAP entity error with context."""
        super().__init__(f"Entity error: {message}", **kwargs)


class FlextLdapUserError(FlextLdapEntityError):
    """Errors specific to LDAP user operations."""

    def __init__(self, message: str = "LDAP user error", **kwargs: object) -> None:
        """Initialize LDAP user error with context."""
        super().__init__(f"User error: {message}", **kwargs)


class FlextLdapGroupError(FlextLdapEntityError):
    """Errors specific to LDAP group operations."""

    def __init__(self, message: str = "LDAP group error", **kwargs: object) -> None:
        """Initialize LDAP group error with context."""
        super().__init__(f"Group error: {message}", **kwargs)


class FlextLdapConnectionError(FlextConnectionError):
    """Errors specific to LDAP connection operations."""

    def __init__(self, message: str = "LDAP connection failed", **kwargs: object) -> None:
        """Initialize LDAP connection error with context."""
        super().__init__(f"LDAP connection: {message}", **kwargs)


class FlextLdapOperationError(FlextOperationError):
    """Errors specific to LDAP operation tracking."""

    def __init__(
        self,
        message: str = "LDAP operation failed",
        operation: str | None = None,
        stage: str | None = None,
        **kwargs: object,
    ) -> None:
        """Initialize LDAP operation error with context."""
        super().__init__(f"LDAP operation: {message}", operation=operation, stage=stage, context=kwargs)


class FlextLdapValidationError(FlextValidationError):
    """Validation errors for LDAP data."""

    def __init__(
        self,
        message: str = "LDAP validation failed",
        field: str | None = None,
        value: object = None,
        **kwargs: object,
    ) -> None:
        """Initialize LDAP validation error with context."""
        validation_details = {}
        if field is not None:
            validation_details["field"] = field
        if value is not None:
            validation_details["value"] = value

        super().__init__(
            f"LDAP validation: {message}",
            validation_details=validation_details,
            context=kwargs,
        )


class FlextLdapNotFoundError(FlextNotFoundError):
    """Error when LDAP entity is not found."""

    def __init__(self, message: str = "LDAP entity not found", **kwargs: object) -> None:
        """Initialize LDAP not found error with context."""
        super().__init__(f"LDAP not found: {message}", **kwargs)


class FlextLdapDuplicateError(FlextAlreadyExistsError):
    """Error when LDAP entity already exists."""

    def __init__(self, message: str = "LDAP entity already exists", **kwargs: object) -> None:
        """Initialize LDAP duplicate error with context."""
        super().__init__(f"LDAP duplicate: {message}", **kwargs)


class FlextLdapServiceError(FlextLdapDomainError):
    """Errors related to high-level LDAP service operations."""

    def __init__(self, message: str = "LDAP service error", **kwargs: object) -> None:
        """Initialize LDAP service error with context."""
        super().__init__(f"Service error: {message}", **kwargs)


# Backward compatibility aliases
LDAPDomainError = FlextLdapDomainError
LDAPEntityError = FlextLdapEntityError
LDAPUserError = FlextLdapUserError
LDAPGroupError = FlextLdapGroupError
LDAPConnectionError = FlextLdapConnectionError
LDAPOperationError = FlextLdapOperationError
LDAPValidationError = FlextLdapValidationError
LDAPNotFoundError = FlextLdapNotFoundError
LDAPDuplicateError = FlextLdapDuplicateError
LDAPServiceError = FlextLdapServiceError
