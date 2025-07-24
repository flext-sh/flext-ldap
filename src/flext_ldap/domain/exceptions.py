"""LDAP Domain Exceptions - Version 0.7.0.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

Domain-specific exceptions for LDAP operations.
"""

from __future__ import annotations

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


class FlextLdapDomainError(Exception):
    """Base exception for LDAP domain errors."""


class FlextLdapEntityError(FlextLdapDomainError):
    """Errors related to LDAP entity operations."""


class FlextLdapUserError(FlextLdapEntityError):
    """Errors specific to LDAP user operations."""


class FlextLdapGroupError(FlextLdapEntityError):
    """Errors specific to LDAP group operations."""


class FlextLdapConnectionError(FlextLdapEntityError):
    """Errors specific to LDAP connection operations."""


class FlextLdapOperationError(FlextLdapEntityError):
    """Errors specific to LDAP operation tracking."""


class FlextLdapValidationError(FlextLdapDomainError):
    """Validation errors for LDAP data."""


class FlextLdapNotFoundError(FlextLdapDomainError):
    """Error when LDAP entity is not found."""


class FlextLdapDuplicateError(FlextLdapDomainError):
    """Error when LDAP entity already exists."""


class FlextLdapServiceError(FlextLdapDomainError):
    """Errors related to high-level LDAP service operations."""


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
