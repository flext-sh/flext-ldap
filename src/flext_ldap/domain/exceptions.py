"""LDAP Domain Exceptions - Version 0.7.0.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

Domain-specific exceptions for LDAP operations.
"""

from __future__ import annotations


class LDAPDomainError(Exception):
    """Base exception for LDAP domain errors."""


class LDAPEntityError(LDAPDomainError):
    """Errors related to LDAP entity operations."""


class LDAPUserError(LDAPEntityError):
    """Errors specific to LDAP user operations."""


class LDAPGroupError(LDAPEntityError):
    """Errors specific to LDAP group operations."""


class LDAPConnectionError(LDAPEntityError):
    """Errors specific to LDAP connection operations."""


class LDAPOperationError(LDAPEntityError):
    """Errors specific to LDAP operation tracking."""


class LDAPValidationError(LDAPDomainError):
    """Validation errors for LDAP data."""


class LDAPNotFoundError(LDAPDomainError):
    """Error when LDAP entity is not found."""


class LDAPDuplicateError(LDAPDomainError):
    """Error when LDAP entity already exists."""


class LDAPServiceError(LDAPDomainError):
    """Errors related to high-level LDAP service operations."""
