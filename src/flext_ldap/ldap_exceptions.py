"""FLEXT-LDAP Exceptions - Consolidated Exception Handling.

🎯 CONSOLIDATES FROM errors.py INTO SINGLE PEP8 MODULE

This module provides comprehensive exception handling for FLEXT-LDAP
operations with type-safe error handling and detailed error information.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from flext_core import FlextExceptions

# Create alias for backward compatibility
FlextException = FlextExceptions

# =============================================================================
# LDAP DOMAIN EXCEPTIONS - TYPE-SAFE ERROR HIERARCHY
# =============================================================================


class FlextLdapException(FlextException):
    """Base exception for all FLEXT-LDAP errors."""


class FlextLdapConnectionError(FlextLdapException):
    """LDAP connection related errors."""


class FlextLdapAuthenticationError(FlextLdapException):
    """LDAP authentication errors."""


class FlextLdapSearchError(FlextLdapException):
    """LDAP search operation errors."""


class FlextLdapValidationError(FlextLdapException):
    """LDAP data validation errors."""


class FlextLdapUserError(FlextLdapException):
    """LDAP user-specific errors."""


class FlextLdapGroupError(FlextLdapException):
    """LDAP group-specific errors."""


class FlextLdapOperationError(FlextLdapException):
    """LDAP operation errors (add, modify, delete)."""


class FlextLdapConfigurationError(FlextLdapException):
    """LDAP configuration and settings errors."""


class FlextLdapTypeError(FlextLdapException):
    """LDAP type validation and conversion errors."""


# Export all exception classes
__all__ = [
    "FlextLdapAuthenticationError",
    "FlextLdapConfigurationError",
    "FlextLdapConnectionError",
    "FlextLdapException",
    "FlextLdapGroupError",
    "FlextLdapOperationError",
    "FlextLdapSearchError",
    "FlextLdapTypeError",
    "FlextLdapUserError",
    "FlextLdapValidationError",
]
