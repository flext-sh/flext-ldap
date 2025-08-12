"""FLEXT LDAP Exceptions - PEP8 compliant exception hierarchy.

Consolidates all LDAP exceptions into a single, well-organized module following
PEP8 naming standards and flext-core exception patterns. This module provides
a comprehensive exception hierarchy for LDAP operations.

Originally consolidated from:
- ldap_exceptions.py: Primary LDAP exception classes
- errors.py: Generic error handling patterns
- domain_exceptions.py: Domain-specific exceptions

Architecture:
    - Extends flext-core exception patterns for consistency
    - Implements hierarchical exception design
    - Provides LDAP-specific error handling
    - Follows Clean Architecture error patterns

Key Features:
    - FlextLdapError: Base exception for all LDAP operations
    - Specific exception types for different error categories
    - Integration with FlextResult pattern
    - Structured error information and context

Copyright (c) 2025 FLEXT Contributors
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from flext_core import FlextError, get_logger

logger = get_logger(__name__)


# PEP8 Compliant exception hierarchy (consolidated implementation)
class FlextLdapError(FlextError):
    """Base exception for LDAP operations."""


class FlextLdapConnectionError(FlextLdapError):
    """LDAP connection error."""


class FlextLdapAuthenticationError(FlextLdapError):
    """LDAP authentication error."""


class FlextLdapValidationError(FlextLdapError):
    """LDAP validation error."""


class FlextLdapConfigurationError(FlextLdapError):
    """LDAP configuration error."""


class FlextLdapTimeoutError(FlextLdapError):
    """LDAP timeout error."""


class FlextLdapNotFoundError(FlextLdapError):
    """LDAP resource not found error."""
