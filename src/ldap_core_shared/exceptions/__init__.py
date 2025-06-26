"""🚨 LDAP Core Shared Exception Hierarchy.

UNIFIED EXCEPTION SYSTEM - All exceptions now use core.exceptions.
This module provides imports for backward compatibility with deprecation warnings.

For new code, import directly from:
    from ldap_core_shared.core.exceptions import LDAPCoreError, ValidationError, etc.
"""

from __future__ import annotations

# Import from the unified exception system in core.exceptions
from ldap_core_shared.core.exceptions import (
    ASN1DecodingError,
    ASN1EncodingError,
    AuthenticationError,
    ConfigurationValidationError,
    ConnectionError,
    EncodingError,
    ErrorCategory,
    ErrorContext,
    ErrorSeverity,
    LDAPCoreError,
    MechanismError,
    OperationError,
    PoolExhaustedError,
    SAMLError,
    SchemaOperationError,
    SchemaValidationError,
    ServerConnectionError,
    ValidationError,
)

# Backward compatibility - deprecated imports
from ldap_core_shared.exceptions.base import LDAPError  # Deprecated alias
from ldap_core_shared.exceptions.migration import MigrationError  # Project-specific
from ldap_core_shared.exceptions.schema import SchemaError  # Project-specific

__all__ = [
    "ASN1DecodingError",
    # Specific encoding errors
    "ASN1EncodingError",
    "AuthenticationError",     # Auth errors
    "ConfigurationValidationError",
    "ConnectionError",         # Connection errors
    "EncodingError",           # ASN.1/encoding errors
    "ErrorCategory",
    "ErrorContext",
    # Error metadata
    "ErrorSeverity",
    # PREFERRED: Use these unified exceptions from core.exceptions
    "LDAPCoreError",           # Main base exception
    # DEPRECATED: Use LDAPCoreError instead
    "LDAPError",
    # Specific SASL errors
    "MechanismError",
    # PROJECT-SPECIFIC: These remain for specific project needs
    "MigrationError",          # Migration-specific errors
    "OperationError",          # LDAP operation errors
    "PoolExhaustedError",
    "SAMLError",              # SASL/SAML errors
    "SchemaError",             # Legacy schema errors
    # Specific operation errors
    "SchemaOperationError",
    # Specific validation errors
    "SchemaValidationError",
    # Specific connection errors
    "ServerConnectionError",
    "ValidationError",         # Validation errors
]
