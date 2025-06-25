"""🚨 LDAP Core Shared Exception Hierarchy.

Comprehensive exception system with clear error categories and Python 3.9+ compatibility.
All exceptions include detailed context and are designed for enterprise error handling.
"""

from __future__ import annotations

# Specific exception categories
from ldap_core_shared.exceptions.auth import AuthenticationError

# Base exceptions
from ldap_core_shared.exceptions.base import LDAPError
from ldap_core_shared.exceptions.connection import ConnectionError
from ldap_core_shared.exceptions.migration import MigrationError
from ldap_core_shared.exceptions.schema import SchemaError
from ldap_core_shared.exceptions.validation import ValidationError

__all__ = [
    # Specific exceptions by category
    "AuthenticationError",
    "ConnectionError",
    # Base exception
    "LDAPError",
    "MigrationError",
    "SchemaError",
    "ValidationError",
]
