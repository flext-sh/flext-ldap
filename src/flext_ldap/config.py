"""Configuration facade for backward compatibility.

This module provides backward compatibility imports from the configuration module.
"""

from __future__ import annotations

# Import all configuration classes from the main configuration module
from flext_ldap.configuration import (
    FlextLDAPAuthConfig,
    FlextLDAPConnectionConfig,
    FlextLDAPLoggingConfig,
    FlextLDAPSearchConfig,
    FlextLDAPSettings,
)

# Re-export all classes
__all__ = [
    "FlextLDAPAuthConfig",
    "FlextLDAPConnectionConfig",
    "FlextLDAPLoggingConfig",
    "FlextLDAPSearchConfig",
    "FlextLDAPSettings",
]
