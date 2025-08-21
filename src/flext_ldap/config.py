"""FLEXT-LDAP Configuration - Re-export from configuration module.

This module maintains backward compatibility by re-exporting
configuration classes from the new configuration module.
"""

from __future__ import annotations

# Re-export everything from configuration module
from flext_ldap.configuration import (
    FlextLdapAuthConfig,
    FlextLdapConnectionConfig,
    FlextLdapLoggingConfig,
    FlextLdapSearchConfig,
    FlextLdapSettings,
    create_development_config,
    create_production_config,
    create_test_config,
)

# Import scope enum
from flext_ldap.fields import FlextLdapScopeEnum as FlextLdapScope

# Additional imports from models for backward compatibility
from flext_ldap.models import (
    FlextLdapConstants,
    FlextLdapProtocolConstants,
    LdapAttributeProcessor,
)

__all__ = [
    # Configuration classes
    "FlextLdapAuthConfig",
    "FlextLdapConnectionConfig",
    # Constants
    "FlextLdapConstants",
    "FlextLdapLoggingConfig",
    "FlextLdapProtocolConstants",
    "FlextLdapScope",
    "FlextLdapSearchConfig",
    "FlextLdapSettings",
    # Factory functions
    "LdapAttributeProcessor",
    "create_development_config",
    "create_production_config",
    "create_test_config",
]
