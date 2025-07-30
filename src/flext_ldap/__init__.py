"""FLEXT LDAP - Enterprise LDAP Operations Library.

Unified enterprise-grade LDAP library using flext-core patterns.
Provides Clean Architecture with Domain-Driven Design for LDAP operations.

✅ UNIFIED API (NEW):
from flext_ldap import FlextLdapApi, get_ldap_api

🚀 USAGE EXAMPLES:
```python
# Simple API usage
from flext_ldap import get_ldap_api

api = get_ldap_api()

# Connect with session management
async with api.connection(
    "ldap://localhost", "cn=admin,dc=example,dc=com", "admin"
) as session:
    # Search users
    users = await api.search(
        session, "ou=users,dc=example,dc=com", "(objectClass=person)"
    )

    # Create user
    user_request = FlextLdapCreateUserRequest(
        dn="cn=john,ou=users,dc=example,dc=com", uid="john", cn="John Doe", sn="Doe"
    )
    new_user = await api.create_user(session, user_request)
```

🏗️ DOMAIN OBJECTS:
All operations return rich domain entities instead of raw dictionaries.
Type-safe error handling via FlextResult pattern.

Copyright (c) 2025 FLEXT Team. All rights reserved.
"""

from __future__ import annotations

# Legacy compatibility - these will show deprecation warnings
import warnings

# Core API - Single point of entry
from flext_ldap.api import FlextLdapApi, get_ldap_api

# Configuration
from flext_ldap.config import FlextLdapConnectionConfig, FlextLdapSettings

# Domain entities and value objects (now at root - cleaner imports)
from flext_ldap.entities import FlextLdapEntry, FlextLdapGroup, FlextLdapUser

# Infrastructure client (now at root)
from flext_ldap.ldap_infrastructure import FlextLdapSimpleClient
from flext_ldap.values import (
    FlextLdapCreateUserRequest,
    FlextLdapDistinguishedName,
    FlextLdapExtendedEntry,
    FlextLdapFilterValue,
    FlextLdapScopeEnum,
    # Consolidated aliases for backward compatibility
    LDAPEntry,
    LDAPFilter,
    LDAPScope,
)


def __getattr__(name: str) -> object:
    """Handle legacy imports with deprecation warnings."""
    # Legacy API mappings with warnings
    legacy_mappings = {
        "FlextLdapClient": "FlextLdapApi",
        "LDAPClient": "FlextLdapApi",
        "SimpleAPI": "FlextLdapApi",
        "FlextLdapAPIClient": "FlextLdapApi",
        "LDAPService": "FlextLdapApi",
    }

    if name in legacy_mappings:
        warnings.warn(
            f"Importing {name} is deprecated. "
            f"Use 'from flext_ldap import {legacy_mappings[name]}' instead.",
            DeprecationWarning,
            stacklevel=2,
        )
        return FlextLdapApi

    # Legacy entity mappings
    entity_mappings = {
        "LDAPUser": FlextLdapUser,
        "LDAPGroup": FlextLdapGroup,
        "LDAPEntry": FlextLdapEntry,
        "FlextLdapDistinguishedName": FlextLdapDistinguishedName,
        "CreateUserRequest": FlextLdapCreateUserRequest,
    }

    if name in entity_mappings:
        warnings.warn(
            f"Importing {name} from root is deprecated. "
            f"Use 'from flext_ldap import Flext{name}' instead.",
            DeprecationWarning,
            stacklevel=2,
        )
        return entity_mappings[name]

    msg = f"module '{__name__}' has no attribute '{name}'"
    raise AttributeError(msg)


# Clean public API
__all__ = [
    # Core API
    "FlextLdapApi",
    # Configuration
    "FlextLdapConnectionConfig",
    "FlextLdapCreateUserRequest",
    "FlextLdapDistinguishedName",
    # Domain objects
    "FlextLdapEntry",
    "FlextLdapExtendedEntry",
    "FlextLdapFilterValue",
    "FlextLdapGroup",
    "FlextLdapScopeEnum",
    "FlextLdapSettings",
    # Infrastructure (for advanced usage)
    "FlextLdapSimpleClient",
    "FlextLdapUser",
    # Consolidated backward compatibility
    "LDAPEntry",
    "LDAPFilter",
    "LDAPScope",
    "get_ldap_api",
]
