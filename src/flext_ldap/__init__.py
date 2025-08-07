"""FLEXT-LDAP - Enterprise LDAP Directory Services Library.

🏗️ CLEAN ARCHITECTURE | DDD | RAILWAY-ORIENTED PROGRAMMING

Enterprise-grade LDAP operations library implementing docs/patterns/foundation.md
patterns with type-safe operations and comprehensive error handling.

PUBLIC API - PRODUCTION GRADE:
    FlextLdapApi: Primary interface following flext-core patterns
    FlextLdapService: Application service for business operations
    Domain Entities: FlextLdapUser, FlextLdapGroup, FlextLdapEntry
    Value Objects: FlextLdapCreateUserRequest, FlextLdapDistinguishedName
    Configuration: FlextLdapSettings, FlextLdapConnectionConfig

MODERN USAGE:
    >>> from flext_ldap import FlextLdapApi, FlextLdapCreateUserRequest
    >>> api = FlextLdapApi()
    >>> async with api.connection(server_url, bind_dn, password) as session:
    ...     user_request = FlextLdapCreateUserRequest(
    ...         dn="uid=john,ou=users,dc=example,dc=com",
    ...         uid="john",
    ...         cn="John Doe",
    ...         sn="Doe",
    ...     )
    ...     result = await api.create_user(session, user_request)
    ...     if result.is_success:
    ...         print(f"Created: {result.data.dn}")

FLEXT-CORE INTEGRATION:
    Built on flext-core foundation with FlextResult pattern, FlextEntity base classes,
    and centralized configuration management following enterprise standards.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

import warnings

# ✅ FLEXT-CORE FOUNDATION
from flext_core import FlextLDAPConfig

# ✅ PRIMARY PUBLIC API - PRODUCTION GRADE
from flext_ldap.api import FlextLdapApi, get_ldap_api
from flext_ldap.application.ldap_service import FlextLdapService

# ✅ CONFIGURATION - ENTERPRISE PATTERNS
from flext_ldap.config import FlextLdapConnectionConfig, FlextLdapSettings

# ✅ DOMAIN ENTITIES - RICH BUSINESS OBJECTS
from flext_ldap.entities import FlextLdapEntry, FlextLdapGroup, FlextLdapUser

# ✅ INFRASTRUCTURE - FOR ADVANCED USAGE
from flext_ldap.ldap_infrastructure import FlextLdapSimpleClient

# ✅ VALIDATION UTILITIES - PUBLIC API
from flext_ldap.utils import (
    flext_ldap_sanitize_attribute_name,
    flext_ldap_validate_attribute_name,
    flext_ldap_validate_attribute_value,
    flext_ldap_validate_dn,
)

# ✅ VALUE OBJECTS - IMMUTABLE DATA STRUCTURES
from flext_ldap.values import (
    FlextLdapCreateUserRequest,
    FlextLdapDistinguishedName,
    FlextLdapExtendedEntry,
    FlextLdapFilterValue,
    FlextLdapScopeEnum,
)

# ✅ BACKWARD COMPATIBILITY - SIMPLE ALIASES
LDAPEntry = FlextLdapExtendedEntry
LDAPFilter = FlextLdapFilterValue
LDAPScope = FlextLdapScopeEnum


def __getattr__(name: str) -> object:
    """Legacy import handler with deprecation warnings."""
    # API class aliases - all map to FlextLdapApi
    if name in {
        "FlextLdapClient",
        "LDAPClient",
        "SimpleAPI",
        "FlextLdapAPIClient",
        "LDAPService",
    }:
        warnings.warn(
            f"🚨 DEPRECATED API: {name} is deprecated.\n"
            f"✅ MODERN SOLUTION: Use FlextLdapApi instead\n"
            f"💡 Import: from flext_ldap import FlextLdapApi\n"
            f"📖 Migration will be required in v1.0.0",
            DeprecationWarning,
            stacklevel=2,
        )
        return FlextLdapApi

    # Entity aliases - point to modern classes
    entity_mappings = {
        "LDAPUser": FlextLdapUser,
        "LDAPGroup": FlextLdapGroup,
        "CreateUserRequest": FlextLdapCreateUserRequest,
        "FlextLdapFilter": FlextLdapFilterValue,
        "FlextLdapScope": FlextLdapScopeEnum,
    }

    if name in entity_mappings:
        warnings.warn(
            f"🚨 DEPRECATED IMPORT: {name} is deprecated.\n"
            f"✅ MODERN SOLUTION: Use full class name from flext_ldap\n"
            f"💡 Available classes: {list(entity_mappings.values())}\n"
            f"📖 Legacy imports will be removed in v1.0.0",
            DeprecationWarning,
            stacklevel=2,
        )
        return entity_mappings[name]

    msg = f"module 'flext_ldap' has no attribute '{name}'"
    raise AttributeError(msg)


# ✅ CLEAN PUBLIC API - PRODUCTION GRADE
__all__ = [
    "FlextLDAPConfig",
    "FlextLdapApi",
    "FlextLdapConnectionConfig",
    "FlextLdapCreateUserRequest",
    "FlextLdapDistinguishedName",
    "FlextLdapEntry",
    "FlextLdapExtendedEntry",
    "FlextLdapFilterValue",
    "FlextLdapGroup",
    "FlextLdapScopeEnum",
    "FlextLdapService",
    "FlextLdapSettings",
    "FlextLdapSimpleClient",
    "FlextLdapUser",
    "LDAPEntry",
    "LDAPFilter",
    "LDAPScope",
    "flext_ldap_sanitize_attribute_name",
    "flext_ldap_validate_attribute_name",
    "flext_ldap_validate_attribute_value",
    "flext_ldap_validate_dn",
    "get_ldap_api",
]
