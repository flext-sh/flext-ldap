"""FLEXT-LDAP - Enterprise LDAP Directory Services Library.

Enterprise-grade LDAP operations library implementing Clean Architecture and
Domain-Driven Design patterns. Built on the FLEXT Core foundation for type-safe,
scalable LDAP directory integration.

Architecture:
    This library follows Clean Architecture principles with clear separation
    between domain logic, application services, and infrastructure concerns.
    All operations use railway-oriented programming via FlextResult for
    comprehensive error handling.

Key Components:
    - FlextLdapApi: Unified interface for all LDAP operations
    - Domain Entities: Rich business objects (FlextLdapUser, FlextLdapGroup)
    - Value Objects: Immutable data structures with validation
    - Repository Pattern: Abstract data access with concrete implementations

Example:
    Basic LDAP operations using the unified API:

    >>> from flext_ldap import get_ldap_api, FlextLdapCreateUserRequest
    >>>
    >>> api = get_ldap_api()
    >>> async with api.connection(server_url, bind_dn, password) as session:
    ...     # Search directory entries
    ...     result = await api.search(session, base_dn, "(objectClass=person)")
    ...     if result.is_success:
    ...         for entry in result.data:
    ...             print(f"Found: {entry.dn}")
    ...
    ...     # Create new user
    ...     user_request = FlextLdapCreateUserRequest(
    ...         dn="uid=john,ou=users,dc=example,dc=com",
    ...         uid="john", cn="John Doe", sn="Doe"
    ...     )
    ...     create_result = await api.create_user(session, user_request)

Integration:
    - Built on flext-core foundation patterns
    - Integrates with flext-auth for authentication services
    - Compatible with Singer/Meltano data pipeline ecosystem
    - Supports LDIF data interchange format

Standards Compliance:
    - RFC 4510-4519: LDAP protocol compliance
    - RFC 4514: Distinguished Names (DN) format
    - RFC 4515: LDAP search filters
    - Type-safe operations with 100% MyPy compliance

Author: FLEXT Development Team
Version: 0.9.0
License: MIT

"""

from __future__ import annotations

# Legacy compatibility - these will show deprecation warnings
import warnings

# Configuration - Updated to use centralized FlextLDAPConfig from flext-core
from flext_core import FlextLDAPConfig

# Core API - Single point of entry
from flext_ldap.api import FlextLdapApi, get_ldap_api
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
        # Add missing legacy mappings
        "FlextLdapFilter": FlextLdapFilterValue,
        "FlextLdapScope": FlextLdapScopeEnum,
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
    # Configuration - Centralized from flext-core
    "FlextLDAPConfig",
    # Core API
    "FlextLdapApi",
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
