"""FLEXT-LDAP Models - Compatibility re-export layer.

This module re-exports all domain models from their specific modules
to maintain backward compatibility while following SOLID principles.

ARCHITECTURE: This is a facade that provides a single import point
for all domain models while keeping the actual implementations
organized in focused, single-responsibility modules.
"""

from __future__ import annotations

# Import required for entity status
from flext_core import FlextEntity

# Re-export configuration models
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

# Re-export constants consolidation
from flext_ldap.constants import (
    FlextLdapAttributeConstants,
    FlextLdapConnectionConstants,
    FlextLdapConstants,
    FlextLdapProtocolConstants,
)

# Re-export domain entities
from flext_ldap.entities import (
    FlextLdapCreateUserRequest,
    FlextLdapEntry,
    FlextLdapGroup,
    FlextLdapSearchRequest,
    FlextLdapSearchResponse,
    FlextLdapUser,
)

# Re-export field definitions and processors
from flext_ldap.fields import (
    FlextLdapDataType,
    FlextLdapScopeEnum,
    LdapAttributeProcessor,
    LdapDomainValidator,
)

# Re-export type definitions
from flext_ldap.typings import (
    LdapAttributeDict,
    LdapAttributeValue,
    LdapSearchResult,
)

# Re-export value objects
from flext_ldap.value_objects import (
    FlextLdapDistinguishedName,
    FlextLdapFilter,
    FlextLdapScope,
)

# Type aliases
FlextLdapEntityStatus = getattr(FlextEntity, "status", None)
LDAPScope = FlextLdapScopeEnum

# Re-export for consistency with original API
__all__ = [
    "FlextLdapAttributeConstants",
    "FlextLdapAuthConfig",
    "FlextLdapConnectionConfig",
    "FlextLdapConnectionConstants",
    "FlextLdapConstants",
    "FlextLdapCreateUserRequest",
    "FlextLdapDataType",
    "FlextLdapDistinguishedName",
    "FlextLdapEntityStatus",
    "FlextLdapEntry",
    "FlextLdapFilter",
    "FlextLdapGroup",
    "FlextLdapLoggingConfig",
    "FlextLdapProtocolConstants",
    "FlextLdapScope",
    "FlextLdapScopeEnum",
    "FlextLdapSearchConfig",
    "FlextLdapSearchRequest",
    "FlextLdapSearchResponse",
    "FlextLdapSettings",
    "FlextLdapUser",
    "LDAPScope",
    "LdapAttributeDict",
    "LdapAttributeProcessor",
    "LdapAttributeValue",
    "LdapDomainValidator",
    "LdapSearchResult",
    "create_development_config",
    "create_production_config",
    "create_test_config",
]
