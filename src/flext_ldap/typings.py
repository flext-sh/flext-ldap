"""FLEXT LDAP Type Definitions - Domain-Specific Extensions.

This module provides LDAP-specific type definitions that extend the base types
from flext-core.typings, following the FLEXT ecosystem type hierarchy.

ARCHITECTURE PATTERN: Domain-specific types extending flext-core foundation
- Inherits base types from FlextTypes in flext-core
- Extends with LDAP-specific domain types and business logic
- Maintains consistency with flext-core patterns

Benefits:
✅ Consistent with flext-core type hierarchy
✅ Domain-specific types for LDAP operations
✅ Type safety with FlextResult integration
✅ Enhanced IDE support through inheritance

Type Categories:
    - LDAP Domain Types: Extending flext-core base types
    - LDAP Protocol Definitions: Business protocol interfaces
    - LDAP Service Types: Domain service interfaces
    - LDAP Infrastructure Types: External system integration

Author: FLEXT Development Team
Version: 1.0.0
License: MIT
"""

from __future__ import annotations

from typing import (
    Protocol,
)

from flext_core import (
    FlextTypes,
    P,
    R,
    T,
)

# =============================================================================
# LDAP DOMAIN TYPES - Extending flext-core base types
# =============================================================================

# Core LDAP value types - domain-specific extensions
type LdapAttributeValue = str | bytes | list[str] | list[bytes]
type LdapAttributeDict = dict[str, LdapAttributeValue]
type LdapSearchResult = dict[str, LdapAttributeValue]

# LDAP-specific type aliases following flext-core patterns
type TLdapDn = FlextTypes.Core.Id  # Distinguished Name as ID
type TLdapUri = FlextTypes.Core.ConnectionString  # LDAP URI as connection string
type TLdapFilter = str  # LDAP search filter (domain-specific)
type TLdapSessionId = FlextTypes.Service.CorrelationId  # Session tracking
type TLdapScope = str  # LDAP search scope (subtree, onelevel, base)
type TLdapConnectionId = FlextTypes.Service.ServiceName  # Connection identifier

# LDAP attribute and entry types
type TLdapAttributeValue = LdapAttributeValue
type TLdapAttributes = LdapAttributeDict
type TLdapEntryData = LdapSearchResult
type TLdapSearchResult = list[LdapSearchResult] | list[FlextTypes.Core.Dict]

# Infrastructure types using flext-core base types
type LdapConnectionConfig = FlextTypes.Config.Settings
type SecurityEventData = FlextTypes.Domain.EventData
type ErrorPatternData = FlextTypes.Core.Data
type SchemaData = FlextTypes.Core.Data

# Service layer types using flext-core patterns
type DirectoryAuthConfig = FlextTypes.Auth.Credentials
type ConnectionConfig = FlextTypes.Config.Settings
type UserRequest = FlextTypes.Core.Data
type SearchResult = FlextTypes.Core.Data

# Use flext-core JsonDict type instead of local definition
JsonDict = FlextTypes.Core.JsonDict


class AsyncCallable(Protocol):
    """Callable protocol without explicit Any to satisfy strict mypy."""

    def __call__(self, *args: object, **kwargs: object) -> None:  # pragma: no cover
        ...


# =============================================================================
# FLEXT-CORE PROTOCOL INTEGRATION - LOCAL PROTOCOLS ELIMINATED
# =============================================================================

# LOCAL PROTOCOLS ELIMINATED - NOW USING FlextProtocols FROM FLEXT-CORE
# Per CLAUDE.md: "PROTOCOLS: Define once in flext-core/protocols.py"

# Legacy protocols replaced with flext-core patterns:
# - FlextLdapConnectionProtocol -> Use FlextProtocols.Domain.Service
# - FlextLdapRepositoryProtocol -> Use FlextProtocols.Domain.Repository[T]
# - FlextLdapDirectoryConnectionProtocol -> Use FlextProtocols.Domain.Service
# - FlextLdapDirectoryEntryProtocol -> Use standard Dict protocol

# Import flext-core protocols for type hints where needed
# from flext_core import FlextProtocols


# =============================================================================
# EXPORTS
# =============================================================================

__all__ = [
    "AsyncCallable",
    "ConnectionConfig",
    "DirectoryAuthConfig",
    "ErrorPatternData",
    # LOCAL PROTOCOLS REMOVED - USE FlextProtocols FROM FLEXT-CORE
    "JsonDict",
    "LdapAttributeDict",
    "LdapAttributeValue",
    "LdapConnectionConfig",
    "LdapSearchResult",
    "P",
    "R",
    "SchemaData",
    "SearchResult",
    "SecurityEventData",
    "T",
    "TLdapAttributeValue",
    "TLdapAttributes",
    "TLdapConnectionId",
    "TLdapDn",
    "TLdapEntryData",
    "TLdapFilter",
    "TLdapScope",
    "TLdapSearchResult",
    "TLdapSessionId",
    "TLdapUri",
    "UserRequest",
]
