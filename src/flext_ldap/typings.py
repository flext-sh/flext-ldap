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
    runtime_checkable,
)

from flext_core import FlextResult
from flext_core.typings import (
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
# PROTOCOL DEFINITIONS
# =============================================================================


@runtime_checkable
class FlextLdapConnectionProtocol(Protocol):
    """Protocol for LDAP connection implementations."""

    async def connect(
        self,
        server_uri: str,
        bind_dn: str | None = None,
        bind_password: str | None = None,
    ) -> FlextResult[None]:
        """Connect to LDAP server."""
        ...

    async def disconnect(self) -> FlextResult[None]:
        """Disconnect from LDAP server."""
        ...

    async def search(
        self,
        base_dn: str,
        search_filter: str,
        scope: str = "subtree",
        attributes: list[str] | None = None,
    ) -> FlextResult[list[LdapSearchResult]]:
        """Perform LDAP search."""
        ...


@runtime_checkable
class FlextLdapRepositoryProtocol(Protocol):
    """Protocol for LDAP repository implementations."""

    async def find_by_dn(self, dn: str) -> FlextResult[LdapSearchResult | None]:
        """Find entry by Distinguished Name."""
        ...

    async def save(self, entry_data: LdapAttributeDict) -> FlextResult[None]:
        """Save entry data."""
        ...

    async def delete(self, dn: str) -> FlextResult[None]:
        """Delete entry by DN."""
        ...


@runtime_checkable
class FlextLdapDirectoryConnectionProtocol(Protocol):
    """Protocol for directory connection implementations."""

    def is_connected(self) -> bool:
        """Check if connection is active."""
        ...

    async def bind(self, dn: str, password: str) -> FlextResult[None]:
        """Perform LDAP bind operation."""
        ...


@runtime_checkable
class FlextLdapDirectoryEntryProtocol(Protocol):
    """Protocol for directory entry implementations."""

    @property
    def dn(self) -> str:
        """Get Distinguished Name."""
        ...

    @property
    def attributes(self) -> dict[str, list[str]]:
        """Get entry attributes."""
        ...

    def get_attribute_values(self, name: str) -> list[str]:
        """Get attribute values by name."""
        ...


# =============================================================================
# EXPORTS
# =============================================================================

__all__ = [
    # Protocols
    "AsyncCallable",
    "FlextLdapConnectionProtocol",
    "FlextLdapDirectoryConnectionProtocol",
    "FlextLdapDirectoryEntryProtocol",
    "FlextLdapRepositoryProtocol",
    # Core LDAP Types (domain-specific)
    "LdapAttributeDict",
    "LdapAttributeValue",
    "LdapSearchResult",
    # Type Aliases using flext-core base types
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
    # Infrastructure Types (extending flext-core)
    "LdapConnectionConfig",
    "SecurityEventData",
    "ErrorPatternData",
    "SchemaData",
    # Service Types (extending flext-core)
    "DirectoryAuthConfig",
    "ConnectionConfig",
    "UserRequest",
    "SearchResult",
    # Convenience Aliases
    "JsonDict",
    # Type Variables from flext-core
    "P",
    "R",
    "T",
]
