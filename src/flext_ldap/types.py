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

from typing import TYPE_CHECKING, ParamSpec, Protocol, TypeVar, runtime_checkable

from flext_ldap.typings import FlextTypes

if TYPE_CHECKING:
    from flext_core import FlextResult

# =============================================================================
# LDAP DOMAIN TYPES - Extending flext-core base types
# =============================================================================

# Core LDAP value types (LDAP-specific)
type LdapAttributeValue = str | bytes | list[str] | list[bytes]
type LdapAttributeDict = dict[str, LdapAttributeValue]
type LdapSearchResult = dict[str, LdapAttributeValue]

# Public type aliases for common LDAP concepts (extending core types)
TLdapDn = FlextTypes.Core.EntityId  # Use core entity ID for DN
TLdapUri = FlextTypes.Core.ConnectionString  # Use core connection string
TLdapFilter = str  # LDAP-specific filter syntax
TLdapSessionId = FlextTypes.Service.RequestId  # Use core request ID
TLdapScope = str  # LDAP-specific scope ("base", "one", "sub")
TLdapConnectionId = FlextTypes.Service.CorrelationId  # Use core correlation ID

# Derived types that reference the core ones
TLdapAttributeValue = LdapAttributeValue
TLdapAttributes = LdapAttributeDict
TLdapEntryData = LdapSearchResult
TLdapSearchResult = list[LdapSearchResult] | list[FlextTypes.Core.AnyDict]

# Infrastructure types (extending core types)
LdapConnectionConfig = FlextTypes.Service.Configuration  # Use core config directly
SecurityEventData = FlextTypes.Core.AnyDict  # Use core dict directly
ErrorPatternData = FlextTypes.Core.AnyDict  # Use core dict directly
SchemaData = FlextTypes.Core.AnyDict  # Use core dict directly

# Service layer types (extending core service types)
DirectoryAuthConfig = FlextTypes.Service.Configuration
ConnectionConfig = FlextTypes.Service.Configuration
UserRequest = FlextTypes.CQRS.Message
SearchResult = FlextTypes.Core.AnyDict

P = ParamSpec("P")
R = TypeVar("R")
T = TypeVar("T")

# Extended types for advanced features (using core types)
JsonDict = FlextTypes.Core.JsonDict  # Use core JSON dict directly
FlextTypesCore = FlextTypes.Core.AnyDict  # Reference to core types
AsyncCallable = FlextTypes.Core.AnyCallable  # Use core callable directly

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
    "AsyncCallable",
    "ConnectionConfig",
    # Service Types
    "DirectoryAuthConfig",
    "ErrorPatternData",
    # Protocols
    "FlextLdapConnectionProtocol",
    "FlextLdapDirectoryConnectionProtocol",
    "FlextLdapDirectoryEntryProtocol",
    "FlextLdapRepositoryProtocol",
    "FlextTypesCore",
    "JsonDict",
    # Core Types
    "LdapAttributeDict",
    "LdapAttributeValue",
    # Infrastructure Types
    "LdapConnectionConfig",
    "LdapSearchResult",
    # Generic Types
    "P",
    "R",
    "SchemaData",
    "SearchResult",
    "SecurityEventData",
    "T",
    # Type Aliases
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
