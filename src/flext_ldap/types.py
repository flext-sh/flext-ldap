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
    ParamSpec,
    Protocol,
    TypeVar,
    runtime_checkable,
)

from flext_core import FlextResult

# =============================================================================
# LDAP DOMAIN TYPES - Extending flext-core base types
# =============================================================================

type LdapAttributeValue = str | bytes | list[str] | list[bytes]
type LdapAttributeDict = dict[str, LdapAttributeValue]
type LdapSearchResult = dict[str, LdapAttributeValue]

# Public type aliases for common LDAP concepts
type TLdapDn = str
type TLdapUri = str
type TLdapFilter = str
type TLdapSessionId = str
type TLdapScope = str
type TLdapConnectionId = str

type TLdapAttributeValue = LdapAttributeValue
type TLdapAttributes = LdapAttributeDict
type TLdapEntryData = LdapSearchResult
type TLdapSearchResult = list[LdapSearchResult] | list[dict[str, object]]

# Infrastructure types
type LdapConnectionConfig = dict[str, object]
type SecurityEventData = dict[str, object]
type ErrorPatternData = dict[str, object]
type SchemaData = dict[str, object]

# Service layer types
type DirectoryAuthConfig = dict[str, object]
type ConnectionConfig = dict[str, object]
type UserRequest = dict[str, object]
type SearchResult = dict[str, object]

P = ParamSpec("P")
R = TypeVar("R")
T = TypeVar("T")

# Extended types for advanced features (using core types)
type JsonDict = dict[str, object]
type FlextTypesCore = dict[str, object]


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
