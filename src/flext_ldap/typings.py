"""LDAP Types - Single FlextLdapTypes class following FLEXT patterns.

Single class inheriting from FlextCoreTypes with all LDAP types
organized as internal properties and methods for complete backward compatibility.

Examples:
    Basic usage with hierarchical types::

        from typings import FlextLdapTypes

        dn: FlextLdapTypes.LdapDomain.DistinguishedName = "cn=user,dc=example,dc=com"
        filter_type: FlextLdapTypes.Search.Filter = "(objectClass=person)"
        attrs: FlextLdapTypes.Entry.AttributeDict = {"cn": ["John Doe"]}

    Legacy compatibility::

        # All previous types still work as aliases
        from typings import LdapAttributeDict, TLdapDn

        attrs: LdapAttributeDict = {"cn": ["John Doe"]}
        dn: TLdapDn = "cn=user,dc=example,dc=com"

"""

from __future__ import annotations

from typing import Protocol, TypeVar

from flext_core import FlextCoreTypes, P, T

# =============================================================================
# SINGLE FLEXT LDAP TYPES CLASS - Inheriting from FlextCoreTypes
# =============================================================================


class FlextLdapTypes(FlextCoreTypes):
    """Single FlextLdapTypes class inheriting from FlextCoreTypes.

    Consolidates ALL LDAP types into a single class following FLEXT patterns.
    Everything from the previous type definitions is now available as
    internal properties with full backward compatibility.

    This class follows SOLID principles:
        - Single Responsibility: All LDAP types in one place
        - Open/Closed: Extends FlextCoreTypes without modification
        - Liskov Substitution: Can be used anywhere FlextCoreTypes is expected
        - Interface Segregation: Organized by domain for specific access
        - Dependency Inversion: Depends on FlextCoreTypes abstraction

    Examples:
        Domain types::

            dn: FlextLdapTypes.LdapDomain.DistinguishedName = (
                "cn=user,dc=example,dc=com"
            )
            entry_id: FlextLdapTypes.LdapDomain.EntityId = "user123"

        Search types::

            filter_str: FlextLdapTypes.Search.Filter = "(objectClass=person)"
            scope: FlextLdapTypes.Search.Scope = "subtree"

        Entry types::

            attrs: FlextLdapTypes.Entry.AttributeDict = {"cn": ["John Doe"]}
            value: FlextLdapTypes.Entry.AttributeValue = ["REDACTED_LDAP_BIND_PASSWORD", "user"]

    """

    # =========================================================================
    # DOMAIN TYPES - LDAP Domain-Specific Types
    # =========================================================================

    class LdapDomain:
        """LDAP domain-specific types extending FlextCoreTypes."""

        # Distinguished Name types
        type DistinguishedName = str
        type Dn = str  # Short alias

        # LDAP URI and connection types
        type Uri = str
        type ConnectionString = str

        # Entity identification
        type EntityId = FlextCoreTypes.Domain.EntityId
        type UserId = str
        type GroupId = str

        # LDAP-specific identifiers
        type SessionId = FlextCoreTypes.Service.CorrelationId
        type ConnectionId = FlextCoreTypes.Service.ServiceName

    # =========================================================================
    # SEARCH TYPES - LDAP Search Operations
    # =========================================================================

    class Search:
        """LDAP search operation types."""

        # Search parameters
        type Filter = str
        type Scope = str
        type Base = str

        # Search limits
        type SizeLimit = int
        type TimeLimit = int
        type PageSize = int

        # Search results
        type ResultList = list[dict[str, object]]
        type ResultDict = dict[str, object]

    # =========================================================================
    # ENTRY TYPES - LDAP Entry and Attribute Types
    # =========================================================================

    class Entry:
        """LDAP entry and attribute types."""

        # Attribute value types
        type AttributeValue = str | bytes | list[str] | list[bytes]
        type AttributeDict = dict[str, AttributeValue]
        type AttributeName = str

        # Entry types
        type EntryData = dict[str, AttributeValue]
        type EntryResult = dict[str, object]

        # Modification types
        type ModificationDict = dict[str, object]
        type OperationType = str

    # =========================================================================
    # CONNECTION TYPES - LDAP Connection Management
    # =========================================================================

    class Connection:
        """LDAP connection and configuration types."""

        # Connection configuration
        type Config = FlextCoreTypes.Config.Settings
        type AuthConfig = FlextCoreTypes.Auth.Credentials
        type ConnectionConfig = FlextCoreTypes.Config.Settings

        # Connection state
        type State = str
        type Status = str
        type Health = bool

    # =========================================================================
    # PROTOCOL TYPES - LDAP Protocol Extensions
    # =========================================================================

    class LdapProtocol:
        """LDAP protocol types extending FlextCoreTypes protocols."""

        # Service protocols
        type Service = FlextCoreTypes.Protocol.Service
        type Repository[T] = FlextCoreTypes.Protocol.Repository[T]
        type Handler[TInput, TOutput] = FlextCoreTypes.Protocol.Handler[TInput, TOutput]

        # LDAP-specific protocols
        type Connection = FlextCoreTypes.Protocol.Connection
        type Auth = FlextCoreTypes.Protocol.Auth
        type Validator[T] = FlextCoreTypes.Protocol.Validator[T]


# =============================================================================
# ADDITIONAL PROTOCOLS - Backward Compatibility
# =============================================================================


class AsyncCallable(Protocol):
    """Async callable protocol for backward compatibility."""

    def __call__(self, *args: object, **kwargs: object) -> None:  # pragma: no cover
        ...


# =============================================================================
# LEGACY TYPE ALIASES - Backward Compatibility
# =============================================================================

# Core LDAP value types - legacy compatibility
LdapAttributeValue = FlextLdapTypes.Entry.AttributeValue
LdapAttributeDict = FlextLdapTypes.Entry.AttributeDict
LdapSearchResult = FlextLdapTypes.Entry.EntryResult

# LDAP-specific type aliases - legacy compatibility
TLdapDn = FlextLdapTypes.LdapDomain.DistinguishedName
TLdapUri = FlextLdapTypes.LdapDomain.Uri
TLdapFilter = FlextLdapTypes.Search.Filter
TLdapSessionId = FlextLdapTypes.LdapDomain.SessionId
TLdapScope = FlextLdapTypes.Search.Scope
TLdapConnectionId = FlextLdapTypes.LdapDomain.ConnectionId

# LDAP attribute and entry types - legacy compatibility
TLdapAttributeValue = FlextLdapTypes.Entry.AttributeValue
TLdapAttributes = FlextLdapTypes.Entry.AttributeDict
TLdapEntryData = FlextLdapTypes.Entry.EntryData
TLdapSearchResult = FlextLdapTypes.Search.ResultList

# Infrastructure types - legacy compatibility
LdapConnectionConfig = FlextLdapTypes.Connection.Config
SecurityEventData = FlextCoreTypes.Domain.EventData
ErrorPatternData = FlextCoreTypes.Core.Object
SchemaData = FlextCoreTypes.Core.Object

# Service layer types - legacy compatibility
DirectoryAuthConfig = FlextLdapTypes.Connection.AuthConfig
ConnectionConfig = FlextLdapTypes.Connection.ConnectionConfig
UserRequest = FlextCoreTypes.Core.Data
SearchResult = FlextCoreTypes.Core.Data

# Use flext-core JsonDict type - legacy compatibility
JsonDict = FlextCoreTypes.Core.JsonDict

# Backward compatibility for R (not in FlextCoreTypes)
R = TypeVar("R")  # Use TypeVar for R compatibility


# =============================================================================
# MODULE EXPORTS
# =============================================================================

__all__ = [
    # Legacy type aliases
    "AsyncCallable",
    "ConnectionConfig",
    "DirectoryAuthConfig",
    "ErrorPatternData",
    # Main class
    "FlextLdapTypes",
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
