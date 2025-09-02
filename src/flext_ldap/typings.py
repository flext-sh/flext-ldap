"""LDAP Types - Single FlextLDAPTypes class following FLEXT patterns.

Single class inheriting from FlextCoreTypes with all LDAP types
organized as internal properties and methods for complete backward compatibility.

Examples:
    Basic usage with hierarchical types::

        from typings import FlextLDAPTypes

        dn: FlextLDAPTypes.LdapDomain.DistinguishedName = "cn=user,dc=example,dc=com"
        filter_type: FlextLDAPTypes.Search.Filter = "(objectClass=person)"
        attrs: FlextLDAPTypes.Entry.AttributeDict = {"cn": ["John Doe"]}

    Legacy compatibility::

        # All previous types still work as aliases
        from typings import LdapAttributeDict, TLdapDn

        attrs: LdapAttributeDict = {"cn": ["John Doe"]}
        dn: TLdapDn = "cn=user,dc=example,dc=com"

"""

from __future__ import annotations

from typing import Protocol, TypeVar

from flext_core import FlextTypes, P, T

# =============================================================================
# SINGLE FLEXT LDAP TYPES CLASS - Inheriting from FlextCoreTypes
# =============================================================================


class FlextLDAPTypes(FlextTypes):
    """Single FlextLDAPTypes class inheriting from FlextTypes.

    Consolidates ALL LDAP types into a single class following FLEXT patterns.
    Everything from the previous type definitions is now available as
    internal properties with full backward compatibility.

    This class follows SOLID principles:
        - Single Responsibility: All LDAP types in one place
        - Open/Closed: Extends FlextTypes without modification
        - Liskov Substitution: Can be used anywhere FlextTypes is expected
        - Interface Segregation: Organized by domain for specific access
        - Dependency Inversion: Depends on FlextTypes abstraction

    Examples:
        Domain types::

            dn: FlextLDAPTypes.LdapDomain.DistinguishedName = (
                "cn=user,dc=example,dc=com"
            )
            entry_id: FlextLDAPTypes.LdapDomain.EntityId = "user123"

        Search types::

            filter_str: FlextLDAPTypes.Search.Filter = "(objectClass=person)"
            scope: FlextLDAPTypes.Search.Scope = "subtree"

        Entry types::

            attrs: FlextLDAPTypes.Entry.AttributeDict = {"cn": ["John Doe"]}
            value: FlextLDAPTypes.Entry.AttributeValue = ["REDACTED_LDAP_BIND_PASSWORD", "user"]

    """

    # =========================================================================
    # DOMAIN TYPES - LDAP Domain-Specific Types
    # =========================================================================

    class LdapDomain:
        """LDAP domain-specific types extending FlextTypes."""

        # Distinguished Name types
        type DistinguishedName = str
        type Dn = str  # Short alias

        # LDAP URI and connection types
        type Uri = str
        type ConnectionString = str

        # Entity identification
        type EntityId = FlextTypes.Domain.EntityId
        type UserId = str
        type GroupId = str

        # LDAP-specific identifiers
        type SessionId = str
        type ConnectionId = str

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
        type Config = dict[str, object]
        type AuthConfig = dict[str, object]
        type ConnectionConfig = dict[str, object]

        # Connection state
        type State = str
        type Status = str
        type Health = bool

    # =========================================================================
    # PROTOCOL TYPES - LDAP Protocol Extensions
    # =========================================================================

    class LdapProtocol:
        """LDAP protocol types extending FlextTypes protocols."""

        # Service protocols
        type Service = object
        type Repository[T] = object
        type Handler[TInput, TOutput] = object

        # LDAP-specific protocols
        type Connection = object
        type Auth = object
        type Validator[T] = object


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
LdapAttributeValue = FlextLDAPTypes.Entry.AttributeValue
LdapAttributeDict = FlextLDAPTypes.Entry.AttributeDict
LdapSearchResult = FlextLDAPTypes.Entry.EntryResult

# LDAP-specific type aliases - legacy compatibility
TLdapDn = FlextLDAPTypes.LdapDomain.DistinguishedName
TLdapUri = FlextLDAPTypes.LdapDomain.Uri
TLdapFilter = FlextLDAPTypes.Search.Filter
TLdapSessionId = FlextLDAPTypes.LdapDomain.SessionId
TLdapScope = FlextLDAPTypes.Search.Scope
TLdapConnectionId = FlextLDAPTypes.LdapDomain.ConnectionId

# LDAP attribute and entry types - legacy compatibility
TLdapAttributeValue = FlextLDAPTypes.Entry.AttributeValue
TLdapAttributes = FlextLDAPTypes.Entry.AttributeDict
TLdapEntryData = FlextLDAPTypes.Entry.EntryData
TLdapSearchResult = FlextLDAPTypes.Search.ResultList

# Infrastructure types - legacy compatibility
LdapConnectionConfig = FlextLDAPTypes.Connection.Config
SecurityEventData = FlextTypes.Core.Object
ErrorPatternData = FlextTypes.Core.Object
SchemaData = FlextTypes.Core.Object

# Service layer types - legacy compatibility
DirectoryAuthConfig = FlextLDAPTypes.Connection.AuthConfig
ConnectionConfig = FlextLDAPTypes.Connection.ConnectionConfig
UserRequest = FlextTypes.Core.Object
SearchResult = FlextTypes.Core.Object

# Use flext-core JsonDict type - legacy compatibility
JsonDict = dict[str, object]

# Backward compatibility for R (not in FlextTypes)
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
    "FlextLDAPTypes",
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
