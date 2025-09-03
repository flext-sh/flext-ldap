"""LDAP Types - Single FlextLDAPTypes class following FLEXT patterns.

Single class inheriting from FlextCoreTypes with all LDAP types
organized as internal properties and methods for complete backward compatibility.

Examples:
    Basic usage with hierarchical types::

        from typings import FlextLDAPTypes

        dn: FlextLDAPTypes.LdapDomain.DistinguishedName = "cn=user,dc=example,dc=com"
        filter_type: FlextLDAPTypes.Search.Filter = "(objectClass=person)"
        attrs: FlextLDAPTypes.Entry.AttributeDict = {"cn": ["John Doe"]}


"""

from __future__ import annotations

from collections.abc import Callable
from typing import Protocol

from flext_core import FlextModels, FlextResult, FlextTypes

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
        type Dn = str

        # LDAP URI and connection types
        type Uri = str
        type ConnectionString = str

        # Entity identification
        type EntityId = str
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

        # Advanced Python 3.13 service protocols with proper bounds
        type Service = object
        type Repository[T: FlextModels.Entity] = object  # Bounded to entities only
        type Handler[TInput: FlextModels.Value, TOutput: FlextResult[object]] = (
            object  # Bounded type parameters
        )

        # LDAP-specific protocols with semantic bounds
        type Connection = object
        type Auth = object
        type Validator[T: FlextModels.Value] = Callable[
            [T], FlextResult[None]
        ]  # Proper validator signature

    # =========================================================================
    # PROTOCOLS - Async and callable patterns
    # =========================================================================

    class AsyncCallable(Protocol):
        """Async callable protocol for LDAP operations."""

        def __call__(self, *args: object, **kwargs: object) -> None:  # pragma: no cover
            ...


# =============================================================================
# MODULE EXPORTS
# =============================================================================

# =============================================================================
# ESSENTIAL TYPE ALIASES - Only for internal usage
# =============================================================================

# Core LDAP value types - only the ones used in code
LdapAttributeValue = FlextLDAPTypes.Entry.AttributeValue
LdapAttributeDict = FlextLDAPTypes.Entry.AttributeDict
LdapSearchResult = FlextLDAPTypes.Entry.EntryResult

# LDAP attribute and entry types - only used ones
TLdapAttributes = FlextLDAPTypes.Entry.AttributeDict
TLdapAttributeValue = FlextLDAPTypes.Entry.AttributeValue
TLdapEntryData = FlextLDAPTypes.Entry.EntryData
TLdapSearchResult = FlextLDAPTypes.Search.ResultList


__all__ = [
    # Main class following flext-core pattern
    "FlextLDAPTypes",
    "LdapAttributeDict",
    # Essential aliases used in code
    "LdapAttributeValue",
    "LdapSearchResult",
    "TLdapAttributeValue",
    "TLdapAttributes",
    "TLdapEntryData",
    "TLdapSearchResult",
]
