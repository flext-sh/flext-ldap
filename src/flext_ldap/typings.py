"""FLEXT LDAP Types Module.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Protocol

from flext_core import FlextResult, FlextTypes


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
        DistinguishedName = str
        Dn = str

        # LDAP URI and connection types
        Uri = str
        ConnectionString = str

        # Entity identification
        EntityId = str
        UserId = str
        GroupId = str

        # LDAP-specific identifiers
        SessionId = str
        ConnectionId = str

    # =========================================================================
    # SEARCH TYPES - LDAP Search Operations
    # =========================================================================

    class Search:
        """LDAP search operation types."""

        # Search parameters
        Filter = str
        Scope = str
        Base = str

        # Search limits
        SizeLimit = int
        TimeLimit = int
        PageSize = int

        # Search results
        ResultList = list[FlextTypes.Core.Dict]
        ResultDict = FlextTypes.Core.Dict

    # =========================================================================
    # ENTRY TYPES - LDAP Entry and Attribute Types
    # =========================================================================

    class Entry:
        """LDAP entry and attribute types."""

        # Attribute value types
        AttributeValue = str | bytes | list[str] | list[bytes]
        AttributeDict = dict[str, AttributeValue]
        AttributeName = str

        # Entry types
        EntryData = dict[str, AttributeValue]
        EntryResult = FlextTypes.Core.Dict

        # Modification types
        ModificationDict = FlextTypes.Core.Dict
        OperationType = str

    # =========================================================================
    # CONNECTION TYPES - LDAP Connection Management
    # =========================================================================

    class Connection:
        """LDAP connection and configuration types."""

        # Connection configuration
        Config = FlextTypes.Core.Dict
        AuthConfig = FlextTypes.Core.Dict
        ConnectionConfig = FlextTypes.Core.Dict

        # Connection state
        State = str
        Status = str
        Health = bool

    # =========================================================================
    # PROTOCOL TYPES - LDAP Protocol Extensions
    # =========================================================================

    class LdapProtocol:
        """LDAP protocol types extending FlextTypes protocols."""

        # Advanced Python 3.13 service protocols with proper bounds
        Service = object
        Repository = object  # Bounded to entities only
        Handler = object  # Bounded type parameters

        # LDAP-specific protocols with semantic bounds
        Connection = object
        Auth = object
        Validator = Callable[[object], FlextResult[None]]  # Proper validator signature

    # =========================================================================
    # PROTOCOLS - Async and callable patterns
    # =========================================================================

    class AsyncCallable(Protocol):
        """Async callable protocol for LDAP operations."""

        def __call__(self, *args: object, **kwargs: object) -> None:  # pragma: no cover
            """Execute async callable with arbitrary arguments."""
            ...


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
