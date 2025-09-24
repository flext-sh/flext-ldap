"""Unified LDAP type definitions for flext-ldap domain.

This module consolidates all type aliases, type definitions, and  protocol
definitions used throughout the flext-ldap domain. Following FLEXT standards,
all types are organized under a single FlextLdapTypes class.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from flext_core import FlextTypes

if TYPE_CHECKING:
    import ldap3


class FlextLdapTypes(FlextTypes):
    """Unified LDAP types class extending FlextTypes with LDAP-specific type definitions.

    This class extends the base FlextTypes with LDAP-specific type aliases, type variables,
    complex type definitions, and  protocol definitions following FLEXT domain separation patterns.
    """

    # =========================================================================
    # ENTRY TYPES - LDAP entry-related type definitions
    # =========================================================================

    # Basic LDAP attribute value types
    EntryAttributeValue = str | list[str] | bytes | list[bytes]

    # LDAP attributes dictionary
    EntryAttributeDict = dict[str, EntryAttributeValue]

    # LDAP entry data structure
    EntryData = dict[str, EntryAttributeValue]

    # Distinguished Name type
    EntryDN = str

    # Object classes list
    EntryObjectClasses = list[str]

    # =========================================================================
    # SEARCH TYPES - LDAP search-related type definitions
    # =========================================================================

    # Search result entry
    SearchResultEntry = dict[str, object]

    # Search result collection
    SearchResult = list[SearchResultEntry]

    # Search filter string
    SearchFilter = str

    # Search scope values
    SearchScope = str

    # Search base DN
    SearchBaseDN = str

    # Attributes to return
    SearchAttributes = list[str] | None

    # =========================================================================
    # CONNECTION TYPES - LDAP connection-related type definitions
    # =========================================================================

    # Server URI
    ConnectionServerURI = str

    # Port number
    ConnectionPort = int

    # Bind DN for authentication
    ConnectionBindDN = str | None

    # Bind password
    ConnectionBindPassword = str | None

    # Connection timeout
    ConnectionTimeout = int

    # SSL/TLS configuration
    ConnectionUseSSL = bool
    ConnectionUseTLS = bool

    # =========================================================================
    # VALIDATION TYPES - LDAP validation-related type definitions
    # =========================================================================

    # Validation result type
    ValidationResult = bool

    # Error message type
    ValidationErrorMessage = str

    # Field name for validation
    ValidationFieldName = str

    # =========================================================================
    # OPERATION TYPES - LDAP operation-related type definitions
    # =========================================================================

    # Operation type identifier
    OperationType = str

    # Operation result code
    OperationResultCode = int

    # Operation duration in milliseconds
    OperationDuration = float

    # Operation status
    OperationStatus = bool

    # =========================================================================
    # DATA STRUCTURES - Composite type aliases for module use
    # =========================================================================

    # ConnectionConfig data structure - specific field types
    ConnectionConfigData = dict[
        str,
        ConnectionServerURI
        | ConnectionPort
        | ConnectionUseSSL
        | ConnectionBindDN
        | ConnectionBindPassword
        | ConnectionTimeout,
    ]

    # SearchRequest data structure - specific field types
    SearchRequestData = dict[
        str,
        SearchBaseDN
        | SearchFilter
        | SearchScope
        | SearchAttributes
        | int
        | bool
        | bytes
        | None,
    ]

    # Generic model data structure - broader for flexibility
    GenericModelData = dict[
        str,
        EntryAttributeValue
        | SearchBaseDN
        | SearchFilter
        | SearchScope
        | SearchAttributes
        | int
        | bool
        | bytes
        | None,
    ]

    # Additional  type aliases for better readability
    AttributeValue = str | list[str]
    Attributes = dict[str, AttributeValue]
    ModifyChanges = dict[str, list[tuple[str, list[str]]]]


# Module-level type aliases for LDAP3 types
if TYPE_CHECKING:
    from ldap3 import Connection, Server, Entry, Attribute
    # LDAP3 constants
    ALL: int
    BASE: int
    LEVEL: int
    SUBTREE: int
    MODIFY_ADD: int
    MODIFY_DELETE: int
    MODIFY_REPLACE: int
    SIMPLE: int
else:
    # Runtime fallbacks
    Connection = Any
    Server = Any
    Entry = Any
    Attribute = Any
    ALL = 0
    BASE = 1
    LEVEL = 2
    SUBTREE = 3
    MODIFY_ADD = 0
    MODIFY_DELETE = 1
    MODIFY_REPLACE = 2
    SIMPLE = 0


__all__ = [
    "FlextLdapTypes",
    "Connection",
    "Server", 
    "Entry",
    "Attribute",
    "ALL",
    "BASE",
    "LEVEL",
    "SUBTREE",
    "MODIFY_ADD",
    "MODIFY_DELETE",
    "MODIFY_REPLACE",
    "SIMPLE",
]