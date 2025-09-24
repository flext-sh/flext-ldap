"""Unified LDAP type definitions for flext-ldap domain.

This module consolidates all type aliases, type definitions, and  protocol
definitions used throughout the flext-ldap domain. Following FLEXT standards,
all types are organized under a single FlextLdapTypes class.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import Protocol

import ldap3

from flext_core import FlextTypes


class FlextLdapTypes(FlextTypes):
    """Unified LDAP types class extending FlextTypes with LDAP-specific type definitions.

    This class extends the base FlextTypes with LDAP-specific type aliases, type variables,
    complex type definitions, and  protocol definitions following FLEXT domain separation patterns.
    """

    # =========================================================================
    # ENTRY TYPES - LDAP entry-related type definitions
    # =========================================================================

    # Basic LDAP attribute value types
    type EntryAttributeValue = str | list[str] | bytes | list[bytes]

    # LDAP attributes dictionary
    type EntryAttributeDict = dict[str, EntryAttributeValue]

    # LDAP attributes for add operations
    type Attributes = dict[str, str | list[str]]

    # LDAP entry data structure
    type EntryData = dict[str, EntryAttributeValue]

    # Distinguished Name type
    type EntryDN = str

    # Object classes list
    type EntryObjectClasses = list[str]

    # =========================================================================
    # SEARCH TYPES - LDAP search-related type definitions
    # =========================================================================

    # Search result entry
    type SearchResultEntry = dict[str, object]

    # Search result collection
    type SearchResult = list[SearchResultEntry]

    # Generic LDAP entry type
    type Entry = object  # Generic LDAP entry object

    # Search filter string
    type SearchFilter = str

    # Search scope values
    type SearchScope = str

    # Search base DN
    type SearchBaseDN = str

    # Attributes to return
    type SearchAttributes = list[str] | None

    # =========================================================================
    # MODIFY TYPES - LDAP modify operation type definitions
    # =========================================================================

    # Modify changes dictionary
    type ModifyChanges = dict[str, list[tuple[str, list[str]]]]

    # =========================================================================
    # CONNECTION TYPES - LDAP connection-related type definitions
    # =========================================================================

    # Server URI
    type ConnectionServerURI = str

    # Port number
    type ConnectionPort = int

    # Bind DN for authentication
    type ConnectionBindDN = str | None

    # Bind password
    type ConnectionBindPassword = str | None

    # Connection timeout
    type ConnectionTimeout = int

    # SSL/TLS configuration
    type ConnectionUseSSL = bool
    type ConnectionUseTLS = bool

    # =========================================================================
    # VALIDATION TYPES - LDAP validation-related type definitions
    # =========================================================================

    # Validation result type
    type ValidationResult = bool

    # Error message type
    type ValidationErrorMessage = str

    # Field name for validation
    type ValidationFieldName = str

    # =========================================================================
    # OPERATION TYPES - LDAP operation-related type definitions
    # =========================================================================

    # Operation type identifier
    type OperationType = str

    # Operation result code
    type OperationResultCode = int

    # Operation duration in milliseconds
    type OperationDuration = float

    # Operation status
    type OperationStatus = bool

    # =========================================================================
    # DATA STRUCTURES - Composite type aliases for module use
    # =========================================================================

    # ConnectionConfig data structure - specific field types
    type ConnectionConfigData = dict[
        str,
        ConnectionServerURI
        | ConnectionPort
        | ConnectionUseSSL
        | ConnectionBindDN
        | ConnectionBindPassword
        | ConnectionTimeout,
    ]

    # SearchRequest data structure - specific field types
    type SearchRequestData = dict[
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
    type GenericModelData = dict[
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
type AttributeValue = str | list[str]
type Attributes = dict[str, AttributeValue]
type ModifyChanges = dict[str, list[tuple[str, list[str]]]]

# =========================================================================
# LDAP3 CONNECTION PROTOCOL - Type-safe interface for ldap3 Connection
# =========================================================================


class LdapConnectionProtocol(Protocol):
    """Protocol for ldap3 Connection to provide type safety for untyped methods."""

    bound: bool
    last_error: str

    def modify(self, dn: str, changes: ModifyChanges) -> bool: ...
    def delete(self, dn: str) -> bool: ...
    def add(self, dn: str, attributes: dict[str, object]) -> bool: ...
    def compare(self, dn: str, attribute: str, value: str) -> bool: ...
    def extended(self, request_name: str, request_value: str | None = None) -> bool: ...
    def search(
        self,
        search_base: str,
        search_filter: str,
        search_scope: str,
        attributes: list[str] | None = None,
        size_limit: int = 0,
        time_limit: int = 0,
        types_only: bool = False,  # noqa: FBT001, FBT002
        dereference_aliases: int = 0,
    ) -> bool: ...
    def unbind(self) -> bool: ...


# Module-level type aliases for LDAP3 types

# LDAP3 constants - provide actual values at runtime
# FIXED: Removed ImportError fallback - ldap3 must be available (ZERO TOLERANCE)

ALL = ldap3.ALL
BASE = ldap3.BASE
LEVEL = ldap3.LEVEL
SUBTREE = ldap3.SUBTREE
MODIFY_ADD = ldap3.MODIFY_ADD
MODIFY_DELETE = ldap3.MODIFY_DELETE
MODIFY_REPLACE = ldap3.MODIFY_REPLACE
SIMPLE = ldap3.SIMPLE


__all__ = [
    "ALL",
    "BASE",
    "LEVEL",
    "MODIFY_ADD",
    "MODIFY_DELETE",
    "MODIFY_REPLACE",
    "SIMPLE",
    "SUBTREE",
    "FlextLdapTypes",
]
