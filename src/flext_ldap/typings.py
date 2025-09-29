"""Unified LDAP type definitions for flext-ldap domain.

This module consolidates all type aliases, type definitions, and protocol
definitions used throughout the flext-ldap domain. Following FLEXT standards,
all types are organized under a single FlextLdapTypes class and extend
centralized types from flext-core.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import Literal, Protocol

from ldap3 import Connection, Server

from flext_core import FlextTypes

# =============================================================================
# LDAP-SPECIFIC TYPE VARIABLES - Domain-specific TypeVars for LDAP operations
# =============================================================================

# LDAP domain TypeVars


class FlextLdapTypes(FlextTypes):
    """Unified LDAP types class extending FlextTypes with LDAP-specific type definitions.

    This class extends the base FlextTypes with LDAP-specific type aliases, type variables,
    complex type definitions, and protocol definitions following FLEXT domain separation patterns.
    All types are centralized and extend from flext-core to eliminate duplication.

    Following FLEXT standards:
    - Single unified class per module
    - Extends FlextTypes from flext-core
    - No duplicate type definitions
    - Centralized type management
    - Python 3.13+ syntax
    """

    # =========================================================================
    # LDAP3 TYPE ALIASES - Direct type aliases for ldap3 library types
    # =========================================================================

    # Core LDAP3 types
    Server = Server
    Connection = Connection
    SIMPLE: Literal["SIMPLE"] = "SIMPLE"

    # LDAP scope constants - using proper literal types
    BASE: Literal["BASE"] = "BASE"
    LEVEL: Literal["LEVEL"] = "LEVEL"
    SUBTREE: Literal["SUBTREE"] = "SUBTREE"

    # LDAP modify operation constants
    MODIFY_ADD: Literal["MODIFY_ADD"] = "MODIFY_ADD"
    MODIFY_DELETE: Literal["MODIFY_DELETE"] = "MODIFY_DELETE"
    MODIFY_REPLACE: Literal["MODIFY_REPLACE"] = "MODIFY_REPLACE"

    # =========================================================================
    # LDAP DOMAIN TYPES - LDAP-specific type definitions
    # =========================================================================

    class LdapDomain:
        """LDAP domain-specific types extending FlextTypes.Ldap."""

        # Core LDAP attribute and value types
        type AttributeValue = str | list[str]
        type AttributeDict = dict[str, AttributeValue]
        type ModifyChanges = dict[str, list[tuple[str, list[str]]]]

        # LDAP search and filter types
        type SearchFilter = str
        type SearchScope = Literal["BASE", "LEVEL", "SUBTREE"]
        type SearchResult = list[dict[str, object]]

        # LDAP connection and server types
        type ServerURI = str
        type BindDN = str
        type BindPassword = str
        type DistinguishedName = str

        # LDAP protocol types
        type ObjectClass = str
        type AttributeName = str
        type ConnectionState = Literal["unbound", "bound", "closed", "error"]
        type OperationType = Literal[
            "search", "add", "modify", "delete", "compare", "extended"
        ]
        type SecurityLevel = Literal["none", "simple", "sasl"]
        type AuthenticationMethod = Literal["simple", "sasl", "external"]

        # Complex LDAP operation types
        type BulkOperation = list[dict[str, AttributeValue | OperationType]]
        type SearchConfiguration = dict[str, SearchScope | int | list[str]]
        type EntryTemplate = dict[str, AttributeValue | list[ObjectClass]]

    # =========================================================================
    # LDAP CORE TYPES - Domain-specific core types extending FlextTypes.Core
    # =========================================================================

    class Core(FlextTypes.Core):
        """Core LDAP types extending FlextTypes.Core."""

        # LDAP-specific core types for configuration and operations
        type LdapConfigValue = str | int | bool | list[str] | dict[str, object]
        type LdapConnectionValue = str | int | bool | dict[str, str]
        type LdapOperationValue = str | int | bool | list[str] | dict[str, object]
        type LdapAttributeValue = str | list[str] | dict[str, object]
        type LdapEntryValue = dict[str, str | list[str]]
        type LdapResultValue = dict[str, object] | list[dict[str, object]] | bool | str

        # LDAP-specific data structures
        type LdapDict = dict[str, object]
        type LdapConfigDict = dict[str, LdapConfigValue]
        type LdapConnectionDict = dict[str, LdapConnectionValue]
        type LdapOperationDict = dict[str, LdapOperationValue]
        type LdapAttributeDict = dict[str, LdapAttributeValue]
        type LdapEntryDict = dict[str, LdapEntryValue]
        type LdapResultDict = dict[str, LdapResultValue]

        # LDAP-specific lists
        type LdapStringList = list[str]
        type LdapAttributeList = list[str]
        type LdapEntryList = list[dict[str, object]]
        type LdapOperationList = list[dict[str, object]]

    # =========================================================================
    # LDAP CONFIGURATION TYPES - Configuration-specific types
    # =========================================================================

    class LdapConfig:
        """LDAP configuration types."""

        type ServerConfig = dict[str, FlextLdapTypes.Core.ConfigValue]
        type ConnectionConfig = dict[str, FlextLdapTypes.Core.ConfigValue]
        type ConnectionConfigData = dict[str, FlextLdapTypes.Core.ConfigValue]
        type SecurityConfig = dict[str, FlextLdapTypes.Core.ConfigValue]
        type SearchConfig = dict[str, FlextLdapTypes.Core.ConfigValue]
        type TimeoutConfig = dict[str, int]

    # =========================================================================
    # LDAP OPERATION TYPES - Operation-specific types
    # =========================================================================

    class LdapOperations:
        """LDAP operation types."""

        type SearchOperation = dict[str, FlextLdapTypes.Core.ConfigValue]
        type ModifyOperation = dict[str, FlextLdapTypes.Core.ConfigValue]
        type AddOperation = dict[str, FlextLdapTypes.Core.ConfigValue]
        type DeleteOperation = dict[str, FlextLdapTypes.Core.ConfigValue]
        type CompareOperation = dict[str, FlextLdapTypes.Core.ConfigValue]
        type ExtendedOperation = dict[str, FlextLdapTypes.Core.ConfigValue]

    # =========================================================================
    # LDAP RESULT TYPES - Result and response types
    # =========================================================================

    class LdapResults:
        """LDAP result and response types."""

        type SearchResult = list[dict[str, object]]
        type OperationResult = bool
        type ErrorResult = str
        type ValidationResult = bool
        type ConnectionResult = bool

    # =========================================================================
    # LDAP ENTRY TYPES - Entry-specific types
    # =========================================================================

    # LDAP entry attribute types
    type EntryAttributeValue = str | list[str]
    type EntryAttributeDict = dict[str, EntryAttributeValue]

    class LdapEntries:
        """LDAP entry-specific types."""

        type EntryAttributeValue = str | list[str]
        type EntryAttributeDict = dict[str, EntryAttributeValue]

    # =========================================================================
    # LDAP PROJECT TYPES - Domain-specific project types extending FlextTypes
    # =========================================================================

    class Project(FlextTypes.Project):
        """LDAP-specific project types extending FlextTypes.Project.

        Adds LDAP/directory services-specific project types while inheriting
        generic types from FlextTypes. Follows domain separation principle:
        LDAP domain owns directory-specific types.
        """

        # LDAP-specific project types extending the generic ones
        type LdapProjectType = Literal[
            # LDAP-specific types
            "ldap-service",
            "directory-service",
            "ldap-client",
            "identity-provider",
            "ldap-sync",
            "directory-sync",
            "user-provisioning",
            "ldap-gateway",
            "authentication-service",
            "sso-service",
            "directory-api",
            "ldap-proxy",
            "identity-management",
            "user-directory",
            "group-management",
            "ldap-migration",
        ]

        # LDAP-specific project configurations
        type LdapProjectConfig = dict[str, FlextLdapTypes.Core.ConfigValue | object]
        type DirectoryConfig = dict[str, str | int | bool | list[str]]
        type AuthenticationConfig = dict[str, bool | str | dict[str, object]]
        type SyncConfig = dict[str, FlextLdapTypes.Core.ConfigValue | object]


# =============================================================================
# LDAP PROTOCOL DEFINITIONS - LDAP-specific protocols
# =============================================================================


class LdapAttribute(Protocol):
    """Protocol for LDAP attribute objects."""

    value: object


class LdapEntry(Protocol):
    """Protocol for LDAP entry objects."""

    entry_dn: str
    entry_attributes: dict[str, list[str]]

    def __getitem__(self, key: str) -> LdapAttribute:
        """Get attribute by key."""
        ...


class LdapConnectionProtocol(Protocol):
    """Protocol for LDAP connection with proper type annotations."""

    bound: bool
    last_error: str
    entries: list[LdapEntry]

    def bind(self) -> bool:
        """Bind to LDAP server."""
        ...

    def unbind(self) -> bool:
        """Unbind from LDAP server."""
        ...

    def search(
        self,
        search_base: str,
        search_filter: str,
        search_scope: Literal["BASE", "LEVEL", "SUBTREE"],
        attributes: list[str] | None = None,
        paged_size: int | None = None,
        paged_cookie: str | bytes | None = None,
        controls: list[object] | None = None,
    ) -> bool:
        """Search LDAP directory."""
        ...

    def add(
        self, dn: str, attributes: dict[str, str | list[str]] | None = None
    ) -> bool:
        """Add entry to LDAP directory."""
        ...

    def modify(self, dn: str, changes: dict[str, list[tuple[str, list[str]]]]) -> bool:
        """Modify LDAP entry."""
        ...

    def delete(self, dn: str) -> bool:
        """Delete LDAP entry."""
        ...

    def compare(self, dn: str, attribute: str, value: str) -> bool:
        """Compare attribute value."""
        ...

    def extended(
        self, request_name: str, request_value: str | bytes | None = None
    ) -> bool:
        """Perform extended LDAP operation."""
        ...


# =========================================================================
# PUBLIC API EXPORTS - Essential types at module level
# =========================================================================

# Export constants from FlextLdapTypes at module level
BASE = FlextLdapTypes.BASE
LEVEL = FlextLdapTypes.LEVEL
SUBTREE = FlextLdapTypes.SUBTREE
MODIFY_ADD = FlextLdapTypes.MODIFY_ADD
MODIFY_DELETE = FlextLdapTypes.MODIFY_DELETE
MODIFY_REPLACE = FlextLdapTypes.MODIFY_REPLACE

# Type aliases at module level for common use
ModifyChanges = FlextLdapTypes.LdapDomain.ModifyChanges

# Missing type alias that needs to be exported
Attributes = FlextLdapTypes.LdapDomain.AttributeDict

__all__: list[str] = [
    "BASE",
    "LEVEL",
    "MODIFY_ADD",
    "MODIFY_DELETE",
    "MODIFY_REPLACE",
    "SUBTREE",
    "Attributes",
    "FlextLdapTypes",
    "LdapAttribute",
    "LdapConnectionProtocol",
    "LdapEntry",
    "ModifyChanges",
]
