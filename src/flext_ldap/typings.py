"""LDAP domain type exports - centralized in FlextTypes.Ldap.

This module consolidates all type aliases, type definitions, and protocol
definitions used throughout the flext-ldap domain. Following FLEXT standards,
all types are organized under a single FlextLdapTypes class and extend
centralized types from flext-core.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import Literal

from ldap3 import Connection, Server

from flext_core import (
    T1,
    T2,
    T3,
    E,
    F,
    FlextTypes,
    K,
    P,
    R,
    T,
    T_co,
    T_contra,
    TCommand,
    TCommand_contra,
    TEvent,
    TEvent_contra,
    TQuery,
    TQuery_contra,
    TResult,
    TState,
    TState_co,
    U,
    V,
    W,
)


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
        type AttributeValue = str | FlextTypes.StringList
        type AttributeDict = dict[str, AttributeValue]
        type ModifyChanges = dict[str, list[tuple[str, FlextTypes.StringList]]]

        # LDAP search and filter types
        type SearchFilter = str
        type SearchScope = Literal["BASE", "LEVEL", "SUBTREE"]
        type SearchResult = list[FlextTypes.Dict]

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
        type SearchConfiguration = dict[str, SearchScope | int | FlextTypes.StringList]
        type EntryTemplate = dict[str, AttributeValue | list[ObjectClass]]

    # =========================================================================
    # LDAP CORE TYPES - Domain-specific core types extending FlextTypes
    # =========================================================================

    class Core:
        """Core LDAP types extending FlextTypes."""

        # LDAP-specific core types for configuration and operations
        type LdapConfigValue = (
            str | int | bool | FlextTypes.StringList | FlextTypes.Dict
        )
        type LdapConnectionValue = str | int | bool | FlextTypes.StringDict
        type LdapOperationValue = (
            str | int | bool | FlextTypes.StringList | FlextTypes.Dict
        )
        type LdapAttributeValue = str | FlextTypes.StringList | FlextTypes.Dict
        type LdapEntryValue = dict[str, str | FlextTypes.StringList]
        type LdapResultValue = FlextTypes.Dict | list[FlextTypes.Dict] | bool | str

        # LDAP-specific data structures
        type LdapDict = FlextTypes.Dict
        type LdapConfigDict = dict[str, LdapConfigValue]
        type LdapConnectionDict = dict[str, LdapConnectionValue]
        type LdapOperationDict = dict[str, LdapOperationValue]
        type LdapAttributeDict = dict[str, LdapAttributeValue]
        type LdapEntryDict = dict[str, LdapEntryValue]
        type LdapResultDict = dict[str, LdapResultValue]

        # LDAP-specific lists
        type LdapStringList = FlextTypes.StringList
        type LdapAttributeList = FlextTypes.StringList
        type LdapEntryList = list[FlextTypes.Dict]
        type LdapOperationList = list[FlextTypes.Dict]

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

        type SearchResult = list[FlextTypes.Dict]
        type OperationResult = bool
        type ErrorResult = str
        type ValidationResult = bool
        type ConnectionResult = bool

    # =========================================================================
    # LDAP ENTRY TYPES - Entry-specific types
    # =========================================================================

    # LDAP entry attribute types
    type EntryAttributeValue = str | FlextTypes.StringList
    type EntryAttributeDict = dict[str, EntryAttributeValue]

    class LdapEntries:
        """LDAP entry-specific types."""

        type EntryAttributeValue = str | FlextTypes.StringList
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
        type DirectoryConfig = dict[str, str | int | bool | FlextTypes.StringList]
        type AuthenticationConfig = dict[str, bool | str | FlextTypes.Dict]
        type SyncConfig = dict[str, FlextLdapTypes.Core.ConfigValue | object]


# =========================================================================
# PUBLIC API EXPORTS - FlextLdapTypes and flext-core TypeVars
# =========================================================================

__all__: FlextTypes.StringList = [
    "T1",
    "T2",
    "T3",
    "E",
    "F",
    "FlextLdapTypes",
    "K",
    "P",
    "R",
    "T",
    "TCommand",
    "TCommand_contra",
    "TEvent",
    "TEvent_contra",
    "TQuery",
    "TQuery_contra",
    "TResult",
    "TState",
    "TState_co",
    "T_co",
    "T_contra",
    "U",
    "V",
    "W",
]
