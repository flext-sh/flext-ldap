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

from flext_core import FlextTypes
from flext_ldap.constants import FlextLdapConstants


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

    # Basic collection types - Direct access for LDAP operations
    StringList = list[str]

    # LDAP constants - using centralized constants
    SIMPLE = FlextLdapConstants.LiteralTypes.AUTH_SIMPLE
    BASE = FlextLdapConstants.LiteralTypes.SEARCH_SCOPE_BASE
    LEVEL = FlextLdapConstants.LiteralTypes.SEARCH_SCOPE_LEVEL
    SUBTREE = FlextLdapConstants.LiteralTypes.SEARCH_SCOPE_SUBTREE
    MODIFY_ADD = FlextLdapConstants.LiteralTypes.MODIFY_ADD
    MODIFY_DELETE = FlextLdapConstants.LiteralTypes.MODIFY_DELETE
    MODIFY_REPLACE = FlextLdapConstants.LiteralTypes.MODIFY_REPLACE

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
        type SearchScope = Literal[
            FlextLdapConstants.LiteralTypes.SEARCH_SCOPE_BASE,
            FlextLdapConstants.LiteralTypes.SEARCH_SCOPE_LEVEL,
            FlextLdapConstants.LiteralTypes.SEARCH_SCOPE_SUBTREE,
        ]
        type SearchResult = list[FlextTypes.Dict]

        # LDAP connection and server types
        type ServerURI = str
        type BindDN = str
        type BindPassword = str
        type DistinguishedName = str

        # LDAP protocol types
        type ObjectClass = str
        type AttributeName = str
        type ConnectionState = Literal[
            FlextLdapConstants.LiteralTypes.CONNECTION_STATE_UNBOUND,
            FlextLdapConstants.LiteralTypes.CONNECTION_STATE_BOUND,
            FlextLdapConstants.LiteralTypes.CONNECTION_STATE_CLOSED,
            FlextLdapConstants.LiteralTypes.CONNECTION_STATE_ERROR,
        ]
        type OperationType = Literal[
            FlextLdapConstants.LiteralTypes.OPERATION_SEARCH,
            FlextLdapConstants.LiteralTypes.OPERATION_ADD,
            FlextLdapConstants.LiteralTypes.OPERATION_MODIFY,
            FlextLdapConstants.LiteralTypes.OPERATION_DELETE,
            FlextLdapConstants.LiteralTypes.OPERATION_COMPARE,
            FlextLdapConstants.LiteralTypes.OPERATION_EXTENDED,
        ]
        type SecurityLevel = Literal[
            FlextLdapConstants.LiteralTypes.SECURITY_NONE,
            FlextLdapConstants.LiteralTypes.SECURITY_SIMPLE,
            FlextLdapConstants.LiteralTypes.SECURITY_SASL,
        ]
        type AuthenticationMethod = Literal[
            FlextLdapConstants.LiteralTypes.AUTH_SIMPLE,
            FlextLdapConstants.LiteralTypes.AUTH_SASL,
            FlextLdapConstants.LiteralTypes.AUTH_EXTERNAL,
        ]

        # Complex LDAP operation types
        type BulkOperation = list[dict[str, AttributeValue | OperationType]]
        type SearchConfiguration = dict[str, SearchScope | int | FlextTypes.StringList]
        type EntryTemplate = dict[str, AttributeValue | list[ObjectClass]]

    # =========================================================================
    # LDAP CORE TYPES - Domain-specific core types extending FlextTypes
    # =========================================================================

    class LdapCore:
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

        type ServerConfig = dict[str, FlextLdapTypes.LdapCore.LdapConfigValue]
        type ConnectionConfig = dict[str, FlextLdapTypes.LdapCore.LdapConfigValue]
        type ConnectionConfigData = dict[str, FlextLdapTypes.LdapCore.LdapConfigValue]
        type SecurityConfig = dict[str, FlextLdapTypes.LdapCore.LdapConfigValue]
        type SearchConfig = dict[str, FlextLdapTypes.LdapCore.LdapConfigValue]
        type TimeoutConfig = dict[str, int]

    # =========================================================================
    # LDAP OPERATION TYPES - Operation-specific types
    # =========================================================================

    class LdapOperations:
        """LDAP operation types."""

        type SearchOperation = dict[str, FlextLdapTypes.LdapCore.LdapConfigValue]
        type ModifyOperation = dict[str, FlextLdapTypes.LdapCore.LdapConfigValue]
        type AddOperation = dict[str, FlextLdapTypes.LdapCore.LdapConfigValue]
        type DeleteOperation = dict[str, FlextLdapTypes.LdapCore.LdapConfigValue]
        type CompareOperation = dict[str, FlextLdapTypes.LdapCore.LdapConfigValue]
        type ExtendedOperation = dict[str, FlextLdapTypes.LdapCore.LdapConfigValue]

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
        type LdapProjectConfig = dict[
            str, FlextLdapTypes.LdapCore.LdapConfigValue | object
        ]
        type DirectoryConfig = dict[str, str | int | bool | FlextTypes.StringList]
        type AuthenticationConfig = dict[str, bool | str | FlextTypes.Dict]
        type SyncConfig = dict[str, FlextLdapTypes.LdapCore.LdapConfigValue | object]


# =========================================================================
# PUBLIC API EXPORTS - FlextLdapTypes and flext-core TypeVars
# =========================================================================

__all__: FlextTypes.StringList = [
    "FlextLdapTypes",
]
