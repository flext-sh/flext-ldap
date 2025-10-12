"""LDAP domain type exports - centralized in FlextCore.Types.Ldap.

This module consolidates all type aliases, type definitions, and protocol
definitions used throughout the flext-ldap domain. Following FLEXT standards,
all types are organized under a single FlextLdapTypes class and extend
centralized types from flext-core.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from flext_core import FlextCore

from flext_ldap.constants import FlextLdapConstants


class FlextLdapTypes(FlextCore.Types):
    """Unified LDAP types class extending FlextCore.Types with LDAP-specific type definitions.

    This class extends the base FlextCore.Types with LDAP-specific type aliases, type variables,
    complex type definitions, and protocol definitions following FLEXT domain separation patterns.
    All types are centralized and extend from flext-core to eliminate duplication.

    Following FLEXT standards:
    - Single unified class per module
    - Extends FlextCore.Types from flext-core
    - No duplicate type definitions
    - Centralized type management
    - Python 3.13+ syntax
    """

    # =========================================================================
    # LDAP3 TYPE ALIASES - Direct type aliases for ldap3 library types
    # =========================================================================

    # Core LDAP3 types - direct use from ldap3, no redeclaration
    # Infrastructure layer imports ldap3 directly where needed
    # Use: from ldap3 import Server, Connection

    # Note: Constants moved to FlextLdapConstants.LiteralTypes
    # Use FlextLdapConstants.LiteralTypes directly instead of redeclaring here

    # =========================================================================
    # LDAP DOMAIN TYPES - LDAP-specific type definitions
    # =========================================================================

    class LdapDomain:
        """LDAP domain-specific types extending FlextCore.Types.Ldap."""

        # Core LDAP attribute and value types
        type AttributeValue = str | FlextCore.Types.StringList
        type AttributeDict = dict[str, AttributeValue]
        type ModifyChanges = dict[str, list[tuple[str, FlextCore.Types.StringList]]]

        # LDAP search and filter types
        type SearchFilter = str
        type SearchScope = FlextLdapConstants.SearchScope
        type SearchResult = list[FlextCore.Types.Dict]

        # LDAP connection and server types
        type ServerURI = str
        type BindDN = str
        type BindPassword = str
        type DistinguishedName = str

        # LDAP protocol types
        type ObjectClass = str
        type AttributeName = str
        type ConnectionState = FlextLdapConstants.ConnectionState
        type OperationType = FlextLdapConstants.OperationType
        type SecurityLevel = FlextLdapConstants.SecurityLevel
        type AuthenticationMethod = FlextLdapConstants.AuthenticationMethod

        # Complex LDAP operation types
        type BulkOperation = list[dict[str, AttributeValue | OperationType]]
        type SearchConfiguration = dict[
            str, SearchScope | int | FlextCore.Types.StringList
        ]
        type EntryTemplate = dict[str, AttributeValue | list[ObjectClass]]

    # =========================================================================
    # LDAP CORE TYPES - Domain-specific core types extending FlextCore.Types
    # =========================================================================

    class LdapCore:
        """Core LDAP types extending FlextCore.Types.

        Use FlextCore.Types directly for most operations. Only define LDAP-specific
        composite types that add domain meaning.
        """

        # LDAP-specific configuration value (composite type)
        type LdapConfigValue = (
            str | int | bool | FlextCore.Types.StringList | FlextCore.Types.Dict
        )

        # LDAP-specific attribute value (composite type)
        type LdapAttributeValue = (
            str | FlextCore.Types.StringList | FlextCore.Types.Dict
        )

        # LDAP-specific entry value (composite type)
        type LdapEntryValue = dict[str, str | FlextCore.Types.StringList]

    # Note: Configuration types use FlextCore.Types.Dict directly
    # Operation types use FlextLdapModels (Command/Query patterns)
    # Result types use FlextCore.Result[T] from flext-core

    # =========================================================================
    # LDAP ENTRY TYPES - Entry-specific types
    # =========================================================================

    class LdapEntries:
        """LDAP entry-specific types."""

        type EntryAttributeValue = str | FlextCore.Types.StringList
        type EntryAttributeDict = dict[str, EntryAttributeValue]

    # =========================================================================
    # LDAP PROJECT TYPES - Domain-specific project types extending FlextCore.Types
    # =========================================================================

    class Project(FlextCore.Types.Project):
        """LDAP-specific project types extending FlextCore.Types.Project.

        Adds LDAP/directory services-specific project types while inheriting
        generic types from FlextCore.Types. Follows domain separation principle:
        LDAP domain owns directory-specific types.
        """

        # LDAP-specific project types extending the generic ones
        type LdapProjectType = FlextLdapConstants.LdapProjectType

        # LDAP-specific project configurations
        type LdapProjectConfig = dict[
            str,
            FlextLdapTypes.LdapCore.LdapConfigValue | object,
        ]
        type DirectoryConfig = dict[str, str | int | bool | FlextCore.Types.StringList]
        type AuthenticationConfig = dict[str, bool | str | FlextCore.Types.Dict]
        type SyncConfig = dict[str, FlextLdapTypes.LdapCore.LdapConfigValue | object]


# =========================================================================
# PUBLIC API EXPORTS - FlextLdapTypes and flext-core TypeVars
# =========================================================================

__all__: FlextCore.Types.StringList = [
    "FlextLdapTypes",
]
