"""LDAP domain type exports - centralized in FlextTypes.Ldap.

This module consolidates all type aliases, type definitions, and protocol
definitions used throughout the flext-ldap domain. Following FLEXT standards,
all types are organized under a single FlextLdapTypes class and extend
centralized types from flext-core.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

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

    # Core LDAP3 types - direct use from ldap3, no redeclaration
    # Infrastructure layer imports ldap3 directly where needed
    # Use: from ldap3 import Server, Connection

    # Note: Constants moved to FlextLdapConstants.LiteralTypes
    # Use FlextLdapConstants.LiteralTypes directly instead of redeclaring here

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
        type SearchScope = (
            FlextLdapConstants.LiteralTypes.SEARCH_SCOPE_BASE
            | FlextLdapConstants.LiteralTypes.SEARCH_SCOPE_LEVEL
            | FlextLdapConstants.LiteralTypes.SEARCH_SCOPE_SUBTREE
        )
        type SearchResult = list[FlextTypes.Dict]

        # LDAP connection and server types
        type ServerURI = str
        type BindDN = str
        type BindPassword = str
        type DistinguishedName = str

        # LDAP protocol types
        type ObjectClass = str
        type AttributeName = str
        type ConnectionState = (
            FlextLdapConstants.LiteralTypes.CONNECTION_STATE_UNBOUND
            | FlextLdapConstants.LiteralTypes.CONNECTION_STATE_BOUND
            | FlextLdapConstants.LiteralTypes.CONNECTION_STATE_CLOSED
            | FlextLdapConstants.LiteralTypes.CONNECTION_STATE_ERROR
        )
        type OperationType = (
            FlextLdapConstants.LiteralTypes.OPERATION_SEARCH
            | FlextLdapConstants.LiteralTypes.OPERATION_ADD
            | FlextLdapConstants.LiteralTypes.OPERATION_MODIFY
            | FlextLdapConstants.LiteralTypes.OPERATION_DELETE
            | FlextLdapConstants.LiteralTypes.OPERATION_COMPARE
            | FlextLdapConstants.LiteralTypes.OPERATION_EXTENDED
        )
        type SecurityLevel = (
            FlextLdapConstants.LiteralTypes.SECURITY_NONE
            | FlextLdapConstants.LiteralTypes.SECURITY_SIMPLE
            | FlextLdapConstants.LiteralTypes.SECURITY_SASL
        )
        type AuthenticationMethod = (
            FlextLdapConstants.LiteralTypes.AUTH_SIMPLE
            | FlextLdapConstants.LiteralTypes.AUTH_SASL
            | FlextLdapConstants.LiteralTypes.AUTH_EXTERNAL
        )

        # Complex LDAP operation types
        type BulkOperation = list[dict[str, AttributeValue | OperationType]]
        type SearchConfiguration = dict[str, SearchScope | int | FlextTypes.StringList]
        type EntryTemplate = dict[str, AttributeValue | list[ObjectClass]]

    # =========================================================================
    # LDAP CORE TYPES - Domain-specific core types extending FlextTypes
    # =========================================================================

    class LdapCore:
        """Core LDAP types extending FlextTypes.

        Use FlextTypes directly for most operations. Only define LDAP-specific
        composite types that add domain meaning.
        """

        # LDAP-specific configuration value (composite type)
        type LdapConfigValue = (
            str | int | bool | FlextTypes.StringList | FlextTypes.Dict
        )

        # LDAP-specific attribute value (composite type)
        type LdapAttributeValue = str | FlextTypes.StringList | FlextTypes.Dict

        # LDAP-specific entry value (composite type)
        type LdapEntryValue = dict[str, str | FlextTypes.StringList]

    # Note: Configuration types use FlextTypes.Dict directly
    # Operation types use FlextLdapModels (Command/Query patterns)
    # Result types use FlextResult[T] from flext-core

    # =========================================================================
    # LDAP ENTRY TYPES - Entry-specific types
    # =========================================================================

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
        type LdapProjectType = (
            FlextLdapConstants.LiteralTypes.PROJECT_TYPE_LDAP_SERVICE
            | FlextLdapConstants.LiteralTypes.PROJECT_TYPE_DIRECTORY_SERVICE
            | FlextLdapConstants.LiteralTypes.PROJECT_TYPE_LDAP_CLIENT
            | FlextLdapConstants.LiteralTypes.PROJECT_TYPE_IDENTITY_PROVIDER
            | FlextLdapConstants.LiteralTypes.PROJECT_TYPE_LDAP_SYNC
            | FlextLdapConstants.LiteralTypes.PROJECT_TYPE_DIRECTORY_SYNC
            | FlextLdapConstants.LiteralTypes.PROJECT_TYPE_USER_PROVISIONING
            | FlextLdapConstants.LiteralTypes.PROJECT_TYPE_LDAP_GATEWAY
            | FlextLdapConstants.LiteralTypes.PROJECT_TYPE_AUTHENTICATION_SERVICE
            | FlextLdapConstants.LiteralTypes.PROJECT_TYPE_SSO_SERVICE
            | FlextLdapConstants.LiteralTypes.PROJECT_TYPE_DIRECTORY_API
            | FlextLdapConstants.LiteralTypes.PROJECT_TYPE_LDAP_PROXY
            | FlextLdapConstants.LiteralTypes.PROJECT_TYPE_IDENTITY_MANAGEMENT
            | FlextLdapConstants.LiteralTypes.PROJECT_TYPE_USER_DIRECTORY
            | FlextLdapConstants.LiteralTypes.PROJECT_TYPE_GROUP_MANAGEMENT
            | FlextLdapConstants.LiteralTypes.PROJECT_TYPE_LDAP_MIGRATION
        )

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
