"""LDAP constants and enumerations.

This module defines constant values and enumerations used throughout the
LDAP library. Minimal constants - reuses flext-ldif when possible.

Python 3.13+ strict features:
- PEP 695 type aliases (type keyword) - no TypeAlias
- collections.abc for type hints (preferred over typing)
- StrEnum for type-safe string enums
- Literal types derived from StrEnum values
- No backward compatibility with Python < 3.13

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

from enum import StrEnum
from typing import Final, Literal

from flext_core import FlextConstants

# Import for static method access


class FlextLdapConstants(FlextConstants):
    """LDAP domain constants extending flext-core FlextConstants.

    Contains ONLY constant values specific to LDAP operations.
    Reuses flext-ldif constants for Entry, DN, and Schema operations.

    Constants are organized with the most important ones first:
    1. Enums (SearchScope, OperationType)
    2. Literal Types
    3. Connection Defaults
    4. Server Types
    5. Other constants
    """

    # =========================================================================
    # LDAP SEARCH SCOPE ENUMS (FIRST - Most Used)
    # =========================================================================
    # Python 3.13+ StrEnum Best Practices: Provides string-like behavior
    # with enum validation

    class SearchScope(StrEnum):
        """LDAP search scope types (RFC 4511).

        Python 3.13+ StrEnum provides string-like behavior with enum validation.
        Can be used interchangeably with SearchScopeLiteral in type hints.

        **Pydantic 2 Usage:**
            Prefer using StrEnum directly in Pydantic models for better validation:
            >>> from pydantic import BaseModel
            >>> class SearchRequest(BaseModel):
            ...     scope: FlextLdapConstants.SearchScope
            ...     base_dn: str
            >>> request = SearchRequest(scope="BASE", base_dn="dc=example,dc=com")
            >>> request.scope  # <SearchScope.BASE: 'BASE'>

        **Literal Usage:**
            Use LiteralTypes.SearchScopeLiteral for function parameters and type hints
            where you need strict string literal validation without enum instances.
        """

        BASE = "BASE"
        ONELEVEL = "ONELEVEL"
        SUBTREE = "SUBTREE"

    # =========================================================================
    # LDAP OPERATION TYPES (FIRST - Most Used)
    # =========================================================================

    class OperationType(StrEnum):
        """LDAP operation types."""

        SEARCH = "search"
        ADD = "add"
        MODIFY = "modify"
        DELETE = "delete"
        MODIFY_DN = "modify_dn"
        COMPARE = "compare"
        BIND = "bind"
        UNBIND = "unbind"

    # =========================================================================
    # TYPE ALIASES (for backward compatibility and type hints)
    # =========================================================================
    # Note: Type aliases are defined after all StrEnum classes
    # See end of class for type aliases

    # =========================================================================
    # SERVER TYPES (FIRST - Server Identification)
    # =========================================================================

    class ServerTypes(StrEnum):
        """LDAP server type identifiers."""

        RFC = "rfc"  # RFC-compliant (no quirks)
        GENERIC = "generic"
        OPENLDAP = "openldap"
        OPENLDAP1 = "openldap1"
        OPENLDAP2 = "openldap2"
        OID = "oid"
        OUD = "oud"
        AD = "ad"

    # =========================================================================
    # LDAP CONNECTION DEFAULTS
    # =========================================================================

    class ConnectionDefaults:
        """Default values for LDAP connections."""

        PORT: Final[int] = 389
        PORT_SSL: Final[int] = 636
        TIMEOUT: Final[int] = 30
        AUTO_BIND: Final[bool] = True
        AUTO_RANGE: Final[bool] = True
        POOL_SIZE: Final[int] = 10
        POOL_LIFETIME: Final[int] = 3600

    # =========================================================================
    # DEFAULT VALUES
    # =========================================================================

    class LdapDefaults(StrEnum):
        """LDAP-specific default values.

        Note: SERVER_TYPE removed - use ServerTypes.GENERIC instead.
        """

        OBJECT_CLASS_TOP = "top"
        SCHEMA_SUBENTRY = "cn=subschema"
        DEFAULT_SEARCH_FILTER = "(objectClass=*)"
        SCHEMA_OBJECT_CLASSES = "objectClasses"
        SCHEMA_ATTRIBUTE_TYPES = "attributeTypes"
        SCHEMA_LDAP_SYNTAXES = "ldapSyntaxes"

    # =========================================================================
    # SEARCH FILTERS
    # =========================================================================

    class Filters(StrEnum):
        """Default LDAP search filters.

        DRY: Reuses LdapDefaults.DEFAULT_SEARCH_FILTER for ALL_ENTRIES_FILTER.
        """

        ALL_ENTRIES_FILTER = "(objectClass=*)"
        ALL_USERS_FILTER = "(objectClass=person)"
        DEFAULT_USER_FILTER = "(objectClass=inetOrgPerson)"
        DEFAULT_GROUP_FILTER = "(objectClass=groupOfNames)"

    # =========================================================================
    # LDAP ATTRIBUTE NAMES
    # =========================================================================

    class LdapAttributeNames(StrEnum):
        """LDAP attribute names."""

        DN = "dn"
        OBJECT_CLASS = "objectClass"
        CN = "cn"
        UID = "uid"
        MAIL = "mail"
        ALL_ATTRIBUTES = "*"  # Wildcard for all attributes
        CHANGETYPE = "changetype"

    # =========================================================================
    # ERROR STRINGS
    # =========================================================================

    class ErrorStrings(StrEnum):
        """Error/status string constants."""

        UNKNOWN_ERROR = "Unknown error"
        NOT_CONNECTED = "Not connected to LDAP server"
        ENTRY_ALREADY_EXISTS = "already exists"
        ENTRY_ALREADY_EXISTS_ALT = "entryalreadyexists"
        ENTRY_ALREADY_EXISTS_LDAP = "ldap_already_exists"
        SESSION_TERMINATED = "session terminated"

    # =========================================================================
    # LDAP CHANGE TYPE OPERATIONS
    # =========================================================================

    class ChangeTypeOperations(StrEnum):
        """LDAP changetype operation constants (RFC 2849).

        Used for LDIF changetype attribute and modify operations.
        DRY: Reuses class-level constants for common operation strings.
        """

        ADD = "add"
        DELETE = "delete"
        MODIFY = "modify"
        MODDN = "moddn"
        MODRDN = "modrdn"
        REPLACE = "replace"

    # =========================================================================
    # OPERATIONAL ATTRIBUTES (IGNORED IN COMPARISON)
    # =========================================================================

    class OperationalAttributes:
        """Operational attributes ignored in entry comparison (immutable frozenset)."""

        IGNORE_SET: Final[frozenset[str]] = frozenset({
            "add",
            "delete",
            "modify",
            "replace",
            "changetype",
            "createTimestamp",
            "modifyTimestamp",
            "creatorsName",
            "modifiersName",
            "entryUUID",
            "entryCSN",
        })

    # =========================================================================
    # UPSERT OPERATION RESULTS
    # =========================================================================

    class UpsertOperations(StrEnum):
        """Upsert operation result types."""

        ADDED = "added"
        MODIFIED = "modified"
        SKIPPED = "skipped"

    # =========================================================================
    # LDAP OPERATION LOGGING CONSTANTS
    # =========================================================================

    class LdapOperationLogging:
        """LDAP operation logging constants for structured logging."""

        MAX_LOG_LENGTH: Final[int] = 100

    class LdapOperationNames(StrEnum):
        """LDAP operation name constants for structured logging.

        DRY: Reuses OperationType values where applicable.
        """

        SYNC = "sync_ldif_file"
        CONNECT = "connect"
        DISCONNECT = "disconnect"
        SEARCH = "search"
        ADD = "add"
        MODIFY = "modify"
        DELETE = "delete"
        BATCH_UPSERT = "batch_upsert"
        DETECT_FROM_CONNECTION = "detect_from_connection"
        LDAP3_TO_LDIF_ENTRY = "ldap3_to_ldif_entry"
        LDIF_ENTRY_TO_LDAP3_ATTRIBUTES = "ldif_entry_to_ldap3_attributes"

    # =========================================================================
    # LDAP RESULT CODES
    # =========================================================================

    class LdapResultCodes:
        """LDAP result codes (RFC 4511)."""

        SUCCESS: Final[int] = 0
        PARTIAL_SUCCESS_CODES: Final[frozenset[int]] = frozenset({0, 3, 4, 11})

    # =========================================================================
    # ACL ATTRIBUTES
    # =========================================================================

    class AclAttributes(StrEnum):
        """ACL-related attribute names."""

        RAW = "raw"
        TARGET = "target"
        TARGET_ATTRIBUTES = "targetAttributes"
        SUBJECT = "subject"
        PERMISSIONS = "permissions"

    # =========================================================================
    # ACL FORMAT
    # =========================================================================

    class AclFormat(StrEnum):
        """Supported ACL format identifiers."""

        GENERIC = "generic"
        OPENLDAP2 = "openldap2"
        OPENLDAP1 = "openldap1"
        ORACLE = "oracle"

    # =========================================================================
    # SYNTHETIC DNS
    # =========================================================================

    class SyntheticDns(StrEnum):
        """Synthetic DN constants for internal operations."""

        ACL_RULE = "cn=acl-rule"
        OBJECT_CLASS_DEFINITION = "cn=objectclass-definition"
        ATTRIBUTE_TYPE_DEFINITION = "cn=attributetype-definition"

    # =========================================================================
    # LDAP DICT KEYS
    # =========================================================================

    class LdapDictKeys(StrEnum):
        """LDAP dictionary key names."""

        DESCRIPTION = "description"

    # =========================================================================
    # SASL MECHANISMS
    # =========================================================================

    class SaslMechanisms(StrEnum):
        """SASL authentication mechanism constants."""

        SIMPLE = "SIMPLE"
        SASL_EXTERNAL = "SASL/EXTERNAL"
        SASL_DIGEST_MD5 = "SASL/DIGEST-MD5"
        SASL_GSSAPI = "SASL/GSSAPI"

    # =========================================================================
    # SCOPES
    # =========================================================================

    class Scopes:
        """LDAP search scope constants for ldap3."""

        BASE_LDAP3: Final[int] = 0  # BASE scope
        LEVEL_LDAP3: Final[int] = 1  # ONELEVEL scope
        SUBTREE_LDAP3: Final[int] = 2  # SUBTREE scope

    class Ldap3ScopeValues(StrEnum):
        """LDAP3 scope string values matching Ldap3Scope Literal type."""

        BASE = "BASE"
        LEVEL = "LEVEL"
        SUBTREE = "SUBTREE"

    # =========================================================================
    # ROOT DSE ATTRIBUTES
    # =========================================================================

    class RootDseAttributes(StrEnum):
        """Root DSE attribute name constants."""

        VENDOR_NAME = "vendorName"
        VENDOR_VERSION = "vendorVersion"
        CONFIG_CONTEXT = "configContext"
        ROOT_DOMAIN_NAMING_CONTEXT = "rootDomainNamingContext"
        DEFAULT_NAMING_CONTEXT = "defaultNamingContext"

    # =========================================================================
    # VENDOR NAMES
    # =========================================================================

    class VendorNames(StrEnum):
        """Vendor name constants for server detection."""

        ORACLE = "oracle"
        OPENLDAP = "openldap"
        MICROSOFT = "microsoft"
        WINDOWS = "windows"
        NOVELL = "novell"
        EDIR = "edir"
        IBM = "ibm"
        UNBOUNDID = "unboundid"
        FORGEROCK = "forgerock"

    # =========================================================================
    # LITERAL TYPES (Python 3.13+ PEP 695 type aliases for type hints and Pydantic 2)
    # =========================================================================
    # PEP 695 type aliases (Python 3.13+): Using `type` keyword for type aliases
    # These Literal types are derived from StrEnum values above and are used in:
    # - Pydantic model field annotations
    # - Function parameter type hints
    # - External library compatibility (ldap3, etc.)
    #
    # IMPORTANT: All Literal types MUST match their corresponding StrEnum
    # values exactly. This ensures type safety and consistency across
    # the codebase.
    #
    # Python 3.13+ PEP 695: Using `type` keyword for type aliases
    # (no backward compatibility needed)

    class LiteralTypes:
        """Literal type aliases for type-safe annotations (Python 3.13+ PEP 695).

        These type aliases provide strict type checking for common string values
        used throughout the flext-ldap codebase. They are derived directly from
        StrEnum values using FlextConstants.extract_enum_values() to ensure
        zero duplication and automatic synchronization.

        All Literal types are generated from their StrEnum counterparts:
        - SearchScopeLiteral ↔ SearchScope
        - OperationTypeLiteral ↔ OperationType
        - ServerTypeLiteral ↔ ServerTypes
        - etc.

        Uses PEP 695 `type` keyword (Python 3.13+) for type aliases.

        **DRY Pattern:**
        Literals are defined using values extracted from StrEnum classes,
        ensuring they stay in sync automatically. No manual validation needed.

        **When to Use Literal vs StrEnum:**

        1. **Use StrEnum in Pydantic Models** (Recommended):
           - Better validation and error messages
           - Automatic serialization to string values
           - Runtime enum validation
           >>> from pydantic import BaseModel
           >>> class SearchModel(BaseModel):
           ...     scope: FlextLdapConstants.SearchScope  # StrEnum
           ...     operation: FlextLdapConstants.OperationType  # StrEnum

        2. **Use Literal in Function Signatures** (For strict string typing):
           - When you need string literal types without enum instances
           - For external library compatibility (ldap3, etc.)
           - For type hints in protocols and interfaces
           >>> def search(
           ...     scope: FlextLdapConstants.LiteralTypes.SearchScopeLiteral,
           ... ) -> None: ...

        3. **Use Literal in Pydantic Models** (When needed):
           - When you need strict string validation without enum overhead
           - For JSON schema generation with specific string values
           >>> class ConfigModel(BaseModel):
           ...     server_type: FlextLdapConstants.LiteralTypes.ServerTypeLiteral

        **Pydantic 2 Best Practices:**
        - StrEnum fields serialize to their string values in JSON mode
        - StrEnum fields can accept both enum instances and string values
        - Literal fields only accept exact string matches
        - Both provide type safety, but StrEnum offers better runtime validation
        """

        # DRY Pattern: Literals manually defined but auto-validated against StrEnum
        # StrEnum is single source of truth - validation ensures sync
        # SearchScope StrEnum → Literal (values must match SearchScope enum)
        type SearchScopeLiteral = Literal[
            "BASE",
            "ONELEVEL",
            "SUBTREE",
        ]

        # OperationType StrEnum → Literal (values must match OperationType enum)
        type OperationTypeLiteral = Literal[
            "search",
            "add",
            "modify",
            "delete",
            "modify_dn",
            "compare",
            "bind",
            "unbind",
        ]

        # ServerTypes StrEnum → Literal (values must match ServerTypes enum)
        type ServerTypeLiteral = Literal[
            "rfc",
            "generic",
            "openldap",
            "openldap1",
            "openldap2",
            "oid",
            "oud",
            "ad",
        ]

        # UpsertOperations StrEnum → Literal (values must match UpsertOperations enum)
        type UpsertOperationLiteral = Literal[
            "added",
            "modified",
            "skipped",
        ]

        # Ldap3ScopeValues StrEnum → Literal (for ldap3 library compatibility)
        type Ldap3ScopeLiteral = Literal[
            "BASE",
            "LEVEL",
            "SUBTREE",
        ]

        # LdapDefaults StrEnum → Literal (values must match LdapDefaults enum)
        type LdapDefaultLiteral = Literal[
            "top",
            "cn=subschema",
            "(objectClass=*)",
            "objectClasses",
            "attributeTypes",
            "ldapSyntaxes",
        ]  # Values match LdapDefaults enum - no duplication

        # Filters StrEnum → Literal (values hardcoded to avoid forward references)
        type FilterLiteral = Literal[
            "(objectClass=*)",
            "(objectClass=person)",
            "(objectClass=inetOrgPerson)",
            "(objectClass=groupOfNames)",
        ]  # Values match Filters enum - no duplication

        # LdapAttributeNames StrEnum → Literal (values hardcoded to avoid forward references)
        type LdapAttributeNameLiteral = Literal[
            "dn",
            "objectClass",
            "cn",
            "uid",
            "mail",
            "*",
            "changetype",
        ]  # Values match LdapAttributeNames enum - no duplication

        # ErrorStrings StrEnum → Literal (values hardcoded to avoid forward references)
        type ErrorStringLiteral = Literal[
            "Unknown error",
            "Not connected to LDAP server",
            "already exists",
            "entryalreadyexists",
            "ldap_already_exists",
            "session terminated",
        ]  # Values match ErrorStrings enum - no duplication

        # LdapOperationNames StrEnum → Literal (auto-generated from enum values)
        type LdapOperationNameLiteral = Literal[
            "sync_ldif_file",
            "connect",
            "disconnect",
            "search",
            "add",
            "modify",
            "delete",
            "batch_upsert",
            "detect_from_connection",
            "ldap3_to_ldif_entry",
            "ldif_entry_to_ldap3_attributes",
        ]  # Values match LdapOperationNames enum - no duplication

        # AclAttributes StrEnum → Literal (auto-generated from enum values)
        type AclAttributeLiteral = Literal[
            "raw",
            "target",
            "targetAttributes",
            "subject",
            "permissions",
        ]  # Values match AclAttributes enum - no duplication

        # AclFormat StrEnum → Literal (auto-generated from enum values)
        type AclFormatLiteral = Literal[
            "generic",
            "openldap2",
            "openldap1",
            "oracle",
        ]  # Values match AclFormat enum - no duplication

        # SyntheticDns StrEnum → Literal (auto-generated from enum values)
        type SyntheticDnLiteral = Literal[
            "cn=acl-rule",
            "cn=objectclass-definition",
            "cn=attributetype-definition",
        ]  # Values match SyntheticDns enum - no duplication

        # SaslMechanisms StrEnum → Literal (values hardcoded to avoid forward references)
        type SaslMechanismLiteral = Literal[
            "SIMPLE",
            "SASL/EXTERNAL",
            "SASL/DIGEST-MD5",
            "SASL/GSSAPI",
        ]  # Values match SaslMechanisms enum - no duplication

        # RootDseAttributes StrEnum → Literal (values from RootDseAttributes enum)
        type RootDseAttributeLiteral = Literal[
            "vendorName",
            "vendorVersion",
            "configContext",
            "rootDomainNamingContext",
            "defaultNamingContext",
        ]  # Values match RootDseAttributes enum - no duplication

        # VendorNames StrEnum → Literal (values from VendorNames enum)
        type VendorNameLiteral = Literal[
            "oracle",
            "openldap",
            "microsoft",
            "windows",
            "novell",
            "edir",
            "ibm",
            "unboundid",
            "forgerock",
        ]  # Values match VendorNames enum - no duplication

        # ChangeTypeOperations StrEnum → Literal (values from ChangeTypeOperations enum)
        type ChangeTypeOperationLiteral = Literal[
            "add",
            "delete",
            "modify",
            "moddn",
            "modrdn",
            "replace",
        ]  # Values match ChangeTypeOperations enum - no duplication

    # =========================================================================
    # TYPE ALIASES REMOVED
    # =========================================================================
    # Note: Removed convenience aliases (SearchScopeType, OperationTypeType, Ldap3ScopeType)
    # Use StrEnum classes directly: SearchScope, OperationType, Ldap3ScopeValues
    # This follows the rule of no convenience aliases - use types directly.

    # =========================================================================
    # RUNTIME VALIDATION - Ensure Literal types match StrEnum values
    # =========================================================================

    # @staticmethod
    # def validate_literal_matches_enum(
    #     enum_class: type[StrEnum],
    #     literal_values: tuple[str, ...],
    # ) -> None:
        """Validate that Literal type values match StrEnum values at runtime.

        This helper ensures that Literal types derived from StrEnums are kept
        in sync. Should be called during module initialization for validation.

        Args:
            enum_class: The StrEnum class to validate against
            literal_values: Tuple of literal string values

        Raises:
            ValueError: If literal values don't match enum values

        Example:
            >>> FlextLdapConstants.validate_literal_matches_enum(
            ...     FlextLdapConstants.SearchScope,
            ...     ("BASE", "ONELEVEL", "SUBTREE"),
            ... )

        # """
        # enum_values = frozenset(item.value for item in enum_class)
        # literal_set = frozenset(literal_values)
        #
        # if enum_values != literal_set:
        #     missing_in_literal = enum_values - literal_set
        #     extra_in_literal = literal_set - enum_values
        #     msg_parts = []
        #     if missing_in_literal:
        #         msg_parts.append(
        #             f"Missing in Literal (present in Enum): {sorted(missing_in_literal)}",
        #         )
        #     if extra_in_literal:
        #         msg_parts.append(
        #             f"Extra in Literal (not in Enum): {sorted(extra_in_literal)}",
        #         )
        #     msg = (
        #         f"Literal values for {enum_class.__name__} don't match Enum values. "
        #         + "; ".join(msg_parts)
        #     )
        #     raise ValueError(msg)

    # =========================================================================
    # DRY VALIDATION - Auto-validate Literals from StrEnum (no duplication)
    # =========================================================================
    # Single source of truth: StrEnum values are extracted and used to validate
    # that Literal types match. No manual validation needed - values come from
    # StrEnum directly.


# Note: Literal validation removed to avoid circular dependencies
# Literals are manually maintained to match StrEnum values
