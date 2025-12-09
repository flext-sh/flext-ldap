"""[PACKAGE] constants module."""

from __future__ import annotations

from collections.abc import Mapping
from enum import StrEnum
from typing import Final, Literal

from flext_ldif import FlextLdifConstants


class FlextLdapConstants(FlextLdifConstants):
    """FlextLdap domain constants extending FlextLdifConstants.

    Hierarchy:
        FlextLdifConstants (flext-core)
        └── FlextLdifConstants (flext-ldif)
            └── FlextLdapConstants (this module)

    Architecture:
    - All LDAP constants are organized in the .Ldap namespace
    - Direct access via FlextLdapConstants.Ldap.*
    - Access flext-ldif constants via FlextLdapConstants.Ldif.* (inherited from parent)
    - No aliases - use namespaces directly
    """

    # =========================================================================
    # NAMESPACE: .Ldap - All LDAP domain constants
    # =========================================================================

    class Ldap:
        """LDAP domain constants namespace.

        All LDAP-specific constants are organized here for better namespace
        organization and to enable composition with other domain constants.
        """

        # ═══════════════════════════════════════════════════════════════════
        # CORE IDENTIFIERS
        # ═══════════════════════════════════════════════════════════════════

        class Core:
            """Core identifiers for FLEXT LDAP."""

            NAME: Final[str] = "FLEXT_LDAP"

        # ═══════════════════════════════════════════════════════════════════
        # CQRS PATTERNS
        # ═══════════════════════════════════════════════════════════════════

        class LdapCqrs:
            """LDAP CQRS pattern constants."""

            class Status(StrEnum):
                """LDAP CQRS status enumeration.

                DRY Pattern:
                    StrEnum is the single source of truth. Use Status.PENDING.value
                    or Status.PENDING directly - no base strings needed.
                """

                PENDING = "pending"
                RUNNING = "running"
                COMPLETED = "completed"
                FAILED = "failed"

            type StatusLiteral = Literal[
                Status.PENDING,
                Status.RUNNING,
                Status.COMPLETED,
                Status.FAILED,
            ]

        # ═══════════════════════════════════════════════════════════════════
        # COMPOSITION: Use FlextLdifConstants via .Ldif namespace (no duplication)
        # ═══════════════════════════════════════════════════════════════════
        # Server types, filters, attributes come from flext-ldif domain
        # Access via .Ldif namespace: FlextLdapConstants.Ldif.ServerTypes
        # This enables clean namespace separation

        # ═══════════════════════════════════════════════════════════════════
        # LDAP FILTERS
        # ═══════════════════════════════════════════════════════════════════

        class Filters:
            """LDAP filter constants."""

            ALL_ENTRIES_FILTER: Final[str] = "(objectClass=*)"

        # ═══════════════════════════════════════════════════════════════════
        # LDAP ATTRIBUTE NAMES
        # ═══════════════════════════════════════════════════════════════════

        class LdapAttributeNames(StrEnum):
            """LDAP attribute name constants.

            Extends parent with LDAP-specific attribute names.
            DN and CHANGETYPE are available via .Ldif namespace from FlextLdifConstants.

            DRY Pattern:
                StrEnum is the single source of truth. Use LdapAttributeNames.OBJECT_CLASS.value
                or LdapAttributeNames.OBJECT_CLASS directly - no base strings needed.
            """

            # Core attribute names (reused from flext-ldif via .Ldif namespace)
            # Use FlextLdapConstants.Ldif.DictKeys.DN.value directly - no aliases
            # LDAP-specific attribute names
            CHANGETYPE = "changetype"
            OBJECT_CLASS = "objectClass"
            ALL_ATTRIBUTES = "*"

        # ═══════════════════════════════════════════════════════════════════
        # LDAP SEARCH SCOPE ENUMS (FIRST - Most Used)
        # ═══════════════════════════════════════════════════════════════════
        # Python 3.13+ StrEnum Best Practices: Provides string-like behavior
        # with enum validation

        class SearchScope(StrEnum):
            """LDAP search scope types (RFC 4511).

            Python 3.13+ StrEnum provides string-like behavior with enum validation.

            DRY Pattern:
                StrEnum is the single source of truth. Use SearchScope.BASE.value
                or SearchScope.BASE directly - no base strings needed.

            Can be used interchangeably with SearchScopeLiteral in type hints.

            **Pydantic 2 Usage:**
                Prefer using StrEnum directly in Pydantic models for better validation:
                >>> from pydantic import BaseModel
                >>> class SearchRequest(BaseModel):
                ...     scope: FlextLdapConstants.Ldap.SearchScope
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

        # ═══════════════════════════════════════════════════════════════════
        # LDAP OPERATION TYPES (FIRST - Most Used)
        # ═══════════════════════════════════════════════════════════════════

        class OperationType(StrEnum):
            """LDAP operation types.

            Extends base operation constants from flext-ldif with LDAP-specific operations.

            DRY Pattern:
                StrEnum is the single source of truth. Use OperationType.SEARCH.value
                or OperationType.SEARCH directly - no base strings needed.

            Uses .Ldif namespace to access parent constants.
            """

            SEARCH = "search"
            # Base operation constants (reused from flext-ldif via .Ldif namespace)
            ADD = "add"
            MODIFY = "modify"
            DELETE = "delete"
            # LDAP-specific operation types
            MODIFY_DN = "modify_dn"
            COMPARE = "compare"
            BIND = "bind"
            UNBIND = "unbind"

        # ═══════════════════════════════════════════════════════════════════
        # LDAP CONNECTION DEFAULTS
        # ═══════════════════════════════════════════════════════════════════

        class ConnectionDefaults:
            """Default values for LDAP connections."""

            PORT: Final[int] = 389  # LDAP standard port
            PORT_SSL: Final[int] = 636  # LDAPS standard port
            # Reuse DEFAULT_TIMEOUT from flext-core (no duplication)
            TIMEOUT: Final[int] = FlextLdifConstants.Network.DEFAULT_TIMEOUT
            AUTO_BIND: Final[bool] = True
            AUTO_RANGE: Final[bool] = True
            # Reuse DEFAULT_CONNECTION_POOL_SIZE from flext-core (no duplication)
            POOL_SIZE: Final[int] = (
                FlextLdifConstants.Network.DEFAULT_CONNECTION_POOL_SIZE
            )
            POOL_LIFETIME: Final[int] = 3600

        # ═══════════════════════════════════════════════════════════════════
        # ERROR STRINGS
        # ═══════════════════════════════════════════════════════════════════

        class ErrorStrings(StrEnum):
            """Error/status string constants.

            DRY Pattern:
                StrEnum is the single source of truth. Use ErrorStrings.UNKNOWN_ERROR.value
                or ErrorStrings.UNKNOWN_ERROR directly - no base strings needed.
            """

            UNKNOWN_ERROR = "Unknown error"
            NOT_CONNECTED = "Not connected to LDAP server"
            ENTRY_ALREADY_EXISTS = "already exists"
            ENTRY_ALREADY_EXISTS_ALT = "entryalreadyexists"
            ENTRY_ALREADY_EXISTS_LDAP = "ldap_already_exists"
            SESSION_TERMINATED = "session terminated"

        # ═══════════════════════════════════════════════════════════════════
        # LDAP CHANGE TYPE OPERATIONS
        # ═══════════════════════════════════════════════════════════════════

        class ChangeTypeOperations(StrEnum):
            """LDAP changetype operation constants (RFC 2849).

            Used for LDIF changetype attribute and modify operations.
            Extends base operation constants from flext-ldif with LDAP-specific operations.

            DRY Pattern:
                StrEnum is the single source of truth. Use ChangeTypeOperations.ADD.value
                or ChangeTypeOperations.ADD directly - no base strings needed.
            """

            # Base operation constants (reused from flext-ldif via .Ldif namespace)
            ADD = "add"
            DELETE = "delete"
            MODIFY = "modify"
            REPLACE = "replace"
            # LDAP-specific changetype operations
            MODDN = "moddn"
            MODRDN = "modrdn"

        # ═══════════════════════════════════════════════════════════════════
        # OPERATIONAL ATTRIBUTES (IGNORED IN COMPARISON)
        # ═══════════════════════════════════════════════════════════════════
        # NOTE: This class extends parent OperationalAttributes with LDAP-specific
        # IGNORE_SET for entry comparison. Parent class has COMMON set for migration.

        class OperationalAttributes(FlextLdifConstants.Ldif.OperationalAttributes):
            """Operational attributes ignored in entry comparison (immutable frozenset).

            Extends parent OperationalAttributes with LDAP-specific IGNORE_SET
            for entry comparison operations.
            """

            IGNORE_SET: Final[frozenset[str]] = frozenset({
                # Base operation constants (reused from flext-ldif via .Ldif namespace)
                "add",
                "delete",
                "modify",
                "replace",
                "changetype",
                # LDAP-specific operational attributes
                "createTimestamp",
                "modifyTimestamp",
                "creatorsName",
                "modifiersName",
                "entryUUID",
                "entryCSN",
            })

        # ═══════════════════════════════════════════════════════════════════
        # UPSERT OPERATION RESULTS
        # ═══════════════════════════════════════════════════════════════════

        class UpsertOperations(StrEnum):
            """Upsert operation result types.

            DRY Pattern:
                StrEnum is the single source of truth. Use UpsertOperations.ADDED.value
                or UpsertOperations.ADDED directly - no base strings needed.
            """

            ADDED = "added"
            MODIFIED = "modified"
            SKIPPED = "skipped"

        # ═══════════════════════════════════════════════════════════════════
        # LDAP OPERATION LOGGING CONSTANTS
        # ═══════════════════════════════════════════════════════════════════

        class LdapOperationLogging:
            """LDAP operation logging constants for structured logging."""

            MAX_LOG_LENGTH: Final[int] = 100

        class LdapOperationNames(StrEnum):
            """LDAP operation name constants for structured logging.

            DRY: Reuses OperationType values where applicable.
            Uses .Ldif namespace to access parent constants.

            DRY Pattern:
                StrEnum is the single source of truth. Use LdapOperationNames.SYNC.value
                or LdapOperationNames.SYNC directly - no base strings needed.
            """

            SYNC = "sync_ldif_file"
            CONNECT = "connect"
            DISCONNECT = "disconnect"
            SEARCH = "search"
            # Base operation constants (reused from flext-ldif via .Ldif namespace)
            ADD = "add"
            MODIFY = "modify"
            DELETE = "delete"
            # LDAP-specific operation names
            BATCH_UPSERT = "batch_upsert"
            DETECT_FROM_CONNECTION = "detect_from_connection"
            LDAP3_TO_LDIF_ENTRY = "ldap3_to_ldif_entry"
            LDIF_ENTRY_TO_LDAP3_ATTRIBUTES = "ldif_entry_to_ldap3_attributes"

        # ═══════════════════════════════════════════════════════════════════
        # LDAP RESULT CODES
        # ═══════════════════════════════════════════════════════════════════

        class LdapResultCodes:
            """LDAP result codes (RFC 4511)."""

            SUCCESS: Final[int] = 0
            PARTIAL_SUCCESS_CODES: Final[frozenset[int]] = frozenset({0, 3, 4, 11})

        # ═══════════════════════════════════════════════════════════════════
        # ACL ATTRIBUTES
        # ═══════════════════════════════════════════════════════════════════
        # NOTE: LdapAclAttributes is a StrEnum for LDAP-specific ACL attributes
        # Parent FlextLdifConstants.Ldif.AclAttributes is a class with RFC baseline attributes
        # These serve different purposes - using separate class to avoid override conflict

        class LdapAclAttributes(StrEnum):
            """ACL-related attribute names for LDAP operations.

            LDAP-specific ACL attribute names used in LDAP operations.
            For RFC baseline ACL attributes, use FlextLdapConstants.Ldif.AclAttributes.

            DRY Pattern:
                StrEnum is the single source of truth. Use LdapAclAttributes.RAW.value
                or LdapAclAttributes.RAW directly - no base strings needed.
            """

            RAW = "raw"
            TARGET = "target"
            TARGET_ATTRIBUTES = "targetAttributes"
            SUBJECT = "subject"
            PERMISSIONS = "permissions"

        # Access parent AclAttributes via .Ldif namespace (not override)
        # Use FlextLdapConstants.Ldif.AclAttributes for RFC baseline attributes
        # Use LdapAclAttributes for LDAP-specific enum values

        # ═══════════════════════════════════════════════════════════════════
        # ACL FORMAT
        # ═══════════════════════════════════════════════════════════════════

        class AclFormat(StrEnum):
            """Supported ACL format identifiers.

            DRY Pattern:
                StrEnum is the single source of truth. Use AclFormat.GENERIC.value
                or AclFormat.GENERIC directly - no base strings needed.
            """

            GENERIC = "generic"
            OPENLDAP2 = "openldap2"
            OPENLDAP1 = "openldap1"
            ORACLE = "oracle"

        # ═══════════════════════════════════════════════════════════════════
        # SYNTHETIC DNS
        # ═══════════════════════════════════════════════════════════════════

        class SyntheticDns(StrEnum):
            """Synthetic DN constants for internal operations.

            DRY Pattern:
                StrEnum is the single source of truth. Use SyntheticDns.ACL_RULE.value
                or SyntheticDns.ACL_RULE directly - no base strings needed.
            """

            ACL_RULE = "cn=acl-rule"
            OBJECT_CLASS_DEFINITION = "cn=objectclass-definition"
            ATTRIBUTE_TYPE_DEFINITION = "cn=attributetype-definition"

        # ═══════════════════════════════════════════════════════════════════
        # LDAP DICT KEYS
        # ═══════════════════════════════════════════════════════════════════

        class LdapDictKeys(StrEnum):
            """LDAP dictionary key names.

            DRY Pattern:
                StrEnum is the single source of truth. Use LdapDictKeys.DESCRIPTION.value
                or LdapDictKeys.DESCRIPTION directly - no base strings needed.
            """

            DESCRIPTION = "description"

        # ═══════════════════════════════════════════════════════════════════
        # SASL MECHANISMS
        # ═══════════════════════════════════════════════════════════════════

        class SaslMechanisms(StrEnum):
            """SASL authentication mechanism constants.

            DRY Pattern:
                StrEnum is the single source of truth. Use SaslMechanisms.SIMPLE.value
                or SaslMechanisms.SIMPLE directly - no base strings needed.
            """

            SIMPLE = "SIMPLE"
            SASL_EXTERNAL = "SASL/EXTERNAL"
            SASL_DIGEST_MD5 = "SASL/DIGEST-MD5"
            SASL_GSSAPI = "SASL/GSSAPI"

        # ═══════════════════════════════════════════════════════════════════
        # SCOPES
        # ═══════════════════════════════════════════════════════════════════
        # NOTE: Scopes in flext-ldap provides ldap3-specific integer constants
        # Parent FlextLdifConstants.Ldif.Scopes provides string constants
        # These serve different purposes (ldap3 library vs LDIF parsing)

        class Scopes(FlextLdifConstants.Ldif.Scopes):
            """LDAP search scope constants for ldap3.

            Extends parent Scopes with ldap3-specific integer constants.
            Parent class provides string constants for LDIF parsing.
            """

            BASE_LDAP3: Final[int] = 0  # BASE scope
            LEVEL_LDAP3: Final[int] = 1  # ONELEVEL scope
            SUBTREE_LDAP3: Final[int] = 2  # SUBTREE scope

        class Ldap3ScopeValues(StrEnum):
            """LDAP3 scope string values matching Ldap3Scope Literal type.

            DRY Pattern:
                StrEnum is the single source of truth. Use Ldap3ScopeValues.BASE.value
                or Ldap3ScopeValues.BASE directly - no base strings needed.
            """

            BASE = "BASE"
            LEVEL = "LEVEL"
            SUBTREE = "SUBTREE"

        # ═══════════════════════════════════════════════════════════════════
        # ROOT DSE ATTRIBUTES
        # ═══════════════════════════════════════════════════════════════════

        class RootDseAttributes(StrEnum):
            """Root DSE attribute name constants.

            DRY Pattern:
                StrEnum is the single source of truth. Use RootDseAttributes.VENDOR_NAME.value
                or RootDseAttributes.VENDOR_NAME directly - no base strings needed.
            """

            VENDOR_NAME = "vendorName"
            VENDOR_VERSION = "vendorVersion"
            CONFIG_CONTEXT = "configContext"
            ROOT_DOMAIN_NAMING_CONTEXT = "rootDomainNamingContext"
            DEFAULT_NAMING_CONTEXT = "defaultNamingContext"

        # ═══════════════════════════════════════════════════════════════════
        # VENDOR NAMES
        # ═══════════════════════════════════════════════════════════════════

        class VendorNames(StrEnum):
            """Vendor name constants for server detection.

            DRY Pattern:
                StrEnum is the single source of truth. Use VendorNames.ORACLE.value
                or VendorNames.ORACLE directly - no base strings needed.
            """

            ORACLE = "oracle"
            OPENLDAP = "openldap"
            MICROSOFT = "microsoft"
            WINDOWS = "windows"
            NOVELL = "novell"
            EDIR = "edir"
            IBM = "ibm"
            UNBOUNDID = "unboundid"
            FORGEROCK = "forgerock"

        # ═══════════════════════════════════════════════════════════════════
        # LITERAL TYPES (Python 3.13+ PEP 695 type aliases for type hints and Pydantic 2)
        # ═══════════════════════════════════════════════════════════════════
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

        class LiteralTypes(FlextLdifConstants.Ldif.LiteralTypes):
            """Literal type aliases for type-safe annotations (Python 3.13+ PEP 695).

            Extends parent LiteralTypes with LDAP-specific literal types.
            Parent class provides LDIF-specific literal types.

            These type aliases provide strict type checking for common string values
            used throughout the flext-ldap codebase. They are derived directly from
            StrEnum values using FlextLdifConstants.extract_enum_values() to ensure
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
               ...     scope: FlextLdapConstants.Ldap.SearchScope  # StrEnum
               ...     operation: FlextLdapConstants.Ldap.OperationType  # StrEnum

            2. **Use Literal in Function Signatures** (For strict string typing):
               - When you need string literal types without enum instances
               - For external library compatibility (ldap3, etc.)
               - For type hints in protocols and interfaces
               >>> def search(
               ...     scope: FlextLdapConstants.Ldap.LiteralTypes.SearchScopeLiteral,
               ... ) -> None: ...

            3. **Use Literal in Pydantic Models** (When needed):
               - When you need strict string validation without enum overhead
               - For JSON schema generation with specific string values
               >>> class ConfigModel(BaseModel):
               ...     server_type: (
               ...         FlextLdapConstants.Ldap.LiteralTypes.LdapServerTypeLiteral
               ...     )

            **Pydantic 2 Best Practices:**
            - StrEnum fields serialize to their string values in JSON mode
            - StrEnum fields can accept both enum instances and string values
            - Literal fields only accept exact string matches
            - Both provide type safety, but StrEnum offers better runtime validation
            """

        # DRY Pattern: Literals reference StrEnum members - NO string duplication!
        # StrEnum is single source of truth - Literal types reference enum members
        # SearchScope StrEnum → Literal (references SearchScope enum members)
        type SearchScopeLiteral = Literal[
            SearchScope.BASE,
            SearchScope.ONELEVEL,
            SearchScope.SUBTREE,
        ]

        # OperationType StrEnum → Literal (references OperationType enum members)
        # Reuses base operation constants from flext-ldif via OperationType enum
        type OperationTypeLiteral = Literal[
            OperationType.SEARCH,
            # Reuses base operations from flext-ldif via OperationType enum
            OperationType.ADD,
            OperationType.MODIFY,
            OperationType.DELETE,
            OperationType.MODIFY_DN,
            OperationType.COMPARE,
            OperationType.BIND,
            OperationType.UNBIND,
        ]

        # ServerTypes StrEnum → Literal (references ServerTypes enum members)
        # NOTE: LdapServerTypeLiteral provides LDAP-specific server types
        # Parent FlextLdifConstants.LiteralTypes.ServerTypeLiteral has
        # LDIF-specific types
        # Using separate type alias to avoid override conflict
        # For LDIF parsing, use parent FlextLdifConstants.LiteralTypes.ServerTypeLiteral
        # DRY Pattern: References parent ServerTypes enum members - NO string duplication!
        # Use string literals matching enum values for Literal type compatibility
        type LdapServerTypeLiteral = Literal[
            "rfc",  # FlextLdifConstants.Ldif.ServerTypes.RFC
            "oid",  # FlextLdifConstants.Ldif.ServerTypes.OID
            "oud",  # FlextLdifConstants.Ldif.ServerTypes.OUD
            "openldap",  # FlextLdifConstants.Ldif.ServerTypes.OPENLDAP
            "openldap1",  # FlextLdifConstants.Ldif.ServerTypes.OPENLDAP1
            "apache",  # FlextLdifConstants.Ldif.ServerTypes.APACHE
            "ds389",  # FlextLdifConstants.Ldif.ServerTypes.DS389
            "novell",  # FlextLdifConstants.Ldif.ServerTypes.NOVELL
            "ibm_tivoli",  # FlextLdifConstants.Ldif.ServerTypes.IBM_TIVOLI
            "ad",  # FlextLdifConstants.Ldif.ServerTypes.AD
            "relaxed",  # FlextLdifConstants.Ldif.ServerTypes.RELAXED
        ]

        # UpsertOperations StrEnum → Literal (references UpsertOperations enum members)
        type UpsertOperationLiteral = Literal[
            UpsertOperations.ADDED,
            UpsertOperations.MODIFIED,
            UpsertOperations.SKIPPED,
        ]

        # Ldap3ScopeValues StrEnum → Literal (references Ldap3ScopeValues enum members)
        type Ldap3ScopeLiteral = Literal[
            Ldap3ScopeValues.BASE,
            Ldap3ScopeValues.LEVEL,
            Ldap3ScopeValues.SUBTREE,
        ]

        # ErrorStrings StrEnum → Literal (references ErrorStrings enum members)
        type ErrorStringLiteral = Literal[
            ErrorStrings.UNKNOWN_ERROR,
            ErrorStrings.NOT_CONNECTED,
            ErrorStrings.ENTRY_ALREADY_EXISTS,
            ErrorStrings.ENTRY_ALREADY_EXISTS_ALT,
            ErrorStrings.ENTRY_ALREADY_EXISTS_LDAP,
            ErrorStrings.SESSION_TERMINATED,
        ]

        # LdapOperationNames StrEnum → Literal (references LdapOperationNames enum members)
        # Reuses base operation constants from flext-ldif via LdapOperationNames enum
        type LdapOperationNameLiteral = Literal[
            LdapOperationNames.SYNC,
            LdapOperationNames.CONNECT,
            LdapOperationNames.DISCONNECT,
            LdapOperationNames.SEARCH,
            # Reuses base operations from flext-ldif via LdapOperationNames enum
            LdapOperationNames.ADD,
            LdapOperationNames.MODIFY,
            LdapOperationNames.DELETE,
            LdapOperationNames.BATCH_UPSERT,
            LdapOperationNames.DETECT_FROM_CONNECTION,
            LdapOperationNames.LDAP3_TO_LDIF_ENTRY,
            LdapOperationNames.LDIF_ENTRY_TO_LDAP3_ATTRIBUTES,
        ]

        # LdapAclAttributes StrEnum → Literal (references LdapAclAttributes enum members)
        type AclAttributeLiteral = Literal[
            LdapAclAttributes.RAW,
            LdapAclAttributes.TARGET,
            LdapAclAttributes.TARGET_ATTRIBUTES,
            LdapAclAttributes.SUBJECT,
            LdapAclAttributes.PERMISSIONS,
        ]

        # AclFormat StrEnum → Literal (references AclFormat enum members)
        type AclFormatLiteral = Literal[
            AclFormat.GENERIC,
            AclFormat.OPENLDAP2,
            AclFormat.OPENLDAP1,
            AclFormat.ORACLE,
        ]

        # SyntheticDns StrEnum → Literal (references SyntheticDns enum members)
        type SyntheticDnLiteral = Literal[
            SyntheticDns.ACL_RULE,
            SyntheticDns.OBJECT_CLASS_DEFINITION,
            SyntheticDns.ATTRIBUTE_TYPE_DEFINITION,
        ]

        # SaslMechanisms StrEnum → Literal (references SaslMechanisms enum members)
        type SaslMechanismLiteral = Literal[
            SaslMechanisms.SIMPLE,
            SaslMechanisms.SASL_EXTERNAL,
            SaslMechanisms.SASL_DIGEST_MD5,
            SaslMechanisms.SASL_GSSAPI,
        ]

        # RootDseAttributes StrEnum → Literal (references RootDseAttributes enum members)
        type RootDseAttributeLiteral = Literal[
            RootDseAttributes.VENDOR_NAME,
            RootDseAttributes.VENDOR_VERSION,
            RootDseAttributes.CONFIG_CONTEXT,
            RootDseAttributes.ROOT_DOMAIN_NAMING_CONTEXT,
            RootDseAttributes.DEFAULT_NAMING_CONTEXT,
        ]

        # VendorNames StrEnum → Literal (references VendorNames enum members)
        type VendorNameLiteral = Literal[
            VendorNames.ORACLE,
            VendorNames.OPENLDAP,
            VendorNames.MICROSOFT,
            VendorNames.WINDOWS,
            VendorNames.NOVELL,
            VendorNames.EDIR,
            VendorNames.IBM,
            VendorNames.UNBOUNDID,
            VendorNames.FORGEROCK,
        ]

        # ChangeTypeOperations StrEnum → Literal (references ChangeTypeOperations enum members)
        # Reuses base operation constants from flext-ldif via ChangeTypeOperations enum
        type ChangeTypeOperationLiteral = Literal[
            # Reuses base operations from flext-ldif via ChangeTypeOperations enum
            ChangeTypeOperations.ADD,
            ChangeTypeOperations.DELETE,
            ChangeTypeOperations.MODIFY,
            ChangeTypeOperations.MODDN,
            ChangeTypeOperations.MODRDN,
            ChangeTypeOperations.REPLACE,
        ]

        # ═══════════════════════════════════════════════════════════════════
        # SERVER TYPE MAPPINGS (flext-ldap ↔ flext-ldif compatibility)
        # ═══════════════════════════════════════════════════════════════════

        class ServerTypeMappings:
            """Mappings between flext-ldap server type strings and flext-ldif.

            ServerTypeLiteral used in adapters/ldap3.py SearchExecutor for
            normalizing server types.

            Used in adapters/ldap3.py SearchExecutor for normalizing server types
            for flext-ldif parser compatibility via .Ldif namespace.
            """

            LDIF_COMPATIBLE: Final[Mapping[str, str]] = {
                "oid": "oid",
                "oud": "oud",
                "openldap": "openldap",
                "openldap1": "openldap1",
                "openldap2": "openldap2",
                "active_directory": "active_directory",
                "apache_directory": "apache_directory",
                "generic": "generic",
                "rfc": "rfc",
                "389ds": "ds389",
                "ds389": "ds389",
                "relaxed": "relaxed",
                "novell_edirectory": "novell_edirectory",
                "ibm_tivoli": "ibm_tivoli",
            }

            # Server detection thresholds
            VENDOR_STRING_MAX_TOKENS: Final[int] = 2
            """Maximum number of tokens in a vendor string for Oracle server detection."""

        # ═══════════════════════════════════════════════════════════════════
        # REFERÊNCIAS A FLEXT-CORE (quando necessário reutilizar)
        # ═══════════════════════════════════════════════════════════════════

        class LdapInherited:
            """Explicit references to inherited constants from FlextLdifConstants.

            Use for documenting which constants from FlextLdifConstants are used
            in this domain, without creating aliases.
            """

            # Only references, not aliases
            # Use FlextLdifConstants.Cqrs.Status directly in code


# Convenience alias for common usage pattern - exported for domain usage
c = FlextLdapConstants

__all__ = ["FlextLdapConstants", "c"]
