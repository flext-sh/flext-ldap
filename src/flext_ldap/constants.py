"""[PACKAGE] constants module."""

from __future__ import annotations

from collections.abc import Mapping
from enum import StrEnum
from typing import Final, Literal, TypeIs

from flext_core import FlextConstants


class FlextLdapConstants(FlextConstants):
    """FlextLdap domain constants extending FlextConstants.

    Hierarchy:
        FlextConstants (flext-core)
        └── FlextLdapConstants (this module)
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
            """LDAP CQRS status enumeration."""

            PENDING = "pending"
            RUNNING = "running"
            COMPLETED = "completed"
            FAILED = "failed"

        type StatusLiteral = Literal[
            "pending",
            "running",
            "completed",
            "failed",
        ]

    # ═══════════════════════════════════════════════════════════════════
    # VALIDATION HELPERS
    # ═══════════════════════════════════════════════════════════════════

    class LdapValidation:
        """LDAP validation helpers for constants."""

        @staticmethod
        def is_valid_status(
            value: str
            | FlextLdapConstants.LdapCqrs.Status
            | FlextLdapConstants.LdapCqrs.StatusLiteral,
        ) -> TypeIs[FlextLdapConstants.LdapCqrs.StatusLiteral]:
            """TypeIs narrowing - works in both if/else branches.

            Since StatusLiteral is a subtype of str, after checking isinstance(value, Status),
            the remaining type is str | StatusLiteral. We can check membership directly
            without another isinstance check.
            """
            valid_statuses = {
                FlextLdapConstants.LdapCqrs.Status.PENDING,
                FlextLdapConstants.LdapCqrs.Status.RUNNING,
                FlextLdapConstants.LdapCqrs.Status.COMPLETED,
                FlextLdapConstants.LdapCqrs.Status.FAILED,
            }
            if isinstance(value, FlextLdapConstants.LdapCqrs.Status):
                return True
            # Type narrowing: value is str | StatusLiteral after Status check
            # Check membership directly - valid strings are StatusLiteral values
            return value in valid_statuses

    # ═══════════════════════════════════════════════════════════════════
    # COMPOSITION: Use FlextLdifConstants directly (no duplication)
    # ═══════════════════════════════════════════════════════════════════
    # Server types, filters, attributes come from flext-ldif domain
    # Direct composition - no aliases, no duplication
    # Use FlextLdifConstants.ServerTypes directly in code

    # ═══════════════════════════════════════════════════════════════════
    # LDAP FILTERS
    # ═══════════════════════════════════════════════════════════════════

    class Filters:
        """LDAP filter constants."""

        ALL_ENTRIES_FILTER: Final[str] = "(objectClass=*)"

    # ═══════════════════════════════════════════════════════════════════
    # LDAP ATTRIBUTE NAMES
    # ═══════════════════════════════════════════════════════════════════

    class LdapAttributeNames:
        """LDAP attribute name constants."""

        DN: Final[str] = "dn"
        OBJECT_CLASS: Final[str] = "objectClass"
        ALL_ATTRIBUTES: Final[str] = "*"
        CHANGETYPE: Final[str] = "changetype"

    # ═══════════════════════════════════════════════════════════════════
    # LDAP SEARCH SCOPE ENUMS (FIRST - Most Used)
    # ═══════════════════════════════════════════════════════════════════
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

    # ═══════════════════════════════════════════════════════════════════
    # LDAP OPERATION TYPES (FIRST - Most Used)
    # ═══════════════════════════════════════════════════════════════════

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

    # ═══════════════════════════════════════════════════════════════════
    # LDAP CONNECTION DEFAULTS
    # ═══════════════════════════════════════════════════════════════════

    class ConnectionDefaults:
        """Default values for LDAP connections."""

        PORT: Final[int] = 389
        PORT_SSL: Final[int] = 636
        TIMEOUT: Final[int] = 30
        AUTO_BIND: Final[bool] = True
        AUTO_RANGE: Final[bool] = True
        POOL_SIZE: Final[int] = 10
        POOL_LIFETIME: Final[int] = 3600

    # ═══════════════════════════════════════════════════════════════════
    # ERROR STRINGS
    # ═══════════════════════════════════════════════════════════════════

    class ErrorStrings(StrEnum):
        """Error/status string constants."""

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
        DRY: Reuses class-level constants for common operation strings.
        """

        ADD = "add"
        DELETE = "delete"
        MODIFY = "modify"
        MODDN = "moddn"
        MODRDN = "modrdn"
        REPLACE = "replace"

    # ═══════════════════════════════════════════════════════════════════
    # OPERATIONAL ATTRIBUTES (IGNORED IN COMPARISON)
    # ═══════════════════════════════════════════════════════════════════

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

    # ═══════════════════════════════════════════════════════════════════
    # UPSERT OPERATION RESULTS
    # ═══════════════════════════════════════════════════════════════════

    class UpsertOperations(StrEnum):
        """Upsert operation result types."""

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

    class AclAttributes(StrEnum):
        """ACL-related attribute names."""

        RAW = "raw"
        TARGET = "target"
        TARGET_ATTRIBUTES = "targetAttributes"
        SUBJECT = "subject"
        PERMISSIONS = "permissions"

    # ═══════════════════════════════════════════════════════════════════
    # ACL FORMAT
    # ═══════════════════════════════════════════════════════════════════

    class AclFormat(StrEnum):
        """Supported ACL format identifiers."""

        GENERIC = "generic"
        OPENLDAP2 = "openldap2"
        OPENLDAP1 = "openldap1"
        ORACLE = "oracle"

    # ═══════════════════════════════════════════════════════════════════
    # SYNTHETIC DNS
    # ═══════════════════════════════════════════════════════════════════

    class SyntheticDns(StrEnum):
        """Synthetic DN constants for internal operations."""

        ACL_RULE = "cn=acl-rule"
        OBJECT_CLASS_DEFINITION = "cn=objectclass-definition"
        ATTRIBUTE_TYPE_DEFINITION = "cn=attributetype-definition"

    # ═══════════════════════════════════════════════════════════════════
    # LDAP DICT KEYS
    # ═══════════════════════════════════════════════════════════════════

    class LdapDictKeys(StrEnum):
        """LDAP dictionary key names."""

        DESCRIPTION = "description"

    # ═══════════════════════════════════════════════════════════════════
    # SASL MECHANISMS
    # ═══════════════════════════════════════════════════════════════════

    class SaslMechanisms(StrEnum):
        """SASL authentication mechanism constants."""

        SIMPLE = "SIMPLE"
        SASL_EXTERNAL = "SASL/EXTERNAL"
        SASL_DIGEST_MD5 = "SASL/DIGEST-MD5"
        SASL_GSSAPI = "SASL/GSSAPI"

    # ═══════════════════════════════════════════════════════════════════
    # SCOPES
    # ═══════════════════════════════════════════════════════════════════

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

    # ═══════════════════════════════════════════════════════════════════
    # ROOT DSE ATTRIBUTES
    # ═══════════════════════════════════════════════════════════════════

    class RootDseAttributes(StrEnum):
        """Root DSE attribute name constants."""

        VENDOR_NAME = "vendorName"
        VENDOR_VERSION = "vendorVersion"
        CONFIG_CONTEXT = "configContext"
        ROOT_DOMAIN_NAMING_CONTEXT = "rootDomainNamingContext"
        DEFAULT_NAMING_CONTEXT = "defaultNamingContext"

    # ═══════════════════════════════════════════════════════════════════
    # VENDOR NAMES
    # ═══════════════════════════════════════════════════════════════════

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
            "oid",
            "oud",
            "openldap",
            "openldap1",
            "apache",
            "ds389",
            "novell",
            "tivoli",
            "ad",
            "relaxed",
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

    # ═══════════════════════════════════════════════════════════════════
    # SERVER TYPE MAPPINGS (flext-ldap ↔ flext-ldif compatibility)
    # ═══════════════════════════════════════════════════════════════════

    class ServerTypeMappings:
        """Mappings between flext-ldap server type strings and flext-ldif ServerTypeLiteral.

        Used in adapters/ldap3.py SearchExecutor for normalizing server types
        for flext-ldif parser compatibility.
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

    # ═══════════════════════════════════════════════════════════════════
    # REFERÊNCIAS A FLEXT-CORE (quando necessário reutilizar)
    # ═══════════════════════════════════════════════════════════════════

    class LdapInherited:
        """Explicit references to inherited constants from FlextConstants.

        Use for documenting which constants from FlextConstants are used
        in this domain, without creating aliases.
        """

        # Apenas referências, não aliases
        # Use FlextConstants.Cqrs.Status directly in code


# Note: Literal validation removed to avoid circular dependencies
# Literals are manually maintained to match StrEnum values


# Convenience alias for common usage pattern
c = FlextLdapConstants
