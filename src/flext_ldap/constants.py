"""LDAP domain constants following FLEXT standardization.

Layer 0 pure constants with nested class organization, FlextConstants
inheritance, and Final[Type] declarations for type-safe immutability.

Domain coverage includes LDAP Protocol (RFC 4511), ACL keywords, operation
types, validation patterns, and type definitions.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from enum import StrEnum
from typing import Final, Literal

from flext_core import FlextConstants
from flext_ldif import FlextLdifConstants
from ldap3 import (
    MODIFY_ADD,
    MODIFY_DELETE,
    MODIFY_REPLACE,
)


class FlextLdapConstants(FlextLdifConstants):
    """LDAP domain-specific constants extending FlextLdifConstants directly.

    **Direct Inheritance Pattern:**
    - Inherits all FlextLdifConstants (LDIF patterns, entry types, server configs)
    - Extends with LDAP-specific protocol constants and operations
    - No aliases needed - all LDIF constants available directly

    **Domain Coverage:**
    - LDAP Protocol (RFC 4511 scopes, ports, connection management)
    - LDAP-specific ACL keywords and parsing constants
    - LDAP operation types and validation
    - Type definitions for strict typing

    **Dependency Chain (Simplified):**
    - FlextLdapConstants → FlextLdifConstants → FlextConstants (direct inheritance)
    - All LDIF constants accessible as: FlextLdapConstants.DnPatterns, etc.
    """

    # =========================================================================
    # PROTOCOL CONSTANTS
    # =========================================================================

    class Protocol:
        """LDAP protocol defaults and URI helpers (RFC 4511)."""

        LDAP_SCHEME: Final[str] = "ldap"
        LDAPS_SCHEME: Final[str] = "ldaps"
        LDAP: Final[str] = LDAP_SCHEME
        LDAPS: Final[str] = LDAPS_SCHEME
        DEFAULT_PORT: Final[int] = 389
        DEFAULT_SSL_PORT: Final[int] = 636
        DEFAULT_TIMEOUT_SECONDS: Final[int] = 30
        DEFAULT_SERVER_URI: Final[str] = "ldap://localhost"
        DEFAULT_SSL_SERVER_URI: Final[str] = "ldaps://localhost"
        MAX_DESCRIPTION_LENGTH: Final[int] = 1024
        LDAP_URI: Final[str] = "ldap://"
        LDAPS_URI: Final[str] = "ldaps://"
        URI_PREFIX_LDAP: Final[str] = LDAP_URI
        URI_PREFIX_LDAPS: Final[str] = LDAPS_URI
        URI_PATTERN: Final[str] = r"^ldaps?://"

    class Protocols:
        """Backward-compatible protocol namespace for legacy references."""

        LDAP: Final[str] = "ldap://"
        LDAPS: Final[str] = "ldaps://"

    class ModifyOperation(StrEnum):
        """Canonical LDAP modify operations (RFC 4511)."""

        ADD = str(MODIFY_ADD)
        DELETE = str(MODIFY_DELETE)
        REPLACE = str(MODIFY_REPLACE)
        INCREMENT = "MODIFY_INCREMENT"

        @classmethod
        def is_valid(cls, value: str) -> bool:
            """Return True when the provided value matches a supported operation."""
            try:
                cls(value)
            except ValueError:
                return False
            return True

    class Connection:
        """LDAP connection-specific constants."""

        DEFAULT_TIMEOUT: Final[int] = 30
        DEFAULT_PAGE_SIZE: Final[int] = 100
        DEFAULT_SEARCH_PAGE_SIZE: Final[int] = 100
        MAX_PAGE_SIZE_GENERIC: Final[int] = 1000
        MAX_PAGE_SIZE_AD: Final[int] = 100000

    class Scopes(FlextLdifConstants.Scopes):
        """LDAP search scope constants (RFC 4511) - extends FlextLdifConstants.Scopes.

        Inherits: BASE, ONELEVEL, SUBTREE, CHILDREN from parent class.
        """

        # LDAP3 uppercase constants for library compatibility
        BASE_LDAP3: Final[str] = "BASE"
        LEVEL_LDAP3: Final[str] = "LEVEL"
        SUBTREE_LDAP3: Final[str] = "SUBTREE"

        # Scope mapping: RFC scope strings -> LDAP3 uppercase constants
        SCOPE_TO_LDAP3: Final[dict[str, str]] = {
            FlextLdifConstants.Scopes.BASE: BASE_LDAP3,
            FlextLdifConstants.Scopes.ONELEVEL: LEVEL_LDAP3,
            FlextLdifConstants.Scopes.SUBTREE: SUBTREE_LDAP3,
            "level": LEVEL_LDAP3,  # Alternative name for ONELEVEL
        }

    # =========================================================================
    # SCHEMA ATTRIBUTE NAMES
    # =========================================================================

    class SchemaAttributes:
        """Schema attribute names for LDAP schema operations."""

        ATTRIBUTE_TYPES: Final[str] = "attributeTypes"
        OBJECT_CLASSES: Final[str] = "objectClasses"
        LDAP_SYNTAXES: Final[str] = "ldapSyntaxes"
        MATCHING_RULES: Final[str] = "matchingRules"

    # =========================================================================
    # ACL ATTRIBUTE NAMES
    # =========================================================================

    class AclAttributes(FlextLdifConstants.AclAttributes):
        """ACL-related attribute names - extends FlextLdifConstants.AclAttributes.

        Inherits: ACI, ACLENTRY, ACLRIGHTS, ALL_ACL_ATTRIBUTES,
                  FILTER_ACL_ATTRIBUTES from parent class.
        """

        # Server-specific ACL attribute names
        ORCLACI: Final[str] = "orclaci"  # Oracle Internet Directory
        DS_PRIVILEGE_NAME: Final[str] = "ds-privilege-name"  # Oracle Unified Directory
        OLC_ACCESS: Final[str] = "olcAccess"  # OpenLDAP 2.x
        ACCESS: Final[str] = "access"  # OpenLDAP 1.x
        NT_SECURITY_DESCRIPTOR: Final[str] = "nTSecurityDescriptor"  # Active Directory

        # Common ACL entry attribute names
        RAW: Final[str] = "raw"
        INDEX: Final[str] = "index"  # ACL index (OpenLDAP 2.x)
        TARGET: Final[str] = "target"
        TARGET_TYPE: Final[str] = "targetType"  # Target type (entry/attr)
        TARGET_TYPE_ALT: Final[str] = "target_type"  # Alternative target type key
        TARGET_ATTRIBUTES: Final[str] = "targetAttributes"
        SUBJECT: Final[str] = "subject"
        PERMISSIONS: Final[str] = "permissions"

        # ACL parsing/storage attributes
        FORMAT: Final[str] = "format"  # ACL format identifier
        SERVER_TYPE: Final[str] = "server_type"  # Server type identifier
        SERVER_TYPE_ALT: Final[str] = (
            "serverType"  # Alternate server type identifier (camelCase)
        )
        TO: Final[str] = "to"  # OpenLDAP 1.x/2.x "to" clause
        RULES: Final[str] = "rules"  # ACL rules list
        BY: Final[str] = "by"  # OpenLDAP 1.x/2.x "by" clause
        # ACCESS defined above in server-specific ACL attribute names section

    # =========================================================================
    # ACL SUBJECT TYPES
    # =========================================================================

    class AclSubjectTypes(FlextLdifConstants.AclSubjectTypes):
        """ACL subject type constants - extends FlextLdifConstants.AclSubjectTypes.

        Inherits: USER, GROUP, DN_PREFIX, SELF, ANONYMOUS, AUTHENTICATED,
                  PUBLIC, ROLE, ALL from parent class.

        No additional LDAP-specific subject types at this time.
        """

    # =========================================================================
    # ACL PERMISSION NAMES
    # =========================================================================

    class AclPermissions:
        """ACL permission name constants."""

        READ: Final[str] = "read"
        WRITE: Final[str] = "write"
        ADD: Final[str] = "add"
        DELETE: Final[str] = "delete"
        SEARCH: Final[str] = "search"
        COMPARE: Final[str] = "compare"
        SELFWRITE: Final[str] = "selfwrite"
        PROXY: Final[str] = "proxy"

        # Standard permission list
        ALL_PERMISSIONS: Final[list[str]] = [
            READ,
            WRITE,
            ADD,
            DELETE,
            SEARCH,
            COMPARE,
            SELFWRITE,
            PROXY,
        ]

    # =========================================================================
    # OPERATION NAMES
    # =========================================================================

    class OperationNames:
        """Operation name constants."""

        BIND: Final[str] = "bind"
        UNBIND: Final[str] = "unbind"
        SEARCH: Final[str] = "search"
        ADD: Final[str] = "add"
        MODIFY: Final[str] = "modify"
        DELETE: Final[str] = "delete"
        COMPARE: Final[str] = "compare"
        UPSERT: Final[str] = "upsert"
        SCHEMA: Final[str] = "schema"
        ACL: Final[str] = "acl"

    # =========================================================================
    # CAPABILITY NAMES
    # =========================================================================

    class CapabilityNames:
        """Server capability name constants."""

        SASL: Final[str] = "sasl"

    # =========================================================================
    # DICTIONARY KEY NAMES (API/Response)
    # =========================================================================

    class ApiDictKeys:
        """Dictionary key names used in API responses and info dictionaries."""

        CAPABILITIES: Final[str] = "capabilities"
        SSL: Final[str] = "ssl"
        STARTTLS: Final[str] = "starttls"
        PAGED_RESULTS: Final[str] = "paged_results"
        MAX_PAGE_SIZE: Final[str] = "max_page_size"
        DEFAULT_PORT: Final[str] = "default_port"
        TYPE: Final[str] = "type"
        CONNECTED: Final[str] = "connected"
        QUIRKS_MODE: Final[str] = "quirks_mode"
        ACL_FORMAT: Final[str] = "aclFormat"

    # =========================================================================
    # CONFIG CATEGORY KEYS
    # =========================================================================

    class ConfigCategoryKeys:
        """Configuration category keys for config access."""

        CONNECTION: Final[str] = "connection"
        AUTH: Final[str] = "auth"
        POOL: Final[str] = "pool"
        OPERATION: Final[str] = "operation"
        CACHE: Final[str] = "cache"
        RETRY: Final[str] = "retry"
        LOGGING: Final[str] = "logging"

    # =========================================================================
    # CONFIG PROPERTY KEYS
    # =========================================================================

    class ConfigPropertyKeys:
        """Configuration property keys for config access."""

        SERVER: Final[str] = "server"
        PORT: Final[str] = "port"
        SSL: Final[str] = "ssl"
        TIMEOUT: Final[str] = "timeout"
        URI: Final[str] = "uri"
        BIND_DN: Final[str] = "bind_dn"
        BIND_PASSWORD: Final[str] = "bind_password"
        BASE_DN: Final[str] = "base_dn"
        SIZE: Final[str] = "size"
        ENABLED: Final[str] = "enabled"
        TTL: Final[str] = "ttl"
        ATTEMPTS: Final[str] = "attempts"
        DELAY: Final[str] = "delay"
        LEVEL: Final[str] = "level"
        DEBUG: Final[str] = "debug"
        TRACE: Final[str] = "trace"
        QUERIES: Final[str] = "queries"
        MASK_PASSWORDS: Final[str] = "mask_passwords"
        SIZE_LIMIT: Final[str] = "size_limit"
        TIME_LIMIT: Final[str] = "time_limit"
        HOST: Final[str] = "host"

    # =========================================================================
    # CONFIG PROPERTY MAPPINGS - Centralized field name mappings
    # =========================================================================

    class ConfigPropertyMappings:
        """Property name mappings for configuration categories.

        Maps config property keys to actual field names for dot notation access.
        Used by FlextLdapConfig.__call__ for optimized property resolution.
        """

        # Connection properties mapping
        CONNECTION: Final[dict[str, str]] = {
            "server": "ldap_server_uri",
            "port": "ldap_port",
            "ssl": "ldap_use_ssl",
            "timeout": "ldap_connection_timeout",
            "uri": "_connection_uri",  # Computed dynamically
        }

        # Authentication properties mapping
        AUTH: Final[dict[str, str]] = {
            "bind_dn": "ldap_bind_dn",
            "bind_password": "effective_bind_password",  # Property
            "base_dn": "ldap_base_dn",
        }

        # Pool properties mapping
        POOL: Final[dict[str, str]] = {
            "size": "ldap_pool_size",
            "timeout": "ldap_pool_timeout",
        }

        # Operation properties mapping
        OPERATION: Final[dict[str, str]] = {
            "timeout": "ldap_operation_timeout",
            "size_limit": "ldap_size_limit",
            "time_limit": "ldap_time_limit",
        }

        # Cache properties mapping
        CACHE: Final[dict[str, str]] = {
            "enabled": "enable_caching",
            "ttl": "cache_ttl",
        }

        # Retry properties mapping
        RETRY: Final[dict[str, str]] = {
            "attempts": "max_retry_attempts",
            "delay": "retry_delay",
        }

        # Logging properties mapping
        LOGGING: Final[dict[str, str]] = {
            "debug": "ldap_enable_debug",
            "trace": "ldap_enable_trace",
            "queries": "ldap_log_queries",
            "mask_passwords": "ldap_mask_passwords",
        }

    # =========================================================================
    # ERROR PATTERNS
    # =========================================================================

    class ErrorPatterns:
        """Error message patterns for matching."""

        ENTRY_ALREADY_EXISTS: Final[str] = "entryalreadyexists"
        ALREADY_EXISTS: Final[str] = "already exists"
        CODE_68: Final[str] = "code 68"

    # =========================================================================
    # STATUS KEYS
    # =========================================================================

    class StatusKeys:
        """Status dictionary keys."""

        FAILED: Final[str] = "failed"
        SUCCESS: Final[str] = "success"
        ERROR: Final[str] = "error"
        UPSERTED: Final[str] = "upserted"
        ADDED: Final[str] = "added"
        REPLACED: Final[str] = "replaced"
        UNCHANGED: Final[str] = "unchanged"
        TOTAL: Final[str] = "total"
        ATTRIBUTE_COUNT: Final[str] = "attribute_count"
        USEDS: Final[str] = "useds"

    # =========================================================================
    # DEFAULT VALUES
    # =========================================================================

    class DefaultValues:
        """Default value constants."""

        LOCALHOST: Final[str] = "localhost"
        LDAP_VERSION: Final[str] = "3"
        NORMALIZE_TYPE_STRING: Final[str] = "string"

    # =========================================================================
    # ERROR/STATUS STRINGS
    # =========================================================================

    class ErrorStrings:
        """Error/status string constants."""

        NONE: Final[str] = "NONE"
        UNKNOWN_ERROR: Final[str] = "Unknown error"
        UNKNOWN: Final[str] = "Unknown"
        UNKNOWN_USER: Final[str] = "Unknown User"
        NOT_CONNECTED: Final[str] = "Not connected to LDAP server"

    # =========================================================================
    # PROTOCOL/URI CONSTANTS
    # =========================================================================

    # =========================================================================
    # REGEX PATTERNS
    # =========================================================================

    class RegexPatterns:
        """Regular expression patterns for validation."""

        # LDAP filter pattern - must be enclosed in parentheses
        FILTER_PATTERN: Final[str] = r"^\(.*\)$"

        # LDAP DN RDN part pattern
        RDN_PART: Final[str] = r"[a-zA-Z0-9][a-zA-Z0-9\-_]*=[^,]+"

        # Full DN pattern (composite of RDN parts)
        DN_PATTERN: Final[str] = rf"^{RDN_PART}(?:,{RDN_PART})*$"

        # Server URI pattern
        SERVER_URI_PATTERN: Final[str] = r"^ldaps?://"

        # Username sanitization pattern (alphanumeric, underscore, hyphen)
        USERNAME_SANITIZE_PATTERN: Final[str] = r"[^a-zA-Z0-9_-]"

    # =========================================================================
    # DEFAULT VALUES (First definition - consolidated into parent Defaults later)
    # =========================================================================
    # VALIDATION SETS
    # =========================================================================

    class ValidationSets:
        """Sets of valid values for validation."""

        VALID_SCOPES: Final[frozenset[str]] = frozenset({"base", "onelevel", "subtree"})
        VALID_MODIFY_OPERATIONS: Final[frozenset[str]] = frozenset({
            "add",
            "delete",
            "replace",
        })
        REQUIRED_CONNECTION_FIELDS: Final[list[str]] = [
            "server",
            "port",
            "bind_dn",
            "bind_password",
        ]

    # =========================================================================
    # LDAP ATTRIBUTE NAMES - High frequency usage (63 references)
    # =========================================================================

    class LdapAttributeNames:
        """LDAP attribute names with convenience attribute lists."""

        DN: Final[str] = "dn"
        OBJECT_CLASS: Final[str] = "objectClass"
        CN: Final[str] = "cn"
        SN: Final[str] = "sn"
        GIVEN_NAME: Final[str] = "givenName"
        DISPLAY_NAME: Final[str] = "displayName"
        UID: Final[str] = "uid"
        MAIL: Final[str] = "mail"
        USER_PASSWORD: Final[str] = "userPassword"
        COMMON_NAME: Final[str] = "cn"
        SURNAME: Final[str] = "sn"
        USER_ID: Final[str] = "uid"
        MEMBER: Final[str] = "member"
        UNIQUE_MEMBER: Final[str] = "uniqueMember"
        MEMBER_OF: Final[str] = "memberOf"
        OWNER: Final[str] = "owner"
        GID_NUMBER: Final[str] = "gidNumber"
        TELEPHONE_NUMBER: Final[str] = "telephoneNumber"
        MOBILE: Final[str] = "mobile"
        DEPARTMENT: Final[str] = "department"
        TITLE: Final[str] = "title"
        OU: Final[str] = "ou"
        DESCRIPTION: Final[str] = "description"
        EMPLOYEE_NUMBER: Final[str] = "employeeNumber"
        EMPLOYEE_TYPE: Final[str] = "employeeType"

        MINIMAL_USER_ATTRS: Final[list[str]] = ["uid", "cn", "mail"]
        MINIMAL_GROUP_ATTRS: Final[list[str]] = ["cn", "member"]
        ALL_USER_ATTRS: Final[list[str]] = [
            "objectClass",
            "cn",
            "sn",
            "givenName",
            "displayName",
            "uid",
            "mail",
            "userPassword",
            "description",
            "memberOf",
        ]
        ALL_GROUP_ATTRS: Final[list[str]] = [
            "objectClass",
            "cn",
            "description",
            "member",
            "uniqueMember",
            "owner",
            "memberOf",
        ]

    # =========================================================================
    # SKIP ATTRIBUTES - Attributes to skip during UPSERT operations
    # =========================================================================

    class SkipAttributes:
        """Attributes that should be skipped during UPSERT operations.

        These attributes should never be modified:
        - Operational attributes (managed by server)
        - RDN attributes (cannot be modified via MODIFY)
        - Structural attributes (objectClass cannot be modified)
        """

        DEFAULT_SKIP_ATTRIBUTES: Final[set[str]] = {
            # Operational attributes
            "createtimestamp",
            "modifytimestamp",
            "creatorsname",
            "modifiersname",
            "entryuuid",
            "entrycsn",
            "structuralobjectclass",
            "hassubordinates",
            "subschemasubentry",
            # Common RDN attributes (check these, they're often RDNs)
            "cn",
            "uid",
            "ou",
            # Structural attributes (cannot be modified)
            "objectclass",
        }

    # =========================================================================
    # SEARCH FILTERS - Consolidated from Filters class
    # =========================================================================

    class Filters:
        """Default LDAP search filters."""

        DEFAULT_USER_FILTER: Final[str] = "(objectClass=inetOrgPerson)"
        ALL_USERS_FILTER: Final[str] = "(objectClass=person)"
        # userAccountControl:1.2.840.113556.1.4.803:=2 → disabled
        _IOP = "(objectClass=inetOrgPerson)"
        _COND = "(!(userAccountControl:1.2.840.113556.1.4.803:=2))"
        ACTIVE_USERS_FILTER: Final[str] = f"(&{_IOP}{_COND})"
        DEFAULT_GROUP_FILTER: Final[str] = "(objectClass=groupOfNames)"
        _GOU_FILTER = "(objectClass=groupOfUniqueNames)"
        ALL_GROUPS_FILTER: Final[str] = f"(|(objectClass=groupOfNames){_GOU_FILTER})"
        ALL_ENTRIES_FILTER: Final[str] = "(objectClass=*)"
        ORGANIZATIONAL_UNITS_FILTER: Final[str] = "(objectClass=organizationalUnit)"

    # =========================================================================
    # OBJECT CLASS NAMES - Extends FlextLdifConstants.ObjectClasses
    # =========================================================================

    class ObjectClasses(FlextLdifConstants.ObjectClasses):
        """LDAP-specific object class name constants extending FlextLdifConstants.

        Inherits all standard RFC 4512 object classes from FlextLdifConstants.ObjectClasses
        and adds LDAP protocol-specific extensions commonly used in LDAP operations.
        """

        # LDAP-specific object classes (server-specific extensions available here)
        # All RFC 4512 standard classes are inherited from FlextLdifConstants.ObjectClasses
        # Additional LDAP protocol-specific classes can be added here if needed

    # =========================================================================
    # BOOLEAN STRING CONSTANTS
    # =========================================================================

    class BooleanStrings:
        """Boolean value string constants."""

        TRUE: Final[str] = "true"
        FALSE: Final[str] = "false"
        YES: Final[str] = "yes"
        NO: Final[str] = "no"
        ONE: Final[str] = "1"  # Alternative true value

    # =========================================================================
    # OUD PRIVILEGE NAMES
    # =========================================================================

    class OudPrivileges:
        """Oracle OUD privilege name constants."""

        CONFIG_READ: Final[str] = "config-read"
        CONFIG_WRITE: Final[str] = "config-write"
        PASSWORD_RESET: Final[str] = "password-reset"
        PASSWORD_MODIFY: Final[str] = "password-modify"
        PROXIED_AUTH: Final[str] = "proxied-auth"
        BYPASS_ACL: Final[str] = "bypass-acl"
        PRIVILEGE_CHANGE: Final[str] = "privilege-change"
        UPDATE_SCHEMA: Final[str] = "update-schema"
        LDIF_IMPORT: Final[str] = "ldif-import"
        LDIF_EXPORT: Final[str] = "ldif-export"
        BACKEND_BACKUP: Final[str] = "backend-backup"
        BACKEND_RESTORE: Final[str] = "backend-restore"

        # Privilege sets by category
        CONFIG_PRIVILEGES: Final[frozenset[str]] = frozenset({
            CONFIG_READ,
            CONFIG_WRITE,
        })
        PASSWORD_PRIVILEGES: Final[frozenset[str]] = frozenset({
            PASSWORD_RESET,
            PASSWORD_MODIFY,
        })
        ADMINISTRATIVE_PRIVILEGES: Final[frozenset[str]] = frozenset({
            PROXIED_AUTH,
            BYPASS_ACL,
        })
        MANAGEMENT_PRIVILEGES: Final[frozenset[str]] = frozenset({
            PRIVILEGE_CHANGE,
            UPDATE_SCHEMA,
        })
        DATA_MANAGEMENT_PRIVILEGES: Final[frozenset[str]] = frozenset({
            LDIF_IMPORT,
            LDIF_EXPORT,
        })
        MAINTENANCE_PRIVILEGES: Final[frozenset[str]] = frozenset({
            BACKEND_BACKUP,
            BACKEND_RESTORE,
        })

    # =========================================================================
    # OUD PRIVILEGE CATEGORIES
    # =========================================================================

    class OudPrivilegeCategories:
        """Oracle OUD privilege category constants."""

        CONFIGURATION: Final[str] = "configuration"
        PASSWORD: Final[str] = "password"
        ADMINISTRATIVE: Final[str] = "REDACTED_LDAP_BIND_PASSWORDistrative"
        MANAGEMENT: Final[str] = "management"
        DATA_MANAGEMENT: Final[str] = "data-management"
        MAINTENANCE: Final[str] = "maintenance"
        CUSTOM: Final[str] = "custom"

    # =========================================================================
    # VALIDATION CONSTANTS
    # =========================================================================

    class Validation(FlextConstants.Validation):
        """LDAP-specific validation constants."""

        MIN_DN_PARTS: Final[int] = 2
        MIN_DN_LENGTH: Final[int] = 3
        MAX_DN_LENGTH: Final[int] = 2048
        # DN RDN format: attr=value(,attr=value)*
        # Note: Full patterns moved to RegexPatterns class
        MIN_FILTER_LENGTH: Final[int] = 1
        MAX_FILTER_LENGTH: Final[int] = 8192
        # Filter pattern moved to RegexPatterns.FILTER_PATTERN
        MIN_PASSWORD_LENGTH: Final[int] = 8
        MAX_PASSWORD_LENGTH: Final[int] = 128
        MIN_CONNECTION_ARGS: Final[int] = 3

    # =========================================================================
    # ERROR & VALIDATION MESSAGES
    # =========================================================================

    class Messages(FlextConstants.Messages):
        """LDAP-specific error and validation messages."""

        HOST_CANNOT_BE_EMPTY: Final[str] = "Host cannot be empty"
        CONNECTION_FAILED: Final[str] = "Connection failed"
        FIELD_CANNOT_BE_EMPTY: Final[str] = "{0} cannot be empty"
        INVALID_DN_FORMAT: Final[str] = "Invalid DN format"
        INVALID_SEARCH_FILTER: Final[str] = "Invalid LDAP search filter"
        CONNECTION_FAILED_WITH_CONTEXT: Final[str] = "Connection failed: {0}"
        EMAIL_VALIDATION_FAILED: Final[str] = "Invalid email format: {error}"
        DN_CANNOT_BE_EMPTY: Final[str] = "DN cannot be empty"
        CLIENT_NOT_INITIALIZED: Final[str] = "Client not initialized"
        NO_SERVER_OPERATIONS_AVAILABLE: Final[str] = "No server operations available"

    # =========================================================================
    # ERROR CODES
    # =========================================================================

    class Errors(FlextConstants.Errors):
        """LDAP-specific error codes."""

        LDAP_BIND_ERROR: Final[str] = "LDAP_BIND_ERROR"
        LDAP_SEARCH_ERROR: Final[str] = "LDAP_SEARCH_ERROR"
        LDAP_ADD_ERROR: Final[str] = "LDAP_ADD_ERROR"
        LDAP_MODIFY_ERROR: Final[str] = "LDAP_MODIFY_ERROR"
        LDAP_DELETE_ERROR: Final[str] = "LDAP_DELETE_ERROR"
        LDAP_INVALID_DN: Final[str] = "LDAP_INVALID_DN"
        LDAP_INVALID_FILTER: Final[str] = "LDAP_INVALID_FILTER"

    # =========================================================================
    # DEFAULT VALUES - High frequency usage (31 references)
    # =========================================================================

    class Defaults(FlextConstants.Defaults):
        """LDAP-specific default values."""

        SERVER_TYPE: Final[str] = "generic"
        OBJECT_CLASS_TOP: Final[str] = "top"
        DEFAULT_TIMEOUT: Final[int] = 30
        DEFAULT_PORT: Final[int] = 389
        DEFAULT_PORT_SSL: Final[int] = 636
        DEFAULT_PAGE_SIZE: Final[int] = 1000
        SCHEMA_SUBENTRY: Final[str] = "cn=subschema"  # RFC 4512 standard schema DN
        DEFAULT_SEARCH_FILTER: Final[str] = "(objectClass=*)"  # ALL_ENTRIES_FILTER
        DEFAULT_SEARCH_BASE: Final[str] = ""
        DEFAULT_SERVICE_NAME: Final[str] = "flext-ldap"
        DEFAULT_SERVICE_VERSION: Final[str] = "1.0.0"
        # Import max validation size from core performance constants
        _MAX_VAL_SZ = FlextConstants.Performance.BatchProcessing.MAX_VALIDATION_SIZE
        MAX_SEARCH_ENTRIES: Final[int] = _MAX_VAL_SZ
        VALID_LDAP_USER_NAME: Final[str] = "testuser"
        VALID_LDAP_USER_DESCRIPTION: Final[str] = "Test LDAP User"
        DEFAULT_DEPARTMENT: Final[str] = "IT"
        DEFAULT_ORGANIZATION: Final[str] = "Company"
        DEFAULT_TITLE: Final[str] = "Employee"
        DEFAULT_STATUS: Final[str] = "active"
        ERROR_SUMMARY_MAX_ITEMS: Final[int] = 3
        MIN_USERNAME_LENGTH: Final[int] = 3
        MIN_GROUP_NAME_LENGTH: Final[int] = 3
        MAX_GROUP_DESCRIPTION_LENGTH: Final[int] = 500
        MAX_DESCRIPTION_LENGTH: Final[int] = 500
        MIN_CONNECTION_ARGS: Final[int] = 3

    # =========================================================================
    # SERVER TYPES - Server identification constants
    # =========================================================================

    class ServerTypes(FlextLdifConstants.ServerTypes):
        """LDAP server type identifiers extending FlextLdifConstants.

        Inherits: GENERIC, OPENLDAP, OPENLDAP1, OPENLDAP2, OID, OUD, AD,
                  DS_389 (DS389), APACHE, IBM_TIVOLI, NOVELL, RELAXED, RFC
                  from parent class.

        Also inherits utility methods: matches(), normalize(), and variant lists.

        LDAP-specific additions:
        - AD_SHORT: Short form "ad" for Active Directory (parent uses "active_directory")
        """

        # LDAP-specific short form for Active Directory
        # Parent class uses AD = "active_directory", but LDAP operations use "ad"
        AD_SHORT: Final[str] = "ad"

    # =========================================================================
    # RETRY & TIMING CONSTANTS
    # =========================================================================

    class LdapRetry:
        """LDAP retry and timing constants."""

        SERVER_READY_RETRY_DELAY: Final[int] = 2
        SERVER_READY_MAX_RETRIES: Final[int] = 10
        SERVER_READY_TIMEOUT: Final[int] = 30
        CONNECTION_RETRY_DELAY: Final[float] = 1.0
        CONNECTION_MAX_RETRIES: Final[int] = 3

    # =========================================================================
    # ACL SUPPORT - Consolidated from multiple keyword classes
    # =========================================================================

    class AclFormat:
        """Supported ACL format identifiers."""

        GENERIC: Final[str] = "generic"  # Generic/fallback ACL format
        OPENLDAP: Final[str] = "openldap"
        OPENLDAP1: Final[str] = "openldap1"
        OPENLDAP2: Final[str] = "openldap2"
        ORACLE: Final[str] = "oracle"
        ACI: Final[str] = "aci"
        ACTIVE_DIRECTORY: Final[str] = "active_directory"
        SDDL: Final[str] = "sddl"  # Security Descriptor Definition Language for AD
        UNIFIED: Final[str] = "unified"
        AUTO: Final[str] = "auto"

    # =========================================================================
    # LDAP DICT KEYS - High frequency usage (62 references)
    # =========================================================================

    class LdapDictKeys(FlextLdifConstants.DictKeys):
        """Extend FlextLdifConstants.DictKeys with LDAP-specific keys."""

        # LDAP-specific operational keys
        ACL_DATA: Final[str] = "acl_data"
        ACL_ATTRIBUTE: Final[str] = "acl_attribute"
        ACL_FORMAT: Final[str] = "acl_format"
        SCHEMA_SUBENTRY: Final[str] = "schema_subentry"
        SUPPORTS_OPERATIONAL_ATTRS: Final[str] = "supports_operational_attrs"
        DESCRIPTION: Final[str] = "description"

        # Connection and server keys
        GENERIC: Final[str] = "generic"
        LDAP_SERVER: Final[str] = "ldap_server"
        LDAP_PORT: Final[str] = "ldap_port"
        BIND_DN: Final[str] = "bind_dn"
        BIND_PASSWORD: Final[str] = "bind_password"
        LDAP_BIND_PASSWORD: Final[str] = "ldap_bind_password"
        SERVER_URI: Final[str] = "server_uri"
        DEFAULT_TIMEOUT: Final[str] = "default_timeout"
        MAX_PAGE_SIZE: Final[str] = "max_page_size"
        DEFAULT_PORT: Final[str] = "defaultPort"
        SUPPORTS_START_TLS: Final[str] = "supportsStartTls"
        PORT: Final[str] = "port"
        BASE_DN: Final[str] = "base_dn"
        SERVER: Final[str] = "server"

        # Operation keys
        OPERATION: Final[str] = "operation"
        OPERATION_TYPE: Final[str] = "operation_type"
        TARGET_TYPE: Final[str] = "target_type"

        # ACL and privilege keys
        ACL_STRING: Final[str] = "acl_string"
        WHO: Final[str] = "who"
        PRIVILEGE: Final[str] = "privilege"
        CATEGORY: Final[str] = "category"

        # Entry attribute keys
        ATTRIBUTE: Final[str] = "attribute"
        VALUES: Final[str] = "values"
        ORGANIZATION: Final[str] = "organization"
        TITLE: Final[str] = "title"
        DEPARTMENT: Final[str] = "department"
        MOBILE: Final[str] = "mobile"
        GIVEN_NAME: Final[str] = "given_name"
        USER_PASSWORD: Final[str] = "user_password"

    # =========================================================================
    # OBJECT CLASS KIND CONSTANTS
    # =========================================================================

    class ObjectClassKindConstants:
        """Object class kind constants for schema operations."""

        STRUCTURAL: Final[str] = "STRUCTURAL"
        AUXILIARY: Final[str] = "AUXILIARY"
        ABSTRACT: Final[str] = "ABSTRACT"

    # =========================================================================
    # SASL AUTHENTICATION MECHANISMS
    # =========================================================================

    class SaslMechanisms:
        """SASL authentication mechanism constants."""

        SIMPLE: Final[str] = "SIMPLE"
        EXTERNAL: Final[str] = "EXTERNAL"
        NTLM: Final[str] = "NTLM"
        GSSAPI: Final[str] = "GSSAPI"
        DIGEST_MD5: Final[str] = "DIGEST-MD5"
        SASL_EXTERNAL: Final[str] = "SASL/EXTERNAL"
        SASL_DIGEST_MD5: Final[str] = "SASL/DIGEST-MD5"
        SASL_GSSAPI: Final[str] = "SASL/GSSAPI"
        SASL_PLAIN: Final[str] = "SASL/PLAIN"

        # Standard mechanism lists by server type
        DEFAULT_MECHANISMS: Final[list[str]] = [SIMPLE]
        GENERIC_MECHANISMS: Final[list[str]] = [SIMPLE, SASL_EXTERNAL]

    # =========================================================================
    # ROOT DSE ATTRIBUTE NAMES
    # =========================================================================

    class RootDseAttributes:
        """Root DSE attribute name constants."""

        VENDOR_NAME: Final[str] = "vendorName"
        VENDOR_VERSION: Final[str] = "vendorVersion"
        CONFIG_CONTEXT: Final[str] = "configContext"
        SUPPORTED_LDAP_VERSION: Final[str] = "supportedLDAPVersion"
        NAMING_CONTEXTS: Final[str] = "namingContexts"
        SUPPORTED_SASL_MECHANISMS: Final[str] = "supportedSASLMechanisms"
        FOREST_FUNCTIONALITY: Final[str] = "forestFunctionality"
        DOMAIN_FUNCTIONALITY: Final[str] = "domainFunctionality"
        ROOT_DOMAIN_NAMING_CONTEXT: Final[str] = (
            "rootDomainNamingContext"  # Active Directory
        )
        DEFAULT_NAMING_CONTEXT: Final[str] = "defaultNamingContext"  # Active Directory
        VENDOR_NAME_LOWER: Final[str] = "vendorname"  # Lowercase variant (OID/OUD)

    # =========================================================================
    # ACL SYNTAX KEYWORDS
    # =========================================================================

    class AclSyntaxKeywords:
        """ACL syntax keyword constants for parsing and formatting."""

        ACCESS_TO: Final[str] = "access to"
        ATTR_PREFIX: Final[str] = "attr:"
        ENTRY: Final[str] = "entry"
        BY: Final[str] = "by"
        TARGET_TYPE_ENTRY: Final[str] = "entry"
        TARGET_TYPE_ATTR: Final[str] = "attr"

    # =========================================================================
    # SCHEMA DN VALUES
    # =========================================================================

    class SchemaDns:
        """Schema distinguished name constants for different server types."""

        SUBS_SCHEMA: Final[str] = "cn=subschema"  # RFC 4512 standard
        SUBS_SCHEMA_SUBENTRY: Final[str] = "cn=subschemasubentry"  # Oracle variant
        SCHEMA: Final[str] = "cn=schema"  # OpenLDAP 2.x / OUD
        SCHEMA_CONFIG: Final[str] = "cn=schema,cn=config"  # OpenLDAP with config
        CONFIG: Final[str] = "cn=config"  # OpenLDAP 2.x config
        AD_SCHEMA: Final[str] = "CN=Schema,CN=Configuration"  # Active Directory

    # =========================================================================
    # TEMPORARY/SYNTHETIC DN VALUES
    # =========================================================================

    class SyntheticDns:
        """Temporary DN values for synthetic entries (ACL rules, server info, etc.)."""

        ACL_RULE: Final[str] = "cn=AclRule"
        ACL_INFO: Final[str] = "cn=AclInfo"
        SERVER_INFO: Final[str] = "cn=ServerInfo"
        SUBS_SCHEMA_ALT: Final[str] = "cn=Subschema"  # Alternative casing variant

    # =========================================================================
    # USER STATUS VALUES
    # =========================================================================

    class UserStatus:
        """User account status constants."""

        ACTIVE: Final[str] = "active"
        LOCKED: Final[str] = "locked"
        DISABLED: Final[str] = "disabled"
        UNLOCKED: Final[str] = "unlocked"

    # =========================================================================
    # ACTIVE DIRECTORY ATTRIBUTES & FLAGS
    # =========================================================================

    class ActiveDirectoryAttributes:
        """Active Directory specific attribute names."""

        USER_ACCOUNT_CONTROL: Final[str] = "userAccountControl"
        ACCOUNT_EXPIRES: Final[str] = "accountExpires"
        PWD_LAST_SET: Final[str] = "pwdLastSet"

    class ActiveDirectoryFlags:
        """Active Directory user account control flags."""

        ADS_UF_ACCOUNTDISABLE: Final[int] = 0x2  # Account is disabled
        ADS_UF_LOCKOUT: Final[int] = 0x10  # Account is locked out
        ADS_UF_PASSWORD_EXPIRED: Final[int] = 0x800000  # Password is expired
        ADS_UF_DONT_EXPIRE_PASSWORD: Final[int] = 0x10000  # Password never expires

    # =========================================================================
    # OID/OUD LOCK ATTRIBUTES
    # =========================================================================

    class LockAttributes:
        """LDAP lock-related attribute names by server type."""

        NS_ACCOUNT_LOCK: Final[str] = "nsAccountLock"  # OID/OUD
        USER_ACCOUNT_CONTROL: Final[str] = "userAccountControl"  # Active Directory
        DS_PWP_ACCOUNT_DISABLED: Final[str] = "ds-pwp-account-disabled"  # OUD

        # Lock attribute lists by server type
        OID_OUD_LOCK_ATTRIBUTES: Final[list[str]] = [
            NS_ACCOUNT_LOCK,
            DS_PWP_ACCOUNT_DISABLED,
        ]
        AD_LOCK_ATTRIBUTES: Final[list[str]] = [USER_ACCOUNT_CONTROL]
        ALL_LOCK_ATTRIBUTES: Final[list[str]] = [
            NS_ACCOUNT_LOCK,
            USER_ACCOUNT_CONTROL,
            DS_PWP_ACCOUNT_DISABLED,
        ]

    # =========================================================================
    # VENDOR IDENTIFIERS
    # =========================================================================

    class VendorNames:
        """Vendor name identifiers for server detection."""

        MICROSOFT: Final[str] = "microsoft"
        WINDOWS: Final[str] = "windows"
        ORACLE: Final[str] = "oracle"
        OPENLDAP: Final[str] = "openldap"
        NOVELL: Final[str] = "novell"
        EDIR: Final[str] = "edir"  # Novell eDirectory
        IBM: Final[str] = "ibm"
        UNBOUNDID: Final[str] = "unboundid"
        FORGEROCK: Final[str] = "forgerock"

    # =========================================================================
    # VERSION PREFIXES
    # =========================================================================

    class VersionPrefixes:
        """Version string prefixes for server detection."""

        VERSION_1_PREFIX: Final[str] = "1."
        VERSION_2_PREFIX: Final[str] = "2."

    # =========================================================================
    # TYPE DEFINITIONS (moved from module level)
    # =========================================================================

    class Types:
        """Type aliases for LDAP domain (moved from module level for Layer 0 compliance)."""

        SearchScope = Literal["base", "onelevel", "subtree", "children"]
        # LDAP3 uppercase scope literals matching Scopes constants
        Ldap3Scope = Literal["BASE", "LEVEL", "SUBTREE"]
        ModifyOperation = Literal["add", "delete", "replace"]
        UpdateStrategy = Literal["merge", "replace"]
        AclType = Literal["openldap", "oracle", "aci", "active_directory", "auto"]
        ObjectClassKind = Literal["STRUCTURAL", "AUXILIARY", "ABSTRACT"]
        ConnectionState = Literal["unbound", "bound", "closed", "error"]
        OperationType = Literal[
            "search",
            "add",
            "modify",
            "delete",
            "compare",
            "extended",
        ]
        SecurityLevel = Literal["none", "simple", "sasl"]
        AuthenticationMethod = Literal["simple", "sasl", "external"]
        ConnectionMode = Literal["sync", "async"]
        IpMode = Literal[
            "IP_SYSTEM_DEFAULT",
            "IP_V4_ONLY",
            "IP_V4_PREFERRED",
            "IP_V6_ONLY",
            "IP_V6_PREFERRED",
        ]
        ConnectionInfo = Literal["ALL", "DSA", "NO_INFO", "SCHEMA"]
        # API operation types
        ApiOperation = Literal["add", "modify", "delete"]
        ValidationMode = Literal["schema", "business", "all"]
        DataFormat = Literal["ldif", "json", "csv"]
        ExchangeDirection = Literal["import", "export"]
        InfoDetailLevel = Literal["basic", "full", "diagnostic"]

        # LDAP Connection and Configuration Enums
        class GetInfoType(StrEnum):
            """LDAP get_info parameter values for connection establishment."""

            NO_INFO = "NO_INFO"
            DSA = "DSA"
            SCHEMA = "SCHEMA"
            ALL = "ALL"

        # LDAP3 get_info constants for library compatibility (Literal types for type safety)
        ALL_LDAP3: Literal["ALL"] = "ALL"
        DSA_LDAP3: Literal["DSA"] = "DSA"
        NO_INFO_LDAP3: Literal["NO_INFO"] = "NO_INFO"
        SCHEMA_LDAP3: Literal["SCHEMA"] = "SCHEMA"

        # GetInfo mapping: GetInfoType enum -> LDAP3 Literal constants
        GET_INFO_TO_LDAP3: Final[
            dict[GetInfoType, Literal["ALL", "DSA", "NO_INFO", "SCHEMA"]]
        ] = {
            GetInfoType.ALL: ALL_LDAP3,
            GetInfoType.DSA: DSA_LDAP3,
            GetInfoType.NO_INFO: NO_INFO_LDAP3,
            GetInfoType.SCHEMA: SCHEMA_LDAP3,
        }

        class ModeType(StrEnum):
            """LDAP IP mode values for connection configuration."""

            IP_SYSTEM_DEFAULT = "IP_SYSTEM_DEFAULT"
            IP_V4_ONLY = "IP_V4_ONLY"
            IP_V6_ONLY = "IP_V6_ONLY"
            IP_V4_PREFERRED = "IP_V4_PREFERRED"
            IP_V6_PREFERRED = "IP_V6_PREFERRED"

        class QuirksMode(StrEnum):
            """LDAP quirks mode values for server compatibility handling."""

            AUTOMATIC = "automatic"
            SERVER = "server"
            RFC = "rfc"
            RELAXED = "relaxed"

    # =========================================================================
    # VALIDATION MODE VALUES
    # =========================================================================

    class ValidationModeValues:
        """Validation mode string constants."""

        SCHEMA: Final[str] = "schema"
        BUSINESS: Final[str] = "business"
        ALL: Final[str] = "all"

    # =========================================================================
    # INFO DETAIL LEVEL VALUES
    # =========================================================================

    class InfoDetailLevelValues:
        """Info detail level string constants."""

        BASIC: Final[str] = "basic"
        FULL: Final[str] = "full"
        DIAGNOSTIC: Final[str] = "diagnostic"

    # =========================================================================
    # DATA FORMAT VALUES
    # =========================================================================

    class DataFormatValues:
        """Data format string constants."""

        LDIF: Final[str] = "ldif"
        JSON: Final[str] = "json"
        CSV: Final[str] = "csv"

    # =========================================================================
    # EXCHANGE DIRECTION VALUES
    # =========================================================================

    class ExchangeDirectionValues:
        """Exchange direction string constants."""

        IMPORT: Final[str] = "import"
        EXPORT: Final[str] = "export"

    # =========================================================================
    # UPDATE STRATEGY VALUES
    # =========================================================================

    class UpdateStrategyValues:
        """Update strategy string constants."""

        MERGE: Final[str] = "merge"
        REPLACE: Final[str] = "replace"

    # =========================================================================
    # SERVER TYPE ALIASES
    # =========================================================================

    class ServerTypeAliases:
        """Server type alias strings for factory and compatibility."""

        ORACLE_OID: Final[str] = "oracle_oid"
        ORACLE_OUD: Final[str] = "oracle_oud"
        ACTIVE_DIRECTORY: Final[str] = "active_directory"
        IBM_TIVOLI: Final[str] = "ibm-tivoli"
        ORACLE_OID_LEGACY: Final[str] = "oracle-oid"
        ACTIVE_DIRECTORY_LEGACY: Final[str] = "active-directory"

    # =========================================================================
    # SCHEMA DEFINITION TYPE VALUES
    # =========================================================================

    class SchemaDefinitionTypes:
        """Schema definition type constants."""

        ATTRIBUTE_TYPE: Final[str] = "attributeType"
        OBJECT_CLASS: Final[str] = "objectClass"
        LDAP_SYNTAX: Final[str] = "ldapSyntax"
        MATCHING_RULE: Final[str] = "matchingRule"

    class AclTypes:
        """ACL type constants - permission types, subject types, etc."""

        Permissions = Literal[
            "read",
            "write",
            "add",
            "delete",
            "search",
            "compare",
            "browse",
            "proxy",
            "auth",
            "all",
            "none",
        ]
        SubjectType = Literal[
            "user",
            "group",
            "dn",
            "self",
            "anonymous",
            "authenticated",
            "anyone",
        ]
        TargetType = Literal["dn", "attributes", "entry", "filter"]
        AclFormat = Literal[
            "openldap",
            "oracle",
            "aci",
            "active_directory",
            "unified",
            "auto",
        ]

    # =========================================================================
    # ACL PARSING CONSTANTS
    # =========================================================================

    class AclParsing:
        """ACL parsing constants."""

        MIN_ACL_PARTS: Final[int] = 4
        ACL_RULE_PARTS: Final[int] = 2
        OPENLDAP_PREFIX_LENGTH: Final[int] = 3
        MIN_OC_LENGTH: Final[int] = 3
        MODIFY_OPERATION_TUPLE_LENGTH: Final[int] = 2

        # ACL conversion warning messages
        ACL_PERMISSION_NOT_SUPPORTED: Final[str] = "Perm '{permission}' not in {format}"
        ACL_FEATURE_LOSS: Final[str] = "Feature '{feature}' lost in {format}"
        ACL_SYNTAX_MISMATCH: Final[str] = "Syntax not translatable"

    # =========================================================================
    # ERROR MESSAGE CONSTANTS
    # =========================================================================

    class ErrorMessages:
        """Error message constants for consistent error handling."""

        # Connection errors
        LDAP_CONNECTION_NOT_ESTABLISHED: Final[str] = "LDAP connection not established"
        SERVER_CONNECTION_NOT_ESTABLISHED: Final[str] = (
            "No server connection established"
        )
        CONNECTION_NOT_BOUND: Final[str] = "Connection not bound"
        NOT_CONNECTED_TO_SERVER: Final[str] = "Not connected to LDAP server"

        # Entry validation errors
        ENTRY_DN_EMPTY: Final[str] = "Entry DN cannot be empty"
        ENTRY_ATTRIBUTES_EMPTY: Final[str] = "Entry attributes cannot be empty"
        ENTRY_MUST_HAVE_OBJECTCLASSES: Final[str] = "Entry must have object classes"
        ENTRY_MUST_HAVE_VALID_DN: Final[str] = "Entry must have a valid DN"
        ENTRY_MUST_HAVE_ATTRIBUTES: Final[str] = "Entry must have attributes"

        # Operation errors
        NO_ATTRIBUTES_PROVIDED: Final[str] = "No attributes provided for update"
        NO_ROOT_DSE_FOUND: Final[str] = "No Root DSE found"

    # =========================================================================
    # VERSION CONSTANTS
    # =========================================================================

    class Version:
        """Version constants for flext-ldap."""

        CURRENT_VERSION: Final[str] = "0.9.0"
        VERSION_INFO: Final[tuple[int | str, ...]] = (0, 9, 0)


__all__ = [
    "FlextLdapConstants",
]
