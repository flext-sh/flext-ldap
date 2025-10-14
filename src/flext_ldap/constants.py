"""LDAP Constants - Essential constants only, using FlextCore.Constants.LDAP exclusively.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import Final, Literal

from flext_core import FlextCore


class FlextLdapConstants(FlextCore.Constants):
    """LDAP domain-specific constants - essential constants only.

    Extends FlextCore.Constants from flext-core. Use parent constants directly:
    - Network constants → FlextCore.Constants.Network.*
    - Platform constants → FlextCore.Constants.Platform.*
    - Performance constants → FlextCore.Constants.Performance.*
    - Errors → FlextCore.Constants.Errors.*
    """

    # Direct access constants for backward compatibility
    DEFAULT_TIMEOUT: Final[int] = 30
    DEFAULT_PAGE_SIZE: Final[int] = 100

    # LDAP port constants for compatibility
    LDAP_DEFAULT_PORT: Final[int] = 389
    LDAPS_DEFAULT_PORT: Final[int] = 636

    # =========================================================================
    # LDAP-SPECIFIC CONSTANTS ONLY - Essential domain constants
    # =========================================================================

    class Protocol:
        """LDAP protocol-specific constants.

        Standard LDAP protocol constants. These are LDAP-specific and not
        available in flext-core Platform constants.
        """

        # LDAP protocols (domain-specific string values)
        LDAP: Final[str] = "ldap"
        LDAPS: Final[str] = "ldaps"

        # LDAP standard ports (RFC 4511)
        DEFAULT_PORT: Final[int] = 389
        DEFAULT_SSL_PORT: Final[int] = 636

        # Aliases for compatibility (referenced in examples/tests)
        LDAP_DEFAULT_PORT: Final[int] = DEFAULT_PORT
        LDAPS_DEFAULT_PORT: Final[int] = DEFAULT_SSL_PORT

        # Timeout constants
        DEFAULT_TIMEOUT_SECONDS: Final[int] = 30

        # LDAP URIs (domain-specific defaults)
        DEFAULT_SERVER_URI: Final[str] = "ldap://localhost"
        DEFAULT_SSL_SERVER_URI: Final[str] = "ldaps://localhost"

        # Limits for LDAP data
        MAX_DESCRIPTION_LENGTH: Final[int] = 1024

    class Connection:
        """LDAP connection-specific constants.

        Note: Use FlextCore.Constants directly for:
        - DEFAULT_TIMEOUT → FlextCore.Constants.Network.DEFAULT_TIMEOUT
        - DEFAULT_POOL_SIZE → FlextCore.Constants.Performance.DEFAULT_DB_POOL_SIZE
        - DEFAULT_PAGE_SIZE → FlextCore.Constants.Performance.DEFAULT_PAGE_SIZE
        """

        # Connection settings (LDAP-specific defaults)
        DEFAULT_TIMEOUT: Final[int] = 30
        DEFAULT_PAGE_SIZE: Final[int] = 100

        # LDAP-specific page sizes
        DEFAULT_SEARCH_PAGE_SIZE: Final[int] = 100
        MAX_PAGE_SIZE_GENERIC: Final[int] = 1000
        MAX_PAGE_SIZE_AD: Final[int] = 100000

    class Scopes:
        """LDAP search scope constants.

        Standard RFC 4511 scope constants. These are LDAP-specific and not
        available in flext-core Platform constants.
        """

        # RFC 4511 standard search scopes
        BASE: Final[str] = "base"
        ONELEVEL: Final[str] = "onelevel"
        SUBTREE: Final[str] = "subtree"

        # LDAP-specific scope (not in RFC 4511)
        CHILDREN: Final[str] = "children"

    class Attributes:
        """Standard LDAP attribute names.

        Note: OBJECT_CLASS from FlextCore.Constants.Platform.LDAP_ATTR_OBJECT_CLASS
        """

        # Core LDAP attributes (RFC 4519 standard names)
        COMMON_NAME: Final[str] = "cn"
        SURNAME: Final[str] = "sn"
        GIVEN_NAME: Final[str] = "givenName"
        DISPLAY_NAME: Final[str] = "displayName"
        DESCRIPTION: Final[str] = "description"
        USER_ID: Final[str] = "uid"
        MAIL: Final[str] = "mail"
        USER_PASSWORD: Final[str] = "userPassword"  # nosec B105

        # Group attributes
        MEMBER: Final[str] = "member"
        UNIQUE_MEMBER: Final[str] = "uniqueMember"
        MEMBER_OF: Final[str] = "memberOf"
        OWNER: Final[str] = "owner"

        # Convenience attribute sets
        MINIMAL_USER_ATTRS: Final[FlextCore.Types.StringList] = ["uid", "cn", "mail"]
        MINIMAL_GROUP_ATTRS: Final[FlextCore.Types.StringList] = ["cn", "member"]

        ALL_USER_ATTRS: Final[FlextCore.Types.StringList] = [
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
        ALL_GROUP_ATTRS: Final[FlextCore.Types.StringList] = [
            "objectClass",
            "cn",
            "description",
            "member",
            "uniqueMember",
            "owner",
            "memberOf",
        ]

        @classmethod
        def get_group_attributes(cls) -> FlextCore.Types.StringList:
            """Get all standard group attributes."""
            return cls.ALL_GROUP_ATTRS.copy()

    class LdapAttributeNames:
        """LDAP attribute names for convenience access.

        Provides direct access to commonly used LDAP attribute names.
        These are aliases to the values in the Attributes class.
        """

        # Core attributes (aliases for convenience)
        DN: Final[str] = "dn"
        OBJECT_CLASS: Final[str] = "objectClass"
        CN: Final[str] = "cn"
        SN: Final[str] = "sn"
        GIVEN_NAME: Final[str] = "givenName"
        DISPLAY_NAME: Final[str] = "displayName"
        UID: Final[str] = "uid"
        MAIL: Final[str] = "mail"
        USER_PASSWORD: Final[str] = "userPassword"

        # Group attributes
        MEMBER: Final[str] = "member"
        UNIQUE_MEMBER: Final[str] = "uniqueMember"
        MEMBER_OF: Final[str] = "memberOf"
        OWNER: Final[str] = "owner"
        GID_NUMBER: Final[str] = "gidNumber"

        # Additional common attributes
        TELEPHONE_NUMBER: Final[str] = "telephoneNumber"
        MOBILE: Final[str] = "mobile"
        DEPARTMENT: Final[str] = "department"
        TITLE: Final[str] = "title"
        OU: Final[str] = "ou"
        DESCRIPTION: Final[str] = "description"
        EMPLOYEE_NUMBER: Final[str] = "employeeNumber"
        EMPLOYEE_TYPE: Final[str] = "employeeType"

    class ObjectClasses:
        """Standard LDAP object classes."""

        TOP: Final[str] = "top"
        PERSON: Final[str] = "person"
        ORGANIZATIONAL_PERSON: Final[str] = "organizationalPerson"
        INET_ORG_PERSON: Final[str] = "inetOrgPerson"
        ORGANIZATIONAL_UNIT: Final[str] = "organizationalUnit"
        GROUP_OF_NAMES: Final[str] = "groupOfNames"
        GROUP_OF_UNIQUE_NAMES: Final[str] = "groupOfUniqueNames"

    class Filters:
        """Default LDAP search filters for common operations."""

        # User filters
        DEFAULT_USER_FILTER: Final[str] = "(objectClass=inetOrgPerson)"
        ALL_USERS_FILTER: Final[str] = "(objectClass=person)"
        ACTIVE_USERS_FILTER: Final[str] = (
            "(&(objectClass=inetOrgPerson)"
            "(!(userAccountControl:1.2.840.113556.1.4.803:=2)))"
        )

        # Group filters
        DEFAULT_GROUP_FILTER: Final[str] = "(objectClass=groupOfNames)"
        ALL_GROUPS_FILTER: Final[str] = (
            "(|(objectClass=groupOfNames)(objectClass=groupOfUniqueNames))"
        )

        # Common combined filters
        ALL_ENTRIES_FILTER: Final[str] = "(objectClass=*)"
        ORGANIZATIONAL_UNITS_FILTER: Final[str] = "(objectClass=organizationalUnit)"

    # LDAP-specific validation constants
    class Validation(FlextCore.Constants.Validation):
        """LDAP-specific validation constants extending base validation."""

        # LDAP DN validation
        MIN_DN_PARTS: Final[int] = 2
        MIN_DN_LENGTH: Final[int] = 3
        MAX_DN_LENGTH: Final[int] = 2048
        DN_PATTERN: Final[str] = (
            r"^[a-zA-Z0-9][a-zA-Z0-9\-_]*=[^,]+(?:,[a-zA-Z0-9][a-zA-Z0-9\-_]*=[^,]+)*$"
        )

        # LDAP filter validation
        MIN_FILTER_LENGTH: Final[int] = 1
        MAX_FILTER_LENGTH: Final[int] = 8192
        FILTER_PATTERN: Final[str] = r"^\(.+\)$"

        # LDAP password validation
        MIN_PASSWORD_LENGTH: Final[int] = 8
        MAX_PASSWORD_LENGTH: Final[int] = 128

        # LDAP connection validation
        MIN_CONNECTION_ARGS: Final[int] = 3  # server_uri, bind_dn, password

    # LDAP-specific error and validation messages
    class Messages(FlextCore.Constants.Messages):
        """LDAP-specific error and validation messages extending base messages."""

        # LDAP validation messages
        HOST_CANNOT_BE_EMPTY: Final[str] = "Host cannot be empty"
        CONNECTION_FAILED: Final[str] = "Connection failed"
        FIELD_CANNOT_BE_EMPTY: Final[str] = "{0} cannot be empty"
        INVALID_DN_FORMAT: Final[str] = "Invalid DN format"
        INVALID_SEARCH_FILTER: Final[str] = "Invalid LDAP search filter"
        CONNECTION_FAILED_WITH_CONTEXT: Final[str] = "Connection failed: {0}"

        # LDAP error messages following FLEXT standards
        # INVALID_EMAIL_FORMAT inherited from FlextCore.Constants.Messages
        EMAIL_VALIDATION_FAILED: Final[str] = "Invalid email format: {error}"
        DN_CANNOT_BE_EMPTY: Final[str] = "DN cannot be empty"

        # Client and server error messages
        CLIENT_NOT_INITIALIZED: Final[str] = "Client not initialized"
        NO_SERVER_OPERATIONS_AVAILABLE: Final[str] = "No server operations available"

    # LDAP-specific error codes
    class Errors(FlextCore.Constants.Errors):
        """LDAP-specific error codes extending universal error codes."""

        # LDAP-specific errors
        LDAP_BIND_ERROR: Final[str] = "LDAP_BIND_ERROR"
        LDAP_SEARCH_ERROR: Final[str] = "LDAP_SEARCH_ERROR"
        LDAP_ADD_ERROR: Final[str] = "LDAP_ADD_ERROR"
        LDAP_MODIFY_ERROR: Final[str] = "LDAP_MODIFY_ERROR"
        LDAP_DELETE_ERROR: Final[str] = "LDAP_DELETE_ERROR"
        LDAP_INVALID_DN: Final[str] = "LDAP_INVALID_DN"
        LDAP_INVALID_FILTER: Final[str] = "LDAP_INVALID_FILTER"

    # LDAP-specific default values
    class Defaults(FlextCore.Constants.Defaults):
        """LDAP-specific default values extending base defaults."""

        DEFAULT_SEARCH_FILTER: Final[str] = "(objectClass=*)"
        DEFAULT_SEARCH_BASE: Final[str] = ""
        DEFAULT_SERVICE_NAME: Final[str] = "flext-ldap"
        DEFAULT_SERVICE_VERSION: Final[str] = "1.0.0"
        MAX_SEARCH_ENTRIES: Final[int] = (
            FlextCore.Constants.Performance.BatchProcessing.MAX_VALIDATION_SIZE
        )

        # Valid LDAP user for testing
        VALID_LDAP_USER_NAME: Final[str] = "testuser"
        VALID_LDAP_USER_DESCRIPTION: Final[str] = "Test LDAP User"

        # Default values for LDAP models
        DEFAULT_DEPARTMENT: Final[str] = "IT"
        DEFAULT_ORGANIZATION: Final[str] = "Company"
        DEFAULT_TITLE: Final[str] = "Employee"
        DEFAULT_STATUS: Final[str] = "active"

        # Error reporting constants
        ERROR_SUMMARY_MAX_ITEMS: Final[int] = 3

        # Domain validation constants
        MIN_USERNAME_LENGTH: Final[int] = 3
        MIN_GROUP_NAME_LENGTH: Final[int] = 2
        MAX_GROUP_DESCRIPTION_LENGTH: Final[int] = 500

        # Service limits
        MAX_DESCRIPTION_LENGTH: Final[int] = (
            500  # Maximum description length for groups/users
        )

        # Connection argument count
        MIN_CONNECTION_ARGS: Final[int] = 3

    class LdapRetry:
        """LDAP retry and timing constants."""

        # Server readiness retry timing
        SERVER_READY_RETRY_DELAY: Final[int] = 2  # seconds
        SERVER_READY_MAX_RETRIES: Final[int] = 10
        SERVER_READY_TIMEOUT: Final[int] = 30  # seconds

        # Connection retry timing
        CONNECTION_RETRY_DELAY: Final[float] = 1.0  # seconds
        CONNECTION_MAX_RETRIES: Final[int] = 3

    class AclFormat:
        """Supported ACL format identifiers."""

        OPENLDAP: Final[str] = "openldap"
        ORACLE: Final[str] = "oracle"
        ACI: Final[str] = "aci"  # 389 DS / Apache DS
        ACTIVE_DIRECTORY: Final[str] = "active_directory"
        UNIFIED: Final[str] = "unified"
        AUTO: Final[str] = "auto"  # Auto-detect format

    class DictKeys:
        """Standard dictionary key names for LDAP operations."""

        # ACL operation keys
        OPERATION: Final[str] = "operation"
        ACL_STRING: Final[str] = "acl_string"
        ACL_DATA: Final[str] = "acl_data"
        TARGET_FORMAT: Final[str] = "target_format"
        FORMAT: Final[str] = "format"

        # LDAP entry attribute keys
        DN: Final[str] = "dn"
        UID: Final[str] = "uid"
        CN: Final[str] = "cn"
        SN: Final[str] = "sn"
        MAIL: Final[str] = "mail"
        GIVEN_NAME: Final[str] = "given_name"
        TELEPHONE_NUMBER: Final[str] = "telephone_number"
        MOBILE: Final[str] = "mobile"
        DEPARTMENT: Final[str] = "department"
        TITLE: Final[str] = "title"
        ORGANIZATION: Final[str] = "organization"
        ORGANIZATIONAL_UNIT: Final[str] = "organizational_unit"
        USER_PASSWORD: Final[str] = "user_password"  # nosec B105 - Dictionary key

        # LDAP search keys
        BASE_DN: Final[str] = "base_dn"
        FILTER: Final[str] = "filter"
        FILTER_STR: Final[str] = "filter_str"

        # LDAP connection keys
        LDAP_SERVER: Final[str] = "ldap_server"
        LDAP_PORT: Final[str] = "ldap_port"
        BIND_DN: Final[str] = "bind_dn"
        BIND_PASSWORD: Final[str] = "bind_password"
        LDAP_BIND_PASSWORD: Final[str] = "ldap_bind_password"

        # Operation config keys
        OPERATION_TYPE: Final[str] = "operation_type"

        # Additional config/operation keys
        SERVER: Final[str] = "server"
        SERVER_URI: Final[str] = "server_uri"
        PORT: Final[str] = "port"
        ATTRIBUTES: Final[str] = "attributes"
        ATTRIBUTE: Final[str] = "attribute"
        VALUES: Final[str] = "values"
        INDENT: Final[str] = "indent"
        SORT_KEYS: Final[str] = "sort_keys"
        INCLUDE_CREDENTIALS: Final[str] = "include_credentials"
        DEFAULT_TIMEOUT: Final[str] = "default_timeout"
        MAX_PAGE_SIZE: Final[str] = "max_page_size"
        SUPPORTS_OPERATIONAL_ATTRS: Final[str] = "supports_operational_attrs"
        SCHEMA_SUBENTRY: Final[str] = "schema_subentry"

        # ACL-specific keys
        ACL_ATTRIBUTE: Final[str] = "acl_attribute"
        ACL_FORMAT: Final[str] = "acl_format"
        SOURCE_FORMAT: Final[str] = "source_format"
        PERMISSIONS: Final[str] = "permissions"
        SUBJECT: Final[str] = "subject"
        TARGET: Final[str] = "target"
        TARGET_TYPE: Final[str] = "target_type"
        ACCESS: Final[str] = "access"
        WHO: Final[str] = "who"
        TYPE: Final[str] = "type"
        DESCRIPTION: Final[str] = "description"
        SUCCESS: Final[str] = "success"

        # Server type keys
        GENERIC: Final[str] = "generic"

    class Permission:
        """Standard ACL permissions mapped across formats."""

        READ: Final[str] = "read"
        WRITE: Final[str] = "write"
        ADD: Final[str] = "add"
        DELETE: Final[str] = "delete"
        SEARCH: Final[str] = "search"
        COMPARE: Final[str] = "compare"
        BROWSE: Final[str] = "browse"
        PROXY: Final[str] = "proxy"
        AUTH: Final[str] = "auth"
        ALL: Final[str] = "all"
        NONE: Final[str] = "none"

    class SubjectType:
        """ACL subject types."""

        USER: Final[str] = "user"
        GROUP: Final[str] = "group"
        DN: Final[str] = "dn"
        SELF: Final[str] = "self"
        ANONYMOUS: Final[str] = "anonymous"
        AUTHENTICATED: Final[str] = "authenticated"
        ANYONE: Final[str] = "anyone"

    class TargetType:
        """ACL target types."""

        DN: Final[str] = "dn"
        ATTRIBUTES: Final[str] = "attributes"
        ENTRY: Final[str] = "entry"
        FILTER: Final[str] = "filter"

    class OpenLdapKeywords:
        """OpenLDAP ACL keywords."""

        ACCESS_TO: Final[str] = "access to"
        BY: Final[str] = "by"
        ATTRS: Final[str] = "attrs="
        DN_EXACT: Final[str] = "dn.exact="
        DN_REGEX: Final[str] = "dn.regex="
        FILTER: Final[str] = "filter="

    class OracleKeywords:
        """Oracle Directory ACL keywords."""

        ACCESS_TO: Final[str] = "access to"
        ATTR: Final[str] = "attr="
        ENTRY: Final[str] = "entry"
        BY: Final[str] = "by"
        GROUP: Final[str] = "group="
        USER: Final[str] = "user="

    class AciKeywords:
        """389 DS/Apache DS ACI keywords."""

        TARGET: Final[str] = "target"
        TARGETATTR: Final[str] = "targetattr"
        TARGETFILTER: Final[str] = "targetfilter"
        VERSION: Final[str] = "version 3.0"
        ACL: Final[str] = "acl"
        ALLOW: Final[str] = "allow"
        DENY: Final[str] = "deny"
        USERDN: Final[str] = "userdn"
        GROUPDN: Final[str] = "groupdn"

    class ConversionWarnings:
        """Warning messages for ACL conversion."""

        PERMISSION_NOT_SUPPORTED: Final[str] = (
            "Permission '{permission}' not supported in {format}, using closest match"
        )
        FEATURE_LOSS: Final[str] = (
            "Feature '{feature}' cannot be preserved in {format} conversion"
        )
        SYNTAX_MISMATCH: Final[str] = (
            "Syntax pattern not directly translatable between formats"
        )

    class Parsing:
        """ACL parsing constants."""

        MIN_ACL_PARTS: Final[int] = 4  # Minimum parts for valid ACL (OpenLDAP format)
        ACL_RULE_PARTS: Final[int] = (
            2  # Number of parts in an ACL rule (<who> <access>)
        )
        OPENLDAP_PREFIX_LENGTH: Final[int] = 3  # Length of "olc" prefix
        MIN_OC_LENGTH: Final[int] = 3  # Minimum length for object class with prefix

    # =========================================================================
    # LITERAL TYPES - All Literal types centralized here per FLEXT standards
    # =========================================================================

    class LiteralTypes:
        """Centralized Literal types for LDAP operations."""

        # LDAP scope literals
        SEARCH_SCOPE_BASE: Final = "BASE"
        SEARCH_SCOPE_LEVEL: Final = "LEVEL"
        SEARCH_SCOPE_SUBTREE: Final = "SUBTREE"

        # LDAP modify operation literals
        MODIFY_ADD: Final = "MODIFY_ADD"
        MODIFY_DELETE: Final = "MODIFY_DELETE"
        MODIFY_REPLACE: Final = "MODIFY_REPLACE"

        # LDAP connection state literals
        CONNECTION_STATE_UNBOUND: Final = "unbound"
        CONNECTION_STATE_BOUND: Final = "bound"
        CONNECTION_STATE_CLOSED: Final = "closed"
        CONNECTION_STATE_ERROR: Final = "error"

        # LDAP operation type literals
        OPERATION_SEARCH: Final = "search"
        OPERATION_ADD: Final = "add"
        OPERATION_MODIFY: Final = "modify"
        OPERATION_DELETE: Final = "delete"
        OPERATION_COMPARE: Final = "compare"
        OPERATION_EXTENDED: Final = "extended"

        # ACL operation literals
        OPERATION_PARSE: Final = "parse"
        OPERATION_CONVERT: Final = "convert"

        # LDAP security level literals
        SECURITY_NONE: Final = "none"
        SECURITY_SIMPLE: Final = "simple"
        SECURITY_SASL: Final = "sasl"

        # LDAP authentication method literals
        AUTH_SIMPLE: Final = "simple"
        AUTH_SASL: Final = "sasl"
        AUTH_EXTERNAL: Final = "external"

        # LDAP connection info literals
        CONNECTION_INFO_ALL: Final = "ALL"
        CONNECTION_INFO_DSA: Final = "DSA"
        CONNECTION_INFO_NO_INFO: Final = "NO_INFO"
        CONNECTION_INFO_SCHEMA: Final = "SCHEMA"

        # LDAP connection mode literals
        CONNECTION_MODE_SYNC: Final = "sync"
        CONNECTION_MODE_ASYNC: Final = "async"

        # LDAP IP mode literals
        IP_MODE_SYSTEM_DEFAULT: Final = "IP_SYSTEM_DEFAULT"
        IP_MODE_V4_ONLY: Final = "IP_V4_ONLY"
        IP_MODE_V4_PREFERRED: Final = "IP_V4_PREFERRED"
        IP_MODE_V6_ONLY: Final = "IP_V6_ONLY"
        IP_MODE_V6_PREFERRED: Final = "IP_V6_PREFERRED"

        # LDAP search scope literals

        # LDAP connection state literals

        # LDAP operation type literals

        # LDAP security level literals

        # LDAP authentication method literals

        # LDAP project type literals
        PROJECT_TYPE_LDAP_SERVICE: Final = "ldap-service"
        PROJECT_TYPE_DIRECTORY_SERVICE: Final = "directory-service"
        PROJECT_TYPE_LDAP_CLIENT: Final = "ldap-client"
        PROJECT_TYPE_IDENTITY_PROVIDER: Final = "identity-provider"
        PROJECT_TYPE_LDAP_SYNC: Final = "ldap-sync"
        PROJECT_TYPE_DIRECTORY_SYNC: Final = "directory-sync"
        PROJECT_TYPE_USER_PROVISIONING: Final = "user-provisioning"
        PROJECT_TYPE_LDAP_GATEWAY: Final = "ldap-gateway"
        PROJECT_TYPE_AUTHENTICATION_SERVICE: Final = "authentication-service"
        PROJECT_TYPE_SSO_SERVICE: Final = "sso-service"
        PROJECT_TYPE_DIRECTORY_API: Final = "directory-api"
        PROJECT_TYPE_LDAP_PROXY: Final = "ldap-proxy"
        PROJECT_TYPE_IDENTITY_MANAGEMENT: Final = "identity-management"
        PROJECT_TYPE_USER_DIRECTORY: Final = "user-directory"
        PROJECT_TYPE_GROUP_MANAGEMENT: Final = "group-management"
        PROJECT_TYPE_LDAP_MIGRATION: Final = "ldap-migration"

    # =========================================================================
    # LITERAL TYPE DEFINITIONS - Centralized Literal types for ALL modules
    # =========================================================================

    # LDAP scope literals (CRITICAL: Use these instead of inline Literal types)
    type SearchScope = Literal["BASE", "LEVEL", "SUBTREE"]
    type ConnectionState = Literal["unbound", "bound", "closed", "error"]
    type OperationType = Literal[
        "search", "add", "modify", "delete", "compare", "extended"
    ]
    type SecurityLevel = Literal["none", "simple", "sasl"]
    type AuthenticationMethod = Literal["simple", "sasl", "external"]

    # LDAP modify operation literals
    type ModifyOperation = Literal["MODIFY_ADD", "MODIFY_DELETE", "MODIFY_REPLACE"]
    type UpdateStrategy = Literal["merge", "replace"]
    type AclType = Literal["openldap", "oracle", "aci", "auto"]
    type ObjectClassKind = Literal["STRUCTURAL", "AUXILIARY", "ABSTRACT"]

    # LDAP connection and server literals
    type ConnectionMode = Literal["sync", "async"]
    type IpMode = Literal[
        "IP_SYSTEM_DEFAULT",
        "IP_V4_ONLY",
        "IP_V4_PREFERRED",
        "IP_V6_ONLY",
        "IP_V6_PREFERRED",
    ]
    type ConnectionInfo = Literal["ALL", "DSA", "NO_INFO", "SCHEMA"]

    # LDAP project type literals
    type LdapProjectType = Literal[
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

    class Version:
        """Version constants for flext-ldap."""

        # Version information from metadata
        CURRENT_VERSION: Final[str] = "0.9.0"
        VERSION_INFO: Final[tuple[int | str, ...]] = (0, 9, 0)

        @classmethod
        def get_version(cls) -> str:
            """Get current version."""
            return cls.CURRENT_VERSION

        @classmethod
        def get_version_info(cls) -> tuple[int | str, ...]:
            """Get version info tuple."""
            return cls.VERSION_INFO

    class Servers:
        """LDAP server type constants."""

        # Server type identifiers
        OPENLDAP1: Final[str] = "openldap1"
        OPENLDAP2: Final[str] = "openldap2"
        OID: Final[str] = "oid"  # Oracle Internet Directory
        OUD: Final[str] = "oud"  # Oracle Unified Directory
        AD: Final[str] = "ad"  # Active Directory
        GENERIC: Final[str] = "generic"


__all__ = [
    "FlextLdapConstants",
]
