"""LDAP domain constants following FLEXT standardization.

Layer 0 pure constants with nested class organization, FlextConstants
inheritance, and Final[Type] declarations for type-safe immutability.

Domain coverage includes LDAP Protocol (RFC 4511), ACL keywords, operation
types, validation patterns, and type definitions.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import Final, Literal, cast

from flext_core import FlextConstants
from flext_ldif import FlextLdifConstants
from ldap3 import (
    MODIFY_ADD,
    MODIFY_DELETE,
    MODIFY_REPLACE,
)


class FlextLdapConstants(FlextConstants):
    """LDAP domain-specific constants extending FlextConstants directly.

    **Composition Pattern (Standardization Compliance):**
    - LdifConstants: Reference to FlextLdifConstants for LDIF patterns
    - Core composition: Direct inheritance from FlextConstants

    **Domain Coverage:**
    - LDAP Protocol (RFC 4511 scopes, ports, connection management)
    - LDAP-specific ACL keywords and parsing constants
    - LDAP operation types and validation
    - Type definitions for strict typing

    **Dependency Chain (Standardized):**
    - FlextLdapConstants → FlextConstants (direct inheritance)
    - FlextLdapConstants.LdifConstants → FlextLdifConstants (composition)
    """

    # =========================================================================
    # COMPOSITION REFERENCES (Standardization Pattern)
    # =========================================================================

    # Re-export commonly used flext-ldif constants for convenience (composition pattern)
    DnPatterns = FlextLdifConstants.DnPatterns
    ObjectClasses = FlextLdifConstants.ObjectClasses
    Encoding = FlextLdifConstants.Encoding
    LdapServers = FlextLdifConstants.LdapServers
    Servers = FlextLdifConstants.LdapServers
    EntryType = FlextLdifConstants.EntryType
    AclFormats = FlextLdifConstants.AclFormats
    OperationalAttributes = FlextLdifConstants.OperationalAttributes

    # Direct access constants for backward compatibility
    DEFAULT_TIMEOUT: Final[int] = FlextConstants.Network.DEFAULT_TIMEOUT
    DEFAULT_PAGE_SIZE: Final[int] = FlextConstants.Performance.DEFAULT_PAGE_SIZE
    LDAP_DEFAULT_PORT: Final[int] = 389
    LDAPS_DEFAULT_PORT: Final[int] = 636

    # =========================================================================
    # PROTOCOL CONSTANTS
    # =========================================================================

    class Protocol:
        """LDAP protocol-specific constants (RFC 4511)."""

        LDAP: Final[str] = "ldap"
        LDAPS: Final[str] = "ldaps"
        DEFAULT_PORT: Final[int] = 389
        DEFAULT_SSL_PORT: Final[int] = 636
        DEFAULT_TIMEOUT_SECONDS: Final[int] = 30
        DEFAULT_SERVER_URI: Final[str] = "ldap://localhost"
        DEFAULT_SSL_SERVER_URI: Final[str] = "ldaps://localhost"
        MAX_DESCRIPTION_LENGTH: Final[int] = 1024

    class ModifyOperation:
        """LDAP modify operations (RFC 4511).

        Public API constants for LDAP modify operations.
        Re-exports ldap3 constants with FLEXT namespace for proper encapsulation.

        Use these constants instead of importing ldap3 directly:
        - FlextLdapConstants.ModifyOperation.ADD
        - FlextLdapConstants.ModifyOperation.DELETE
        - FlextLdapConstants.ModifyOperation.REPLACE
        - FlextLdapConstants.ModifyOperation.INCREMENT

        Example:
            from flext_ldap import FlextLdap, FlextLdapConstants

            ldap_client = FlextLdap()
            ldap_client.modify_entry(
                dn="cn=schema",
                changes={"attributeTypes": ["..."]},
                operation=FlextLdapConstants.ModifyOperation.ADD
            )

        """

        # Re-export ldap3 constants (strings in ldap3, typed as int in stubs)
        ADD: Final[str] = cast("str", MODIFY_ADD)
        DELETE: Final[str] = cast("str", MODIFY_DELETE)
        REPLACE: Final[str] = cast("str", MODIFY_REPLACE)

    class Connection:
        """LDAP connection-specific constants."""

        DEFAULT_TIMEOUT: Final[int] = 30
        DEFAULT_PAGE_SIZE: Final[int] = 100
        DEFAULT_SEARCH_PAGE_SIZE: Final[int] = 100
        MAX_PAGE_SIZE_GENERIC: Final[int] = 1000
        MAX_PAGE_SIZE_AD: Final[int] = 100000

    class Scopes:
        """LDAP search scope constants (RFC 4511)."""

        BASE: Final[str] = "base"
        ONELEVEL: Final[str] = "onelevel"
        SUBTREE: Final[str] = "subtree"
        CHILDREN: Final[str] = "children"

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

        @classmethod
        def get_group_attributes(cls) -> list[str]:
            """Get all standard group attributes."""
            return cls.ALL_GROUP_ATTRS.copy()

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
    # VALIDATION CONSTANTS
    # =========================================================================

    class Validation(FlextConstants.Validation):
        """LDAP-specific validation constants."""

        MIN_DN_PARTS: Final[int] = 2
        MIN_DN_LENGTH: Final[int] = 3
        MAX_DN_LENGTH: Final[int] = 2048
        # DN RDN format: attr=value(,attr=value)*
        _RDN_PART = r"[a-zA-Z0-9][a-zA-Z0-9\-_]*=[^,]+"
        DN_PATTERN: Final[str] = rf"^{_RDN_PART}(?:,{_RDN_PART})*$"
        MIN_FILTER_LENGTH: Final[int] = 1
        MAX_FILTER_LENGTH: Final[int] = 8192
        FILTER_PATTERN: Final[str] = r"^\(.+\)$"
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

        DEFAULT_SEARCH_FILTER: Final[str] = "(objectClass=*)"
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
        MIN_GROUP_NAME_LENGTH: Final[int] = 2
        MAX_GROUP_DESCRIPTION_LENGTH: Final[int] = 500
        MAX_DESCRIPTION_LENGTH: Final[int] = 500
        MIN_CONNECTION_ARGS: Final[int] = 3

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

        OPENLDAP: Final[str] = "openldap"
        ORACLE: Final[str] = "oracle"
        ACI: Final[str] = "aci"
        ACTIVE_DIRECTORY: Final[str] = "active_directory"
        UNIFIED: Final[str] = "unified"
        AUTO: Final[str] = "auto"

    # =========================================================================
    # LDAP DICT KEYS - High frequency usage (62 references)
    # =========================================================================

    class LdapDictKeys(FlextLdifConstants.DictKeys):
        """Extend FlextLdifConstants.DictKeys with LDAP-specific keys."""

        ACL_DATA: Final[str] = "acl_data"
        GENERIC: Final[str] = "generic"
        LDAP_SERVER: Final[str] = "ldap_server"
        LDAP_PORT: Final[str] = "ldap_port"
        BIND_DN: Final[str] = "bind_dn"
        BIND_PASSWORD: Final[str] = "bind_password"
        LDAP_BIND_PASSWORD: Final[str] = "ldap_bind_password"
        SERVER_URI: Final[str] = "server_uri"
        DEFAULT_TIMEOUT: Final[str] = "default_timeout"
        MAX_PAGE_SIZE: Final[str] = "max_page_size"
        OPERATION: Final[str] = "operation"
        ACL_STRING: Final[str] = "acl_string"
        WHO: Final[str] = "who"
        ATTRIBUTE: Final[str] = "attribute"
        VALUES: Final[str] = "values"
        OPERATION_TYPE: Final[str] = "operation_type"
        PORT: Final[str] = "port"
        BASE_DN: Final[str] = "base_dn"
        SERVER: Final[str] = "server"
        TARGET_TYPE: Final[str] = "target_type"
        SUBJECT: Final[str] = "subject"
        ORGANIZATION: Final[str] = "organization"
        TITLE: Final[str] = "title"
        DEPARTMENT: Final[str] = "department"
        MOBILE: Final[str] = "mobile"
        GIVEN_NAME: Final[str] = "given_name"
        USER_PASSWORD: Final[str] = "user_password"

    # Alias for backward compatibility
    DictKeys = LdapDictKeys

    # =========================================================================
    # TYPE DEFINITIONS (moved from module level)
    # =========================================================================

    class Types:
        """Type aliases for LDAP domain (moved from module level for Layer 0 compliance)."""

        SearchScope = Literal["base", "onelevel", "subtree", "children"]
        ModifyOperation = Literal["add", "delete", "replace"]
        UpdateStrategy = Literal["merge", "replace"]
        AclType = Literal["openldap", "oracle", "aci", "active_directory", "auto"]
        ObjectClassKind = Literal["STRUCTURAL", "AUXILIARY", "ABSTRACT"]
        ConnectionState = Literal["unbound", "bound", "closed", "error"]
        OperationType = Literal[
            "search", "add", "modify", "delete", "compare", "extended"
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
        LdapProjectType = Literal[
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

        # ACL type definitions
        Permission = Literal[
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
            "user", "group", "dn", "self", "anonymous", "authenticated", "anyone"
        ]
        TargetType = Literal["dn", "attributes", "entry", "filter"]
        AclFormat = Literal[
            "openldap", "oracle", "aci", "active_directory", "unified", "auto"
        ]

    # Re-export AclType for backward compatibility
    AclType = Types.AclType

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
    # VERSION CONSTANTS
    # =========================================================================

    class Version:
        """Version constants for flext-ldap."""

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


# Make constants available at module level for backward compatibility
AclType = FlextLdapConstants.Types.AclType
AuthenticationMethod = FlextLdapConstants.Types.AuthenticationMethod
ConnectionState = FlextLdapConstants.Types.ConnectionState
LdapProjectType = FlextLdapConstants.Types.LdapProjectType
ObjectClassKind = FlextLdapConstants.Types.ObjectClassKind
OperationType = FlextLdapConstants.Types.OperationType
SecurityLevel = FlextLdapConstants.Types.SecurityLevel
UpdateStrategy = FlextLdapConstants.Types.UpdateStrategy

__all__ = [
    "AclType",
    "AuthenticationMethod",
    "ConnectionState",
    "FlextLdapConstants",
    "LdapProjectType",
    "ObjectClassKind",
    "OperationType",
    "SecurityLevel",
    "UpdateStrategy",
]
