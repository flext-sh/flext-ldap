"""LDAP Constants - Essential constants only, using FlextConstants.LDAP exclusively.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import Final, Literal

from flext_core import FlextConstants, FlextTypes


class FlextLdapConstants(FlextConstants):
    """LDAP domain-specific constants - essential constants only."""

    # Import universal constants from flext-core (single source of truth)
    DEFAULT_TIMEOUT = FlextConstants.Network.DEFAULT_TIMEOUT
    VALIDATION_ERROR_BASE = FlextConstants.Errors.VALIDATION_ERROR

    # =========================================================================
    # LDAP-SPECIFIC CONSTANTS ONLY - Essential constants
    # =========================================================================

    class Protocol:
        """LDAP protocol-specific constants - extending centralized FlextConstants."""

        # LDAP ports - using centralized constants
        DEFAULT_PORT: Final[int] = FlextConstants.Platform.LDAP_DEFAULT_PORT
        DEFAULT_SSL_PORT: Final[int] = FlextConstants.Platform.LDAPS_DEFAULT_PORT
        MAX_PORT: Final[int] = FlextConstants.Network.MAX_PORT

        # LDAP protocols - using centralized constants
        LDAP: Final[str] = "ldap"
        LDAPS: Final[str] = "ldaps"

        # LDAP protocol prefixes - using centralized constants
        PROTOCOL_PREFIX_LDAP: Final[str] = FlextConstants.Platform.PROTOCOL_LDAP
        PROTOCOL_PREFIX_LDAPS: Final[str] = FlextConstants.Platform.PROTOCOL_LDAPS

        # LDAP URIs
        DEFAULT_SERVER_URI: Final[str] = "ldap://localhost"
        DEFAULT_SSL_SERVER_URI: Final[str] = "ldaps://localhost"

        # LDAP pool settings - using centralized constants
        DEFAULT_POOL_SIZE: Final[int] = FlextConstants.Performance.DEFAULT_DB_POOL_SIZE
        DEFAULT_TIMEOUT_SECONDS: Final[int] = FlextConstants.Network.DEFAULT_TIMEOUT

    class Connection:
        """LDAP connection-specific constants."""

        # LDAP connection limits - using centralized constants
        MAX_SIZE_LIMIT: Final[int] = (
            FlextConstants.Performance.BatchProcessing.MAX_VALIDATION_SIZE
        )
        DEFAULT_PAGE_SIZE: Final[int] = FlextConstants.Performance.DEFAULT_PAGE_SIZE

    class Scopes:
        """LDAP search scope constants - extending centralized FlextConstants."""

        # LDAP search scope constants - using centralized constants
        BASE: Final[str] = FlextConstants.Platform.LDAP_SCOPE_BASE
        ONELEVEL: Final[str] = FlextConstants.Platform.LDAP_SCOPE_LEVEL
        SUBTREE: Final[str] = FlextConstants.Platform.LDAP_SCOPE_SUBTREE
        CHILDREN: Final[str] = "children"

        VALID_SCOPES: Final[set[str]] = {BASE, ONELEVEL, SUBTREE, CHILDREN}

    class Attributes:
        """Standard LDAP attribute names - extending centralized FlextConstants."""

        # Core Attributes - using centralized constants where available
        OBJECT_CLASS: Final[str] = FlextConstants.Platform.LDAP_ATTR_OBJECT_CLASS
        COMMON_NAME: Final[str] = "cn"
        SURNAME: Final[str] = "sn"
        GIVEN_NAME: Final[str] = "givenName"
        DISPLAY_NAME: Final[str] = "displayName"
        DESCRIPTION: Final[str] = "description"
        USER_ID: Final[str] = "uid"
        MAIL: Final[str] = "mail"
        USER_PASSWORD: Final[str] = "userPassword"  # nosec B105 - LDAP attribute name

        # Group Attributes
        MEMBER: Final[str] = "member"
        UNIQUE_MEMBER: Final[str] = "uniqueMember"
        MEMBER_OF: Final[str] = "memberOf"
        OWNER: Final[str] = "owner"

        @classmethod
        def get_person_attributes(cls) -> FlextTypes.StringList:
            """Get standard person-related attributes."""
            return [
                cls.OBJECT_CLASS,
                cls.COMMON_NAME,
                cls.SURNAME,
                cls.GIVEN_NAME,
                cls.DISPLAY_NAME,
                cls.USER_ID,
                cls.MAIL,
                cls.DESCRIPTION,
            ]

        @classmethod
        def get_group_attributes(cls) -> FlextTypes.StringList:
            """Get standard group-related attributes."""
            return [
                cls.OBJECT_CLASS,
                cls.COMMON_NAME,
                cls.DESCRIPTION,
                cls.MEMBER,
                cls.UNIQUE_MEMBER,
                cls.OWNER,
            ]

    class ObjectClasses:
        """Standard LDAP object classes."""

        TOP: Final[str] = "top"
        PERSON: Final[str] = "person"
        INET_ORG_PERSON: Final[str] = "inetOrgPerson"
        GROUP_OF_NAMES: Final[str] = "groupOfNames"
        GROUP_OF_UNIQUE_NAMES: Final[str] = "groupOfUniqueNames"

    # LDAP-specific validation constants
    class Validation(FlextConstants.Validation):
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

    # LDAP-specific error and validation messages
    class Messages(FlextConstants.Messages):
        """LDAP-specific error and validation messages extending base messages."""

        # LDAP validation messages
        HOST_CANNOT_BE_EMPTY: Final[str] = "Host cannot be empty"
        CONNECTION_FAILED: Final[str] = "Connection failed"
        FIELD_CANNOT_BE_EMPTY: Final[str] = "{0} cannot be empty"
        INVALID_DN_FORMAT: Final[str] = "Invalid DN format"
        INVALID_SEARCH_FILTER: Final[str] = "Invalid LDAP search filter"
        CONNECTION_FAILED_WITH_CONTEXT: Final[str] = "Connection failed: {0}"

        # LDAP error messages following FLEXT standards
        # INVALID_EMAIL_FORMAT inherited from FlextConstants.Messages
        EMAIL_VALIDATION_FAILED: Final[str] = "Invalid email format: {error}"
        DN_CANNOT_BE_EMPTY: Final[str] = "DN cannot be empty"

    # LDAP-specific error codes
    class Errors(FlextConstants.Errors):
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
    class Defaults(FlextConstants.Defaults):
        """LDAP-specific default values extending base defaults."""

        DEFAULT_SEARCH_FILTER: Final[str] = "(objectClass=*)"
        DEFAULT_SEARCH_BASE: Final[str] = ""
        DEFAULT_SERVICE_NAME: Final[str] = "flext-ldap"
        DEFAULT_SERVICE_VERSION: Final[str] = "1.0.0"
        MAX_SEARCH_ENTRIES: Final[int] = (
            FlextConstants.Performance.BatchProcessing.MAX_VALIDATION_SIZE
        )

        # Valid LDAP user for testing
        VALID_LDAP_USER_NAME: Final[str] = "testuser"
        VALID_LDAP_USER_DESCRIPTION: Final[str] = "Test LDAP User"

        # Default values for LDAP models
        DEFAULT_DEPARTMENT: Final[str] = "IT"
        DEFAULT_ORGANIZATION: Final[str] = "Company"
        DEFAULT_TITLE: Final[str] = "Employee"
        DEFAULT_STATUS: Final[str] = "active"

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

    # =========================================================================
    # LITERAL TYPES - All Literal types centralized here per FLEXT standards
    # =========================================================================

    class LiteralTypes:
        """Centralized Literal types for LDAP operations."""

        # LDAP scope literals
        SEARCH_SCOPE_BASE: Final[Literal["BASE"]] = "BASE"
        SEARCH_SCOPE_LEVEL: Final[Literal["LEVEL"]] = "LEVEL"
        SEARCH_SCOPE_SUBTREE: Final[Literal["SUBTREE"]] = "SUBTREE"

        # LDAP modify operation literals
        MODIFY_ADD: Final[Literal["MODIFY_ADD"]] = "MODIFY_ADD"
        MODIFY_DELETE: Final[Literal["MODIFY_DELETE"]] = "MODIFY_DELETE"
        MODIFY_REPLACE: Final[Literal["MODIFY_REPLACE"]] = "MODIFY_REPLACE"

        # LDAP connection state literals
        CONNECTION_STATE_UNBOUND: Final[Literal["unbound"]] = "unbound"
        CONNECTION_STATE_BOUND: Final[Literal["bound"]] = "bound"
        CONNECTION_STATE_CLOSED: Final[Literal["closed"]] = "closed"
        CONNECTION_STATE_ERROR: Final[Literal["error"]] = "error"

        # LDAP operation type literals
        OPERATION_SEARCH: Final[Literal["search"]] = "search"
        OPERATION_ADD: Final[Literal["add"]] = "add"
        OPERATION_MODIFY: Final[Literal["modify"]] = "modify"
        OPERATION_DELETE: Final[Literal["delete"]] = "delete"
        OPERATION_COMPARE: Final[Literal["compare"]] = "compare"
        OPERATION_EXTENDED: Final[Literal["extended"]] = "extended"

        # LDAP security level literals
        SECURITY_NONE: Final[Literal["none"]] = "none"
        SECURITY_SIMPLE: Final[Literal["simple"]] = "simple"
        SECURITY_SASL: Final[Literal["sasl"]] = "sasl"

        # LDAP authentication method literals
        AUTH_SIMPLE: Final[Literal["simple"]] = "simple"
        AUTH_SASL: Final[Literal["sasl"]] = "sasl"
        AUTH_EXTERNAL: Final[Literal["external"]] = "external"

        # LDAP connection info literals
        CONNECTION_INFO_ALL: Final[Literal["ALL"]] = "ALL"
        CONNECTION_INFO_DSA: Final[Literal["DSA"]] = "DSA"
        CONNECTION_INFO_NO_INFO: Final[Literal["NO_INFO"]] = "NO_INFO"
        CONNECTION_INFO_SCHEMA: Final[Literal["SCHEMA"]] = "SCHEMA"

        # LDAP connection mode literals
        CONNECTION_MODE_SYNC: Final[Literal["sync"]] = "sync"
        CONNECTION_MODE_ASYNC: Final[Literal["async"]] = "async"

        # LDAP IP mode literals
        IP_MODE_SYSTEM_DEFAULT: Final[Literal["IP_SYSTEM_DEFAULT"]] = (
            "IP_SYSTEM_DEFAULT"
        )
        IP_MODE_V4_ONLY: Final[Literal["IP_V4_ONLY"]] = "IP_V4_ONLY"
        IP_MODE_V4_PREFERRED: Final[Literal["IP_V4_PREFERRED"]] = "IP_V4_PREFERRED"
        IP_MODE_V6_ONLY: Final[Literal["IP_V6_ONLY"]] = "IP_V6_ONLY"
        IP_MODE_V6_PREFERRED: Final[Literal["IP_V6_PREFERRED"]] = "IP_V6_PREFERRED"

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
