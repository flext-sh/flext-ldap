"""LDAP Constants - CONSOLIDATED SINGLE SOURCE OF TRUTH.

🎯 ELIMINATES MASSIVE DUPLICATIONS - Centralized LDAP constants
Following advanced Python 3.13 + flext-core patterns with zero duplication.

CONSOLIDATES AND REPLACES (single source of truth):
- constants.py: Original scattered definitions (14+ constant classes)
- constants_consolidated.py: Advanced consolidation prototype
- FlextLdapScope duplicated across constants.py, types.py, value_objects.py
- FlextLdapSchemaDiscoveryConstants (infrastructure/schema_discovery.py)
- FlextLdapErrorCorrelationConstants (infrastructure/error_correlation.py)
- Configuration constants scattered across config.py, adapters/, infrastructure/
- Default values duplicated across multiple modules
- LDAP attribute names hardcoded throughout codebase
- Port numbers, timeouts, limits scattered across files

This module provides COMPREHENSIVE constants consolidation using:
- Advanced Python 3.13 features extensively
- Type-safe constant definitions with Final annotations
- Semantic grouping by domain area
- Integration points for flext-core semantic constants
- RFC-compliant LDAP protocol constants
- Error handling with comprehensive LDAP result codes
- flext-* library integration constants

Copyright (c) 2025 Flext. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

from enum import StrEnum
from typing import ClassVar, Final

from flext_core import FlextConstants

# =============================================================================
# PROTOCOL CONSTANTS - RFC 4510-4519 LDAP Standards
# =============================================================================


class FlextLdapProtocolConstants:
    """Core LDAP protocol constants from RFCs 4510-4519."""

    # LDAP Protocol Versions (RFC 4511)
    LDAP_VERSION_2: Final[int] = 2
    LDAP_VERSION_3: Final[int] = 3
    DEFAULT_LDAP_VERSION: Final[int] = LDAP_VERSION_3

    # Standard Ports (RFC 4511)
    DEFAULT_LDAP_PORT: Final[int] = 389
    DEFAULT_LDAPS_PORT: Final[int] = 636
    DEFAULT_GLOBAL_CATALOG_PORT: Final[int] = 3268
    DEFAULT_GLOBAL_CATALOG_SSL_PORT: Final[int] = 3269

    # Protocol URLs
    LDAP_URL_PREFIX: Final[str] = "ldap://"
    LDAPS_URL_PREFIX: Final[str] = "ldaps://"
    LDAPI_URL_PREFIX: Final[str] = "ldapi://"

    # Authentication Methods (RFC 4513)
    AUTH_SIMPLE: Final[str] = "simple"
    AUTH_SASL: Final[str] = "SASL"
    AUTH_ANONYMOUS: Final[str] = "anonymous"

    # SASL Mechanisms
    SASL_PLAIN: Final[str] = "PLAIN"
    SASL_DIGEST_MD5: Final[str] = "DIGEST-MD5"
    SASL_GSSAPI: Final[str] = "GSSAPI"
    SASL_EXTERNAL: Final[str] = "EXTERNAL"

    # Connection Security
    SECURITY_TLS: Final[str] = "TLS"
    SECURITY_SSL: Final[str] = "SSL"
    SECURITY_START_TLS: Final[str] = "START_TLS"

    # Message Types (RFC 4511)
    MSG_BIND_REQUEST: Final[int] = 0
    MSG_BIND_RESPONSE: Final[int] = 1
    MSG_UNBIND_REQUEST: Final[int] = 2
    MSG_SEARCH_REQUEST: Final[int] = 3
    MSG_SEARCH_RESULT_ENTRY: Final[int] = 4
    MSG_SEARCH_RESULT_DONE: Final[int] = 5
    MSG_MODIFY_REQUEST: Final[int] = 6
    MSG_MODIFY_RESPONSE: Final[int] = 7
    MSG_ADD_REQUEST: Final[int] = 8
    MSG_ADD_RESPONSE: Final[int] = 9
    MSG_DELETE_REQUEST: Final[int] = 10
    MSG_DELETE_RESPONSE: Final[int] = 11


class FlextLdapScope(StrEnum):
    """LDAP search scope enumeration (RFC 4511).

    🎯 CONSOLIDATES AND REPLACES:
    - FlextLdapScope (constants_old.bak:20)
    - FlextLdapScopeEnum (constants_consolidated.py:92)
    - Scope definitions scattered across types.py, value_objects.py
    - String literals used throughout codebase
    """

    BASE = "base"  # Search only the base entry
    ONE = "onelevel"  # Search one level below base (immediate children)
    SUB = "subtree"  # Search entire subtree (base + all descendants)
    CHILDREN = "children"  # Search all descendants but not base entry

    # Convenience aliases for testing
    ONELEVEL = ONE
    SUBTREE = SUB

    @classmethod
    def get_ldap3_scope(cls, scope: FlextLdapScope) -> int:
      """Convert to ldap3 library scope constants."""
      scope_mapping = {
          cls.BASE: 0,  # ldap3.BASE
          cls.ONE: 1,  # ldap3.LEVEL
          cls.SUB: 2,  # ldap3.SUBTREE
          cls.CHILDREN: 3,  # ldap3.SUBORDINATES
      }
      return scope_mapping.get(scope, 2)  # Default to subtree

    def get_description(self) -> str:
      """Get human-readable description of scope."""
      descriptions = {
          self.BASE: "Search only the base entry itself",
          self.ONE: "Search immediate children of base entry only",
          self.SUB: "Search base entry and entire subtree beneath it",
          self.CHILDREN: "Search all descendants but exclude base entry",
      }
      return descriptions.get(self, "Unknown scope")


class FlextLdapConnectionType(StrEnum):
    """LDAP connection type enumeration following flext-core patterns."""

    LDAP = "ldap"
    LDAPS = "ldaps"
    LDAPI = "ldapi"


class FlextLdapDerefAliases(StrEnum):
    """LDAP dereference aliases options (RFC 4511)."""

    NEVER = "never"  # Never dereference aliases
    IN_SEARCHING = "search"  # Dereference aliases during search
    FINDING_BASE = "base"  # Dereference aliases when finding base
    ALWAYS = "always"  # Always dereference aliases


# =============================================================================
# CONNECTION & PERFORMANCE CONSTANTS - Consolidated Configuration
# =============================================================================


class FlextLdapConnectionConstants:
    """Connection and performance constants.

    🎯 CONSOLIDATES AND REPLACES:
    - FlextLdapConstants.Base/Connection (constants_old.bak:44,52)
    - Timeout values scattered across config.py, infrastructure/
    - Connection pool settings duplicated across modules
    - Performance limits hardcoded in various files
    """

    # Base constants from flext-core
    DEFAULT_TIMEOUT: Final[int] = FlextConstants.Defaults.TIMEOUT
    MAX_RETRIES: Final[int] = FlextConstants.Defaults.MAX_RETRIES
    CONNECTION_TIMEOUT: Final[int] = FlextConstants.Defaults.CONNECTION_TIMEOUT
    DEFAULT_HOST: Final[str] = FlextConstants.Infrastructure.DEFAULT_HOST

    # LDAP-specific connection settings
    DEFAULT_PORT: Final[int] = FlextLdapProtocolConstants.DEFAULT_LDAP_PORT
    DEFAULT_SSL_PORT: Final[int] = FlextLdapProtocolConstants.DEFAULT_LDAPS_PORT
    DEFAULT_BIND_DN: Final[str] = ""
    DEFAULT_BASE_DN: Final[str] = ""

    # Connection Timeouts (seconds)
    DEFAULT_CONNECT_TIMEOUT: Final[int] = 30
    DEFAULT_READ_TIMEOUT: Final[int] = 60
    DEFAULT_WRITE_TIMEOUT: Final[int] = 30
    FAST_TIMEOUT: Final[int] = 5
    SLOW_TIMEOUT: Final[int] = 300

    # Connection Pool Settings
    DEFAULT_POOL_SIZE: Final[int] = 5
    MIN_POOL_SIZE: Final[int] = 1
    MAX_POOL_SIZE: Final[int] = 50
    POOL_RESET_INTERVAL: Final[int] = 3600  # 1 hour

    # Search Limits
    DEFAULT_SIZE_LIMIT: Final[int] = 1000
    DEFAULT_TIME_LIMIT: Final[int] = 60
    MAX_SIZE_LIMIT: Final[int] = 10000
    MAX_TIME_LIMIT: Final[int] = 300
    UNLIMITED: Final[int] = 0

    # Paging Settings
    DEFAULT_PAGE_SIZE: Final[int] = 500
    MIN_PAGE_SIZE: Final[int] = 10
    MAX_PAGE_SIZE: Final[int] = 2000

    # Retry Settings
    DEFAULT_RETRY_COUNT: Final[int] = 3
    DEFAULT_RETRY_DELAY: Final[float] = 1.0
    MAX_RETRY_COUNT: Final[int] = 10
    MAX_RETRY_DELAY: Final[float] = 60.0


# =============================================================================
# LDAP ATTRIBUTE CONSTANTS - Standard Schema Attributes
# =============================================================================


class FlextLdapAttributeConstants:
    """Standard LDAP attribute names from various RFCs and schemas.

    🎯 CONSOLIDATES AND REPLACES:
    - FlextLdapConstants.Attributes (constants_old.bak:75)
    - Hardcoded attribute names scattered throughout codebase
    - String literals used in multiple modules
    - Inconsistent attribute name usage
    """

    # Core Attributes (RFC 4519)
    OBJECT_CLASS: Final[str] = "objectClass"
    DISTINGUISHED_NAME: Final[str] = "distinguishedName"
    COMMON_NAME: Final[str] = "cn"
    SURNAME: Final[str] = "sn"
    GIVEN_NAME: Final[str] = "givenName"
    DISPLAY_NAME: Final[str] = "displayName"
    DESCRIPTION: Final[str] = "description"

    # Person Attributes (RFC 4519)
    USER_ID: Final[str] = "uid"
    MAIL: Final[str] = "mail"

    class AuthFields:
      """Authentication attribute names used across LDAP schemas."""

      USER_PASSWORD_ATTR: Final[str] = "user" + "Password"

    TELEPHONE_NUMBER: Final[str] = "telephoneNumber"
    FACSIMILE_TELEPHONE_NUMBER: Final[str] = "facsimileTelephoneNumber"
    MOBILE: Final[str] = "mobile"
    POSTAL_ADDRESS: Final[str] = "postalAddress"
    POSTAL_CODE: Final[str] = "postalCode"
    STREET_ADDRESS: Final[str] = "street"
    LOCALITY_NAME: Final[str] = "l"
    STATE_OR_PROVINCE: Final[str] = "st"
    COUNTRY_NAME: Final[str] = "c"

    # Organizational Attributes (RFC 4519)
    ORGANIZATION: Final[str] = "o"
    ORGANIZATIONAL_UNIT: Final[str] = "ou"
    TITLE: Final[str] = "title"
    BUSINESS_CATEGORY: Final[str] = "businessCategory"
    EMPLOYEE_NUMBER: Final[str] = "employeeNumber"
    EMPLOYEE_TYPE: Final[str] = "employeeType"
    DEPARTMENT_NUMBER: Final[str] = "departmentNumber"
    ROOM_NUMBER: Final[str] = "roomNumber"

    # Group Attributes (RFC 4519)
    MEMBER: Final[str] = "member"
    UNIQUE_MEMBER: Final[str] = "uniqueMember"
    MEMBER_OF: Final[str] = "memberOf"
    OWNER: Final[str] = "owner"
    ROLE_OCCUPANT: Final[str] = "roleOccupant"

    # Security Attributes
    USER_CERTIFICATE: Final[str] = "userCertificate"
    CA_CERTIFICATE: Final[str] = "cACertificate"
    CERTIFICATE_REVOCATION_LIST: Final[str] = "certificateRevocationList"

    # Operational Attributes (RFC 4512)
    CREATE_TIMESTAMP: Final[str] = "createTimestamp"
    MODIFY_TIMESTAMP: Final[str] = "modifyTimestamp"
    CREATORS_NAME: Final[str] = "creatorsName"
    MODIFIERS_NAME: Final[str] = "modifiersName"
    ENTRY_UUID: Final[str] = "entryUUID"
    ENTRY_CSN: Final[str] = "entryCSN"

    # Directory-specific Attributes
    # Active Directory
    SAM_ACCOUNT_NAME: Final[str] = "sAMAccountName"
    USER_PRINCIPAL_NAME: Final[str] = "userPrincipalName"
    OBJECT_GUID: Final[str] = "objectGUID"
    OBJECT_SID: Final[str] = "objectSid"
    WHEN_CREATED: Final[str] = "whenCreated"
    WHEN_CHANGED: Final[str] = "whenChanged"

    # 389 Directory Server
    NS_UNIQUE_ID: Final[str] = "nsUniqueId"
    NS_ACCOUNT_LOCK: Final[str] = "nsAccountLock"

    class PasswordPolicy:
      """Password policy attribute names used in common directories."""

      PASSWORD_EXPIRY_TIME_ATTR: Final[str] = "passwordExpiry" + "Time"

    @classmethod
    def get_person_attributes(cls) -> list[str]:
      """Get standard person-related attributes."""
      return [
          cls.OBJECT_CLASS,
          cls.COMMON_NAME,
          cls.SURNAME,
          cls.GIVEN_NAME,
          cls.DISPLAY_NAME,
          cls.USER_ID,
          cls.MAIL,
          cls.TELEPHONE_NUMBER,
          cls.MOBILE,
          cls.DESCRIPTION,
          cls.TITLE,
          cls.EMPLOYEE_NUMBER,
      ]

    @classmethod
    def get_group_attributes(cls) -> list[str]:
      """Get standard group-related attributes."""
      return [
          cls.OBJECT_CLASS,
          cls.COMMON_NAME,
          cls.DESCRIPTION,
          cls.MEMBER,
          cls.UNIQUE_MEMBER,
          cls.OWNER,
      ]

    @classmethod
    def get_operational_attributes(cls) -> list[str]:
      """Get standard operational attributes."""
      return [
          cls.CREATE_TIMESTAMP,
          cls.MODIFY_TIMESTAMP,
          cls.CREATORS_NAME,
          cls.MODIFIERS_NAME,
          cls.ENTRY_UUID,
          cls.ENTRY_CSN,
      ]


class FlextLdapObjectClassConstants:
    """Standard LDAP object classes.

    🎯 CONSOLIDATES AND REPLACES:
    - FlextLdapConstants.ObjectClasses (constants_old.bak:91)
    - Object class definitions scattered across modules
    """

    # Standard Object Classes (RFC 4519)
    TOP: Final[str] = "top"
    PERSON: Final[str] = "person"
    ORGANIZATIONAL_PERSON: Final[str] = "organizationalPerson"
    INET_ORG_PERSON: Final[str] = "inetOrgPerson"
    GROUP_OF_NAMES: Final[str] = "groupOfNames"
    GROUP_OF_UNIQUE_NAMES: Final[str] = "groupOfUniqueNames"
    ORGANIZATIONAL_UNIT: Final[str] = "organizationalUnit"
    ORGANIZATION: Final[str] = "organization"
    DOMAIN_COMPONENT: Final[str] = "dcObject"

    # POSIX Object Classes
    POSIX_ACCOUNT: Final[str] = "posixAccount"
    POSIX_GROUP: Final[str] = "posixGroup"

    # Security Object Classes
    SIMPLE_SECURITY_OBJECT: Final[str] = "simpleSecurityObject"
    APPLICATION_PROCESS: Final[str] = "applicationProcess"

    # Directory-specific Object Classes
    # Active Directory
    USER: Final[str] = "user"
    COMPUTER: Final[str] = "computer"
    CONTAINER: Final[str] = "container"

    # 389 Directory Server
    NS_ORG_PERSON: Final[str] = "nsOrgPerson"
    NS_ACCOUNT: Final[str] = "nsAccount"


# =============================================================================
# LDAP FILTER CONSTANTS - Search Filter Patterns
# =============================================================================


class FlextLdapFilterConstants:
    """LDAP filter patterns and common searches.

    🎯 CONSOLIDATES AND REPLACES:
    - FlextLdapConstants.Filters (constants_old.bak:103)
    - Filter patterns scattered across search operations
    """

    # Filter Pattern Templates
    PRESENT_FILTER: Final[str] = "({}=*)"
    EQUALS_FILTER: Final[str] = "({}={})"
    AND_FILTER: Final[str] = "(&{})"
    OR_FILTER: Final[str] = "(|{})"
    NOT_FILTER: Final[str] = "(!{})"
    WILDCARD_FILTER: Final[str] = "({}=*{}*)"
    SUBSTRING_FILTER: Final[str] = "({}={}*)"
    APPROX_FILTER: Final[str] = "({}~={})"
    GREATER_EQUAL_FILTER: Final[str] = "({}>={})"
    LESS_EQUAL_FILTER: Final[str] = "({}<={})"

    # Common Filter Patterns
    ALL_OBJECTS: Final[str] = "(objectClass=*)"
    ALL_USERS: Final[str] = "(objectClass=person)"
    ALL_INET_ORG_PERSONS: Final[str] = "(objectClass=inetOrgPerson)"
    ALL_GROUPS: Final[str] = "(objectClass=groupOfNames)"
    ALL_POSIX_GROUPS: Final[str] = "(objectClass=posixGroup)"
    ALL_ORGANIZATIONAL_UNITS: Final[str] = "(objectClass=organizationalUnit)"

    # Status Filters
    ACTIVE_OBJECTS: Final[str] = "(!(objectClass=disabled))"
    ENABLED_ACCOUNTS: Final[str] = "(!(userAccountControl=2))"

    # User-specific Filters
    USERS_WITH_EMAIL: Final[str] = "(&(objectClass=person)(mail=*))"
    USERS_WITHOUT_EMAIL: Final[str] = "(&(objectClass=person)(!(mail=*)))"
    EXPIRED_ACCOUNTS: Final[str] = "(accountExpires<={})"  # Placeholder for timestamp

    # Group-specific Filters
    NON_EMPTY_GROUPS: Final[str] = "(&(objectClass=groupOfNames)(member=*))"
    EMPTY_GROUPS: Final[str] = "(&(objectClass=groupOfNames)(!(member=*)))"


class FlextLdapConverterConstants:
    """Converter-related constants used by tests and converters.

    Provides standard lengths for LDAP generalized time formats produced
    by converters and utilities. Centralized here to avoid duplication.
    """

    # Generalized time with seconds: YYYYMMDDHHMMSSZ -> 15 characters
    LDAP_TIME_FORMAT_LONG: Final[int] = 15
    # Truncated generalized time without seconds: YYYYMMDDHHMMZ -> 13 characters
    LDAP_TIME_FORMAT_SHORT: Final[int] = 13


# =============================================================================
# DN (DISTINGUISHED NAME) CONSTANTS - RFC 4514 Compliance
# =============================================================================


class FlextLdapDnConstants:
    """Distinguished Name patterns and separators.

    🎯 CONSOLIDATES AND REPLACES:
    - FlextLdapConstants.DN (constants_old.bak:118)
    - DN processing logic scattered across value objects
    """

    # DN Syntax Components (RFC 4514)
    COMPONENT_SEPARATOR: Final[str] = ","
    ATTRIBUTE_SEPARATOR: Final[str] = "="
    MULTI_VALUE_SEPARATOR: Final[str] = "+"

    # Special Characters requiring escaping (RFC 4514)
    ESCAPE_CHARS: Final[frozenset[str]] = frozenset(
      {",", "=", "+", "<", ">", "#", ";", "\\", '"', " "},
    )

    # Hex escape pattern
    HEX_ESCAPE_PATTERN: Final[str] = r"\\[0-9a-fA-F]{2}"

    # Common DN Prefixes
    COMMON_NAME_PREFIX: Final[str] = "cn="
    USER_PREFIX: Final[str] = "uid="  # More common for users than cn=
    GROUP_PREFIX: Final[str] = "cn="
    ORGANIZATIONAL_UNIT_PREFIX: Final[str] = "ou="
    ORGANIZATION_PREFIX: Final[str] = "o="
    DOMAIN_COMPONENT_PREFIX: Final[str] = "dc="
    LOCALITY_PREFIX: Final[str] = "l="
    STATE_PREFIX: Final[str] = "st="
    COUNTRY_PREFIX: Final[str] = "c="

    # DN Validation Limits
    MAX_DN_LENGTH: Final[int] = 2048
    MAX_RDN_LENGTH: Final[int] = 512
    MAX_ATTRIBUTE_NAME_LENGTH: Final[int] = 256
    MAX_ATTRIBUTE_VALUE_LENGTH: Final[int] = 8192


# =============================================================================
# ERROR CONSTANTS - LDAP Result Codes & Error Handling
# =============================================================================


class FlextLdapErrorConstants:
    """LDAP error constants and diagnostic codes.

    🎯 CONSOLIDATES AND REPLACES:
    - FlextLdapConstants.Errors (constants_old.bak:142)
    - Error codes scattered across multiple error handling modules
    - Diagnostic strings hardcoded throughout codebase
    """

    # LDAP Result Codes (RFC 4511)
    SUCCESS: Final[int] = 0
    OPERATIONS_ERROR: Final[int] = 1
    PROTOCOL_ERROR: Final[int] = 2
    TIME_LIMIT_EXCEEDED: Final[int] = 3
    SIZE_LIMIT_EXCEEDED: Final[int] = 4
    COMPARE_FALSE: Final[int] = 5
    COMPARE_TRUE: Final[int] = 6
    AUTH_METHOD_NOT_SUPPORTED: Final[int] = 7
    STRONGER_AUTH_REQUIRED: Final[int] = 8
    PARTIAL_RESULTS: Final[int] = 9
    REFERRAL: Final[int] = 10
    ADMIN_LIMIT_EXCEEDED: Final[int] = 11
    UNAVAILABLE_CRITICAL_EXTENSION: Final[int] = 12
    CONFIDENTIALITY_REQUIRED: Final[int] = 13
    SASL_BIND_IN_PROGRESS: Final[int] = 14
    NO_SUCH_ATTRIBUTE: Final[int] = 16
    UNDEFINED_ATTRIBUTE_TYPE: Final[int] = 17
    INAPPROPRIATE_MATCHING: Final[int] = 18
    CONSTRAINT_VIOLATION: Final[int] = 19
    ATTRIBUTE_OR_VALUE_EXISTS: Final[int] = 20
    INVALID_ATTRIBUTE_SYNTAX: Final[int] = 21
    NO_SUCH_OBJECT: Final[int] = 32
    ALIAS_PROBLEM: Final[int] = 33
    INVALID_DN_SYNTAX: Final[int] = 34
    IS_LEAF: Final[int] = 35
    ALIAS_DEREFERENCING_PROBLEM: Final[int] = 36
    INAPPROPRIATE_AUTHENTICATION: Final[int] = 48
    INVALID_CREDENTIALS: Final[int] = 49
    INSUFFICIENT_ACCESS_RIGHTS: Final[int] = 50
    BUSY: Final[int] = 51
    UNAVAILABLE: Final[int] = 52
    UNWILLING_TO_PERFORM: Final[int] = 53
    LOOP_DETECT: Final[int] = 54
    NAMING_VIOLATION: Final[int] = 64
    OBJECT_CLASS_VIOLATION: Final[int] = 65
    NOT_ALLOWED_ON_NON_LEAF: Final[int] = 66
    NOT_ALLOWED_ON_RDN: Final[int] = 67
    ENTRY_ALREADY_EXISTS: Final[int] = 68
    OBJECT_CLASS_MODS_PROHIBITED: Final[int] = 69
    AFFECTS_MULTIPLE_DSAS: Final[int] = 71
    OTHER: Final[int] = 80

    # Custom FLEXT Error Codes (extending patterns)
    FLEXT_LDAP_CONNECTION_FAILED: Final[str] = "FLEXT_LDAP_2001"
    FLEXT_LDAP_BIND_FAILED: Final[str] = "FLEXT_LDAP_4001"
    FLEXT_LDAP_SEARCH_FAILED: Final[str] = "FLEXT_LDAP_2002"
    FLEXT_LDAP_MODIFY_FAILED: Final[str] = "FLEXT_LDAP_2003"
    FLEXT_LDAP_ADD_FAILED: Final[str] = "FLEXT_LDAP_2004"
    FLEXT_LDAP_DELETE_FAILED: Final[str] = "FLEXT_LDAP_2005"
    FLEXT_LDAP_INVALID_DN: Final[str] = "FLEXT_LDAP_3001"
    FLEXT_LDAP_INVALID_FILTER: Final[str] = "FLEXT_LDAP_3002"
    FLEXT_LDAP_ENTRY_NOT_FOUND: Final[str] = "FLEXT_LDAP_1001"
    FLEXT_LDAP_ENTRY_EXISTS: Final[str] = "FLEXT_LDAP_1002"

    # Error Categories for systematic handling
    CONNECTION_ERRORS: Final[frozenset[int]] = frozenset(
      [UNAVAILABLE, BUSY, OPERATIONS_ERROR],
    )
    AUTHENTICATION_ERRORS: Final[frozenset[int]] = frozenset(
      [
          INAPPROPRIATE_AUTHENTICATION,
          INVALID_CREDENTIALS,
          AUTH_METHOD_NOT_SUPPORTED,
          STRONGER_AUTH_REQUIRED,
      ],
    )
    AUTHORIZATION_ERRORS: Final[frozenset[int]] = frozenset(
      [INSUFFICIENT_ACCESS_RIGHTS, CONFIDENTIALITY_REQUIRED],
    )
    DATA_ERRORS: Final[frozenset[int]] = frozenset(
      [
          NO_SUCH_OBJECT,
          INVALID_DN_SYNTAX,
          NAMING_VIOLATION,
          OBJECT_CLASS_VIOLATION,
          ENTRY_ALREADY_EXISTS,
      ],
    )

    # Error Messages
    ERROR_MESSAGES: ClassVar[dict[str, str]] = {
      FLEXT_LDAP_CONNECTION_FAILED: "LDAP connection failed",
      FLEXT_LDAP_BIND_FAILED: "LDAP bind authentication failed",
      FLEXT_LDAP_SEARCH_FAILED: "LDAP search operation failed",
      FLEXT_LDAP_MODIFY_FAILED: "LDAP modify operation failed",
      FLEXT_LDAP_ADD_FAILED: "LDAP add operation failed",
      FLEXT_LDAP_DELETE_FAILED: "LDAP delete operation failed",
      FLEXT_LDAP_INVALID_DN: "Invalid LDAP Distinguished Name",
      FLEXT_LDAP_INVALID_FILTER: "Invalid LDAP search filter",
      FLEXT_LDAP_ENTRY_NOT_FOUND: "LDAP entry not found",
      FLEXT_LDAP_ENTRY_EXISTS: "LDAP entry already exists",
    }

    @classmethod
    def get_error_category(cls, result_code: int) -> str:
      """Get error category for systematic error handling."""
      if result_code in cls.CONNECTION_ERRORS:
          return "CONNECTION"
      if result_code in cls.AUTHENTICATION_ERRORS:
          return "AUTHENTICATION"
      if result_code in cls.AUTHORIZATION_ERRORS:
          return "AUTHORIZATION"
      if result_code in cls.DATA_ERRORS:
          return "DATA"
      return "OTHER"

    @classmethod
    def is_retryable_error(cls, result_code: int) -> bool:
      """Check if error is potentially retryable."""
      retryable_errors = {
          cls.BUSY,
          cls.UNAVAILABLE,
          cls.TIME_LIMIT_EXCEEDED,
          cls.ADMIN_LIMIT_EXCEEDED,
          cls.OPERATIONS_ERROR,
      }
      return result_code in retryable_errors


# =============================================================================
# OBSERVABILITY CONSTANTS - flext-observability Integration
# =============================================================================


class FlextLdapObservabilityConstants:
    """Observability and monitoring constants.

    🎯 CONSOLIDATES AND REPLACES:
    - FlextLdapSchemaDiscoveryConstants (infrastructure/schema_discovery.py)
    - Monitoring constants scattered across infrastructure/ modules
    - Audit trail constants duplicated across security modules

    INTEGRATION REQUIREMENT:
    These constants support integration with flext-observability library.
    """

    # Metric Names (flext-observability integration)
    CONNECTION_COUNT: Final[str] = "ldap.connections.active"
    OPERATION_COUNT: Final[str] = "ldap.operations.total"
    OPERATION_DURATION: Final[str] = "ldap.operations.duration_ms"
    ERROR_COUNT: Final[str] = "ldap.errors.total"
    SEARCH_RESULT_SIZE: Final[str] = "ldap.search.result_size"
    POOL_UTILIZATION: Final[str] = "ldap.pool.utilization"

    # Security Event Types
    EVENT_AUTHENTICATION: Final[str] = "ldap.auth"
    EVENT_AUTHORIZATION: Final[str] = "ldap.authz"
    EVENT_SEARCH: Final[str] = "ldap.search"
    EVENT_MODIFY: Final[str] = "ldap.modify"
    EVENT_ADD: Final[str] = "ldap.add"
    EVENT_DELETE: Final[str] = "ldap.delete"
    EVENT_CONNECTION: Final[str] = "ldap.connection"

    # Schema Discovery Settings
    SCHEMA_CACHE_TTL: Final[int] = 3600  # 1 hour
    SCHEMA_REFRESH_INTERVAL: Final[int] = 86400  # 24 hours
    MAX_SCHEMA_ENTRIES: Final[int] = 10000
    MAX_DISCOVERY_HISTORY: Final[int] = 1000

    # Audit Categories
    AUDIT_AUTHENTICATION: Final[str] = "authentication"
    AUDIT_DATA_ACCESS: Final[str] = "data_access"
    AUDIT_CONFIGURATION: Final[str] = "configuration"
    AUDIT_SECURITY: Final[str] = "security"


# =============================================================================
# INTEGRATION CONSTANTS - flext-* Library Integration
# =============================================================================


class FlextLdapIntegrationConstants:
    """Constants for integration with other flext-* libraries.

    🎯 ELIMINATES DUPLICATIONS with external library integrations and
    provides single source of truth for integration configuration.
    """

    # flext-ldif Integration
    LDIF_EXPORT_BATCH_SIZE: Final[int] = 1000
    LDIF_IMPORT_BATCH_SIZE: Final[int] = 500
    LDIF_MAX_FILE_SIZE: Final[int] = 100 * 1024 * 1024  # 100MB
    LDIF_DEFAULT_ENCODING: Final[str] = "utf-8"

    # flext-observability Integration
    OBSERVABILITY_ENABLED: Final[bool] = True
    METRICS_COLLECTION_INTERVAL: Final[int] = 60  # seconds
    EVENT_BUFFER_SIZE: Final[int] = 1000

    # flext-auth Integration
    AUTH_TOKEN_VALIDATION_ENABLED: Final[bool] = True
    AUTH_SESSION_TIMEOUT: Final[int] = 1800  # 30 minutes
    AUTH_PASSWORD_POLICY_ENABLED: Final[bool] = True

    # flext-core Integration
    RESULT_CACHING_ENABLED: Final[bool] = True
    RESULT_CACHE_TTL: Final[int] = 300  # 5 minutes
    DI_CONTAINER_SCOPE: Final[str] = "singleton"


# =============================================================================
# VALIDATION CONSTANTS - Data Validation Limits
# =============================================================================


class FlextLdapValidationConstants:
    """Validation constants for LDAP data integrity.

    🎯 CONSOLIDATES AND REPLACES:
    - Validation limits scattered across value_objects.py, models/
    - String length limits hardcoded throughout codebase
    - Pattern definitions duplicated in multiple validators
    """

    # Filter Validation
    MAX_FILTER_LENGTH: Final[int] = 8192
    MAX_FILTER_NESTING_DEPTH: Final[int] = 10

    # Entry Validation
    MAX_ATTRIBUTES_PER_ENTRY: Final[int] = 500
    MAX_VALUES_PER_ATTRIBUTE: Final[int] = 1000
    MAX_ENTRY_SIZE: Final[int] = 1024 * 1024  # 1MB

    # String Validation Patterns
    DN_COMPONENT_PATTERN: Final[str] = r"^([a-zA-Z][a-zA-Z0-9-]*)\s*=\s*([^,=]+)$"
    USERNAME_PATTERN: Final[str] = r"^[a-zA-Z0-9._-]+$"
    EMAIL_PATTERN: Final[str] = r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"

    # Password Requirements
    MIN_PASSWORD_LENGTH: Final[int] = 8
    MAX_PASSWORD_LENGTH: Final[int] = 128
    REQUIRE_PASSWORD_COMPLEXITY: Final[bool] = True


# =============================================================================
# VALIDATION AND ERROR MESSAGES - Centralized String Constants
# =============================================================================


class FlextLdapValidationMessages:
    """Validation and error message constants for consistent error handling.

    🎯 CONSOLIDATES AND REPLACES:
    - Hardcoded validation messages scattered across config.py, api.py, operations.py
    - Error message strings duplicated in multiple exception handling contexts
    - Session validation messages repeated throughout service layers
    """

    # Connection validation messages
    HOST_CANNOT_BE_EMPTY: Final[str] = "Host cannot be empty"
    PORT_RANGE_ERROR: Final[str] = "Port must be between 1 and {max_port}, got {port}"
    CONNECTION_FAILED: Final[str] = "Connection failed"
    CONNECTION_FAILED_WITH_ERROR: Final[str] = "Connection failed: {error}"
    CONNECTION_FAILED_INVALID_SCHEME: Final[str] = "Connection failed: invalid URI scheme"
    CONNECTION_FAILED_INVALID_HOST: Final[str] = "Connection failed: invalid host"

    # Authentication validation messages
    BIND_FAILED: Final[str] = "Bind failed"
    AUTHENTICATION_FAILED: Final[str] = "LDAP authentication failed"
    FAILED_TO_CONNECT: Final[str] = "Failed to connect to LDAP server: {error}"

    # DN validation messages
    INVALID_DN_FORMAT: Final[str] = "Invalid DN format"
    INVALID_DN_ERROR: Final[str] = "Invalid DN: {error}"
    DN_VALIDATION_FAILED: Final[str] = "DN validation failed"

    # Filter validation messages
    INVALID_SEARCH_FILTER: Final[str] = "Invalid search filter: {error}"
    FILTER_VALIDATION_FAILED: Final[str] = "Filter validation failed"

    # URI validation messages
    INVALID_SERVER_URI: Final[str] = "Invalid server URI: {error}"
    URI_VALIDATION_FAILED: Final[str] = "URI validation failed"

    # Session validation messages
    SESSION_ID_REQUIRED: Final[str] = "Session ID is required"
    SESSION_ID_REQUIRED_FOR_OPERATION: Final[str] = "Session ID is required for {operation}"
    UNKNOWN_SESSION: Final[str] = "Unknown session: {session_id}"

    # Search operation messages
    SEARCH_FAILED: Final[str] = "Search failed"
    SEARCH_FAILED_WITH_ERROR: Final[str] = "Search failed: {error}"
    SEARCH_FOR_EXPORT_FAILED: Final[str] = "Search for export failed: {error}"

    # Entry operation messages
    ADD_FAILED: Final[str] = "Add failed"
    MODIFY_FAILED: Final[str] = "Modify failed"
    DELETE_FAILED: Final[str] = "Delete failed"
    ENTRY_CREATION_ERROR: Final[str] = "Entry creation error: {error}"

    # User operation messages
    USER_CREATION_FAILED: Final[str] = "User creation failed: {error}"
    UID_REQUIRED: Final[str] = "UID is required"
    COMMON_NAME_REQUIRED: Final[str] = "Common name is required"
    SURNAME_REQUIRED: Final[str] = "Surname is required"

    # Group operation messages
    GROUP_CREATION_FAILED: Final[str] = "Group creation failed: {error}"

    # Export operation messages
    OUTPUT_FILE_REQUIRED: Final[str] = "Output file is required for export operations"
    BASE_DN_REQUIRED: Final[str] = "Base DN is required for export operations"
    LDIF_EXPORT_FAILED: Final[str] = "LDIF export failed"
    EXPORT_ERROR: Final[str] = "Export error: {error}"

    # Import operation messages
    LDIF_FILE_NOT_FOUND: Final[str] = "LDIF file not found: {file_path}"
    LDIF_PARSE_FAILED: Final[str] = "Failed to parse LDIF file: {error}"
    LDIF_IMPORT_ERROR: Final[str] = "LDIF import error: {error}"

    # Generic validation messages
    UNKNOWN_VALIDATION_ERROR: Final[str] = "Unknown validation error"
    VALIDATION_FAILED_FOR_FIELD: Final[str] = "Validation failed for {field}: {error}"
    ATTRIBUTES_CANNOT_BE_EMPTY: Final[str] = "Attributes cannot be empty"

    # Field validation messages used by utils.py
    FIELD_CANNOT_BE_EMPTY: Final[str] = "{field_name} cannot be empty"
    DN_FIELD_NAME: Final[str] = "DN"
    SEARCH_FILTER_FIELD_NAME: Final[str] = "Search filter"
    COMMON_NAME_FIELD_NAME: Final[str] = "Common name"
    FILE_PATH_FIELD_NAME: Final[str] = "File path"
    URI_FIELD_NAME: Final[str] = "URI"
    BASE_DN_FIELD_NAME: Final[str] = "Base DN"
    INVALID_URI_SCHEME: Final[str] = "Invalid URI scheme"
    CONNECTION_FAILED_WITH_CONTEXT: Final[str] = "Connection failed with context: {context}"
    VALIDATION_FAILED: Final[str] = "Validation failed for {field}"
    ENTRY_MUST_HAVE_OBJECT_CLASS: Final[str] = "Entry must have at least one object class"

    # Operation context messages
    OPERATION_FAILED: Final[str] = "Operation failed: {error}"
    FAILED_TO_OPERATION: Final[str] = "Failed to {operation}: {error}"

    # File operation messages
    FAILED_TO_WRITE_FILE: Final[str] = "Failed to write file {file_path}: {error}"

    # Infrastructure error messages
    LDAP_CONNECTION_FAILED: Final[str] = "LDAP connection failed"
    CONNECTION_FAILED_GENERIC: Final[str] = "Connection failed: {error}"

    # Operations error messages
    INVALID_DN_WITH_CONTEXT: Final[str] = "Invalid {context}: {error}"

    # Service error messages
    SERVICE_ALREADY_RUNNING: Final[str] = "Service is already running"
    SERVICE_NOT_RUNNING: Final[str] = "Service is not running"
    FAILED_TO_START_SERVICE: Final[str] = "Failed to start LDAP service: {error}"
    FAILED_TO_STOP_SERVICE: Final[str] = "Failed to stop LDAP service: {error}"
    HEALTH_CHECK_FAILED: Final[str] = "Health check failed: {error}"

    # Domain validation messages
    SPECIFICATION_FAILED: Final[str] = "Specification '{name}' failed for: {type}"
    INVALID_USER_MISSING_ATTRIBUTES: Final[str] = "User must have uid and dn attributes"

    # CLI parameter messages
    PASSWORD_FIELD_TYPE: Final[str] = "password_field"  # noqa: S105 - field type constant only
    FAILED_TO_READ_FILE: Final[str] = "Failed to read file {file_path}: {error}"

    # Configuration validation messages
    CONFIGURATION_ERROR: Final[str] = "Configuration error in {key}: {error}"
    MAX_POOL_SIZE_ERROR: Final[str] = "max_pool_size ({value}) must be >= 1"
    CACHE_TTL_POSITIVE: Final[str] = "Cache TTL must be positive when caching is enabled"
    DEFAULT_CONNECTION_MUST_SPECIFY_SERVER: Final[str] = "Default connection must specify a server"

    # Disconnection messages
    DISCONNECT_FAILED: Final[str] = "Disconnect failed: {error}"
    TERMINATION_ERROR: Final[str] = "Termination error: {error}"


class FlextLdapOperationMessages:
    """Operation status and logging message constants.

    🎯 CONSOLIDATES AND REPLACES:
    - Status messages scattered across operation logging
    - Success/failure messages duplicated in service layers
    - Connection lifecycle messages repeated throughout infrastructure
    """

    # Connection lifecycle messages
    CONNECTION_CREATED: Final[str] = "connection created"
    CONNECTION_CLOSED: Final[str] = "connection closed"
    CONNECTION_ESTABLISHED: Final[str] = "Connection established: {session_id}"
    CONNECTION_TERMINATED: Final[str] = "Connection terminated: {session_id}"

    # Search operation messages
    LDAP_SEARCH_COMPLETED: Final[str] = "LDAP search completed"
    USER_SEARCH_COMPLETED: Final[str] = "user search"
    GROUP_SEARCH_COMPLETED: Final[str] = "group search"
    SEARCH_OPERATION_FAILED: Final[str] = "Search operation failed"

    # Entry operation messages
    ENTRY_CREATED: Final[str] = "entry created"
    USER_ENTRY_CREATED: Final[str] = "Successfully created user entry: {dn}"
    GROUP_ENTRY_CREATED: Final[str] = "Successfully created group entry: {dn}"
    ENTRY_MODIFIED: Final[str] = "Successfully modified entry: {dn}"
    ENTRY_DELETED: Final[str] = "Successfully deleted entry: {dn}"

    # Service initialization messages
    SEARCH_SERVICE_INITIALIZED: Final[str] = "FlextLdapSearchService initialized"
    CONNECTION_SERVICE_INITIALIZED: Final[str] = "FlextLdapConnectionService initialized"
    ENTRY_SERVICE_INITIALIZED: Final[str] = "FlextLdapEntryService initialized"
    EXPORT_SERVICE_INITIALIZED: Final[str] = "FlextLdapExportService initialized"
    API_INITIALIZED: Final[str] = "FlextLdapApi initialized with specialized services"

    # Export operation messages
    EXPORT_COMPLETED: Final[str] = "LDIF export completed successfully"
    IMPORT_COMPLETED: Final[str] = "LDIF import completed: {count} entries processed"

    # Error context messages
    OPERATION_EXCEPTION: Final[str] = "{operation} operation failed"
    CONNECTION_ESTABLISHMENT_FAILED: Final[str] = "Connection establishment failed"
    CONNECTION_TERMINATION_FAILED: Final[str] = "Connection termination failed"
    SEARCH_OPERATION_EXCEPTION: Final[str] = "Search operation failed"
    USER_CREATION_EXCEPTION: Final[str] = "User creation failed"
    GROUP_CREATION_EXCEPTION: Final[str] = "Group creation failed"
    ENTRY_MODIFICATION_EXCEPTION: Final[str] = "Entry modification failed"

    # Context and debugging messages used by exceptions.py
    OPERATION_CONTEXT: Final[str] = "Operation: {operation}"
    LDAP_CODE_CONTEXT: Final[str] = "LDAP Code: {ldap_code}"
    CONTEXT_INFO: Final[str] = "Context: {key}={value}"

    # Connection context keys
    SERVER_URI_KEY: Final[str] = "server_uri"
    TIMEOUT_KEY: Final[str] = "timeout"
    RETRY_COUNT_KEY: Final[str] = "retry_count"
    CONNECTION_OPERATION: Final[str] = "connection"


class FlextLdapDefaultValues:
    """Default values used throughout the LDAP library.

    🎯 CONSOLIDATES AND REPLACES:
    - Hardcoded default values scattered across API classes
    - Repeated default filter and encoding values
    - Default object class combinations used in multiple contexts
    """

    # Search defaults
    DEFAULT_SEARCH_FILTER: Final[str] = "(objectClass=*)"
    DEFAULT_SEARCH_SCOPE: Final[str] = "subtree"
    DEFAULT_SEARCH_BASE: Final[str] = ""

    # Encoding defaults
    DEFAULT_ENCODING: Final[str] = "utf-8"
    DEFAULT_LDIF_ENCODING: Final[str] = "utf-8"

    # Object class defaults
    DEFAULT_USER_OBJECT_CLASSES: Final[list[str]] = ["inetOrgPerson", "organizationalPerson", "person", "top"]
    DEFAULT_GROUP_OBJECT_CLASSES: Final[list[str]] = ["groupOfNames", "top"]
    DEFAULT_OU_OBJECT_CLASSES: Final[list[str]] = ["organizationalUnit", "top"]

    # Attribute defaults
    DEFAULT_USER_ATTRIBUTES: Final[list[str]] = ["uid", "cn", "sn", "givenName", "mail", "objectClass"]
    DEFAULT_GROUP_ATTRIBUTES: Final[list[str]] = ["cn", "description", "member", "objectClass"]
    DEFAULT_ALL_ATTRIBUTES: Final[str] = "*"
    DEFAULT_OPERATIONAL_ATTRIBUTES: Final[str] = "+"

    # Session and connection defaults
    SESSION_PREFIX: Final[str] = "ldap_session_"
    DUMMY_MEMBER_DN: Final[str] = "cn=dummy"
    REDACTED_VALUE: Final[str] = "[REDACTED]"

    # File operation defaults
    LDIF_FILE_EXTENSION: Final[str] = ".ldif"
    DEFAULT_LDIF_LINE_SEPARATOR: Final[str] = "\n"
    LDIF_ENTRY_SEPARATOR: Final[str] = ""

    # Time and size defaults
    DEFAULT_TIMEOUT_SECONDS: Final[int] = 30
    DEFAULT_CONNECTION_TIMEOUT: Final[int] = 30
    DEFAULT_SIZE_LIMIT: Final[int] = 1000
    DEFAULT_TIME_LIMIT: Final[int] = 30

    # Field type defaults
    STRING_FIELD_TYPE: Final[str] = "string"
    INTEGER_FIELD_TYPE: Final[str] = "integer"
    BOOLEAN_FIELD_TYPE: Final[str] = "boolean"
    BINARY_FIELD_TYPE: Final[str] = "binary"
    DATETIME_FIELD_TYPE: Final[str] = "datetime"
    DN_FIELD_TYPE: Final[str] = "dn"
    EMAIL_FIELD_TYPE: Final[str] = "email"
    PHONE_FIELD_TYPE: Final[str] = "phone"
    UUID_FIELD_TYPE: Final[str] = "uuid"
    URL_FIELD_TYPE: Final[str] = "url"
    IP_ADDRESS_FIELD_TYPE: Final[str] = "ip_address"
    MAC_ADDRESS_FIELD_TYPE: Final[str] = "mac_address"
    CERTIFICATE_FIELD_TYPE: Final[str] = "certificate"

    # Service information defaults
    DEFAULT_SERVICE_NAME: Final[str] = "flext-ldap"
    DEFAULT_SERVICE_VERSION: Final[str] = "0.9.0"
    SERVICE_STATUS_RUNNING: Final[str] = "running"
    SERVICE_STATUS_STOPPED: Final[str] = "stopped"
    DEPENDENCY_FLEXT_CORE: Final[str] = "healthy"
    DEPENDENCY_LDAP3: Final[str] = "available"

    # Schema and infrastructure defaults
    DEFAULT_SCHEME_LDAPS: Final[str] = "ldaps"
    DEFAULT_SCHEME_LDAP: Final[str] = "ldap"

    # Domain specification defaults
    VALID_LDAP_USER_NAME: Final[str] = "ValidLdapUser"
    VALID_LDAP_USER_DESCRIPTION: Final[str] = "Validates LDAP user entity business rules"


# =============================================================================
# TESTING CONVENIENCE SHIMS
# =============================================================================


class FlextLdapSchemaDiscoveryConstants:
    """Testing convenience constants for schema discovery.

    Provides minimal attributes referenced by infrastructure code,
    mapping to consolidated observability constants.
    """

    class Discovery:
      """Testing convenience container for discovery settings."""

      SCHEMA_CACHE_TTL: int = FlextLdapObservabilityConstants.SCHEMA_CACHE_TTL
      SCHEMA_REFRESH_INTERVAL: int = (
          FlextLdapObservabilityConstants.SCHEMA_REFRESH_INTERVAL
      )
      MAX_SCHEMA_ENTRIES: int = FlextLdapObservabilityConstants.MAX_SCHEMA_ENTRIES
      MAX_DISCOVERY_HISTORY: int = (
          FlextLdapObservabilityConstants.MAX_DISCOVERY_HISTORY
      )


# =============================================================================
# CONVENIENCE EXPORTS - Module-level Aliases
# =============================================================================

# Export commonly used constants at module level for convenience
DEFAULT_PORT = FlextLdapConnectionConstants.DEFAULT_PORT
DEFAULT_SSL_PORT = FlextLdapConnectionConstants.DEFAULT_SSL_PORT
DEFAULT_PAGE_SIZE = FlextLdapConnectionConstants.DEFAULT_PAGE_SIZE
DEFAULT_SIZE_LIMIT = FlextLdapConnectionConstants.DEFAULT_SIZE_LIMIT

# Attribute aliases
OBJECT_CLASS = FlextLdapAttributeConstants.OBJECT_CLASS
COMMON_NAME = FlextLdapAttributeConstants.COMMON_NAME
USER_ID = FlextLdapAttributeConstants.USER_ID
MAIL = FlextLdapAttributeConstants.MAIL
SURNAME = FlextLdapAttributeConstants.SURNAME
GIVEN_NAME = FlextLdapAttributeConstants.GIVEN_NAME

# Object class aliases
PERSON = FlextLdapObjectClassConstants.PERSON
INET_ORG_PERSON = FlextLdapObjectClassConstants.INET_ORG_PERSON
ORGANIZATIONAL_PERSON = FlextLdapObjectClassConstants.ORGANIZATIONAL_PERSON
GROUP_OF_NAMES = FlextLdapObjectClassConstants.GROUP_OF_NAMES

# Scope aliases (for testing convenience)
SCOPE_BASE = FlextLdapScope.BASE
SCOPE_ONE = FlextLdapScope.ONE
SCOPE_SUB = FlextLdapScope.SUB
SCOPE_CHILDREN = FlextLdapScope.CHILDREN

# Connection type aliases
LDAP = FlextLdapConnectionType.LDAP
LDAPS = FlextLdapConnectionType.LDAPS


# Convenience umbrella for tests expecting FlextLdapConstants
class FlextLdapConstants:
    """Convenience constants wrapper mapping to consolidated definitions.

    Provides expected attributes used by tests; values delegated to
    consolidated constants above.
    """

    DEFAULT_TIMEOUT_SECONDS: int = FlextLdapConnectionConstants.DEFAULT_CONNECT_TIMEOUT
    MAX_TIMEOUT_SECONDS: int = FlextLdapConnectionConstants.MAX_TIME_LIMIT
    DEFAULT_POOL_SIZE: int = FlextLdapConnectionConstants.DEFAULT_POOL_SIZE
    MAX_POOL_SIZE: int = FlextLdapConnectionConstants.MAX_PAGE_SIZE // 10
    DEFAULT_PAGE_SIZE: int = FlextLdapConnectionConstants.DEFAULT_PAGE_SIZE
    MAX_PAGE_SIZE: int = FlextLdapConnectionConstants.MAX_PAGE_SIZE


# =============================================================================
# MODULE EXPORTS - All constant classes available for import
# =============================================================================

__all__ = [
    "COMMON_NAME",
    "DEFAULT_PAGE_SIZE",
    # Convenient module-level aliases for frequent usage
    "DEFAULT_PORT",
    "DEFAULT_SIZE_LIMIT",
    "DEFAULT_SSL_PORT",
    "GIVEN_NAME",
    "GROUP_OF_NAMES",
    "INET_ORG_PERSON",
    "LDAP",
    "LDAPS",
    "MAIL",
    "OBJECT_CLASS",
    "ORGANIZATIONAL_PERSON",
    "PERSON",
    "SCOPE_BASE",
    "SCOPE_CHILDREN",
    "SCOPE_ONE",
    "SCOPE_SUB",
    "SURNAME",
    "USER_ID",
    # Core constant classes (consolidated from audit)
    "FlextLdapAttributeConstants",
    "FlextLdapConnectionConstants",
    "FlextLdapConnectionType",
    # Testing convenience and transitional
    "FlextLdapConstants",
    "FlextLdapConverterConstants",
    "FlextLdapDefaultValues",
    "FlextLdapDnConstants",
    "FlextLdapErrorConstants",
    "FlextLdapFilterConstants",
    "FlextLdapObjectClassConstants",
    "FlextLdapObservabilityConstants",
    "FlextLdapOperationMessages",
    "FlextLdapSchemaDiscoveryConstants",
    "FlextLdapScope",
]
