"""LDAP Constants - Single FlextLDAPConstants class following FLEXT patterns.

Single class inheriting from FlextConstants with all LDAP constants
organized as internal properties and methods for complete backward compatibility.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import Final

from flext_core import FlextConstants, FlextTypes
from flext_core.typings import FlextTypes


class FlextLDAPConstants(FlextConstants):
    """Single FlextLDAPConstants class inheriting from FlextConstants.

    Consolidates ALL LDAP constants into a single class following FLEXT patterns.
    Everything from the previous multiple constant classes is now available as
    internal properties with full backward compatibility.

    """

    # =========================================================================
    # PROTOCOL CONSTANTS - RFC 4510-4519 LDAP Standards
    # =========================================================================

    class Protocol:
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

    # =========================================================================
    # CONNECTION CONSTANTS - Performance and Configuration
    # =========================================================================

    class Connection:
        """Connection and performance constants extending FlextConstants."""

        # Base constants from flext-core (inherit from parent)
        DEFAULT_TIMEOUT: Final[int] = FlextConstants.Defaults.TIMEOUT
        MAX_RETRIES: Final[int] = FlextConstants.Defaults.MAX_RETRIES
        CONNECTION_TIMEOUT: Final[int] = FlextConstants.Defaults.CONNECTION_TIMEOUT
        DEFAULT_HOST: Final[str] = FlextConstants.Infrastructure.DEFAULT_HOST

        # LDAP-specific connection settings
        DEFAULT_PORT: Final[int] = 389
        DEFAULT_SSL_PORT: Final[int] = 636
        MAX_PORT: Final[int] = 65535
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

    # =========================================================================
    # ATTRIBUTE CONSTANTS - Standard LDAP Schema Attributes
    # =========================================================================

    class Attributes:
        """Standard LDAP attribute names from various RFCs and schemas."""

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
        USER_PASSWORD: Final[str] = "userPassword"
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

        @classmethod
        def get_person_attributes(cls) -> FlextTypes.Core.StringList:
            """Get standard person-related attributes.

            Returns:
                FlextTypes.Core.StringList: List of standard person attributes.

            """
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
        def get_group_attributes(cls) -> FlextTypes.Core.StringList:
            """Get standard group-related attributes.

            Returns:
                FlextTypes.Core.StringList: List of standard group attributes.

            """
            return [
                cls.OBJECT_CLASS,
                cls.COMMON_NAME,
                cls.DESCRIPTION,
                cls.MEMBER,
                cls.UNIQUE_MEMBER,
                cls.OWNER,
            ]

    # =========================================================================
    # VALIDATION CONSTANTS - Messages and Rules
    # =========================================================================

    class LdapValidation:
        """Validation constants for LDAP data integrity."""

        MAX_FILTER_LENGTH: Final[int] = 8192
        MAX_FILTER_NESTING_DEPTH: Final[int] = 10
        MIN_PASSWORD_LENGTH: Final[int] = 8
        MAX_PASSWORD_LENGTH: Final[int] = 128
        MIN_DN_PARTS: Final[int] = 2
        REQUIRE_PASSWORD_COMPLEXITY: Final[bool] = True
        EMAIL_PATTERN: Final[str] = r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"

    class ValidationMessages:
        """Validation and error message constants."""

        # Core field validation messages
        HOST_CANNOT_BE_EMPTY: Final[str] = "Host cannot be empty"
        CONNECTION_FAILED: Final[str] = "Connection failed"
        FIELD_CANNOT_BE_EMPTY: Final[str] = "{0} cannot be empty"

        # Field names for validation messages
        DN_FIELD_NAME: Final[str] = "DN"
        SEARCH_FILTER_FIELD_NAME: Final[str] = "Search Filter"
        COMMON_NAME_FIELD_NAME: Final[str] = "Common Name"
        FILE_PATH_FIELD_NAME: Final[str] = "File Path"
        URI_FIELD_NAME: Final[str] = "URI"
        BASE_DN_FIELD_NAME: Final[str] = "Base DN"

        # Error format messages
        INVALID_URI_SCHEME: Final[str] = "Invalid URI scheme"
        INVALID_DN_FORMAT: Final[str] = "Invalid DN format"
        INVALID_DN_WITH_CONTEXT: Final[str] = "Invalid DN format: {0}"
        INVALID_SEARCH_FILTER: Final[str] = "Invalid LDAP search filter"
        CONNECTION_FAILED_WITH_CONTEXT: Final[str] = "Connection failed: {0}"
        OPERATION_FAILED: Final[str] = "Operation {0} failed"
        VALIDATION_FAILED: Final[str] = "Validation failed for {0}"
        UNKNOWN_VALIDATION_ERROR: Final[str] = "Unknown validation error occurred"

    # =========================================================================
    # OPERATION CONSTANTS - Messages and Context
    # =========================================================================

    class Operations:
        """Operation status and logging message constants."""

        CONNECTION_OPERATION: Final[str] = "connection"
        LDAP_CODE_CONTEXT: Final[str] = "LDAP Code: {ldap_code}"
        OPERATION_CONTEXT: Final[str] = "Operation: {operation}"
        CONTEXT_INFO: Final[str] = "Context: {context}"

        # Context dictionary keys
        SERVER_URI_KEY: Final[str] = "server_uri"
        TIMEOUT_KEY: Final[str] = "timeout"
        RETRY_COUNT_KEY: Final[str] = "retry_count"

    # =========================================================================
    # OBJECT CLASS CONSTANTS - Standard LDAP Object Classes
    # =========================================================================

    class ObjectClasses:
        """Standard LDAP object classes."""

        TOP: Final[str] = "top"
        PERSON: Final[str] = "person"
        INET_ORG_PERSON: Final[str] = "inetOrgPerson"
        GROUP_OF_NAMES: Final[str] = "groupOfNames"

    # =========================================================================
    # SCOPE CONSTANTS - LDAP Search Scopes
    # =========================================================================

    class Scopes:
        """LDAP search scope constants (RFC 4511)."""

        BASE: Final[str] = "base"
        ONE: Final[str] = "onelevel"
        SUB: Final[str] = "subtree"

    # =========================================================================
    # DEFAULT VALUES CONSTANTS - Configuration and Type Defaults
    # =========================================================================

    class DefaultValues:
        """Default values used throughout the LDAP library."""

        # Search defaults
        DEFAULT_SEARCH_FILTER: Final[str] = "(objectClass=*)"
        DEFAULT_SEARCH_BASE: Final[str] = ""
        DEFAULT_PAGE_SIZE: Final[int] = 100
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
        DEFAULT_SERVICE_VERSION: Final[str] = "1.0.0"
        DEFAULT_USER_AGENT: Final[str] = "FlextLDAP/1.0.0"

        # User specification defaults
        VALID_LDAP_USER_NAME: Final[str] = "valid_user"
        VALID_LDAP_USER_DESCRIPTION: Final[str] = "Valid LDAP user"


# =============================================================================
# MODULE EXPORTS - FLEXT-CORE PATTERN
# =============================================================================

__all__ = [
    "FlextLDAPConstants",
]
