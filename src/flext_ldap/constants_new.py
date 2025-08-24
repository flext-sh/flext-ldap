"""LDAP Constants - Single FlextLdapConstants class following FLEXT patterns.

Single class inheriting from FlextCoreConstants with all LDAP constants
organized as internal properties and methods for complete backward compatibility.

Examples:
    Basic usage with hierarchical constants::

        from flext_ldap.constants import FlextLdapConstants

        port = FlextLdapConstants.Connection.DEFAULT_LDAP_PORT
        timeout = FlextLdapConstants.Connection.DEFAULT_TIMEOUT
        scope = FlextLdapConstants.Search.SCOPE_SUBTREE

    Legacy compatibility::

        # All previous classes still work as properties
        protocol_consts = FlextLdapConstants.Protocol
        attr_consts = FlextLdapConstants.Attributes
        error_consts = FlextLdapConstants.Errors

"""

from __future__ import annotations

from enum import StrEnum
from typing import Final

from flext_core import FlextCoreConstants

# =============================================================================
# SINGLE FLEXT LDAP CONSTANTS CLASS - Inheriting from FlextCoreConstants
# =============================================================================


class FlextLdapConstants(FlextCoreConstants):
    """Single FlextLdapConstants class inheriting from FlextCoreConstants.
    
    Consolidates ALL LDAP constants into a single class following FLEXT patterns.
    Everything from the previous multiple constant classes is now available as
    internal properties with full backward compatibility.
    
    This class follows SOLID principles:
        - Single Responsibility: All LDAP constants in one place
        - Open/Closed: Extends FlextCoreConstants without modification
        - Liskov Substitution: Can be used anywhere FlextCoreConstants is expected
        - Interface Segregation: Organized by domain for specific access
        - Dependency Inversion: Depends on FlextCoreConstants abstraction
    
    Examples:
        Protocol constants::
        
            port = FlextLdapConstants.Protocol.DEFAULT_LDAP_PORT
            version = FlextLdapConstants.Protocol.LDAP_VERSION_3
            
        Connection constants::
        
            timeout = FlextLdapConstants.Connection.DEFAULT_TIMEOUT
            pool_size = FlextLdapConstants.Connection.DEFAULT_POOL_SIZE
            
        Attribute constants::
        
            attr = FlextLdapConstants.Attributes.COMMON_NAME
            mail = FlextLdapConstants.Attributes.MAIL

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
        """Connection and performance constants extending FlextCoreConstants."""

        # Base constants from flext-core (inherit from parent)
        DEFAULT_TIMEOUT: Final[int] = FlextCoreConstants.Defaults.TIMEOUT
        MAX_RETRIES: Final[int] = FlextCoreConstants.Defaults.MAX_RETRIES
        CONNECTION_TIMEOUT: Final[int] = FlextCoreConstants.Defaults.CONNECTION_TIMEOUT
        DEFAULT_HOST: Final[str] = FlextCoreConstants.Infrastructure.DEFAULT_HOST

        # LDAP-specific connection settings
        DEFAULT_PORT: Final[int] = 389
        DEFAULT_SSL_PORT: Final[int] = 636
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
        USER_PASSWORD: Final[str] = "userPassword"  # noqa: S105
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

    # =========================================================================
    # LEGACY COMPATIBILITY PROPERTIES - Backward Compatibility
    # =========================================================================

    @classmethod
    @property
    def FlextLdapProtocolConstants(cls) -> type[Protocol]:
        """Legacy compatibility for FlextLdapProtocolConstants."""
        return cls.Protocol

    @classmethod
    @property
    def FlextLdapConnectionConstants(cls) -> type[Connection]:
        """Legacy compatibility for FlextLdapConnectionConstants."""
        return cls.Connection

    @classmethod
    @property
    def FlextLdapAttributeConstants(cls) -> type[Attributes]:
        """Legacy compatibility for FlextLdapAttributeConstants."""
        return cls.Attributes


# =============================================================================
# SCOPE ENUMERATION - LDAP Search Scopes
# =============================================================================


class FlextLdapScope(StrEnum):
    """LDAP search scope enumeration (RFC 4511).
    
    Consolidates and replaces scattered scope definitions throughout codebase.
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


# =============================================================================
# MODULE EXPORTS - Backward Compatibility
# =============================================================================

# Legacy class aliases for backward compatibility
FlextLdapProtocolConstants = FlextLdapConstants.Protocol
FlextLdapConnectionConstants = FlextLdapConstants.Connection
FlextLdapAttributeConstants = FlextLdapConstants.Attributes

# Convenient module-level aliases for frequent usage
DEFAULT_PORT = FlextLdapConstants.Connection.DEFAULT_PORT
DEFAULT_SSL_PORT = FlextLdapConstants.Connection.DEFAULT_SSL_PORT
DEFAULT_PAGE_SIZE = FlextLdapConstants.Connection.DEFAULT_PAGE_SIZE
OBJECT_CLASS = FlextLdapConstants.Attributes.OBJECT_CLASS
COMMON_NAME = FlextLdapConstants.Attributes.COMMON_NAME
USER_ID = FlextLdapConstants.Attributes.USER_ID
MAIL = FlextLdapConstants.Attributes.MAIL

__all__ = [
    "FlextLdapConstants",
    "FlextLdapScope",
    # Legacy compatibility
    "FlextLdapProtocolConstants",
    "FlextLdapConnectionConstants",
    "FlextLdapAttributeConstants",
    # Convenient aliases
    "DEFAULT_PORT",
    "DEFAULT_SSL_PORT",
    "DEFAULT_PAGE_SIZE",
    "OBJECT_CLASS",
    "COMMON_NAME",
    "USER_ID",
    "MAIL",
]
