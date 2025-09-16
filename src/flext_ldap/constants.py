"""LDAP Constants - SOURCE OF TRUTH using FlextConstants.LDAP exclusively.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import Final, final

from flext_core import FlextConstants


@final
class FlextLDAPConstants(FlextConstants):
    """LDAP Constants using SOURCE OF TRUTH pattern - FlextConstants.LDAP exclusively."""

    # LDAP constants - defined directly since FlextConstants.LDAP doesn't exist
    class LDAP:
        """Standard LDAP constants."""

        # Standard LDAP ports
        DEFAULT_PORT = 389
        DEFAULT_SSL_PORT = 636

        # Standard LDAP timeouts
        DEFAULT_TIMEOUT = 30

        # Standard LDAP protocols
        PROTOCOL_LDAP = "ldap"
        PROTOCOL_LDAPS = "ldaps"

        # Standard LDAP URIs - SINGLE SOURCE OF TRUTH
        DEFAULT_SERVER_URI = "ldap://localhost"
        DEFAULT_SSL_SERVER_URI = "ldaps://localhost"
        DEFAULT_TEST_SERVER_URI = "ldap://localhost"

        # Standard LDAP pool settings
        DEFAULT_POOL_SIZE = 5
        DEFAULT_TEST_PORT = 3389

        # Standard LDAP scopes
        SCOPE_BASE = "base"
        SCOPE_ONELEVEL = "onelevel"
        SCOPE_SUBTREE = "subtree"

        # Standard LDAP object classes
        OBJECT_CLASS_PERSON = "person"
        OBJECT_CLASS_ORGANIZATIONAL_PERSON = "organizationalPerson"
        OBJECT_CLASS_INET_ORG_PERSON = "inetOrgPerson"
        OBJECT_CLASS_GROUP = "group"
        OBJECT_CLASS_GROUP_OF_NAMES = "groupOfNames"
        OBJECT_CLASS_GROUP_OF_UNIQUE_NAMES = "groupOfUniqueNames"

        # Standard LDAP attributes
        ATTR_CN = "cn"
        ATTR_SN = "sn"
        ATTR_GIVEN_NAME = "givenName"
        ATTR_MAIL = "mail"
        ATTR_UID = "uid"
        ATTR_USER_PASSWORD = "userPassword"  # nosec B105 - LDAP attribute name, not password
        ATTR_OBJECT_CLASS = "objectClass"
        ATTR_DISTINGUISHED_NAME = "distinguishedName"

    # =========================================================================
    # LDAP-SPECIFIC EXTENSIONS - Only what FlextConstants.LDAP doesn't provide
    # =========================================================================

    class Attributes:
        """Standard LDAP attribute names - only non-standard extensions."""

        # Core Attributes (use SOURCE OF TRUTH patterns)
        OBJECT_CLASS: Final[str] = "objectClass"
        COMMON_NAME: Final[str] = "cn"
        SURNAME: Final[str] = "sn"
        GIVEN_NAME: Final[str] = "givenName"
        DISPLAY_NAME: Final[str] = "displayName"
        DESCRIPTION: Final[str] = "description"
        USER_ID: Final[str] = "uid"
        MAIL: Final[str] = "mail"
        USER_PASSWORD: Final[str] = "userPassword"  # nosec B105 - LDAP attribute name, not password

        # Group Attributes
        MEMBER: Final[str] = "member"
        UNIQUE_MEMBER: Final[str] = "uniqueMember"
        MEMBER_OF: Final[str] = "memberOf"
        OWNER: Final[str] = "owner"

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
                cls.DESCRIPTION,
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

    class ObjectClasses:
        """Standard LDAP object classes."""

        TOP: Final[str] = "top"
        PERSON: Final[str] = "person"
        INET_ORG_PERSON: Final[str] = "inetOrgPerson"
        GROUP_OF_NAMES: Final[str] = "groupOfNames"

    class ValidationMessages:
        """Validation and error message constants."""

        HOST_CANNOT_BE_EMPTY: Final[str] = "Host cannot be empty"
        CONNECTION_FAILED: Final[str] = "Connection failed"
        FIELD_CANNOT_BE_EMPTY: Final[str] = "{0} cannot be empty"
        INVALID_DN_FORMAT: Final[str] = "Invalid DN format"
        INVALID_SEARCH_FILTER: Final[str] = "Invalid LDAP search filter"
        CONNECTION_FAILED_WITH_CONTEXT: Final[str] = "Connection failed: {0}"
        OPERATION_FAILED: Final[str] = "Operation {0} failed"

    class Operations:
        """Operation status and logging message constants."""

        CONNECTION_OPERATION: Final[str] = "connection"
        LDAP_CODE_CONTEXT: Final[str] = "LDAP Code: {ldap_code}"
        OPERATION_CONTEXT: Final[str] = "Operation: {operation}"

    class DefaultValues:
        """Default values - minimal LDAP-specific only."""

        DEFAULT_SEARCH_FILTER: Final[str] = "(objectClass=*)"
        DEFAULT_SEARCH_BASE: Final[str] = ""
        DEFAULT_SERVICE_NAME: Final[str] = "flext-ldap"
        DEFAULT_SERVICE_VERSION: Final[str] = "1.0.0"

        # Field type constants
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

        # LDAP domain-specific constants
        VALID_LDAP_USER_NAME: Final[str] = "testuser"
        VALID_LDAP_USER_DESCRIPTION: Final[str] = "Test LDAP User"

    class Scopes:
        """LDAP search scope constants - string representation for LDAP protocol."""

        BASE: Final[str] = "base"
        ONE: Final[str] = "onelevel"
        SUB: Final[str] = "subtree"
        SUBTREE: Final[str] = "subtree"
        CHILDREN: Final[str] = "children"

        # Valid scopes set for validation
        VALID_SCOPES: Final[set[str]] = {
            BASE,
            "one",
            ONE,
            "sub",
            SUB,
            SUBTREE,
            CHILDREN,
        }

        # Mapping from flext-core integer scopes to string scopes
        SCOPE_INT_TO_STRING: Final[dict[str, str]] = {
            "base": BASE,
            "one": ONE,
            "sub": SUB,
        }

    class Connection:
        """LDAP connection constants."""

        MAX_SIZE_LIMIT: Final[int] = 1000

    class Protocol:
        """LDAP protocol constants."""

        DEFAULT_TIMEOUT_SECONDS: Final[int] = 30
        MAX_SEARCH_ENTRIES: Final[int] = 1000

    class LdapValidation:
        """LDAP validation constants for value objects."""

        MIN_DN_PARTS: Final[int] = 2
        MIN_DN_LENGTH: Final[int] = 3
        MAX_DN_LENGTH: Final[int] = 2048
        MIN_FILTER_LENGTH: Final[int] = 1
        MAX_FILTER_LENGTH_VALUE_OBJECTS: Final[int] = 4096
        DN_PATTERN: Final[str] = (
            r"^[a-zA-Z0-9][a-zA-Z0-9\-_]*=[^,]+(?:,[a-zA-Z0-9][a-zA-Z0-9\-_]*=[^,]+)*$"
        )
        FILTER_PATTERN: Final[str] = r"^\(.+\)$"
        EMAIL_PATTERN: Final[str] = r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
        MAX_FILTER_LENGTH: Final[int] = 8192
        MIN_PASSWORD_LENGTH: Final[int] = 8
        MAX_PASSWORD_LENGTH: Final[int] = 128
        REQUIRE_PASSWORD_COMPLEXITY: Final[bool] = True


__all__ = [
    "FlextLDAPConstants",
]
