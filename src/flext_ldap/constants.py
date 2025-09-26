"""LDAP Constants - Essential constants only, using FlextConstants.LDAP exclusively.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import Final

from flext_core import FlextConstants


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
        GROUP_OF_UNIQUE_NAMES: Final[str] = "groupOfUniqueNames"

    class LdapValidation:
        """LDAP-specific validation constants."""

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

    class LdapMessages:
        """LDAP-specific error and validation messages."""

        # LDAP validation messages
        HOST_CANNOT_BE_EMPTY: Final[str] = "Host cannot be empty"
        CONNECTION_FAILED: Final[str] = "Connection failed"
        FIELD_CANNOT_BE_EMPTY: Final[str] = "{0} cannot be empty"
        INVALID_DN_FORMAT: Final[str] = "Invalid DN format"
        INVALID_SEARCH_FILTER: Final[str] = "Invalid LDAP search filter"
        CONNECTION_FAILED_WITH_CONTEXT: Final[str] = "Connection failed: {0}"
        OPERATION_FAILED: Final[str] = "Operation {0} failed"

        # LDAP error messages following FLEXT standards
        INVALID_EMAIL_FORMAT: Final[str] = "Invalid email format"
        EMAIL_VALIDATION_FAILED: Final[str] = "Invalid email format: {error}"
        DN_CANNOT_BE_EMPTY: Final[str] = "DN cannot be empty"

    class LdapErrors:
        """LDAP-specific error codes - extend universal error codes."""

        # Base universal error from flext-core
        VALIDATION_ERROR: Final[str] = f"LDAP_{FlextConstants.Errors.VALIDATION_ERROR}"
        CONNECTION_ERROR: Final[str] = f"LDAP_{FlextConstants.Errors.CONNECTION_ERROR}"

        # LDAP-specific errors
        LDAP_BIND_ERROR: Final[str] = "LDAP_BIND_ERROR"
        LDAP_SEARCH_ERROR: Final[str] = "LDAP_SEARCH_ERROR"
        LDAP_ADD_ERROR: Final[str] = "LDAP_ADD_ERROR"
        LDAP_MODIFY_ERROR: Final[str] = "LDAP_MODIFY_ERROR"
        LDAP_DELETE_ERROR: Final[str] = "LDAP_DELETE_ERROR"
        LDAP_INVALID_DN: Final[str] = "LDAP_INVALID_DN"
        LDAP_INVALID_FILTER: Final[str] = "LDAP_INVALID_FILTER"

    class LdapDefaults:
        """LDAP-specific default values."""

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

    class LdapRetry:
        """LDAP retry and timing constants."""

        # Server readiness retry timing
        SERVER_READY_RETRY_DELAY: Final[int] = 2  # seconds
        SERVER_READY_MAX_RETRIES: Final[int] = 10
        SERVER_READY_TIMEOUT: Final[int] = 30  # seconds

        # Connection retry timing
        CONNECTION_RETRY_DELAY: Final[float] = 1.0  # seconds
        CONNECTION_MAX_RETRIES: Final[int] = 3


__all__ = [
    "FlextLdapConstants",
]
