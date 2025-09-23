"""LDAP Constants - SOURCE OF TRUTH using FlextConstants.LDAP exclusively.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import os
from typing import ClassVar, Final, final

from flext_core import FlextConstants


@final
class FlextLdapConstants:
    """LDAP domain-specific constants - universal constants from flext-core."""

    # Import universal constants from flext-core (single source of truth)

    # Use universal constants instead of duplicating
    DEFAULT_TIMEOUT = FlextConstants.Network.DEFAULT_TIMEOUT  # Use from flext-core
    VALIDATION_ERROR_BASE = (
        FlextConstants.Errors.VALIDATION_ERROR
    )  # Base error for extensions

    # =========================================================================
    # LDAP-SPECIFIC CONSTANTS ONLY - No universal duplications
    # =========================================================================

    class Protocol:
        """LDAP protocol-specific constants."""

        # LDAP ports
        DEFAULT_PORT: Final[int] = 389
        DEFAULT_SSL_PORT: Final[int] = 636
        MAX_PORT: Final[int] = 65535

        # LDAP protocols
        LDAP: Final[str] = "ldap"
        LDAPS: Final[str] = "ldaps"

        # LDAP protocol prefixes
        PROTOCOL_PREFIX_LDAP: Final[str] = "ldap://"
        PROTOCOL_PREFIX_LDAPS: Final[str] = "ldaps://"

        # LDAP URIs
        DEFAULT_SERVER_URI: Final[str] = "ldap://localhost"
        DEFAULT_SSL_SERVER_URI: Final[str] = "ldaps://localhost"

        # LDAP pool settings
        DEFAULT_POOL_SIZE: Final[int] = 5
        DEFAULT_TEST_PORT: Final[int] = 3389

        # LDAP timeouts
        DEFAULT_TIMEOUT_SECONDS: Final[int] = 30

    class Connection:
        """LDAP connection-specific constants."""

        # LDAP connection limits
        MAX_SIZE_LIMIT: Final[int] = 1000
        DEFAULT_PAGE_SIZE: Final[int] = 100

    class Scopes:
        """LDAP search scope constants."""

        BASE: Final[str] = "base"
        ONELEVEL: Final[str] = "onelevel"
        SUBTREE: Final[str] = "subtree"
        CHILDREN: Final[str] = "children"

        VALID_SCOPES: Final[set[str]] = {BASE, ONELEVEL, SUBTREE, CHILDREN}

    class Attributes:
        """Standard LDAP attribute names."""

        # Core Attributes
        OBJECT_CLASS: Final[str] = "objectClass"
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
            """Get standard person-related attributes.

            Returns:
                list[str]: List of person-related attribute names.

            """
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
            """Get standard group-related attributes.

            Returns:
                list[str]: List of group-related attribute names.

            """
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

    class Validation:
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
        REQUIRE_PASSWORD_COMPLEXITY: Final[bool] = True

    class Messages:
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

    class Errors:
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

    class Defaults:
        """LDAP-specific default values."""

        DEFAULT_SEARCH_FILTER: Final[str] = "(objectClass=*)"
        DEFAULT_SEARCH_BASE: Final[str] = ""
        DEFAULT_SERVICE_NAME: Final[str] = "flext-ldap"
        DEFAULT_SERVICE_VERSION: Final[str] = "1.0.0"
        MAX_SEARCH_ENTRIES: Final[int] = 1000

        # Valid LDAP user for testing
        VALID_LDAP_USER_NAME: Final[str] = "testuser"
        VALID_LDAP_USER_DESCRIPTION: Final[str] = "Test LDAP User"

    class FeatureFlags:
        """LDAP-specific feature toggles."""

        @staticmethod
        def _env_enabled(flag_name: str, default: str = "0") -> bool:
            value = os.environ.get(flag_name, default)
            return value.lower() not in {"0", "false", "no"}

        @classmethod
        def dispatcher_enabled(cls) -> bool:
            """Return True when dispatcher integration should be used.

            Returns:
                bool: True if dispatcher integration is enabled.

            """
            return cls._env_enabled("FLEXT_LDAP_ENABLE_DISPATCHER")

    class Logging:
        """LDAP-specific logging constants for FLEXT LDAP module.

        Provides domain-specific logging defaults, levels, and configuration
        options tailored for LDAP operations, directory access, and LDAP
        performance monitoring.
        """

        # LDAP-specific log levels
        DEFAULT_LEVEL = FlextConstants.Config.LogLevel.WARNING
        CONNECTION_LEVEL = FlextConstants.Config.LogLevel.INFO
        QUERY_LEVEL = FlextConstants.Config.LogLevel.DEBUG
        AUTHENTICATION_LEVEL = FlextConstants.Config.LogLevel.INFO
        MODIFICATION_LEVEL = FlextConstants.Config.LogLevel.INFO
        ERROR_LEVEL = FlextConstants.Config.LogLevel.ERROR

        # Connection logging
        LOG_CONNECTION_ATTEMPTS = True
        LOG_CONNECTION_SUCCESS = True
        LOG_CONNECTION_FAILURES = True
        LOG_CONNECTION_CLOSURES = True
        LOG_CONNECTION_POOL_EVENTS = True
        LOG_CONNECTION_TIMEOUTS = True

        # Query and search logging
        LOG_SEARCH_OPERATIONS = True
        LOG_SEARCH_FILTERS = False  # Don't log search filters by default (privacy)
        LOG_SEARCH_RESULTS_COUNT = True
        LOG_SEARCH_DURATION = True
        LOG_LARGE_RESULT_SETS = True
        LARGE_RESULT_SET_THRESHOLD = 1000

        # Authentication logging
        LOG_AUTHENTICATION_ATTEMPTS = True
        LOG_AUTHENTICATION_SUCCESS = True
        LOG_AUTHENTICATION_FAILURES = True
        LOG_AUTHENTICATION_ERRORS = True
        MASK_PASSWORDS = True
        MASK_BIND_DN = False  # Log bind DN for debugging

        # Modification logging
        LOG_ADD_OPERATIONS = True
        LOG_MODIFY_OPERATIONS = True
        LOG_DELETE_OPERATIONS = True
        LOG_MODIFY_ATTRIBUTES = (
            False  # Don't log modified attributes by default (privacy)
        )
        LOG_MODIFY_VALUES = False  # Don't log modified values by default (privacy)

        # Performance tracking
        TRACK_LDAP_PERFORMANCE = True
        LDAP_PERFORMANCE_THRESHOLD_WARNING = 1000.0  # 1 second
        LDAP_PERFORMANCE_THRESHOLD_CRITICAL = 5000.0  # 5 seconds
        TRACK_CONNECTION_POOL_USAGE = True
        TRACK_QUERY_COMPLEXITY = True

        # Error logging specifics
        LOG_LDAP_ERRORS = True
        LOG_VALIDATION_ERRORS = True
        LOG_TIMEOUT_ERRORS = True
        LOG_CONNECTION_ERRORS = True
        LOG_QUERY_ERRORS = True

        # Context information to include
        INCLUDE_VALUES_IN_LOGS = False
        INCLUDE_FILTERS_IN_LOGS = False
        INCLUDE_CONTROLS_IN_LOGS = False
        INCLUDE_TIMING_IN_LOGS = True
        INCLUDE_CONNECTION_INFO_IN_LOGS = True
        INCLUDE_USER_INFO_IN_LOGS = True
        INCLUDE_SERVER_INFO_IN_LOGS = True
        MASK_SENSITIVE_DATA = True
        MASK_ATTRIBUTES = False
        MASK_VALUES = True
        USE_STANDARD_TEMPLATES = True
        CUSTOM_LOG_FORMAT = ""
        ENABLE_AUDIT_LOGGING = True
        AUDIT_LOG_LEVEL = FlextConstants.Config.LogLevel.INFO
        INCLUDE_CONNECTION_ID = True
        INCLUDE_OPERATION_ID = True
        INCLUDE_USER_DN = True
        INCLUDE_BASE_DN = True
        INCLUDE_SCOPE = True
        INCLUDE_ATTRIBUTES = False  # Don't include attributes by default (privacy)

        # Security logging
        LOG_ACCESS_CONTROL_VIOLATIONS = True
        LOG_PERMISSION_DENIED = True
        LOG_SUSPICIOUS_QUERIES = True
        LOG_BULK_OPERATIONS = True
        BULK_OPERATION_THRESHOLD = 100

        # Additional logging constants referenced in config
        LOG_LDAP_QUERIES = True
        LOG_LDAP_RESPONSES = True
        STRUCTURED_LOGGING = True
        LOG_CONNECTION_EVENTS = True
        LOG_BIND_ATTEMPTS = True
        LOG_SEARCH_RESULTS = True
        LOG_COMPARE_OPERATIONS = True
        LOG_LDAP_WARNINGS = True
        LOG_LDAP_EXCEPTIONS = True
        LOG_LDAP_TIMEOUTS = True
        LOG_LDAP_RETRIES = True
        LOG_LDAP_PERFORMANCE = True
        LOG_LDAP_CONNECTIONS = True
        LOG_LDAP_DISCONNECTIONS = True
        LOG_LDAP_POOL_EVENTS = True
        LOG_LDAP_CACHE_EVENTS = True
        LOG_LDAP_SSL_EVENTS = True
        LOG_LDAP_AUTHENTICATION = True
        LOG_LDAP_AUTHORIZATION = True
        LOG_LDAP_AUDIT = True
        LOG_LDAP_SECURITY = True
        LOG_LDAP_COMPLIANCE = True
        ENVIRONMENT_SPECIFIC_LOGGING = True
        AUDIT_LOG_FILE = "/var/log/flext-ldap/audit.log"
        INCLUDE_DN_IN_LOGS = True
        INCLUDE_ATTRIBUTES_IN_LOGS = False

        # Message templates for LDAP operations
        class Messages:
            """LDAP-specific log message templates."""

            # Connection messages
            CONNECTION_ATTEMPT = "LDAP connection attempt to {server}:{port}"
            CONNECTION_SUCCESS = "LDAP connection established to {server}:{port}"
            CONNECTION_FAILED = "LDAP connection failed to {server}:{port}: {error}"
            CONNECTION_CLOSED = "LDAP connection closed to {server}:{port}"
            CONNECTION_TIMEOUT = "LDAP connection timeout to {server}:{port}"

            # Authentication messages
            AUTH_ATTEMPT = "LDAP authentication attempt for user: {user_dn}"
            AUTH_SUCCESS = "LDAP authentication successful for user: {user_dn}"
            AUTH_FAILED = "LDAP authentication failed for user: {user_dn}: {error}"
            AUTH_ERROR = "LDAP authentication error for user: {user_dn}: {error}"

            # Search messages
            SEARCH_STARTED = (
                "LDAP search started: base={base_dn} scope={scope} filter={filter}"
            )
            SEARCH_COMPLETED = (
                "LDAP search completed: {result_count} results in {duration}ms"
            )
            SEARCH_FAILED = "LDAP search failed: {error}"
            LARGE_RESULT_SET = (
                "LDAP search returned large result set: {result_count} results"
            )

            # Modification messages
            ADD_OPERATION = "LDAP add operation: dn={dn}"
            ADD_SUCCESS = "LDAP add successful: dn={dn}"
            ADD_FAILED = "LDAP add failed: dn={dn} error: {error}"

            MODIFY_OPERATION = "LDAP modify operation: dn={dn}"
            MODIFY_SUCCESS = "LDAP modify successful: dn={dn}"
            MODIFY_FAILED = "LDAP modify failed: dn={dn} error: {error}"

            DELETE_OPERATION = "LDAP delete operation: dn={dn}"
            DELETE_SUCCESS = "LDAP delete successful: dn={dn}"
            DELETE_FAILED = "LDAP delete failed: dn={dn} error: {error}"

            # Performance messages
            SLOW_OPERATION = "Slow LDAP operation: {operation} took {duration}ms"
            SLOW_SEARCH = "Slow LDAP search: {filter} took {duration}ms"
            HIGH_CONNECTION_USAGE = "High LDAP connection pool usage: {used}/{total}"

            # Error messages
            LDAP_ERROR = "LDAP error: {error_code} {error_message}"
            VALIDATION_ERROR = "LDAP validation error: {field} {error}"
            TIMEOUT_ERROR = "LDAP timeout error: {operation} exceeded {timeout}ms"
            CONNECTION_ERROR = "LDAP connection error: {error}"

            # Security messages
            ACCESS_DENIED = "LDAP access denied: {user_dn} {operation} {dn}"
            PERMISSION_DENIED = "LDAP permission denied: {user_dn} {operation}"
            SUSPICIOUS_QUERY = "Suspicious LDAP query: {user_dn} {filter}"
            BULK_OPERATION = "LDAP bulk operation detected: {operation} {count} entries"

        # Environment-specific overrides for LDAP logging
        class Environment:
            """Environment-specific LDAP logging configuration."""

            DEVELOPMENT: ClassVar[dict[str, object]] = {
                "log_search_filters": True,  # Log search filters in dev
                "log_modify_attributes": True,  # Log modified attributes in dev
                "log_modify_values": True,  # Log modified values in dev
                "include_attributes": True,  # Include attributes in dev
                "audit_log_level": FlextConstants.Config.LogLevel.DEBUG,
            }

            STAGING: ClassVar[dict[str, object]] = {
                "log_search_filters": False,
                "log_modify_attributes": False,
                "log_modify_values": False,
                "include_attributes": False,
                "audit_log_level": FlextConstants.Config.LogLevel.INFO,
            }

            PRODUCTION: ClassVar[dict[str, object]] = {
                "log_search_filters": False,
                "log_modify_attributes": False,
                "log_modify_values": False,
                "include_attributes": False,
                "audit_log_level": FlextConstants.Config.LogLevel.WARNING,
            }

            TESTING: ClassVar[dict[str, object]] = {
                "log_search_filters": True,
                "log_modify_attributes": True,
                "log_modify_values": True,
                "include_attributes": True,
                "audit_log_level": FlextConstants.Config.LogLevel.DEBUG,
            }


__all__ = [
    "FlextLdapConstants",
]
