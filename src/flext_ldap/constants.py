"""FLEXT-LDAP Constants - Centralized Operational Constants.

Single source of truth for all FLEXT-LDAP operational constants, eliminating
duplications and providing centralized configuration following DRY principle.

Constants are organized by functional area and follow flext-core patterns.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

from typing import ClassVar

# Import flext-core constants as SINGLE SOURCE OF TRUTH


# OPERATION RESULT CONSTANTS - Eliminates FBT003 boolean parameters
class LDAPOperationResult:
    """LDAP operation result constants to eliminate FBT003 positional boolean values."""

    SUCCESS: ClassVar[bool] = True
    FAILURE: ClassVar[bool] = False


class DirectoryOperationResult:
    """Directory operation result constants - eliminates boolean parameters."""

    SUCCESS: ClassVar[bool] = True
    FAILURE: ClassVar[bool] = False


# LDAP PROTOCOL CONSTANTS
class FlextLdapConstants:
    """Operational constants for FLEXT-LDAP directory operations."""

    # Logging
    TRACE_LEVEL_VALUE: ClassVar[int] = 5  # Custom trace logging level

    # Connection & Timeout
    DEFAULT_TIMEOUT: ClassVar[int] = 30
    DEFAULT_PORT: ClassVar[int] = 389
    DEFAULT_SSL_PORT: ClassVar[int] = 636
    DEFAULT_TIMEOUT_SECONDS: ClassVar[int] = 30
    MAX_TIMEOUT_SECONDS: ClassVar[int] = 300

    # Connection Pooling
    DEFAULT_POOL_SIZE: ClassVar[int] = 10
    MAX_POOL_SIZE: ClassVar[int] = 100

    # Search & Pagination
    DEFAULT_PAGE_SIZE: ClassVar[int] = 1000
    MAX_PAGE_SIZE: ClassVar[int] = 10000
    DEFAULT_SIZE_LIMIT: ClassVar[int] = 1000
    DEFAULT_TIME_LIMIT: ClassVar[int] = 30

    # Protocol
    DEFAULT_PROTOCOL_VERSION: ClassVar[int] = 3
    SUPPORTED_PROTOCOLS: ClassVar[set[int]] = {2, 3}

    # Common LDAP Object Classes
    PERSON_OBJECT_CLASSES: ClassVar[list[str]] = [
        "person",
        "organizationalPerson",
        "inetOrgPerson",
    ]
    GROUP_OBJECT_CLASSES: ClassVar[list[str]] = [
        "group",
        "groupOfNames",
        "groupOfUniqueNames",
        "posixGroup",
    ]

    # Standard LDAP Attributes
    REQUIRED_USER_ATTRIBUTES: ClassVar[list[str]] = ["uid", "cn", "sn"]
    REQUIRED_GROUP_ATTRIBUTES: ClassVar[list[str]] = ["cn"]
    STANDARD_USER_ATTRIBUTES: ClassVar[list[str]] = [
        "uid",
        "cn",
        "sn",
        "mail",
        "telephoneNumber",
        "title",
        "department",
    ]
    STANDARD_GROUP_ATTRIBUTES: ClassVar[list[str]] = [
        "cn",
        "description",
        "member",
        "memberUid",
    ]


# CONVERTER CONSTANTS
class FlextLdapConverterConstants:
    """Converter constants following DRY principle."""

    # LDAP Time Format Lengths
    LDAP_TIME_FORMAT_LONG: ClassVar[int] = 15  # YYYYMMDDHHMMSSZ
    LDAP_TIME_FORMAT_SHORT: ClassVar[int] = 13  # YYMMDDHHMMSSZ

    # Type Detection Patterns
    EMAIL_PATTERN: ClassVar[str] = r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
    PHONE_PATTERN: ClassVar[str] = r"^\+?[1-9][\d\-\(\)\s]{1,14}$"
    UUID_PATTERN: ClassVar[str] = (
        r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"
    )
    DN_COMPONENT_PATTERN: ClassVar[str] = r"^[^=]+=[^=]+$"


# PROJECT IDENTIFICATION
class FlextLdapProjectConstants:
    """Project identification constants."""

    PROJECT_NAME: ClassVar[str] = "flext-infrastructure.databases.flext-ldap"
    PROJECT_VERSION: ClassVar[str] = "0.9.0"
    PROJECT_DESCRIPTION: ClassVar[str] = "Enterprise LDAP Directory Services Library"

    # API Version
    API_VERSION: ClassVar[str] = "v1"
    API_PREFIX: ClassVar[str] = "/api/v1/ldap"


class FlextLdapSchemaDiscoveryConstants:
    """Schema discovery constants - CONSOLIDATED from infrastructure/schema_discovery.py."""

    # Discovery History Management
    MAX_DISCOVERY_HISTORY: ClassVar[int] = 100


class FlextLdapSecurityConstants:
    """Security constants - CONSOLIDATED from domain/security.py."""

    # Network Port Constants
    MIN_PORT: ClassVar[int] = 1
    MAX_PORT: ClassVar[int] = 65535


class FlextLdapErrorCorrelationConstants:
    """Error correlation constants - CONSOLIDATED from infrastructure/error_correlation.py."""

    # Correlation Threshold Constants
    SIGNIFICANT_CORRELATION_THRESHOLD: ClassVar[float] = 0.5
    MINIMUM_CORRELATION_THRESHOLD: ClassVar[float] = 0.3


# BACKWARD COMPATIBILITY - Legacy constants
class LDAPConstants:
    """Legacy constant names for backward compatibility."""

    DEFAULT_PORT: ClassVar[int] = FlextLdapConstants.DEFAULT_PORT
    DEFAULT_SSL_PORT: ClassVar[int] = FlextLdapConstants.DEFAULT_SSL_PORT
    DEFAULT_TIMEOUT: ClassVar[int] = FlextLdapConstants.DEFAULT_TIMEOUT
    DEFAULT_POOL_SIZE: ClassVar[int] = FlextLdapConstants.DEFAULT_POOL_SIZE
