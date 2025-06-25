"""Enterprise LDAP constants and configuration values.

This module provides comprehensive LDAP constants used across the entire
ldap-core-shared library. Based on enterprise patterns from client-a-oud-mig
migration project.

Architecture:
    Centralized constants to ensure consistency across all LDAP operations
    and prevent magic numbers throughout the codebase.

Constants Categories:
    - Connection: LDAP connection defaults and limits
    - Performance: Pool sizes, timeouts, and thresholds
    - Protocol: LDAP protocol constants and supported values
    - Security: Encryption and authentication defaults
    - Operations: Search limits, batch sizes, and intervals

Version: 1.0.0-enterprise
"""

from __future__ import annotations

# LDAP Connection Constants
DEFAULT_LDAP_PORT = 389
DEFAULT_LDAPS_PORT = 636
DEFAULT_LDAP_TIMEOUT = 30
DEFAULT_LDAP_SIZE_LIMIT = 1000
DEFAULT_LDAP_TIME_LIMIT = 30

# Connection Pool Constants
DEFAULT_POOL_SIZE = 10
DEFAULT_MAX_POOL_SIZE = 50
DEFAULT_POOL_TIMEOUT = 60
CONNECTION_MAX_AGE = 3600  # 1 hour
CONNECTION_MAX_IDLE = 300  # 5 minutes

# Performance Constants
DEFAULT_BATCH_SIZE = 100
CHECKPOINT_INTERVAL_ENTRIES = 1000
PERFORMANCE_SAMPLING_INTERVAL = 10  # seconds
MAX_RETRY_ATTEMPTS = 3
RETRY_DELAY_BASE = 1.0  # seconds

# LDAP Search Scopes
LDAP_SCOPES = {
    "BASE": "base",
    "ONELEVEL": "level",
    "SUBTREE": "subtree",
}

# LDAP Search Scope Constants (for import compatibility)
BASE = "base"
ONELEVEL = "onelevel"
SUBTREE = "subtree"

# LDAP Authentication Methods
LDAP_AUTH_METHODS = {
    "ANONYMOUS": "anonymous",
    "SIMPLE": "simple",
    "SASL": "sasl",
}

# Supported Encryption Protocols
SUPPORTED_PROTOCOLS = {
    "NONE": "none",
    "SSL": "ssl",
    "TLS": "tls",
    "STARTTLS": "starttls",
}

# Error Handling Constants
MAX_ERROR_RETRIES = 3
ERROR_COOLDOWN_SECONDS = 5
FAILURE_RATE_THRESHOLD = 0.1  # 10%
LDAP_FAILURE_RATE_THRESHOLD = 0.1  # 10% (alias for compatibility)
CIRCUIT_BREAKER_THRESHOLD = 5

# Memory and Resource Limits
MAX_ENTRIES_LIMIT = 100000
MAX_MEMORY_MB = 1024
DEFAULT_FILE_ENCODING = "utf-8"

# SSH Tunnel Constants
SSH_TUNNEL_TIMEOUT = 30
SSH_TUNNEL_RETRY_ATTEMPTS = 3
SSH_LOCAL_PORT_RANGE = (20000, 30000)

# Performance Thresholds (A+ Grade Targets)
TARGET_OPERATIONS_PER_SECOND = 12000
TARGET_OPERATIONS_PER_SECOND_A_GRADE = 8000
TARGET_OPERATIONS_PER_SECOND_B_GRADE = 4000
TARGET_CONNECTION_REUSE_RATE = 0.95  # 95%
TARGET_POOL_EFFICIENCY_MS = 10  # <10ms connection acquisition
TARGET_SUCCESS_RATE = 0.99  # 99%

# Monitoring and Metrics
METRICS_COLLECTION_INTERVAL = 30  # seconds
HEALTH_CHECK_INTERVAL = 60  # seconds
LOG_ROTATION_SIZE_MB = 100

# LDAP Object Classes (Common)
COMMON_OBJECT_CLASSES = {
    "PERSON": "person",
    "INET_ORG_PERSON": "inetOrgPerson",
    "GROUP": "group",
    "ORGANIZATIONAL_UNIT": "organizationalUnit",
    "ORGANIZATION": "organization",
    "DOMAIN": "domain",
}

# Standard LDAP Attributes
STANDARD_ATTRIBUTES = {
    "CN": "cn",  # Common Name
    "SN": "sn",  # Surname
    "GIVEN_NAME": "givenName",
    "DISPLAY_NAME": "displayName",
    "MAIL": "mail",
    "UID": "uid",
    "OU": "ou",  # Organizational Unit
    "DC": "dc",  # Domain Component
    "OBJECT_CLASS": "objectClass",
    "DISTINGUISHED_NAME": "distinguishedName",
    "MEMBER": "member",
    "MEMBER_OF": "memberOf",
}

# Search Filter Templates
SEARCH_FILTERS = {
    "ALL_OBJECTS": "(objectClass=*)",
    "PERSONS": "(objectClass=person)",
    "GROUPS": "(objectClass=group)",
    "USERS": "(objectClass=inetOrgPerson)",
    "CONTAINERS": "(objectClass=organizationalUnit)",
}

# Transaction and Backup Constants
BACKUP_INITIAL_COUNT = 0
LDAP_BACKUP_RETENTION_DAYS = 30
TRANSACTION_TIMEOUT_SECONDS = 300  # 5 minutes
CHECKPOINT_FILE_PREFIX = "ldap_checkpoint"

# Validation Constants
SCHEMA_VALIDATION_TIMEOUT = 60
REFERENCE_VALIDATION_TIMEOUT = 120
ENCODING_VALIDATION_PATTERNS = [
    r"[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]",  # Control characters
    r"[\uFFFE\uFFFF]",  # Invalid Unicode
]

# API and Client Constants
API_RATE_LIMIT_PER_MINUTE = 1000
CLIENT_MAX_CONCURRENT_OPERATIONS = 20
DEFAULT_PAGE_SIZE = 100
MAX_PAGE_SIZE = 1000

# Enterprise Security Constants
PASSWORD_MIN_LENGTH = 12
SESSION_TIMEOUT_MINUTES = 30
AUDIT_LOG_RETENTION_DAYS = 365
ENCRYPTION_ALGORITHM = "AES-256-GCM"

# Status and State Constants
CONNECTION_STATES = {
    "DISCONNECTED": "disconnected",
    "CONNECTING": "connecting",
    "CONNECTED": "connected",
    "AUTHENTICATING": "authenticating",
    "AUTHENTICATED": "authenticated",
    "ERROR": "error",
}

OPERATION_STATES = {
    "PENDING": "pending",
    "RUNNING": "running",
    "SUCCESS": "success",
    "FAILED": "failed",
    "CANCELLED": "cancelled",
}

# Performance Calculation Constants
PERCENTAGE_CALCULATION_BASE = 100.0
MILLISECONDS_PER_SECOND = 1000
BYTES_PER_MB = 1024 * 1024

# Default Configuration Profiles
DEFAULT_PROFILES = {
    "DEVELOPMENT": {
        "pool_size": 5,
        "max_pool_size": 10,
        "timeout": 10,
        "retry_attempts": 1,
    },
    "TESTING": {
        "pool_size": 3,
        "max_pool_size": 5,
        "timeout": 5,
        "retry_attempts": 1,
    },
    "PRODUCTION": {
        "pool_size": 20,
        "max_pool_size": 100,
        "timeout": 30,
        "retry_attempts": 3,
    },
    "HIGH_PERFORMANCE": {
        "pool_size": 50,
        "max_pool_size": 200,
        "timeout": 60,
        "retry_attempts": 5,
    },
}
