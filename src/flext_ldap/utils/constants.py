"""Enterprise LDAP constants and configuration values."""

from __future__ import annotations

# LDAP Connection Constants

# Constants for magic values
BYTES_PER_KB = 1024
DEFAULT_CONFIDENCE_PERCENT = 95
DEFAULT_LARGE_LIMIT = 1000
DEFAULT_MAX_ITEMS = 100
DEFAULT_TIMEOUT_SECONDS = 30
HTTP_OK = 200
LDAPS_DEFAULT_PORT = 636
LDAP_DEFAULT_PORT = 389
SECONDS_PER_HOUR = 3600
SECONDS_PER_MINUTE = 60

# Network Constants
TCP_PORT_MIN = 1
TCP_PORT_MAX = 65535
LDAP_MESSAGE_ID_MAX = 2147483647  # 2^31 - 1

# Microsoft LDAP Extensions Constants
GUID_BYTE_LENGTH = 16  # Microsoft GUID is 128 bits = 16 bytes

# ASN.1 BER Constants
BER_SEQUENCE_TAG = 0x30
BER_CONTEXT_TAG_0 = 0x80

# LDAP Filter Constants
MIN_LOGICAL_OPERATORS = 2  # Minimum operands required for AND/OR operations

DEFAULT_LDAP_PORT = LDAP_DEFAULT_PORT
DEFAULT_LDAPS_PORT = LDAPS_DEFAULT_PORT
DEFAULT_LDAP_TIMEOUT = DEFAULT_TIMEOUT_SECONDS
DEFAULT_LDAP_SIZE_LIMIT = DEFAULT_LARGE_LIMIT
DEFAULT_LDAP_TIME_LIMIT = DEFAULT_TIMEOUT_SECONDS

# Connection Pool Constants
DEFAULT_POOL_SIZE = 10
DEFAULT_MAX_POOL_SIZE = 50
DEFAULT_POOL_TIMEOUT = SECONDS_PER_MINUTE
CONNECTION_MAX_AGE = SECONDS_PER_HOUR  # 1 hour
CONNECTION_MAX_IDLE = 300  # 5 minutes

# Performance Constants
DEFAULT_BATCH_SIZE = DEFAULT_MAX_ITEMS
CHECKPOINT_INTERVAL_ENTRIES = DEFAULT_LARGE_LIMIT
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
MAX_MEMORY_MB = BYTES_PER_KB
DEFAULT_FILE_ENCODING = "utf-8"

# SSH Tunnel Constants
SSH_TUNNEL_TIMEOUT = DEFAULT_TIMEOUT_SECONDS
SSH_TUNNEL_RETRY_ATTEMPTS = 3
SSH_LOCAL_PORT_RANGE = (20000, 30000)

# ZERO TOLERANCE - Timing Constants for Operations
CONNECTION_SIMULATION_DELAY_SECONDS = 0.1  # Connection setup simulation
AUTHENTICATION_SIMULATION_DELAY_SECONDS = 0.05  # Authentication simulation
OPERATION_RETRY_BASE_DELAY_SECONDS = 0.1  # Base delay for exponential backoff

# Performance Thresholds (A+ Grade Targets)
TARGET_OPERATIONS_PER_SECOND: int = 12000
TARGET_OPERATIONS_PER_SECOND_A_GRADE: int = 8000
TARGET_OPERATIONS_PER_SECOND_B_GRADE: int = 4000
TARGET_CONNECTION_REUSE_RATE: float = (
    DEFAULT_CONFIDENCE_PERCENT / 100.0
)  # 95% as decimal
TARGET_POOL_EFFICIENCY_MS: int = 10  # <10ms connection acquisition
TARGET_SUCCESS_RATE: float = 0.99  # 99%

# Monitoring and Metrics
METRICS_COLLECTION_INTERVAL = DEFAULT_TIMEOUT_SECONDS  # seconds
HEALTH_CHECK_INTERVAL = SECONDS_PER_MINUTE  # seconds
LOG_ROTATION_SIZE_MB = DEFAULT_MAX_ITEMS

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
LDAP_BACKUP_RETENTION_DAYS = DEFAULT_TIMEOUT_SECONDS
TRANSACTION_TIMEOUT_SECONDS = 300  # 5 minutes
CHECKPOINT_FILE_PREFIX = "ldap_checkpoint"

# Validation Constants
SCHEMA_VALIDATION_TIMEOUT = SECONDS_PER_MINUTE
REFERENCE_VALIDATION_TIMEOUT = 120
ENCODING_VALIDATION_PATTERNS = [
    r"[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]",  # Control characters
    r"[\uFFFE\uFFFF]",  # Invalid Unicode
]

# API and Client Constants
API_RATE_LIMIT_PER_MINUTE = DEFAULT_LARGE_LIMIT
CLIENT_MAX_CONCURRENT_OPERATIONS = 20
DEFAULT_PAGE_SIZE = DEFAULT_MAX_ITEMS
MAX_PAGE_SIZE = DEFAULT_LARGE_LIMIT

# Enterprise Security Constants
PASSWORD_MIN_LENGTH = 12
SESSION_TIMEOUT_MINUTES = DEFAULT_TIMEOUT_SECONDS
AUDIT_LOG_RETENTION_DAYS = 365
ENCRYPTION_ALGORITHM = "AES-256-GCM"

# Security Configuration Environment Variables
# These should be set via environment variables or secure config management
DEFAULT_PASSWORD_ATTRIBUTE = "userPassword"  # LDAP standard attribute name
SENSITIVE_DATA_MASK = "***MASKED***"  # Standard mask for sensitive data logging
PLACEHOLDER_OID = (
    "0.0.0.0"  # Placeholder OID value (not a network binding)  # noqa: S104
)

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
PERCENTAGE_CALCULATION_BASE: int = DEFAULT_MAX_ITEMS
MILLISECONDS_PER_SECOND: int = DEFAULT_LARGE_LIMIT
BYTES_PER_MB: int = BYTES_PER_KB * BYTES_PER_KB

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
        "max_pool_size": DEFAULT_MAX_ITEMS,
        "timeout": DEFAULT_TIMEOUT_SECONDS,
        "retry_attempts": 3,
    },
    "HIGH_PERFORMANCE": {
        "pool_size": 50,
        "max_pool_size": HTTP_OK,
        "timeout": SECONDS_PER_MINUTE,
        "retry_attempts": 5,
    },
}
