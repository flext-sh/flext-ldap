"""Type aliases for LDAP Core Shared.

This module provides type aliases that improve code readability and type safety
throughout the library. These aliases represent common LDAP concepts and data
structures in a type-safe manner.

Design principles:
- Clear, descriptive names that match LDAP terminology
- Strong typing to prevent common errors
- Consistent usage across the entire library
- Easy to understand and maintain
"""

from __future__ import annotations

import uuid

# Use typing_extensions for TypeAlias compatibility across Python versions
from typing import Any, Literal, TypeAlias

# ===== BASIC LDAP TYPES =====

#: Distinguished Name - primary identifier in LDAP
DN: TypeAlias = str

#: Relative Distinguished Name - component of a DN
RDN: TypeAlias = str

#: LDAP attribute name
AttributeName: TypeAlias = str

#: LDAP attribute value (can be string, bytes, or list of either)
AttributeValue: TypeAlias = str | bytes | list[str] | list[bytes]

#: Dictionary of LDAP attributes
Attributes: TypeAlias = dict[AttributeName, AttributeValue]

#: LDAP filter expression string
FilterExpression: TypeAlias = str

#: LDAP search scope options
SearchScope: TypeAlias = Literal["base", "onelevel", "subtree"]

#: LDAP modification operation types
ModificationOperation: TypeAlias = Literal["add", "replace", "delete"]

# ===== CONNECTION AND AUTHENTICATION =====

#: LDAP server URI
ServerURI: TypeAlias = str

#: Authentication mechanism
AuthMechanism: TypeAlias = Literal["simple", "sasl", "anonymous"]

#: SASL mechanism types
SASLMechanism: TypeAlias = Literal["GSSAPI", "DIGEST-MD5", "PLAIN", "EXTERNAL"]

#: Connection timeout in seconds
Timeout: TypeAlias = float

#: TLS/SSL version
TLSVersion: TypeAlias = Literal["TLSv1.2", "TLSv1.3"]

# ===== OPERATION RESULTS =====

#: LDAP operation result code
ResultCode: TypeAlias = int

#: LDAP operation result message
ResultMessage: TypeAlias = str

#: Complete operation result
OperationResult: TypeAlias = dict[
    Literal["result_code", "message", "dn"],
    ResultCode | ResultMessage | DN | None,
]

#: Entry result from search operation
SearchResult: TypeAlias = dict[Literal["dn", "attributes"], DN | Attributes]

#: Collection of search results
SearchResults: TypeAlias = list[SearchResult]

# ===== SCHEMA TYPES =====

#: Object identifier (OID)
OID: TypeAlias = str

#: Object class name
ObjectClass: TypeAlias = str

#: Attribute type definition
AttributeType: TypeAlias = str

#: Syntax definition
Syntax: TypeAlias = str

#: Matching rule
MatchingRule: TypeAlias = str

#: Schema element definition
SchemaElement: TypeAlias = dict[str, Any]

#: Complete schema definition
Schema: TypeAlias = dict[
    Literal["object_classes", "attribute_types", "syntaxes", "matching_rules"],
    list[SchemaElement],
]

# ===== MIGRATION AND LDIF =====

#: LDIF record type
LDIFRecordType: TypeAlias = Literal["entry", "modification", "delete", "moddn"]

#: LDIF record
LDIFRecord: TypeAlias = dict[
    Literal["type", "dn", "attributes", "changes"],
    LDIFRecordType | DN | Attributes | list[dict[str, Any]] | None,
]

#: Collection of LDIF records
LDIFRecords: TypeAlias = list[LDIFRecord]

#: Migration status
MigrationStatus: TypeAlias = Literal[
    "pending",
    "running",
    "completed",
    "failed",
    "cancelled",
]

#: Migration result statistics
MigrationStats: TypeAlias = dict[
    Literal["total_entries", "successful", "failed", "skipped", "duration"],
    int | float,
]

# ===== CONFIGURATION TYPES =====

#: Configuration value (can be various types)
ConfigValue: TypeAlias = str | int | float | bool | list[Any] | dict[str, Any] | None

#: Configuration dictionary
Config: TypeAlias = dict[str, ConfigValue]

#: Environment name
Environment: TypeAlias = Literal["development", "testing", "staging", "production"]

#: Log level
LogLevel: TypeAlias = Literal["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]

# ===== MONITORING AND OBSERVABILITY =====

#: Metric name
MetricName: TypeAlias = str

#: Metric value
MetricValue: TypeAlias = int | float

#: Metric labels/tags
MetricLabels: TypeAlias = dict[str, str]

#: Metric data point
Metric: TypeAlias = dict[
    Literal["name", "value", "labels", "timestamp"],
    MetricName | MetricValue | MetricLabels | float,
]

#: Collection of metrics
Metrics: TypeAlias = list[Metric]

#: Event type identifier
EventType: TypeAlias = str

#: Event data payload
EventData: TypeAlias = dict[str, Any]

#: Trace ID for distributed tracing
TraceID: TypeAlias = str

#: Span ID for distributed tracing
SpanID: TypeAlias = str

# ===== SECURITY AND ENCRYPTION =====

#: Certificate in PEM format
Certificate: TypeAlias = str

#: Private key in PEM format
PrivateKey: TypeAlias = str

#: Certificate authority bundle
CABundle: TypeAlias = str

#: Encryption algorithm
EncryptionAlgorithm: TypeAlias = Literal["AES-256-GCM", "ChaCha20-Poly1305"]

#: Hash algorithm
HashAlgorithm: TypeAlias = Literal["SHA-256", "SHA-512", "BLAKE2b"]

#: JWT token
JWTToken: TypeAlias = str

#: API key
APIKey: TypeAlias = str

# ===== ERROR AND EXCEPTION TYPES =====

#: Error code
ErrorCode: TypeAlias = str

#: Error severity level
ErrorSeverity: TypeAlias = Literal["low", "medium", "high", "critical"]

#: Error context information
ErrorContext: TypeAlias = dict[str, Any]

#: Exception details
ExceptionDetails: TypeAlias = dict[
    Literal["type", "message", "traceback", "context"],
    str | ErrorContext | None,
]

# ===== VALIDATION TYPES =====

#: Validation rule name
ValidationRule: TypeAlias = str

#: Validation error message
ValidationError: TypeAlias = str

#: Field path for nested validation
FieldPath: TypeAlias = str

#: Validation result
ValidationResult: TypeAlias = dict[
    Literal["valid", "errors"],
    bool | dict[FieldPath, list[ValidationError]],
]

# ===== PAGINATION AND FILTERING =====

#: Page number (1-based)
PageNumber: TypeAlias = int

#: Page size (number of items per page)
PageSize: TypeAlias = int

#: Total count of items
TotalCount: TypeAlias = int

#: Pagination token for cursor-based pagination
PaginationToken: TypeAlias = str

#: Pagination metadata
PaginationMeta: TypeAlias = dict[
    Literal["page", "size", "total", "token"],
    PageNumber | PageSize | TotalCount | PaginationToken | None,
]

#: Sort field name
SortField: TypeAlias = str

#: Sort direction
SortDirection: TypeAlias = Literal["asc", "desc"]

#: Sort specification
SortSpec: TypeAlias = dict[
    Literal["field", "direction"],
    SortField | SortDirection,
]

#: Collection of sort specifications
SortSpecs: TypeAlias = list[SortSpec]

# ===== ENTITY AND REPOSITORY TYPES =====

#: Entity ID (using UUID for uniqueness)
EntityID: TypeAlias = uuid.UUID

#: Entity version for optimistic locking
EntityVersion: TypeAlias = int

#: Repository query specification
QuerySpec: TypeAlias = dict[str, Any]

#: Repository filter specification
FilterSpec: TypeAlias = dict[str, Any]

#: Aggregation specification
AggregationSpec: TypeAlias = dict[str, Any]

# ===== PERFORMANCE AND CACHING =====

#: Cache key
CacheKey: TypeAlias = str

#: Cache TTL in seconds
CacheTTL: TypeAlias = int

#: Performance threshold in milliseconds
PerformanceThreshold: TypeAlias = float

#: Memory usage in bytes
MemoryUsage: TypeAlias = int

#: CPU usage percentage
CPUUsage: TypeAlias = float

# ===== UTILITY TYPES =====

from collections.abc import Callable

#: Callback function type
Callback: TypeAlias = Callable[..., Any]

#: Async callback function type
AsyncCallback: TypeAlias = Callable[..., Any]  # Should be Awaitable but keeping simple

#: Factory function type
Factory: TypeAlias = Callable[..., Any]

#: Predicate function type
Predicate: TypeAlias = Callable[[Any], bool]

#: Mapper function type
Mapper: TypeAlias = Callable[[Any], Any]

#: Reducer function type
Reducer: TypeAlias = Callable[[Any, Any], Any]
