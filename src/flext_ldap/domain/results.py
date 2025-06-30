"""DEPRECATED: Use api.Result[T] instead of these specialized result classes.

This module contains legacy result classes. For new code, use the unified api.Result[T] pattern.
Migration utilities are provided for backward compatibility.

PREFERRED PATTERN:
    from flext_ldap.domain.results import Result

    # Instead of LDAPSearchResult:
    result: Result[list[LDAPEntry]] = await ldap.search(...)

    # Instead of LDAPConnectionResult:
    result: Result[bool] = await ldap.test_connection()

    # Instead of LDAPOperationResult:
    result: Result[LDAPEntry] = await ldap.add_entry(...)
"""

from __future__ import annotations

import warnings
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any, Generic, TypeVar

from flext_ldapants import (
    DEFAULT_LARGE_LIMIT,
    DEFAULT_MAX_ITEMS,
    DEFAULT_TIMEOUT_SECONDS,
)
from pydantic import BaseModel, ConfigDict, Field, computed_field

# Import unified Result for migration utilities
if TYPE_CHECKING:
    from flext_ldap.domain.results import Result

T = TypeVar("T")


class LDAPConnectionResult(BaseModel):
    """Typed result for LDAP connection operations."""

    model_config = ConfigDict(
        strict=True,
        extra="forbid",
        frozen=True,
        validate_assignment=True,
    )

    connected: bool
    host: str
    port: int
    auth_method: str = "simple"
    encryption: str = "none"

    # Connection metrics
    connection_time: float = Field(default=0.0, ge=0.0)
    response_time: float = Field(default=0.0, ge=0.0)
    last_activity: datetime | None = None

    # Tunnel information
    tunnel_active: bool = False
    tunnel_local_port: int | None = Field(default=None, gt=0, lt=65536)

    # Error tracking
    connection_error: str | None = None
    auth_error: str | None = None

    # Protocol-specific info
    ldap_info: dict[str, Any] = Field(default_factory=dict)
    ssh_info: dict[str, Any] = Field(default_factory=dict)

    timestamp: datetime = Field(default_factory=lambda: datetime.now(UTC))

    @computed_field
    def has_errors(self) -> bool:
        """Check if any connection errors occurred."""
        return bool(self.connection_error or self.auth_error)

    @computed_field
    def is_secure(self) -> bool:
        """Check if connection uses secure protocols."""
        return self.encryption in {"ssl", "tls", "starttls"} or self.tunnel_active


class LDAPSearchResult(BaseModel):
    """Typed result for LDAP search operations."""

    model_config = ConfigDict(
        strict=True,
        extra="forbid",
        frozen=True,
        validate_assignment=True,
    )

    success: bool
    entries_found: int = Field(default=0, ge=0)
    search_base: str
    search_filter: str

    # Search results
    entries: list[dict[str, Any]] = Field(default_factory=list)
    attributes_returned: list[str] = Field(default_factory=list)

    # Search configuration
    scope: str = "subtree"
    size_limit: int = Field(default=DEFAULT_LARGE_LIMIT, ge=0)
    time_limit: int = Field(default=DEFAULT_TIMEOUT_SECONDS, ge=0)

    # Performance metrics
    search_duration: float = Field(default=0.0, ge=0.0)
    entries_per_second: float = Field(default=0.0, ge=0.0)

    # Pagination support
    page_size: int | None = Field(default=None, gt=0)
    has_more_pages: bool = False
    page_cookie: str | None = None

    # Error tracking
    errors: list[str] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)

    timestamp: datetime = Field(default_factory=lambda: datetime.now(UTC))

    @computed_field
    def has_errors(self) -> bool:
        """Check if any search errors occurred."""
        return len(self.errors) > 0

    @computed_field
    def has_warnings(self) -> bool:
        """Check if any search warnings occurred."""
        return len(self.warnings) > 0


class LDAPOperationResult(BaseModel, Generic[T]):
    """Typed result for individual LDAP operations (add, modify, delete)."""

    model_config = ConfigDict(
        strict=True,
        extra="forbid",
        frozen=True,
        validate_assignment=True,
    )

    success: bool
    operation: str = ""  # operation name
    data: T | None = None

    # Operation details
    attributes_modified: dict[str, Any] = Field(default_factory=dict)
    backup_created: bool = False
    transaction_id: str | None = None

    # Performance metrics
    operation_duration: float = Field(default=0.0, ge=0.0)

    # Error tracking
    error_message: str | None = None
    ldap_error_code: int | None = None

    # Additional details and message support
    message: str | None = None
    details: dict[str, Any] = Field(default_factory=dict)
    metadata: dict[str, Any] = Field(default_factory=dict)

    # Rollback information
    rollback_data: dict[str, Any] = Field(default_factory=dict)

    timestamp: datetime = Field(default_factory=lambda: datetime.now(UTC))

    @computed_field
    def has_error(self) -> bool:
        """Check if operation failed."""
        return not self.success or bool(self.error_message)

    @computed_field
    def duration(self) -> float:
        """Alias for operation_duration for compatibility."""
        return self.operation_duration

    @computed_field
    def computed_message(self) -> str:
        """Get appropriate message based on operation status."""
        if self.message:
            return self.message
        if self.error_message:
            return self.error_message
        return f"Successfully completed {self.operation} operation"


class LDAPBulkResult(BaseModel):
    """Typed result for bulk LDAP operations."""

    model_config = ConfigDict(
        strict=True,
        extra="forbid",
        frozen=True,
        validate_assignment=True,
    )

    total_entries: int = Field(default=0, ge=0)
    successful_entries: int = Field(default=0, ge=0)
    failed_entries: int = Field(default=0, ge=0)
    operation_type: str

    # Operation details
    operations_log: list[LDAPOperationResult[Any]] = Field(default_factory=list)
    checkpoints: list[dict[str, Any]] = Field(default_factory=list)

    # Performance metrics
    operation_duration: float = Field(default=0.0, ge=0.0)
    operations_per_second: float = Field(default=0.0, ge=0.0)

    # Transaction info
    transaction_id: str | None = None
    transaction_committed: bool = False
    backup_created: bool = False

    # Error tracking
    errors: list[str] = Field(default_factory=list)
    critical_errors: list[str] = Field(default_factory=list)

    timestamp: datetime = Field(default_factory=lambda: datetime.now(UTC))

    @computed_field
    def success_rate(self) -> float:
        """Calculate success rate as percentage."""
        if self.total_entries == 0:
            return DEFAULT_MAX_ITEMS
        return (self.successful_entries / self.total_entries) * DEFAULT_MAX_ITEMS

    @computed_field
    def has_critical_errors(self) -> bool:
        """Check if any critical errors occurred."""
        return len(self.critical_errors) > 0

    @computed_field
    def is_complete_success(self) -> bool:
        """Check if all operations succeeded."""
        return self.failed_entries == 0 and not self.has_critical_errors  # type: ignore[truthy-function]


class LDAPPerformanceResult(BaseModel):
    """Typed result for LDAP performance monitoring."""

    model_config = ConfigDict(
        strict=True,
        extra="forbid",
        frozen=True,
        validate_assignment=True,
    )

    operation_name: str
    total_operations: int = Field(default=0, ge=0)
    successful_operations: int = Field(default=0, ge=0)
    failed_operations: int = Field(default=0, ge=0)

    # Performance metrics
    total_duration: float = Field(default=0.0, ge=0.0)
    average_duration: float = Field(default=0.0, ge=0.0)
    operations_per_second: float = Field(default=0.0, ge=0.0)

    # Resource usage
    memory_peak_mb: float = Field(default=0.0, ge=0.0)
    cpu_usage_percent: float = Field(default=0.0, ge=0.0, le=DEFAULT_MAX_ITEMS)

    # Connection pool metrics
    pool_size: int = Field(default=0, ge=0)
    pool_utilization: float = Field(default=0.0, ge=0.0, le=DEFAULT_MAX_ITEMS)
    connection_reuse_rate: float = Field(default=0.0, ge=0.0, le=DEFAULT_MAX_ITEMS)

    timestamp: datetime = Field(default_factory=lambda: datetime.now(UTC))

    @computed_field
    def success_rate(self) -> float:
        """Calculate success rate as percentage."""
        if self.total_operations == 0:
            return DEFAULT_MAX_ITEMS
        return (self.successful_operations / self.total_operations) * DEFAULT_MAX_ITEMS

    @computed_field
    def failure_rate(self) -> float:
        """Calculate failure rate as percentage."""
        if self.total_operations == 0:
            return 0.0
        return (self.failed_operations / self.total_operations) * DEFAULT_MAX_ITEMS


class LDAPValidationResult(BaseModel):
    """Typed result for LDAP validation operations."""

    model_config = ConfigDict(
        strict=True,
        extra="forbid",
        frozen=True,
        validate_assignment=True,
    )

    valid: bool
    validation_type: str
    entries_validated: int = Field(default=0, ge=0)

    # Validation details
    schema_errors: list[str] = Field(default_factory=list)
    syntax_errors: list[str] = Field(default_factory=list)
    reference_errors: list[str] = Field(default_factory=list)

    # Performance metrics
    validation_duration: float = Field(default=0.0, ge=0.0)

    timestamp: datetime = Field(default_factory=lambda: datetime.now(UTC))

    @computed_field
    def has_errors(self) -> bool:
        """Check if any validation errors occurred."""
        return len(self.schema_errors + self.syntax_errors + self.reference_errors) > 0

    @computed_field
    def total_errors(self) -> int:
        """Get total count of all validation errors."""
        return len(self.schema_errors + self.syntax_errors + self.reference_errors)


# Aliases for backward compatibility and enterprise integration
BulkOperationResult = LDAPBulkResult
OperationSummary = LDAPOperationResult


# Utility functions for result aggregation
def merge_search_results(results: list[LDAPSearchResult]) -> LDAPSearchResult:
    """Merge multiple search results into a single result."""
    if not results:
        return LDAPSearchResult(
            success=False,
            entries_found=0,
            search_base="",
            search_filter="",
            search_duration=0.0,
            entries_per_second=0.0,
        )

    first_result = results[0]
    all_entries = []
    total_duration = 0.0
    all_errors = []
    all_warnings = []

    for result in results:
        all_entries.extend(result.entries)
        total_duration += result.search_duration
        all_errors.extend(result.errors)
        all_warnings.extend(result.warnings)

    avg_eps = len(all_entries) / total_duration if total_duration > 0 else 0.0

    return LDAPSearchResult(
        success=all(r.success for r in results),
        entries_found=len(all_entries),
        search_base=first_result.search_base,
        search_filter=first_result.search_filter,
        entries=all_entries,
        search_duration=total_duration,
        entries_per_second=avg_eps,
        errors=all_errors,
        warnings=all_warnings,
    )


def merge_bulk_results(results: list[LDAPBulkResult]) -> LDAPBulkResult:
    """Merge multiple bulk operation results into a single result."""
    if not results:
        return LDAPBulkResult(
            total_entries=0,
            successful_entries=0,
            failed_entries=0,
            operation_type="unknown",
            operation_duration=0.0,
            operations_per_second=0.0,
        )

    first_result = results[0]
    total_entries = sum(r.total_entries for r in results)
    successful_entries = sum(r.successful_entries for r in results)
    failed_entries = sum(r.failed_entries for r in results)
    total_duration = sum(r.operation_duration for r in results)

    all_operations = []
    all_errors = []
    all_critical_errors = []

    for result in results:
        all_operations.extend(result.operations_log)
        all_errors.extend(result.errors)
        all_critical_errors.extend(result.critical_errors)

    ops_per_second = total_entries / total_duration if total_duration > 0 else 0.0

    return LDAPBulkResult(
        total_entries=total_entries,
        successful_entries=successful_entries,
        failed_entries=failed_entries,
        operation_type=first_result.operation_type,
        operations_log=all_operations,
        operation_duration=total_duration,
        operations_per_second=ops_per_second,
        errors=all_errors,
        critical_errors=all_critical_errors,
    )


# ============================================================================
# 🔄 MIGRATION UTILITIES - Convert legacy results to unified api.Result[T]
# ============================================================================


def migrate_connection_result_to_unified(
    legacy_result: LDAPConnectionResult,
) -> Result[bool]:
    """Convert LDAPConnectionResult to unified Result[bool].

    DEPRECATED: Use api.Result[bool] directly for new connection testing.

    Args:
        legacy_result: Legacy connection result

    Returns:
        Unified Result[bool] with connection status
    """
    warnings.warn(
        "LDAPConnectionResult is deprecated. Use api.Result[bool] with LDAP.test_connection() instead.",
        DeprecationWarning,
        stacklevel=2,
    )

    # Dynamic import to avoid circular dependency
    from flext_ldap.domain.results import Result

    if legacy_result.has_errors:
        error_msg = (
            legacy_result.connection_error
            or legacy_result.auth_error
            or "Connection failed"
        )
        return Result.fail(error_msg, default_data=False)

    return Result.ok(
        legacy_result.connected,
        context={
            "host": legacy_result.host,
            "port": legacy_result.port,
            "secure": legacy_result.is_secure,
            "connection_time": legacy_result.connection_time,
        },
    )


def migrate_search_result_to_unified(
    legacy_result: LDAPSearchResult,
) -> Result[list[dict[str, Any]]]:
    """Convert LDAPSearchResult to unified Result[list[LDAPEntry]].

    DEPRECATED: Use api.Result[list[LDAPEntry]] with LDAP.search() instead.

    Args:
        legacy_result: Legacy search result

    Returns:
        Unified Result with search entries
    """
    warnings.warn(
        "LDAPSearchResult is deprecated. Use api.Result[list[LDAPEntry]] with LDAP.query().execute() instead.",
        DeprecationWarning,
        stacklevel=2,
    )

    # Dynamic import to avoid circular dependency
    from flext_ldap.domain.results import Result

    if not legacy_result.success or legacy_result.has_errors:
        error_msg = (
            "; ".join(legacy_result.errors) if legacy_result.errors else "Search failed"
        )
        return Result.fail(error_msg, default_data=[])

    return Result.ok(
        legacy_result.entries,
        execution_time_ms=legacy_result.search_duration * 1000,
        context={
            "base_dn": legacy_result.search_base,
            "filter": legacy_result.search_filter,
            "count": legacy_result.entries_found,
            "scope": legacy_result.scope,
        },
    )


def migrate_operation_result_to_unified(
    legacy_result: LDAPOperationResult[T],
) -> Result[T]:
    """Convert LDAPOperationResult to unified Result[T].

    DEPRECATED: Use api.Result[T] directly for LDAP operations.

    Args:
        legacy_result: Legacy operation result

    Returns:
        Unified Result with operation data
    """
    warnings.warn(
        "LDAPOperationResult is deprecated. Use api.Result[T] with unified LDAP operations instead.",
        DeprecationWarning,
        stacklevel=2,
    )

    # Dynamic import to avoid circular dependency
    from flext_ldap.domain.results import Result

    if legacy_result.has_error:
        return Result.fail(
            legacy_result.error_message or "Operation failed",
            code=str(legacy_result.ldap_error_code)
            if legacy_result.ldap_error_code
            else None,
            execution_time_ms=legacy_result.operation_duration * 1000,
            default_data=legacy_result.data,
        )

    return Result.ok(
        legacy_result.data,
        execution_time_ms=legacy_result.operation_duration * 1000,
        context={
            "operation": legacy_result.operation,
            "transaction_id": legacy_result.transaction_id,
            "backup_created": legacy_result.backup_created,
        },
    )


def migrate_bulk_result_to_unified(
    legacy_result: LDAPBulkResult,
) -> Result[dict[str, Any]]:
    """Convert LDAPBulkResult to unified Result[dict].

    DEPRECATED: Use api.Result[dict] for bulk operation summaries.

    Args:
        legacy_result: Legacy bulk result

    Returns:
        Unified Result with bulk operation summary
    """
    warnings.warn(
        "LDAPBulkResult is deprecated. Use api.Result[dict] for bulk operation reporting instead.",
        DeprecationWarning,
        stacklevel=2,
    )

    # Dynamic import to avoid circular dependency
    from flext_ldap.domain.results import Result

    summary_data = {
        "total_entries": legacy_result.total_entries,
        "successful_entries": legacy_result.successful_entries,
        "failed_entries": legacy_result.failed_entries,
        "success_rate": legacy_result.success_rate,
        "operation_type": legacy_result.operation_type,
        "operations_per_second": legacy_result.operations_per_second,
    }

    if legacy_result.has_critical_errors:
        error_msg = "; ".join(legacy_result.critical_errors)
        return Result.fail(
            f"Bulk operation had critical errors: {error_msg}",
            execution_time_ms=legacy_result.operation_duration * 1000,
            default_data=summary_data,
        )

    return Result.ok(
        summary_data,
        execution_time_ms=legacy_result.operation_duration * 1000,
        context={
            "transaction_committed": legacy_result.transaction_committed,
            "backup_created": legacy_result.backup_created,
            "warnings": len(legacy_result.errors),
        },
    )


# Utility function to auto-migrate any legacy result to unified format
def auto_migrate_to_unified(legacy_result: Any) -> Result[Any]:
    """Automatically migrate any legacy result to unified format.

    Args:
        legacy_result: Any legacy result object

    Returns:
        Unified Result object

    Raises:
        ValueError: If result type is not recognized
    """
    if isinstance(legacy_result, LDAPConnectionResult):
        return migrate_connection_result_to_unified(legacy_result)
    if isinstance(legacy_result, LDAPSearchResult):
        return migrate_search_result_to_unified(legacy_result)
    if isinstance(legacy_result, LDAPOperationResult):
        return migrate_operation_result_to_unified(legacy_result)
    if isinstance(legacy_result, LDAPBulkResult):
        return migrate_bulk_result_to_unified(legacy_result)
    msg = f"Unknown legacy result type: {type(legacy_result)}"
    raise ValueError(msg)


# Export migration utilities
__all__ = [
    "LDAPBulkResult",
    "LDAPConnectionResult",
    "LDAPOperationResult",
    "LDAPSearchResult",
    "auto_migrate_to_unified",
    "migrate_bulk_result_to_unified",
    "migrate_connection_result_to_unified",
    "migrate_operation_result_to_unified",
    "migrate_search_result_to_unified",
]
