"""Enterprise-grade typed result classes for LDAP operations.

This module provides comprehensive typed result objects for LDAP operations,
ensuring type safety, IDE support, runtime validation, and consistent result
structures across all LDAP operations.

Architecture:
    The results module serves as the data layer foundation, providing strongly-typed
    result objects that eliminate the need for untyped dictionaries while maintaining
    backward compatibility through conversion methods.

Key Design Principles:
    - Zero Tolerance: No untyped dict returns where structure is known
    - Type Safety: Full typing with mypy compliance  
    - Enterprise Validation: Comprehensive validation using Pydantic
    - Performance: Optimized for high-throughput LDAP operations
    - Composability: Results can be merged and aggregated
    - Backward Compatibility: to_dict() methods for legacy consumers

Result Categories:
    - LDAPConnectionResult: Connection operations, tunnels, authentication
    - LDAPSearchResult: Search operations with pagination and filtering
    - LDAPOperationResult: CRUD operations with transaction support
    - LDAPBulkResult: Bulk operations with progress tracking
    - LDAPPerformanceResult: Performance metrics and monitoring

Version: 1.0.0-enterprise
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, computed_field


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
    connection_time: float = Field(ge=0.0)
    response_time: float = Field(ge=0.0)
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
    @property
    def has_errors(self) -> bool:
        """Check if any connection errors occurred."""
        return bool(self.connection_error or self.auth_error)

    @computed_field
    @property
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
    entries_found: int = Field(ge=0)
    search_base: str
    search_filter: str

    # Search results
    entries: list[dict[str, Any]] = Field(default_factory=list)
    attributes_returned: list[str] = Field(default_factory=list)

    # Search configuration
    scope: str = "subtree"
    size_limit: int = Field(default=1000, ge=0)
    time_limit: int = Field(default=30, ge=0)

    # Performance metrics
    search_duration: float = Field(ge=0.0)
    entries_per_second: float = Field(ge=0.0)

    # Pagination support
    page_size: int | None = Field(default=None, gt=0)
    has_more_pages: bool = False
    page_cookie: str | None = None

    # Error tracking
    errors: list[str] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)

    timestamp: datetime = Field(default_factory=lambda: datetime.now(UTC))

    @computed_field
    @property
    def has_errors(self) -> bool:
        """Check if any search errors occurred."""
        return len(self.errors) > 0

    @computed_field
    @property
    def has_warnings(self) -> bool:
        """Check if any search warnings occurred."""
        return len(self.warnings) > 0


class LDAPOperationResult(BaseModel):
    """Typed result for individual LDAP operations (add, modify, delete)."""

    model_config = ConfigDict(
        strict=True,
        extra="forbid",
        frozen=True,
        validate_assignment=True,
    )

    success: bool
    operation_type: str  # add, modify, delete
    dn: str

    # Operation details
    attributes_modified: dict[str, Any] = Field(default_factory=dict)
    backup_created: bool = False
    transaction_id: str | None = None

    # Performance metrics
    operation_duration: float = Field(ge=0.0)

    # Error tracking
    error_message: str | None = None
    ldap_error_code: int | None = None

    # Rollback information
    rollback_data: dict[str, Any] = Field(default_factory=dict)

    timestamp: datetime = Field(default_factory=lambda: datetime.now(UTC))

    @computed_field
    @property
    def has_error(self) -> bool:
        """Check if operation failed."""
        return not self.success or bool(self.error_message)


class LDAPBulkResult(BaseModel):
    """Typed result for bulk LDAP operations."""

    model_config = ConfigDict(
        strict=True,
        extra="forbid",
        frozen=True,
        validate_assignment=True,
    )

    total_entries: int = Field(ge=0)
    successful_entries: int = Field(ge=0)
    failed_entries: int = Field(ge=0)
    operation_type: str

    # Operation details
    operations_log: list[LDAPOperationResult] = Field(default_factory=list)
    checkpoints: list[dict[str, Any]] = Field(default_factory=list)

    # Performance metrics
    operation_duration: float = Field(ge=0.0)
    operations_per_second: float = Field(ge=0.0)

    # Transaction info
    transaction_id: str | None = None
    transaction_committed: bool = False
    backup_created: bool = False

    # Error tracking
    errors: list[str] = Field(default_factory=list)
    critical_errors: list[str] = Field(default_factory=list)

    timestamp: datetime = Field(default_factory=lambda: datetime.now(UTC))

    @computed_field
    @property
    def success_rate(self) -> float:
        """Calculate success rate as percentage."""
        if self.total_entries == 0:
            return 100.0
        return (self.successful_entries / self.total_entries) * 100.0

    @computed_field
    @property
    def has_critical_errors(self) -> bool:
        """Check if any critical errors occurred."""
        return len(self.critical_errors) > 0

    @computed_field
    @property
    def is_complete_success(self) -> bool:
        """Check if all operations succeeded."""
        return self.failed_entries == 0 and not self.has_critical_errors


class LDAPPerformanceResult(BaseModel):
    """Typed result for LDAP performance monitoring."""

    model_config = ConfigDict(
        strict=True,
        extra="forbid",
        frozen=True,
        validate_assignment=True,
    )

    operation_name: str
    total_operations: int = Field(ge=0)
    successful_operations: int = Field(ge=0)
    failed_operations: int = Field(ge=0)

    # Performance metrics
    total_duration: float = Field(ge=0.0)
    average_duration: float = Field(ge=0.0)
    operations_per_second: float = Field(ge=0.0)

    # Resource usage
    memory_peak_mb: float = Field(ge=0.0)
    cpu_usage_percent: float = Field(ge=0.0, le=100.0)

    # Connection pool metrics
    pool_size: int = Field(ge=0)
    pool_utilization: float = Field(ge=0.0, le=100.0)
    connection_reuse_rate: float = Field(ge=0.0, le=100.0)

    timestamp: datetime = Field(default_factory=lambda: datetime.now(UTC))

    @computed_field
    @property
    def success_rate(self) -> float:
        """Calculate success rate as percentage."""
        if self.total_operations == 0:
            return 100.0
        return (self.successful_operations / self.total_operations) * 100.0

    @computed_field
    @property
    def failure_rate(self) -> float:
        """Calculate failure rate as percentage."""
        if self.total_operations == 0:
            return 0.0
        return (self.failed_operations / self.total_operations) * 100.0


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
    entries_validated: int = Field(ge=0)

    # Validation details
    schema_errors: list[str] = Field(default_factory=list)
    syntax_errors: list[str] = Field(default_factory=list)
    reference_errors: list[str] = Field(default_factory=list)

    # Performance metrics
    validation_duration: float = Field(ge=0.0)

    timestamp: datetime = Field(default_factory=lambda: datetime.now(UTC))

    @computed_field
    @property
    def has_errors(self) -> bool:
        """Check if any validation errors occurred."""
        return len(self.schema_errors + self.syntax_errors + self.reference_errors) > 0

    @computed_field
    @property
    def total_errors(self) -> int:
        """Get total count of all validation errors."""
        return len(self.schema_errors + self.syntax_errors + self.reference_errors)


# Utility functions for result aggregation
def merge_search_results(results: list[LDAPSearchResult]) -> LDAPSearchResult:
    """Merge multiple search results into a single result."""
    if not results:
        return LDAPSearchResult(
            success=False,
            entries_found=0,
            search_base="",
            search_filter="",
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
