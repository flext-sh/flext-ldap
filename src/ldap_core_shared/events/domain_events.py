"""
Domain events for LDAP operations.

Events that capture significant domain occurrences during LDAP
operations, migrations, and validations.
"""

import uuid
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any


@dataclass
class DomainEvent(ABC):
    """Base class for all domain events."""

    event_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: datetime = field(default_factory=datetime.now)
    source: str = field(default="ldap-core")

    @property
    @abstractmethod
    def event_type(self) -> str:
        """Get the event type identifier."""


@dataclass
class LDAPConnectionEvent(DomainEvent):
    """Event for LDAP connection status changes."""

    host: str
    port: int
    bind_dn: str
    connected: bool
    connection_id: str | None = field(default=None)
    error_message: str | None = field(default=None)

    @property
    def event_type(self) -> str:
        return "ldap.connection"


@dataclass
class LDAPOperationEvent(DomainEvent):
    """Event for LDAP operations (search, add, modify, delete)."""

    operation: str  # search, add, modify, delete
    dn: str
    success: bool
    duration_ms: float | None = field(default=None)
    entry_count: int | None = field(default=None)
    error_message: str | None = field(default=None)
    attributes_modified: list[str] | None = field(default=None)

    @property
    def event_type(self) -> str:
        return "ldap.operation"


@dataclass
class MigrationStageEvent(DomainEvent):
    """Event for migration stage completion."""

    migration_id: str
    stage_name: str
    stage_order: int
    success: bool
    entries_processed: int = 0
    entries_successful: int = 0
    entries_failed: int = 0
    duration_s: float | None = None
    error_details: list[str] | None = None

    @property
    def event_type(self) -> str:
        return "migration.stage"


@dataclass
class MigrationCompletedEvent(DomainEvent):
    """Event for complete migration finish."""

    migration_id: str
    success: bool
    total_stages: int
    successful_stages: int
    total_entries: int
    successful_entries: int
    total_duration_s: float
    final_validation_passed: bool
    summary_report: dict[str, Any]

    @property
    def event_type(self) -> str:
        return "migration.completed"


@dataclass
class ValidationEvent(DomainEvent):
    """Event for validation operations."""

    validation_type: str  # schema, data, connectivity
    target: str  # what was validated
    success: bool
    details: dict[str, Any] = field(default_factory=dict)
    warnings: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    recommendations: list[str] = field(default_factory=list)

    @property
    def event_type(self) -> str:
        return "validation"


@dataclass
class ErrorEvent(DomainEvent):
    """Event for error conditions."""

    error_type: str
    error_message: str
    component: str
    severity: str  # critical, error, warning
    context: dict[str, Any] = field(default_factory=dict)
    stack_trace: str | None = None
    recovery_suggestions: list[str] = field(default_factory=list)

    @property
    def event_type(self) -> str:
        return "error"


@dataclass
class SchemaDiscoveryEvent(DomainEvent):
    """Event for schema discovery operations."""

    server_host: str
    object_classes_found: int
    attributes_found: int
    custom_schemas_detected: list[str] = field(default_factory=list)
    compatibility_issues: list[str] = field(default_factory=list)
    discovery_duration_s: float | None = None

    @property
    def event_type(self) -> str:
        return "schema.discovery"


@dataclass
class PerformanceEvent(DomainEvent):
    """Event for performance metrics."""

    operation_type: str
    measurement_type: str  # throughput, latency, memory
    value: float
    unit: str  # ops/sec, ms, MB
    component: str
    additional_metrics: dict[str, float] = field(default_factory=dict)

    @property
    def event_type(self) -> str:
        return "performance"
