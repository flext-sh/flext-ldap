from __future__ import annotations

from ldap_core_shared.utils.constants import (
    DEFAULT_MAX_ITEMS,
    LDAP_DEFAULT_PORT,
    TCP_PORT_MAX,
    TCP_PORT_MIN,
)

"""Core LDAP domain models for shared use across tap-ldap, target-ldap, and flx-ldap."""


from typing import TYPE_CHECKING, Any

from pydantic import BaseModel, Field, field_validator

# Constants for magic values

if TYPE_CHECKING:
    from datetime import datetime
    from pathlib import Path


class LDAPConnectionConfig(BaseModel):
    """LDAP connection configuration.

    Standardized configuration for LDAP connections across all projects.
    """

    host: str = Field(..., description="LDAP server hostname")
    port: int = Field(default=LDAP_DEFAULT_PORT, description="LDAP server port")
    bind_dn: str = Field(..., description="Bind DN for authentication")
    password: str = Field(..., description="Password for authentication")
    base_dn: str = Field(..., description="Base DN for operations")
    use_ssl: bool = Field(default=False, description="Use SSL connection")

    @field_validator("port")
    @classmethod
    def validate_port(cls, v: int) -> int:
        """Validate port number is in valid range."""
        if not TCP_PORT_MIN <= v <= TCP_PORT_MAX:
            msg = f"Port must be between {TCP_PORT_MIN} and {TCP_PORT_MAX}"
            raise ValueError(msg)
        return v


class LDAPEntry(BaseModel):
    """LDAP entry representation.

    Standard representation of an LDAP entry with DN and attributes.
    """

    dn: str = Field(..., description="Distinguished Name")
    attributes: dict[str, list[str]] = Field(
        default_factory=dict,
        description="Entry attributes",
    )
    raw_attributes: dict[str, list[bytes]] = Field(
        default_factory=dict,
        description="Raw binary attributes",
    )

    @field_validator("dn")
    @classmethod
    def validate_dn(cls, v: str) -> str:
        """Validate DN is not empty."""
        if not v.strip():
            msg = "DN cannot be empty"
            raise ValueError(msg)
        return v.strip()

    def get_attribute(self, name: str) -> str | None:
        """Get single attribute value by name (case-insensitive).

        Returns first value for multi-valued attributes for compatibility
        with the unified API. Use get_attribute_values() for all values.
        """
        values = self.get_attribute_values(name)
        return values[0] if values else None

    def get_attribute_values(self, name: str) -> list[str]:
        """Get all attribute values by name (case-insensitive)."""
        for attr_name, values in self.attributes.items():
            if attr_name.lower() == name.lower():
                return values
        return []

    def has_object_class(self, object_class: str) -> bool:
        """Check if entry has specific object class."""
        object_classes = self.get_attribute_values("objectClass")
        return any(oc.lower() == object_class.lower() for oc in object_classes)

    def is_user(self) -> bool:
        """Check if entry is a user (person/user object class)."""
        return self.has_object_class("person") or self.has_object_class("user")

    def is_group(self) -> bool:
        """Check if entry is a group."""
        return self.has_object_class("group") or self.has_object_class("groupOfNames")

    def get_display_name(self) -> str:
        """Get display name (cn, displayName, or name attribute)."""
        return (
            self.get_attribute("displayName")
            or self.get_attribute("cn")
            or self.get_attribute("name")
            or self.dn.split(",")[0].split("=")[1]
            if "=" in self.dn
            else self.dn
        )


class MigrationConfig(BaseModel):
    """Migration configuration.

    Standard configuration for LDAP migration operations.
    """

    source_ldif_path: Path = Field(..., description="Source LDIF directory path")
    target_ldap_config: LDAPConnectionConfig = Field(
        ...,
        description="Target LDAP configuration",
    )
    output_directory: Path = Field(
        ...,
        description="Output directory for generated files",
    )
    migration_stages: list[str] = Field(
        default_factory=lambda: [
            "00_hierarchy.ldif",
            "01_schema.ldif",
            "02_data.ldif",
            "03_groups.ldif",
            "04_acls.ldif",
        ],
        description="Migration stages in order",
    )
    skip_existing: bool = Field(default=True, description="Skip existing entries")
    dry_run: bool = Field(
        default=False,
        description="Perform dry run without actual changes",
    )

    @field_validator("source_ldif_path")
    @classmethod
    def validate_source_path(cls, v: Path) -> Path:
        """Validate source path exists."""
        if not v.exists():
            msg = f"Source LDIF path does not exist: {v}"
            raise ValueError(msg)
        return v


class MigrationStats(BaseModel):
    """Migration statistics.

    Tracks statistics for migration operations.
    """

    total_processed: int = Field(default=0, description="Total entries processed")
    successful: int = Field(default=0, description="Successfully processed entries")
    skipped: int = Field(default=0, description="Skipped entries")
    failed: int = Field(default=0, description="Failed entries")
    errors: list[str] = Field(default_factory=list, description="Error messages")

    @property
    def success_rate(self) -> float:
        """Calculate success rate percentage."""
        if self.total_processed == 0:
            return 0.0
        return (
            (self.successful + self.skipped) / self.total_processed
        ) * DEFAULT_MAX_ITEMS


class MigrationStage(BaseModel):
    """Migration stage information.

    Represents a single stage in a multi-stage migration.
    """

    name: str = Field(..., description="Stage name")
    filename: str = Field(..., description="LDIF filename")
    description: str = Field(..., description="Stage description")
    critical: bool = Field(
        default=True,
        description="Whether stage is critical for migration",
    )
    order: int = Field(..., description="Execution order")

    @field_validator("order")
    @classmethod
    def validate_order(cls, v: int) -> int:
        """Validate order is non-negative."""
        if v < 0:
            msg = "Order must be non-negative"
            raise ValueError(msg)
        return v


class MigrationReport(BaseModel):
    """Complete migration report.

    Comprehensive report of migration execution.
    """

    start_time: datetime = Field(..., description="Migration start time")
    end_time: datetime | None = Field(None, description="Migration end time")
    config: Any = Field(
        ...,
        description="Migration configuration",
    )  # Using Any to avoid circular import
    stats: MigrationStats = Field(
        default_factory=MigrationStats,
        description="Migration statistics",
    )
    stage_results: dict[str, bool] = Field(
        default_factory=dict,
        description="Stage results",
    )
    validation_results: dict[str, Any] = Field(
        default_factory=dict,
        description="Validation results",
    )
    success: bool = Field(default=False, description="Overall migration success")

    @property
    def duration(self) -> float | None:
        """Calculate migration duration in seconds."""
        if self.end_time is None:
            return None
        return (self.end_time - self.start_time).total_seconds()


class LDIFGenerationResult(BaseModel):
    """LDIF generation result.

    Result of generating LDIF files during migration.
    """

    stage: str = Field(..., description="Stage name")
    filename: str = Field(..., description="Generated filename")
    file_path: Path | None = Field(None, description="Generated file path")
    success: bool = Field(..., description="Generation success")
    lines_generated: int = Field(default=0, description="Number of lines generated")
    error_message: str | None = Field(None, description="Error message if failed")


class ValidationResult(BaseModel):
    """Validation result for migration.

    Result of validation checks during migration.
    """

    check_name: str = Field(..., description="Validation check name")
    success: bool = Field(..., description="Validation success")
    message: str = Field(..., description="Validation message")
    count: int | None = Field(None, description="Count value if applicable")
    details: dict[str, Any] = Field(
        default_factory=dict,
        description="Additional details",
    )


class EntryProcessingResult(BaseModel):
    """Result of processing a single LDAP entry.

    Detailed result of processing an individual LDAP entry.
    """

    dn: str = Field(..., description="Entry DN")
    success: bool = Field(..., description="Processing success")
    action: str = Field(..., description="Action taken (add, skip, error)")
    message: str = Field(..., description="Result message")
    original_attributes: dict[str, list[str]] = Field(
        default_factory=dict,
        description="Original attributes",
    )
    processed_attributes: dict[str, list[str]] = Field(
        default_factory=dict,
        description="Processed attributes",
    )
