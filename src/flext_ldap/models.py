"""LDAP domain models and data structures.

This module defines Pydantic v2 models for LDAP operations including connection
configuration, search options, operation results, and sync operations. Uses advanced
Python 3.13 features with computed fields, nested validation, and type-safe patterns.
Reuses FlextLdifModels for Entry/DN handling to avoid duplication and maintain consistency.

Business Rules:
    - ConnectionConfig enforces SSL/TLS mutual exclusion (cannot use both simultaneously)
    - SearchOptions validates base_dn format via FlextLdifUtilities.DN.validate()
    - SearchOptions.normalized() factory uses DN.norm_string() for consistency
    - SyncStats.success_rate computed as (added + skipped) / total (skipped = already exists)
    - BatchUpsertResult.success_rate computed as successful / total_processed
    - All models are frozen (immutable) unless mutability is required for service state

Audit Implications:
    - OperationResult tracks entries_affected for audit trail
    - ConversionMetadata preserves source_dn, removed_attributes, attribute_changes
    - PhaseSyncResult tracks per-phase duration and success rate for compliance reporting
    - MultiPhaseSyncResult aggregates all phases with overall_success_rate metric

Architecture Notes:
    - Uses FlextModelsCollections base classes (Config, Options, Results, Statistics)
    - Uses FlextModelsEntity.Core for models requiring entity identity (SearchResult, BatchUpsertResult)
    - Reuses FlextLdifModels.Entry for LDAP entries (no duplication)
    - Python 3.13+ PEP 695 type aliases in nested Types class
    - @computed_field for derived values (success_rate, total_count, by_objectclass)
    - Factory methods (normalized, from_counters) encapsulate common creation patterns

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Self

from flext_core import FlextModels, FlextUtilities
from flext_core._models.collections import FlextModelsCollections
from flext_core._models.entity import FlextModelsEntity
from flext_ldif import FlextLdifModels
from flext_ldif.utilities import FlextLdifUtilities
from pydantic import (
    ConfigDict,
    Field,
    computed_field,
    field_validator,
    model_validator,
)

from flext_ldap.constants import FlextLdapConstants


class FlextLdapModels(FlextModels):
    """LDAP domain models extending flext-core FlextModels.

    Uses advanced Python 3.13 patterns with enums, mappings, and computed fields
    for type-safe, efficient model definitions. All models follow Pydantic v2 patterns
    with proper validation and immutability.

    **Pydantic 2 Integration:**
    - use_enum_values=True: StrEnum fields serialize as strings
    - validate_default=True: Validates default values
    - arbitrary_types_allowed=True: Allows custom types
    - str_strip_whitespace=True: Strips whitespace from strings
    - extra="forbid": Rejects extra fields
    """

    model_config = ConfigDict(
        frozen=True,  # Immutable models
        use_enum_values=True,  # StrEnum → string serialization
        validate_default=True,  # Validate defaults
        arbitrary_types_allowed=True,  # Custom types allowed
        str_strip_whitespace=True,  # Strip whitespace
        extra="forbid",  # Reject extra fields
    )

    # =========================================================================
    # CONNECTION MODELS
    # =========================================================================

    class ConnectionConfig(FlextModelsCollections.Config):
        """Configuration for LDAP connection (frozen, immutable)."""

        host: str = Field(default="localhost")
        port: int = Field(
            default=FlextLdapConstants.ConnectionDefaults.PORT,
            ge=1,
            le=65535,
        )
        use_ssl: bool = Field(default=False)
        use_tls: bool = Field(default=False)
        bind_dn: str | None = Field(default=None)
        bind_password: str | None = Field(default=None)
        timeout: int = Field(
            default=FlextLdapConstants.ConnectionDefaults.TIMEOUT,
            ge=1,
        )
        auto_bind: bool = Field(default=FlextLdapConstants.ConnectionDefaults.AUTO_BIND)
        auto_range: bool = Field(
            default=FlextLdapConstants.ConnectionDefaults.AUTO_RANGE,
        )

        @model_validator(mode="after")
        def validate_ssl_tls_mutual_exclusion(self) -> Self:
            """Validate SSL and TLS are mutually exclusive."""
            if self.use_ssl and self.use_tls:
                error_msg = (
                    "use_ssl and use_tls are mutually exclusive. "
                    "Use SSL (port 636) OR TLS/STARTTLS (port 389), not both."
                )
                raise ValueError(error_msg)
            return self

    # =========================================================================
    # SEARCH MODELS
    # =========================================================================

    class SearchOptions(FlextModelsCollections.Options):
        """Options for LDAP search operations (frozen value object with DN validation)."""

        base_dn: str = Field(...)
        scope: str = Field(
            default="SUBTREE",
        )
        filter_str: str = Field(default=FlextLdapConstants.Filters.ALL_ENTRIES_FILTER)
        attributes: list[str] | None = Field(default=None)
        size_limit: int = Field(default=0, ge=0)
        time_limit: int = Field(default=0, ge=0)

        @field_validator("base_dn")
        @classmethod
        def validate_base_dn_format(cls, v: str) -> str:
            """Validate base_dn format."""
            if not FlextLdifUtilities.DN.validate(v):
                error_msg = f"Invalid base_dn format: {v}"
                raise ValueError(error_msg)
            return v

        @field_validator("scope", mode="before")
        @classmethod
        def normalize_scope(
            cls,
            v: str | FlextLdapConstants.SearchScope,
        ) -> str:
            """Normalize scope to string (accepts StrEnum or str).

            Business Rules:
                - StrEnum values are converted to their string value
                - String values are returned as-is
                - Used by Pydantic field_validator for automatic normalization
                - Ensures consistent string format for scope field

            Architecture:
                - Uses isinstance check for StrEnum detection
                - Returns str for consistent field type
                - No network calls - pure data normalization

            Args:
                v: Scope value (StrEnum or string).

            Returns:
                Normalized string value.

            """
            if isinstance(v, FlextLdapConstants.SearchScope):
                return v.value
            return v

        @dataclass(frozen=True)
        class NormalizedConfig:
            """Configuration for normalized SearchOptions factory."""

            scope: str | None = None
            filter_str: str | None = None
            attributes: list[str] | None = None
            size_limit: int | None = None
            time_limit: int | None = None

        @classmethod
        def normalized(
            cls,
            base_dn: str,
            *,
            config: NormalizedConfig | None = None,
        ) -> FlextLdapModels.SearchOptions:
            """Factory method with normalized base_dn using DN.norm_string().

            Business Rules:
                - Base DN is normalized using FlextLdifUtilities.DN.norm_string()
                - Default scope is "SUBTREE" if not provided
                - Default filter is ALL_ENTRIES_FILTER if not provided
                - Default size_limit and time_limit are 0 (unlimited)
                - Uses NormalizedConfig dataclass for optional parameters

            Audit Implications:
                - DN normalization ensures consistent format across operations
                - Normalized DNs enable proper LDAP directory targeting
                - Factory method provides type-safe SearchOptions creation

            Architecture:
                - Uses FlextLdifUtilities.DN.norm_string() for DN normalization
                - Returns validated SearchOptions instance
                - No network calls - pure factory method

            Args:
                base_dn: Base distinguished name to normalize.
                config: Optional NormalizedConfig with scope, filter, attributes, limits.

            Returns:
                SearchOptions instance with normalized base_dn.

            """
            if config is None:
                config = cls.NormalizedConfig()

            normalized_base = FlextLdifUtilities.DN.norm_string(base_dn)
            return cls(
                base_dn=normalized_base,
                scope=config.scope if config.scope is not None else "SUBTREE",
                filter_str=config.filter_str
                if config.filter_str is not None
                else FlextLdapConstants.Filters.ALL_ENTRIES_FILTER,
                attributes=config.attributes,
                size_limit=config.size_limit if config.size_limit is not None else 0,
                time_limit=config.time_limit if config.time_limit is not None else 0,
            )

    # =========================================================================
    # OPERATION RESULT MODELS
    # =========================================================================

    class OperationResult(FlextModelsCollections.Results):
        """Result of LDAP operation (frozen, immutable).

        Generic result model for all LDAP operations.
        Uses FlextModels.Results base (Value object) for:
        - Immutability (frozen=True)
        - Value-based equality
        - Hashability for caching
        """

        success: bool = Field(..., description="Whether operation succeeded")
        operation_type: FlextLdapConstants.OperationType = Field(
            ...,
            description="Type of operation performed",
        )
        message: str = Field(
            default="",
            description="Operation result message",
        )
        entries_affected: int = Field(
            default=0,
            ge=0,
            description="Number of entries affected",
        )

    # =========================================================================
    # SEARCH RESULT MODELS
    # =========================================================================

    class SearchResult(FlextModelsEntity.Core):
        """Result of LDAP search operation with Entity features."""

        entries: list[FlextLdifModels.Entry] = Field(default_factory=list)
        search_options: FlextLdapModels.SearchOptions

        @computed_field
        def total_count(self) -> int:
            """Total number of entries found.

            Business Rules:
                - Returns length of entries list
                - Always >= 0 (empty list returns 0)
                - Computed field (no storage, calculated on access)

            Architecture:
                - Uses Pydantic computed_field decorator
                - Returns int for count value
                - No network calls - pure computed property

            Returns:
                Number of entries in search result.

            """
            return len(self.entries)

        @computed_field
        def by_objectclass(
            self,
        ) -> FlextModelsCollections.Categories[FlextLdifModels.Entry]:
            """Categorize entries by objectClass attribute.

            Business Rules:
                - Entries are grouped by first objectClass value
                - Entries without objectClass are categorized as "unknown"
                - Uses FlextModelsCollections.Categories for grouping
                - Handles both LdifAttributes and Mapping types

            Audit Implications:
                - Categorization enables entry analysis by object type
                - Unknown category indicates missing objectClass attribute
                - Categories can be used for compliance reporting

            Architecture:
                - Uses FlextModelsCollections.Categories for grouping
                - Handles LdifAttributes and Mapping types safely
                - Returns Categories[Entry] for type-safe access
                - No network calls - pure data categorization

            Returns:
                Categories instance with entries grouped by objectClass.

            """
            categories: FlextModelsCollections.Categories[FlextLdifModels.Entry] = (
                FlextModelsCollections.Categories()
            )
            for entry in self.entries:
                if entry.attributes is None:
                    categories.add_entries("unknown", [entry])
                    continue
                # Type narrowing: LdifAttributes has .attributes property
                # entry.attributes can be LdifAttributes | Mapping[str, Sequence[str]] | None
                # None already handled above, so remaining types are LdifAttributes | Mapping
                if isinstance(entry.attributes, FlextLdifModels.LdifAttributes):
                    attrs_dict = entry.attributes.attributes
                elif isinstance(entry.attributes, Mapping):
                    # Type narrowing: entry.attributes is Mapping[str, Sequence[str]]
                    # Convert Mapping to dict[str, list[str]] for processing
                    attrs_dict = {k: list(v) for k, v in entry.attributes.items()}
                else:
                    # Fallback: empty dict if type is unexpected
                    attrs_dict = {}
                object_classes = attrs_dict.get("objectClass", [])
                category = (
                    object_classes[0]
                    if object_classes
                    and FlextUtilities.TypeGuards.is_string_non_empty(object_classes[0])
                    else "unknown"
                )
                categories.add_entries(category, [entry])
            return categories

    # =========================================================================
    # SYNC MODELS
    # =========================================================================

    class SyncOptions(FlextModelsCollections.Options):
        """Options for LDIF to LDAP synchronization (frozen, immutable)."""

        batch_size: int = Field(default=100, ge=1)
        auto_create_parents: bool = Field(default=True)
        allow_deletes: bool = Field(default=False)
        source_basedn: str = Field(default="")
        target_basedn: str = Field(default="")
        progress_callback: FlextLdapModels.Types.LdapProgressCallback | None = Field(
            default=None,
        )

    class SyncStats(FlextModelsCollections.Statistics):
        """Statistics for LDIF synchronization operation (frozen, immutable)."""

        added: int = Field(default=0, ge=0)
        skipped: int = Field(default=0, ge=0)
        failed: int = Field(default=0, ge=0)
        total: int = Field(default=0, ge=0)
        duration_seconds: float = Field(default=0.0, ge=0.0)

        @computed_field
        def success_rate(self) -> float:
            """Calculate success rate as float (0.0-1.0).

            Business Rules:
                - Returns 0.0 if total is 0 (no operations performed)
                - Success rate = (added + skipped) / total
                - Skipped entries count as successful (not failures)
                - Result is float between 0.0 and 1.0

            Audit Implications:
                - Success rate indicates operation reliability
                - Skipped entries are considered successful (not errors)
                - Used for performance and compliance reporting

            Architecture:
                - Uses Pydantic computed_field decorator
                - Returns float for percentage calculation
                - No network calls - pure computed property

            Returns:
                Success rate as float (0.0-1.0).

            """
            if self.total == 0:
                return 0.0
            return (self.added + self.skipped) / self.total

        @classmethod
        def from_counters(
            cls,
            added: int = 0,
            skipped: int = 0,
            failed: int = 0,
            duration_seconds: float = 0.0,
            **kwargs: str | float | bool | None,
        ) -> FlextLdapModels.SyncStats:
            """Factory method with auto-calculated total from counters.

            Additional kwargs are passed to Pydantic model constructor for field updates.
            """
            return cls(
                added=added,
                skipped=skipped,
                failed=failed,
                total=added + skipped + failed,
                duration_seconds=duration_seconds,
                **kwargs,
            )

    # =========================================================================
    # UPSERT RESULT MODELS
    # =========================================================================

    class UpsertResult(FlextModelsCollections.Results):
        """Result of individual LDAP upsert operation (frozen, immutable)."""

        success: bool
        dn: str
        operation: FlextLdapConstants.OperationType
        error: str | None = None

    class BatchUpsertResult(FlextModelsEntity.Core):
        """Result of batch LDAP upsert operation with Entity features."""

        total_processed: int = Field(ge=0)
        successful: int = Field(ge=0)
        failed: int = Field(ge=0)
        results: list[FlextLdapModels.UpsertResult] = Field(default_factory=list)

        @computed_field
        def success_rate(self) -> float:
            """Calculate success rate as percentage.

            Business Rules:
                - Returns 0.0 if total_processed is 0 (no operations performed)
                - Success rate = successful / total_processed
                - Result is float between 0.0 and 1.0 (can be multiplied by 100 for percentage)

            Audit Implications:
                - Success rate indicates batch operation reliability
                - Used for performance and compliance reporting
                - Failed operations reduce success rate

            Architecture:
                - Uses Pydantic computed_field decorator
                - Returns float for percentage calculation
                - No network calls - pure computed property

            Returns:
                Success rate as float (0.0-1.0).

            """
            if self.total_processed == 0:
                return 0.0
            return self.successful / self.total_processed

    class ConversionMetadata(FlextModelsCollections.Config):
        """Metadata tracking attribute conversions during ldap3 to LDIF conversion."""

        source_attributes: list[str] = Field(default_factory=list)
        source_dn: str = ""
        removed_attributes: list[str] = Field(default_factory=list)
        base64_encoded_attributes: list[str] = Field(default_factory=list)
        dn_changed: bool = False
        converted_dn: str = ""
        attribute_changes: list[str] = Field(default_factory=list)

    class LdapOperationResult(FlextModelsCollections.Results):
        """Result of LDAP operation as simple key-value structure."""

        operation: FlextLdapConstants.UpsertOperations

    class LdapBatchStats(FlextModelsCollections.Statistics):
        """Batch operation statistics (frozen, immutable)."""

        synced: int = Field(default=0, ge=0)
        failed: int = Field(default=0, ge=0)
        skipped: int = Field(default=0, ge=0)

    # =========================================================================
    # PHASE SYNC MODELS
    # =========================================================================

    class PhaseSyncResult(FlextModelsCollections.Results):
        """Result of synchronizing a single LDIF phase file to LDAP."""

        phase_name: str
        total_entries: int = Field(ge=0)
        synced: int = Field(ge=0)
        failed: int = Field(ge=0)
        skipped: int = Field(ge=0)
        duration_seconds: float = Field(ge=0.0)
        success_rate: float = Field(ge=0.0, le=100.0)

    class MultiPhaseSyncResult(FlextModelsCollections.Results):
        """Aggregated result of synchronizing multiple LDIF phase files to LDAP."""

        phase_results: dict[str, FlextLdapModels.PhaseSyncResult] = Field(
            default_factory=dict,
        )
        total_entries: int = Field(ge=0)
        total_synced: int = Field(ge=0)
        total_failed: int = Field(ge=0)
        total_skipped: int = Field(ge=0)
        overall_success_rate: float = Field(ge=0.0, le=100.0)
        total_duration_seconds: float = Field(ge=0.0)
        overall_success: bool = Field(default=True)

    # =========================================================================
    # TYPE ALIASES (Python 3.13+ PEP 695)
    # =========================================================================

    class Types:
        """Type aliases for FlextLdapModels (Python 3.13+ PEP 695)."""

        type LdapProgressCallback = Callable[
            [int, int, str, FlextLdapModels.LdapBatchStats],
            None,
        ]
        """Progress callback for batch operations (Python 3.13+ PEP 695 type alias).

        Signature: (index: int, total: int, dn: str, stats: LdapBatchStats) -> None

        Defined in models.py to avoid circular import with typings.py.
        """


__all__ = ["FlextLdapModels"]
