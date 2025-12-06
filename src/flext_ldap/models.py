"""LDAP domain models and data structures.

This module defines Pydantic v2 models for LDAP operations including connection
configuration, search options, operation results, and sync operations. Uses advanced
Python 3.13 features with computed fields, nested validation, and type-safe patterns.
Reuses FlextLdifModels for Entry/DN handling to avoid duplication
and maintain consistency.

Business Rules:
    - ConnectionConfig enforces SSL/TLS mutual exclusion
      (cannot use both simultaneously)
    - SearchOptions validates base_dn format via FlextLdifUtilities.DN.validate()
    - SearchOptions.normalized() factory uses DN.norm_string() for consistency
    - SyncStats.success_rate computed as (added + skipped) / total
      (skipped = already exists)
    - BatchUpsertResult.success_rate computed as successful / total_processed
    - All models are frozen (immutable) unless mutability is required for service state

Audit Implications:
    - OperationResult tracks entries_affected for audit trail
    - ConversionMetadata preserves source_dn, removed_attributes, attribute_changes
    - PhaseSyncResult tracks per-phase duration and success rate
      for compliance reporting
    - MultiPhaseSyncResult aggregates all phases with overall_success_rate metric

Architecture Notes:
    - Uses m.Collections base classes
      (Config, Options, Results, Statistics)
    - Uses FlextModels.Entity for models requiring entity identity
      (SearchResult, BatchUpsertResult)
    - Uses m.Entry via inheritance (no duplication)
      (no duplication, full hierarchy exposed)
    - Python 3.13+ PEP 695 type aliases in nested Types class
    - @computed_field for derived values (success_rate, total_count, by_objectclass)
    - Factory methods (normalized, from_counters) encapsulate common creation patterns

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import logging
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Self

from flext_core import FlextModels, FlextRuntime
from flext_ldif import FlextLdifModels, FlextLdifUtilities
from pydantic import (
    ConfigDict,
    Field,
    computed_field,
    field_validator,
    model_validator,
)

from flext_ldap.constants import FlextLdapConstants as c
from flext_ldap.typings import FlextLdapTypes as t
from flext_ldap.utilities import FlextLdapUtilities as u


class FlextLdapModels(FlextLdifModels):
    """LDAP domain models extending FlextLdifModels.

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
    # COLLECTIONS - Expose FlextModels.Collections via inheritance
    # =========================================================================

    class Collections(FlextModels.Collections):
        """Collections base classes extending FlextModels.Collections.

        Exposes Config, Options, Results, Statistics, Categories via inheritance
        to enable access via m.Collections.* namespace.
        """

        class Config(FlextModels.Collections.Config):
            """Collections config - real inheritance."""

        class Rules(FlextModels.Collections.Rules):
            """Collections rules - real inheritance."""

        class Statistics(FlextModels.Collections.Statistics):
            """Collections statistics - real inheritance."""

        class Results(FlextModels.Collections.Results):
            """Collections results - real inheritance."""

        class Options(FlextModels.Collections.Options):
            """Collections options - real inheritance."""

        class ParseOptions(FlextModels.Collections.ParseOptions):
            """Collections parse options - real inheritance."""

        class Categories[T](FlextModels.Collections.Categories[T]):
            """Categories collection with real inheritance - generic class."""

    # =========================================================================
    # ENTITY - Expose FlextModels.Entity via inheritance
    # =========================================================================

    class Entity(FlextModels.Entity):
        """Entity base class extending FlextModels.Entity.

        Exposes Entity base class via inheritance to enable access via
        m.Entity namespace.
        """

    # =========================================================================
    # LDIF MODELS - Expose FlextLdifModels via inheritance
    # =========================================================================
    # BaseEntry is inherited from FlextLdifModels (no need to redeclare per rule 19)

    class Entry(FlextLdifModels.Entry):
        """LDAP entry model extending public API Entry from flext-ldif.

        Exposes Entry model via inheritance to enable access via
        m.Entry namespace. Uses public API (m.Entry) internally.
        """

    # Direct re-export aliases from FlextLdifModels
    # These are type aliases, not subclasses - provides m.DistinguishedName syntax
    DistinguishedName = FlextLdifModels.DistinguishedName
    """Distinguished name model alias from flext-ldif.

    Direct re-export to enable access via m.DistinguishedName namespace.
    """

    LdifAttributes = FlextLdifModels.LdifAttributes
    """LDIF attributes model alias from flext-ldif.

    Direct re-export to enable access via m.LdifAttributes namespace.
    """

    QuirkMetadata = FlextLdifModels.QuirkMetadata
    """Quirk metadata model alias from flext-ldif.

    Direct re-export to enable access via m.QuirkMetadata namespace.
    """

    ParseResponse = FlextLdifModels.ParseResponse
    """Parse response model alias from flext-ldif.

    Direct re-export to enable access via m.ParseResponse namespace.
    """

    # =========================================================================
    # CONNECTION MODELS
    # =========================================================================

    class ConnectionConfig(Collections.Config):
        """Configuration for LDAP connection (frozen, immutable)."""

        host: str = Field(default="localhost")
        port: int = Field(
            default=c.ConnectionDefaults.PORT,
            ge=1,
            le=65535,
        )
        use_ssl: bool = Field(default=False)
        use_tls: bool = Field(default=False)
        bind_dn: str | None = Field(default=None)
        bind_password: str | None = Field(default=None)
        timeout: int = Field(
            default=c.ConnectionDefaults.TIMEOUT,
            ge=1,
        )
        auto_bind: bool = Field(default=c.ConnectionDefaults.AUTO_BIND)
        auto_range: bool = Field(
            default=c.ConnectionDefaults.AUTO_RANGE,
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

    class SearchOptions(Collections.Options):
        """Options for LDAP search operations.

        Frozen value object with DN validation.
        """

        base_dn: str = Field(...)
        scope: str = Field(
            default="SUBTREE",
        )
        filter_str: str = Field(default=c.Filters.ALL_ENTRIES_FILTER)
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
            v: str | c.SearchScope,
        ) -> str:
            """Normalize scope to string (accepts StrEnum or str).

            Business Rules:
                - StrEnum values are converted to their string value
                - String values are parsed using u.Enum.parse
                - Used by Pydantic field_validator for automatic normalization
                - Ensures consistent string format for scope field

            Architecture:
                - Uses u.Enum.parse for unified enum parsing
                - Returns str for consistent field type
                - No network calls - pure data normalization

            Args:
                v: Scope value (StrEnum or string).

            Returns:
                Normalized string value.

            """
            if isinstance(v, c.SearchScope):
                return v.value
            # Use FlextLdapUtilities.Enum.parse for unified enum parsing
            parse_result = u.Enum.parse(
                c.SearchScope,
                v,
            )
            if parse_result.is_success:
                return parse_result.value.value
            return str(v)

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
        ) -> Self:
            """Create SearchOptions with normalized base_dn using DN.norm_string().

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
                config: Optional NormalizedConfig with scope, filter,
                    attributes, limits.

            Returns:
                SearchOptions instance with normalized base_dn.

            """
            # Use default config if None
            if config is None:
                config = cls.NormalizedConfig()

            normalized_base = FlextLdifUtilities.DN.norm_string(base_dn)
            return cls(
                base_dn=normalized_base,
                scope=config.scope or "SUBTREE",
                filter_str=config.filter_str or c.Filters.ALL_ENTRIES_FILTER,
                attributes=config.attributes,
                size_limit=config.size_limit or 0,
                time_limit=config.time_limit or 0,
            )

    # =========================================================================
    # OPERATION RESULT MODELS
    # =========================================================================

    class OperationResult(Collections.Results):
        """Result of LDAP operation (frozen, immutable).

        Generic result model for all LDAP operations.
        Uses FlextModels.Results base (Value object) for:
        - Immutability (frozen=True)
        - Value-based equality
        - Hashability for caching
        """

        success: bool = Field(..., description="Whether operation succeeded")
        operation_type: c.OperationType = Field(
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

    class SearchResult(Entity):
        """Result of LDAP search operation with Entity features."""

        entries: list[m.Entry] = Field(default_factory=list)
        search_options: m.SearchOptions

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
        ) -> m.Collections.Categories[m.Entry]:
            """Categorize entries by objectClass attribute.

            Business Rules:
                - Entries are grouped by first objectClass value
                - Entries without objectClass are categorized as "unknown"
                - Uses m.Collections.Categories for grouping
                - Handles both LdifAttributes and Mapping types

            Audit Implications:
                - Categorization enables entry analysis by object type
                - Unknown category indicates missing objectClass attribute
                - Categories can be used for compliance reporting

            Architecture:
                - Uses m.Collections.Categories for grouping
                - Handles LdifAttributes and Mapping types safely
                - Returns Categories[Entry] for type-safe access
                - No network calls - pure data categorization

            Returns:
                Categories instance with entries grouped by objectClass.

            """
            categories: m.Collections.Categories[m.Entry] = m.Collections.Categories[
                m.Entry
            ]()

            logger = logging.getLogger(__name__)
            for entry in self.entries:
                try:
                    category = self.__class__.get_entry_category(entry)
                    categories.add_entries(category, [entry])
                except Exception as e:
                    logger.debug(
                        "Failed to process entry, skipping",
                        exc_info=e,
                    )
                    continue
            return categories

        @classmethod
        def extract_attrs_dict_from_entry(
            cls,
            entry: m.Entry,
        ) -> dict[str, list[str]]:
            """Extract attributes dict from entry.

            Uses duck-typing to handle m.LdifAttributes (public API)
            which has the same structure with .attributes property.

            Args:
                entry: Entry to extract attributes from

            Returns:
                Attributes dict or empty dict

            """
            if entry.attributes is None:
                return {}
            # Try primary approach: LdifAttributes-like object with .attributes dict
            if hasattr(entry.attributes, "attributes"):
                inner_attrs = getattr(entry.attributes, "attributes", None)
                if isinstance(inner_attrs, Mapping):
                    return cls._convert_attrs_mapping(inner_attrs)
            # Fallback: try direct dict-like access
            if hasattr(entry.attributes, "items"):
                return cls._convert_items_method(entry.attributes)
            return {}

        @classmethod
        def _convert_attrs_mapping(
            cls,
            attrs: Mapping[str, object],
        ) -> dict[str, list[str]]:
            """Convert attributes mapping to dict[str, list[str]]."""
            result: dict[str, list[str]] = {}
            for k, v in attrs.items():
                if FlextRuntime.is_list_like(v):
                    result[k] = [str(item) for item in v]
                else:
                    result[k] = [str(v)]
            return result

        @classmethod
        def _convert_items_method(
            cls,
            attrs: object,
        ) -> dict[str, list[str]]:
            """Convert items method result to dict[str, list[str]]."""
            try:
                items_method = getattr(attrs, "items", None)
                if items_method is not None and callable(items_method):
                    items_result = items_method()
                    if isinstance(items_result, (list, tuple)):
                        return cls._convert_attrs_mapping(dict(items_result))
            except (AttributeError, TypeError):
                pass
            return {}

        @classmethod
        def extract_objectclass_category(
            cls,
            attrs_dict: dict[str, list[str]],
        ) -> str:
            """Extract objectClass category from attributes.

            Args:
                attrs_dict: Attributes dictionary

            Returns:
                Category name or "unknown"

            """
            if not attrs_dict:
                return "unknown"
            object_classes_raw = attrs_dict.get("objectClass", [])
            if FlextRuntime.is_list_like(object_classes_raw):
                object_classes = [str(item) for item in object_classes_raw if item]
            else:
                object_classes = [str(object_classes_raw)] if object_classes_raw else []
            found_category = next(
                (oc for oc in object_classes if oc and oc.strip()),
                None,
            )
            return found_category or "unknown"

        @classmethod
        def get_entry_category(
            cls,
            entry: m.Entry,
        ) -> str:
            """Get category for entry based on objectClass.

            Args:
                entry: Entry to categorize

            Returns:
                Category name or "unknown"

            """
            # Use class methods directly via composition
            attrs_dict = cls.extract_attrs_dict_from_entry(entry)
            return cls.extract_objectclass_category(attrs_dict)

    # =========================================================================
    # SYNC MODELS
    # =========================================================================

    class SyncOptions(Collections.Options):
        """Options for LDIF to LDAP synchronization (frozen, immutable)."""

        batch_size: int = Field(default=100, ge=1)
        auto_create_parents: bool = Field(default=True)
        allow_deletes: bool = Field(default=False)
        source_basedn: str = Field(default="")
        target_basedn: str = Field(default="")
        progress_callback: m.Types.LdapProgressCallback | None = Field(
            default=None,
        )

    class SyncStats(Collections.Statistics):
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
        ) -> Self:
            """Factory method with auto-calculated total from counters.

            Additional kwargs are passed to Pydantic model constructor
            for field updates.
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

    class UpsertResult(Collections.Results):
        """Result of individual LDAP upsert operation (frozen, immutable)."""

        success: bool
        dn: str
        operation: c.OperationType
        error: str | None = None

    class BatchUpsertResult(Entity):
        """Result of batch LDAP upsert operation with Entity features."""

        total_processed: int = Field(ge=0)
        successful: int = Field(ge=0)
        failed: int = Field(ge=0)
        results: list[m.UpsertResult] = Field(default_factory=list)

        @computed_field
        def success_rate(self) -> float:
            """Calculate success rate as percentage.

            Business Rules:
                - Returns 0.0 if total_processed is 0 (no operations performed)
                - Success rate = successful / total_processed
                - Result is float between 0.0 and 1.0
                  (can be multiplied by 100 for percentage)

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

    class SyncPhaseConfig(Collections.Config):
        """Configuration for phase synchronization operations.

        Immutable dataclass holding settings for sync_phase_entries() and
        sync_multiple_phases() operations. Frozen for hashability and thread safety.

        Business Rules:
            - server_type controls LDIF parsing quirks (RFC, OUD, OID, OpenLDAP)
            - progress_callback can be single-phase (4 params) or multi-phase (5 params)
            - retry_on_errors defaults to None (uses method-level defaults)
            - max_retries defaults to 5 for robust network handling
            - stop_on_error=False enables batch continuation on failures

        Attributes:
            server_type: LDAP server type for LDIF parsing (default: "rfc").
            progress_callback: Optional callback for progress tracking.
            retry_on_errors: Error patterns to retry (None uses defaults).
            max_retries: Maximum retry attempts per entry (default: 5).
            stop_on_error: Abort batch on first error (default: False).

        """

        server_type: c.LiteralTypes.ServerTypeLiteral = Field(
            default="rfc",
            description="LDAP server type for LDIF parsing",
        )
        progress_callback: t.Ldap.ProgressCallbackUnion = Field(
            default=None,
            description="Optional callback for progress tracking",
        )
        retry_on_errors: list[str] | None = Field(
            default=None,
            description="Error patterns to retry (None uses defaults)",
        )
        max_retries: int = Field(
            default=5,
            description="Maximum retry attempts per entry",
        )
        stop_on_error: bool = Field(
            default=False,
            description="Abort batch on first error",
        )

    class ConversionMetadata(Collections.Config):
        """Metadata tracking attribute conversions during ldap3 to LDIF conversion."""

        source_attributes: list[str] = Field(default_factory=list)
        source_dn: str = ""
        removed_attributes: list[str] = Field(default_factory=list)
        base64_encoded_attributes: list[str] = Field(default_factory=list)
        dn_changed: bool = False
        converted_dn: str = ""
        attribute_changes: list[str] = Field(default_factory=list)

    class LdapOperationResult(Collections.Results):
        """Result of LDAP operation as simple key-value structure."""

        operation: c.UpsertOperations

    class LdapBatchStats(Collections.Statistics):
        """Batch operation statistics (frozen, immutable)."""

        synced: int = Field(default=0, ge=0)
        failed: int = Field(default=0, ge=0)
        skipped: int = Field(default=0, ge=0)

    # =========================================================================
    # PHASE SYNC MODELS
    # =========================================================================

    class PhaseSyncResult(Collections.Results):
        """Result of synchronizing a single LDIF phase file to LDAP."""

        phase_name: str
        total_entries: int = Field(ge=0)
        synced: int = Field(ge=0)
        failed: int = Field(ge=0)
        skipped: int = Field(ge=0)
        duration_seconds: float = Field(ge=0.0)
        success_rate: float = Field(ge=0.0, le=100.0)

    class MultiPhaseSyncResult(Collections.Results):
        """Aggregated result of synchronizing multiple LDIF phase files to LDAP."""

        phase_results: dict[str, m.PhaseSyncResult] = Field(
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
            [int, int, str, m.LdapBatchStats],
            None,
        ]
        """Progress callback for batch operations (Python 3.13+ PEP 695 type alias).

        Signature: (index: int, total: int, dn: str, stats: LdapBatchStats) -> None

        Defined in models.py to avoid circular import with typings.py.
        """


# Convenience alias for common usage pattern - exported for domain usage
m = FlextLdapModels

__all__ = ["FlextLdapModels", "m"]
