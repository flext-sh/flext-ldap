"""LDAP domain models and data structures.

This module defines Pydantic v2 models for LDAP operations including connection
configuration, search options, operation results, and sync operations. Uses advanced
Python 3.13 features with computed fields, nested validation, and type-safe patterns.
Reuses FlextLdifModels for Entry/DN handling to avoid duplication and maintain consistency.

Tested scope: Model validation, computed properties, factory methods, type safety
Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from collections.abc import Callable
from typing import ClassVar, Self

from flext_core import FlextModels, FlextModelsCollections, FlextUtilities
from flext_ldif import FlextLdifModels
from flext_ldif.utilities import FlextLdifUtilities
from pydantic import Field, computed_field, field_validator, model_validator

from flext_ldap.constants import FlextLdapConstants


class FlextLdapModels(FlextModels):
    """LDAP domain models extending flext-core FlextModels.

    Uses advanced Python 3.13 patterns with enums, mappings, and computed fields
    for type-safe, efficient model definitions. All models follow Pydantic v2 patterns
    with proper validation and immutability.
    """

    # Configuration mappings for DRY field definitions
    CONNECTION_DEFAULTS: ClassVar[dict[str, str | int | bool | None]] = {
        "host": "localhost",
        "port": FlextLdapConstants.ConnectionDefaults.PORT,
        "use_ssl": False,
        "use_tls": False,
        "bind_dn": None,
        "bind_password": None,
        "timeout": FlextLdapConstants.ConnectionDefaults.TIMEOUT,
        "auto_bind": FlextLdapConstants.ConnectionDefaults.AUTO_BIND,
        "auto_range": FlextLdapConstants.ConnectionDefaults.AUTO_RANGE,
    }

    SEARCH_DEFAULTS: ClassVar[dict[str, str | int | None]] = {
        "scope": "SUBTREE",
        "filter_str": FlextLdapConstants.Filters.ALL_ENTRIES_FILTER,
        "attributes": None,
        "size_limit": 0,
        "time_limit": 0,
    }

    SYNC_DEFAULTS: ClassVar[dict[str, int | bool | str | None]] = {
        "batch_size": 100,
        "auto_create_parents": True,
        "allow_deletes": False,
        "source_basedn": "",
        "target_basedn": "",
        "progress_callback": None,
    }

    # =========================================================================
    # CONNECTION MODELS
    # =========================================================================

    class ConnectionConfig(FlextModelsCollections.Config):
        """Configuration for LDAP connection (frozen, immutable).

        Minimal configuration model for establishing LDAP connections.
        Uses advanced Python 3.13 patterns with mapping-based field definitions
        for DRY configuration and type safety.
        """

        host: str = Field(
            default="localhost",
            description="LDAP server hostname or IP",
        )
        port: int = Field(
            default=FlextLdapConstants.ConnectionDefaults.PORT,
            ge=1,
            le=65535,
            description="LDAP server port",
        )
        use_ssl: bool = Field(
            default=False,
            description="Use SSL/TLS for connection",
        )
        use_tls: bool = Field(
            default=False,
            description="Use STARTTLS for connection",
        )
        bind_dn: str | None = Field(
            default=None,
            description="Bind DN for authentication (None for anonymous bind)",
        )
        bind_password: str | None = Field(
            default=None,
            description="Bind password for authentication (None for anonymous bind)",
        )
        timeout: int = Field(
            default=FlextLdapConstants.ConnectionDefaults.TIMEOUT,
            ge=1,
            description="Connection timeout in seconds",
        )
        auto_bind: bool = Field(
            default=FlextLdapConstants.ConnectionDefaults.AUTO_BIND,
            description="Automatically bind after connection",
        )
        auto_range: bool = Field(
            default=FlextLdapConstants.ConnectionDefaults.AUTO_RANGE,
            description="Automatically handle range queries",
        )

        @model_validator(mode="after")
        def validate_ssl_tls_mutual_exclusion(self) -> Self:
            """Validate that SSL and TLS are mutually exclusive.

            SSL (port 636) and TLS/STARTTLS (port 389) are two different
            approaches to secure LDAP connections and cannot be used simultaneously.

            Args:
                self: The ConnectionConfig instance to validate

            Returns:
                The validated ConnectionConfig instance

            Raises:
                ValueError: If both use_ssl and use_tls are True

            """
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
        """Options for LDAP search operations (frozen, immutable).

        Minimal search configuration model.
        Uses FlextModels.Options base (Value object) for:
        - Immutability (frozen=True)
        - Value-based equality
        - Hashability for caching

        Uses FlextLdapConstants for scope and filter defaults.
        Uses Pydantic v2 field validators for DN format validation.
        """

        base_dn: str = Field(..., description="Base DN for search")
        scope: FlextLdapConstants.LiteralTypes.SearchScope = Field(
            default="SUBTREE",
            description="Search scope (BASE, ONELEVEL, SUBTREE)",
        )
        filter_str: str = Field(
            default=FlextLdapConstants.Filters.ALL_ENTRIES_FILTER,
            description="LDAP filter string",
        )
        attributes: list[str] | None = Field(
            default=None,
            description="Attributes to retrieve (None = all attributes, default: all)",
        )
        size_limit: int = Field(
            default=0,
            ge=0,
            description="Maximum number of entries to return (0 = no limit)",
        )
        time_limit: int = Field(
            default=0,
            ge=0,
            description="Maximum time in seconds (0 = no limit)",
        )

        @field_validator("base_dn")
        @classmethod
        def validate_base_dn_format(cls, v: str) -> str:
            """Validate base_dn format using FlextLdif.utilities.DN.validate.

            Pydantic v2 field validator ensures DN format is correct at model creation.
            This replaces runtime validation in service methods.

            Args:
                v: Base DN string to validate

            Returns:
                Validated base_dn string

            Raises:
                ValueError: If DN format is invalid

            """
            if not FlextLdifUtilities.DN.validate(v):
                error_msg = f"Invalid base_dn format: {v}"
                raise ValueError(error_msg)
            return v

        @classmethod
        def normalized(
            cls,
            base_dn: str,
            scope: FlextLdapConstants.LiteralTypes.SearchScope = "SUBTREE",
            filter_str: str = FlextLdapConstants.Filters.ALL_ENTRIES_FILTER,
            attributes: list[str] | None = None,
            size_limit: int = 0,
            time_limit: int = 0,
        ) -> FlextLdapModels.SearchOptions:
            """Factory method to create SearchOptions with normalized base_dn.

            Convenient factory that automatically normalizes the base_dn
            using FlextLdif.utilities.DN.norm_string() to ensure consistent
            DN formatting across LDAP operations.

            Args:
                base_dn: Base DN for search (will be normalized)
                scope: Search scope (BASE, ONELEVEL, SUBTREE)
                filter_str: LDAP filter string
                attributes: Attributes to retrieve (None = all)
                size_limit: Maximum entries to return (0 = no limit)
                time_limit: Maximum time in seconds (0 = no limit)

            Returns:
                SearchOptions instance with normalized base_dn

            Example:
                >>> opts = FlextLdapModels.SearchOptions.normalized(
                ...     base_dn=" dc=test , dc=local ", filter_str="(cn=user)"
                ... )
                >>> opts.base_dn  # Normalized
                'dc=test,dc=local'

            """
            normalized_base = FlextLdifUtilities.DN.norm_string(base_dn)
            return cls(
                base_dn=normalized_base,
                scope=scope,
                filter_str=filter_str,
                attributes=attributes,
                size_limit=size_limit,
                time_limit=time_limit,
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
        operation_type: FlextLdapConstants.LiteralTypes.OperationType = Field(
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

    class SearchResult(FlextModels.Entity):
        """Result of LDAP search operation with Entity features.

        Contains search results as Entry models (reusing FlextLdifModels.Entry).
        Uses FlextModels.Entity.Core for:
        - unique_id: Unique identifier (UUID)
        - created_at/updated_at: Automatic timestamps
        - version: Optimistic locking
        - entity_id property: Alias for unique_id
        """

        entries: list[FlextLdifModels.Entry] = Field(
            default_factory=list,
            description="Search results as Entry models",
        )
        search_options: FlextLdapModels.SearchOptions = Field(
            ...,
            description="Search options used",
        )

        @computed_field
        def total_count(self) -> int:
            """Total number of entries found (computed from entries list).

            This is a computed field that automatically returns the length
            of the entries list, ensuring consistency and eliminating
            the possibility of desynchronization.

            Returns:
                Number of entries in the result

            """
            return len(self.entries)

        @computed_field
        def by_objectclass(self) -> dict[str, list[FlextLdifModels.Entry]]:
            """Categorize entries by objectClass attribute.

            This computed field provides automatic categorization of search
            results by their objectClass values, making it easy to group
            and filter results by type.

            Returns:
                Dictionary mapping objectClass values to lists of entries

            Example:
                >>> result = ldap.search(base_dn="dc=example,dc=com")
                >>> users = result.by_objectclass.get("person", [])
                >>> groups = result.by_objectclass.get("groupOfNames", [])

            """
            categories: dict[str, list[FlextLdifModels.Entry]] = {}

            for entry in self.entries:
                object_classes = entry.attributes.get("objectClass", [])
                if object_classes:
                    # Use the first (most specific) objectClass as category
                    first_class = object_classes[0]
                    category = (
                        first_class
                        if FlextUtilities.TypeGuards.is_string_non_empty(first_class)
                        else str(first_class)
                    )
                else:
                    category = "unknown"

                if category not in categories:
                    categories[category] = []
                categories[category].append(entry)

            return categories

    # =========================================================================
    # SYNC MODELS
    # =========================================================================

    class SyncOptions(FlextModels.Options):
        """Options for LDIF to LDAP synchronization (frozen, immutable).

        Configuration for syncing LDIF files to LDAP directory.
        Uses FlextModels.Options base (Value object) for:
        - Immutability (frozen=True)
        - Value-based equality
        - Hashability for caching

        Uses FlextLdapConfig for default values.
        """

        batch_size: int = Field(
            default=100,
            ge=1,
            description="Number of entries to process in each batch",
        )
        auto_create_parents: bool = Field(
            default=True,
            description="Automatically create parent DNs if they don't exist",
        )
        allow_deletes: bool = Field(
            default=False,
            description="Allow delete operations (changetype: delete)",
        )
        source_basedn: str = Field(
            default="",
            description=(
                "Source BaseDN for transformation "
                "(if LDIF has different BaseDN than LDAP, empty = no transformation)"
            ),
        )
        target_basedn: str = Field(
            default="",
            description=(
                "Target BaseDN for transformation "
                "(LDAP server BaseDN, empty = no transformation)"
            ),
        )
        progress_callback: Callable[[int, int, str, dict[str, int]], None] | None = (
            Field(
                default=None,
                description=(
                    "Optional callback for progress updates (idx, total, dn, stats)"
                ),
            )
        )

    class SyncStats(FlextModelsCollections.Statistics):
        """Statistics for LDIF synchronization operation (frozen, immutable).

        Aggregated statistics from syncing LDIF entries to LDAP.
        Uses FlextModels.Statistics base (Value object) for:
        - Immutability (frozen=True)
        - Value-based equality
        - Hashability for caching
        - Automatic comparison operators
        """

        added: int = Field(
            default=0,
            ge=0,
            description="Number of entries successfully added",
        )
        skipped: int = Field(
            default=0,
            ge=0,
            description="Number of entries skipped (e.g., already exists)",
        )
        failed: int = Field(
            default=0,
            ge=0,
            description="Number of entries that failed to sync",
        )
        total: int = Field(
            default=0,
            ge=0,
            description="Total number of entries processed",
        )
        duration_seconds: float = Field(
            default=0.0,
            ge=0.0,
            description="Duration of sync operation in seconds",
        )

        @computed_field
        def success_rate(self) -> float:
            """Calculate success rate as percentage.

            Returns:
                Success rate as float between 0.0 and 1.0

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
            **kwargs: object,
        ) -> FlextLdapModels.SyncStats:
            """Factory method to create SyncStats with auto-calculated total.

            Convenient factory that automatically calculates the total field
            from the individual counters, ensuring consistency. Uses kwargs for direct model creation.

            Args:
                added: Number of entries successfully added
                skipped: Number of entries skipped
                failed: Number of entries that failed
                duration_seconds: Duration of sync operation in seconds
                **kwargs: Additional SyncStats fields

            Returns:
                SyncStats instance with total auto-calculated

            Example:
                >>> stats = FlextLdapModels.SyncStats.from_counters(
                ...     added=5, skipped=2, failed=1, duration_seconds=10.5
                ... )
                >>> stats.total  # Automatically 8
                8

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

    class UpsertResult(FlextModels.Results):
        """Result of individual LDAP upsert operation (frozen, immutable).

        Contains the result of a single upsert operation (add/modify).
        Uses FlextModels.Results base (Value object) for:
        - Immutability (frozen=True)
        - Value-based equality
        - Hashability for caching
        """

        success: bool = Field(..., description="Whether the upsert operation succeeded")
        dn: str = Field(..., description="DN of the entry that was upserted")
        operation: FlextLdapConstants.LiteralTypes.OperationType = Field(
            ...,
            description="Type of operation performed (add, modify, etc.)",
        )
        error: str | None = Field(
            default=None,
            description="Error message if operation failed",
        )

    class BatchUpsertResult(FlextModels.Entity):
        """Result of batch LDAP upsert operation with Entity features.

        Aggregates results from multiple upsert operations.
        Uses FlextModels.Entity.Core for:
        - unique_id: Unique identifier (UUID)
        - created_at/updated_at: Automatic timestamps
        - version: Optimistic locking
        - entity_id property: Alias for unique_id
        """

        total_processed: int = Field(
            ...,
            ge=0,
            description="Total number of entries processed in the batch",
        )
        successful: int = Field(
            ...,
            ge=0,
            description="Number of successful operations",
        )
        failed: int = Field(
            ...,
            ge=0,
            description="Number of failed operations",
        )
        results: list[FlextLdapModels.UpsertResult] = Field(
            default_factory=list,
            description="Individual results for each entry",
        )

        @computed_field
        def success_rate(self) -> float:
            """Calculate success rate as percentage.

            Returns:
                Success rate as float between 0.0 and 1.0

            """
            if self.total_processed == 0:
                return 0.0
            return self.successful / self.total_processed

    class ConversionMetadata(FlextModels.Config):
        """Metadata tracking attribute conversions during ldap3 to LDIF conversion."""

        source_attributes: list[str] = Field(
            default_factory=list,
            description="Original attributes from ldap3 entry",
        )
        source_dn: str = Field(
            default="",
            description="Original DN from ldap3 entry (preserves case)",
        )
        removed_attributes: list[str] = Field(
            default_factory=list,
            description="Attributes that were removed (had None values)",
        )
        base64_encoded_attributes: list[str] = Field(
            default_factory=list,
            description="List of attributes detected as base64-encoded",
        )
        dn_changed: bool = Field(
            default=False,
            description="Whether DN was normalized/changed",
        )
        converted_dn: str = Field(
            default="",
            description="DN after normalization (if different from source)",
        )
        attribute_changes: list[str] = Field(
            default_factory=list,
            description="List of attributes that had value changes during conversion",
        )

    # =========================================================================
    # NO ALIASES - Use FlextLdifModels directly for clarity
    # =========================================================================
    # FlextLdifModels.Entry - LDIF entry with parsing capabilities
    # FlextLdifModels.DistinguishedName - DN validation and normalization
    # FlextLdifModels.LdifAttributes - LDIF attribute handling


__all__ = ["FlextLdapModels"]
