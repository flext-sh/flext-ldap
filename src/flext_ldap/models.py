"""LDAP domain models and data structures.

This module defines Pydantic models for LDAP operations including connection
configuration, search options, and operation results. Reuses FlextLdifModels
for Entry, DN, and Attributes to avoid duplication.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

Notes:
 - Reuses FlextLdifModels.Entry, FlextLdifModels.DistinguishedName, etc.
 - Only defines LDAP-specific models (connection, search, operations)
 - Minimal models following Pydantic v2 patterns

"""

from __future__ import annotations

from collections.abc import Callable
from typing import cast

from flext_core import FlextModels, FlextUtilities
from flext_ldif import FlextLdifModels, FlextLdifUtilities
from pydantic import Field, computed_field, field_validator, model_validator

from flext_ldap.base import FlextLdapServiceBase
from flext_ldap.constants import FlextLdapConstants

# Get nested classes from FlextModels at runtime
_FlextModels_Config = getattr(FlextModels, "Config", None)
_FlextModels_Options = getattr(FlextModels, "Options", None)
_FlextModels_Results = getattr(FlextModels, "Results", None)
_FlextModels_Statistics = getattr(FlextModels, "Statistics", None)

if _FlextModels_Config is None:
    msg = "FlextModels.Config not found"
    raise AttributeError(msg)
if _FlextModels_Options is None:
    msg = "FlextModels.Options not found"
    raise AttributeError(msg)
if _FlextModels_Results is None:
    msg = "FlextModels.Results not found"
    raise AttributeError(msg)
if _FlextModels_Statistics is None:
    msg = "FlextModels.Statistics not found"
    raise AttributeError(msg)


class FlextLdapModels(FlextModels):
    """LDAP domain models extending flext-core FlextModels.

    Unified namespace class that aggregates all LDAP domain models.
    Use FlextLdapServiceBase static methods for config access in defaults.
    """

    # =========================================================================
    # CONNECTION MODELS
    # =========================================================================

    class ConnectionConfig(_FlextModels_Config):
        """Configuration for LDAP connection (frozen, immutable).

        Minimal configuration model for establishing LDAP connections.
        Uses FlextModels.Config base for:
        - Immutability (frozen=True via base)
        - Value-based equality
        - Configuration validation

        Uses simple defaults from constants to avoid config mutation issues.

        Pydantic v2 Pattern:
        - Simple default values from constants
        - Explicit values passed override defaults automatically
        - No default_factory to avoid side effects
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
        def validate_ssl_tls_mutual_exclusion(self) -> FlextLdapModels.ConnectionConfig:
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

    class SearchOptions(_FlextModels_Options):
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
            default=cast(
                "FlextLdapConstants.LiteralTypes.SearchScope",
                FlextLdapConstants.SearchScope.SUBTREE,
            ),
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
            """Validate base_dn format using FlextLdifUtilities.DN.validate.

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
            scope: FlextLdapConstants.LiteralTypes.SearchScope | None = None,
            filter_str: str | None = None,
            attributes: list[str] | None = None,
            size_limit: int = 0,
            time_limit: int = 0,
        ) -> FlextLdapModels.SearchOptions:
            """Factory method to create SearchOptions with normalized base_dn.

            Convenient factory that automatically normalizes the base_dn
            using FlextLdifUtilities.DN.norm_string() to ensure consistent
            DN formatting across LDAP operations.

            Args:
                base_dn: Base DN for search (will be normalized)
                scope: Search scope (defaults to SUBTREE if not provided)
                filter_str: LDAP filter string (defaults to all entries if not provided)
                attributes: Attributes to retrieve (None = all)
                size_limit: Maximum number of entries to return
                time_limit: Maximum time in seconds

            Returns:
                SearchOptions instance with normalized base_dn

            Example:
                >>> opts = FlextLdapModels.SearchOptions.normalized(
                ...     base_dn=" dc=test , dc=local ", filter_str="(cn=user)"
                ... )
                >>> opts.base_dn  # Normalized
                'dc=test,dc=local'

            """
            # Normalize the base_dn
            normalized_base_dn = FlextLdifUtilities.DN.norm_string(base_dn)

            # Use defaults if not provided
            actual_scope = (
                scope
                if scope is not None
                else cast(
                    "FlextLdapConstants.LiteralTypes.SearchScope",
                    FlextLdapConstants.SearchScope.SUBTREE,
                )
            )
            actual_filter = (
                filter_str
                if filter_str is not None
                else FlextLdapConstants.Filters.ALL_ENTRIES_FILTER
            )

            return cls(
                base_dn=normalized_base_dn,
                scope=actual_scope,
                filter_str=actual_filter,
                attributes=attributes,
                size_limit=size_limit,
                time_limit=time_limit,
            )

    # =========================================================================
    # OPERATION RESULT MODELS
    # =========================================================================

    class OperationResult(_FlextModels_Results):
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
        data: dict[str, str | int | float | bool | list[str]] = Field(
            default_factory=dict,
            description="Additional operation data",
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

    class SyncOptions(_FlextModels_Options):
        """Options for LDIF to LDAP synchronization (frozen, immutable).

        Configuration for syncing LDIF files to LDAP directory.
        Uses FlextModels.Options base (Value object) for:
        - Immutability (frozen=True)
        - Value-based equality
        - Hashability for caching

        Uses FlextLdapConfig for default values.
        """

        batch_size: int = Field(
            default_factory=lambda: FlextLdapServiceBase.get_ldap_config().chunk_size,
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

    class SyncStats(_FlextModels_Statistics):
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
        ) -> FlextLdapModels.SyncStats:
            """Factory method to create SyncStats with auto-calculated total.

            Convenient factory that automatically calculates the total field
            from the individual counters, ensuring consistency.

            Args:
                added: Number of entries successfully added
                skipped: Number of entries skipped
                failed: Number of entries that failed
                duration_seconds: Duration of sync operation in seconds

            Returns:
                SyncStats instance with total auto-calculated

            Example:
                >>> stats = FlextLdapModels.SyncStats.from_counters(
                ...     added=5, skipped=2, failed=1, duration_seconds=10.5
                ... )
                >>> stats.total  # Automatically 8
                8

            """
            total = added + skipped + failed
            return cls(
                added=added,
                skipped=skipped,
                failed=failed,
                total=total,
                duration_seconds=duration_seconds,
            )

    # =========================================================================
    # NO ALIASES - Use FlextLdifModels directly for clarity
    # =========================================================================
    # FlextLdifModels.Entry - LDIF entry with parsing capabilities
    # FlextLdifModels.DistinguishedName - DN validation and normalization
    # FlextLdifModels.LdifAttributes - LDIF attribute handling


__all__ = ["FlextLdapModels"]
