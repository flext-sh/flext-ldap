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

from flext_core import FlextLogger, FlextModels
from flext_ldif.models import FlextLdifModels
from pydantic import Field

from flext_ldap.constants import FlextLdapConstants

logger = FlextLogger(__name__)


def _get_config_default(field_name: str) -> str | int | bool | None:
    """Get default value from FlextLdapConfig SINGLETON for a field.

    IMPORTANT: Gets value from EXISTING config singleton, does NOT create new config.
    This allows ConnectionConfig defaults to come from .env-loaded FlextLdapConfig.

    Pydantic v2 Pattern:
    - default_factory gets value from config singleton
    - Explicit values passed override the default
    - No @model_validator needed - Pydantic handles override automatically

    Args:
        field_name: Name of the config field to get default for

    Returns:
        Default value from Config singleton (which loaded from .env)

    """
    from flext_ldap.config import FlextLdapConfig

    # FlextConfig is a Pydantic Settings class, instantiate directly
    # It will use environment variables and defaults automatically
    config = FlextLdapConfig()
    value = getattr(config, field_name)
    # Type narrowing - fast fail if unexpected type
    if isinstance(value, (str, int, bool)) or value is None:
        return value
    # Fast fail - unexpected type, don't fallback
    error_msg = (
        f"Unexpected type for config field {field_name}: "
        f"{type(value).__name__}. Expected str, int, bool, or None."
    )
    raise TypeError(error_msg)


class FlextLdapModels(FlextModels):
    """LDAP domain models extending flext-core FlextModels.

    Unified namespace class that aggregates all LDAP domain models.
    Reuses FlextLdifModels for Entry, DN, Attributes, and Schema.
    Only defines LDAP-specific models for connection and operations.
    """

    # =========================================================================
    # CONNECTION MODELS
    # =========================================================================

    class ConnectionConfig(FlextModels.ArbitraryTypesModel):
        """Configuration for LDAP connection.

        Minimal configuration model for establishing LDAP connections.
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

    # =========================================================================
    # SEARCH MODELS
    # =========================================================================

    class SearchOptions(FlextModels.ArbitraryTypesModel):
        """Options for LDAP search operations.

        Minimal search configuration model.
        Uses FlextLdapConstants for scope and filter defaults.
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

    # =========================================================================
    # OPERATION RESULT MODELS
    # =========================================================================

    class OperationResult(FlextModels.ArbitraryTypesModel):
        """Result of LDAP operation.

        Generic result model for all LDAP operations.
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

    class SearchResult(FlextModels.ArbitraryTypesModel):
        """Result of LDAP search operation.

        Contains search results as Entry models (reusing FlextLdifModels.Entry).
        """

        entries: list[FlextLdifModels.Entry] = Field(
            default_factory=list,
            description="Search results as Entry models",
        )
        total_count: int = Field(
            default=0,
            ge=0,
            description="Total number of entries found",
        )
        search_options: FlextLdapModels.SearchOptions = Field(
            ...,
            description="Search options used",
        )

    # =========================================================================
    # SYNC MODELS
    # =========================================================================

    class SyncOptions(FlextModels.ArbitraryTypesModel):
        """Options for LDIF to LDAP synchronization.

        Configuration for syncing LDIF files to LDAP directory.
        Uses FlextLdapConfig for default values.
        """

        batch_size: int = Field(
            default_factory=lambda: cast("int", _get_config_default("ldap_chunk_size")),
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

    class SyncStats(FlextModels.ArbitraryTypesModel):
        """Statistics for LDIF synchronization operation.

        Aggregated statistics from syncing LDIF entries to LDAP.
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

        @property
        def success_rate(self) -> float:
            """Calculate success rate as percentage.

            Returns:
                Success rate as float between 0.0 and 1.0

            """
            if self.total == 0:
                return 0.0
            return (self.added + self.skipped) / self.total

    # =========================================================================
    # REUSED MODELS (from FlextLdifModels)
    # =========================================================================

    # Re-export commonly used models from FlextLdifModels for convenience
    Entry = FlextLdifModels.Entry
    DistinguishedName = FlextLdifModels.DistinguishedName
    LdifAttributes = FlextLdifModels.LdifAttributes


__all__ = ["FlextLdapModels"]
