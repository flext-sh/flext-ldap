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

from flext_core import FlextLogger, FlextModels
from flext_ldif.models import FlextLdifModels
from pydantic import Field

from flext_ldap.constants import FlextLdapConstants

logger = FlextLogger(__name__)


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
        """

        host: str = Field(..., description="LDAP server hostname or IP")
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
            description="Bind DN for authentication",
        )
        bind_password: str | None = Field(
            default=None,
            description="Bind password for authentication",
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
        """

        base_dn: str = Field(..., description="Base DN for search")
        scope: FlextLdapConstants.LiteralTypes.SearchScope = Field(
            default="SUBTREE",
            description="Search scope (BASE, ONELEVEL, SUBTREE)",
        )
        filter_str: str = Field(
            default="(objectClass=*)",
            description="LDAP filter string",
        )
        attributes: list[str] | None = Field(
            default=None,
            description="Attributes to retrieve (None = all attributes)",
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
        message: str | None = Field(
            default=None,
            description="Operation result message",
        )
        entries_affected: int = Field(
            default=0,
            ge=0,
            description="Number of entries affected",
        )
        data: dict[str, object] | None = Field(
            default=None,
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
        """

        batch_size: int = Field(
            default=50,
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
        progress_callback: (
            Callable[[int, int, str, dict[str, int]], None] | None
        ) = Field(
            default=None,
            description="Optional callback for progress updates (idx, total, dn, stats)",
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
