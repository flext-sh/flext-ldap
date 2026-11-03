# AUTO-GENERATED FILE — Regenerate with: make gen
"""Source-derived structural model contracts.

Copyright (c) 2026 FLEXT Team. All rights reserved.
src/flext_ldap/_protocols/ldap
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import TYPE_CHECKING, Protocol, runtime_checkable

from flext_ldif import FlextLdifProtocols

from flext_ldap import t

if TYPE_CHECKING:
    from flext_ldif import p

    from flext_ldap._typings import FlextLdapTypesLdap


class FlextLdapProtocolsLdap:
    """Own the structural contracts declared by its model source."""

    @runtime_checkable
    class ConnectionConfig(FlextLdifProtocols.Model, Protocol):
        """Structural data contract projected from the owning model."""

        @property
        def host(self) -> str:
            """LDAP server hostname."""
            ...

        @property
        def port(self) -> t.PortNumber:
            """LDAP server port."""
            ...

        @property
        def use_ssl(self) -> bool:
            """Enable SSL (LDAPS)."""
            ...

        @property
        def use_tls(self) -> bool:
            """Enable StartTLS."""
            ...

        @property
        def bind_dn(self) -> str | None:
            """Bind DN for authentication."""
            ...

        @property
        def bind_password(self) -> str | None:
            """Bind password for authentication."""
            ...

        @property
        def timeout(self) -> t.PositiveInt:
            """Connection timeout in seconds."""
            ...

        @property
        def auto_bind(self) -> bool:
            """Auto-bind on connection."""
            ...

        @property
        def auto_range(self) -> bool:
            """Enable auto-range for paged results."""
            ...

    @runtime_checkable
    class NormalizedConfig(FlextLdifProtocols.Model, Protocol):
        """Structural data contract projected from the owning model."""

        scope: str
        filter_str: str
        size_limit: t.NonNegativeInt
        time_limit: t.NonNegativeInt
        attributes: Sequence[str] | None

    @runtime_checkable
    class SearchOptions(FlextLdifProtocols.Model, Protocol):
        """Structural data contract projected from the owning model."""

        @property
        def base_dn(self) -> t.NonEmptyStr:
            """Base DN for search (required, non-empty)."""
            ...

        scope: str
        filter_str: str
        attributes: Sequence[str] | None
        size_limit: t.NonNegativeInt
        time_limit: t.NonNegativeInt

    @runtime_checkable
    class SearchParams(FlextLdifProtocols.Model, Protocol):
        """Structural data contract projected from the owning model."""

        @property
        def base_dn(self) -> str:
            """Structural member projected from the owning model."""
            ...

        @property
        def filter_str(self) -> str:
            """Structural member projected from the owning model."""
            ...

        @property
        def ldap_scope(self) -> t.NonNegativeInt:
            """Structural member projected from the owning model."""
            ...

        @property
        def search_attributes(self) -> Sequence[str]:
            """Structural member projected from the owning model."""
            ...

        @property
        def size_limit(self) -> t.NonNegativeInt:
            """Structural member projected from the owning model."""
            ...

        @property
        def time_limit(self) -> t.NonNegativeInt:
            """Structural member projected from the owning model."""
            ...

    @runtime_checkable
    class LdapBatchStats(FlextLdifProtocols.Model, Protocol):
        """Structural data contract projected from the owning model."""

        @property
        def synced(self) -> t.NonNegativeInt:
            """Entries synced successfully."""
            ...

        @property
        def failed(self) -> t.NonNegativeInt:
            """Entries that failed."""
            ...

        @property
        def skipped(self) -> t.NonNegativeInt:
            """Entries skipped."""
            ...

    @runtime_checkable
    class SubtreeDeleteResult(FlextLdifProtocols.Model, Protocol):
        """Structural data contract projected from the owning model."""

        @property
        def base_dn(self) -> str:
            """Base DN of the targeted subtree."""
            ...

        @property
        def deleted_count(self) -> t.NonNegativeInt:
            """Entries deleted before the run stopped."""
            ...

        @property
        def failed_dn(self) -> str | None:
            """DN of the first failed deletion, if any."""
            ...

        @property
        def cause(self) -> str | None:
            """Failure cause reported for failed_dn."""
            ...

    @runtime_checkable
    class UpsertPlan(FlextLdifProtocols.Model, Protocol):
        """Structural data contract projected from the owning model."""

        @property
        def adds(self) -> t.NonNegativeInt:
            """Entries absent from the directory (would be added)."""
            ...

        @property
        def modifies(self) -> t.NonNegativeInt:
            """Entries present with differences (would be modified)."""
            ...

        @property
        def unchanged(self) -> t.NonNegativeInt:
            """Entries already matching the desired state."""
            ...

    @runtime_checkable
    class UpsertResult(FlextLdifProtocols.Model, Protocol):
        """Structural data contract projected from the owning model."""

        @property
        def success(self) -> bool:
            """Whether the upsert succeeded."""
            ...

        @property
        def dn(self) -> str:
            """Distinguished name of the entry."""
            ...

        @property
        def operation(self) -> str:
            """Operation performed (ADD/MODIFY/SKIP)."""
            ...

        @property
        def error(self) -> str | None:
            """Error message if operation failed."""
            ...

    @runtime_checkable
    class BatchUpsertResult(FlextLdifProtocols.Model, Protocol):
        """Structural data contract projected from the owning model."""

        total_processed: t.NonNegativeInt
        successful: t.NonNegativeInt
        failed: t.NonNegativeInt

        @property
        def results(self) -> Sequence[FlextLdapProtocolsLdap.UpsertResult]:
            """Validated per-entry upsert results."""
            ...

        @property
        def success_rate(self) -> float:
            """Success rate (successful / total_processed)."""
            ...

    @runtime_checkable
    class SyncPhaseConfig(FlextLdifProtocols.Model, Protocol):
        """Structural data contract projected from the owning model."""

        server_type: str

        @property
        def progress_callback(self) -> FlextLdapTypesLdap.ProgressCallbackUnion | None:
            """Structural member projected from the owning model."""
            ...

        retry_on_errors: Sequence[str]
        max_retries: t.RetryCount
        stop_on_error: bool

    @runtime_checkable
    class ConversionMetadata(FlextLdifProtocols.Model, Protocol):
        """Structural data contract projected from the owning model."""

        source_attributes: Sequence[str]
        source_dn: str
        removed_attributes: Sequence[str]
        base64_encoded_attributes: Sequence[str]
        dn_changed: bool
        converted_dn: str
        attribute_changes: Sequence[str]

    @runtime_checkable
    class OperationResult(FlextLdifProtocols.Model, Protocol):
        """Structural data contract projected from the owning model."""

        @property
        def success(self) -> bool:
            """Whether the operation succeeded."""
            ...

        @property
        def operation_type(self) -> str:
            """Type of operation performed."""
            ...

        @property
        def message(self) -> str:
            """Result or error message."""
            ...

        @property
        def entries_affected(self) -> t.NonNegativeInt:
            """Number of entries affected."""
            ...

    @runtime_checkable
    class SearchResult(FlextLdifProtocols.Model, Protocol):
        """Structural data contract projected from the owning model."""

        @property
        def entries(self) -> Sequence[p.Ldif.Entry]:
            """Structural member projected from the owning model."""
            ...

        @property
        def search_options(self) -> FlextLdapProtocolsLdap.SearchOptions:
            """Structural member projected from the owning model."""
            ...

    @runtime_checkable
    class LdapOperationResult(FlextLdifProtocols.Model, Protocol):
        """Structural data contract projected from the owning model."""

        operation: str

    @runtime_checkable
    class PhaseSyncResult(LdapBatchStats, Protocol):
        """Structural data contract projected from the owning model."""

        phase_name: str
        total_entries: t.NonNegativeInt
        duration_seconds: t.NonNegativeFloat
        success_rate: t.NonNegativeFloat

    @runtime_checkable
    class MultiPhaseSyncResult(FlextLdifProtocols.Model, Protocol):
        """Structural data contract projected from the owning model."""

        @property
        def phase_results(self) -> Mapping[str, FlextLdapProtocolsLdap.PhaseSyncResult]:
            """Per-phase sync results keyed by phase name."""
            ...

        total_entries: t.NonNegativeInt
        total_synced: t.NonNegativeInt
        total_failed: t.NonNegativeInt
        total_skipped: t.NonNegativeInt
        overall_success_rate: t.NonNegativeFloat
        total_duration_seconds: t.NonNegativeFloat
        overall_success: bool


__all__: list[str] = [
    "FlextLdapProtocolsLdap",
]
