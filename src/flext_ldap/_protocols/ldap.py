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

if TYPE_CHECKING:
    from flext_ldif import p

    from flext_ldap import c, t


class FlextLdapProtocolsLdap:
    """Own the structural contracts declared by its model source."""

    @runtime_checkable
    class ConnectionConfig(FlextLdifProtocols.BaseModel, Protocol):
        """Structural data contract projected from the owning model."""

        host: str
        port: t.PortNumber
        use_ssl: bool
        use_tls: bool
        tls_validate: c.Ldap.TlsValidation
        ca_certs_file: t.FilePath | None
        server_name: t.NonEmptyStr | None
        bind_dn: str | None
        bind_password: str | None
        timeout: t.PositiveInt
        auto_bind: bool
        auto_range: bool

    @runtime_checkable
    class NormalizedConfig(FlextLdifProtocols.BaseModel, Protocol):
        """Structural data contract projected from the owning model."""

        scope: str
        filter_str: str
        size_limit: t.NonNegativeInt
        time_limit: t.NonNegativeInt
        attributes: Sequence[str] | None

    @runtime_checkable
    class SearchOptions(FlextLdifProtocols.BaseModel, Protocol):
        """Structural data contract projected from the owning model."""

        base_dn: t.NonEmptyStr
        scope: str
        filter_str: str
        attributes: Sequence[str] | None
        size_limit: t.NonNegativeInt
        time_limit: t.NonNegativeInt

    @runtime_checkable
    class SearchParams(FlextLdifProtocols.BaseModel, Protocol):
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
    class LdapBatchStats(FlextLdifProtocols.BaseModel, Protocol):
        """Structural data contract projected from the owning model."""

        synced: t.NonNegativeInt
        failed: t.NonNegativeInt
        skipped: t.NonNegativeInt

    @runtime_checkable
    class SubtreeDeleteResult(FlextLdifProtocols.BaseModel, Protocol):
        """Structural data contract projected from the owning model."""

        base_dn: str
        deleted_count: t.NonNegativeInt
        failed_dn: str | None
        cause: str | None

    @runtime_checkable
    class UpsertOperation(FlextLdifProtocols.BaseModel, Protocol):
        """Structural data contract projected from the owning model."""

        @property
        def entry(self) -> p.Ldif.Entry:
            """Structural member projected from the owning model."""
            ...

        @property
        def operation(self) -> c.Ldap.UpsertOperation:
            """Structural member projected from the owning model."""
            ...

        @property
        def changes(self) -> t.Ldap.OperationChanges:
            """Structural member projected from the owning model."""
            ...

        @property
        def observed_entry(self) -> p.Ldif.Entry | None:
            """Structural member projected from the owning model."""
            ...

        @property
        def observation_is_projected(self) -> bool:
            """Structural member projected from the owning model."""
            ...

    @runtime_checkable
    class UpsertPlan(FlextLdifProtocols.BaseModel, Protocol):
        """Structural data contract projected from the owning model."""

        @property
        def operations(self) -> tuple[FlextLdapProtocolsLdap.UpsertOperation, ...]:
            """Structural member projected from the owning model."""
            ...

        @property
        def planned_entries(self) -> tuple[p.Ldif.Entry, ...]:
            """Final declared ADD state carried between phases."""
            ...

        @property
        def added_dns(self) -> tuple[str, ...]:
            """DNs of native ADD preparations, in input order."""
            ...

        @property
        def modified_dns(self) -> tuple[str, ...]:
            """DNs of native MODIFY preparations, in input order."""
            ...

        @property
        def unchanged_dns(self) -> tuple[str, ...]:
            """DNs of native no-op preparations, in input order."""
            ...

        @property
        def adds(self) -> int:
            """Number of entries to add."""
            ...

        @property
        def modifies(self) -> int:
            """Number of entries to modify."""
            ...

        @property
        def unchanged(self) -> int:
            """Number of entries already at their desired state."""
            ...

    @runtime_checkable
    class UpsertResult(FlextLdifProtocols.BaseModel, Protocol):
        """Structural data contract projected from the owning model."""

        success: bool
        dn: str
        operation: str
        error: str | None

    @runtime_checkable
    class BatchUpsertResult(FlextLdifProtocols.BaseModel, Protocol):
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
    class SyncPhaseConfig(FlextLdifProtocols.BaseModel, Protocol):
        """Structural data contract projected from the owning model."""

        server_type: str
        progress_callback: t.Ldap.ProgressCallbackUnion | None
        stop_on_error: bool

    @runtime_checkable
    class ConversionMetadata(FlextLdifProtocols.BaseModel, Protocol):
        """Structural data contract projected from the owning model."""

        source_attributes: Sequence[str]
        source_dn: str
        removed_attributes: Sequence[str]
        base64_encoded_attributes: Sequence[str]
        dn_changed: bool
        converted_dn: str
        attribute_changes: Sequence[str]

    @runtime_checkable
    class OperationResult(FlextLdifProtocols.BaseModel, Protocol):
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
    class SearchResult(FlextLdifProtocols.BaseModel, Protocol):
        """Structural data contract projected from the owning model."""

        entries: Sequence[p.Ldif.Entry]

        @property
        def search_options(self) -> FlextLdapProtocolsLdap.SearchOptions:
            """Structural member projected from the owning model."""
            ...

    @runtime_checkable
    class LdapOperationResult(FlextLdifProtocols.BaseModel, Protocol):
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
    class MultiPhaseSyncResult(FlextLdifProtocols.BaseModel, Protocol):
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
