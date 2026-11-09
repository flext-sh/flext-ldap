"""FlextLdap LDAP-specific models.

LDAP operation models with validation logic.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Annotated, ClassVar, Self

from flext_ldif import m

from flext_ldap.constants import c
from flext_ldap.protocols import p
from flext_ldap.typings import t


class FlextLdapModelsFlextLdap:
    """Canonical namespace owner."""

    class FlextLdapModelsLdap:
        """LDAP-specific models namespace."""

        class ConnectionConfig(m.BaseModel):
            """Connection configuration for LDAP server."""

            host: Annotated[str, m.Field(description="LDAP server hostname")] = (
                c.LOCALHOST
            )
            port: Annotated[t.PortNumber, m.Field(description="LDAP server port")] = (
                c.Ldap.PORT
            )
            use_ssl: Annotated[bool, m.Field(description="Enable SSL (LDAPS)")] = False
            use_tls: Annotated[bool, m.Field(description="Enable StartTLS")] = False
            tls_validate: Annotated[
                c.Ldap.TlsValidation,
                m.Field(
                    description=(
                        "Peer certificate and hostname validation for LDAPS or "
                        "StartTLS; disabling it requires the explicit NONE mode"
                    ),
                ),
            ] = c.Ldap.DEFAULT_TLS_VALIDATION
            ca_certs_file: Annotated[
                t.FilePath | None,
                m.Field(
                    description=(
                        "PEM CA bundle trusted for the server certificate; "
                        "the system trust store applies when unset"
                    ),
                ),
            ] = None
            server_name: Annotated[
                t.NonEmptyStr | None,
                m.Field(
                    description=(
                        "Expected certificate server name, sent as SNI and "
                        "accepted by the hostname check besides host"
                    ),
                ),
            ] = None
            bind_dn: Annotated[
                str | None,
                m.Field(description="Bind DN for authentication"),
            ] = None
            bind_password: Annotated[
                str | None,
                m.Field(description="Bind password for authentication", repr=False),
            ] = None
            timeout: Annotated[
                t.PositiveInt,
                m.Field(description="Connection timeout in seconds"),
            ] = c.Ldap.TIMEOUT
            auto_bind: Annotated[
                bool,
                m.Field(description="Auto-bind on connection"),
            ] = True
            auto_range: Annotated[
                bool,
                m.Field(description="Enable auto-range for paged results"),
            ] = True

            @m.model_validator(mode="after")
            def validate_ssl_tls_exclusion(self) -> Self:
                """Validate that SSL and TLS are mutually exclusive.

                Returns:
                    The resulting ``Self``.

                Raises:
                    ValueError: If use_ssl and use_tls are mutually exclusive.

                """
                if self.use_ssl and self.use_tls:
                    msg = "use_ssl and use_tls are mutually exclusive"
                    raise ValueError(msg)
                return self

            @m.model_validator(mode="after")
            def validate_tls_options(self) -> Self:
                """Reject TLS options that cannot take effect.

                Returns:
                    The resulting ``Self``.

                Raises:
                    ValueError: If TLS options are set without LDAPS or StartTLS,
                        or a CA bundle is combined with disabled validation.

                """
                tls_enabled = self.use_ssl or self.use_tls
                tls_options_set = (
                    self.ca_certs_file is not None
                    or self.server_name is not None
                    or self.tls_validate != c.Ldap.DEFAULT_TLS_VALIDATION
                )
                if tls_options_set and not tls_enabled:
                    msg = (
                        "tls_validate, ca_certs_file and server_name require "
                        "use_ssl or use_tls"
                    )
                    raise ValueError(msg)
                if (
                    self.tls_validate == c.Ldap.TlsValidation.NONE
                    and self.ca_certs_file is not None
                ):
                    msg = "ca_certs_file contradicts tls_validate=none"
                    raise ValueError(msg)
                return self

        class NormalizedConfig(m.BaseModel):
            """Configuration for normalized SearchOptions factory."""

            scope: str = c.Ldap.DEFAULT_SCOPE
            filter_str: str = c.Ldap.ALL_ENTRIES_FILTER
            size_limit: t.NonNegativeInt = 0
            time_limit: t.NonNegativeInt = 0
            attributes: Sequence[str] | None = None

        class SearchOptions(m.BaseModel):
            """Search options."""

            base_dn: Annotated[
                t.NonEmptyStr,
                m.Field(..., description="Base DN for search (required, non-empty)"),
            ]
            scope: str = c.Ldap.DEFAULT_SCOPE
            filter_str: str = c.Ldap.ALL_ENTRIES_FILTER
            attributes: Sequence[str] | None = None
            size_limit: t.NonNegativeInt = 0
            time_limit: t.NonNegativeInt = 0
            controls: t.Ldap.SearchControls | None = None

            @classmethod
            def normalized(
                cls,
                base_dn: str,
                settings: FlextLdapModelsFlextLdap.FlextLdapModelsLdap.NormalizedConfig
                | None = None,
            ) -> FlextLdapModelsFlextLdap.FlextLdapModelsLdap.SearchOptions:
                """Create SearchOptions with normalized configuration.

                Args:
                    base_dn: Base DN for search
                    settings: Optional NormalizedConfig with custom values

                Returns:
                    SearchOptions with specified or default values

                """
                norm_config = (
                    FlextLdapModelsFlextLdap.FlextLdapModelsLdap.NormalizedConfig()
                    if settings is None
                    else settings
                )
                return cls(
                    base_dn=base_dn,
                    scope=norm_config.scope,
                    filter_str=norm_config.filter_str,
                    size_limit=norm_config.size_limit,
                    time_limit=norm_config.time_limit,
                    attributes=norm_config.attributes,
                )

            @classmethod
            def base_scope(cls, base_dn: str) -> Self:
                """Build base-scope search options requesting all user attributes.

                Base-scope lookups target a single known DN to read that entry (e.g.
                the upsert existence check), so the entry's user attributes must be
                returned for a meaningful comparison — ldap3 omits them unless asked.

                Returns:
                    The resulting ``Self``.

                """
                return cls(
                    base_dn=base_dn,
                    scope=c.Ldap.SearchScope.BASE,
                    attributes=[c.Ldap.AttributeName.ALL_ATTRIBUTES],
                )

        class SearchParams(m.BaseModel):
            """Typed LDAP search parameters passed to ldap3 search calls."""

            model_config = m.ConfigDict(frozen=True, extra="forbid")
            base_dn: str
            filter_str: str
            ldap_scope: t.NonNegativeInt
            search_attributes: Sequence[str]
            size_limit: t.NonNegativeInt
            time_limit: t.NonNegativeInt
            controls: t.Ldap.SearchControls | None = None

        class LdapBatchStats(m.BaseModel):
            """Base counters for batch LDAP operations (reused via MRO)."""

            synced: Annotated[
                t.NonNegativeInt,
                m.Field(description="Entries synced successfully"),
            ] = 0
            failed: Annotated[
                t.NonNegativeInt,
                m.Field(description="Entries that failed"),
            ] = 0
            skipped: Annotated[
                t.NonNegativeInt,
                m.Field(description="Entries skipped"),
            ] = 0

        class SubtreeDeleteResult(m.BaseModel):
            """Outcome of a deepest-first subtree deletion."""

            base_dn: Annotated[
                str,
                m.Field(description="Base DN of the targeted subtree"),
            ] = ""
            deleted_count: Annotated[
                t.NonNegativeInt,
                m.Field(description="Entries deleted before the run stopped"),
            ] = 0
            failed_dn: Annotated[
                str | None,
                m.Field(description="DN of the first failed deletion, if any"),
            ] = None
            cause: Annotated[
                str | None,
                m.Field(description="Failure cause reported for failed_dn"),
            ] = None

        class UpsertOperation(m.BaseModel):
            """One native preparation shared by planning and writing.

            ``observed_entry`` is the effective comparison projection, including
            preceding declared effects, or observed absence. It is never a full
            directory backup. Freezing protects the envelope; native payloads
            retain their references and must not be mutated by consumers.
            """

            model_config: ClassVar[t.ConfigDict] = m.ConfigDict(
                frozen=True, extra="forbid"
            )

            entry: t.Port[p.Ldif.Entry] = m.Field(repr=False)
            operation: c.Ldap.UpsertOperation
            changes: t.Ldap.OperationChanges = m.Field(repr=False)
            observed_entry: t.Port[p.Ldif.Entry] | None = m.Field(repr=False)
            observation_is_projected: bool

        class UpsertPlan(m.BaseModel):
            """Ordered native preparations are the single source of plan counts."""

            model_config: ClassVar[t.ConfigDict] = m.ConfigDict(
                frozen=True, extra="forbid"
            )

            operations: tuple[
                FlextLdapModelsFlextLdap.FlextLdapModelsLdap.UpsertOperation, ...
            ] = m.Field(default=(), repr=False)
            planned_entries: tuple[t.Port[p.Ldif.Entry], ...] = m.Field(
                default=(),
                exclude=True,
                repr=False,
                description="Final declared ADD state carried between phases.",
            )

            @m.computed_field(repr=False)
            @property
            def added_dns(self) -> tuple[str, ...]:
                """DNs of native ADD preparations, in input order."""
                return tuple(
                    value.entry.dn_str
                    for value in self.operations
                    if value.operation == c.Ldap.UpsertOperation.ADDED
                )

            @m.computed_field(repr=False)
            @property
            def modified_dns(self) -> tuple[str, ...]:
                """DNs of native MODIFY preparations, in input order."""
                return tuple(
                    value.entry.dn_str
                    for value in self.operations
                    if value.operation == c.Ldap.UpsertOperation.MODIFIED
                )

            @m.computed_field(repr=False)
            @property
            def unchanged_dns(self) -> tuple[str, ...]:
                """DNs of native no-op preparations, in input order."""
                return tuple(
                    value.entry.dn_str
                    for value in self.operations
                    if value.operation == c.Ldap.UpsertOperation.SKIPPED
                )

            @m.computed_field
            @property
            def adds(self) -> int:
                """Number of entries to add."""
                return len(self.added_dns)

            @m.computed_field
            @property
            def modifies(self) -> int:
                """Number of entries to modify."""
                return len(self.modified_dns)

            @m.computed_field
            @property
            def unchanged(self) -> int:
                """Number of entries already at their desired state."""
                return len(self.unchanged_dns)

        class UpsertResult(m.BaseModel):
            """Result of a single upsert operation."""

            success: Annotated[
                bool,
                m.Field(description="Whether the upsert succeeded"),
            ] = False
            dn: Annotated[
                str,
                m.Field(description="Distinguished name of the entry"),
            ] = ""
            operation: Annotated[
                str,
                m.Field(description="Operation performed (ADD/MODIFY/SKIP)"),
            ] = ""
            error: Annotated[
                str | None,
                m.Field(description="Error message if operation failed"),
            ] = None

        class BatchUpsertResult(m.BaseModel):
            """Batch upsert result."""

            total_processed: t.NonNegativeInt = 0
            successful: t.NonNegativeInt = 0
            failed: t.NonNegativeInt = 0
            results: Annotated[
                Sequence[FlextLdapModelsFlextLdap.FlextLdapModelsLdap.UpsertResult],
                m.Field(
                    default_factory=list,
                    description="Validated per-entry upsert results",
                ),
            ]

            @m.computed_field
            @property
            def success_rate(self) -> float:
                """Success rate (successful / total_processed)."""
                if self.total_processed == 0:
                    return 0.0
                return float(self.successful) / float(self.total_processed)

        class SyncPhaseConfig(m.BaseModel):
            """Sync phase settings."""

            model_config = m.ConfigDict(
                arbitrary_types_allowed=True,
                extra="forbid",
                validate_assignment=True,
            )
            server_type: str = c.Ldap.DEFAULT_TYPE
            progress_callback: t.Ldap.ProgressCallbackUnion | None = None
            stop_on_error: bool = False

        class ConversionMetadata(m.BaseModel):
            """Conversion metadata."""

            source_attributes: Sequence[str] = m.Field(
                default_factory=list[str],
                description="Source attribute names",
            )
            source_dn: str = ""
            removed_attributes: Sequence[str] = m.Field(
                default_factory=list[str],
                description="Attributes removed during conversion",
            )
            base64_encoded_attributes: Sequence[str] = m.Field(
                default_factory=list[str],
                description="Attributes that were base64-encoded",
            )
            dn_changed: bool = False
            converted_dn: str = ""
            attribute_changes: Sequence[str] = m.Field(
                default_factory=list[str],
                description="Tracked attribute change descriptions",
            )

        class OperationResult(m.BaseModel):
            """Immutable result of an LDAP operation (add/modify/delete/search)."""

            model_config = m.ConfigDict(frozen=True)
            success: Annotated[
                bool,
                m.Field(description="Whether the operation succeeded"),
            ] = False
            operation_type: Annotated[
                str,
                m.Field(description="Type of operation performed"),
            ] = ""
            message: Annotated[str, m.Field(description="Result or error message")] = ""
            entries_affected: Annotated[
                t.NonNegativeInt,
                m.Field(description="Number of entries affected"),
            ] = 0

        class SearchResult(m.BaseModel):
            """Search result.

            Contains entries from LDAP search operations. The entries field
            holds a list of directory entries returned from the search.
            """

            entries: Annotated[
                Sequence[
                    Annotated[
                        p.Ldif.Entry, m.ValidateAs(m.Ldif.Entry, lambda entry: entry)
                    ]
                ],
                m.Field(default_factory=list),
            ]
            search_options: FlextLdapModelsFlextLdap.FlextLdapModelsLdap.SearchOptions

        class LdapOperationResult(m.BaseModel):
            """LDAP operation result."""

            operation: str = ""

        class PhaseSyncResult(LdapBatchStats):
            """Phase sync result - extends LdapBatchStats."""

            phase_name: str = ""
            total_entries: t.NonNegativeInt = 0
            duration_seconds: t.NonNegativeFloat = 0.0
            success_rate: t.NonNegativeFloat = 0.0

        class MultiPhaseSyncResult(m.BaseModel):
            """Multi-phase sync result."""

            model_config = m.ConfigDict(arbitrary_types_allowed=True)
            phase_results: Mapping[
                str,
                FlextLdapModelsFlextLdap.FlextLdapModelsLdap.PhaseSyncResult,
            ] = m.Field(
                default_factory=dict[
                    str,
                    "FlextLdapModelsFlextLdap.FlextLdapModelsLdap.PhaseSyncResult",
                ],
                description="Per-phase sync results keyed by phase name",
            )
            total_entries: t.NonNegativeInt = 0
            total_synced: t.NonNegativeInt = 0
            total_failed: t.NonNegativeInt = 0
            total_skipped: t.NonNegativeInt = 0
            overall_success_rate: t.NonNegativeFloat = 0.0
            total_duration_seconds: t.NonNegativeFloat = 0.0
            overall_success: bool = True

        type Response = (
            OperationResult
            | SearchResult
            | LdapOperationResult
            | UpsertResult
            | BatchUpsertResult
            | LdapBatchStats
            | PhaseSyncResult
            | MultiPhaseSyncResult
        )


__all__: list[str] = ["FlextLdapModelsFlextLdap"]
