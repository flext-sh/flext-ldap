"""FlextLdap LDAP-specific models.

LDAP operation models with validation logic.
"""

from __future__ import annotations

from types import MappingProxyType
from typing import Annotated, ClassVar, Self, TypeAlias

from flext_ldap import c, t
from flext_ldif import m, p, u


class FlextLdapModelsLdap:
    """LDAP-specific models namespace."""

    class ConnectionConfig(m.BaseModel):
        """Connection configuration for LDAP server."""

        host: Annotated[str, u.Field(description="LDAP server hostname")] = c.LOCALHOST
        port: Annotated[
            t.PortNumber,
            u.Field(description="LDAP server port"),
        ] = c.Ldap.PORT
        use_ssl: Annotated[bool, u.Field(description="Enable SSL (LDAPS)")] = False
        use_tls: Annotated[bool, u.Field(description="Enable StartTLS")] = False
        bind_dn: Annotated[
            str | None,
            u.Field(description="Bind DN for authentication"),
        ] = None
        bind_password: Annotated[
            str | None,
            u.Field(description="Bind password for authentication"),
        ] = None
        timeout: Annotated[
            t.PositiveInt,
            u.Field(description="Connection timeout in seconds"),
        ] = c.Ldap.TIMEOUT
        auto_bind: Annotated[
            bool,
            u.Field(description="Auto-bind on connection"),
        ] = True
        auto_range: Annotated[
            bool,
            u.Field(description="Enable auto-range for paged results"),
        ] = True

        @u.model_validator(mode="after")
        def validate_ssl_tls_exclusion(self) -> Self:
            """Validate that SSL and TLS are mutually exclusive."""
            if self.use_ssl and self.use_tls:
                msg = "use_ssl and use_tls are mutually exclusive"
                raise ValueError(msg)
            return self

    class NormalizedConfig(m.BaseModel):
        """Configuration for normalized SearchOptions factory."""

        scope: str = c.Ldap.DEFAULT_SCOPE
        filter_str: str = c.Ldap.ALL_ENTRIES_FILTER
        size_limit: t.NonNegativeInt = 0
        time_limit: t.NonNegativeInt = 0
        attributes: t.StrSequence | None = None

    class SearchOptions(m.BaseModel):
        """Search options."""

        base_dn: Annotated[
            t.NonEmptyStr,
            u.Field(..., description="Base DN for search (required, non-empty)"),
        ]
        scope: str = c.Ldap.DEFAULT_SCOPE
        filter_str: str = c.Ldap.ALL_ENTRIES_FILTER
        attributes: t.StrSequence | None = None
        size_limit: t.NonNegativeInt = 0
        time_limit: t.NonNegativeInt = 0

        @classmethod
        def normalized(
            cls,
            base_dn: str,
            settings: FlextLdapModelsLdap.NormalizedConfig | None = None,
        ) -> FlextLdapModelsLdap.SearchOptions:
            """Create SearchOptions with normalized configuration.

            Args:
                base_dn: Base DN for search
                settings: Optional NormalizedConfig with custom values

            Returns:
                SearchOptions with specified or default values

            """
            norm_config = (
                FlextLdapModelsLdap.NormalizedConfig() if settings is None else settings
            )
            return cls.model_validate({
                "base_dn": base_dn,
                "scope": norm_config.scope,
                "filter_str": norm_config.filter_str,
                "size_limit": norm_config.size_limit,
                "time_limit": norm_config.time_limit,
                "attributes": norm_config.attributes,
            })

        @classmethod
        def base_scope(cls, base_dn: str) -> Self:
            """Build base-scope search options using model defaults everywhere else."""
            return cls(
                base_dn=base_dn,
                scope=c.Ldap.SearchScope.BASE,
            )

    class SearchParams(m.BaseModel):
        """Typed LDAP search parameters passed to ldap3 search calls."""

        model_config: ClassVar[m.ConfigDict] = m.ConfigDict(
            frozen=True,
            extra="forbid",
        )
        base_dn: str
        filter_str: str
        ldap_scope: t.NonNegativeInt
        search_attributes: t.StrSequence
        size_limit: t.NonNegativeInt
        time_limit: t.NonNegativeInt

    class LdapBatchStats(m.BaseModel):
        """Base counters for batch LDAP operations (reused via MRO)."""

        synced: Annotated[
            t.NonNegativeInt,
            u.Field(description="Entries synced successfully"),
        ] = 0
        failed: Annotated[
            t.NonNegativeInt,
            u.Field(description="Entries that failed"),
        ] = 0
        skipped: Annotated[
            t.NonNegativeInt,
            u.Field(description="Entries skipped"),
        ] = 0

    class SyncOptions(m.BaseModel):
        """Configuration for LDAP sync operations."""

        model_config: ClassVar[m.ConfigDict] = m.ConfigDict(
            arbitrary_types_allowed=True,
        )
        batch_size: Annotated[
            t.PositiveInt,
            u.Field(description="Batch size for sync operations"),
        ] = c.Ldap.BATCH_SIZE
        auto_create_parents: Annotated[
            bool,
            u.Field(description="Auto-create parent entries if missing"),
        ] = True
        allow_deletes: Annotated[
            bool,
            u.Field(description="Allow deletion of entries during sync"),
        ] = False
        source_basedn: Annotated[
            str,
            u.Field(description="Source base DN for sync"),
        ] = ""
        target_basedn: Annotated[
            str,
            u.Field(description="Target base DN for sync"),
        ] = ""
        progress_callback: t.Ldap.ProgressCallbackUnion = None

    class SyncStats(LdapBatchStats):
        """Sync stats - extends LdapBatchStats."""

        total: t.NonNegativeInt = 0
        duration_seconds: t.NonNegativeFloat = 0.0

        @u.computed_field()
        @property
        def success_rate(self) -> float:
            """Calculate success rate (synced + skipped) / total."""
            if self.total == 0:
                return 0.0
            return (self.synced + self.skipped) / self.total

        @classmethod
        def from_counters(
            cls,
            synced: int = 0,
            skipped: int = 0,
            failed: int = 0,
            duration_seconds: float = 0.0,
            **kwargs: t.Primitives | None,
        ) -> Self:
            """Factory method with auto-calculated total from counters."""
            return cls.model_validate({
                "synced": synced,
                "skipped": skipped,
                "failed": failed,
                "total": synced + skipped + failed,
                "duration_seconds": duration_seconds,
                **kwargs,
            })

    class UpsertResult(m.BaseModel):
        """Result of a single upsert operation."""

        success: Annotated[
            bool, u.Field(description="Whether the upsert succeeded")
        ] = False
        dn: Annotated[str, u.Field(description="Distinguished name of the entry")] = ""
        operation: Annotated[
            str,
            u.Field(description="Operation performed (ADD/MODIFY/SKIP)"),
        ] = ""
        error: Annotated[
            str | None,
            u.Field(description="Error message if operation failed"),
        ] = None

    class BatchUpsertResult(m.BaseModel):
        """Batch upsert result."""

        total_processed: t.NonNegativeInt = 0
        successful: t.NonNegativeInt = 0
        failed: t.NonNegativeInt = 0
        results: Annotated[
            t.SequenceOf[t.MappingKV[str, t.Primitives]], u.Field(default_factory=list)
        ]

        @u.computed_field()
        @property
        def success_rate(self) -> float:
            """Calculate success rate (successful / total_processed)."""
            if self.total_processed == 0:
                return 0.0
            return self.successful / self.total_processed

    class SyncPhaseConfig(m.BaseModel):
        """Sync phase settings."""

        model_config: ClassVar[m.ConfigDict] = m.ConfigDict(
            arbitrary_types_allowed=True,
        )
        server_type: str = c.Ldap.DEFAULT_TYPE
        progress_callback: t.Ldap.ProgressCallbackUnion = None
        retry_on_errors: t.StrSequence | None = None
        max_retries: t.RetryCount = c.Ldap.DEFAULT_MAX_RETRIES
        stop_on_error: bool = False

    class ConversionMetadata(m.BaseModel):
        """Conversion metadata."""

        source_attributes: t.StrSequence = u.Field(
            default_factory=list, description="Source attribute names"
        )
        source_dn: str = ""
        removed_attributes: t.StrSequence = u.Field(
            default_factory=list, description="Attributes removed during conversion"
        )
        base64_encoded_attributes: t.StrSequence = u.Field(
            default_factory=list, description="Attributes that were base64-encoded"
        )
        dn_changed: bool = False
        converted_dn: str = ""
        attribute_changes: t.StrSequence = u.Field(
            default_factory=list, description="Tracked attribute change descriptions"
        )

    class OperationResult(m.BaseModel):
        """Immutable result of an LDAP operation (add/modify/delete/search)."""

        model_config: ClassVar[m.ConfigDict] = m.ConfigDict(frozen=True)
        success: Annotated[
            bool, u.Field(description="Whether the operation succeeded")
        ] = False
        operation_type: Annotated[
            str,
            u.Field(description="Type of operation performed"),
        ] = ""
        message: Annotated[
            str,
            u.Field(description="Result or error message"),
        ] = ""
        entries_affected: Annotated[
            t.NonNegativeInt,
            u.Field(description="Number of entries affected"),
        ] = 0

    class SearchResult(m.BaseModel):
        """Search result.

        Contains entries from LDAP search operations. The entries field
        holds a list of directory entries returned from the search.
        """

        entries: Annotated[t.SequenceOf[m.Ldif.Entry], u.Field(default_factory=list)]
        search_options: FlextLdapModelsLdap.SearchOptions

        @u.computed_field()
        @property
        def by_objectclass(self) -> m.Ldif.FlexibleCategories:
            """Group entries by objectclass."""
            result = m.Ldif.FlexibleCategories()
            for entry in self.entries:
                category = self.get_entry_category(entry)
                result[category].append(entry)
            return result

        @u.computed_field()
        @property
        def total_count(self) -> int:
            """Total count of entries in result."""
            return len(self.entries)

        @staticmethod
        def extract_attrs_dict_from_entry(
            entry: p.Ldif.Entry,
        ) -> t.MappingKV[str, t.StrSequence]:
            """Extract attributes dict from entry."""
            attributes = entry.attributes
            if attributes is None:
                return {}
            return attributes.attributes

        @staticmethod
        def extract_objectclass_category(
            attrs: t.AttributeMapping,
        ) -> str:
            """Extract objectclass category from attributes."""
            if not attrs:
                return c.Ldap.UNKNOWN_CATEGORY
            oc_list = attrs.get("objectClass", attrs.get("objectclass", []))
            if isinstance(oc_list, list):
                if not oc_list:
                    return c.Ldap.UNKNOWN_CATEGORY
                first_value = oc_list[0]
                return first_value.lower()
            return c.Ldap.UNKNOWN_CATEGORY

        @staticmethod
        def get_entry_category(entry: p.Ldif.Entry) -> str:
            """Get category (objectclass) of an entry."""
            attrs = FlextLdapModelsLdap.SearchResult.extract_attrs_dict_from_entry(
                entry,
            )
            if not attrs:
                return c.Ldap.UNKNOWN_CATEGORY
            oc_list = attrs.get("objectClass", attrs.get("objectclass", []))
            match oc_list:
                case list() as oc_values if oc_values:
                    return oc_values[0].lower()
                case _:
                    return c.Ldap.UNKNOWN_CATEGORY

    class LdapOperationResult(m.BaseModel):
        """LDAP operation result."""

        operation: str = ""

        @classmethod
        def with_operation(cls, operation: str) -> Self:
            """Build a minimal LDAP operation result."""
            return cls(operation=operation)

    class PhaseSyncResult(LdapBatchStats):
        """Phase sync result - extends LdapBatchStats."""

        phase_name: str = ""
        total_entries: t.NonNegativeInt = 0
        duration_seconds: t.NonNegativeFloat = 0.0
        success_rate: t.NonNegativeFloat = 0.0

    class MultiPhaseSyncResult(m.BaseModel):
        """Multi-phase sync result."""

        model_config: ClassVar[m.ConfigDict] = m.ConfigDict(
            arbitrary_types_allowed=True,
        )
        phase_results: t.MappingKV[str, m.BaseModel] = u.Field(
            default_factory=lambda: MappingProxyType({}),
            description="Per-phase sync results keyed by phase name",
        )
        total_entries: t.NonNegativeInt = 0
        total_synced: t.NonNegativeInt = 0
        total_failed: t.NonNegativeInt = 0
        total_skipped: t.NonNegativeInt = 0
        overall_success_rate: t.NonNegativeFloat = 0.0
        total_duration_seconds: t.NonNegativeFloat = 0.0
        overall_success: bool = True

    Response: TypeAlias = (
        OperationResult
        | SearchResult
        | LdapOperationResult
        | UpsertResult
        | BatchUpsertResult
        | LdapBatchStats
        | PhaseSyncResult
        | MultiPhaseSyncResult
    )


__all__: list[str] = ["FlextLdapModelsLdap"]
