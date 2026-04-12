"""FlextLdap LDAP-specific models.

LDAP operation models with validation logic.
"""

from __future__ import annotations

from collections.abc import Mapping, MutableMapping, MutableSequence, Sequence
from typing import Annotated, ClassVar, Self

from pydantic import BaseModel, ConfigDict, Field, computed_field, model_validator

from flext_ldap import c, t


class FlextLdapModelsLdap:
    """LDAP-specific models namespace."""

    class ConnectionConfig(BaseModel):
        """Connection configuration for LDAP server."""

        host: Annotated[str, Field(description="LDAP server hostname")] = c.LOCALHOST
        port: Annotated[
            t.PortNumber,
            Field(description="LDAP server port"),
        ] = c.Ldap.ConnectionDefaults.PORT
        use_ssl: Annotated[bool, Field(description="Enable SSL (LDAPS)")] = False
        use_tls: Annotated[bool, Field(description="Enable StartTLS")] = False
        bind_dn: Annotated[
            str | None,
            Field(description="Bind DN for authentication"),
        ] = None
        bind_password: Annotated[
            str | None,
            Field(description="Bind password for authentication"),
        ] = None
        timeout: Annotated[
            t.PositiveInt,
            Field(description="Connection timeout in seconds"),
        ] = c.Ldap.ConnectionDefaults.TIMEOUT
        auto_bind: Annotated[
            bool,
            Field(description="Auto-bind on connection"),
        ] = True
        auto_range: Annotated[
            bool,
            Field(description="Enable auto-range for paged results"),
        ] = True

        @model_validator(mode="after")
        def validate_ssl_tls_exclusion(self) -> Self:
            """Validate that SSL and TLS are mutually exclusive."""
            if self.use_ssl and self.use_tls:
                msg = "use_ssl and use_tls are mutually exclusive"
                raise ValueError(msg)
            return self

    class NormalizedConfig(BaseModel):
        """Configuration for normalized SearchOptions factory."""

        scope: str = c.Ldap.SearchDefaults.DEFAULT_SCOPE
        filter_str: str = c.Ldap.Filters.ALL_ENTRIES_FILTER
        size_limit: t.NonNegativeInt = 0
        time_limit: t.NonNegativeInt = 0
        attributes: t.StrSequence | None = None

    class SearchOptions(BaseModel):
        """Search options."""

        base_dn: Annotated[
            t.NonEmptyStr,
            Field(..., description="Base DN for search (required, non-empty)"),
        ]
        scope: str = c.Ldap.SearchDefaults.DEFAULT_SCOPE
        filter_str: str = c.Ldap.Filters.ALL_ENTRIES_FILTER
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

    class SearchParams(BaseModel):
        """Typed LDAP search parameters passed to ldap3 search calls."""

        model_config: ClassVar[ConfigDict] = ConfigDict(frozen=True, extra="forbid")
        base_dn: str
        filter_str: str
        ldap_scope: t.NonNegativeInt
        search_attributes: t.StrSequence
        size_limit: t.NonNegativeInt
        time_limit: t.NonNegativeInt

    class LdapBatchStats(BaseModel):
        """Base counters for batch LDAP operations (reused via MRO)."""

        synced: Annotated[
            t.NonNegativeInt,
            Field(description="Entries synced successfully"),
        ] = 0
        failed: Annotated[
            t.NonNegativeInt,
            Field(description="Entries that failed"),
        ] = 0
        skipped: Annotated[
            t.NonNegativeInt,
            Field(description="Entries skipped"),
        ] = 0

    class SyncOptions(BaseModel):
        """Configuration for LDAP sync operations."""

        model_config: ClassVar[ConfigDict] = ConfigDict(arbitrary_types_allowed=True)
        batch_size: Annotated[
            t.PositiveInt,
            Field(description="Batch size for sync operations"),
        ] = c.Ldap.SyncDefaults.BATCH_SIZE
        auto_create_parents: Annotated[
            bool,
            Field(description="Auto-create parent entries if missing"),
        ] = True
        allow_deletes: Annotated[
            bool,
            Field(description="Allow deletion of entries during sync"),
        ] = False
        source_basedn: Annotated[
            str,
            Field(description="Source base DN for sync"),
        ] = ""
        target_basedn: Annotated[
            str,
            Field(description="Target base DN for sync"),
        ] = ""
        progress_callback: t.Ldap.ProgressCallbackUnion = None

    class SyncStats(LdapBatchStats):
        """Sync stats - extends LdapBatchStats."""

        total: t.NonNegativeInt = 0
        duration_seconds: t.NonNegativeFloat = 0.0

        @computed_field
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

    class UpsertResult(BaseModel):
        """Result of a single upsert operation."""

        success: Annotated[bool, Field(description="Whether the upsert succeeded")] = (
            False
        )
        dn: Annotated[str, Field(description="Distinguished name of the entry")] = ""
        operation: Annotated[
            str,
            Field(description="Operation performed (ADD/MODIFY/SKIP)"),
        ] = ""
        error: Annotated[
            str | None,
            Field(description="Error message if operation failed"),
        ] = None

    class BatchUpsertResult(BaseModel):
        """Batch upsert result."""

        total_processed: t.NonNegativeInt = 0
        successful: t.NonNegativeInt = 0
        failed: t.NonNegativeInt = 0
        results: Sequence[Mapping[str, t.Primitives]] = []

        @computed_field
        @property
        def success_rate(self) -> float:
            """Calculate success rate (successful / total_processed)."""
            if self.total_processed == 0:
                return 0.0
            return self.successful / self.total_processed

    class SyncPhaseConfig(BaseModel):
        """Sync phase settings."""

        model_config: ClassVar[ConfigDict] = ConfigDict(arbitrary_types_allowed=True)
        server_type: str = c.Ldap.ServerDefaults.DEFAULT_TYPE
        progress_callback: t.Ldap.ProgressCallbackUnion = None
        retry_on_errors: t.StrSequence | None = None
        max_retries: t.RetryCount = c.Ldap.ConnectionDefaults.DEFAULT_MAX_RETRIES
        stop_on_error: bool = False

    class ConversionMetadata(BaseModel):
        """Conversion metadata."""

        source_attributes: t.StrSequence = Field(
            default_factory=list, description="Source attribute names"
        )
        source_dn: str = ""
        removed_attributes: t.StrSequence = Field(
            default_factory=list, description="Attributes removed during conversion"
        )
        base64_encoded_attributes: t.StrSequence = Field(
            default_factory=list, description="Attributes that were base64-encoded"
        )
        dn_changed: bool = False
        converted_dn: str = ""
        attribute_changes: t.StrSequence = Field(
            default_factory=list, description="Tracked attribute change descriptions"
        )

    class OperationResult(BaseModel):
        """Immutable result of an LDAP operation (add/modify/delete/search)."""

        model_config: ClassVar[ConfigDict] = ConfigDict(frozen=True)
        success: Annotated[
            bool, Field(description="Whether the operation succeeded")
        ] = False
        operation_type: Annotated[
            str,
            Field(description="Type of operation performed"),
        ] = ""
        message: Annotated[
            str,
            Field(description="Result or error message"),
        ] = ""
        entries_affected: Annotated[
            t.NonNegativeInt,
            Field(description="Number of entries affected"),
        ] = 0

    class SearchResult(BaseModel):
        """Search result.

        Contains entries from LDAP search operations. The entries field
        holds a list of directory entries returned from the search.
        """

        entries: Sequence[Mapping[str, t.StrSequence]] = []
        search_options: FlextLdapModelsLdap.SearchOptions | None = None

        @computed_field
        @property
        def by_objectclass(self) -> Mapping[str, Sequence[Mapping[str, t.StrSequence]]]:
            """Group entries by objectclass."""
            result: MutableMapping[
                str,
                MutableSequence[Mapping[str, t.StrSequence]],
            ] = {}
            for entry in self.entries:
                category = self.get_entry_category(entry)
                if category not in result:
                    result[category] = []
                result[category].append(entry)
            return result

        @computed_field
        @property
        def total_count(self) -> int:
            """Total count of entries in result."""
            return len(self.entries)

        @staticmethod
        def extract_attrs_dict_from_entry(
            entry: Mapping[str, t.StrSequence],
        ) -> Mapping[str, t.StrSequence]:
            """Extract attributes dict from entry."""
            return {key: list(values) for key, values in entry.items()}

        @staticmethod
        def extract_objectclass_category(
            attrs: t.AttributeMapping,
        ) -> str:
            """Extract objectclass category from attributes."""
            if not attrs:
                return c.Ldap.Defaults.UNKNOWN_CATEGORY
            oc_list = attrs.get("objectClass", attrs.get("objectclass", []))
            if isinstance(oc_list, list):
                if not oc_list:
                    return c.Ldap.Defaults.UNKNOWN_CATEGORY
                first_value = oc_list[0]
                return first_value.lower()
            return c.Ldap.Defaults.UNKNOWN_CATEGORY

        @staticmethod
        def get_entry_category(entry: Mapping[str, t.StrSequence]) -> str:
            """Get category (objectclass) of an entry."""
            attrs = FlextLdapModelsLdap.SearchResult.extract_attrs_dict_from_entry(
                entry,
            )
            if not attrs:
                return c.Ldap.Defaults.UNKNOWN_CATEGORY
            oc_list = attrs.get("objectClass", attrs.get("objectclass", []))
            match oc_list:
                case list() as oc_values if oc_values:
                    return str(oc_values[0]).lower()
                case _:
                    return c.Ldap.Defaults.UNKNOWN_CATEGORY

    class LdapOperationResult(BaseModel):
        """LDAP operation result."""

        operation: str = ""

    class PhaseSyncResult(LdapBatchStats):
        """Phase sync result - extends LdapBatchStats."""

        phase_name: str = ""
        total_entries: t.NonNegativeInt = 0
        duration_seconds: t.NonNegativeFloat = 0.0
        success_rate: t.NonNegativeFloat = 0.0

    class MultiPhaseSyncResult(BaseModel):
        """Multi-phase sync result."""

        model_config: ClassVar[ConfigDict] = ConfigDict(arbitrary_types_allowed=True)
        phase_results: Mapping[str, FlextLdapModelsLdap.PhaseSyncResult] = Field(
            default_factory=dict,
            description="Per-phase sync results keyed by phase name",
        )
        total_entries: t.NonNegativeInt = 0
        total_synced: t.NonNegativeInt = 0
        total_failed: t.NonNegativeInt = 0
        total_skipped: t.NonNegativeInt = 0
        overall_success_rate: t.NonNegativeFloat = 0.0
        total_duration_seconds: t.NonNegativeFloat = 0.0
        overall_success: bool = True


__all__: list[str] = ["FlextLdapModelsLdap"]
