"""FlextLdap LDAP-specific models.

LDAP operation models with validation logic.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping, MutableMapping, MutableSequence, Sequence
from typing import Annotated, ClassVar, Self

from pydantic import BaseModel, ConfigDict, Field, computed_field, model_validator

from flext_ldap import c, p, t


class FlextLdapModelsLdap:
    """LDAP-specific models namespace."""

    class ConnectionConfig(BaseModel):
        """Connection config."""

        host: str = c.LOCALHOST
        port: Annotated[
            t.PortNumber,
            Field(default=c.Ldap.ConnectionDefaults.PORT),
        ]
        use_ssl: bool = False
        use_tls: bool = False
        bind_dn: str | None = None
        bind_password: str | None = None
        timeout: int = c.Ldap.ConnectionDefaults.TIMEOUT
        auto_bind: bool = True
        auto_range: bool = True

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
        size_limit: int = 0
        time_limit: int = 0
        attributes: Sequence[str] | None = None

    class SearchOptions(BaseModel):
        """Search options."""

        base_dn: Annotated[
            t.NonEmptyStr,
            Field(
                ...,
                description="Base DN for search (required, non-empty)",
            ),
        ]
        scope: str = c.Ldap.SearchDefaults.DEFAULT_SCOPE
        filter_str: str = c.Ldap.Filters.ALL_ENTRIES_FILTER
        attributes: Sequence[str] | None = None
        size_limit: int = 0
        time_limit: int = 0

        @classmethod
        def normalized(
            cls,
            base_dn: str,
            config: FlextLdapModelsLdap.NormalizedConfig | None = None,
        ) -> FlextLdapModelsLdap.SearchOptions:
            """Create SearchOptions with normalized configuration.

            Args:
                base_dn: Base DN for search
                config: Optional NormalizedConfig with custom values

            Returns:
                SearchOptions with specified or default values

            """
            norm_config = (
                FlextLdapModelsLdap.NormalizedConfig() if config is None else config
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
        ldap_scope: int
        search_attributes: Sequence[str]
        size_limit: int
        time_limit: int

    class LdapBatchStats(BaseModel):
        """Batch stats."""

        synced: int = 0
        failed: int = 0
        skipped: int = 0

    class SyncOptions(BaseModel):
        """Sync options."""

        batch_size: Annotated[
            t.PositiveInt,
            Field(
                default=100,
                description="Batch size for sync operations (must be >= 1)",
            ),
        ]
        auto_create_parents: bool = True
        allow_deletes: bool = False
        source_basedn: str = ""
        target_basedn: str = ""
        progress_callback: Callable[..., None] | None = None

    class SyncStats(BaseModel):
        """Sync stats - implements LdapBatchStats."""

        synced: int = 0
        skipped: int = 0
        failed: int = 0
        total: int = 0
        duration_seconds: float = 0.0

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
            **kwargs: str | float | bool | None,
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
        """Upsert result."""

        success: bool
        dn: str
        operation: str
        error: str | None = None

    class BatchUpsertResult(BaseModel):
        """Batch upsert result."""

        total_processed: int = 0
        successful: int = 0
        failed: int = 0
        results: Sequence[Mapping[str, t.Primitives]] = []

        @property
        def success_rate(self) -> float:
            """Calculate success rate (successful / total_processed)."""
            if self.total_processed == 0:
                return 0.0
            return self.successful / self.total_processed

    class SyncPhaseConfig(BaseModel):
        """Sync phase config."""

        model_config: ClassVar[ConfigDict] = ConfigDict(arbitrary_types_allowed=True)
        server_type: str = c.Ldap.ServerDefaults.DEFAULT_TYPE
        progress_callback: Callable[..., None] | None = None
        retry_on_errors: Sequence[str] | None = None
        max_retries: int = c.Ldap.ConnectionDefaults.DEFAULT_MAX_RETRIES
        stop_on_error: bool = False

    class ConversionMetadata(BaseModel):
        """Conversion metadata."""

        source_attributes: Annotated[Sequence[str], Field(default_factory=list)]
        source_dn: str = ""
        removed_attributes: Annotated[Sequence[str], Field(default_factory=list)]
        base64_encoded_attributes: Annotated[Sequence[str], Field(default_factory=list)]
        dn_changed: bool = False
        converted_dn: str = ""
        attribute_changes: Annotated[Sequence[str], Field(default_factory=list)]

    class OperationResult(BaseModel):
        """LDAP operation result."""

        model_config: ClassVar[ConfigDict] = ConfigDict(frozen=True)
        success: bool
        operation_type: str
        message: str = ""
        entries_affected: int = 0

    class SearchResult(BaseModel):
        """Search result.

        Contains entries from LDAP search operations. The entries field
        holds a list of directory entries returned from the search.
        """

        entries: Sequence[Mapping[str, Sequence[str]]] = []
        search_options: FlextLdapModelsLdap.SearchOptions | None = None

        @property
        def by_objectclass(self) -> Mapping[str, Sequence[Mapping[str, Sequence[str]]]]:
            """Group entries by objectclass."""
            result: MutableMapping[str, MutableSequence[Mapping[str, Sequence[str]]]] = {}
            for entry in self.entries:
                category = self.get_entry_category(entry)
                if category not in result:
                    result[category] = []
                result[category].append(entry)
            return result

        @property
        def total_count(self) -> int:
            """Total count of entries in result."""
            return len(self.entries)

        @staticmethod
        def extract_attrs_dict_from_entry(
            entry: Mapping[str, Sequence[str]],
        ) -> Mapping[str, Sequence[str]]:
            """Extract attributes dict from entry."""
            return {key: list(values) for key, values in entry.items()}

        @staticmethod
        def extract_objectclass_category(
            attrs: Mapping[str, str | Sequence[str]],
        ) -> str:
            """Extract objectclass category from attributes."""
            if not attrs:
                return "unknown"
            oc_list = attrs.get("objectClass", attrs.get("objectclass", []))
            if isinstance(oc_list, list):
                if len(oc_list) == 0:
                    return "unknown"
                first_value = oc_list[0]
                if isinstance(first_value, str):
                    return first_value.lower()
                return str(first_value).lower()
            return "unknown"

        @staticmethod
        def get_entry_category(entry: Mapping[str, Sequence[str]]) -> str:
            """Get category (objectclass) of an entry."""
            attrs = FlextLdapModelsLdap.SearchResult.extract_attrs_dict_from_entry(
                entry,
            )
            if not attrs:
                return "unknown"
            oc_list = attrs.get("objectClass", attrs.get("objectclass", []))
            match oc_list:
                case list() as oc_values if oc_values:
                    return str(oc_values[0]).lower()
                case _:
                    return "unknown"

    class Types:
        """Type definitions for LDAP models."""

        LdapProgressCallback = Callable[[int, int, str, "p.Ldap.LdapBatchStats"], None]
        MultiPhaseProgressCallback = Callable[
            [str, int, int, str, "p.Ldap.LdapBatchStats"],
            None,
        ]
        ProgressCallbackUnion = LdapProgressCallback | MultiPhaseProgressCallback | None

    class LdapOperationResult(BaseModel):
        """LDAP operation result."""

        operation: str

    class PhaseSyncResult(BaseModel):
        """Phase sync result."""

        phase_name: str
        total_entries: int = 0
        synced: int = 0
        failed: int = 0
        skipped: int = 0
        duration_seconds: float = 0.0
        success_rate: float = 0.0

    class MultiPhaseSyncResult(BaseModel):
        """Multi-phase sync result."""

        model_config: ClassVar[ConfigDict] = ConfigDict(arbitrary_types_allowed=True)
        phase_results: Mapping[str, FlextLdapModelsLdap.PhaseSyncResult] = Field(
            default_factory=dict
        )
        total_entries: int = 0
        total_synced: int = 0
        total_failed: int = 0
        total_skipped: int = 0
        overall_success_rate: float = 0.0
        total_duration_seconds: float = 0.0
        overall_success: bool = True


__all__ = ["FlextLdapModelsLdap"]
