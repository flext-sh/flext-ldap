"""FlextLdap LDAP-specific models.

LDAP operation models with validation logic.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from typing import Annotated, Self

from pydantic import BaseModel, ConfigDict, Field, computed_field, model_validator

from flext_ldap.constants import c
from flext_ldap.protocols import p
from flext_ldap.typings import t


class FlextLdapModelsLdap:
    """LDAP-specific models namespace."""

    class ConnectionConfig(BaseModel):
        """Connection config."""

        host: str = c.Ldap.ConnectionDefaults.DEFAULT_HOST
        port: Annotated[
            int, Field(default=c.Ldap.ConnectionDefaults.PORT, ge=1, le=65535)
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
        attributes: list[str] | None = None

    class SearchOptions(BaseModel):
        """Search options."""

        base_dn: Annotated[
            str,
            Field(
                ...,
                min_length=1,
                description="Base DN for search (required, non-empty)",
            ),
        ]
        scope: str = c.Ldap.SearchDefaults.DEFAULT_SCOPE
        filter_str: str = c.Ldap.Filters.ALL_ENTRIES_FILTER
        attributes: list[str] | None = None
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

    class LdapBatchStats(BaseModel):
        """Batch stats."""

        synced: int = 0
        failed: int = 0
        skipped: int = 0

    class SyncOptions(BaseModel):
        """Sync options."""

        batch_size: Annotated[
            int,
            Field(
                default=100,
                ge=1,
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
        results: list[dict[str, t.Primitives]] = []

        @property
        def success_rate(self) -> float:
            """Calculate success rate (successful / total_processed)."""
            if self.total_processed == 0:
                return 0.0
            return self.successful / self.total_processed

    class SyncPhaseConfig(BaseModel):
        """Sync phase config."""

        model_config = ConfigDict(arbitrary_types_allowed=True)
        server_type: str = c.Ldap.ServerDefaults.DEFAULT_TYPE
        progress_callback: Callable[..., None] | None = None
        retry_on_errors: list[str] | None = None
        max_retries: int = c.Ldap.ConnectionDefaults.DEFAULT_MAX_RETRIES
        stop_on_error: bool = False

    class ConversionMetadata(BaseModel):
        """Conversion metadata."""

        source_attributes: Annotated[list[str], Field(default_factory=list)]
        source_dn: str = ""
        removed_attributes: Annotated[list[str], Field(default_factory=list)]
        base64_encoded_attributes: Annotated[list[str], Field(default_factory=list)]
        dn_changed: bool = False
        converted_dn: str = ""
        attribute_changes: Annotated[list[str], Field(default_factory=list)]

    class OperationResult(BaseModel):
        """LDAP operation result."""

        model_config = ConfigDict(frozen=True)
        success: bool
        operation_type: str
        message: str = ""
        entries_affected: int = 0

    class SearchResult(BaseModel):
        """Search result.

        Contains entries from LDAP search operations. The entries field
        holds a list of directory entries returned from the search.
        """

        entries: list[dict[str, list[str]]] = []
        search_options: FlextLdapModelsLdap.SearchOptions | None = None

        @property
        def by_objectclass(self) -> Mapping[str, list[dict[str, list[str]]]]:
            """Group entries by objectclass."""
            result: dict[str, list[dict[str, list[str]]]] = {}
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
            entry: dict[str, list[str]],
        ) -> Mapping[str, list[str]]:
            """Extract attributes dict from entry."""
            return {key: list(values) for key, values in entry.items()}

        @staticmethod
        def extract_objectclass_category(attrs: Mapping[str, object]) -> str:
            """Extract objectclass category from attributes."""
            if not attrs:
                return "unknown"
            oc_list = attrs.get("objectClass", attrs.get("objectclass", []))
            match oc_list:
                case list() as oc_values if oc_values:
                    return str(oc_values[0]).lower()
                case _:
                    return "unknown"

        @staticmethod
        def get_entry_category(entry: dict[str, list[str]]) -> str:
            """Get category (objectclass) of an entry."""
            attrs = FlextLdapModelsLdap.SearchResult.extract_attrs_dict_from_entry(
                entry
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
            [str, int, int, str, "p.Ldap.LdapBatchStats"], None
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

        model_config = ConfigDict(arbitrary_types_allowed=True)
        phase_results: Annotated[
            dict[str, FlextLdapModelsLdap.PhaseSyncResult], Field(default_factory=dict)
        ]
        total_entries: int = 0
        total_synced: int = 0
        total_failed: int = 0
        total_skipped: int = 0
        overall_success_rate: float = 0.0
        total_duration_seconds: float = 0.0
        overall_success: bool = True


__all__ = ["FlextLdapModelsLdap"]
