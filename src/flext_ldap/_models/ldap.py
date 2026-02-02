"""FlextLdap LDAP-specific models.

LDAP operation models with validation logic.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Self

from flext_core import FlextTypes as t
from pydantic import BaseModel, ConfigDict, Field, computed_field, model_validator

__all__ = [
    "FlextLdapModelsLdap",
]


class FlextLdapModelsLdap:
    """LDAP-specific models namespace."""

    class ConnectionConfig(BaseModel):
        """Connection config."""

        host: str = "localhost"
        port: int = Field(default=389, ge=1, le=65535)
        use_ssl: bool = False
        use_tls: bool = False
        bind_dn: str | None = None
        bind_password: str | None = None
        timeout: int = 30
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

        scope: str = "SUBTREE"
        filter_str: str = "(objectClass=*)"
        size_limit: int = 0
        time_limit: int = 0
        attributes: list[str] | None = None

    class SearchOptions(BaseModel):
        """Search options."""

        base_dn: str = Field(
            ...,
            min_length=1,
            description="Base DN for search (required, non-empty)",
        )
        scope: str = "SUBTREE"
        filter_str: str = "(objectClass=*)"
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

            return cls(
                base_dn=base_dn,
                scope=norm_config.scope,
                filter_str=norm_config.filter_str,
                size_limit=norm_config.size_limit,
                time_limit=norm_config.time_limit,
                attributes=norm_config.attributes,
            )

    class LdapBatchStats(BaseModel):
        """Batch stats."""

        synced: int = 0
        failed: int = 0
        skipped: int = 0

    class SyncOptions(BaseModel):
        """Sync options."""

        batch_size: int = Field(
            default=100,
            ge=1,
            description="Batch size for sync operations (must be >= 1)",
        )
        auto_create_parents: bool = True
        allow_deletes: bool = False
        source_basedn: str = ""
        target_basedn: str = ""
        progress_callback: object = None  # Simplified callback type

    class SyncStats(BaseModel):
        """Sync stats."""

        added: int = 0
        skipped: int = 0
        failed: int = 0
        total: int = 0
        duration_seconds: float = 0.0

        @computed_field
        @property
        def success_rate(self) -> float:
            """Calculate success rate (added + skipped) / total."""
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
            **kwargs: object,
        ) -> Self:
            """Factory method with auto-calculated total from counters."""
            return cls(
                added=added,
                skipped=skipped,
                failed=failed,
                total=added + skipped + failed,
                duration_seconds=duration_seconds,
                **kwargs,
            )

    class UpsertResult(BaseModel):
        """Upsert result."""

        success: bool
        dn: str
        operation: str
        error: str | None = None

        @property
        def is_success(self) -> bool:
            """Alias for success field for FlextResult compatibility."""
            return self.success

    class BatchUpsertResult(BaseModel):
        """Batch upsert result."""

        total_processed: int = 0
        successful: int = 0
        failed: int = 0
        results: list[t.GeneralValueType] = Field(default_factory=list)

        @property
        def success_rate(self) -> float:
            """Calculate success rate (successful / total_processed)."""
            if self.total_processed == 0:
                return 0.0
            return self.successful / self.total_processed

    class SyncPhaseConfig(BaseModel):
        """Sync phase config."""

        model_config = ConfigDict(arbitrary_types_allowed=True)

        server_type: str = "rfc"
        progress_callback: FlextLdapModelsLdap.Types.ProgressCallbackUnion = None
        retry_on_errors: list[str] | None = None
        max_retries: int = 5
        stop_on_error: bool = False

    class ConversionMetadata(BaseModel):
        """Conversion metadata."""

        source_attributes: list[str] = Field(default_factory=list)
        source_dn: str = ""
        removed_attributes: list[str] = Field(default_factory=list)
        base64_encoded_attributes: list[str] = Field(default_factory=list)
        dn_changed: bool = False
        converted_dn: str = ""
        attribute_changes: list[str] = Field(default_factory=list)

    class OperationResult(BaseModel):
        """LDAP operation result."""

        model_config = {"frozen": True}

        success: bool
        operation_type: str
        message: str = ""
        entries_affected: int = 0

        @property
        def is_success(self) -> bool:
            """Alias for success field for FlextResult compatibility."""
            return self.success

    class SearchResult(BaseModel):
        """Search result.

        Contains entries from LDAP search operations. The entries field
        holds a list of directory entries returned from the search.
        """

        entries: list[t.GeneralValueType] = Field(default_factory=list)
        search_options: object = None

        @property
        def total_count(self) -> int:
            """Total count of entries in result."""
            return len(self.entries)

        @property
        def by_objectclass(self) -> dict[str, list[t.GeneralValueType]]:
            """Group entries by objectclass."""
            result: dict[str, list[t.GeneralValueType]] = {}
            for entry in self.entries:
                category = self.get_entry_category(entry)
                if category not in result:
                    result[category] = []
                result[category].append(entry)
            return result

        @staticmethod
        def extract_attrs_dict_from_entry(
            entry: object,
        ) -> dict[str, list[str]]:
            """Extract attributes dict from entry."""
            if entry is None:
                return {}
            # Try to get attributes from entry
            if hasattr(entry, "attributes"):
                attrs = getattr(entry, "attributes", None)
                if attrs is None:
                    return {}
                # Handle different attribute formats
                if isinstance(attrs, dict):
                    return attrs
                if hasattr(attrs, "attributes"):
                    attrs_inner = getattr(attrs, "attributes", None)
                    if isinstance(attrs_inner, dict):
                        return attrs_inner
            return {}

        @staticmethod
        def extract_objectclass_category(
            attrs: dict[str, t.GeneralValueType],
        ) -> str:
            """Extract objectclass category from attributes."""
            if not attrs or not isinstance(attrs, dict):
                return "unknown"
            oc_list = attrs.get("objectClass", attrs.get("objectclass", []))
            if isinstance(oc_list, (list, tuple)) and oc_list:
                return str(oc_list[0]).lower()
            return "unknown"

        @staticmethod
        def get_entry_category(entry: object) -> str:
            """Get category (objectclass) of an entry."""
            # Extract attributes from entry
            attrs: dict[str, list[str]] = {}
            if entry is not None and hasattr(entry, "attributes"):
                attrs_obj = getattr(entry, "attributes", None)
                if attrs_obj is None:
                    attrs = {}
                elif isinstance(attrs_obj, dict):
                    attrs = attrs_obj
                elif hasattr(attrs_obj, "attributes"):
                    attrs_inner = getattr(attrs_obj, "attributes", None)
                    if isinstance(attrs_inner, dict):
                        attrs = attrs_inner
            # Extract objectclass category from attributes
            if not attrs or not isinstance(attrs, dict):
                return "unknown"
            oc_list = attrs.get("objectClass", attrs.get("objectclass", []))
            if isinstance(oc_list, (list, tuple)) and oc_list:
                return str(oc_list[0]).lower()
            return "unknown"

    class Types:
        """Type definitions for LDAP models."""

        LdapProgressCallback = Callable[[int, int, str, object], None]
        MultiPhaseProgressCallback = Callable[[str, int, int, str, object], None]
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

        phase_results: dict[str, FlextLdapModelsLdap.PhaseSyncResult] = Field(
            default_factory=dict,
        )
        total_entries: int = 0
        total_synced: int = 0
        total_failed: int = 0
        total_skipped: int = 0
        overall_success_rate: float = 0.0
        total_duration_seconds: float = 0.0
        overall_success: bool = True
