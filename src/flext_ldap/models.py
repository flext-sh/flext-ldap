"""FlextLdap models module.

This module provides models for LDAP operations, extending FlextLdifModels.
"""

from __future__ import annotations

from collections.abc import Callable, Sequence
from typing import Protocol, Self, runtime_checkable

from flext_ldif.models import FlextLdifModels
from pydantic import BaseModel, Field, model_validator


@runtime_checkable
class HasItemsMethod(Protocol):
    """Protocol for objects with items() method."""

    def items(self) -> Sequence[tuple[str, object]]:
        """Return items as sequence of tuples."""
        ...


class FlextLdapModels(FlextLdifModels):
    """LDAP domain models extending FlextLdifModels.

    Hierarchy:
    FlextModels (flext-core)
    -> FlextLdifModels (flext-ldif)
    -> FlextLdapModels (this module)

    Access patterns:
    - m.Ldap.* (LDAP-specific models)
    - m.Ldif.* (inherited from FlextLdifModels)
    - m.Entity.*, m.Value, etc. (inherited from FlextModels)
    """

    class Collections:
        """Collection-related models (direct access)."""

        class Config(BaseModel):
            """Collection configuration."""

            max_size: int = Field(default=1000, ge=1)

        class Options(BaseModel):
            """Collection options."""

            sorted: bool = Field(default=False)

        class Results(BaseModel):
            """Collection results."""

            total: int = Field(default=0)
            success: int = Field(default=0)
            failed: int = Field(default=0)

        class Statistics(BaseModel):
            """Collection statistics."""

            count: int = Field(default=0)
            unique: int = Field(default=0)

    class Ldap:
        """LDAP-specific models."""

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
                    raise ValueError("use_ssl and use_tls are mutually exclusive")
                return self

        class SearchOptions(BaseModel):
            """Search options."""

            base_dn: str = ""
            scope: str = "SUBTREE"
            filter_str: str = "(objectClass=*)"
            attributes: list[str] | None = None
            size_limit: int = 0
            time_limit: int = 0

        class LdapBatchStats(BaseModel):
            """Batch stats."""

            synced: int = 0
            failed: int = 0
            skipped: int = 0

        class SyncOptions(BaseModel):
            """Sync options."""

            batch_size: int = 100
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

            @classmethod
            def from_counters(
                cls,
                added: int = 0,
                skipped: int = 0,
                failed: int = 0,
                duration_seconds: float = 0.0,
                **kwargs: object,
            ) -> FlextLdapModels.Ldap.SyncStats:
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

        class BatchUpsertResult(BaseModel):
            """Batch upsert result."""

            total_processed: int = 0
            successful: int = 0
            failed: int = 0
            results: list[object] = Field(default_factory=list)

        class SyncPhaseConfig(BaseModel):
            """Sync phase config."""

            server_type: str = "rfc"
            progress_callback: object = None
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

            success: bool
            operation_type: str
            message: str = ""
            entries_affected: int = 0

        class SearchResult(BaseModel):
            """Search result."""

            entries: list[object] = Field(default_factory=list)
            search_options: object = None

        class Types:
            """Type definitions for LDAP models."""

            LdapProgressCallback = Callable[[int, int, str, object], None]
            MultiPhaseProgressCallback = Callable[[str, int, int, str, object], None]
            ProgressCallbackUnion = (
                LdapProgressCallback | MultiPhaseProgressCallback | None
            )

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

            phase_results: dict[str, object] = Field(default_factory=dict)
            total_entries: int = 0
            total_synced: int = 0
            total_failed: int = 0
            total_skipped: int = 0
            overall_success_rate: float = 0.0
            total_duration_seconds: float = 0.0
            overall_success: bool = True


# Global instance
m = FlextLdapModels

__all__ = ["FlextLdapModels", "m"]
