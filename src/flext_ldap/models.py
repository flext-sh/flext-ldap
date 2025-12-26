"""FlextLdap models module - FACADE ONLY.

This module provides models for LDAP operations, extending FlextLdifModels.
All model implementations are in _models/*.py - this is a pure facade.
"""

from __future__ import annotations

from typing import TypeAlias

from flext_ldif.models import FlextLdifModels

from flext_ldap._models.ldap import FlextLdapModelsLdap
from flext_ldap.protocols import p

# Protocol reference from centralized protocols.py for backward compatibility
HasItemsMethod = p.Ldap.HasItemsMethod


class FlextLdapModels(FlextLdifModels):
    """LDAP domain models extending FlextLdifModels.

    Hierarchy:
    FlextModels (flext-core)
    -> FlextLdifModels (flext-ldif)
    -> FlextLdapModels (this module)

    Access patterns:
    - m.Ldap.* (LDAP-specific models)
    - m.Ldif.* (inherited from FlextLdifModels)
    - m.Collections.* (inherited from FlextModels via FlextLdifModels)
    - m.Entity.*, m.Value, etc. (inherited from FlextModels)

    This is a FACADE - all implementations are in _models/*.py.
    NOTE: Collections is inherited from parent - do NOT override.
    """

    # LDAP namespace with real inheritance from _models classes
    # Following flext-ldif pattern: define classes that inherit from _models
    class Ldap:
        """LDAP-specific models namespace."""

        # Configuration models
        class ConnectionConfig(FlextLdapModelsLdap.ConnectionConfig):
            """Connection configuration for LDAP connections."""

        class NormalizedConfig(FlextLdapModelsLdap.NormalizedConfig):
            """Configuration for normalized SearchOptions factory."""

        class SearchOptions(FlextLdapModelsLdap.SearchOptions):
            """Options for LDAP search operations."""

        class SyncOptions(FlextLdapModelsLdap.SyncOptions):
            """Options for LDAP sync operations."""

        class SyncPhaseConfig(FlextLdapModelsLdap.SyncPhaseConfig):
            """Configuration for sync phase operations."""

        # Result models
        class SearchResult(FlextLdapModelsLdap.SearchResult):
            """Result of LDAP search operations."""

        class OperationResult(FlextLdapModelsLdap.OperationResult):
            """Result of LDAP operations."""

        class LdapOperationResult(FlextLdapModelsLdap.LdapOperationResult):
            """LDAP operation result."""

        class SyncStats(FlextLdapModelsLdap.SyncStats):
            """Statistics from sync operations."""

        class LdapBatchStats(FlextLdapModelsLdap.LdapBatchStats):
            """Batch statistics for LDAP operations."""

        class UpsertResult(FlextLdapModelsLdap.UpsertResult):
            """Result of upsert operations."""

        class BatchUpsertResult(FlextLdapModelsLdap.BatchUpsertResult):
            """Result of batch upsert operations."""

        class PhaseSyncResult(FlextLdapModelsLdap.PhaseSyncResult):
            """Result of phase sync operations."""

        class MultiPhaseSyncResult(FlextLdapModelsLdap.MultiPhaseSyncResult):
            """Result of multi-phase sync operations."""

        # Metadata models
        class ConversionMetadata(FlextLdapModelsLdap.ConversionMetadata):
            """Metadata for LDAP entry conversions."""

        # Type definitions namespace
        class Types:
            """Type definitions for LDAP models."""

            LdapProgressCallback: TypeAlias = (
                FlextLdapModelsLdap.Types.LdapProgressCallback
            )
            MultiPhaseProgressCallback: TypeAlias = (
                FlextLdapModelsLdap.Types.MultiPhaseProgressCallback
            )
            ProgressCallbackUnion: TypeAlias = (
                FlextLdapModelsLdap.Types.ProgressCallbackUnion
            )


# Global instance
m = FlextLdapModels

__all__ = ["FlextLdapModels", "HasItemsMethod", "m"]
