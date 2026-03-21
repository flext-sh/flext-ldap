"""FlextLdap models module - FACADE ONLY.

This module provides models for LDAP operations, extending FlextLdifModels.
All model implementations are in _models/*.py - this is a pure facade.
"""

from __future__ import annotations

from flext_ldif import FlextLdifModels

from flext_ldap._models.ldap import FlextLdapModelsLdap


class FlextLdapModels(FlextLdifModels):
    """LDAP domain models extending FlextLdifModels.

    Hierarchy:
    FlextModels (flext-core)
    -> FlextLdifModels (flext-ldif)
    -> FlextLdapModels (this module)

    Access patterns:
    - m.Ldap.* (LDAP-specific models)
    - m.Ldif.* (inherited from FlextLdifModels)
    - m.CollectionsCategories, .Config, etc. (inherited from FlextModels via FlextLdifModels)
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

        class SearchParams(FlextLdapModelsLdap.SearchParams):
            """Typed LDAP search parameters passed to ldap3 search calls."""

        class SyncOptions(FlextLdapModelsLdap.SyncOptions):
            """Sync options model namespace."""

        class SyncPhaseConfig(FlextLdapModelsLdap.SyncPhaseConfig):
            """Sync phase configuration model namespace."""

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

            LdapProgressCallback = FlextLdapModelsLdap.Types.LdapProgressCallback
            MultiPhaseProgressCallback = (
                FlextLdapModelsLdap.Types.MultiPhaseProgressCallback
            )
            ProgressCallbackUnion = FlextLdapModelsLdap.Types.ProgressCallbackUnion


# Global instance

__all__ = ["FlextLdapModels", "m"]

m = FlextLdapModels
