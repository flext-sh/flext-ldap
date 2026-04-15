"""FlextLdap models module - FACADE ONLY.

This module provides models for LDAP operations, extending FlextLdifModels.
All model implementations are in _models/*.py - this is a pure facade.
"""

from __future__ import annotations

from collections.abc import Mapping

from pydantic import Field

from flext_ldap import FlextLdapModelsLdap
from flext_ldif import FlextLdifModels


class FlextLdapModels(FlextLdifModels, FlextLdapModelsLdap):
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

    class Ldap(FlextLdapModelsLdap):
        """LDAP-specific models namespace via pure MRO composition."""

        class MultiPhaseSyncResult(FlextLdapModelsLdap.MultiPhaseSyncResult):
            """Result of multi-phase sync operations.

            Overrides phase_results to ensure Mapping resolves in facade namespace.
            """

            phase_results: Mapping[str, FlextLdapModelsLdap.PhaseSyncResult] = Field(
                default_factory=dict,
                description="Per-phase sync results keyed by phase name",
            )


# Global instance

__all__: list[str] = ["FlextLdapModels", "m"]

m = FlextLdapModels
