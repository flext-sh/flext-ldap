"""FlextLdap models module - FACADE ONLY.

This module provides models for LDAP operations, extending FlextLdifModels.
All model implementations are in _models/*.py - this is a pure facade.
"""

from __future__ import annotations

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

    # Expose Ldap namespace from _models (new namespace, not an override)
    Ldap = FlextLdapModelsLdap


# Global instance
m = FlextLdapModels

__all__ = ["FlextLdapModels", "HasItemsMethod", "m"]
