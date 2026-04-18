"""FlextLdap models module - FACADE ONLY.

This module provides models for LDAP operations, extending m.
All model implementations are in _models/*.py - this is a pure facade.
"""

from __future__ import annotations


from flext_ldap import FlextLdapModelsLdap
from flext_ldif import m


class FlextLdapModels(m):
    """LDAP domain models extending m.

    Hierarchy:
    FlextModels (flext-core)
    -> m (flext-ldif)
    -> FlextLdapModels (this module)

    Access patterns:
    - m.Ldap.* (LDAP-specific models)
    - m.Ldif.* (inherited from m)
    - m.CollectionsCategories, .Config, etc. (inherited from FlextModels via m)
    - m.Entity.*, m.Value, etc. (inherited from FlextModels)

    This is a FACADE - all implementations are in _models/*.py.
    NOTE: Collections is inherited from parent - do NOT override.
    """

    class Ldap(FlextLdapModelsLdap):
        """LDAP-specific models namespace via pure MRO composition."""


# Global instance

__all__: list[str] = ["FlextLdapModels", "m"]

m = FlextLdapModels
