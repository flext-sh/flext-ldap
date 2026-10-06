"""FlextLdap models module - FACADE ONLY.

This module provides models for LDAP operations, extending m.
All model implementations are in models/*.py - this is a pure facade.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from flext_ldif import FlextLdifModels

from flext_ldap._models.ldap import FlextLdapFlextModelsLdap


class FlextLdapModels(FlextLdifModels):
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

    This is a FACADE - all implementations are in models/*.py.
    NOTE: Collections is inherited from parent - do NOT override.
    """

    class Ldap(FlextLdapFlextModelsLdap.FlextLdapModelsLdap):
        """LDAP-specific models namespace via pure MRO composition."""


# Global instance


m = FlextLdapModels

__all__: list[str] = ["FlextLdapModels", "m"]
