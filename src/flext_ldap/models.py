# AUTO-GENERATED FILE — Regenerate with: make gen
"""FlextLdap models module - FACADE ONLY.

This module provides models for LDAP operations, extending m.
All model implementations are in models/*.py - this is a pure facade.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from collections.abc import (
    Iterable,
    Iterator,
    Mapping,
    MutableMapping,
    MutableSequence,
    Sequence,
)

from flext_ldif import m as flext_ldif_m

from flext_ldap._models import (
    FlextLdapModelsBase,
    FlextLdapModelsConfig,
    FlextLdapModelsFlextLdap,
)


class FlextLdapModels(flext_ldif_m):
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

    class Ldap(
        FlextLdapModelsBase,
        FlextLdapModelsConfig,
        FlextLdapModelsFlextLdap.FlextLdapModelsLdap,
    ):
        """LDAP-specific models namespace via pure MRO composition."""


# Global instance


m = FlextLdapModels
__all__: list[str] = ["FlextLdapModels", "m"]
