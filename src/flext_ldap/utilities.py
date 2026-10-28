# AUTO-GENERATED FILE — Regenerate with: make gen
"""FLEXT LDAP utility facade.

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

from flext_ldif import u as flext_ldif_u

from flext_ldap._utilities import (
    FlextLdapUtilitiesComparison,
    FlextLdapUtilitiesConversion,
    FlextLdapUtilitiesRootDse,
    FlextLdapUtilitiesServer,
    FlextLdapUtilitiesValidation,
)


class FlextLdapUtilities(flext_ldif_u):
    """LDAP-specific utility facade."""

    class Ldap(
        FlextLdapUtilitiesComparison,
        FlextLdapUtilitiesConversion,
        FlextLdapUtilitiesRootDse,
        FlextLdapUtilitiesServer,
        FlextLdapUtilitiesValidation,
    ):
        """LDAP-specific utility namespace."""


u = FlextLdapUtilities
__all__: list[str] = ["FlextLdapUtilities", "u"]
