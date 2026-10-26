# AUTO-GENERATED FILE — Regenerate with: make gen
"""FLEXT LDAP utility facade.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from flext_ldif import u

from flext_ldap._utilities import (
    FlextLdapUtilitiesBase,
    FlextLdapUtilitiesComparison,
    FlextLdapUtilitiesConversion,
    FlextLdapUtilitiesDetection,
    FlextLdapUtilitiesNormalization,
    FlextLdapUtilitiesRootDse,
    FlextLdapUtilitiesServer,
    FlextLdapUtilitiesValidation,
)


class FlextLdapUtilities(u):
    """LDAP-specific utility facade."""

    class Ldap(
        FlextLdapUtilitiesComparison,
        FlextLdapUtilitiesConversion,
        FlextLdapUtilitiesRootDse,
        FlextLdapUtilitiesDetection,
        FlextLdapUtilitiesNormalization,
        FlextLdapUtilitiesServer,
        FlextLdapUtilitiesValidation,
        FlextLdapUtilitiesBase,
    ):
        """LDAP-specific utility namespace."""


u = FlextLdapUtilities
__all__: list[str] = ["FlextLdapUtilities", "u"]
