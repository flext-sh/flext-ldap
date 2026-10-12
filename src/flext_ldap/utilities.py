"""FLEXT LDAP utility facade.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from flext_ldif import FlextLdifUtilities

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


class FlextLdapUtilities(FlextLdifUtilities):
    """LDAP-specific utility facade."""

    class Ldap(
        FlextLdapUtilitiesServer,
        FlextLdapUtilitiesConversion,
        FlextLdapUtilitiesComparison,
        FlextLdapUtilitiesRootDse,
        FlextLdapUtilitiesDetection,
        FlextLdapUtilitiesNormalization,
        FlextLdapUtilitiesValidation,
        FlextLdapUtilitiesBase,
    ):
        """LDAP-specific utility namespace."""

        Validation: type[FlextLdapUtilitiesValidation] = FlextLdapUtilitiesValidation


u = FlextLdapUtilities

__all__: list[str] = ["FlextLdapUtilities", "u"]
