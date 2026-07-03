# AUTO-GENERATED FILE — Regenerate with: make gen
"""Utilities package."""

from __future__ import annotations

from typing import TYPE_CHECKING

from flext_core.lazy import build_lazy_import_map, install_lazy_exports

if TYPE_CHECKING:
    from flext_ldap._utilities.comparison import (
        FlextLdapUtilitiesComparison as FlextLdapUtilitiesComparison,
    )
    from flext_ldap._utilities.conversion import (
        FlextLdapUtilitiesConversion as FlextLdapUtilitiesConversion,
    )
    from flext_ldap._utilities.detection import (
        FlextLdapUtilitiesDetection as FlextLdapUtilitiesDetection,
    )
    from flext_ldap._utilities.normalization import (
        FlextLdapUtilitiesNormalization as FlextLdapUtilitiesNormalization,
    )
    from flext_ldap._utilities.root_dse import (
        FlextLdapUtilitiesRootDse as FlextLdapUtilitiesRootDse,
    )
    from flext_ldap._utilities.server import (
        FlextLdapUtilitiesServer as FlextLdapUtilitiesServer,
    )
    from flext_ldap._utilities.validation import (
        FlextLdapUtilitiesValidation as FlextLdapUtilitiesValidation,
    )
_LAZY_IMPORTS = build_lazy_import_map(
    {
        ".comparison": ("FlextLdapUtilitiesComparison",),
        ".conversion": ("FlextLdapUtilitiesConversion",),
        ".detection": ("FlextLdapUtilitiesDetection",),
        ".normalization": ("FlextLdapUtilitiesNormalization",),
        ".root_dse": ("FlextLdapUtilitiesRootDse",),
        ".server": ("FlextLdapUtilitiesServer",),
        ".validation": ("FlextLdapUtilitiesValidation",),
    },
)


install_lazy_exports(
    __name__,
    globals(),
    _LAZY_IMPORTS,
    publish_all=False,
)
