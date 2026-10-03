# AUTO-GENERATED FILE — Regenerate with: make gen
"""Flext Ldap. Utilities package.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from types import MappingProxyType
from typing import TYPE_CHECKING

from flext_core import build_lazy_import_map, install_lazy_exports

if TYPE_CHECKING:
    from flext_ldap._utilities.comparison import FlextLdapUtilitiesComparison
    from flext_ldap._utilities.conversion import FlextLdapUtilitiesConversion
    from flext_ldap._utilities.detection import FlextLdapUtilitiesDetection
    from flext_ldap._utilities.normalization import FlextLdapUtilitiesNormalization
    from flext_ldap._utilities.root_dse import FlextLdapUtilitiesRootDse
    from flext_ldap._utilities.server import FlextLdapUtilitiesServer
    from flext_ldap._utilities.validation import FlextLdapUtilitiesValidation


__all__: tuple[str, ...] = (
    "FlextLdapUtilitiesComparison",
    "FlextLdapUtilitiesConversion",
    "FlextLdapUtilitiesDetection",
    "FlextLdapUtilitiesNormalization",
    "FlextLdapUtilitiesRootDse",
    "FlextLdapUtilitiesServer",
    "FlextLdapUtilitiesValidation",
)

_LAZY_IMPORTS = MappingProxyType(
    build_lazy_import_map(
        MappingProxyType({
            ".comparison": ("FlextLdapUtilitiesComparison",),
            ".conversion": ("FlextLdapUtilitiesConversion",),
            ".detection": ("FlextLdapUtilitiesDetection",),
            ".normalization": ("FlextLdapUtilitiesNormalization",),
            ".root_dse": ("FlextLdapUtilitiesRootDse",),
            ".server": ("FlextLdapUtilitiesServer",),
            ".validation": ("FlextLdapUtilitiesValidation",),
        }),
        alias_groups=MappingProxyType({}),
        sort_keys=False,
    ),
)

install_lazy_exports(__name__, globals(), _LAZY_IMPORTS, public_exports=__all__)
