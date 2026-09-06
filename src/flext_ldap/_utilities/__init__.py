# AUTO-GENERATED FILE — Regenerate with: make gen
"""Flext Ldap. Utilities package."""

from __future__ import annotations

from typing import TYPE_CHECKING

from types import MappingProxyType

from flext_core.lazy import build_lazy_import_map, install_lazy_exports

if TYPE_CHECKING:
    from .comparison import FlextLdapUtilitiesComparison
    from .conversion import FlextLdapUtilitiesConversion
    from .detection import FlextLdapUtilitiesDetection
    from .normalization import FlextLdapUtilitiesNormalization
    from .root_dse import FlextLdapUtilitiesRootDse
    from .server import FlextLdapUtilitiesServer
    from .validation import FlextLdapUtilitiesValidation
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
    )
)

install_lazy_exports(__name__, globals(), _LAZY_IMPORTS, public_exports=__all__)
