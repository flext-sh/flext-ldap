# @generated AUTO-GENERATED FILE — Regenerate with: make gen
"""Flext Ldap. Utilities package."""

from __future__ import annotations

from typing import TYPE_CHECKING

from flext_core.lazy import build_lazy_import_map, install_lazy_exports

if TYPE_CHECKING:
    from .comparison import FlextLdapUtilitiesComparison as FlextLdapUtilitiesComparison
    from .conversion import FlextLdapUtilitiesConversion as FlextLdapUtilitiesConversion
    from .detection import FlextLdapUtilitiesDetection as FlextLdapUtilitiesDetection
    from .normalization import (
        FlextLdapUtilitiesNormalization as FlextLdapUtilitiesNormalization,
    )
    from .root_dse import FlextLdapUtilitiesRootDse as FlextLdapUtilitiesRootDse
    from .server import FlextLdapUtilitiesServer as FlextLdapUtilitiesServer
    from .validation import FlextLdapUtilitiesValidation as FlextLdapUtilitiesValidation

_LAZY_MODULES: dict[str, tuple[str, ...]] = {
    ".comparison": ("FlextLdapUtilitiesComparison",),
    ".conversion": ("FlextLdapUtilitiesConversion",),
    ".detection": ("FlextLdapUtilitiesDetection",),
    ".normalization": ("FlextLdapUtilitiesNormalization",),
    ".root_dse": ("FlextLdapUtilitiesRootDse",),
    ".server": ("FlextLdapUtilitiesServer",),
    ".validation": ("FlextLdapUtilitiesValidation",),
}


_LAZY_ALIAS_GROUPS: dict[str, tuple[tuple[str, str], ...]] = {}


_LAZY_IMPORTS = build_lazy_import_map(
    _LAZY_MODULES, alias_groups=_LAZY_ALIAS_GROUPS, sort_keys=False
)

_PUBLIC_EXPORTS: tuple[str, ...] = (
    "FlextLdapUtilitiesComparison",
    "FlextLdapUtilitiesConversion",
    "FlextLdapUtilitiesDetection",
    "FlextLdapUtilitiesNormalization",
    "FlextLdapUtilitiesRootDse",
    "FlextLdapUtilitiesServer",
    "FlextLdapUtilitiesValidation",
)

__all__: tuple[str, ...] = tuple(_PUBLIC_EXPORTS)

install_lazy_exports(__name__, globals(), _LAZY_IMPORTS, public_exports=__all__)
