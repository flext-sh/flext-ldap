# @generated AUTO-GENERATED FILE — Regenerate with: make gen
"""Flext Ldap.services package."""

from __future__ import annotations

from typing import TYPE_CHECKING

from flext_core.lazy import build_lazy_import_map, install_lazy_exports

if TYPE_CHECKING:
    from .api_runtime import FlextLdapApiRuntime as FlextLdapApiRuntime
    from .connection import FlextLdapConnection as FlextLdapConnection
    from .detection import FlextLdapServerDetector as FlextLdapServerDetector
    from .operations import FlextLdapOperations as FlextLdapOperations
    from .sync import FlextLdapSync as FlextLdapSync

_LAZY_MODULES: dict[str, tuple[str, ...]] = {
    ".api_runtime": ("FlextLdapApiRuntime",),
    ".connection": ("FlextLdapConnection",),
    ".detection": ("FlextLdapServerDetector",),
    ".operations": ("FlextLdapOperations",),
    ".sync": ("FlextLdapSync",),
}


_LAZY_ALIAS_GROUPS: dict[str, tuple[tuple[str, str], ...]] = {}


_LAZY_IMPORTS = build_lazy_import_map(
    _LAZY_MODULES, alias_groups=_LAZY_ALIAS_GROUPS, sort_keys=False
)

_PUBLIC_EXPORTS: tuple[str, ...] = (
    "FlextLdapApiRuntime",
    "FlextLdapConnection",
    "FlextLdapOperations",
    "FlextLdapServerDetector",
    "FlextLdapSync",
)

__all__: tuple[str, ...] = tuple(_PUBLIC_EXPORTS)

install_lazy_exports(__name__, globals(), _LAZY_IMPORTS, public_exports=__all__)
