# AUTO-GENERATED FILE — Regenerate with: make gen
"""Flext Ldap.services package."""

from __future__ import annotations

from typing import TYPE_CHECKING

from types import MappingProxyType

from flext_core.lazy import build_lazy_import_map, install_lazy_exports

if TYPE_CHECKING:
    from .api_runtime import FlextLdapApiRuntime
    from .sync import FlextLdapSync
__all__: tuple[str, ...] = ("FlextLdapApiRuntime", "FlextLdapSync")

_LAZY_IMPORTS = MappingProxyType(
    build_lazy_import_map(
        MappingProxyType({
            ".api_runtime": ("FlextLdapApiRuntime",),
            ".sync": ("FlextLdapSync",),
        }),
        alias_groups=MappingProxyType({}),
        sort_keys=False,
    )
)

install_lazy_exports(__name__, globals(), _LAZY_IMPORTS, public_exports=__all__)
