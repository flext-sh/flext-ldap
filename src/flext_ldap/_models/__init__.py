# AUTO-GENERATED FILE — Regenerate with: make gen
"""Flext Ldap. Models package."""

from __future__ import annotations

from typing import TYPE_CHECKING

from types import MappingProxyType

from flext_core.lazy import build_lazy_import_map, install_lazy_exports

if TYPE_CHECKING:
    from .ldap import FlextLdapModelsLdap
__all__: tuple[str, ...] = ("FlextLdapModelsLdap",)

_LAZY_IMPORTS = MappingProxyType(
    build_lazy_import_map(
        MappingProxyType({".ldap": ("FlextLdapModelsLdap",)}),
        alias_groups=MappingProxyType({}),
        sort_keys=False,
    )
)

install_lazy_exports(__name__, globals(), _LAZY_IMPORTS, public_exports=__all__)
