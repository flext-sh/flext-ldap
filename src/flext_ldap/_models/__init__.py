# AUTO-GENERATED FILE — Regenerate with: make gen
"""Models package."""

from __future__ import annotations

from typing import TYPE_CHECKING

from flext_core.lazy import build_lazy_import_map, install_lazy_exports

if TYPE_CHECKING:
    from flext_ldap._models.ldap import FlextLdapModelsLdap as FlextLdapModelsLdap
_LAZY_IMPORTS = build_lazy_import_map(
    {
        ".ldap": ("FlextLdapModelsLdap",),
    },
)


install_lazy_exports(
    __name__,
    globals(),
    _LAZY_IMPORTS,
    publish_all=False,
)
