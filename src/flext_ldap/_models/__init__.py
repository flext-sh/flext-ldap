# AUTO-GENERATED FILE — DO NOT EDIT MANUALLY.
# Regenerate with: make gen
#
"""Models package."""

from __future__ import annotations

import typing as _t

from flext_core.lazy import install_lazy_exports

if _t.TYPE_CHECKING:
    import flext_ldap._models.ldap as _flext_ldap__models_ldap

    ldap = _flext_ldap__models_ldap
    from flext_ldap._models.ldap import FlextLdapModelsLdap
_LAZY_IMPORTS = {
    "FlextLdapModelsLdap": ("flext_ldap._models.ldap", "FlextLdapModelsLdap"),
    "ldap": "flext_ldap._models.ldap",
}

__all__ = [
    "FlextLdapModelsLdap",
    "ldap",
]


install_lazy_exports(__name__, globals(), _LAZY_IMPORTS)
