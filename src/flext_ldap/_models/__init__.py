# AUTO-GENERATED FILE — DO NOT EDIT MANUALLY.
# Regenerate with: make gen
#
"""FlextLdap internal models package.

This package contains the actual model implementations.
The public models.py facade imports and exposes these.

NOTE: Collections is inherited from FlextModels - no custom implementation needed.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import TYPE_CHECKING

from flext_core.lazy import install_lazy_exports

if TYPE_CHECKING:
    from flext_ldap._models import ldap as ldap
    from flext_ldap._models.ldap import FlextLdapModelsLdap as FlextLdapModelsLdap

_LAZY_IMPORTS: Mapping[str, Sequence[str]] = {
    "FlextLdapModelsLdap": ["flext_ldap._models.ldap", "FlextLdapModelsLdap"],
    "ldap": ["flext_ldap._models.ldap", ""],
}

_EXPORTS: Sequence[str] = [
    "FlextLdapModelsLdap",
    "ldap",
]


install_lazy_exports(__name__, globals(), _LAZY_IMPORTS, _EXPORTS)
