# AUTO-GENERATED FILE — DO NOT EDIT MANUALLY.
# Regenerate with: make gen
#
"""Models package."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import TYPE_CHECKING as _TYPE_CHECKING

from flext_core.lazy import install_lazy_exports

if _TYPE_CHECKING:
    from flext_core import FlextTypes
    from flext_ldap._models import ldap
    from flext_ldap._models.ldap import FlextLdapModelsLdap

_LAZY_IMPORTS: FlextTypes.LazyImportIndex = {
    "FlextLdapModelsLdap": "flext_ldap._models.ldap",
    "ldap": "flext_ldap._models.ldap",
}


install_lazy_exports(__name__, globals(), _LAZY_IMPORTS)
