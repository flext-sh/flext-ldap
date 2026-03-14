# AUTO-GENERATED FILE — DO NOT EDIT MANUALLY.
# Regenerate with: make codegen
#
"""LDAP adapters package.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

from typing import TYPE_CHECKING

from flext_core.lazy import cleanup_submodule_namespace, lazy_getattr

if TYPE_CHECKING:
    from flext_core.typings import FlextTypes

    from flext_ldap.adapters.entry import FlextLdapEntryAdapter
    from flext_ldap.adapters.ldap3 import (
        FlextLdapLdap3Wrappers,
        Ldap3Adapter,
        LdifEntry,
    )

# Lazy import mapping: export_name -> (module_path, attr_name)
_LAZY_IMPORTS: dict[str, tuple[str, str]] = {
    "FlextLdapEntryAdapter": ("flext_ldap.adapters.entry", "FlextLdapEntryAdapter"),
    "FlextLdapLdap3Wrappers": ("flext_ldap.adapters.ldap3", "FlextLdapLdap3Wrappers"),
    "Ldap3Adapter": ("flext_ldap.adapters.ldap3", "Ldap3Adapter"),
    "LdifEntry": ("flext_ldap.adapters.ldap3", "LdifEntry"),
}

__all__ = [
    "FlextLdapEntryAdapter",
    "FlextLdapLdap3Wrappers",
    "Ldap3Adapter",
    "LdifEntry",
]


def __getattr__(name: str) -> FlextTypes.ModuleExport:
    """Lazy-load module attributes on first access (PEP 562)."""
    return lazy_getattr(name, _LAZY_IMPORTS, globals(), __name__)


def __dir__() -> list[str]:
    """Return list of available attributes for dir() and autocomplete."""
    return sorted(__all__)


cleanup_submodule_namespace(__name__, _LAZY_IMPORTS)
