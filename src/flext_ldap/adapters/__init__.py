"""LDAP adapters package.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from flext_core.lazy import cleanup_submodule_namespace, lazy_getattr

if TYPE_CHECKING:
    from flext_ldap.adapters.entry import FlextLdapEntryAdapter
    from flext_ldap.adapters.ldap3 import Ldap3Adapter

# Lazy import mapping: export_name -> (module_path, attr_name)
_LAZY_IMPORTS: dict[str, tuple[str, str]] = {
    "FlextLdapEntryAdapter": ("flext_ldap.adapters.entry", "FlextLdapEntryAdapter"),
    "Ldap3Adapter": ("flext_ldap.adapters.ldap3", "Ldap3Adapter"),
}

__all__ = [
    "FlextLdapEntryAdapter",
    "Ldap3Adapter",
]


def __getattr__(name: str) -> Any:  # noqa: ANN401  # JUSTIFIED: Ruff (any-type) with PEP 562 dynamic module exports — https://docs.astral.sh/ruff/rules/any-type/
    """Lazy-load module attributes on first access (PEP 562)."""
    return lazy_getattr(name, _LAZY_IMPORTS, globals(), __name__)


def __dir__() -> list[str]:
    """Return list of available attributes for dir() and autocomplete."""
    return sorted(__all__)


cleanup_submodule_namespace(__name__, _LAZY_IMPORTS)
