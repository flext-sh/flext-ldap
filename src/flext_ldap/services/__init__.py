"""LDAP services package.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

from typing import TYPE_CHECKING

from flext_core.lazy import cleanup_submodule_namespace, lazy_getattr

if TYPE_CHECKING:
    from flext_ldap.services.connection import FlextLdapConnection
    from flext_ldap.services.detection import FlextLdapServerDetector
    from flext_ldap.services.operations import FlextLdapOperations
    from flext_ldap.services.sync import FlextLdapSyncService

# Lazy import mapping: export_name -> (module_path, attr_name)
_LAZY_IMPORTS: dict[str, tuple[str, str]] = {
    "FlextLdapConnection": ("flext_ldap.services.connection", "FlextLdapConnection"),
    "FlextLdapOperations": ("flext_ldap.services.operations", "FlextLdapOperations"),
    "FlextLdapServerDetector": (
        "flext_ldap.services.detection",
        "FlextLdapServerDetector",
    ),
    "FlextLdapSyncService": ("flext_ldap.services.sync", "FlextLdapSyncService"),
}

__all__ = [
    "FlextLdapConnection",
    "FlextLdapOperations",
    "FlextLdapServerDetector",
    "FlextLdapSyncService",
]


def __getattr__(name: str) -> t.GeneralValueType:
    """Lazy-load module attributes on first access (PEP 562)."""
    return lazy_getattr(name, _LAZY_IMPORTS, globals(), __name__)


def __dir__() -> list[str]:
    """Return list of available attributes for dir() and autocomplete."""
    return sorted(__all__)


cleanup_submodule_namespace(__name__, _LAZY_IMPORTS)
