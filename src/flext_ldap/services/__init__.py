# AUTO-GENERATED FILE — DO NOT EDIT MANUALLY.
# Regenerate with: make gen
#
"""LDAP services package.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

from collections.abc import Mapping, MutableMapping, Sequence
from typing import TYPE_CHECKING

from flext_core.lazy import cleanup_submodule_namespace, lazy_getattr

if TYPE_CHECKING:
    from flext_core import FlextTypes

    from flext_ldap.services import connection, detection, operations, sync
    from flext_ldap.services.connection import FlextLdapConnection
    from flext_ldap.services.detection import FlextLdapServerDetector
    from flext_ldap.services.operations import FlextLdapOperations
    from flext_ldap.services.sync import FlextLdapSync, FlextLdapSyncCallbacks

_LAZY_IMPORTS: Mapping[str, Sequence[str]] = {
    "FlextLdapConnection": ["flext_ldap.services.connection", "FlextLdapConnection"],
    "FlextLdapOperations": ["flext_ldap.services.operations", "FlextLdapOperations"],
    "FlextLdapServerDetector": [
        "flext_ldap.services.detection",
        "FlextLdapServerDetector",
    ],
    "FlextLdapSync": ["flext_ldap.services.sync", "FlextLdapSync"],
    "FlextLdapSyncCallbacks": ["flext_ldap.services.sync", "FlextLdapSyncCallbacks"],
    "connection": ["flext_ldap.services.connection", ""],
    "detection": ["flext_ldap.services.detection", ""],
    "operations": ["flext_ldap.services.operations", ""],
    "sync": ["flext_ldap.services.sync", ""],
}

__all__ = [
    "FlextLdapConnection",
    "FlextLdapOperations",
    "FlextLdapServerDetector",
    "FlextLdapSync",
    "FlextLdapSyncCallbacks",
    "connection",
    "detection",
    "operations",
    "sync",
]


_LAZY_CACHE: MutableMapping[str, FlextTypes.ModuleExport] = {}


def __getattr__(name: str) -> FlextTypes.ModuleExport:
    """Lazy-load module attributes on first access (PEP 562).

    A local cache ``_LAZY_CACHE`` persists resolved objects across repeated
    accesses during process lifetime.

    Args:
        name: Attribute name requested by dir()/import.

    Returns:
        Lazy-loaded module export type.

    Raises:
        AttributeError: If attribute not registered.

    """
    if name in _LAZY_CACHE:
        return _LAZY_CACHE[name]

    value = lazy_getattr(name, _LAZY_IMPORTS, globals(), __name__)
    _LAZY_CACHE[name] = value
    return value


def __dir__() -> Sequence[str]:
    """Return list of available attributes for dir() and autocomplete.

    Returns:
        List of public names from module exports.

    """
    return sorted(__all__)


cleanup_submodule_namespace(__name__, _LAZY_IMPORTS)
