"""FLEXT-LDAP - LDAP Client Library.

LDAP client library with RFC compliance and server-specific quirks
for the FLEXT ecosystem. Reuses flext-ldif for Entry models and parsing.

Single Entry Point Architecture:
    This module enforces a single entry point pattern. ALL LDAP operations must
    go through the FlextLdap class. Internal modules (adapters, services) are
    NOT part of the public API and should not be imported directly by consumers.

    Correct usage:
        from flext_ldap import FlextLdap
        ldap = FlextLdap()
        result = ldap.search(options)

    Incorrect usage (bypasses single entry point):
        from flext_ldap import FlextLdapConnection  # ❌ WRONG
        from flext_ldap import Ldap3Adapter  # ❌ WRONG

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

from typing import TYPE_CHECKING

from flext_core import cleanup_submodule_namespace, lazy_getattr

if TYPE_CHECKING:
    from flext_core import (
        FlextDecorators as d,
        FlextExceptions as e,
        FlextHandlers as h,
        r,
        x,
    )

    from flext_ldap import (
        FlextLdap,
        FlextLdapConnection,
        FlextLdapConstants,
        FlextLdapConstants as c,
        FlextLdapModels,
        FlextLdapModels as m,
        FlextLdapOperations,
        FlextLdapProtocols,
        FlextLdapProtocols as p,
        FlextLdapServerDetector,
        FlextLdapServiceBase,
        FlextLdapSettings,
        FlextLdapTypes,
        FlextLdapTypes as t,
        FlextLdapUtilities,
        FlextLdapUtilities as u,
        s,
    )

# Lazy import mapping: export_name -> (module_path, attr_name)
_LAZY_IMPORTS: dict[str, tuple[str, str]] = {
    "FlextLdap": ("flext_ldap.api", "FlextLdap"),
    "FlextLdapConnection": ("flext_ldap.services.connection", "FlextLdapConnection"),
    "FlextLdapConstants": ("flext_ldap.constants", "FlextLdapConstants"),
    "FlextLdapModels": ("flext_ldap.models", "FlextLdapModels"),
    "FlextLdapOperations": ("flext_ldap.services.operations", "FlextLdapOperations"),
    "FlextLdapProtocols": ("flext_ldap.protocols", "FlextLdapProtocols"),
    "FlextLdapServerDetector": (
        "flext_ldap.services.detection",
        "FlextLdapServerDetector",
    ),
    "FlextLdapServiceBase": ("flext_ldap.base", "FlextLdapServiceBase"),
    "FlextLdapSettings": ("flext_ldap.settings", "FlextLdapSettings"),
    "FlextLdapTypes": ("flext_ldap.typings", "FlextLdapTypes"),
    "FlextLdapUtilities": ("flext_ldap.utilities", "FlextLdapUtilities"),
    "c": ("flext_ldap.constants", "FlextLdapConstants"),
    "d": ("flext_core", "FlextDecorators"),
    "e": ("flext_core", "FlextExceptions"),
    "h": ("flext_core", "FlextHandlers"),
    "m": ("flext_ldap.models", "FlextLdapModels"),
    "p": ("flext_ldap.protocols", "FlextLdapProtocols"),
    "r": ("flext_core", "r"),
    "s": ("flext_ldap.base", "s"),
    "t": ("flext_ldap.typings", "FlextLdapTypes"),
    "u": ("flext_ldap.utilities", "FlextLdapUtilities"),
    "x": ("flext_core", "x"),
}

__all__ = [
    "FlextLdap",
    "FlextLdapConnection",
    "FlextLdapConstants",
    "FlextLdapModels",
    "FlextLdapOperations",
    "FlextLdapProtocols",
    "FlextLdapServerDetector",
    "FlextLdapServiceBase",
    "FlextLdapSettings",
    "FlextLdapTypes",
    "FlextLdapUtilities",
    "c",
    "d",
    "e",
    "h",
    "m",
    "p",
    "r",
    "s",
    "t",
    "u",
    "x",
]


def __getattr__(name: str) -> t.GeneralValueType:
    """Lazy-load module attributes on first access (PEP 562)."""
    return lazy_getattr(name, _LAZY_IMPORTS, globals(), __name__)


def __dir__() -> list[str]:
    """Return list of available attributes for dir() and autocomplete."""
    return sorted(__all__)


cleanup_submodule_namespace(__name__, _LAZY_IMPORTS)
