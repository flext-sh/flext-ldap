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

from typing import TYPE_CHECKING, Any

from flext_core import cleanup_submodule_namespace, lazy_getattr

if TYPE_CHECKING:
    from flext_core import (
        FlextDecorators as d,
        FlextExceptions as e,
        FlextHandlers as h,
        r,
        x,
    )

    from flext_ldap.api import FlextLdap
    from flext_ldap.base import FlextLdapServiceBase, s
    from flext_ldap.constants import FlextLdapConstants, FlextLdapConstants as c
    from flext_ldap.models import FlextLdapModels, FlextLdapModels as m
    from flext_ldap.protocols import FlextLdapProtocols, FlextLdapProtocols as p
    from flext_ldap.services.connection import FlextLdapConnection
    from flext_ldap.services.detection import FlextLdapServerDetector
    from flext_ldap.services.operations import FlextLdapOperations
    from flext_ldap.services.sync import FlextLdapSyncService
    from flext_ldap.settings import FlextLdapSettings
    from flext_ldap.typings import FlextLdapTypes, FlextLdapTypes as t
    from flext_ldap.utilities import FlextLdapUtilities, FlextLdapUtilities as u
    from flext_ldap.api import MULTI_PHASE_CALLBACK_PARAM_COUNT
    from flext_ldap.api import SINGLE_PHASE_CALLBACK_PARAM_COUNT

# Lazy import mapping: export_name -> (module_path, attr_name)
_LAZY_IMPORTS: dict[str, tuple[str, str]] = {
    "FlextLdap": ("flext_ldap.api", "FlextLdap"),
    "FlextLdapConnection": ("flext_ldap.services.connection", "FlextLdapConnection"),
    "FlextLdapConstants": ("flext_ldap.constants", "FlextLdapConstants"),
    "FlextLdapModels": ("flext_ldap.models", "FlextLdapModels"),
    "FlextLdapOperations": ("flext_ldap.services.operations", "FlextLdapOperations"),
    "FlextLdapProtocols": ("flext_ldap.protocols", "FlextLdapProtocols"),
    "FlextLdapServerDetector": ("flext_ldap.services.detection", "FlextLdapServerDetector"),
    "FlextLdapServiceBase": ("flext_ldap.base", "FlextLdapServiceBase"),
    "FlextLdapSyncService": ("flext_ldap.services.sync", "FlextLdapSyncService"),
    "FlextLdapSyncCallbacks": ("flext_ldap.api", "FlextLdapSyncCallbacks"),
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
    "MULTI_PHASE_CALLBACK_PARAM_COUNT": ("flext_ldap.api", "MULTI_PHASE_CALLBACK_PARAM_COUNT"),
    "SINGLE_PHASE_CALLBACK_PARAM_COUNT": ("flext_ldap.api", "SINGLE_PHASE_CALLBACK_PARAM_COUNT"),
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
    "FlextLdapSyncService",
    "FlextLdapSyncCallbacks",
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
    "MULTI_PHASE_CALLBACK_PARAM_COUNT",
    "SINGLE_PHASE_CALLBACK_PARAM_COUNT",
]


def __getattr__(name: str) -> Any:  # noqa: ANN401
    """Lazy-load module attributes on first access (PEP 562)."""
    return lazy_getattr(name, _LAZY_IMPORTS, globals(), __name__)


def __dir__() -> list[str]:
    """Return list of available attributes for dir() and autocomplete."""
    return sorted(__all__)


cleanup_submodule_namespace(__name__, _LAZY_IMPORTS)
