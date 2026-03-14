# AUTO-GENERATED FILE — DO NOT EDIT MANUALLY.
# Regenerate with: make codegen
#
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

from flext_core.lazy import cleanup_submodule_namespace, lazy_getattr

if TYPE_CHECKING:
    from flext_core.typings import FlextTypes

    from flext_ldap.__version__ import __all__
    from flext_ldap._models.ldap import FlextLdapModelsLdap
    from flext_ldap.adapters.entry import FlextLdapEntryAdapter
    from flext_ldap.adapters.ldap3 import (
        FlextLdapLdap3Wrappers,
        Ldap3Adapter,
        LdifEntry,
    )
    from flext_ldap.api import (
        MULTI_PHASE_CALLBACK_PARAM_COUNT,
        SINGLE_PHASE_CALLBACK_PARAM_COUNT,
        FlextLdap,
        FlextLdapSyncCallbacks,
    )
    from flext_ldap.base import FlextLdapServiceBase, s
    from flext_ldap.constants import FlextLdapConstants, c
    from flext_ldap.models import FlextLdapModels, m
    from flext_ldap.protocols import FlextLdapProtocols, p
    from flext_ldap.services.connection import FlextLdapConnection
    from flext_ldap.services.detection import FlextLdapServerDetector
    from flext_ldap.services.operations import FlextLdapOperations, LaxStr
    from flext_ldap.services.sync import FlextLdapSyncService
    from flext_ldap.settings import FlextLdapSettings
    from flext_ldap.typings import (
        FlextLdapTypes,
        LdapEntryContract,
        SearchOptionsContract,
        t,
    )
    from flext_ldap.utilities import FlextLdapUtilities, u

# Lazy import mapping: export_name -> (module_path, attr_name)
_LAZY_IMPORTS: dict[str, tuple[str, str]] = {
    "FlextLdap": ("flext_ldap.api", "FlextLdap"),
    "FlextLdapConnection": ("flext_ldap.services.connection", "FlextLdapConnection"),
    "FlextLdapConstants": ("flext_ldap.constants", "FlextLdapConstants"),
    "FlextLdapEntryAdapter": ("flext_ldap.adapters.entry", "FlextLdapEntryAdapter"),
    "FlextLdapLdap3Wrappers": ("flext_ldap.adapters.ldap3", "FlextLdapLdap3Wrappers"),
    "FlextLdapModels": ("flext_ldap.models", "FlextLdapModels"),
    "FlextLdapModelsLdap": ("flext_ldap._models.ldap", "FlextLdapModelsLdap"),
    "FlextLdapOperations": ("flext_ldap.services.operations", "FlextLdapOperations"),
    "FlextLdapProtocols": ("flext_ldap.protocols", "FlextLdapProtocols"),
    "FlextLdapServerDetector": ("flext_ldap.services.detection", "FlextLdapServerDetector"),
    "FlextLdapServiceBase": ("flext_ldap.base", "FlextLdapServiceBase"),
    "FlextLdapSettings": ("flext_ldap.settings", "FlextLdapSettings"),
    "FlextLdapSyncCallbacks": ("flext_ldap.api", "FlextLdapSyncCallbacks"),
    "FlextLdapSyncService": ("flext_ldap.services.sync", "FlextLdapSyncService"),
    "FlextLdapTypes": ("flext_ldap.typings", "FlextLdapTypes"),
    "FlextLdapUtilities": ("flext_ldap.utilities", "FlextLdapUtilities"),
    "LaxStr": ("flext_ldap.services.operations", "LaxStr"),
    "Ldap3Adapter": ("flext_ldap.adapters.ldap3", "Ldap3Adapter"),
    "LdapEntryContract": ("flext_ldap.typings", "LdapEntryContract"),
    "LdifEntry": ("flext_ldap.adapters.ldap3", "LdifEntry"),
    "MULTI_PHASE_CALLBACK_PARAM_COUNT": ("flext_ldap.api", "MULTI_PHASE_CALLBACK_PARAM_COUNT"),
    "SINGLE_PHASE_CALLBACK_PARAM_COUNT": ("flext_ldap.api", "SINGLE_PHASE_CALLBACK_PARAM_COUNT"),
    "SearchOptionsContract": ("flext_ldap.typings", "SearchOptionsContract"),
    "__all__": ("flext_ldap.__version__", "__all__"),
    "c": ("flext_ldap.constants", "c"),
    "m": ("flext_ldap.models", "m"),
    "p": ("flext_ldap.protocols", "p"),
    "s": ("flext_ldap.base", "s"),
    "t": ("flext_ldap.typings", "t"),
    "u": ("flext_ldap.utilities", "u"),
}

__all__ = [
    "MULTI_PHASE_CALLBACK_PARAM_COUNT",
    "SINGLE_PHASE_CALLBACK_PARAM_COUNT",
    "FlextLdap",
    "FlextLdapConnection",
    "FlextLdapConstants",
    "FlextLdapEntryAdapter",
    "FlextLdapLdap3Wrappers",
    "FlextLdapModels",
    "FlextLdapModelsLdap",
    "FlextLdapOperations",
    "FlextLdapProtocols",
    "FlextLdapServerDetector",
    "FlextLdapServiceBase",
    "FlextLdapSettings",
    "FlextLdapSyncCallbacks",
    "FlextLdapSyncService",
    "FlextLdapTypes",
    "FlextLdapUtilities",
    "LaxStr",
    "Ldap3Adapter",
    "LdapEntryContract",
    "LdifEntry",
    "SearchOptionsContract",
    "__all__",
    "c",
    "m",
    "p",
    "s",
    "t",
    "u",
]


def __getattr__(name: str) -> FlextTypes.ModuleExport:
    """Lazy-load module attributes on first access (PEP 562)."""
    return lazy_getattr(name, _LAZY_IMPORTS, globals(), __name__)


def __dir__() -> list[str]:
    """Return list of available attributes for dir() and autocomplete."""
    return sorted(__all__)


cleanup_submodule_namespace(__name__, _LAZY_IMPORTS)
