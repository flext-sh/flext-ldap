# AUTO-GENERATED FILE — DO NOT EDIT MANUALLY.
# Regenerate with: make gen
#
"""Flext ldap package."""

from __future__ import annotations

from collections.abc import Mapping, MutableMapping, Sequence
from typing import TYPE_CHECKING

from flext_core.lazy import cleanup_submodule_namespace, lazy_getattr

from flext_ldap.__version__ import (
    __author__,
    __author_email__,
    __description__,
    __license__,
    __title__,
    __url__,
    __version__,
    __version_info__,
)
from flext_ldap.typings import FlextLdapDomainResultT, FlextLdapEntryT

if TYPE_CHECKING:
    from flext_core import FlextTypes
    from flext_ldif import d, e, h, r, x

    from flext_ldap import (
        _models,
        adapters,
        api,
        base,
        constants,
        models,
        protocols,
        services,
        settings,
        typings,
        utilities,
    )
    from flext_ldap._models.ldap import FlextLdapModelsLdap
    from flext_ldap.adapters import entry, ldap3
    from flext_ldap.adapters.entry import FlextLdapEntryAdapter
    from flext_ldap.adapters.ldap3 import FlextLdapLdap3Adapter, FlextLdapLdap3Wrappers
    from flext_ldap.api import FlextLdap, ldap
    from flext_ldap.base import FlextLdapServiceBase, s
    from flext_ldap.constants import FlextLdapConstants, FlextLdapConstants as c
    from flext_ldap.models import FlextLdapModels, FlextLdapModels as m
    from flext_ldap.protocols import FlextLdapProtocols, FlextLdapProtocols as p
    from flext_ldap.services import connection, detection, operations, sync
    from flext_ldap.services.connection import FlextLdapConnection
    from flext_ldap.services.detection import FlextLdapServerDetector
    from flext_ldap.services.operations import FlextLdapOperations
    from flext_ldap.services.sync import FlextLdapSync, FlextLdapSyncCallbacks
    from flext_ldap.settings import FlextLdapSettings
    from flext_ldap.typings import FlextLdapTypes, FlextLdapTypes as t
    from flext_ldap.utilities import FlextLdapUtilities, FlextLdapUtilities as u

_LAZY_IMPORTS: Mapping[str, Sequence[str]] = {
    "FlextLdap": ["flext_ldap.api", "FlextLdap"],
    "FlextLdapConnection": ["flext_ldap.services.connection", "FlextLdapConnection"],
    "FlextLdapConstants": ["flext_ldap.constants", "FlextLdapConstants"],
    "FlextLdapEntryAdapter": ["flext_ldap.adapters.entry", "FlextLdapEntryAdapter"],
    "FlextLdapLdap3Adapter": ["flext_ldap.adapters.ldap3", "FlextLdapLdap3Adapter"],
    "FlextLdapLdap3Wrappers": ["flext_ldap.adapters.ldap3", "FlextLdapLdap3Wrappers"],
    "FlextLdapModels": ["flext_ldap.models", "FlextLdapModels"],
    "FlextLdapModelsLdap": ["flext_ldap._models.ldap", "FlextLdapModelsLdap"],
    "FlextLdapOperations": ["flext_ldap.services.operations", "FlextLdapOperations"],
    "FlextLdapProtocols": ["flext_ldap.protocols", "FlextLdapProtocols"],
    "FlextLdapServerDetector": [
        "flext_ldap.services.detection",
        "FlextLdapServerDetector",
    ],
    "FlextLdapServiceBase": ["flext_ldap.base", "FlextLdapServiceBase"],
    "FlextLdapSettings": ["flext_ldap.settings", "FlextLdapSettings"],
    "FlextLdapSync": ["flext_ldap.services.sync", "FlextLdapSync"],
    "FlextLdapSyncCallbacks": ["flext_ldap.services.sync", "FlextLdapSyncCallbacks"],
    "FlextLdapTypes": ["flext_ldap.typings", "FlextLdapTypes"],
    "FlextLdapUtilities": ["flext_ldap.utilities", "FlextLdapUtilities"],
    "_models": ["flext_ldap._models", ""],
    "adapters": ["flext_ldap.adapters", ""],
    "api": ["flext_ldap.api", ""],
    "base": ["flext_ldap.base", ""],
    "c": ["flext_ldap.constants", "FlextLdapConstants"],
    "connection": ["flext_ldap.services.connection", ""],
    "constants": ["flext_ldap.constants", ""],
    "d": ["flext_ldif", "d"],
    "detection": ["flext_ldap.services.detection", ""],
    "e": ["flext_ldif", "e"],
    "entry": ["flext_ldap.adapters.entry", ""],
    "h": ["flext_ldif", "h"],
    "ldap": ["flext_ldap.api", "ldap"],
    "ldap3": ["flext_ldap.adapters.ldap3", ""],
    "m": ["flext_ldap.models", "FlextLdapModels"],
    "models": ["flext_ldap.models", ""],
    "operations": ["flext_ldap.services.operations", ""],
    "p": ["flext_ldap.protocols", "FlextLdapProtocols"],
    "protocols": ["flext_ldap.protocols", ""],
    "r": ["flext_ldif", "r"],
    "s": ["flext_ldap.base", "s"],
    "services": ["flext_ldap.services", ""],
    "settings": ["flext_ldap.settings", ""],
    "sync": ["flext_ldap.services.sync", ""],
    "t": ["flext_ldap.typings", "FlextLdapTypes"],
    "typings": ["flext_ldap.typings", ""],
    "u": ["flext_ldap.utilities", "FlextLdapUtilities"],
    "utilities": ["flext_ldap.utilities", ""],
    "x": ["flext_ldif", "x"],
}

__all__ = [
    "FlextLdap",
    "FlextLdapConnection",
    "FlextLdapConstants",
    "FlextLdapDomainResultT",
    "FlextLdapEntryAdapter",
    "FlextLdapEntryT",
    "FlextLdapLdap3Adapter",
    "FlextLdapLdap3Wrappers",
    "FlextLdapModels",
    "FlextLdapModelsLdap",
    "FlextLdapOperations",
    "FlextLdapProtocols",
    "FlextLdapServerDetector",
    "FlextLdapServiceBase",
    "FlextLdapSettings",
    "FlextLdapSync",
    "FlextLdapSyncCallbacks",
    "FlextLdapTypes",
    "FlextLdapUtilities",
    "__author__",
    "__author_email__",
    "__description__",
    "__license__",
    "__title__",
    "__url__",
    "__version__",
    "__version_info__",
    "_models",
    "adapters",
    "api",
    "base",
    "c",
    "connection",
    "constants",
    "d",
    "detection",
    "e",
    "entry",
    "h",
    "ldap",
    "ldap3",
    "m",
    "models",
    "operations",
    "p",
    "protocols",
    "r",
    "s",
    "services",
    "settings",
    "sync",
    "t",
    "typings",
    "u",
    "utilities",
    "x",
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
