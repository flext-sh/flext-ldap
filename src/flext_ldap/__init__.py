# AUTO-GENERATED FILE — Regenerate with: make gen
"""Flext Ldap package."""

from __future__ import annotations

import typing as _t

from flext_core.lazy import (
    build_lazy_import_map,
    install_lazy_exports,
    merge_lazy_imports,
)
from flext_ldap.__version__ import *

if _t.TYPE_CHECKING:
    from _models.ldap import FlextLdapModelsLdap

    from flext_core.decorators import d
    from flext_core.exceptions import e
    from flext_core.handlers import h
    from flext_core.mixins import x
    from flext_core.result import r
    from flext_ldap.api import FlextLdap, ldap
    from flext_ldap.base import FlextLdapServiceBase, s
    from flext_ldap.connection import FlextLdapConnection
    from flext_ldap.constants import FlextLdapConstants, c
    from flext_ldap.detection import FlextLdapServerDetector
    from flext_ldap.entry import FlextLdapEntryAdapter
    from flext_ldap.ldap3 import FlextLdapLdap3Adapter, FlextLdapLdap3Wrappers
    from flext_ldap.models import FlextLdapModels, m
    from flext_ldap.operations import FlextLdapOperations
    from flext_ldap.protocols import FlextLdapProtocols, p
    from flext_ldap.settings import FlextLdapSettings
    from flext_ldap.sync import FlextLdapSync, FlextLdapSyncCallbacks
    from flext_ldap.typings import FlextLdapTypes, t
    from flext_ldap.utilities import FlextLdapUtilities, u
_LAZY_IMPORTS = merge_lazy_imports(
    (
        "._models",
        ".adapters",
        ".services",
    ),
    build_lazy_import_map(
        {
            ".__version__": (
                "__author__",
                "__author_email__",
                "__description__",
                "__license__",
                "__title__",
                "__url__",
                "__version__",
                "__version_info__",
            ),
            ".api": (
                "FlextLdap",
                "ldap",
            ),
            ".base": (
                "FlextLdapServiceBase",
                "s",
            ),
            ".connection": ("FlextLdapConnection",),
            ".constants": (
                "FlextLdapConstants",
                "c",
            ),
            ".detection": ("FlextLdapServerDetector",),
            ".entry": ("FlextLdapEntryAdapter",),
            ".ldap3": (
                "FlextLdapLdap3Adapter",
                "FlextLdapLdap3Wrappers",
            ),
            ".models": (
                "FlextLdapModels",
                "m",
            ),
            ".operations": ("FlextLdapOperations",),
            ".protocols": (
                "FlextLdapProtocols",
                "p",
            ),
            ".settings": ("FlextLdapSettings",),
            ".sync": (
                "FlextLdapSync",
                "FlextLdapSyncCallbacks",
            ),
            ".typings": (
                "FlextLdapTypes",
                "t",
            ),
            ".utilities": (
                "FlextLdapUtilities",
                "u",
            ),
            "_models.ldap": ("FlextLdapModelsLdap",),
            "flext_core.decorators": ("d",),
            "flext_core.exceptions": ("e",),
            "flext_core.handlers": ("h",),
            "flext_core.mixins": ("x",),
            "flext_core.result": ("r",),
        },
    ),
    exclude_names=(
        "cleanup_submodule_namespace",
        "install_lazy_exports",
        "lazy_getattr",
        "logger",
        "merge_lazy_imports",
        "output",
        "output_reporting",
    ),
    module_name=__name__,
)


install_lazy_exports(__name__, globals(), _LAZY_IMPORTS)

__all__ = [
    "FlextLdap",
    "FlextLdapConnection",
    "FlextLdapConstants",
    "FlextLdapEntryAdapter",
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
    "c",
    "d",
    "e",
    "h",
    "ldap",
    "m",
    "p",
    "r",
    "s",
    "t",
    "u",
    "x",
]
