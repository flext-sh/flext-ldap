# AUTO-GENERATED FILE — Regenerate with: make gen
"""Flext Ldap package."""

from __future__ import annotations

import typing as _t

from flext_core.lazy import (
    build_lazy_import_map,
    install_lazy_exports,
    merge_lazy_imports,
)

if _t.TYPE_CHECKING:
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
    from flext_ldap._models.ldap import FlextLdapModelsLdap
    from flext_ldap.adapters._ldap3.connection_manager import ConnectionManager
    from flext_ldap.adapters._ldap3.operation_executor import OperationExecutor
    from flext_ldap.adapters._ldap3.result_converter import ResultConverter
    from flext_ldap.adapters._ldap3.search_executor import SearchExecutor
    from flext_ldap.adapters._ldap3.wrappers import FlextLdapLdap3Wrappers
    from flext_ldap.adapters.entry import FlextLdapEntryAdapter
    from flext_ldap.adapters.ldap3 import FlextLdapLdap3Adapter
    from flext_ldap.api import FlextLdap, ldap
    from flext_ldap.base import FlextLdapService, s
    from flext_ldap.constants import FlextLdapConstants, c
    from flext_ldap.models import FlextLdapModels, m
    from flext_ldap.protocols import FlextLdapProtocols, p
    from flext_ldap.services.api_runtime import FlextLdapApiRuntime
    from flext_ldap.services.connection import FlextLdapConnection
    from flext_ldap.services.detection import FlextLdapServerDetector
    from flext_ldap.services.operations import FlextLdapOperations
    from flext_ldap.services.sync import FlextLdapSync, FlextLdapSyncCallbacks
    from flext_ldap.settings import FlextLdapSettings
    from flext_ldap.typings import FlextLdapTypes, t
    from flext_ldap.utilities import FlextLdapUtilities, u
    from flext_ldif import d, e, h, r, x
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
            "._models.ldap": ("FlextLdapModelsLdap",),
            ".adapters._ldap3.connection_manager": ("ConnectionManager",),
            ".adapters._ldap3.operation_executor": ("OperationExecutor",),
            ".adapters._ldap3.result_converter": ("ResultConverter",),
            ".adapters._ldap3.search_executor": ("SearchExecutor",),
            ".adapters._ldap3.wrappers": ("FlextLdapLdap3Wrappers",),
            ".adapters.entry": ("FlextLdapEntryAdapter",),
            ".adapters.ldap3": ("FlextLdapLdap3Adapter",),
            ".api": (
                "FlextLdap",
                "ldap",
            ),
            ".base": (
                "FlextLdapService",
                "s",
            ),
            ".constants": (
                "FlextLdapConstants",
                "c",
            ),
            ".models": (
                "FlextLdapModels",
                "m",
            ),
            ".protocols": (
                "FlextLdapProtocols",
                "p",
            ),
            ".services.api_runtime": ("FlextLdapApiRuntime",),
            ".services.connection": ("FlextLdapConnection",),
            ".services.detection": ("FlextLdapServerDetector",),
            ".services.operations": ("FlextLdapOperations",),
            ".services.sync": (
                "FlextLdapSync",
                "FlextLdapSyncCallbacks",
            ),
            ".settings": ("FlextLdapSettings",),
            ".typings": (
                "FlextLdapTypes",
                "t",
            ),
            ".utilities": (
                "FlextLdapUtilities",
                "u",
            ),
            "flext_ldif": (
                "d",
                "e",
                "h",
                "r",
                "x",
            ),
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
        "pytest_addoption",
        "pytest_collect_file",
        "pytest_collection_modifyitems",
        "pytest_configure",
        "pytest_runtest_setup",
        "pytest_runtest_teardown",
        "pytest_sessionfinish",
        "pytest_sessionstart",
        "pytest_terminal_summary",
        "pytest_warning_recorded",
    ),
    module_name=__name__,
)


install_lazy_exports(__name__, globals(), _LAZY_IMPORTS)

__all__: list[str] = [
    "ConnectionManager",
    "FlextLdap",
    "FlextLdapApiRuntime",
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
    "FlextLdapService",
    "FlextLdapSettings",
    "FlextLdapSync",
    "FlextLdapSyncCallbacks",
    "FlextLdapTypes",
    "FlextLdapUtilities",
    "OperationExecutor",
    "ResultConverter",
    "SearchExecutor",
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
