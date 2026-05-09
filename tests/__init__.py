# AUTO-GENERATED FILE — Regenerate with: make gen
"""Tests package."""

from __future__ import annotations

import typing as _t

from flext_core.lazy import (
    build_lazy_import_map,
    install_lazy_exports,
    merge_lazy_imports,
)

if _t.TYPE_CHECKING:
    from flext_tests import td, tf, tk, tm, tv

    from flext_ldap import d, e, h, r, x
    from tests.base import TestsFlextLdapServiceBase, s
    from tests.conftest import WorkerInputConfig
    from tests.constants import TestsFlextLdapConstants, c
    from tests.integration.test_smoke import TestsFlextLdapSmoke
    from tests.models import TestsFlextLdapModels, m
    from tests.protocols import TestsFlextLdapProtocols, p
    from tests.settings import TestsFlextLdapSettings
    from tests.typings import TestsFlextLdapTypes, t
    from tests.unit.test_api import TestsFlextLdapApi
    from tests.unit.test_base import TestsFlextLdapBase
    from tests.unit.test_config import TestsFlextLdapConfig
    from tests.unit.test_connection import TestsFlextLdapConnection
    from tests.unit.test_constants import TestsFlextLdapConstantsUnit
    from tests.unit.test_detection import TestsFlextLdapDetection
    from tests.unit.test_entry_adapter import TestsFlextLdapEntryAdapter
    from tests.unit.test_ldap3_adapter import TestsFlextLdapLdap3Adapter
    from tests.unit.test_models import TestsFlextLdapModelsUnit
    from tests.unit.test_models_search import TestsFlextLdapModelsSearch
    from tests.unit.test_models_sync import TestsFlextLdapModelsSync
    from tests.unit.test_operations import TestsFlextLdapOperations
    from tests.unit.test_sync import TestsFlextLdapSync
    from tests.unit.test_utilities import TestsFlextLdapUtilitiesUnit
    from tests.utilities import TestsFlextLdapUtilities, u
_LAZY_IMPORTS = merge_lazy_imports(
    (
        ".integration",
        ".unit",
    ),
    build_lazy_import_map(
        {
            ".base": (
                "TestsFlextLdapServiceBase",
                "s",
            ),
            ".conftest": ("WorkerInputConfig",),
            ".constants": (
                "TestsFlextLdapConstants",
                "c",
            ),
            ".integration.test_smoke": ("TestsFlextLdapSmoke",),
            ".models": (
                "TestsFlextLdapModels",
                "m",
            ),
            ".protocols": (
                "TestsFlextLdapProtocols",
                "p",
            ),
            ".settings": ("TestsFlextLdapSettings",),
            ".typings": (
                "TestsFlextLdapTypes",
                "t",
            ),
            ".unit.test_api": ("TestsFlextLdapApi",),
            ".unit.test_base": ("TestsFlextLdapBase",),
            ".unit.test_config": ("TestsFlextLdapConfig",),
            ".unit.test_connection": ("TestsFlextLdapConnection",),
            ".unit.test_constants": ("TestsFlextLdapConstantsUnit",),
            ".unit.test_detection": ("TestsFlextLdapDetection",),
            ".unit.test_entry_adapter": ("TestsFlextLdapEntryAdapter",),
            ".unit.test_ldap3_adapter": ("TestsFlextLdapLdap3Adapter",),
            ".unit.test_models": ("TestsFlextLdapModelsUnit",),
            ".unit.test_models_search": ("TestsFlextLdapModelsSearch",),
            ".unit.test_models_sync": ("TestsFlextLdapModelsSync",),
            ".unit.test_operations": ("TestsFlextLdapOperations",),
            ".unit.test_sync": ("TestsFlextLdapSync",),
            ".unit.test_utilities": ("TestsFlextLdapUtilitiesUnit",),
            ".utilities": (
                "TestsFlextLdapUtilities",
                "u",
            ),
            "flext_ldap": (
                "d",
                "e",
                "h",
                "r",
                "x",
            ),
            "flext_tests": (
                "td",
                "tf",
                "tk",
                "tm",
                "tv",
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
    "TestsFlextLdapApi",
    "TestsFlextLdapBase",
    "TestsFlextLdapConfig",
    "TestsFlextLdapConnection",
    "TestsFlextLdapConstants",
    "TestsFlextLdapConstantsUnit",
    "TestsFlextLdapDetection",
    "TestsFlextLdapEntryAdapter",
    "TestsFlextLdapLdap3Adapter",
    "TestsFlextLdapModels",
    "TestsFlextLdapModelsSearch",
    "TestsFlextLdapModelsSync",
    "TestsFlextLdapModelsUnit",
    "TestsFlextLdapOperations",
    "TestsFlextLdapProtocols",
    "TestsFlextLdapServiceBase",
    "TestsFlextLdapSettings",
    "TestsFlextLdapSmoke",
    "TestsFlextLdapSync",
    "TestsFlextLdapTypes",
    "TestsFlextLdapUtilities",
    "TestsFlextLdapUtilitiesUnit",
    "WorkerInputConfig",
    "c",
    "d",
    "e",
    "h",
    "m",
    "p",
    "r",
    "s",
    "t",
    "td",
    "tf",
    "tk",
    "tm",
    "tv",
    "u",
    "x",
]
