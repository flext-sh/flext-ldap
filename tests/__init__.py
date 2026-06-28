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
    from flext_tests import td as td, tf as tf, tk as tk, tv as tv

    from flext_ldap import d as d, e as e, h as h, r as r, x as x
    from tests.base import (
        TestsFlextLdapServiceBase as TestsFlextLdapServiceBase,
        s as s,
    )
    from tests.conftest import WorkerInputConfig as WorkerInputConfig
    from tests.constants import (
        TestsFlextLdapConstants as TestsFlextLdapConstants,
        c as c,
    )
    from tests.integration.test_smoke import TestsFlextLdapSmoke as TestsFlextLdapSmoke
    from tests.models import TestsFlextLdapModels as TestsFlextLdapModels, m as m
    from tests.protocols import (
        TestsFlextLdapProtocols as TestsFlextLdapProtocols,
        p as p,
    )
    from tests.settings import TestsFlextLdapSettings as TestsFlextLdapSettings
    from tests.typings import TestsFlextLdapTypes as TestsFlextLdapTypes, t as t
    from tests.unit.test_api import TestsFlextLdapApi as TestsFlextLdapApi
    from tests.unit.test_base import TestsFlextLdapBase as TestsFlextLdapBase
    from tests.unit.test_config import TestsFlextLdapConfig as TestsFlextLdapConfig
    from tests.unit.test_connection import (
        TestsFlextLdapConnection as TestsFlextLdapConnection,
    )
    from tests.unit.test_constants import (
        TestsFlextLdapConstantsUnit as TestsFlextLdapConstantsUnit,
    )
    from tests.unit.test_detection import (
        TestsFlextLdapDetection as TestsFlextLdapDetection,
    )
    from tests.unit.test_entry_adapter import (
        TestsFlextLdapEntryAdapter as TestsFlextLdapEntryAdapter,
    )
    from tests.unit.test_ldap3_adapter import (
        TestsFlextLdapLdap3Adapter as TestsFlextLdapLdap3Adapter,
    )
    from tests.unit.test_models import (
        TestsFlextLdapModelsUnit as TestsFlextLdapModelsUnit,
    )
    from tests.unit.test_models_search import (
        TestsFlextLdapModelsSearch as TestsFlextLdapModelsSearch,
    )
    from tests.unit.test_models_sync import (
        TestsFlextLdapModelsSync as TestsFlextLdapModelsSync,
    )
    from tests.unit.test_operations import (
        TestsFlextLdapOperations as TestsFlextLdapOperations,
    )
    from tests.unit.test_public_api_contract import (
        TestsFlextLdapPublicApiContract as TestsFlextLdapPublicApiContract,
    )
    from tests.unit.test_sync import TestsFlextLdapSync as TestsFlextLdapSync
    from tests.unit.test_utilities import (
        TestsFlextLdapUtilitiesUnit as TestsFlextLdapUtilitiesUnit,
    )
    from tests.utilities import (
        TestsFlextLdapUtilities as TestsFlextLdapUtilities,
        u as u,
    )
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
            ".unit.test_public_api_contract": ("TestsFlextLdapPublicApiContract",),
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
    "TestsFlextLdapPublicApiContract",
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
    "tv",
    "u",
    "x",
]
