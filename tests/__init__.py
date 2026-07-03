# AUTO-GENERATED FILE — Regenerate with: make gen
"""Tests package."""

from __future__ import annotations

from typing import TYPE_CHECKING

from flext_core.lazy import (
    build_lazy_import_map,
    install_lazy_exports,
    merge_lazy_imports,
)

if TYPE_CHECKING:
    from flext_tests import (
        d as d,
        e as e,
        h as h,
        r as r,
        td as td,
        tf as tf,
        tk as tk,
        tm as tm,
        tv as tv,
        x as x,
    )

    from flext_ldap.tests.base import (
        TestsFlextLdapServiceBase as TestsFlextLdapServiceBase,
        s as s,
    )
    from flext_ldap.tests.conftest import WorkerInputConfig as WorkerInputConfig
    from flext_ldap.tests.constants import (
        TestsFlextLdapConstants as TestsFlextLdapConstants,
        c as c,
    )
    from flext_ldap.tests.integration.test_smoke import (
        TestsFlextLdapSmoke as TestsFlextLdapSmoke,
    )
    from flext_ldap.tests.models import (
        TestsFlextLdapModels as TestsFlextLdapModels,
        m as m,
    )
    from flext_ldap.tests.protocols import (
        TestsFlextLdapProtocols as TestsFlextLdapProtocols,
        p as p,
    )
    from flext_ldap.tests.settings import (
        TestsFlextLdapSettings as TestsFlextLdapSettings,
    )
    from flext_ldap.tests.typings import (
        TestsFlextLdapTypes as TestsFlextLdapTypes,
        t as t,
    )
    from flext_ldap.tests.unit.test_api import TestsFlextLdapApi as TestsFlextLdapApi
    from flext_ldap.tests.unit.test_base import TestsFlextLdapBase as TestsFlextLdapBase
    from flext_ldap.tests.unit.test_config import (
        TestsFlextLdapConfig as TestsFlextLdapConfig,
    )
    from flext_ldap.tests.unit.test_connection import (
        TestsFlextLdapConnection as TestsFlextLdapConnection,
    )
    from flext_ldap.tests.unit.test_constants import (
        TestsFlextLdapConstantsUnit as TestsFlextLdapConstantsUnit,
    )
    from flext_ldap.tests.unit.test_detection import (
        TestsFlextLdapDetection as TestsFlextLdapDetection,
    )
    from flext_ldap.tests.unit.test_entry_adapter import (
        TestsFlextLdapEntryAdapter as TestsFlextLdapEntryAdapter,
    )
    from flext_ldap.tests.unit.test_ldap3_adapter import (
        TestsFlextLdapLdap3Adapter as TestsFlextLdapLdap3Adapter,
    )
    from flext_ldap.tests.unit.test_ldap3_adapter_helpers import (
        TestsFlextLdapLdap3AdapterHelpers as TestsFlextLdapLdap3AdapterHelpers,
    )
    from flext_ldap.tests.unit.test_models import (
        TestsFlextLdapModelsUnit as TestsFlextLdapModelsUnit,
    )
    from flext_ldap.tests.unit.test_models_search import (
        TestsFlextLdapModelsSearch as TestsFlextLdapModelsSearch,
    )
    from flext_ldap.tests.unit.test_models_sync import (
        TestsFlextLdapModelsSync as TestsFlextLdapModelsSync,
    )
    from flext_ldap.tests.unit.test_operations import (
        TestsFlextLdapOperations as TestsFlextLdapOperations,
    )
    from flext_ldap.tests.unit.test_public_api_contract import (
        TestsFlextLdapPublicApiContract as TestsFlextLdapPublicApiContract,
    )
    from flext_ldap.tests.unit.test_sync import TestsFlextLdapSync as TestsFlextLdapSync
    from flext_ldap.tests.unit.test_utilities import (
        TestsFlextLdapUtilitiesUnit as TestsFlextLdapUtilitiesUnit,
    )
    from flext_ldap.tests.utilities import (
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
            ".integration": ("integration",),
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
            ".unit": ("unit",),
            ".unit.test_api": ("TestsFlextLdapApi",),
            ".unit.test_base": ("TestsFlextLdapBase",),
            ".unit.test_config": ("TestsFlextLdapConfig",),
            ".unit.test_connection": ("TestsFlextLdapConnection",),
            ".unit.test_constants": ("TestsFlextLdapConstantsUnit",),
            ".unit.test_detection": ("TestsFlextLdapDetection",),
            ".unit.test_entry_adapter": ("TestsFlextLdapEntryAdapter",),
            ".unit.test_ldap3_adapter": ("TestsFlextLdapLdap3Adapter",),
            ".unit.test_ldap3_adapter_helpers": ("TestsFlextLdapLdap3AdapterHelpers",),
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
            "flext_tests": (
                "d",
                "e",
                "h",
                "r",
                "td",
                "tf",
                "tk",
                "tm",
                "tv",
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


install_lazy_exports(
    __name__,
    globals(),
    _LAZY_IMPORTS,
    publish_all=False,
)
