# AUTO-GENERATED FILE — Regenerate with: make gen
"""Tests package."""

from __future__ import annotations

from flext_core.lazy import (
    build_lazy_import_map,
    install_lazy_exports,
    merge_lazy_imports,
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
