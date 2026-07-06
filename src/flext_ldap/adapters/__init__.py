# AUTO-GENERATED FILE — Regenerate with: make gen
"""Adapters package."""

from __future__ import annotations

from typing import TYPE_CHECKING

from flext_core.lazy import (
    build_lazy_import_map,
    install_lazy_exports,
    merge_lazy_imports,
)

if TYPE_CHECKING:
    from flext_ldap.adapters._ldap3.connection_manager import ConnectionManager
    from flext_ldap.adapters._ldap3.operation_executor import OperationExecutor
    from flext_ldap.adapters._ldap3.result_converter import ResultConverter
    from flext_ldap.adapters._ldap3.result_extract import ResultConverterExtractMixin
    from flext_ldap.adapters._ldap3.search_executor import SearchExecutor
    from flext_ldap.adapters._ldap3.wrappers import FlextLdapLdap3Wrappers
    from flext_ldap.adapters.entry import FlextLdapEntryAdapter
    from flext_ldap.adapters.ldap3 import FlextLdapAdapterHost, FlextLdapLdap3Adapter
_LAZY_IMPORTS = merge_lazy_imports(
    ("._ldap3",),
    build_lazy_import_map(
        {
            "._ldap3": ("_ldap3",),
            "._ldap3.connection_manager": ("ConnectionManager",),
            "._ldap3.operation_executor": ("OperationExecutor",),
            "._ldap3.result_converter": ("ResultConverter",),
            "._ldap3.result_extract": ("ResultConverterExtractMixin",),
            "._ldap3.search_executor": ("SearchExecutor",),
            "._ldap3.wrappers": ("FlextLdapLdap3Wrappers",),
            ".entry": ("FlextLdapEntryAdapter",),
            ".ldap3": (
                "FlextLdapAdapterHost",
                "FlextLdapLdap3Adapter",
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
