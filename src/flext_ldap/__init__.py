# AUTO-GENERATED FILE — Regenerate with: make gen
"""Flext Ldap package."""

from __future__ import annotations

from typing import TYPE_CHECKING

from flext_core.lazy import (
    build_lazy_import_map,
    install_lazy_exports,
    merge_lazy_imports,
)
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

if TYPE_CHECKING:
    from flext_ldap.adapters.entry import FlextLdapEntryAdapter as FlextLdapEntryAdapter
    from flext_ldap.adapters.ldap3 import (
        FlextLdapAdapterHost as FlextLdapAdapterHost,
        FlextLdapLdap3Adapter as FlextLdapLdap3Adapter,
    )
    from flext_ldap.api import FlextLdap as FlextLdap, ldap as ldap
    from flext_ldap.base import FlextLdapService as FlextLdapService, s as s
    from flext_ldap.constants import FlextLdapConstants as FlextLdapConstants, c as c
    from flext_ldap.models import FlextLdapModels as FlextLdapModels, m as m
    from flext_ldap.protocols import FlextLdapProtocols as FlextLdapProtocols, p as p
    from flext_ldap.services.api_runtime import (
        FlextLdapApiRuntime as FlextLdapApiRuntime,
    )
    from flext_ldap.services.connection import (
        FlextLdapConnection as FlextLdapConnection,
    )
    from flext_ldap.services.detection import (
        FlextLdapServerDetector as FlextLdapServerDetector,
    )
    from flext_ldap.services.operations import (
        FlextLdapOperations as FlextLdapOperations,
    )
    from flext_ldap.services.sync import FlextLdapSync as FlextLdapSync
    from flext_ldap.settings import FlextLdapSettings as FlextLdapSettings
    from flext_ldap.typings import FlextLdapTypes as FlextLdapTypes, t as t
    from flext_ldap.utilities import FlextLdapUtilities as FlextLdapUtilities, u as u
    from flext_ldif import d as d, e as e, h as h, r as r, x as x
_LAZY_IMPORTS = merge_lazy_imports(
    (
        ".adapters",
        ".services",
    ),
    build_lazy_import_map(
        {
            ".adapters._ldap3.connection_manager": ("ConnectionManager",),
            ".adapters._ldap3.operation_executor": ("OperationExecutor",),
            ".adapters._ldap3.result_converter": ("ResultConverter",),
            ".adapters._ldap3.result_extract": ("ResultConverterExtractMixin",),
            ".adapters._ldap3.search_executor": ("SearchExecutor",),
            ".adapters._ldap3.wrappers": ("FlextLdapLdap3Wrappers",),
            ".adapters.entry": ("FlextLdapEntryAdapter",),
            ".adapters.ldap3": (
                "FlextLdapAdapterHost",
                "FlextLdapLdap3Adapter",
            ),
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
            ".services.sync": ("FlextLdapSync",),
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
        "_ldap3",
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


__all__: tuple[str, ...] = (
    "FlextLdap",
    "FlextLdapAdapterHost",
    "FlextLdapApiRuntime",
    "FlextLdapConnection",
    "FlextLdapConstants",
    "FlextLdapEntryAdapter",
    "FlextLdapLdap3Adapter",
    "FlextLdapModels",
    "FlextLdapOperations",
    "FlextLdapProtocols",
    "FlextLdapServerDetector",
    "FlextLdapService",
    "FlextLdapSettings",
    "FlextLdapSync",
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
)


install_lazy_exports(
    __name__,
    globals(),
    _LAZY_IMPORTS,
    public_exports=__all__,
)
