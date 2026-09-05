# AUTO-GENERATED FILE — Regenerate with: make gen
"""Flext Ldap.adapters. Ldap3 package."""

from __future__ import annotations

from typing import TYPE_CHECKING

from types import MappingProxyType

from flext_core.lazy import build_lazy_import_map, install_lazy_exports

if TYPE_CHECKING:
    from .connection_manager import ConnectionManager
    from .operation_executor import OperationExecutor
    from .result_converter import ResultConverter
    from .result_extract import ResultConverterExtractMixin
    from .search_executor import SearchExecutor
    from .wrappers import FlextLdapLdap3Wrappers
__all__: tuple[str, ...] = (
    "ConnectionManager",
    "FlextLdapLdap3Wrappers",
    "OperationExecutor",
    "ResultConverter",
    "ResultConverterExtractMixin",
    "SearchExecutor",
)

_LAZY_IMPORTS = MappingProxyType(
    build_lazy_import_map(
        MappingProxyType({
            ".connection_manager": ("ConnectionManager",),
            ".operation_executor": ("OperationExecutor",),
            ".result_converter": ("ResultConverter",),
            ".result_extract": ("ResultConverterExtractMixin",),
            ".search_executor": ("SearchExecutor",),
            ".wrappers": ("FlextLdapLdap3Wrappers",),
        }),
        alias_groups=MappingProxyType({}),
        sort_keys=False,
    )
)

install_lazy_exports(__name__, globals(), _LAZY_IMPORTS, public_exports=__all__)
