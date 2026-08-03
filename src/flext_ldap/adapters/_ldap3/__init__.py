# @generated AUTO-GENERATED FILE — Regenerate with: make gen
"""Flext Ldap.adapters. Ldap3 package."""

from __future__ import annotations

from typing import TYPE_CHECKING

from flext_core.lazy import build_lazy_import_map, install_lazy_exports

if TYPE_CHECKING:
    from .connection_manager import ConnectionManager as ConnectionManager
    from .operation_executor import OperationExecutor as OperationExecutor
    from .result_converter import ResultConverter as ResultConverter
    from .result_extract import (
        ResultConverterExtractMixin as ResultConverterExtractMixin,
    )
    from .search_executor import SearchExecutor as SearchExecutor
    from .wrappers import FlextLdapLdap3Wrappers as FlextLdapLdap3Wrappers

_LAZY_MODULES: dict[str, tuple[str, ...]] = {
    ".connection_manager": ("ConnectionManager",),
    ".operation_executor": ("OperationExecutor",),
    ".result_converter": ("ResultConverter",),
    ".result_extract": ("ResultConverterExtractMixin",),
    ".search_executor": ("SearchExecutor",),
    ".wrappers": ("FlextLdapLdap3Wrappers",),
}


_LAZY_ALIAS_GROUPS: dict[str, tuple[tuple[str, str], ...]] = {}


_LAZY_IMPORTS = build_lazy_import_map(
    _LAZY_MODULES, alias_groups=_LAZY_ALIAS_GROUPS, sort_keys=False
)

_PUBLIC_EXPORTS: tuple[str, ...] = (
    "ConnectionManager",
    "FlextLdapLdap3Wrappers",
    "OperationExecutor",
    "ResultConverter",
    "ResultConverterExtractMixin",
    "SearchExecutor",
)

__all__: tuple[str, ...] = tuple(_PUBLIC_EXPORTS)

install_lazy_exports(__name__, globals(), _LAZY_IMPORTS, public_exports=__all__)
