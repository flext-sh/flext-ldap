# @generated AUTO-GENERATED FILE — Regenerate with: make gen
"""Flext Ldap.adapters package."""

from __future__ import annotations

from typing import TYPE_CHECKING

from flext_core.lazy import build_lazy_import_map, install_lazy_exports

if TYPE_CHECKING:
    from . import _ldap3 as _ldap3
    from ._ldap3.connection_manager import ConnectionManager as ConnectionManager
    from ._ldap3.operation_executor import OperationExecutor as OperationExecutor
    from ._ldap3.result_converter import ResultConverter as ResultConverter
    from ._ldap3.result_extract import (
        ResultConverterExtractMixin as ResultConverterExtractMixin,
    )
    from ._ldap3.search_executor import SearchExecutor as SearchExecutor
    from ._ldap3.wrappers import FlextLdapLdap3Wrappers as FlextLdapLdap3Wrappers
    from .entry import FlextLdapEntryAdapter as FlextLdapEntryAdapter
    from .ldap3 import FlextLdapAdapterHost as FlextLdapAdapterHost
    from .ldap3 import FlextLdapLdap3Adapter as FlextLdapLdap3Adapter

_LAZY_MODULES: dict[str, tuple[str, ...]] = {
    "._ldap3": ("_ldap3",),
    "._ldap3.connection_manager": ("ConnectionManager",),
    "._ldap3.operation_executor": ("OperationExecutor",),
    "._ldap3.result_converter": ("ResultConverter",),
    "._ldap3.result_extract": ("ResultConverterExtractMixin",),
    "._ldap3.search_executor": ("SearchExecutor",),
    "._ldap3.wrappers": ("FlextLdapLdap3Wrappers",),
    ".entry": ("FlextLdapEntryAdapter",),
    ".ldap3": ("FlextLdapAdapterHost", "FlextLdapLdap3Adapter"),
}


_LAZY_ALIAS_GROUPS: dict[str, tuple[tuple[str, str], ...]] = {}


_LAZY_IMPORTS = build_lazy_import_map(
    _LAZY_MODULES, alias_groups=_LAZY_ALIAS_GROUPS, sort_keys=False
)

_PUBLIC_EXPORTS: tuple[str, ...] = (
    "ConnectionManager",
    "FlextLdapAdapterHost",
    "FlextLdapEntryAdapter",
    "FlextLdapLdap3Adapter",
    "FlextLdapLdap3Wrappers",
    "OperationExecutor",
    "ResultConverter",
    "ResultConverterExtractMixin",
    "SearchExecutor",
    "_ldap3",
)

__all__: tuple[str, ...] = tuple(_PUBLIC_EXPORTS)

install_lazy_exports(__name__, globals(), _LAZY_IMPORTS, public_exports=__all__)
