# AUTO-GENERATED FILE — Regenerate with: make gen
"""Flext Ldap.adapters package."""

from __future__ import annotations

from typing import TYPE_CHECKING

from types import MappingProxyType

from flext_core.lazy import build_lazy_import_map, install_lazy_exports

if TYPE_CHECKING:
    from . import _ldap3 as _ldap3
    from ._ldap3.connection_manager import ConnectionManager
    from ._ldap3.operation_executor import OperationExecutor
    from ._ldap3.result_converter import ResultConverter
    from ._ldap3.result_extract import ResultConverterExtractMixin
    from ._ldap3.search_executor import SearchExecutor
    from ._ldap3.wrappers import FlextLdapLdap3Wrappers
__all__: tuple[str, ...] = (
    "ConnectionManager",
    "FlextLdapLdap3Wrappers",
    "OperationExecutor",
    "ResultConverter",
    "ResultConverterExtractMixin",
    "SearchExecutor",
    "_ldap3",
)

_LAZY_IMPORTS = MappingProxyType(
    build_lazy_import_map(
        MappingProxyType({
            "._ldap3": ("_ldap3",),
            "._ldap3.connection_manager": ("ConnectionManager",),
            "._ldap3.operation_executor": ("OperationExecutor",),
            "._ldap3.result_converter": ("ResultConverter",),
            "._ldap3.result_extract": ("ResultConverterExtractMixin",),
            "._ldap3.search_executor": ("SearchExecutor",),
            "._ldap3.wrappers": ("FlextLdapLdap3Wrappers",),
        }),
        alias_groups=MappingProxyType({}),
        sort_keys=False,
    )
)

install_lazy_exports(__name__, globals(), _LAZY_IMPORTS, public_exports=__all__)
