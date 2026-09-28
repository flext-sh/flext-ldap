# AUTO-GENERATED FILE — Regenerate with: make gen
"""Flext Ldap.adapters. Ldap3 package."""

from __future__ import annotations

from types import MappingProxyType
from typing import TYPE_CHECKING

from flext_core.lazy import build_lazy_import_map, install_lazy_exports

if TYPE_CHECKING:
    from .connection_manager import FlextLdapLdap3ConnectionManager
    from .operation_executor import FlextLdapLdap3OperationExecutor
    from .result_converter import FlextLdapLdap3ResultConverter
    from .result_extract import FlextLdapLdap3ResultExtract
    from .search_executor import FlextLdapLdap3SearchExecutor
    from .wrappers import FlextLdapLdap3Wrappers


__all__: tuple[str, ...] = (
    "FlextLdapLdap3ConnectionManager",
    "FlextLdapLdap3OperationExecutor",
    "FlextLdapLdap3ResultConverter",
    "FlextLdapLdap3ResultExtract",
    "FlextLdapLdap3SearchExecutor",
    "FlextLdapLdap3Wrappers",
)

_LAZY_IMPORTS = MappingProxyType(
    build_lazy_import_map(
        MappingProxyType({
            ".connection_manager": ("FlextLdapLdap3ConnectionManager",),
            ".operation_executor": ("FlextLdapLdap3OperationExecutor",),
            ".result_converter": ("FlextLdapLdap3ResultConverter",),
            ".result_extract": ("FlextLdapLdap3ResultExtract",),
            ".search_executor": ("FlextLdapLdap3SearchExecutor",),
            ".wrappers": ("FlextLdapLdap3Wrappers",),
        }),
        alias_groups=MappingProxyType({}),
        sort_keys=False,
    )
)

install_lazy_exports(__name__, globals(), _LAZY_IMPORTS, public_exports=__all__)
