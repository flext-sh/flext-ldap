# AUTO-GENERATED FILE — Regenerate with: make gen
"""Ldap3 package."""

from __future__ import annotations

from flext_core.lazy import build_lazy_import_map, install_lazy_exports

_LAZY_IMPORTS = build_lazy_import_map(
    {
        ".connection_manager": ("ConnectionManager",),
        ".operation_executor": ("OperationExecutor",),
        ".result_converter": ("ResultConverter",),
        ".result_extract": ("ResultConverterExtractMixin",),
        ".search_executor": ("SearchExecutor",),
        ".wrappers": ("FlextLdapLdap3Wrappers",),
    },
)


install_lazy_exports(
    __name__,
    globals(),
    _LAZY_IMPORTS,
    publish_all=False,
)
