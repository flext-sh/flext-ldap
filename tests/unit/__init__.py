# AUTO-GENERATED FILE — Regenerate with: make gen
"""Unit package."""

from __future__ import annotations

from flext_core.lazy import build_lazy_import_map, install_lazy_exports

_LAZY_IMPORTS = build_lazy_import_map(
    {
        ".test_api": ("test_api",),
        ".test_base": ("test_base",),
        ".test_config": ("test_config",),
        ".test_constants": ("test_constants",),
        ".test_detection": ("test_detection",),
        ".test_entry_adapter": ("test_entry_adapter",),
        ".test_ldap3_adapter": ("test_ldap3_adapter",),
        ".test_models": ("test_models",),
        ".test_models_search": ("test_models_search",),
        ".test_models_sync": ("test_models_sync",),
        ".test_operations": ("test_operations",),
        ".test_sync": ("test_sync",),
        ".test_utilities": ("test_utilities",),
        "flext_ldap": (
            "c",
            "d",
            "e",
            "h",
            "m",
            "p",
            "r",
            "s",
            "t",
            "u",
            "x",
        ),
    },
)


install_lazy_exports(__name__, globals(), _LAZY_IMPORTS, publish_all=False)
