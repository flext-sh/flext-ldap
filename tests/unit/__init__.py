# AUTO-GENERATED FILE — Regenerate with: make gen
"""Unit package."""

from __future__ import annotations

from flext_core.lazy import build_lazy_import_map, install_lazy_exports

_LAZY_IMPORTS = build_lazy_import_map(
    {
        ".test_api": ("TestsFlextLdapApi",),
        ".test_base": ("TestsFlextLdapBase",),
        ".test_config": ("TestsFlextLdapSettings",),
        ".test_constants": ("TestsFlextLdapConstantsUnit",),
        ".test_detection": ("TestsFlextLdapDetection",),
        ".test_entry_adapter": ("TestsFlextLdapEntryAdapter",),
        ".test_ldap3_adapter": ("TestsFlextLdap3Adapter",),
        ".test_models": ("TestsFlextLdapModelsUnit",),
        ".test_models_search": ("TestsFlextLdapModelsSearch",),
        ".test_models_sync": ("TestsFlextLdapModelsSync",),
        ".test_operations": ("TestsFlextLdapOperations",),
        ".test_sync": ("TestsFlextLdapSync",),
        ".test_utilities": ("TestsFlextLdapUtilities",),
    },
)


install_lazy_exports(__name__, globals(), _LAZY_IMPORTS, publish_all=False)
