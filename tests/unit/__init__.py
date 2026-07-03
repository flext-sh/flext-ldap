# AUTO-GENERATED FILE — Regenerate with: make gen
"""Unit package."""

from __future__ import annotations

from flext_core.lazy import build_lazy_import_map, install_lazy_exports

_LAZY_IMPORTS = build_lazy_import_map(
    {
        ".test_api": ("TestsFlextLdapApi",),
        ".test_base": ("TestsFlextLdapBase",),
        ".test_config": ("TestsFlextLdapConfig",),
        ".test_connection": ("TestsFlextLdapConnection",),
        ".test_constants": ("TestsFlextLdapConstantsUnit",),
        ".test_detection": ("TestsFlextLdapDetection",),
        ".test_entry_adapter": ("TestsFlextLdapEntryAdapter",),
        ".test_ldap3_adapter": ("TestsFlextLdapLdap3Adapter",),
        ".test_ldap3_adapter_helpers": ("TestsFlextLdapLdap3AdapterHelpers",),
        ".test_models": ("TestsFlextLdapModelsUnit",),
        ".test_models_search": ("TestsFlextLdapModelsSearch",),
        ".test_models_sync": ("TestsFlextLdapModelsSync",),
        ".test_operations": ("TestsFlextLdapOperations",),
        ".test_public_api_contract": ("TestsFlextLdapPublicApiContract",),
        ".test_sync": ("TestsFlextLdapSync",),
        ".test_utilities": ("TestsFlextLdapUtilitiesUnit",),
        "flext_tests": (
            "c",
            "d",
            "e",
            "h",
            "m",
            "p",
            "r",
            "s",
            "t",
            "td",
            "tf",
            "tk",
            "tm",
            "tv",
            "u",
            "x",
        ),
    },
)


install_lazy_exports(
    __name__,
    globals(),
    _LAZY_IMPORTS,
    publish_all=False,
)
