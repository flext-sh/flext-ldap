# AUTO-GENERATED FILE — Regenerate with: make gen
"""Services package."""

from __future__ import annotations

from flext_core.lazy import build_lazy_import_map, install_lazy_exports

_LAZY_IMPORTS = build_lazy_import_map(
    {
        ".api_runtime": ("FlextLdapApiRuntime",),
        ".connection": ("FlextLdapConnection",),
        ".detection": ("FlextLdapServerDetector",),
        ".operations": ("FlextLdapOperations",),
        ".sync": (
            "FlextLdapSync",
            "FlextLdapSyncCallbacks",
        ),
    },
)


install_lazy_exports(__name__, globals(), _LAZY_IMPORTS, publish_all=False)
