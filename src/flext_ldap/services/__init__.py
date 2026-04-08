# AUTO-GENERATED FILE — DO NOT EDIT MANUALLY.
# Regenerate with: make gen
#
"""Services package."""

from __future__ import annotations

from flext_core.lazy import install_lazy_exports

_LAZY_IMPORTS = {
    "FlextLdapConnection": ".connection",
    "FlextLdapOperations": ".operations",
    "FlextLdapServerDetector": ".detection",
    "FlextLdapSync": ".sync",
    "FlextLdapSyncCallbacks": ".sync",
}


install_lazy_exports(__name__, globals(), _LAZY_IMPORTS, publish_all=False)
