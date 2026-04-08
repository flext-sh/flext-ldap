# AUTO-GENERATED FILE — DO NOT EDIT MANUALLY.
# Regenerate with: make gen
#
"""Services package."""

from __future__ import annotations

from flext_core.lazy import install_lazy_exports

_LAZY_IMPORTS = {
    "FlextLdapConnection": ("flext_ldap.services.connection", "FlextLdapConnection"),
    "FlextLdapOperations": ("flext_ldap.services.operations", "FlextLdapOperations"),
    "FlextLdapServerDetector": (
        "flext_ldap.services.detection",
        "FlextLdapServerDetector",
    ),
    "FlextLdapSync": ("flext_ldap.services.sync", "FlextLdapSync"),
    "FlextLdapSyncCallbacks": ("flext_ldap.services.sync", "FlextLdapSyncCallbacks"),
    "connection": "flext_ldap.services.connection",
    "detection": "flext_ldap.services.detection",
    "operations": "flext_ldap.services.operations",
    "sync": "flext_ldap.services.sync",
}


install_lazy_exports(__name__, globals(), _LAZY_IMPORTS, publish_all=False)
