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
    "c": ("flext_core.constants", "FlextConstants"),
    "connection": "flext_ldap.services.connection",
    "d": ("flext_core.decorators", "FlextDecorators"),
    "detection": "flext_ldap.services.detection",
    "e": ("flext_core.exceptions", "FlextExceptions"),
    "h": ("flext_core.handlers", "FlextHandlers"),
    "m": ("flext_core.models", "FlextModels"),
    "operations": "flext_ldap.services.operations",
    "p": ("flext_core.protocols", "FlextProtocols"),
    "r": ("flext_core.result", "FlextResult"),
    "s": ("flext_core.service", "FlextService"),
    "sync": "flext_ldap.services.sync",
    "t": ("flext_core.typings", "FlextTypes"),
    "u": ("flext_core.utilities", "FlextUtilities"),
    "x": ("flext_core.mixins", "FlextMixins"),
}


install_lazy_exports(__name__, globals(), _LAZY_IMPORTS, publish_all=False)
