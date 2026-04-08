# AUTO-GENERATED FILE — DO NOT EDIT MANUALLY.
# Regenerate with: make gen
#
"""Adapters package."""

from __future__ import annotations

from flext_core.lazy import install_lazy_exports

_LAZY_IMPORTS = {
    "FlextLdapEntryAdapter": ("flext_ldap.adapters.entry", "FlextLdapEntryAdapter"),
    "FlextLdapLdap3Adapter": ("flext_ldap.adapters.ldap3", "FlextLdapLdap3Adapter"),
    "FlextLdapLdap3Wrappers": ("flext_ldap.adapters.ldap3", "FlextLdapLdap3Wrappers"),
    "c": ("flext_core.constants", "FlextConstants"),
    "d": ("flext_core.decorators", "FlextDecorators"),
    "e": ("flext_core.exceptions", "FlextExceptions"),
    "entry": "flext_ldap.adapters.entry",
    "h": ("flext_core.handlers", "FlextHandlers"),
    "ldap3": "flext_ldap.adapters.ldap3",
    "m": ("flext_core.models", "FlextModels"),
    "p": ("flext_core.protocols", "FlextProtocols"),
    "r": ("flext_core.result", "FlextResult"),
    "s": ("flext_core.service", "FlextService"),
    "t": ("flext_core.typings", "FlextTypes"),
    "u": ("flext_core.utilities", "FlextUtilities"),
    "x": ("flext_core.mixins", "FlextMixins"),
}


install_lazy_exports(__name__, globals(), _LAZY_IMPORTS, publish_all=False)
