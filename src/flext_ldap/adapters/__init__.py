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
    "entry": "flext_ldap.adapters.entry",
    "ldap3": "flext_ldap.adapters.ldap3",
}


install_lazy_exports(__name__, globals(), _LAZY_IMPORTS, publish_all=False)
