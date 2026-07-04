"""Root public lazy export contract for flext_ldap."""

from __future__ import annotations

from flext_core.lazy import build_lazy_import_map

FLEXT_LDAP_LAZY_IMPORTS = build_lazy_import_map(
    {
        ".api": ("FlextLdap", "ldap"),
        ".base": ("FlextLdapService", "s"),
        ".constants": ("FlextLdapConstants", "c"),
        ".models": ("FlextLdapModels", "m"),
        ".protocols": ("FlextLdapProtocols", "p"),
        ".settings": ("FlextLdapSettings",),
        ".typings": ("FlextLdapTypes", "t"),
        ".utilities": ("FlextLdapUtilities", "u"),
        "flext_core": ("d", "e", "h", "r", "x"),
    },
)

FLEXT_LDAP_PUBLIC_EXPORTS: tuple[str, ...] = (
    "FlextLdap",
    "FlextLdapConstants",
    "FlextLdapModels",
    "FlextLdapProtocols",
    "FlextLdapService",
    "FlextLdapSettings",
    "FlextLdapTypes",
    "FlextLdapUtilities",
    "__author__",
    "__author_email__",
    "__description__",
    "__license__",
    "__title__",
    "__url__",
    "__version__",
    "__version_info__",
    "c",
    "d",
    "e",
    "h",
    "ldap",
    "m",
    "p",
    "r",
    "s",
    "t",
    "u",
    "x",
)

__all__: tuple[str, ...] = (
    "FLEXT_LDAP_LAZY_IMPORTS",
    "FLEXT_LDAP_PUBLIC_EXPORTS",
)
