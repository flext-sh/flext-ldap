# AUTO-GENERATED FILE — Regenerate with: make gen
"""Flext Ldap package."""

from __future__ import annotations

from typing import TYPE_CHECKING

from flext_core.lazy import build_lazy_import_map, install_lazy_exports
from flext_ldap.__version__ import (
    __author__,
    __author_email__,
    __description__,
    __license__,
    __title__,
    __url__,
    __version__,
    __version_info__,
)

if TYPE_CHECKING:
    from flext_ldap.api import FlextLdap as FlextLdap, ldap as ldap
    from flext_ldap.base import FlextLdapService as FlextLdapService, s as s
    from flext_ldap.constants import FlextLdapConstants as FlextLdapConstants, c as c
    from flext_ldap.models import FlextLdapModels as FlextLdapModels, m as m
    from flext_ldap.protocols import FlextLdapProtocols as FlextLdapProtocols, p as p
    from flext_ldap.settings import FlextLdapSettings as FlextLdapSettings
    from flext_ldap.typings import FlextLdapTypes as FlextLdapTypes, t as t
    from flext_ldap.utilities import FlextLdapUtilities as FlextLdapUtilities, u as u
    from flext_ldif import d as d, e as e, h as h, r as r, x as x
_LAZY_IMPORTS = build_lazy_import_map(
    {
        ".api": (
            "FlextLdap",
            "ldap",
        ),
        ".base": (
            "FlextLdapService",
            "s",
        ),
        ".constants": (
            "FlextLdapConstants",
            "c",
        ),
        ".models": (
            "FlextLdapModels",
            "m",
        ),
        ".protocols": (
            "FlextLdapProtocols",
            "p",
        ),
        ".settings": ("FlextLdapSettings",),
        ".typings": (
            "FlextLdapTypes",
            "t",
        ),
        ".utilities": (
            "FlextLdapUtilities",
            "u",
        ),
        "flext_ldif": (
            "d",
            "e",
            "h",
            "r",
            "x",
        ),
    },
)


__all__: tuple[str, ...] = (
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


install_lazy_exports(
    __name__,
    globals(),
    _LAZY_IMPORTS,
    public_exports=__all__,
)
