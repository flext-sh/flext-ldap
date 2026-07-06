# AUTO-GENERATED FILE — Regenerate with: make gen
"""Flext Ldap package."""

from __future__ import annotations

from typing import TYPE_CHECKING

from flext_core.lazy import install_lazy_exports
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
from flext_ldap._exports import (
    FLEXT_LDAP_LAZY_IMPORTS,
    FLEXT_LDAP_PUBLIC_EXPORTS,
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


_LAZY_IMPORTS = {
    name: target
    for name, target in FLEXT_LDAP_LAZY_IMPORTS.items()
    if name in FLEXT_LDAP_PUBLIC_EXPORTS
}


_EAGER_EXPORTS = (
    __author__,
    __author_email__,
    __description__,
    __license__,
    __title__,
    __url__,
    __version__,
    __version_info__,
)


_PUBLIC_EXPORTS: tuple[str, ...] = FLEXT_LDAP_PUBLIC_EXPORTS

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
    public_exports=_PUBLIC_EXPORTS,
)
