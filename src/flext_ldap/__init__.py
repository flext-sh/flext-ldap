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
    from flext_ldif import d, e, h, r, x

    from ._config import FlextLdapConfig, config
    from ._settings import FlextLdapSettings, settings
    from .api import FlextLdap, ldap
    from .base import FlextLdapService, s
    from .constants import FlextLdapConstants, FlextLdapConstants as c
    from .models import FlextLdapModels, FlextLdapModels as m
    from .protocols import FlextLdapProtocols, FlextLdapProtocols as p
    from .typings import FlextLdapTypes, FlextLdapTypes as t
    from .utilities import FlextLdapUtilities, FlextLdapUtilities as u

    _ = (
        c,
        FlextLdapConstants,
        t,
        FlextLdapTypes,
        p,
        FlextLdapProtocols,
        m,
        FlextLdapModels,
        u,
        FlextLdapUtilities,
        d,
        e,
        h,
        r,
        x,
        s,
        FlextLdapService,
        FlextLdapConfig,
        config,
        FlextLdapSettings,
        settings,
        FlextLdap,
        ldap,
    )


_LAZY_MODULES: dict[str, tuple[str, ...]] = {
    "._config": ("FlextLdapConfig", "config"),
    "._settings": ("FlextLdapSettings", "settings"),
    ".api": ("FlextLdap", "ldap"),
    ".base": ("FlextLdapService", "s"),
    ".constants": ("FlextLdapConstants", "c"),
    ".models": ("FlextLdapModels", "m"),
    ".protocols": ("FlextLdapProtocols", "p"),
    ".typings": ("FlextLdapTypes", "t"),
    ".utilities": ("FlextLdapUtilities", "u"),
    "flext_ldif": ("d", "e", "h", "r", "x"),
}


_LAZY_ALIAS_GROUPS: dict[str, tuple[tuple[str, str], ...]] = {}


_LAZY_IMPORTS = build_lazy_import_map(
    _LAZY_MODULES, alias_groups=_LAZY_ALIAS_GROUPS, sort_keys=False
)

_DIRECT_IMPORTS: tuple[str, ...] = (
    "FlextLdap",
    "FlextLdapConfig",
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
    "build_lazy_import_map",
    "c",
    "config",
    "d",
    "e",
    "h",
    "install_lazy_exports",
    "ldap",
    "m",
    "p",
    "r",
    "s",
    "settings",
    "t",
    "u",
    "x",
)

__all__: tuple[str, ...] = (
    "FlextLdap",
    "FlextLdapConfig",
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
    "config",
    "d",
    "e",
    "h",
    "ldap",
    "m",
    "p",
    "r",
    "s",
    "settings",
    "t",
    "u",
    "x",
)


install_lazy_exports(__name__, globals(), _LAZY_IMPORTS, public_exports=__all__)
