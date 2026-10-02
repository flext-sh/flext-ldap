# AUTO-GENERATED FILE — Regenerate with: make gen
"""Flext Ldap package.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from types import MappingProxyType
from typing import TYPE_CHECKING

from flext_core import build_lazy_import_map, install_lazy_exports


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

    from flext_ldap import adapters, services
    from flext_ldap._config import FlextLdapConfig, config
    from flext_ldap._settings import FlextLdapSettings, settings
    from flext_ldap.api import FlextLdap, ldap
    from flext_ldap.base import FlextLdapService, s
    from flext_ldap.cli import main
    from flext_ldap.constants import FlextLdapConstants, c
    from flext_ldap.models import FlextLdapModels, m
    from flext_ldap.protocols import FlextLdapProtocols, p
    from flext_ldap.services.api_runtime import FlextLdapApiRuntime
    from flext_ldap.services.sync import FlextLdapSync
    from flext_ldap.typings import FlextLdapTypes, t
    from flext_ldap.utilities import FlextLdapUtilities, u


__all__: tuple[str, ...] = (
    "FlextLdap",
    "FlextLdapApiRuntime",
    "FlextLdapConfig",
    "FlextLdapConstants",
    "FlextLdapModels",
    "FlextLdapProtocols",
    "FlextLdapService",
    "FlextLdapSettings",
    "FlextLdapSync",
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
    "adapters",
    "c",
    "config",
    "d",
    "e",
    "h",
    "ldap",
    "m",
    "main",
    "p",
    "r",
    "s",
    "services",
    "settings",
    "t",
    "u",
    "x",
)

_LAZY_IMPORTS = MappingProxyType(
    build_lazy_import_map(
        MappingProxyType({
            "._config": ("FlextLdapConfig", "config"),
            "._settings": ("FlextLdapSettings", "settings"),
            ".adapters": ("adapters",),
            ".api": ("FlextLdap", "ldap"),
            ".base": ("FlextLdapService", "s"),
            ".cli": ("main",),
            ".constants": ("FlextLdapConstants", "c"),
            ".models": ("FlextLdapModels", "m"),
            ".protocols": ("FlextLdapProtocols", "p"),
            ".services": ("services",),
            ".services.api_runtime": ("FlextLdapApiRuntime",),
            ".services.sync": ("FlextLdapSync",),
            ".typings": ("FlextLdapTypes", "t"),
            ".utilities": ("FlextLdapUtilities", "u"),
            "flext_ldif": ("d", "e", "h", "r", "x"),
        }),
        alias_groups=MappingProxyType({}),
        sort_keys=False,
    ),
)

install_lazy_exports(__name__, globals(), _LAZY_IMPORTS, public_exports=__all__)
