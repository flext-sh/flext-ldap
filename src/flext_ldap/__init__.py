# AUTO-GENERATED FILE — Regenerate with: make gen
"""Flext Ldap package.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from types import MappingProxyType
from typing import TYPE_CHECKING

from flext_core import install_lazy_exports
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

install_lazy_exports(
    __name__,
    globals(),
    MappingProxyType({
        "FlextLdap": ".api",
        "FlextLdapApiRuntime": ".services.api_runtime",
        "FlextLdapConfig": "._config",
        "FlextLdapConstants": ".constants",
        "FlextLdapModels": ".models",
        "FlextLdapProtocols": ".protocols",
        "FlextLdapService": ".base",
        "FlextLdapSettings": "._settings",
        "FlextLdapSync": ".services.sync",
        "FlextLdapTypes": ".typings",
        "FlextLdapUtilities": ".utilities",
        "adapters": ".adapters",
        "c": ".constants",
        "config": "._config",
        "d": "flext_ldif",
        "e": "flext_ldif",
        "h": "flext_ldif",
        "ldap": ".api",
        "m": ".models",
        "main": ".cli",
        "p": ".protocols",
        "r": "flext_ldif",
        "s": ".base",
        "services": ".services",
        "settings": "._settings",
        "t": ".typings",
        "u": ".utilities",
        "x": "flext_ldif",
    }),
    public_exports=__all__,
)
