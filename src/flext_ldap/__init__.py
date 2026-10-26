# AUTO-GENERATED FILE — Regenerate with: make gen
"""Flext Ldap package.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from types import MappingProxyType
from typing import TYPE_CHECKING

from flext_core.lazy import install_lazy_exports

if TYPE_CHECKING:
    from flext_ldif import cli, d, e, h, ldif, r, x

    from flext_ldap.__version__ import (
        FlextLdapVersion,
        __author__,
        __author_email__,
        __description__,
        __license__,
        __title__,
        __url__,
        __version__,
        __version_info__,
    )
    from flext_ldap._config import FlextLdapConfig, config
    from flext_ldap._settings import FlextLdapSettings, settings
    from flext_ldap.api import FlextLdap, ldap
    from flext_ldap.base import FlextLdapService, s
    from flext_ldap.cli import main
    from flext_ldap.constants import FlextLdapConstants, c
    from flext_ldap.models import FlextLdapModels, m
    from flext_ldap.protocols import FlextLdapProtocols, p
    from flext_ldap.typings import FlextLdapTypes, t
    from flext_ldap.utilities import FlextLdapUtilities, u


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
    "FlextLdapVersion",
    "__author__",
    "__author_email__",
    "__description__",
    "__license__",
    "__title__",
    "__url__",
    "__version__",
    "__version_info__",
    "c",
    "cli",
    "config",
    "d",
    "e",
    "h",
    "ldap",
    "ldif",
    "m",
    "main",
    "p",
    "r",
    "s",
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
        "FlextLdapConfig": "._config",
        "FlextLdapConstants": ".constants",
        "FlextLdapModels": ".models",
        "FlextLdapProtocols": ".protocols",
        "FlextLdapService": ".base",
        "FlextLdapSettings": "._settings",
        "FlextLdapTypes": ".typings",
        "FlextLdapUtilities": ".utilities",
        "FlextLdapVersion": ".__version__",
        "__author__": ".__version__",
        "__author_email__": ".__version__",
        "__description__": ".__version__",
        "__license__": ".__version__",
        "__title__": ".__version__",
        "__url__": ".__version__",
        "__version_info__": ".__version__",
        "c": ".constants",
        "cli": "flext_ldif",
        "config": "._config",
        "d": "flext_ldif",
        "e": "flext_ldif",
        "h": "flext_ldif",
        "ldap": ".api",
        "ldif": "flext_ldif",
        "m": ".models",
        "main": ".cli",
        "p": ".protocols",
        "r": "flext_ldif",
        "s": ".base",
        "settings": "._settings",
        "t": ".typings",
        "u": ".utilities",
        "x": "flext_ldif",
    }),
    public_exports=__all__,
)

if not TYPE_CHECKING:
    from flext_ldap.__version__ import __version__
