# AUTO-GENERATED FILE — Regenerate with: make gen
"""Tests package.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from flext_core.lazy import install_lazy_exports

if TYPE_CHECKING:
    from flext_tests import api, d, e, h, r, td, tf, tk, tm, x

    from flext_ldap import (
        FlextLdap,
        FlextLdapConfig,
        FlextLdapConstants,
        FlextLdapModels,
        FlextLdapModelsConfigNamespace,
        FlextLdapProtocols,
        FlextLdapService,
        FlextLdapSettings,
        FlextLdapTypes,
        FlextLdapUtilities,
        FlextLdapVersion,
        __author__,
        __author_email__,
        __description__,
        __license__,
        __title__,
        __url__,
        __version__,
        __version_info__,
        config,
        ldap,
        main,
        settings,
    )
    from tests.base import TestsFlextLdapServiceBase, s
    from tests.constants import TestsFlextLdapConstants, c
    from tests.models import TestsFlextLdapModels, m
    from tests.protocols import TestsFlextLdapProtocols, p
    from tests.settings import TestsFlextLdapSettings
    from tests.typings import TestsFlextLdapTypes, t
    from tests.utilities import TestsFlextLdapUtilities, u


__all__: tuple[str, ...] = (
    "FlextLdap",
    "FlextLdapConfig",
    "FlextLdapConstants",
    "FlextLdapModels",
    "FlextLdapModelsConfigNamespace",
    "FlextLdapProtocols",
    "FlextLdapService",
    "FlextLdapSettings",
    "FlextLdapTypes",
    "FlextLdapUtilities",
    "FlextLdapVersion",
    "TestsFlextLdapConstants",
    "TestsFlextLdapModels",
    "TestsFlextLdapProtocols",
    "TestsFlextLdapServiceBase",
    "TestsFlextLdapSettings",
    "TestsFlextLdapTypes",
    "TestsFlextLdapUtilities",
    "__author__",
    "__author_email__",
    "__description__",
    "__license__",
    "__title__",
    "__url__",
    "__version__",
    "__version_info__",
    "api",
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
    "settings",
    "t",
    "td",
    "tf",
    "tk",
    "tm",
    "u",
    "x",
)

install_lazy_exports(
    __name__,
    globals(),
    {
        "FlextLdap": "flext_ldap",
        "FlextLdapConfig": "flext_ldap",
        "FlextLdapConstants": "flext_ldap",
        "FlextLdapModels": "flext_ldap",
        "FlextLdapModelsConfigNamespace": "flext_ldap",
        "FlextLdapProtocols": "flext_ldap",
        "FlextLdapService": "flext_ldap",
        "FlextLdapSettings": "flext_ldap",
        "FlextLdapTypes": "flext_ldap",
        "FlextLdapUtilities": "flext_ldap",
        "FlextLdapVersion": "flext_ldap",
        "TestsFlextLdapConstants": ".constants",
        "TestsFlextLdapModels": ".models",
        "TestsFlextLdapProtocols": ".protocols",
        "TestsFlextLdapServiceBase": ".base",
        "TestsFlextLdapSettings": ".settings",
        "TestsFlextLdapTypes": ".typings",
        "TestsFlextLdapUtilities": ".utilities",
        "__author__": "flext_ldap",
        "__author_email__": "flext_ldap",
        "__description__": "flext_ldap",
        "__license__": "flext_ldap",
        "__title__": "flext_ldap",
        "__url__": "flext_ldap",
        "__version__": "flext_ldap",
        "__version_info__": "flext_ldap",
        "api": "flext_tests",
        "c": ".constants",
        "config": "flext_ldap",
        "d": "flext_tests",
        "e": "flext_tests",
        "h": "flext_tests",
        "ldap": "flext_ldap",
        "m": ".models",
        "main": "flext_ldap",
        "p": ".protocols",
        "r": "flext_tests",
        "s": ".base",
        "settings": "flext_ldap",
        "t": ".typings",
        "td": "flext_tests",
        "tf": "flext_tests",
        "tk": "flext_tests",
        "tm": "flext_tests",
        "u": ".utilities",
        "x": "flext_tests",
    },
    public_exports=__all__,
)
