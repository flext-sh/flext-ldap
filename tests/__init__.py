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
        config,
        ldap,
        main,
        settings,
    )
    from flext_ldap.adapters import (
        FlextLdapAdapterHost,
        FlextLdapEntryAdapter,
        FlextLdapLdap3Adapter,
    )
    from flext_ldap.services import (
        FlextLdapApiRuntime,
        FlextLdapConnection,
        FlextLdapOperations,
        FlextLdapServicesSubtree,
        FlextLdapServicesUpsert,
        FlextLdapSync,
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
    "FlextLdapAdapterHost",
    "FlextLdapApiRuntime",
    "FlextLdapConfig",
    "FlextLdapConnection",
    "FlextLdapConstants",
    "FlextLdapEntryAdapter",
    "FlextLdapLdap3Adapter",
    "FlextLdapModels",
    "FlextLdapModelsConfigNamespace",
    "FlextLdapOperations",
    "FlextLdapProtocols",
    "FlextLdapService",
    "FlextLdapServicesSubtree",
    "FlextLdapServicesUpsert",
    "FlextLdapSettings",
    "FlextLdapSync",
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
        "FlextLdapAdapterHost": "flext_ldap.adapters",
        "FlextLdapApiRuntime": "flext_ldap.services",
        "FlextLdapConfig": "flext_ldap",
        "FlextLdapConnection": "flext_ldap.services",
        "FlextLdapConstants": "flext_ldap",
        "FlextLdapEntryAdapter": "flext_ldap.adapters",
        "FlextLdapLdap3Adapter": "flext_ldap.adapters",
        "FlextLdapModels": "flext_ldap",
        "FlextLdapModelsConfigNamespace": "flext_ldap",
        "FlextLdapOperations": "flext_ldap.services",
        "FlextLdapProtocols": "flext_ldap",
        "FlextLdapService": "flext_ldap",
        "FlextLdapServicesSubtree": "flext_ldap.services",
        "FlextLdapServicesUpsert": "flext_ldap.services",
        "FlextLdapSettings": "flext_ldap",
        "FlextLdapSync": "flext_ldap.services",
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
