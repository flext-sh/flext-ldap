# AUTO-GENERATED FILE — Regenerate with: make gen
"""Tests package.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from types import MappingProxyType
from typing import TYPE_CHECKING

from flext_core import install_lazy_exports

if TYPE_CHECKING:
    from flext_tests import api, d, e, h, r, td, tf, tk, tm, x

    from tests import integration, unit
    from tests.base import TestsFlextLdapServiceBase, s
    from tests.constants import TestsFlextLdapConstants, c
    from tests.models import TestsFlextLdapModels, m
    from tests.protocols import TestsFlextLdapProtocols, p
    from tests.settings import TestsFlextLdapSettings
    from tests.typings import TestsFlextLdapTypes, t
    from tests.utilities import TestsFlextLdapUtilities, u


__all__: tuple[str, ...] = (
    "TestsFlextLdapConstants",
    "TestsFlextLdapModels",
    "TestsFlextLdapProtocols",
    "TestsFlextLdapServiceBase",
    "TestsFlextLdapSettings",
    "TestsFlextLdapTypes",
    "TestsFlextLdapUtilities",
    "api",
    "c",
    "d",
    "e",
    "h",
    "integration",
    "m",
    "p",
    "r",
    "s",
    "t",
    "td",
    "tf",
    "tk",
    "tm",
    "u",
    "unit",
    "x",
)

install_lazy_exports(
    __name__,
    globals(),
    MappingProxyType({
        "TestsFlextLdapConstants": ".constants",
        "TestsFlextLdapModels": ".models",
        "TestsFlextLdapProtocols": ".protocols",
        "TestsFlextLdapServiceBase": ".base",
        "TestsFlextLdapSettings": ".settings",
        "TestsFlextLdapTypes": ".typings",
        "TestsFlextLdapUtilities": ".utilities",
        "api": "flext_tests",
        "c": ".constants",
        "d": "flext_tests",
        "e": "flext_tests",
        "h": "flext_tests",
        "integration": ".integration",
        "m": ".models",
        "p": ".protocols",
        "r": "flext_tests",
        "s": ".base",
        "t": ".typings",
        "td": "flext_tests",
        "tf": "flext_tests",
        "tk": "flext_tests",
        "tm": "flext_tests",
        "u": ".utilities",
        "unit": ".unit",
        "x": "flext_tests",
    }),
    public_exports=__all__,
)
