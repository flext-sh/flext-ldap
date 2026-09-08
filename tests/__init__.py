# AUTO-GENERATED FILE — Regenerate with: make gen
"""Tests package."""

from __future__ import annotations

from types import MappingProxyType
from typing import TYPE_CHECKING

from flext_core.lazy import build_lazy_import_map, install_lazy_exports

if TYPE_CHECKING:
    from flext_tests import FlextTestsConstants, d, e, h, r, td, tf, tk, tm, tv, x

    from . import integration, unit
    from .base import TestsFlextLdapServiceBase, TestsFlextLdapServiceBase as s
    from .constants import TestsFlextLdapConstants, TestsFlextLdapConstants as c
    from .models import TestsFlextLdapModels, TestsFlextLdapModels as m
    from .protocols import TestsFlextLdapProtocols, TestsFlextLdapProtocols as p
    from .settings import TestsFlextLdapSettings
    from .typings import TestsFlextLdapTypes, TestsFlextLdapTypes as t
    from .utilities import TestsFlextLdapUtilities, TestsFlextLdapUtilities as u
__all__: tuple[str, ...] = (
    "FlextTestsConstants",
    "TestsFlextLdapConstants",
    "TestsFlextLdapModels",
    "TestsFlextLdapProtocols",
    "TestsFlextLdapServiceBase",
    "TestsFlextLdapSettings",
    "TestsFlextLdapTypes",
    "TestsFlextLdapUtilities",
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
    "tv",
    "u",
    "unit",
    "x",
)

_LAZY_IMPORTS = MappingProxyType(
    build_lazy_import_map(
        MappingProxyType({
            ".base": ("TestsFlextLdapServiceBase", "s"),
            ".constants": ("TestsFlextLdapConstants", "c"),
            ".integration": ("integration",),
            ".models": ("TestsFlextLdapModels", "m"),
            ".protocols": ("TestsFlextLdapProtocols", "p"),
            ".settings": ("TestsFlextLdapSettings",),
            ".typings": ("TestsFlextLdapTypes", "t"),
            ".unit": ("unit",),
            ".utilities": ("TestsFlextLdapUtilities", "u"),
            "flext_tests": (
                "FlextTestsConstants",
                "d",
                "e",
                "h",
                "r",
                "td",
                "tf",
                "tk",
                "tm",
                "tv",
                "x",
            ),
        }),
        alias_groups=MappingProxyType({}),
        sort_keys=False,
    )
)

install_lazy_exports(__name__, globals(), _LAZY_IMPORTS, public_exports=__all__)
