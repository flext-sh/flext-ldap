# AUTO-GENERATED FILE — Regenerate with: make gen
"""Tests package."""

from __future__ import annotations

from typing import TYPE_CHECKING

from types import MappingProxyType

from flext_core.lazy import build_lazy_import_map, install_lazy_exports

if TYPE_CHECKING:
    from . import integration as integration
    from . import unit as unit
    from enum import StrEnum, unique
    from flext_tests import FlextTestsConstants, d, e, h, r, td, tf, tk, tm, tv, x
    from pathlib import Path
    from tempfile import gettempdir
    from typing import Final, TYPE_CHECKING

    from .base import TestsFlextLdapServiceBase, TestsFlextLdapServiceBase as s
    from .conftest import (
        WorkerInputConfig,
        ldap_container,
        pytest_runtest_makereport,
        worker_id,
    )
    from .constants import TestsFlextLdapConstants, TestsFlextLdapConstants as c
    from .models import TestsFlextLdapModels, TestsFlextLdapModels as m
    from .protocols import TestsFlextLdapProtocols, TestsFlextLdapProtocols as p
    from .settings import TestsFlextLdapSettings
    from .typings import TestsFlextLdapTypes, TestsFlextLdapTypes as t
    from .utilities import TestsFlextLdapUtilities, TestsFlextLdapUtilities as u
__all__: tuple[str, ...] = (
    "TYPE_CHECKING",
    "Final",
    "FlextTestsConstants",
    "MappingProxyType",
    "Path",
    "StrEnum",
    "TestsFlextLdapConstants",
    "TestsFlextLdapModels",
    "TestsFlextLdapProtocols",
    "TestsFlextLdapServiceBase",
    "TestsFlextLdapSettings",
    "TestsFlextLdapTypes",
    "TestsFlextLdapUtilities",
    "WorkerInputConfig",
    "c",
    "d",
    "e",
    "gettempdir",
    "h",
    "integration",
    "ldap_container",
    "m",
    "p",
    "pytest_runtest_makereport",
    "r",
    "s",
    "t",
    "td",
    "tf",
    "tk",
    "tm",
    "tv",
    "u",
    "unique",
    "unit",
    "worker_id",
    "x",
)

_LAZY_IMPORTS = MappingProxyType(
    build_lazy_import_map(
        MappingProxyType({
            ".base": ("TestsFlextLdapServiceBase", "s"),
            ".conftest": (
                "WorkerInputConfig",
                "ldap_container",
                "pytest_runtest_makereport",
                "worker_id",
            ),
            ".constants": ("TestsFlextLdapConstants", "c"),
            ".integration": ("integration",),
            ".models": ("TestsFlextLdapModels", "m"),
            ".protocols": ("TestsFlextLdapProtocols", "p"),
            ".settings": ("TestsFlextLdapSettings",),
            ".typings": ("TestsFlextLdapTypes", "t"),
            ".unit": ("unit",),
            ".utilities": ("TestsFlextLdapUtilities", "u"),
            "enum": ("StrEnum", "unique"),
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
            "pathlib": ("Path",),
            "tempfile": ("gettempdir",),
            "types": ("MappingProxyType",),
            "typing": ("Final", "TYPE_CHECKING"),
        }),
        alias_groups=MappingProxyType({}),
        sort_keys=False,
    )
)

install_lazy_exports(__name__, globals(), _LAZY_IMPORTS, public_exports=__all__)
