# AUTO-GENERATED FILE — Regenerate with: make gen
"""Tests package."""

from __future__ import annotations

from types import MappingProxyType
from typing import TYPE_CHECKING

from flext_core.lazy import build_lazy_import_map, install_lazy_exports

if TYPE_CHECKING:
    from flext_cli import cli
    from flext_ldif import ldif
    from flext_tests import (
        active_rules,
        api,
        config,
        discover_repository_root,
        install_local_packages,
        load_infra_report,
        settings,
        split_csv,
        td,
        tf,
        tk,
        tm,
        tv,
    )

    from flext_core import core, d, e, h, lazy_attribute, r, x
    from flext_ldap import ldap, main

    from . import integration, unit
    from .base import TestsFlextLdapServiceBase, TestsFlextLdapServiceBase as s
    from .constants import TestsFlextLdapConstants, c
    from .models import TestsFlextLdapModels, m
    from .protocols import TestsFlextLdapProtocols, TestsFlextLdapProtocols as p
    from .settings import TestsFlextLdapSettings
    from .typings import TestsFlextLdapTypes, t
    from .utilities import TestsFlextLdapUtilities, u
__all__: tuple[str, ...] = (
    "TestsFlextLdapConstants",
    "TestsFlextLdapModels",
    "TestsFlextLdapProtocols",
    "TestsFlextLdapServiceBase",
    "TestsFlextLdapSettings",
    "TestsFlextLdapTypes",
    "TestsFlextLdapUtilities",
    "active_rules",
    "api",
    "c",
    "cli",
    "config",
    "core",
    "d",
    "discover_repository_root",
    "e",
    "h",
    "install_local_packages",
    "integration",
    "lazy_attribute",
    "ldap",
    "ldif",
    "load_infra_report",
    "m",
    "main",
    "p",
    "r",
    "s",
    "settings",
    "split_csv",
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
            "flext_cli": ("cli",),
            "flext_core": ("core", "d", "e", "h", "lazy_attribute", "r", "x"),
            "flext_ldap": ("ldap", "main"),
            "flext_ldif": ("ldif",),
            "flext_tests": (
                "active_rules",
                "api",
                "config",
                "discover_repository_root",
                "install_local_packages",
                "load_infra_report",
                "settings",
                "split_csv",
                "td",
                "tf",
                "tk",
                "tm",
                "tv",
            ),
        }),
        alias_groups=MappingProxyType({}),
        sort_keys=False,
    )
)

install_lazy_exports(__name__, globals(), _LAZY_IMPORTS, public_exports=__all__)
