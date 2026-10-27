# AUTO-GENERATED FILE — Regenerate with: make gen
"""Tests package.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from types import MappingProxyType
from typing import TYPE_CHECKING

from flext_core.lazy import install_lazy_exports

if TYPE_CHECKING:
    from flext_tests import (
        api,
        cli,
        config,
        d,
        e,
        h,
        install_local_packages,
        main,
        r,
        settings,
        td,
        tf,
        tk,
        tm,
        x,
    )

    from flext_ldap import (
        build_lazy_import_map,
        cleanup_submodule_namespace,
        core,
        install_lazy_exports,
        lazy,
        lazy_getattr,
        lazy_member,
        ldap,
        ldif,
        merge_lazy_imports,
        normalize_lazy_imports,
        resolve_lazy_members,
    )
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
    "build_lazy_import_map",
    "c",
    "cleanup_submodule_namespace",
    "cli",
    "config",
    "core",
    "d",
    "e",
    "h",
    "install_lazy_exports",
    "install_local_packages",
    "lazy",
    "lazy_getattr",
    "lazy_member",
    "ldap",
    "ldif",
    "m",
    "main",
    "merge_lazy_imports",
    "normalize_lazy_imports",
    "p",
    "r",
    "resolve_lazy_members",
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
    MappingProxyType({
        "TestsFlextLdapConstants": ".constants",
        "TestsFlextLdapModels": ".models",
        "TestsFlextLdapProtocols": ".protocols",
        "TestsFlextLdapServiceBase": ".base",
        "TestsFlextLdapSettings": ".settings",
        "TestsFlextLdapTypes": ".typings",
        "TestsFlextLdapUtilities": ".utilities",
        "api": "flext_tests",
        "build_lazy_import_map": "flext_ldap",
        "c": ".constants",
        "cleanup_submodule_namespace": "flext_ldap",
        "cli": "flext_tests",
        "config": "flext_tests",
        "core": "flext_ldap",
        "d": "flext_tests",
        "e": "flext_tests",
        "h": "flext_tests",
        "install_lazy_exports": "flext_ldap",
        "install_local_packages": "flext_tests",
        "lazy": "flext_ldap",
        "lazy_getattr": "flext_ldap",
        "lazy_member": "flext_ldap",
        "ldap": "flext_ldap",
        "ldif": "flext_ldap",
        "m": ".models",
        "main": "flext_tests",
        "merge_lazy_imports": "flext_ldap",
        "normalize_lazy_imports": "flext_ldap",
        "p": ".protocols",
        "r": "flext_tests",
        "resolve_lazy_members": "flext_ldap",
        "s": ".base",
        "settings": "flext_tests",
        "t": ".typings",
        "td": "flext_tests",
        "tf": "flext_tests",
        "tk": "flext_tests",
        "tm": "flext_tests",
        "u": ".utilities",
        "x": "flext_tests",
    }),
    public_exports=__all__,
)
