# AUTO-GENERATED FILE — Regenerate with: make gen
"""Flext Ldap package.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from collections.abc import (
    Iterable,
    Iterator,
    Mapping,
    MutableMapping,
    MutableSequence,
    Sequence,
)

from types import MappingProxyType
from typing import TYPE_CHECKING

from flext_core.lazy import install_lazy_exports

if TYPE_CHECKING:
    from flext_ldif import (
        build_lazy_import_map,
        cleanup_submodule_namespace,
        cli,
        core,
        d,
        e,
        h,
        install_lazy_exports,
        lazy,
        lazy_getattr,
        lazy_member,
        ldif,
        merge_lazy_imports,
        normalize_lazy_imports,
        r,
        resolve_lazy_members,
        x,
    )

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
    from flext_ldap.config_models import FlextLdapModelsConfigNamespace
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
    "FlextLdapModelsConfigNamespace",
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
        "FlextLdapModelsConfigNamespace": ".config_models",
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
        "build_lazy_import_map": "flext_ldif",
        "c": ".constants",
        "cleanup_submodule_namespace": "flext_ldif",
        "cli": "flext_ldif",
        "config": "._config",
        "core": "flext_ldif",
        "d": "flext_ldif",
        "e": "flext_ldif",
        "h": "flext_ldif",
        "install_lazy_exports": "flext_ldif",
        "lazy": "flext_ldif",
        "lazy_getattr": "flext_ldif",
        "lazy_member": "flext_ldif",
        "ldap": ".api",
        "ldif": "flext_ldif",
        "m": ".models",
        "main": ".cli",
        "merge_lazy_imports": "flext_ldif",
        "normalize_lazy_imports": "flext_ldif",
        "p": ".protocols",
        "r": "flext_ldif",
        "resolve_lazy_members": "flext_ldif",
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
