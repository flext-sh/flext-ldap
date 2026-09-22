# AUTO-GENERATED FILE — Regenerate with: make gen
"""Flext Ldap package."""

from __future__ import annotations

from types import MappingProxyType
from typing import TYPE_CHECKING

from flext_core.lazy import build_lazy_import_map, install_lazy_exports

from .__version__ import (
    __author__ as __author__,
    __author_email__ as __author_email__,
    __description__ as __description__,
    __license__ as __license__,
    __title__ as __title__,
    __url__ as __url__,
    __version__ as __version__,
    __version_info__ as __version_info__,
)

if TYPE_CHECKING:
    from flext_cli import cli
    from flext_ldif import ldif
    from pydantic_core import from_json, to_json, to_jsonable_python

    from flext_core import core, d, e, h, lazy_attribute, r, x

    from . import adapters, services
    from .__version__ import FlextLdapVersion
    from ._config import FlextLdapConfig, config
    from ._settings import FlextLdapSettings, settings
    from .api import FlextLdap, ldap
    from .base import FlextLdapService, s
    from .constants import FlextLdapConstants, FlextLdapConstants as c
    from .models import FlextLdapModels, FlextLdapModels as m
    from .protocols import FlextLdapProtocols, FlextLdapProtocols as p
    from .services.api_runtime import FlextLdapApiRuntime
    from .services.sync import FlextLdapSync
    from .typings import FlextLdapTypes, FlextLdapTypes as t
    from .utilities import FlextLdapUtilities, FlextLdapUtilities as u
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
    "FlextLdapVersion",
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
    "p",
    "r",
    "s",
    "services",
    "settings",
    "t",
    "u",
    "x",
)

_LAZY_IMPORTS = MappingProxyType(
    build_lazy_import_map(
        MappingProxyType({
            ".__version__": ("FlextLdapVersion",),
            "._config": ("FlextLdapConfig", "config"),
            "._settings": ("FlextLdapSettings", "settings"),
            ".adapters": ("adapters",),
            ".api": ("FlextLdap", "ldap"),
            ".base": ("FlextLdapService", "s"),
            ".constants": ("FlextLdapConstants", "c"),
            ".models": ("FlextLdapModels", "m"),
            ".protocols": ("FlextLdapProtocols", "p"),
            ".services": ("services",),
            ".services.api_runtime": ("FlextLdapApiRuntime",),
            ".services.sync": ("FlextLdapSync",),
            ".typings": ("FlextLdapTypes", "t"),
            ".utilities": ("FlextLdapUtilities", "u"),
            "flext_cli": ("cli",),
            "flext_core": ("core", "d", "e", "h", "lazy_attribute", "r", "x"),
            "flext_ldif": ("ldif",),
            "pydantic_core": ("from_json", "to_json", "to_jsonable_python"),
        }),
        alias_groups=MappingProxyType({}),
        sort_keys=False,
    )
)

install_lazy_exports(__name__, globals(), _LAZY_IMPORTS, public_exports=__all__)
