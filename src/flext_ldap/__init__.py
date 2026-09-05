# AUTO-GENERATED FILE — Regenerate with: make gen
"""Flext Ldap package."""

from __future__ import annotations

from typing import TYPE_CHECKING

from types import MappingProxyType

from flext_core.lazy import build_lazy_import_map, install_lazy_exports

from .__version__ import __author__ as __author__
from .__version__ import __author_email__ as __author_email__
from .__version__ import __description__ as __description__
from .__version__ import __license__ as __license__
from .__version__ import __title__ as __title__
from .__version__ import __url__ as __url__
from .__version__ import __version__ as __version__
from .__version__ import __version_info__ as __version_info__

if TYPE_CHECKING:
    from . import adapters as adapters
    from . import services as services
    from enum import IntEnum, StrEnum, unique
    from flext_ldif import d, e, h, r, x
    from typing import ClassVar, Final, TYPE_CHECKING

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
    "TYPE_CHECKING",
    "ClassVar",
    "Final",
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
    "IntEnum",
    "MappingProxyType",
    "StrEnum",
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
    "unique",
    "x",
)

_LAZY_IMPORTS = MappingProxyType(
    build_lazy_import_map(
        MappingProxyType({
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
            "enum": ("IntEnum", "StrEnum", "unique"),
            "flext_ldif": ("d", "e", "h", "r", "x"),
            "types": ("MappingProxyType",),
            "typing": ("ClassVar", "Final", "TYPE_CHECKING"),
        }),
        alias_groups=MappingProxyType({}),
        sort_keys=False,
    )
)

install_lazy_exports(__name__, globals(), _LAZY_IMPORTS, public_exports=__all__)
