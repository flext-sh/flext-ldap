# @generated AUTO-GENERATED FILE — Regenerate with: make gen
"""Flext Ldap package."""

from __future__ import annotations

from typing import TYPE_CHECKING

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
    from flext_ldif import d as d
    from flext_ldif import e as e
    from flext_ldif import h as h
    from flext_ldif import r as r
    from flext_ldif import x as x

    from ._config import FlextLdapConfig as FlextLdapConfig
    from ._config import config as config
    from ._settings import FlextLdapSettings as FlextLdapSettings
    from ._settings import settings as settings
    from .api import FlextLdap as FlextLdap
    from .api import ldap as ldap
    from .base import FlextLdapService as FlextLdapService
    from .base import s as s
    from .constants import FlextLdapConstants as FlextLdapConstants

    c: type[FlextLdapConstants]
    from .models import FlextLdapModels as FlextLdapModels

    m: type[FlextLdapModels]
    from .protocols import FlextLdapProtocols as FlextLdapProtocols

    p: type[FlextLdapProtocols]
    from .typings import FlextLdapTypes as FlextLdapTypes

    t: type[FlextLdapTypes]
    from .utilities import FlextLdapUtilities as FlextLdapUtilities

    u: type[FlextLdapUtilities]

_LAZY_MODULES: dict[str, tuple[str, ...]] = {
    "._config": ("FlextLdapConfig", "config"),
    "._settings": ("FlextLdapSettings", "settings"),
    ".api": ("FlextLdap", "ldap"),
    ".base": ("FlextLdapService", "s"),
    ".constants": ("FlextLdapConstants", "c"),
    ".models": ("FlextLdapModels", "m"),
    ".protocols": ("FlextLdapProtocols", "p"),
    ".typings": ("FlextLdapTypes", "t"),
    ".utilities": ("FlextLdapUtilities", "u"),
    "flext_ldif": ("d", "e", "h", "r", "x"),
}


_LAZY_ALIAS_GROUPS: dict[str, tuple[tuple[str, str], ...]] = {}


_LAZY_IMPORTS = build_lazy_import_map(
    _LAZY_MODULES, alias_groups=_LAZY_ALIAS_GROUPS, sort_keys=False
)

_PUBLIC_EXPORTS: tuple[str, ...] = (
    "FlextLdap",
    "FlextLdapConfig",
    "FlextLdapConstants",
    "FlextLdapModels",
    "FlextLdapProtocols",
    "FlextLdapService",
    "FlextLdapSettings",
    "FlextLdapTypes",
    "FlextLdapUtilities",
    "__author__",
    "__author_email__",
    "__description__",
    "__license__",
    "__title__",
    "__url__",
    "__version__",
    "__version_info__",
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
    "settings",
    "t",
    "u",
    "x",
)

__all__: tuple[str, ...] = tuple(_PUBLIC_EXPORTS)

install_lazy_exports(__name__, globals(), _LAZY_IMPORTS, public_exports=__all__)
