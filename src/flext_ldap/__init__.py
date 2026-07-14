# AUTO-GENERATED FILE — Regenerate with: make gen
"""Flext Ldap package."""

from __future__ import annotations

from typing import TYPE_CHECKING

from flext_core.lazy import build_lazy_import_map, install_lazy_exports
from flext_ldap.__version__ import (
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
    from flext_ldif import d, e, h, r, x

    from ._config import FlextLdapConfig, config
    from ._models.ldap import FlextLdapModelsLdap
    from ._settings import FlextLdapSettings, settings
    from ._utilities.comparison import FlextLdapUtilitiesComparison
    from ._utilities.conversion import FlextLdapUtilitiesConversion
    from ._utilities.detection import FlextLdapUtilitiesDetection
    from ._utilities.normalization import FlextLdapUtilitiesNormalization
    from ._utilities.root_dse import FlextLdapUtilitiesRootDse
    from ._utilities.server import FlextLdapUtilitiesServer
    from ._utilities.validation import FlextLdapUtilitiesValidation
    from .adapters._ldap3.connection_manager import ConnectionManager
    from .adapters._ldap3.operation_executor import OperationExecutor
    from .adapters._ldap3.result_converter import ResultConverter
    from .adapters._ldap3.result_extract import ResultConverterExtractMixin
    from .adapters._ldap3.search_executor import SearchExecutor
    from .adapters._ldap3.wrappers import FlextLdapLdap3Wrappers
    from .adapters.entry import FlextLdapEntryAdapter
    from .adapters.ldap3 import FlextLdapAdapterHost, FlextLdapLdap3Adapter
    from .api import FlextLdap, ldap
    from .base import FlextLdapService, s
    from .constants import FlextLdapConstants, FlextLdapConstants as c
    from .models import FlextLdapModels, FlextLdapModels as m
    from .protocols import FlextLdapProtocols, FlextLdapProtocols as p
    from .services.api_runtime import FlextLdapApiRuntime
    from .services.connection import FlextLdapConnection
    from .services.detection import FlextLdapServerDetector
    from .services.operations import FlextLdapOperations
    from .services.sync import FlextLdapSync
    from .typings import FlextLdapTypes, FlextLdapTypes as t
    from .utilities import FlextLdapUtilities, FlextLdapUtilities as u

    _ = (
        c,
        FlextLdapConstants,
        t,
        FlextLdapTypes,
        p,
        FlextLdapProtocols,
        m,
        FlextLdapModels,
        u,
        FlextLdapUtilities,
        d,
        e,
        h,
        r,
        x,
        s,
        FlextLdapService,
        FlextLdapConfig,
        config,
        FlextLdapModelsLdap,
        FlextLdapSettings,
        settings,
        FlextLdapUtilitiesComparison,
        FlextLdapUtilitiesConversion,
        FlextLdapUtilitiesDetection,
        FlextLdapUtilitiesNormalization,
        FlextLdapUtilitiesRootDse,
        FlextLdapUtilitiesServer,
        FlextLdapUtilitiesValidation,
        ConnectionManager,
        OperationExecutor,
        ResultConverter,
        ResultConverterExtractMixin,
        SearchExecutor,
        FlextLdapLdap3Wrappers,
        FlextLdapEntryAdapter,
        FlextLdapAdapterHost,
        FlextLdapLdap3Adapter,
        FlextLdap,
        ldap,
        FlextLdapApiRuntime,
        FlextLdapConnection,
        FlextLdapServerDetector,
        FlextLdapOperations,
        FlextLdapSync,
    )


_LAZY_MODULES: dict[str, tuple[str, ...]] = {
    "._config": (
        "FlextLdapConfig",
        "config",
    ),
    "._models.ldap": ("FlextLdapModelsLdap",),
    "._settings": (
        "FlextLdapSettings",
        "settings",
    ),
    "._utilities.comparison": ("FlextLdapUtilitiesComparison",),
    "._utilities.conversion": ("FlextLdapUtilitiesConversion",),
    "._utilities.detection": ("FlextLdapUtilitiesDetection",),
    "._utilities.normalization": ("FlextLdapUtilitiesNormalization",),
    "._utilities.root_dse": ("FlextLdapUtilitiesRootDse",),
    "._utilities.server": ("FlextLdapUtilitiesServer",),
    "._utilities.validation": ("FlextLdapUtilitiesValidation",),
    ".adapters._ldap3.connection_manager": ("ConnectionManager",),
    ".adapters._ldap3.operation_executor": ("OperationExecutor",),
    ".adapters._ldap3.result_converter": ("ResultConverter",),
    ".adapters._ldap3.result_extract": ("ResultConverterExtractMixin",),
    ".adapters._ldap3.search_executor": ("SearchExecutor",),
    ".adapters._ldap3.wrappers": ("FlextLdapLdap3Wrappers",),
    ".adapters.entry": ("FlextLdapEntryAdapter",),
    ".adapters.ldap3": (
        "FlextLdapAdapterHost",
        "FlextLdapLdap3Adapter",
    ),
    ".api": (
        "FlextLdap",
        "ldap",
    ),
    ".base": (
        "FlextLdapService",
        "s",
    ),
    ".constants": (
        "FlextLdapConstants",
        "c",
    ),
    ".models": (
        "FlextLdapModels",
        "m",
    ),
    ".protocols": (
        "FlextLdapProtocols",
        "p",
    ),
    ".services.api_runtime": ("FlextLdapApiRuntime",),
    ".services.connection": ("FlextLdapConnection",),
    ".services.detection": ("FlextLdapServerDetector",),
    ".services.operations": ("FlextLdapOperations",),
    ".services.sync": ("FlextLdapSync",),
    ".typings": (
        "FlextLdapTypes",
        "t",
    ),
    ".utilities": (
        "FlextLdapUtilities",
        "u",
    ),
    "flext_ldif": (
        "d",
        "e",
        "h",
        "r",
        "x",
    ),
}


_LAZY_ALIAS_GROUPS: dict[str, tuple[tuple[str, str], ...]] = {}


_LAZY_IMPORTS = build_lazy_import_map(
    _LAZY_MODULES,
    alias_groups=_LAZY_ALIAS_GROUPS,
    sort_keys=False,
)

_DIRECT_IMPORTS: tuple[str, ...] = (
    "ConnectionManager",
    "FlextLdap",
    "FlextLdapAdapterHost",
    "FlextLdapApiRuntime",
    "FlextLdapConfig",
    "FlextLdapConnection",
    "FlextLdapConstants",
    "FlextLdapEntryAdapter",
    "FlextLdapLdap3Adapter",
    "FlextLdapLdap3Wrappers",
    "FlextLdapModels",
    "FlextLdapModelsLdap",
    "FlextLdapOperations",
    "FlextLdapProtocols",
    "FlextLdapServerDetector",
    "FlextLdapService",
    "FlextLdapSettings",
    "FlextLdapSync",
    "FlextLdapTypes",
    "FlextLdapUtilities",
    "FlextLdapUtilitiesComparison",
    "FlextLdapUtilitiesConversion",
    "FlextLdapUtilitiesDetection",
    "FlextLdapUtilitiesNormalization",
    "FlextLdapUtilitiesRootDse",
    "FlextLdapUtilitiesServer",
    "FlextLdapUtilitiesValidation",
    "OperationExecutor",
    "ResultConverter",
    "ResultConverterExtractMixin",
    "SearchExecutor",
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
    "config",
    "d",
    "e",
    "h",
    "install_lazy_exports",
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

__all__: tuple[str, ...] = (
    "FlextLdap",
    "FlextLdapAdapterHost",
    "FlextLdapApiRuntime",
    "FlextLdapConnection",
    "FlextLdapConstants",
    "FlextLdapEntryAdapter",
    "FlextLdapLdap3Adapter",
    "FlextLdapModels",
    "FlextLdapOperations",
    "FlextLdapProtocols",
    "FlextLdapServerDetector",
    "FlextLdapService",
    "FlextLdapSettings",
    "FlextLdapSync",
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


install_lazy_exports(
    __name__,
    globals(),
    _LAZY_IMPORTS,
    public_exports=__all__,
)
