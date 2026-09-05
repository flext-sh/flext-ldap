# AUTO-GENERATED FILE — Regenerate with: make gen
"""Tests.unit package."""

from __future__ import annotations

from typing import TYPE_CHECKING

from types import MappingProxyType

from flext_core.lazy import build_lazy_import_map, install_lazy_exports

if TYPE_CHECKING:
    from flext_tests import c, d, e, h, m, p, r, s, t, td, tf, tk, tm, tv, u, x

    from .test_api import TestsFlextLdapApi
    from .test_base import TestsFlextLdapBase
    from .test_config import TestsFlextLdapConfig
    from .test_connection import TestsFlextLdapConnection
    from .test_constants import TestsFlextLdapConstantsUnit
    from .test_detection import TestsFlextLdapDetection
    from .test_entry_adapter import TestsFlextLdapEntryAdapter
    from .test_ldap3_adapter import TestsFlextLdapLdap3Adapter
    from .test_models import TestsFlextLdapModelsUnit
    from .test_models_search import TestsFlextLdapModelsSearch
    from .test_models_sync import TestsFlextLdapModelsSync
    from .test_operations import TestsFlextLdapOperations
    from .test_public_api_contract import TestsFlextLdapPublicApiContract
    from .test_sync import TestsFlextLdapSync
    from .test_utilities import TestsFlextLdapUtilitiesUnit
__all__: tuple[str, ...] = (
    "TestsFlextLdapApi",
    "TestsFlextLdapBase",
    "TestsFlextLdapConfig",
    "TestsFlextLdapConnection",
    "TestsFlextLdapConstantsUnit",
    "TestsFlextLdapDetection",
    "TestsFlextLdapEntryAdapter",
    "TestsFlextLdapLdap3Adapter",
    "TestsFlextLdapModelsSearch",
    "TestsFlextLdapModelsSync",
    "TestsFlextLdapModelsUnit",
    "TestsFlextLdapOperations",
    "TestsFlextLdapPublicApiContract",
    "TestsFlextLdapSync",
    "TestsFlextLdapUtilitiesUnit",
    "c",
    "d",
    "e",
    "h",
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
    "x",
)

_LAZY_IMPORTS = MappingProxyType(
    build_lazy_import_map(
        MappingProxyType({
            ".test_api": ("TestsFlextLdapApi",),
            ".test_base": ("TestsFlextLdapBase",),
            ".test_config": ("TestsFlextLdapConfig",),
            ".test_connection": ("TestsFlextLdapConnection",),
            ".test_constants": ("TestsFlextLdapConstantsUnit",),
            ".test_detection": ("TestsFlextLdapDetection",),
            ".test_entry_adapter": ("TestsFlextLdapEntryAdapter",),
            ".test_ldap3_adapter": ("TestsFlextLdapLdap3Adapter",),
            ".test_models": ("TestsFlextLdapModelsUnit",),
            ".test_models_search": ("TestsFlextLdapModelsSearch",),
            ".test_models_sync": ("TestsFlextLdapModelsSync",),
            ".test_operations": ("TestsFlextLdapOperations",),
            ".test_public_api_contract": ("TestsFlextLdapPublicApiContract",),
            ".test_sync": ("TestsFlextLdapSync",),
            ".test_utilities": ("TestsFlextLdapUtilitiesUnit",),
            "flext_tests": (
                "c",
                "d",
                "e",
                "h",
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
                "x",
            ),
        }),
        alias_groups=MappingProxyType({}),
        sort_keys=False,
    )
)

install_lazy_exports(__name__, globals(), _LAZY_IMPORTS, public_exports=__all__)
