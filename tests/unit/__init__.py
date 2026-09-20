# AUTO-GENERATED FILE — Regenerate with: make gen
"""Tests.unit package."""

from __future__ import annotations

from types import MappingProxyType
from typing import TYPE_CHECKING

from flext_core.lazy import build_lazy_import_map, install_lazy_exports

if TYPE_CHECKING:
    from flext_tests import c, d, e, h, m, p, r, s, t, td, tf, tk, tm, tv, u, x

    from .test_connection import TestsFlextLdapConnection
    from .test_entry_adapter import TestsFlextLdapEntryAdapter
    from .test_models import TestsFlextLdapModelsUnit
    from .test_models_search import TestsFlextLdapModelsSearch
    from .test_sync import TestsFlextLdapSync
    from .test_utilities import TestsFlextLdapUtilitiesUnit
__all__: tuple[str, ...] = (
    "TestsFlextLdapConnection",
    "TestsFlextLdapEntryAdapter",
    "TestsFlextLdapModelsSearch",
    "TestsFlextLdapModelsUnit",
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
            ".test_connection": ("TestsFlextLdapConnection",),
            ".test_entry_adapter": ("TestsFlextLdapEntryAdapter",),
            ".test_models": ("TestsFlextLdapModelsUnit",),
            ".test_models_search": ("TestsFlextLdapModelsSearch",),
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
