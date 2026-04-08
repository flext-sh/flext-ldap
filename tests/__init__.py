# AUTO-GENERATED FILE — Regenerate with: make gen
"""Tests package."""

from __future__ import annotations

import typing as _t

from flext_core.lazy import (
    build_lazy_import_map,
    install_lazy_exports,
    merge_lazy_imports,
)

if _t.TYPE_CHECKING:
    from flext_core.decorators import d
    from flext_core.exceptions import e
    from flext_core.handlers import h
    from flext_core.mixins import x
    from flext_core.result import r
    from flext_core.service import s
    from tests.constants import TestsFlextLdapConstants, TestsFlextLdapConstants as c
    from tests.models import TestsFlextLdapModels, TestsFlextLdapModels as m
    from tests.protocols import TestsFlextLdapProtocols, TestsFlextLdapProtocols as p
    from tests.typings import TestsFlextLdapTypes, TestsFlextLdapTypes as t
    from tests.utilities import TestsFlextLdapUtilities, TestsFlextLdapUtilities as u
_LAZY_IMPORTS = merge_lazy_imports(
    ("._utilities",),
    build_lazy_import_map(
        {
            ".constants": ("TestsFlextLdapConstants",),
            ".models": ("TestsFlextLdapModels",),
            ".protocols": ("TestsFlextLdapProtocols",),
            ".typings": ("TestsFlextLdapTypes",),
            ".utilities": ("TestsFlextLdapUtilities",),
            "flext_core.decorators": ("d",),
            "flext_core.exceptions": ("e",),
            "flext_core.handlers": ("h",),
            "flext_core.mixins": ("x",),
            "flext_core.result": ("r",),
            "flext_core.service": ("s",),
        },
        alias_groups={
            ".constants": (("c", "TestsFlextLdapConstants"),),
            ".models": (("m", "TestsFlextLdapModels"),),
            ".protocols": (("p", "TestsFlextLdapProtocols"),),
            ".typings": (("t", "TestsFlextLdapTypes"),),
            ".utilities": (("u", "TestsFlextLdapUtilities"),),
        },
    ),
    exclude_names=(
        "cleanup_submodule_namespace",
        "install_lazy_exports",
        "lazy_getattr",
        "logger",
        "merge_lazy_imports",
        "output",
        "output_reporting",
    ),
    module_name=__name__,
)

__all__ = [
    "TestsFlextLdapConstants",
    "TestsFlextLdapModels",
    "TestsFlextLdapProtocols",
    "TestsFlextLdapTypes",
    "TestsFlextLdapUtilities",
    "c",
    "d",
    "e",
    "h",
    "m",
    "p",
    "r",
    "s",
    "t",
    "u",
    "x",
]


install_lazy_exports(__name__, globals(), _LAZY_IMPORTS)
