# AUTO-GENERATED FILE — Regenerate with: make gen
"""Tests package."""

from __future__ import annotations

import typing as _t

from flext_core.lazy import install_lazy_exports, merge_lazy_imports

if _t.TYPE_CHECKING:
    from flext_core.decorators import FlextDecorators as d
    from flext_core.exceptions import FlextExceptions as e
    from flext_core.handlers import FlextHandlers as h
    from flext_core.mixins import FlextMixins as x
    from flext_core.result import FlextResult as r
    from flext_core.service import FlextService as s
    from tests.constants import TestsFlextLdapConstants, TestsFlextLdapConstants as c
    from tests.models import TestsFlextLdapModels, TestsFlextLdapModels as m
    from tests.protocols import TestsFlextLdapProtocols, TestsFlextLdapProtocols as p
    from tests.typings import TestsFlextLdapTypes, TestsFlextLdapTypes as t
    from tests.utilities import TestsFlextLdapUtilities, TestsFlextLdapUtilities as u
_LAZY_IMPORTS = merge_lazy_imports(
    ("._utilities",),
    {
        "TestsFlextLdapConstants": ".constants",
        "TestsFlextLdapModels": ".models",
        "TestsFlextLdapProtocols": ".protocols",
        "TestsFlextLdapTypes": ".typings",
        "TestsFlextLdapUtilities": ".utilities",
        "c": (".constants", "TestsFlextLdapConstants"),
        "d": ("flext_core.decorators", "FlextDecorators"),
        "e": ("flext_core.exceptions", "FlextExceptions"),
        "h": ("flext_core.handlers", "FlextHandlers"),
        "m": (".models", "TestsFlextLdapModels"),
        "p": (".protocols", "TestsFlextLdapProtocols"),
        "r": ("flext_core.result", "FlextResult"),
        "s": ("flext_core.service", "FlextService"),
        "t": (".typings", "TestsFlextLdapTypes"),
        "u": (".utilities", "TestsFlextLdapUtilities"),
        "x": ("flext_core.mixins", "FlextMixins"),
    },
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
