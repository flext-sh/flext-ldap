"""Test infrastructure for flext-ldap tests.

Provides centralized test objects that extend production modules from src/flext_ldap/.
All test objects use real inheritance to expose the full hierarchy without duplication.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from flext_core.lazy import cleanup_submodule_namespace, lazy_getattr

if TYPE_CHECKING:
    from flext_core import FlextDecorators as d, FlextExceptions as e, r, x

    from .base import TestsFlextLdapServiceBase, TestsFlextLdapServiceBase as s
    from .constants import TestsFlextLdapConstants, TestsFlextLdapConstants as c
    from .models import TestsFlextLdapModels, TestsFlextLdapModels as m
    from .protocols import TestsFlextLdapProtocols, TestsFlextLdapProtocols as p
    from .typings import TestsFlextLdapTypes, TestsFlextLdapTypes as t, tt
    from .utilities import TestsFlextLdapUtilities, TestsFlextLdapUtilities as u
_LAZY_IMPORTS: dict[str, tuple[str, str]] = {
    "TestsFlextLdapConstants": ("tests.constants", "TestsFlextLdapConstants"),
    "TestsFlextLdapModels": ("tests.models", "TestsFlextLdapModels"),
    "TestsFlextLdapProtocols": ("tests.protocols", "TestsFlextLdapProtocols"),
    "TestsFlextLdapServiceBase": ("tests.base", "TestsFlextLdapServiceBase"),
    "TestsFlextLdapTypes": ("tests.typings", "TestsFlextLdapTypes"),
    "TestsFlextLdapUtilities": ("tests.utilities", "TestsFlextLdapUtilities"),
    "c": ("tests.constants", "TestsFlextLdapConstants"),
    "d": ("flext_core", "FlextDecorators"),
    "e": ("flext_core", "FlextExceptions"),
    "m": ("tests.models", "TestsFlextLdapModels"),
    "p": ("tests.protocols", "TestsFlextLdapProtocols"),
    "r": ("flext_core", "r"),
    "s": ("tests.base", "TestsFlextLdapServiceBase"),
    "t": ("tests.typings", "TestsFlextLdapTypes"),
    "tt": ("tests.typings", "tt"),
    "u": ("tests.utilities", "TestsFlextLdapUtilities"),
    "x": ("flext_core", "x"),
}
__all__ = [
    "TestsFlextLdapConstants",
    "TestsFlextLdapModels",
    "TestsFlextLdapProtocols",
    "TestsFlextLdapServiceBase",
    "TestsFlextLdapTypes",
    "TestsFlextLdapUtilities",
    "c",
    "d",
    "e",
    "m",
    "p",
    "r",
    "s",
    "t",
    "tt",
    "u",
    "x",
]


def __getattr__(name: str) -> Any:
    """Lazy-load module attributes on first access (PEP 562)."""
    return lazy_getattr(name, _LAZY_IMPORTS, globals(), __name__)


def __dir__() -> list[str]:
    """Return list of available attributes for dir() and autocomplete."""
    return sorted(__all__)


cleanup_submodule_namespace(__name__, _LAZY_IMPORTS)
