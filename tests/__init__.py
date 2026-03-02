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
    from base import TestsFlextLdapServiceBase, TestsFlextLdapServiceBase as s
    from constants import TestsFlextLdapConstants, TestsFlextLdapConstants as c
    from flext_core import FlextDecorators as d, FlextExceptions as e, r, x
    from models import TestsFlextLdapModels, TestsFlextLdapModels as m
    from protocols import TestsFlextLdapProtocols, TestsFlextLdapProtocols as p
    from typings import TestsFlextLdapTypes, TestsFlextLdapTypes as t, tt
    from utilities import TestsFlextLdapUtilities, TestsFlextLdapUtilities as u

# Lazy import mapping: export_name -> (module_path, attr_name)
_LAZY_IMPORTS: dict[str, tuple[str, str]] = {
    "TestsFlextLdapConstants": ("constants", "TestsFlextLdapConstants"),
    "TestsFlextLdapModels": ("models", "TestsFlextLdapModels"),
    "TestsFlextLdapProtocols": ("protocols", "TestsFlextLdapProtocols"),
    "TestsFlextLdapServiceBase": ("base", "TestsFlextLdapServiceBase"),
    "TestsFlextLdapTypes": ("typings", "TestsFlextLdapTypes"),
    "TestsFlextLdapUtilities": ("utilities", "TestsFlextLdapUtilities"),
    "c": ("constants", "TestsFlextLdapConstants"),
    "d": ("flext_core", "FlextDecorators"),
    "e": ("flext_core", "FlextExceptions"),
    "m": ("models", "TestsFlextLdapModels"),
    "p": ("protocols", "TestsFlextLdapProtocols"),
    "r": ("flext_core", "r"),
    "s": ("base", "TestsFlextLdapServiceBase"),
    "t": ("typings", "TestsFlextLdapTypes"),
    "tt": ("typings", "tt"),
    "u": ("utilities", "TestsFlextLdapUtilities"),
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


def __getattr__(name: str) -> Any:  # noqa: ANN401
    """Lazy-load module attributes on first access (PEP 562)."""
    return lazy_getattr(name, _LAZY_IMPORTS, globals(), __name__)


def __dir__() -> list[str]:
    """Return list of available attributes for dir() and autocomplete."""
    return sorted(__all__)


cleanup_submodule_namespace(__name__, _LAZY_IMPORTS)
