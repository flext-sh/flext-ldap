# AUTO-GENERATED FILE — DO NOT EDIT MANUALLY.
# Regenerate with: make codegen
#
"""Unit tests for flext-ldap.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from flext_core.lazy import cleanup_submodule_namespace, lazy_getattr

if TYPE_CHECKING:
    from tests.unit.test_api import TestsFlextLdapApi
    from tests.unit.test_base import TestsFlextLdapBase
    from tests.unit.test_config import TestsFlextLdapSettings
    from tests.unit.test_constants_optimized import (
        TestsFlextLdapConstants,
        TestsFlextLdapConstants as c,
    )
    from tests.unit.test_detection import TestsFlextLdapDetection
    from tests.unit.test_entry_adapter import TestsFlextLdapEntryAdapter
    from tests.unit.test_ldap3_adapter import TestsFlextLdap3Adapter
    from tests.unit.test_models import TestsFlextLdapModels, TestsFlextLdapModels as m
    from tests.unit.test_operations import TestsFlextLdapOperations
    from tests.unit.test_sync import TestsFlextLdapSync
    from tests.unit.test_utilities import (
        TestsFlextLdapUtilities,
        TestsFlextLdapUtilities as u,
        pytestmark,
    )

# Lazy import mapping: export_name -> (module_path, attr_name)
_LAZY_IMPORTS: dict[str, tuple[str, str]] = {
    "TestsFlextLdap3Adapter": (
        "tests.unit.test_ldap3_adapter",
        "TestsFlextLdap3Adapter",
    ),
    "TestsFlextLdapApi": ("tests.unit.test_api", "TestsFlextLdapApi"),
    "TestsFlextLdapBase": ("tests.unit.test_base", "TestsFlextLdapBase"),
    "TestsFlextLdapConstants": (
        "tests.unit.test_constants_optimized",
        "TestsFlextLdapConstants",
    ),
    "TestsFlextLdapDetection": ("tests.unit.test_detection", "TestsFlextLdapDetection"),
    "TestsFlextLdapEntryAdapter": (
        "tests.unit.test_entry_adapter",
        "TestsFlextLdapEntryAdapter",
    ),
    "TestsFlextLdapModels": ("tests.unit.test_models", "TestsFlextLdapModels"),
    "TestsFlextLdapOperations": (
        "tests.unit.test_operations",
        "TestsFlextLdapOperations",
    ),
    "TestsFlextLdapSettings": ("tests.unit.test_config", "TestsFlextLdapSettings"),
    "TestsFlextLdapSync": ("tests.unit.test_sync", "TestsFlextLdapSync"),
    "TestsFlextLdapUtilities": ("tests.unit.test_utilities", "TestsFlextLdapUtilities"),
    "c": ("tests.unit.test_constants_optimized", "TestsFlextLdapConstants"),
    "m": ("tests.unit.test_models", "TestsFlextLdapModels"),
    "pytestmark": ("tests.unit.test_utilities", "pytestmark"),
    "u": ("tests.unit.test_utilities", "TestsFlextLdapUtilities"),
}

__all__ = [
    "TestsFlextLdap3Adapter",
    "TestsFlextLdapApi",
    "TestsFlextLdapBase",
    "TestsFlextLdapConstants",
    "TestsFlextLdapDetection",
    "TestsFlextLdapEntryAdapter",
    "TestsFlextLdapModels",
    "TestsFlextLdapOperations",
    "TestsFlextLdapSettings",
    "TestsFlextLdapSync",
    "TestsFlextLdapUtilities",
    "c",
    "m",
    "pytestmark",
    "u",
]


def __getattr__(name: str) -> Any:
    """Lazy-load module attributes on first access (PEP 562)."""
    return lazy_getattr(name, _LAZY_IMPORTS, globals(), __name__)


def __dir__() -> list[str]:
    """Return list of available attributes for dir() and autocomplete."""
    return sorted(__all__)


cleanup_submodule_namespace(__name__, _LAZY_IMPORTS)
