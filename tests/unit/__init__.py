# AUTO-GENERATED FILE — DO NOT EDIT MANUALLY.
# Regenerate with: make codegen
#
"""Unit tests for flext-ldap.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

from typing import TYPE_CHECKING

from flext_core.lazy import cleanup_submodule_namespace, lazy_getattr

if TYPE_CHECKING:
    from flext_core.typings import FlextTypes

    from .test_api import TestsFlextLdapApi
    from .test_base import TestsFlextLdapBase
    from .test_config import TestsFlextLdapSettings
    from .test_constants import TestsFlextLdapConstants
    from .test_detection import TestsFlextLdapDetection
    from .test_entry_adapter import TestsFlextLdapEntryAdapter
    from .test_ldap3_adapter import TestsFlextLdap3Adapter
    from .test_models import TestsFlextLdapModels
    from .test_models_search import TestsFlextLdapModelsSearch
    from .test_models_sync import TestsFlextLdapModelsSync
    from .test_operations import TestsFlextLdapOperations
    from .test_sync import TestsFlextLdapSync, pytestmark
    from .test_utilities import TestsFlextLdapUtilities

_LAZY_IMPORTS: dict[str, tuple[str, str]] = {
    "TestsFlextLdap3Adapter": (
        "tests.unit.test_ldap3_adapter",
        "TestsFlextLdap3Adapter",
    ),
    "TestsFlextLdapApi": ("tests.unit.test_api", "TestsFlextLdapApi"),
    "TestsFlextLdapBase": ("tests.unit.test_base", "TestsFlextLdapBase"),
    "TestsFlextLdapConstants": ("tests.unit.test_constants", "TestsFlextLdapConstants"),
    "TestsFlextLdapDetection": ("tests.unit.test_detection", "TestsFlextLdapDetection"),
    "TestsFlextLdapEntryAdapter": (
        "tests.unit.test_entry_adapter",
        "TestsFlextLdapEntryAdapter",
    ),
    "TestsFlextLdapModels": ("tests.unit.test_models", "TestsFlextLdapModels"),
    "TestsFlextLdapModelsSearch": (
        "tests.unit.test_models_search",
        "TestsFlextLdapModelsSearch",
    ),
    "TestsFlextLdapModelsSync": (
        "tests.unit.test_models_sync",
        "TestsFlextLdapModelsSync",
    ),
    "TestsFlextLdapOperations": (
        "tests.unit.test_operations",
        "TestsFlextLdapOperations",
    ),
    "TestsFlextLdapSettings": ("tests.unit.test_config", "TestsFlextLdapSettings"),
    "TestsFlextLdapSync": ("tests.unit.test_sync", "TestsFlextLdapSync"),
    "TestsFlextLdapUtilities": ("tests.unit.test_utilities", "TestsFlextLdapUtilities"),
    "pytestmark": ("tests.unit.test_sync", "pytestmark"),
}

__all__ = [
    "TestsFlextLdap3Adapter",
    "TestsFlextLdapApi",
    "TestsFlextLdapBase",
    "TestsFlextLdapConstants",
    "TestsFlextLdapDetection",
    "TestsFlextLdapEntryAdapter",
    "TestsFlextLdapModels",
    "TestsFlextLdapModelsSearch",
    "TestsFlextLdapModelsSync",
    "TestsFlextLdapOperations",
    "TestsFlextLdapSettings",
    "TestsFlextLdapSync",
    "TestsFlextLdapUtilities",
    "pytestmark",
]


def __getattr__(name: str) -> FlextTypes.ModuleExport:
    """Lazy-load module attributes on first access (PEP 562)."""
    return lazy_getattr(name, _LAZY_IMPORTS, globals(), __name__)


def __dir__() -> list[str]:
    """Return list of available attributes for dir() and autocomplete."""
    return sorted(__all__)


cleanup_submodule_namespace(__name__, _LAZY_IMPORTS)
