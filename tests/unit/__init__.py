# AUTO-GENERATED FILE — DO NOT EDIT MANUALLY.
# Regenerate with: make codegen
#
"""Unit tests for flext-ldap.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

from collections.abc import Mapping, MutableMapping, Sequence
from typing import TYPE_CHECKING

from flext_core.lazy import cleanup_submodule_namespace, lazy_getattr

if TYPE_CHECKING:
    from flext_core import FlextTypes

    from tests.unit.test_api import TestsFlextLdapApi
    from tests.unit.test_base import TestsFlextLdapBase
    from tests.unit.test_config import TestsFlextLdapSettings
    from tests.unit.test_constants import TestsFlextLdapConstants
    from tests.unit.test_detection import TestsFlextLdapDetection
    from tests.unit.test_entry_adapter import TestsFlextLdapEntryAdapter
    from tests.unit.test_ldap3_adapter import TestsFlextLdap3Adapter
    from tests.unit.test_models import TestsFlextLdapModels
    from tests.unit.test_models_search import TestsFlextLdapModelsSearch
    from tests.unit.test_models_sync import TestsFlextLdapModelsSync
    from tests.unit.test_operations import TestsFlextLdapOperations
    from tests.unit.test_sync import TestsFlextLdapSync, pytestmark
    from tests.unit.test_utilities import TestsFlextLdapUtilities

_LAZY_IMPORTS: Mapping[str, Sequence[str]] = {
    "TestsFlextLdap3Adapter": [
        "tests.unit.test_ldap3_adapter",
        "TestsFlextLdap3Adapter",
    ],
    "TestsFlextLdapApi": ["tests.unit.test_api", "TestsFlextLdapApi"],
    "TestsFlextLdapBase": ["tests.unit.test_base", "TestsFlextLdapBase"],
    "TestsFlextLdapConstants": ["tests.unit.test_constants", "TestsFlextLdapConstants"],
    "TestsFlextLdapDetection": ["tests.unit.test_detection", "TestsFlextLdapDetection"],
    "TestsFlextLdapEntryAdapter": [
        "tests.unit.test_entry_adapter",
        "TestsFlextLdapEntryAdapter",
    ],
    "TestsFlextLdapModels": ["tests.unit.test_models", "TestsFlextLdapModels"],
    "TestsFlextLdapModelsSearch": [
        "tests.unit.test_models_search",
        "TestsFlextLdapModelsSearch",
    ],
    "TestsFlextLdapModelsSync": [
        "tests.unit.test_models_sync",
        "TestsFlextLdapModelsSync",
    ],
    "TestsFlextLdapOperations": [
        "tests.unit.test_operations",
        "TestsFlextLdapOperations",
    ],
    "TestsFlextLdapSettings": ["tests.unit.test_config", "TestsFlextLdapSettings"],
    "TestsFlextLdapSync": ["tests.unit.test_sync", "TestsFlextLdapSync"],
    "TestsFlextLdapUtilities": ["tests.unit.test_utilities", "TestsFlextLdapUtilities"],
    "pytestmark": ["tests.unit.test_sync", "pytestmark"],
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


_LAZY_CACHE: MutableMapping[str, FlextTypes.ModuleExport] = {}


def __getattr__(name: str) -> FlextTypes.ModuleExport:
    """Lazy-load module attributes on first access (PEP 562).

    A local cache ``_LAZY_CACHE`` persists resolved objects across repeated
    accesses during process lifetime.

    Args:
        name: Attribute name requested by dir()/import.

    Returns:
        Lazy-loaded module export type.

    Raises:
        AttributeError: If attribute not registered.

    """
    if name in _LAZY_CACHE:
        return _LAZY_CACHE[name]

    value = lazy_getattr(name, _LAZY_IMPORTS, globals(), __name__)
    _LAZY_CACHE[name] = value
    return value


def __dir__() -> Sequence[str]:
    """Return list of available attributes for dir() and autocomplete.

    Returns:
        List of public names from module exports.

    """
    return sorted(__all__)


cleanup_submodule_namespace(__name__, _LAZY_IMPORTS)
