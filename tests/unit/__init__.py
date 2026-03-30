# AUTO-GENERATED FILE — DO NOT EDIT MANUALLY.
# Regenerate with: make gen
#
"""Unit tests for flext-ldap.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import TYPE_CHECKING

from flext_core.lazy import install_lazy_exports

if TYPE_CHECKING:
    from tests.unit import (
        test_api as test_api,
        test_base as test_base,
        test_config as test_config,
        test_constants as test_constants,
        test_detection as test_detection,
        test_entry_adapter as test_entry_adapter,
        test_ldap3_adapter as test_ldap3_adapter,
        test_models as test_models,
        test_models_search as test_models_search,
        test_models_sync as test_models_sync,
        test_operations as test_operations,
        test_sync as test_sync,
        test_utilities as test_utilities,
    )
    from tests.unit.test_api import TestsFlextLdapApi as TestsFlextLdapApi
    from tests.unit.test_base import TestsFlextLdapBase as TestsFlextLdapBase
    from tests.unit.test_config import TestsFlextLdapSettings as TestsFlextLdapSettings
    from tests.unit.test_constants import (
        TestsFlextLdapConstants as TestsFlextLdapConstants,
    )
    from tests.unit.test_detection import (
        TestsFlextLdapDetection as TestsFlextLdapDetection,
    )
    from tests.unit.test_entry_adapter import (
        TestsFlextLdapEntryAdapter as TestsFlextLdapEntryAdapter,
    )
    from tests.unit.test_ldap3_adapter import (
        TestsFlextLdap3Adapter as TestsFlextLdap3Adapter,
    )
    from tests.unit.test_models import TestsFlextLdapModels as TestsFlextLdapModels
    from tests.unit.test_models_search import (
        TestsFlextLdapModelsSearch as TestsFlextLdapModelsSearch,
    )
    from tests.unit.test_models_sync import (
        TestsFlextLdapModelsSync as TestsFlextLdapModelsSync,
    )
    from tests.unit.test_operations import (
        TestsFlextLdapOperations as TestsFlextLdapOperations,
        pytestmark as pytestmark,
    )
    from tests.unit.test_sync import TestsFlextLdapSync as TestsFlextLdapSync
    from tests.unit.test_utilities import (
        TestsFlextLdapUtilities as TestsFlextLdapUtilities,
    )

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
    "pytestmark": ["tests.unit.test_operations", "pytestmark"],
    "test_api": ["tests.unit.test_api", ""],
    "test_base": ["tests.unit.test_base", ""],
    "test_config": ["tests.unit.test_config", ""],
    "test_constants": ["tests.unit.test_constants", ""],
    "test_detection": ["tests.unit.test_detection", ""],
    "test_entry_adapter": ["tests.unit.test_entry_adapter", ""],
    "test_ldap3_adapter": ["tests.unit.test_ldap3_adapter", ""],
    "test_models": ["tests.unit.test_models", ""],
    "test_models_search": ["tests.unit.test_models_search", ""],
    "test_models_sync": ["tests.unit.test_models_sync", ""],
    "test_operations": ["tests.unit.test_operations", ""],
    "test_sync": ["tests.unit.test_sync", ""],
    "test_utilities": ["tests.unit.test_utilities", ""],
}

_EXPORTS: Sequence[str] = [
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
    "test_api",
    "test_base",
    "test_config",
    "test_constants",
    "test_detection",
    "test_entry_adapter",
    "test_ldap3_adapter",
    "test_models",
    "test_models_search",
    "test_models_sync",
    "test_operations",
    "test_sync",
    "test_utilities",
]


install_lazy_exports(__name__, globals(), _LAZY_IMPORTS, _EXPORTS)
