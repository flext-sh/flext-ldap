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
        test_api,
        test_base,
        test_config,
        test_constants,
        test_detection,
        test_entry_adapter,
        test_ldap3_adapter,
        test_models,
        test_models_search,
        test_models_sync,
        test_operations,
        test_sync,
        test_utilities,
    )
    from tests.unit.test_api import *
    from tests.unit.test_base import *
    from tests.unit.test_config import *
    from tests.unit.test_constants import *
    from tests.unit.test_detection import *
    from tests.unit.test_entry_adapter import *
    from tests.unit.test_ldap3_adapter import *
    from tests.unit.test_models import *
    from tests.unit.test_models_search import *
    from tests.unit.test_models_sync import *
    from tests.unit.test_operations import *
    from tests.unit.test_sync import *
    from tests.unit.test_utilities import *

_LAZY_IMPORTS: Mapping[str, str | Sequence[str]] = {
    "TestsFlextLdap3Adapter": "tests.unit.test_ldap3_adapter",
    "TestsFlextLdapApi": "tests.unit.test_api",
    "TestsFlextLdapBase": "tests.unit.test_base",
    "TestsFlextLdapConstants": "tests.unit.test_constants",
    "TestsFlextLdapDetection": "tests.unit.test_detection",
    "TestsFlextLdapEntryAdapter": "tests.unit.test_entry_adapter",
    "TestsFlextLdapModels": "tests.unit.test_models",
    "TestsFlextLdapModelsSearch": "tests.unit.test_models_search",
    "TestsFlextLdapModelsSync": "tests.unit.test_models_sync",
    "TestsFlextLdapOperations": "tests.unit.test_operations",
    "TestsFlextLdapSettings": "tests.unit.test_config",
    "TestsFlextLdapSync": "tests.unit.test_sync",
    "TestsFlextLdapUtilities": "tests.unit.test_utilities",
    "pytestmark": "tests.unit.test_operations",
    "test_api": "tests.unit.test_api",
    "test_base": "tests.unit.test_base",
    "test_config": "tests.unit.test_config",
    "test_constants": "tests.unit.test_constants",
    "test_detection": "tests.unit.test_detection",
    "test_entry_adapter": "tests.unit.test_entry_adapter",
    "test_ldap3_adapter": "tests.unit.test_ldap3_adapter",
    "test_models": "tests.unit.test_models",
    "test_models_search": "tests.unit.test_models_search",
    "test_models_sync": "tests.unit.test_models_sync",
    "test_operations": "tests.unit.test_operations",
    "test_sync": "tests.unit.test_sync",
    "test_utilities": "tests.unit.test_utilities",
}


install_lazy_exports(__name__, globals(), _LAZY_IMPORTS, sorted(_LAZY_IMPORTS))
