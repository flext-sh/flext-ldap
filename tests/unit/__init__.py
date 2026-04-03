# AUTO-GENERATED FILE — DO NOT EDIT MANUALLY.
# Regenerate with: make gen
#
"""Unit package."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import TYPE_CHECKING as _TYPE_CHECKING

from flext_core.lazy import install_lazy_exports

if _TYPE_CHECKING:
    from flext_core import FlextTypes
    from flext_core.constants import FlextConstants as c
    from flext_core.decorators import FlextDecorators as d
    from flext_core.exceptions import FlextExceptions as e
    from flext_core.handlers import FlextHandlers as h
    from flext_core.mixins import FlextMixins as x
    from flext_core.models import FlextModels as m
    from flext_core.protocols import FlextProtocols as p
    from flext_core.result import FlextResult as r
    from flext_core.service import FlextService as s
    from flext_core.typings import FlextTypes as t
    from flext_core.utilities import FlextUtilities as u
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
    from tests.unit.test_operations import TestsFlextLdapOperations, pytestmark
    from tests.unit.test_sync import TestsFlextLdapSync
    from tests.unit.test_utilities import TestsFlextLdapUtilities

_LAZY_IMPORTS: FlextTypes.LazyImportIndex = {
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
    "c": ("flext_core.constants", "FlextConstants"),
    "d": ("flext_core.decorators", "FlextDecorators"),
    "e": ("flext_core.exceptions", "FlextExceptions"),
    "h": ("flext_core.handlers", "FlextHandlers"),
    "m": ("flext_core.models", "FlextModels"),
    "p": ("flext_core.protocols", "FlextProtocols"),
    "pytestmark": "tests.unit.test_operations",
    "r": ("flext_core.result", "FlextResult"),
    "s": ("flext_core.service", "FlextService"),
    "t": ("flext_core.typings", "FlextTypes"),
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
    "u": ("flext_core.utilities", "FlextUtilities"),
    "x": ("flext_core.mixins", "FlextMixins"),
}


install_lazy_exports(__name__, globals(), _LAZY_IMPORTS)
