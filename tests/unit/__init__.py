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
    from flext_ldap import (
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
    from flext_ldap.test_api import TestsFlextLdapApi
    from flext_ldap.test_config import TestsFlextLdapSettings
    from flext_ldap.test_constants import TestsFlextLdapConstants
    from flext_ldap.test_detection import TestsFlextLdapDetection
    from flext_ldap.test_entry_adapter import TestsFlextLdapEntryAdapter
    from flext_ldap.test_ldap3_adapter import TestsFlextLdap3Adapter
    from flext_ldap.test_models import TestsFlextLdapModels
    from flext_ldap.test_models_search import TestsFlextLdapModelsSearch
    from flext_ldap.test_models_sync import TestsFlextLdapModelsSync
    from flext_ldap.test_operations import TestsFlextLdapOperations, pytestmark
    from flext_ldap.test_sync import TestsFlextLdapSync
    from flext_ldap.test_utilities import TestsFlextLdapUtilities

_LAZY_IMPORTS: FlextTypes.LazyImportIndex = {
    "TestsFlextLdap3Adapter": "flext_ldap.test_ldap3_adapter",
    "TestsFlextLdapApi": "flext_ldap.test_api",
    "TestsFlextLdapConstants": "flext_ldap.test_constants",
    "TestsFlextLdapDetection": "flext_ldap.test_detection",
    "TestsFlextLdapEntryAdapter": "flext_ldap.test_entry_adapter",
    "TestsFlextLdapModels": "flext_ldap.test_models",
    "TestsFlextLdapModelsSearch": "flext_ldap.test_models_search",
    "TestsFlextLdapModelsSync": "flext_ldap.test_models_sync",
    "TestsFlextLdapOperations": "flext_ldap.test_operations",
    "TestsFlextLdapSettings": "flext_ldap.test_config",
    "TestsFlextLdapSync": "flext_ldap.test_sync",
    "TestsFlextLdapUtilities": "flext_ldap.test_utilities",
    "c": ("flext_core.constants", "FlextConstants"),
    "d": ("flext_core.decorators", "FlextDecorators"),
    "e": ("flext_core.exceptions", "FlextExceptions"),
    "h": ("flext_core.handlers", "FlextHandlers"),
    "m": ("flext_core.models", "FlextModels"),
    "p": ("flext_core.protocols", "FlextProtocols"),
    "pytestmark": "flext_ldap.test_operations",
    "r": ("flext_core.result", "FlextResult"),
    "s": ("flext_core.service", "FlextService"),
    "t": ("flext_core.typings", "FlextTypes"),
    "test_api": "flext_ldap.test_api",
    "test_base": "flext_ldap.test_base",
    "test_config": "flext_ldap.test_config",
    "test_constants": "flext_ldap.test_constants",
    "test_detection": "flext_ldap.test_detection",
    "test_entry_adapter": "flext_ldap.test_entry_adapter",
    "test_ldap3_adapter": "flext_ldap.test_ldap3_adapter",
    "test_models": "flext_ldap.test_models",
    "test_models_search": "flext_ldap.test_models_search",
    "test_models_sync": "flext_ldap.test_models_sync",
    "test_operations": "flext_ldap.test_operations",
    "test_sync": "flext_ldap.test_sync",
    "test_utilities": "flext_ldap.test_utilities",
    "u": ("flext_core.utilities", "FlextUtilities"),
    "x": ("flext_core.mixins", "FlextMixins"),
}


install_lazy_exports(__name__, globals(), _LAZY_IMPORTS)
