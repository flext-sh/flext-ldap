# AUTO-GENERATED FILE — DO NOT EDIT MANUALLY.
# Regenerate with: make codegen
#
"""Tests package."""

from __future__ import annotations

from typing import TYPE_CHECKING

from flext_core.lazy import cleanup_submodule_namespace, lazy_getattr

if TYPE_CHECKING:
    from flext_core.typings import FlextTypes

    from . import helpers as helpers, unit as unit
    from .base import TestsFlextLdapServiceBase, s
    from .constants import TestsFlextLdapConstants, c
    from .helpers.operation_helpers import (
        LdapClientType,
        LdapOperationsType,
        SearchScopeType,
        TestsFlextLdapOperationHelpers,
    )
    from .models import TestsFlextLdapModels, m, tm
    from .protocols import TestsFlextLdapProtocols, p
    from .test_smoke import TestsFlextLdapSmoke, pytestmark
    from .typings import (
        GenericCallableParameterDict,
        GenericFieldsDict,
        GenericTestCaseDict,
        LdapConnectionConfigDict,
        LdapConnectionResultDict,
        LdapContainerDict,
        LdapEntryDataDict,
        LdapModifyOperationDict,
        LdapSchemaAttributeDict,
        LdapSchemaObjectClassDict,
        LdapSearchOptionsDict,
        LdapSearchResultDict,
        LdapTestScenarioDict,
        T,
        T_co,
        T_contra,
        TestsFlextLdapTypes,
        t,
        tt,
    )
    from .unit.test_api import TestsFlextLdapApi
    from .unit.test_base import TestsFlextLdapBase
    from .unit.test_config import TestsFlextLdapSettings
    from .unit.test_detection import TestsFlextLdapDetection
    from .unit.test_entry_adapter import TestsFlextLdapEntryAdapter
    from .unit.test_ldap3_adapter import TestsFlextLdap3Adapter
    from .unit.test_operations import TestsFlextLdapOperations
    from .unit.test_sync import TestsFlextLdapSync
    from .utilities import TestsFlextLdapUtilities, u

_LAZY_IMPORTS: dict[str, tuple[str, str]] = {
    "GenericCallableParameterDict": ("tests.typings", "GenericCallableParameterDict"),
    "GenericFieldsDict": ("tests.typings", "GenericFieldsDict"),
    "GenericTestCaseDict": ("tests.typings", "GenericTestCaseDict"),
    "LdapClientType": ("tests.helpers.operation_helpers", "LdapClientType"),
    "LdapConnectionConfigDict": ("tests.typings", "LdapConnectionConfigDict"),
    "LdapConnectionResultDict": ("tests.typings", "LdapConnectionResultDict"),
    "LdapContainerDict": ("tests.typings", "LdapContainerDict"),
    "LdapEntryDataDict": ("tests.typings", "LdapEntryDataDict"),
    "LdapModifyOperationDict": ("tests.typings", "LdapModifyOperationDict"),
    "LdapOperationsType": ("tests.helpers.operation_helpers", "LdapOperationsType"),
    "LdapSchemaAttributeDict": ("tests.typings", "LdapSchemaAttributeDict"),
    "LdapSchemaObjectClassDict": ("tests.typings", "LdapSchemaObjectClassDict"),
    "LdapSearchOptionsDict": ("tests.typings", "LdapSearchOptionsDict"),
    "LdapSearchResultDict": ("tests.typings", "LdapSearchResultDict"),
    "LdapTestScenarioDict": ("tests.typings", "LdapTestScenarioDict"),
    "SearchScopeType": ("tests.helpers.operation_helpers", "SearchScopeType"),
    "T": ("tests.typings", "T"),
    "T_co": ("tests.typings", "T_co"),
    "T_contra": ("tests.typings", "T_contra"),
    "TestsFlextLdap3Adapter": (
        "tests.unit.test_ldap3_adapter",
        "TestsFlextLdap3Adapter",
    ),
    "TestsFlextLdapApi": ("tests.unit.test_api", "TestsFlextLdapApi"),
    "TestsFlextLdapBase": ("tests.unit.test_base", "TestsFlextLdapBase"),
    "TestsFlextLdapConstants": ("tests.constants", "TestsFlextLdapConstants"),
    "TestsFlextLdapDetection": ("tests.unit.test_detection", "TestsFlextLdapDetection"),
    "TestsFlextLdapEntryAdapter": (
        "tests.unit.test_entry_adapter",
        "TestsFlextLdapEntryAdapter",
    ),
    "TestsFlextLdapModels": ("tests.models", "TestsFlextLdapModels"),
    "TestsFlextLdapOperationHelpers": (
        "tests.helpers.operation_helpers",
        "TestsFlextLdapOperationHelpers",
    ),
    "TestsFlextLdapOperations": (
        "tests.unit.test_operations",
        "TestsFlextLdapOperations",
    ),
    "TestsFlextLdapProtocols": ("tests.protocols", "TestsFlextLdapProtocols"),
    "TestsFlextLdapServiceBase": ("tests.base", "TestsFlextLdapServiceBase"),
    "TestsFlextLdapSettings": ("tests.unit.test_config", "TestsFlextLdapSettings"),
    "TestsFlextLdapSmoke": ("tests.test_smoke", "TestsFlextLdapSmoke"),
    "TestsFlextLdapSync": ("tests.unit.test_sync", "TestsFlextLdapSync"),
    "TestsFlextLdapTypes": ("tests.typings", "TestsFlextLdapTypes"),
    "TestsFlextLdapUtilities": ("tests.utilities", "TestsFlextLdapUtilities"),
    "c": ("tests.constants", "c"),
    "helpers": ("tests.helpers", ""),
    "m": ("tests.models", "m"),
    "p": ("tests.protocols", "p"),
    "pytestmark": ("tests.test_smoke", "pytestmark"),
    "s": ("tests.base", "s"),
    "t": ("tests.typings", "t"),
    "tm": ("tests.models", "tm"),
    "tt": ("tests.typings", "tt"),
    "u": ("tests.utilities", "u"),
    "unit": ("tests.unit", ""),
}

__all__ = [
    "GenericCallableParameterDict",
    "GenericFieldsDict",
    "GenericTestCaseDict",
    "LdapClientType",
    "LdapConnectionConfigDict",
    "LdapConnectionResultDict",
    "LdapContainerDict",
    "LdapEntryDataDict",
    "LdapModifyOperationDict",
    "LdapOperationsType",
    "LdapSchemaAttributeDict",
    "LdapSchemaObjectClassDict",
    "LdapSearchOptionsDict",
    "LdapSearchResultDict",
    "LdapTestScenarioDict",
    "SearchScopeType",
    "T",
    "T_co",
    "T_contra",
    "TestsFlextLdap3Adapter",
    "TestsFlextLdapApi",
    "TestsFlextLdapBase",
    "TestsFlextLdapConstants",
    "TestsFlextLdapDetection",
    "TestsFlextLdapEntryAdapter",
    "TestsFlextLdapModels",
    "TestsFlextLdapOperationHelpers",
    "TestsFlextLdapOperations",
    "TestsFlextLdapProtocols",
    "TestsFlextLdapServiceBase",
    "TestsFlextLdapSettings",
    "TestsFlextLdapSmoke",
    "TestsFlextLdapSync",
    "TestsFlextLdapTypes",
    "TestsFlextLdapUtilities",
    "c",
    "helpers",
    "m",
    "p",
    "pytestmark",
    "s",
    "t",
    "tm",
    "tt",
    "u",
    "unit",
]


def __getattr__(name: str) -> FlextTypes.ModuleExport:
    """Lazy-load module attributes on first access (PEP 562)."""
    return lazy_getattr(name, _LAZY_IMPORTS, globals(), __name__)


def __dir__() -> list[str]:
    """Return list of available attributes for dir() and autocomplete."""
    return sorted(__all__)


cleanup_submodule_namespace(__name__, _LAZY_IMPORTS)
