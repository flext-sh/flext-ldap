# AUTO-GENERATED FILE — DO NOT EDIT MANUALLY.
# Regenerate with: make codegen
#
"""Tests package."""

from __future__ import annotations

from typing import TYPE_CHECKING

from flext_core.lazy import cleanup_submodule_namespace, lazy_getattr

if TYPE_CHECKING:
    from flext_core.typings import FlextTypes
    from flext_tests import d, e, h, r, s, x

    from . import _utilities as _utilities, integration as integration, unit as unit
    from ._utilities import TestFixtures
    from .conftest import (
        LdapContainerDict,
        connection_config,
        ldap_container,
        logger,
        pytest_runtest_makereport,
        pytest_sessionstart,
        search_options,
        worker_id,
    )
    from .constants import TestsFlextLdapConstants, TestsFlextLdapConstants as c
    from .integration import TestsFlextLdapSmoke, pytestmark
    from .models import TestsFlextLdapModels, TestsFlextLdapModels as m
    from .protocols import TestsFlextLdapProtocols, TestsFlextLdapProtocols as p
    from .typings import TestsFlextLdapTypes, TestsFlextLdapTypes as t
    from .unit import (
        TestsFlextLdap3Adapter,
        TestsFlextLdapApi,
        TestsFlextLdapBase,
        TestsFlextLdapDetection,
        TestsFlextLdapEntryAdapter,
        TestsFlextLdapModelsSearch,
        TestsFlextLdapModelsSync,
        TestsFlextLdapOperations,
        TestsFlextLdapSettings,
        TestsFlextLdapSync,
    )
    from .utilities import TestsFlextLdapUtilities, TestsFlextLdapUtilities as u

_LAZY_IMPORTS: dict[str, tuple[str, str]] = {
    "LdapContainerDict": ("tests.conftest", "LdapContainerDict"),
    "TestFixtures": ("tests._utilities", "TestFixtures"),
    "TestsFlextLdap3Adapter": ("tests.unit", "TestsFlextLdap3Adapter"),
    "TestsFlextLdapApi": ("tests.unit", "TestsFlextLdapApi"),
    "TestsFlextLdapBase": ("tests.unit", "TestsFlextLdapBase"),
    "TestsFlextLdapConstants": ("tests.constants", "TestsFlextLdapConstants"),
    "TestsFlextLdapDetection": ("tests.unit", "TestsFlextLdapDetection"),
    "TestsFlextLdapEntryAdapter": ("tests.unit", "TestsFlextLdapEntryAdapter"),
    "TestsFlextLdapModels": ("tests.models", "TestsFlextLdapModels"),
    "TestsFlextLdapModelsSearch": ("tests.unit", "TestsFlextLdapModelsSearch"),
    "TestsFlextLdapModelsSync": ("tests.unit", "TestsFlextLdapModelsSync"),
    "TestsFlextLdapOperations": ("tests.unit", "TestsFlextLdapOperations"),
    "TestsFlextLdapProtocols": ("tests.protocols", "TestsFlextLdapProtocols"),
    "TestsFlextLdapSettings": ("tests.unit", "TestsFlextLdapSettings"),
    "TestsFlextLdapSmoke": ("tests.integration", "TestsFlextLdapSmoke"),
    "TestsFlextLdapSync": ("tests.unit", "TestsFlextLdapSync"),
    "TestsFlextLdapTypes": ("tests.typings", "TestsFlextLdapTypes"),
    "TestsFlextLdapUtilities": ("tests.utilities", "TestsFlextLdapUtilities"),
    "_utilities": ("tests._utilities", ""),
    "c": ("tests.constants", "TestsFlextLdapConstants"),
    "connection_config": ("tests.conftest", "connection_config"),
    "d": ("flext_tests", "d"),
    "e": ("flext_tests", "e"),
    "h": ("flext_tests", "h"),
    "integration": ("tests.integration", ""),
    "ldap_container": ("tests.conftest", "ldap_container"),
    "logger": ("tests.conftest", "logger"),
    "m": ("tests.models", "TestsFlextLdapModels"),
    "p": ("tests.protocols", "TestsFlextLdapProtocols"),
    "pytest_runtest_makereport": ("tests.conftest", "pytest_runtest_makereport"),
    "pytest_sessionstart": ("tests.conftest", "pytest_sessionstart"),
    "pytestmark": ("tests.integration", "pytestmark"),
    "r": ("flext_tests", "r"),
    "s": ("flext_tests", "s"),
    "search_options": ("tests.conftest", "search_options"),
    "t": ("tests.typings", "TestsFlextLdapTypes"),
    "u": ("tests.utilities", "TestsFlextLdapUtilities"),
    "unit": ("tests.unit", ""),
    "worker_id": ("tests.conftest", "worker_id"),
    "x": ("flext_tests", "x"),
}

__all__ = [
    "LdapContainerDict",
    "TestFixtures",
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
    "TestsFlextLdapProtocols",
    "TestsFlextLdapSettings",
    "TestsFlextLdapSmoke",
    "TestsFlextLdapSync",
    "TestsFlextLdapTypes",
    "TestsFlextLdapUtilities",
    "_utilities",
    "c",
    "connection_config",
    "d",
    "e",
    "h",
    "integration",
    "ldap_container",
    "logger",
    "m",
    "p",
    "pytest_runtest_makereport",
    "pytest_sessionstart",
    "pytestmark",
    "r",
    "s",
    "search_options",
    "t",
    "u",
    "unit",
    "worker_id",
    "x",
]


def __getattr__(name: str) -> FlextTypes.ModuleExport:
    """Lazy-load module attributes on first access (PEP 562)."""
    return lazy_getattr(name, _LAZY_IMPORTS, globals(), __name__)


def __dir__() -> list[str]:
    """Return list of available attributes for dir() and autocomplete."""
    return sorted(__all__)


cleanup_submodule_namespace(__name__, _LAZY_IMPORTS)
