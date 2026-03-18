# AUTO-GENERATED FILE — DO NOT EDIT MANUALLY.
# Regenerate with: make codegen
#
"""Tests package."""

from __future__ import annotations

from typing import TYPE_CHECKING

from flext_core.lazy import cleanup_submodule_namespace, lazy_getattr

if TYPE_CHECKING:
    from flext_core.typings import FlextTypes

    from . import _utilities as _utilities, integration as integration, unit as unit
    from ._utilities.fixture_loaders import TestFixtures
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
    from .constants import TestsFlextLdapConstants, c
    from .integration.test_smoke import TestsFlextLdapSmoke, pytestmark
    from .models import TestsFlextLdapModels, m
    from .protocols import TestsFlextLdapProtocols, p
    from .typings import TestsFlextLdapTypes, t
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
    "LdapContainerDict": ("tests.conftest", "LdapContainerDict"),
    "TestFixtures": ("tests._utilities.fixture_loaders", "TestFixtures"),
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
    "TestsFlextLdapOperations": (
        "tests.unit.test_operations",
        "TestsFlextLdapOperations",
    ),
    "TestsFlextLdapProtocols": ("tests.protocols", "TestsFlextLdapProtocols"),
    "TestsFlextLdapSettings": ("tests.unit.test_config", "TestsFlextLdapSettings"),
    "TestsFlextLdapSmoke": ("tests.integration.test_smoke", "TestsFlextLdapSmoke"),
    "TestsFlextLdapSync": ("tests.unit.test_sync", "TestsFlextLdapSync"),
    "TestsFlextLdapTypes": ("tests.typings", "TestsFlextLdapTypes"),
    "TestsFlextLdapUtilities": ("tests.utilities", "TestsFlextLdapUtilities"),
    "_utilities": ("tests._utilities", ""),
    "c": ("tests.constants", "c"),
    "connection_config": ("tests.conftest", "connection_config"),
    "integration": ("tests.integration", ""),
    "ldap_container": ("tests.conftest", "ldap_container"),
    "logger": ("tests.conftest", "logger"),
    "m": ("tests.models", "m"),
    "p": ("tests.protocols", "p"),
    "pytest_runtest_makereport": ("tests.conftest", "pytest_runtest_makereport"),
    "pytest_sessionstart": ("tests.conftest", "pytest_sessionstart"),
    "pytestmark": ("tests.integration.test_smoke", "pytestmark"),
    "search_options": ("tests.conftest", "search_options"),
    "t": ("tests.typings", "t"),
    "u": ("tests.utilities", "u"),
    "unit": ("tests.unit", ""),
    "worker_id": ("tests.conftest", "worker_id"),
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
    "integration",
    "ldap_container",
    "logger",
    "m",
    "p",
    "pytest_runtest_makereport",
    "pytest_sessionstart",
    "pytestmark",
    "search_options",
    "t",
    "u",
    "unit",
    "worker_id",
]


def __getattr__(name: str) -> FlextTypes.ModuleExport:
    """Lazy-load module attributes on first access (PEP 562)."""
    return lazy_getattr(name, _LAZY_IMPORTS, globals(), __name__)


def __dir__() -> list[str]:
    """Return list of available attributes for dir() and autocomplete."""
    return sorted(__all__)


cleanup_submodule_namespace(__name__, _LAZY_IMPORTS)
