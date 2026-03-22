# AUTO-GENERATED FILE — DO NOT EDIT MANUALLY.
# Regenerate with: make codegen
#
"""Tests package."""

from __future__ import annotations

from typing import TYPE_CHECKING

from flext_core.lazy import cleanup_submodule_namespace, lazy_getattr

if TYPE_CHECKING:
    from flext_core import FlextTypes
    from flext_tests import d, e, h, r, s, x

    from . import _utilities as _utilities, integration as integration, unit as unit
    from ._utilities.docker_infra import _DockerInfraUtils
    from ._utilities.fixture_loaders import TestFixtures, _FixtureLoaderUtils
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
    from .constants import FlextLdapTestConstants, FlextLdapTestConstants as c
    from .integration.test_smoke import TestsFlextLdapSmoke
    from .models import FlextLdapTestModels, FlextLdapTestModels as m
    from .protocols import FlextLdapTestProtocols, FlextLdapTestProtocols as p
    from .typings import FlextLdapTestTypes, FlextLdapTestTypes as t
    from .unit.test_api import TestsFlextLdapApi
    from .unit.test_base import TestsFlextLdapBase
    from .unit.test_config import TestsFlextLdapSettings
    from .unit.test_constants import TestsFlextLdapConstants
    from .unit.test_detection import TestsFlextLdapDetection
    from .unit.test_entry_adapter import TestsFlextLdapEntryAdapter
    from .unit.test_ldap3_adapter import TestsFlextLdap3Adapter
    from .unit.test_models import TestsFlextLdapModels
    from .unit.test_models_search import TestsFlextLdapModelsSearch
    from .unit.test_models_sync import TestsFlextLdapModelsSync
    from .unit.test_operations import TestsFlextLdapOperations
    from .unit.test_sync import TestsFlextLdapSync, pytestmark
    from .unit.test_utilities import TestsFlextLdapUtilities
    from .utilities import FlextLdapTestUtilities, FlextLdapTestUtilities as u

_LAZY_IMPORTS: dict[str, tuple[str, str]] = {
    "FlextLdapTestConstants": ("tests.constants", "FlextLdapTestConstants"),
    "FlextLdapTestModels": ("tests.models", "FlextLdapTestModels"),
    "FlextLdapTestProtocols": ("tests.protocols", "FlextLdapTestProtocols"),
    "FlextLdapTestTypes": ("tests.typings", "FlextLdapTestTypes"),
    "FlextLdapTestUtilities": ("tests.utilities", "FlextLdapTestUtilities"),
    "LdapContainerDict": ("tests.conftest", "LdapContainerDict"),
    "TestFixtures": ("tests._utilities.fixture_loaders", "TestFixtures"),
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
    "TestsFlextLdapSmoke": ("tests.integration.test_smoke", "TestsFlextLdapSmoke"),
    "TestsFlextLdapSync": ("tests.unit.test_sync", "TestsFlextLdapSync"),
    "TestsFlextLdapUtilities": ("tests.unit.test_utilities", "TestsFlextLdapUtilities"),
    "_DockerInfraUtils": ("tests._utilities.docker_infra", "_DockerInfraUtils"),
    "_FixtureLoaderUtils": ("tests._utilities.fixture_loaders", "_FixtureLoaderUtils"),
    "_utilities": ("tests._utilities", ""),
    "c": ("tests.constants", "FlextLdapTestConstants"),
    "connection_config": ("tests.conftest", "connection_config"),
    "d": ("flext_tests", "d"),
    "e": ("flext_tests", "e"),
    "h": ("flext_tests", "h"),
    "integration": ("tests.integration", ""),
    "ldap_container": ("tests.conftest", "ldap_container"),
    "logger": ("tests.conftest", "logger"),
    "m": ("tests.models", "FlextLdapTestModels"),
    "p": ("tests.protocols", "FlextLdapTestProtocols"),
    "pytest_runtest_makereport": ("tests.conftest", "pytest_runtest_makereport"),
    "pytest_sessionstart": ("tests.conftest", "pytest_sessionstart"),
    "pytestmark": ("tests.unit.test_sync", "pytestmark"),
    "r": ("flext_tests", "r"),
    "s": ("flext_tests", "s"),
    "search_options": ("tests.conftest", "search_options"),
    "t": ("tests.typings", "FlextLdapTestTypes"),
    "u": ("tests.utilities", "FlextLdapTestUtilities"),
    "unit": ("tests.unit", ""),
    "worker_id": ("tests.conftest", "worker_id"),
    "x": ("flext_tests", "x"),
}

__all__ = [
    "FlextLdapTestConstants",
    "FlextLdapTestModels",
    "FlextLdapTestProtocols",
    "FlextLdapTestTypes",
    "FlextLdapTestUtilities",
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
    "TestsFlextLdapSettings",
    "TestsFlextLdapSmoke",
    "TestsFlextLdapSync",
    "TestsFlextLdapUtilities",
    "_DockerInfraUtils",
    "_FixtureLoaderUtils",
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


_LAZY_CACHE: dict[str, FlextTypes.ModuleExport] = {}


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


def __dir__() -> list[str]:
    """Return list of available attributes for dir() and autocomplete.

    Returns:
        List of public names from module exports.

    """
    return sorted(__all__)


cleanup_submodule_namespace(__name__, _LAZY_IMPORTS)
