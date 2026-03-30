# AUTO-GENERATED FILE — DO NOT EDIT MANUALLY.
# Regenerate with: make gen
#
"""Tests package."""

from __future__ import annotations

from collections.abc import Mapping, MutableMapping, Sequence
from typing import TYPE_CHECKING

from flext_core.lazy import cleanup_submodule_namespace, lazy_getattr

if TYPE_CHECKING:
    from flext_core import FlextTypes
    from flext_tests import d, e, h, r, s, x

    from tests import (
        _utilities,
        conftest,
        constants,
        integration,
        models,
        protocols,
        typings,
        unit,
        utilities,
    )
    from tests._utilities import docker_infra, fixture_loaders
    from tests._utilities.docker_infra import _DockerInfraUtils
    from tests._utilities.fixture_loaders import TestFixtures, _FixtureLoaderUtils
    from tests.conftest import (
        LdapContainerDict,
        connection_config,
        ldap_container,
        logger,
        pytest_runtest_makereport,
        pytest_sessionstart,
        search_options,
        worker_id,
    )
    from tests.constants import FlextLdapTestConstants, FlextLdapTestConstants as c
    from tests.integration import test_smoke
    from tests.integration.test_smoke import TestsFlextLdapSmoke
    from tests.models import FlextLdapTestModels, FlextLdapTestModels as m
    from tests.protocols import FlextLdapTestProtocols, FlextLdapTestProtocols as p
    from tests.typings import FlextLdapTestTypes, FlextLdapTestTypes as t
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
    from tests.utilities import FlextLdapTestUtilities, FlextLdapTestUtilities as u

_LAZY_IMPORTS: Mapping[str, Sequence[str]] = {
    "FlextLdapTestConstants": ["tests.constants", "FlextLdapTestConstants"],
    "FlextLdapTestModels": ["tests.models", "FlextLdapTestModels"],
    "FlextLdapTestProtocols": ["tests.protocols", "FlextLdapTestProtocols"],
    "FlextLdapTestTypes": ["tests.typings", "FlextLdapTestTypes"],
    "FlextLdapTestUtilities": ["tests.utilities", "FlextLdapTestUtilities"],
    "LdapContainerDict": ["tests.conftest", "LdapContainerDict"],
    "TestFixtures": ["tests._utilities.fixture_loaders", "TestFixtures"],
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
    "TestsFlextLdapSmoke": ["tests.integration.test_smoke", "TestsFlextLdapSmoke"],
    "TestsFlextLdapSync": ["tests.unit.test_sync", "TestsFlextLdapSync"],
    "TestsFlextLdapUtilities": ["tests.unit.test_utilities", "TestsFlextLdapUtilities"],
    "_DockerInfraUtils": ["tests._utilities.docker_infra", "_DockerInfraUtils"],
    "_FixtureLoaderUtils": ["tests._utilities.fixture_loaders", "_FixtureLoaderUtils"],
    "_utilities": ["tests._utilities", ""],
    "c": ["tests.constants", "FlextLdapTestConstants"],
    "conftest": ["tests.conftest", ""],
    "connection_config": ["tests.conftest", "connection_config"],
    "constants": ["tests.constants", ""],
    "d": ["flext_tests", "d"],
    "docker_infra": ["tests._utilities.docker_infra", ""],
    "e": ["flext_tests", "e"],
    "fixture_loaders": ["tests._utilities.fixture_loaders", ""],
    "h": ["flext_tests", "h"],
    "integration": ["tests.integration", ""],
    "ldap_container": ["tests.conftest", "ldap_container"],
    "logger": ["tests.conftest", "logger"],
    "m": ["tests.models", "FlextLdapTestModels"],
    "models": ["tests.models", ""],
    "p": ["tests.protocols", "FlextLdapTestProtocols"],
    "protocols": ["tests.protocols", ""],
    "pytest_runtest_makereport": ["tests.conftest", "pytest_runtest_makereport"],
    "pytest_sessionstart": ["tests.conftest", "pytest_sessionstart"],
    "pytestmark": ["tests.unit.test_operations", "pytestmark"],
    "r": ["flext_tests", "r"],
    "s": ["flext_tests", "s"],
    "search_options": ["tests.conftest", "search_options"],
    "t": ["tests.typings", "FlextLdapTestTypes"],
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
    "test_smoke": ["tests.integration.test_smoke", ""],
    "test_sync": ["tests.unit.test_sync", ""],
    "test_utilities": ["tests.unit.test_utilities", ""],
    "typings": ["tests.typings", ""],
    "u": ["tests.utilities", "FlextLdapTestUtilities"],
    "unit": ["tests.unit", ""],
    "utilities": ["tests.utilities", ""],
    "worker_id": ["tests.conftest", "worker_id"],
    "x": ["flext_tests", "x"],
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
    "conftest",
    "connection_config",
    "constants",
    "d",
    "docker_infra",
    "e",
    "fixture_loaders",
    "h",
    "integration",
    "ldap_container",
    "logger",
    "m",
    "models",
    "p",
    "protocols",
    "pytest_runtest_makereport",
    "pytest_sessionstart",
    "pytestmark",
    "r",
    "s",
    "search_options",
    "t",
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
    "test_smoke",
    "test_sync",
    "test_utilities",
    "typings",
    "u",
    "unit",
    "utilities",
    "worker_id",
    "x",
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
