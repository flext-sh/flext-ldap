# AUTO-GENERATED FILE — DO NOT EDIT MANUALLY.
# Regenerate with: make gen
#
"""Tests package."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import TYPE_CHECKING

from flext_core.lazy import install_lazy_exports

if TYPE_CHECKING:
    from tests import (
        _utilities as _utilities,
        conftest as conftest,
        constants as constants,
        integration as integration,
        models as models,
        protocols as protocols,
        typings as typings,
        unit as unit,
        utilities as utilities,
    )
    from tests._utilities import (
        docker_infra as docker_infra,
        fixture_loaders as fixture_loaders,
    )
    from tests._utilities.docker_infra import _DockerInfraUtils as _DockerInfraUtils
    from tests._utilities.fixture_loaders import (
        TestFixtures as TestFixtures,
        _FixtureLoaderUtils as _FixtureLoaderUtils,
    )
    from tests.conftest import (
        LdapContainerDict as LdapContainerDict,
        connection_config as connection_config,
        ldap_container as ldap_container,
        logger as logger,
        pytest_runtest_makereport as pytest_runtest_makereport,
        pytest_sessionstart as pytest_sessionstart,
        search_options as search_options,
        worker_id as worker_id,
    )
    from tests.constants import (
        FlextLdapTestConstants as FlextLdapTestConstants,
        FlextLdapTestConstants as c,
    )
    from tests.integration import test_smoke as test_smoke
    from tests.integration.test_smoke import TestsFlextLdapSmoke as TestsFlextLdapSmoke
    from tests.models import (
        FlextLdapTestModels as FlextLdapTestModels,
        FlextLdapTestModels as m,
    )
    from tests.protocols import (
        FlextLdapTestProtocols as FlextLdapTestProtocols,
        FlextLdapTestProtocols as p,
    )
    from tests.typings import (
        FlextLdapTestTypes as FlextLdapTestTypes,
        FlextLdapTestTypes as t,
    )
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
    from tests.utilities import (
        FlextLdapTestUtilities as FlextLdapTestUtilities,
        FlextLdapTestUtilities as u,
    )

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

_EXPORTS: Sequence[str] = [
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


install_lazy_exports(__name__, globals(), _LAZY_IMPORTS, _EXPORTS)
