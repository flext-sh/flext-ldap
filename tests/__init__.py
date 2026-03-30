# AUTO-GENERATED FILE — DO NOT EDIT MANUALLY.
# Regenerate with: make gen
#
"""Tests package."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import TYPE_CHECKING

from flext_core.lazy import install_lazy_exports

if TYPE_CHECKING:
    from flext_tests import *

    from tests import conftest, constants, models, protocols, typings, utilities
    from tests._utilities import *
    from tests.conftest import *
    from tests.constants import *
    from tests.integration import *
    from tests.models import *
    from tests.protocols import *
    from tests.typings import *
    from tests.unit import *
    from tests.utilities import *

_LAZY_IMPORTS: Mapping[str, str | Sequence[str]] = {
    "FlextLdapTestConstants": "tests.constants",
    "FlextLdapTestModels": "tests.models",
    "FlextLdapTestProtocols": "tests.protocols",
    "FlextLdapTestTypes": "tests.typings",
    "FlextLdapTestUtilities": "tests.utilities",
    "LdapContainerDict": "tests.conftest",
    "TestFixtures": "tests._utilities.fixture_loaders",
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
    "TestsFlextLdapSmoke": "tests.integration.test_smoke",
    "TestsFlextLdapSync": "tests.unit.test_sync",
    "TestsFlextLdapUtilities": "tests.unit.test_utilities",
    "_DockerInfraUtils": "tests._utilities.docker_infra",
    "_FixtureLoaderUtils": "tests._utilities.fixture_loaders",
    "_utilities": "tests._utilities",
    "c": ["tests.constants", "FlextLdapTestConstants"],
    "conftest": "tests.conftest",
    "connection_config": "tests.conftest",
    "constants": "tests.constants",
    "d": "flext_tests",
    "docker_infra": "tests._utilities.docker_infra",
    "e": "flext_tests",
    "fixture_loaders": "tests._utilities.fixture_loaders",
    "h": "flext_tests",
    "integration": "tests.integration",
    "ldap_container": "tests.conftest",
    "logger": "tests.conftest",
    "m": ["tests.models", "FlextLdapTestModels"],
    "models": "tests.models",
    "p": ["tests.protocols", "FlextLdapTestProtocols"],
    "protocols": "tests.protocols",
    "pytest_runtest_makereport": "tests.conftest",
    "pytest_sessionstart": "tests.conftest",
    "pytestmark": "tests.unit.test_operations",
    "r": "flext_tests",
    "s": "flext_tests",
    "search_options": "tests.conftest",
    "t": ["tests.typings", "FlextLdapTestTypes"],
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
    "test_smoke": "tests.integration.test_smoke",
    "test_sync": "tests.unit.test_sync",
    "test_utilities": "tests.unit.test_utilities",
    "typings": "tests.typings",
    "u": ["tests.utilities", "FlextLdapTestUtilities"],
    "unit": "tests.unit",
    "utilities": "tests.utilities",
    "worker_id": "tests.conftest",
    "x": "flext_tests",
}


install_lazy_exports(__name__, globals(), _LAZY_IMPORTS, sorted(_LAZY_IMPORTS))
