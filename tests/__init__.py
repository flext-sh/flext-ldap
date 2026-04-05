# AUTO-GENERATED FILE — DO NOT EDIT MANUALLY.
# Regenerate with: make gen
#
"""Tests package."""

from __future__ import annotations

import typing as _t

from flext_core.lazy import install_lazy_exports, merge_lazy_imports

if _t.TYPE_CHECKING:
    import tests._utilities as _tests__utilities

    _utilities = _tests__utilities
    import tests.conftest as _tests_conftest
    from tests._utilities import (
        TestFixtures,
        _DockerInfraUtils,
        _FixtureLoaderUtils,
        docker_infra,
        fixture_loaders,
    )

    conftest = _tests_conftest
    import tests.constants as _tests_constants
    from tests.conftest import (
        LdapContainerDict,
        connection_config,
        ldap_container,
        ldap_settings,
        logger,
        pytest_plugins,
        pytest_runtest_makereport,
        pytest_sessionstart,
        search_options,
        worker_id,
    )

    constants = _tests_constants
    import tests.integration as _tests_integration
    from tests.constants import FlextLdapTestConstants, FlextLdapTestConstants as c

    integration = _tests_integration
    import tests.models as _tests_models
    from tests.integration import TestsFlextLdapSmoke, test_smoke

    models = _tests_models
    import tests.protocols as _tests_protocols
    from tests.models import FlextLdapTestModels, FlextLdapTestModels as m

    protocols = _tests_protocols
    import tests.typings as _tests_typings
    from tests.protocols import FlextLdapTestProtocols, FlextLdapTestProtocols as p

    typings = _tests_typings
    import tests.unit as _tests_unit
    from tests.typings import FlextLdapTestTypes, FlextLdapTestTypes as t

    unit = _tests_unit
    import tests.utilities as _tests_utilities
    from tests.unit import (
        TestsFlextLdap3Adapter,
        TestsFlextLdapApi,
        TestsFlextLdapBase,
        TestsFlextLdapConstants,
        TestsFlextLdapDetection,
        TestsFlextLdapEntryAdapter,
        TestsFlextLdapModels,
        TestsFlextLdapModelsSearch,
        TestsFlextLdapModelsSync,
        TestsFlextLdapOperations,
        TestsFlextLdapSettings,
        TestsFlextLdapSync,
        TestsFlextLdapUtilities,
        pytestmark,
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

    utilities = _tests_utilities
    from flext_core.decorators import FlextDecorators as d
    from flext_core.exceptions import FlextExceptions as e
    from flext_core.handlers import FlextHandlers as h
    from flext_core.mixins import FlextMixins as x
    from flext_core.result import FlextResult as r
    from flext_core.service import FlextService as s
    from tests.utilities import FlextLdapTestUtilities, FlextLdapTestUtilities as u
_LAZY_IMPORTS = merge_lazy_imports(
    (
        "tests._utilities",
        "tests.integration",
        "tests.unit",
    ),
    {
        "FlextLdapTestConstants": "tests.constants",
        "FlextLdapTestModels": "tests.models",
        "FlextLdapTestProtocols": "tests.protocols",
        "FlextLdapTestTypes": "tests.typings",
        "FlextLdapTestUtilities": "tests.utilities",
        "LdapContainerDict": "tests.conftest",
        "_utilities": "tests._utilities",
        "c": ("tests.constants", "FlextLdapTestConstants"),
        "conftest": "tests.conftest",
        "connection_config": "tests.conftest",
        "constants": "tests.constants",
        "d": ("flext_core.decorators", "FlextDecorators"),
        "e": ("flext_core.exceptions", "FlextExceptions"),
        "h": ("flext_core.handlers", "FlextHandlers"),
        "integration": "tests.integration",
        "ldap_container": "tests.conftest",
        "ldap_settings": "tests.conftest",
        "logger": "tests.conftest",
        "m": ("tests.models", "FlextLdapTestModels"),
        "models": "tests.models",
        "p": ("tests.protocols", "FlextLdapTestProtocols"),
        "protocols": "tests.protocols",
        "pytest_plugins": "tests.conftest",
        "pytest_runtest_makereport": "tests.conftest",
        "pytest_sessionstart": "tests.conftest",
        "r": ("flext_core.result", "FlextResult"),
        "s": ("flext_core.service", "FlextService"),
        "search_options": "tests.conftest",
        "t": ("tests.typings", "FlextLdapTestTypes"),
        "typings": "tests.typings",
        "u": ("tests.utilities", "FlextLdapTestUtilities"),
        "unit": "tests.unit",
        "utilities": "tests.utilities",
        "worker_id": "tests.conftest",
        "x": ("flext_core.mixins", "FlextMixins"),
    },
)

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
    "ldap_settings",
    "logger",
    "m",
    "models",
    "p",
    "protocols",
    "pytest_plugins",
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


install_lazy_exports(__name__, globals(), _LAZY_IMPORTS)
