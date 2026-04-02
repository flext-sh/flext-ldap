# AUTO-GENERATED FILE — DO NOT EDIT MANUALLY.
# Regenerate with: make gen
#
"""Tests package."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import TYPE_CHECKING as _TYPE_CHECKING

from flext_core.lazy import install_lazy_exports, merge_lazy_imports

if _TYPE_CHECKING:
    from flext_tests import d, e, h, r, s, x

    from flext_core import FlextTypes
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
    from tests._utilities import (
        TestFixtures,
        _DockerInfraUtils,
        _FixtureLoaderUtils,
        docker_infra,
        fixture_loaders,
    )
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
    from tests.integration import TestsFlextLdapSmoke, test_smoke
    from tests.models import FlextLdapTestModels, FlextLdapTestModels as m
    from tests.protocols import FlextLdapTestProtocols, FlextLdapTestProtocols as p
    from tests.typings import FlextLdapTestTypes, FlextLdapTestTypes as t
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
    from tests.utilities import FlextLdapTestUtilities, FlextLdapTestUtilities as u

_LAZY_IMPORTS: FlextTypes.LazyImportIndex = merge_lazy_imports(
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
        "d": "flext_tests",
        "e": "flext_tests",
        "h": "flext_tests",
        "integration": "tests.integration",
        "ldap_container": "tests.conftest",
        "logger": "tests.conftest",
        "m": ("tests.models", "FlextLdapTestModels"),
        "models": "tests.models",
        "p": ("tests.protocols", "FlextLdapTestProtocols"),
        "protocols": "tests.protocols",
        "pytest_runtest_makereport": "tests.conftest",
        "pytest_sessionstart": "tests.conftest",
        "r": "flext_tests",
        "s": "flext_tests",
        "search_options": "tests.conftest",
        "t": ("tests.typings", "FlextLdapTestTypes"),
        "typings": "tests.typings",
        "u": ("tests.utilities", "FlextLdapTestUtilities"),
        "unit": "tests.unit",
        "utilities": "tests.utilities",
        "worker_id": "tests.conftest",
        "x": "flext_tests",
    },
)


install_lazy_exports(__name__, globals(), _LAZY_IMPORTS)
