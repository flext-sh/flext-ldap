# AUTO-GENERATED FILE — DO NOT EDIT MANUALLY.
# Regenerate with: make gen
#
"""Tests package."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import TYPE_CHECKING as _TYPE_CHECKING

from flext_core.lazy import install_lazy_exports, merge_lazy_imports

if _TYPE_CHECKING:
    from flext_core import FlextTypes
    from flext_core.decorators import FlextDecorators as d
    from flext_core.exceptions import FlextExceptions as e
    from flext_core.handlers import FlextHandlers as h
    from flext_core.mixins import FlextMixins as x
    from flext_core.result import FlextResult as r
    from flext_core.service import FlextService as s
    from flext_ldap import (
        _utilities,
        conftest,
        constants,
        docker_infra,
        fixture_loaders,
        integration,
        models,
        protocols,
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
        test_smoke,
        test_sync,
        test_utilities,
        typings,
        unit,
        utilities,
    )
    from flext_ldap._utilities import TestFixtures, _FixtureLoaderUtils
    from flext_ldap.conftest import (
        LdapContainerDict,
        connection_config,
        ldap_container,
        logger,
        pytest_runtest_makereport,
        search_options,
        worker_id,
    )
    from flext_ldap.constants import FlextLdapTestConstants, FlextLdapTestConstants as c
    from flext_ldap.integration import TestsFlextLdapSmoke
    from flext_ldap.models import FlextLdapTestModels, FlextLdapTestModels as m
    from flext_ldap.protocols import FlextLdapTestProtocols, FlextLdapTestProtocols as p
    from flext_ldap.typings import FlextLdapTestTypes, FlextLdapTestTypes as t
    from flext_ldap.unit import (
        TestsFlextLdap3Adapter,
        TestsFlextLdapApi,
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
    )
    from flext_ldap.utilities import FlextLdapTestUtilities, FlextLdapTestUtilities as u

_LAZY_IMPORTS: FlextTypes.LazyImportIndex = merge_lazy_imports(
    (
        "flext_ldap._utilities",
        "flext_ldap.integration",
        "flext_ldap.unit",
    ),
    {
        "FlextLdapTestConstants": "flext_ldap.constants",
        "FlextLdapTestModels": "flext_ldap.models",
        "FlextLdapTestProtocols": "flext_ldap.protocols",
        "FlextLdapTestTypes": "flext_ldap.typings",
        "FlextLdapTestUtilities": "flext_ldap.utilities",
        "LdapContainerDict": "flext_ldap.conftest",
        "_utilities": "flext_ldap._utilities",
        "c": ("flext_ldap.constants", "FlextLdapTestConstants"),
        "conftest": "flext_ldap.conftest",
        "connection_config": "flext_ldap.conftest",
        "constants": "flext_ldap.constants",
        "d": ("flext_core.decorators", "FlextDecorators"),
        "docker_infra": "flext_ldap.docker_infra",
        "e": ("flext_core.exceptions", "FlextExceptions"),
        "fixture_loaders": "flext_ldap.fixture_loaders",
        "h": ("flext_core.handlers", "FlextHandlers"),
        "integration": "flext_ldap.integration",
        "ldap_container": "flext_ldap.conftest",
        "logger": "flext_ldap.conftest",
        "m": ("flext_ldap.models", "FlextLdapTestModels"),
        "models": "flext_ldap.models",
        "p": ("flext_ldap.protocols", "FlextLdapTestProtocols"),
        "protocols": "flext_ldap.protocols",
        "pytest_runtest_makereport": "flext_ldap.conftest",
        "r": ("flext_core.result", "FlextResult"),
        "s": ("flext_core.service", "FlextService"),
        "search_options": "flext_ldap.conftest",
        "t": ("flext_ldap.typings", "FlextLdapTestTypes"),
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
        "test_smoke": "flext_ldap.test_smoke",
        "test_sync": "flext_ldap.test_sync",
        "test_utilities": "flext_ldap.test_utilities",
        "typings": "flext_ldap.typings",
        "u": ("flext_ldap.utilities", "FlextLdapTestUtilities"),
        "unit": "flext_ldap.unit",
        "utilities": "flext_ldap.utilities",
        "worker_id": "flext_ldap.conftest",
        "x": ("flext_core.mixins", "FlextMixins"),
    },
)


install_lazy_exports(__name__, globals(), _LAZY_IMPORTS)
