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
    from tests._utilities import _DockerInfraUtils, _FixtureLoaderUtils

    conftest = _tests_conftest
    import tests.constants as _tests_constants
    from tests.conftest import pytest_plugins

    constants = _tests_constants
    import tests.models as _tests_models
    from tests.constants import FlextLdapTestConstants, FlextLdapTestConstants as c
    from tests.integration.conftest import (
        LdapContainerDict,
        WorkerInputConfig,
        logger,
        pytest_runtest_makereport,
        pytest_sessionstart,
    )

    models = _tests_models
    import tests.protocols as _tests_protocols
    from tests.models import FlextLdapTestModels, FlextLdapTestModels as m

    protocols = _tests_protocols
    import tests.typings as _tests_typings
    from tests.protocols import FlextLdapTestProtocols, FlextLdapTestProtocols as p

    typings = _tests_typings
    import tests.utilities as _tests_utilities
    from tests.typings import FlextLdapTestTypes, FlextLdapTestTypes as t
    from tests.unit.test_entry_adapter import TestsFlextLdapEntryAdapter
    from tests.unit.test_models import TestsFlextLdapModels
    from tests.unit.test_models_search import TestsFlextLdapModelsSearch
    from tests.unit.test_sync import TestsFlextLdapSync, pytestmark
    from tests.unit.test_utilities import TestsFlextLdapUtilities

    utilities = _tests_utilities
    from flext_core.decorators import FlextDecorators as d
    from flext_core.exceptions import FlextExceptions as e
    from flext_core.handlers import FlextHandlers as h
    from flext_core.mixins import FlextMixins as x
    from flext_core.result import FlextResult as r
    from flext_core.service import FlextService as s
    from tests.utilities import FlextLdapTestUtilities, FlextLdapTestUtilities as u
_LAZY_IMPORTS = merge_lazy_imports(
    ("tests._utilities",),
    {
        "FlextLdapTestConstants": ("tests.constants", "FlextLdapTestConstants"),
        "FlextLdapTestModels": ("tests.models", "FlextLdapTestModels"),
        "FlextLdapTestProtocols": ("tests.protocols", "FlextLdapTestProtocols"),
        "FlextLdapTestTypes": ("tests.typings", "FlextLdapTestTypes"),
        "FlextLdapTestUtilities": ("tests.utilities", "FlextLdapTestUtilities"),
        "LdapContainerDict": ("tests.integration.conftest", "LdapContainerDict"),
        "TestsFlextLdapEntryAdapter": (
            "tests.unit.test_entry_adapter",
            "TestsFlextLdapEntryAdapter",
        ),
        "TestsFlextLdapModels": ("tests.unit.test_models", "TestsFlextLdapModels"),
        "TestsFlextLdapModelsSearch": (
            "tests.unit.test_models_search",
            "TestsFlextLdapModelsSearch",
        ),
        "TestsFlextLdapSync": ("tests.unit.test_sync", "TestsFlextLdapSync"),
        "TestsFlextLdapUtilities": (
            "tests.unit.test_utilities",
            "TestsFlextLdapUtilities",
        ),
        "WorkerInputConfig": ("tests.integration.conftest", "WorkerInputConfig"),
        "_utilities": "tests._utilities",
        "c": ("tests.constants", "FlextLdapTestConstants"),
        "conftest": "tests.conftest",
        "constants": "tests.constants",
        "d": ("flext_core.decorators", "FlextDecorators"),
        "e": ("flext_core.exceptions", "FlextExceptions"),
        "h": ("flext_core.handlers", "FlextHandlers"),
        "logger": ("tests.integration.conftest", "logger"),
        "m": ("tests.models", "FlextLdapTestModels"),
        "models": "tests.models",
        "p": ("tests.protocols", "FlextLdapTestProtocols"),
        "protocols": "tests.protocols",
        "pytest_plugins": ("tests.conftest", "pytest_plugins"),
        "pytest_runtest_makereport": (
            "tests.integration.conftest",
            "pytest_runtest_makereport",
        ),
        "pytest_sessionstart": ("tests.integration.conftest", "pytest_sessionstart"),
        "pytestmark": ("tests.unit.test_sync", "pytestmark"),
        "r": ("flext_core.result", "FlextResult"),
        "s": ("flext_core.service", "FlextService"),
        "t": ("tests.typings", "FlextLdapTestTypes"),
        "typings": "tests.typings",
        "u": ("tests.utilities", "FlextLdapTestUtilities"),
        "utilities": "tests.utilities",
        "x": ("flext_core.mixins", "FlextMixins"),
    },
)
_ = _LAZY_IMPORTS.pop("cleanup_submodule_namespace", None)
_ = _LAZY_IMPORTS.pop("install_lazy_exports", None)
_ = _LAZY_IMPORTS.pop("lazy_getattr", None)
_ = _LAZY_IMPORTS.pop("merge_lazy_imports", None)
_ = _LAZY_IMPORTS.pop("output", None)
_ = _LAZY_IMPORTS.pop("output_reporting", None)

__all__ = [
    "FlextLdapTestConstants",
    "FlextLdapTestModels",
    "FlextLdapTestProtocols",
    "FlextLdapTestTypes",
    "FlextLdapTestUtilities",
    "LdapContainerDict",
    "TestsFlextLdapEntryAdapter",
    "TestsFlextLdapModels",
    "TestsFlextLdapModelsSearch",
    "TestsFlextLdapSync",
    "TestsFlextLdapUtilities",
    "WorkerInputConfig",
    "_DockerInfraUtils",
    "_FixtureLoaderUtils",
    "_utilities",
    "c",
    "conftest",
    "constants",
    "d",
    "e",
    "h",
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
    "t",
    "typings",
    "u",
    "utilities",
    "x",
]


install_lazy_exports(__name__, globals(), _LAZY_IMPORTS)
