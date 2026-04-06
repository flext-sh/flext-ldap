# AUTO-GENERATED FILE — DO NOT EDIT MANUALLY.
# Regenerate with: make gen
#
"""Integration package."""

from __future__ import annotations

import typing as _t

from flext_core.lazy import install_lazy_exports

if _t.TYPE_CHECKING:
    import tests.integration.conftest as _tests_integration_conftest

    conftest = _tests_integration_conftest
    import tests.integration.test_smoke as _tests_integration_test_smoke
    from tests.integration.conftest import (
        LdapContainerDict,
        WorkerInputConfig,
        connection_config,
        ldap_container,
        logger,
        pytest_runtest_makereport,
        pytest_sessionstart,
        search_options,
        worker_id,
    )

    test_smoke = _tests_integration_test_smoke
    from flext_core.constants import FlextConstants as c
    from flext_core.decorators import FlextDecorators as d
    from flext_core.exceptions import FlextExceptions as e
    from flext_core.handlers import FlextHandlers as h
    from flext_core.mixins import FlextMixins as x
    from flext_core.models import FlextModels as m
    from flext_core.protocols import FlextProtocols as p
    from flext_core.result import FlextResult as r
    from flext_core.service import FlextService as s
    from flext_core.typings import FlextTypes as t
    from flext_core.utilities import FlextUtilities as u
    from tests.integration.test_smoke import TestsFlextLdapSmoke, pytestmark
_LAZY_IMPORTS = {
    "LdapContainerDict": ("tests.integration.conftest", "LdapContainerDict"),
    "TestsFlextLdapSmoke": ("tests.integration.test_smoke", "TestsFlextLdapSmoke"),
    "WorkerInputConfig": ("tests.integration.conftest", "WorkerInputConfig"),
    "c": ("flext_core.constants", "FlextConstants"),
    "conftest": "tests.integration.conftest",
    "connection_config": ("tests.integration.conftest", "connection_config"),
    "d": ("flext_core.decorators", "FlextDecorators"),
    "e": ("flext_core.exceptions", "FlextExceptions"),
    "h": ("flext_core.handlers", "FlextHandlers"),
    "ldap_container": ("tests.integration.conftest", "ldap_container"),
    "logger": ("tests.integration.conftest", "logger"),
    "m": ("flext_core.models", "FlextModels"),
    "p": ("flext_core.protocols", "FlextProtocols"),
    "pytest_runtest_makereport": (
        "tests.integration.conftest",
        "pytest_runtest_makereport",
    ),
    "pytest_sessionstart": ("tests.integration.conftest", "pytest_sessionstart"),
    "pytestmark": ("tests.integration.test_smoke", "pytestmark"),
    "r": ("flext_core.result", "FlextResult"),
    "s": ("flext_core.service", "FlextService"),
    "search_options": ("tests.integration.conftest", "search_options"),
    "t": ("flext_core.typings", "FlextTypes"),
    "test_smoke": "tests.integration.test_smoke",
    "u": ("flext_core.utilities", "FlextUtilities"),
    "worker_id": ("tests.integration.conftest", "worker_id"),
    "x": ("flext_core.mixins", "FlextMixins"),
}

__all__ = [
    "LdapContainerDict",
    "TestsFlextLdapSmoke",
    "WorkerInputConfig",
    "c",
    "conftest",
    "connection_config",
    "d",
    "e",
    "h",
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
    "test_smoke",
    "u",
    "worker_id",
    "x",
]


install_lazy_exports(__name__, globals(), _LAZY_IMPORTS)
