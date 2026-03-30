# AUTO-GENERATED FILE — DO NOT EDIT MANUALLY.
# Regenerate with: make gen
#
"""Tests package."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import TYPE_CHECKING

from flext_core.lazy import install_lazy_exports

from tests._utilities import _LAZY_IMPORTS as _CHILD_LAZY_0
from tests.integration import _LAZY_IMPORTS as _CHILD_LAZY_1
from tests.unit import _LAZY_IMPORTS as _CHILD_LAZY_2

if TYPE_CHECKING:
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
    **_CHILD_LAZY_0,
    **_CHILD_LAZY_1,
    **_CHILD_LAZY_2,
    "FlextLdapTestConstants": "tests.constants",
    "FlextLdapTestModels": "tests.models",
    "FlextLdapTestProtocols": "tests.protocols",
    "FlextLdapTestTypes": "tests.typings",
    "FlextLdapTestUtilities": "tests.utilities",
    "LdapContainerDict": "tests.conftest",
    "_utilities": "tests._utilities",
    "c": ["tests.constants", "FlextLdapTestConstants"],
    "conftest": "tests.conftest",
    "connection_config": "tests.conftest",
    "constants": "tests.constants",
    "d": "flext_tests",
    "e": "flext_tests",
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
    "r": "flext_tests",
    "s": "flext_tests",
    "search_options": "tests.conftest",
    "t": ["tests.typings", "FlextLdapTestTypes"],
    "typings": "tests.typings",
    "u": ["tests.utilities", "FlextLdapTestUtilities"],
    "unit": "tests.unit",
    "utilities": "tests.utilities",
    "worker_id": "tests.conftest",
    "x": "flext_tests",
}


install_lazy_exports(__name__, globals(), _LAZY_IMPORTS)
