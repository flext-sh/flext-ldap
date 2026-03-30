# AUTO-GENERATED FILE — DO NOT EDIT MANUALLY.
# Regenerate with: make gen
#
"""Integration package."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import TYPE_CHECKING

from flext_core.lazy import install_lazy_exports

if TYPE_CHECKING:
    from tests.integration import test_smoke as test_smoke
    from tests.integration.test_smoke import (
        TestsFlextLdapSmoke as TestsFlextLdapSmoke,
        pytestmark as pytestmark,
    )

_LAZY_IMPORTS: Mapping[str, Sequence[str]] = {
    "TestsFlextLdapSmoke": ["tests.integration.test_smoke", "TestsFlextLdapSmoke"],
    "pytestmark": ["tests.integration.test_smoke", "pytestmark"],
    "test_smoke": ["tests.integration.test_smoke", ""],
}

_EXPORTS: Sequence[str] = [
    "TestsFlextLdapSmoke",
    "pytestmark",
    "test_smoke",
]


install_lazy_exports(__name__, globals(), _LAZY_IMPORTS, _EXPORTS)
