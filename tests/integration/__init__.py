# AUTO-GENERATED FILE — DO NOT EDIT MANUALLY.
# Regenerate with: make gen
#
"""Integration package."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import TYPE_CHECKING as _TYPE_CHECKING

from flext_core.lazy import install_lazy_exports

if _TYPE_CHECKING:
    from flext_core import FlextTypes

    from tests.integration.test_smoke import *

_LAZY_IMPORTS: Mapping[str, str | Sequence[str]] = {
    "TestsFlextLdapSmoke": "tests.integration.test_smoke",
    "pytestmark": "tests.integration.test_smoke",
    "test_smoke": "tests.integration.test_smoke",
}


install_lazy_exports(__name__, globals(), _LAZY_IMPORTS)
