# AUTO-GENERATED FILE — DO NOT EDIT MANUALLY.
# Regenerate with: make gen
#
"""Utilities package."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import TYPE_CHECKING as _TYPE_CHECKING

from flext_core.lazy import install_lazy_exports

if _TYPE_CHECKING:
    from flext_core import FlextTypes
    from flext_ldap import docker_infra, fixture_loaders
    from flext_ldap.fixture_loaders import TestFixtures, _FixtureLoaderUtils

_LAZY_IMPORTS: FlextTypes.LazyImportIndex = {
    "TestFixtures": "flext_ldap.fixture_loaders",
    "_FixtureLoaderUtils": "flext_ldap.fixture_loaders",
    "docker_infra": "flext_ldap.docker_infra",
    "fixture_loaders": "flext_ldap.fixture_loaders",
}


install_lazy_exports(__name__, globals(), _LAZY_IMPORTS)
