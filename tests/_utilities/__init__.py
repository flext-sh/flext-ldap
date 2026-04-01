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

    from tests._utilities import docker_infra, fixture_loaders
    from tests._utilities.docker_infra import _DockerInfraUtils
    from tests._utilities.fixture_loaders import TestFixtures, _FixtureLoaderUtils

_LAZY_IMPORTS: Mapping[str, str | Sequence[str]] = {
    "TestFixtures": "tests._utilities.fixture_loaders",
    "_DockerInfraUtils": "tests._utilities.docker_infra",
    "_FixtureLoaderUtils": "tests._utilities.fixture_loaders",
    "docker_infra": "tests._utilities.docker_infra",
    "fixture_loaders": "tests._utilities.fixture_loaders",
}


install_lazy_exports(__name__, globals(), _LAZY_IMPORTS)
