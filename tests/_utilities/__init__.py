# AUTO-GENERATED FILE — DO NOT EDIT MANUALLY.
# Regenerate with: make gen
#
"""Utilities package."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import TYPE_CHECKING

from flext_core.lazy import install_lazy_exports

if TYPE_CHECKING:
    from tests._utilities import (
        docker_infra as docker_infra,
        fixture_loaders as fixture_loaders,
    )
    from tests._utilities.docker_infra import _DockerInfraUtils as _DockerInfraUtils
    from tests._utilities.fixture_loaders import (
        TestFixtures as TestFixtures,
        _FixtureLoaderUtils as _FixtureLoaderUtils,
    )

_LAZY_IMPORTS: Mapping[str, Sequence[str]] = {
    "TestFixtures": ["tests._utilities.fixture_loaders", "TestFixtures"],
    "_DockerInfraUtils": ["tests._utilities.docker_infra", "_DockerInfraUtils"],
    "_FixtureLoaderUtils": ["tests._utilities.fixture_loaders", "_FixtureLoaderUtils"],
    "docker_infra": ["tests._utilities.docker_infra", ""],
    "fixture_loaders": ["tests._utilities.fixture_loaders", ""],
}

_EXPORTS: Sequence[str] = [
    "TestFixtures",
    "_DockerInfraUtils",
    "_FixtureLoaderUtils",
    "docker_infra",
    "fixture_loaders",
]


install_lazy_exports(__name__, globals(), _LAZY_IMPORTS, _EXPORTS)
