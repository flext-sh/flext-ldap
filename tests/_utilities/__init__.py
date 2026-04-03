# AUTO-GENERATED FILE — DO NOT EDIT MANUALLY.
# Regenerate with: make gen
#
"""Utilities package."""

from __future__ import annotations

import typing as _t

from flext_core.lazy import install_lazy_exports
from tests._utilities.docker_infra import _DockerInfraUtils
from tests._utilities.fixture_loaders import TestFixtures, _FixtureLoaderUtils

if _t.TYPE_CHECKING:
    import tests._utilities.docker_infra as _tests__utilities_docker_infra

    docker_infra = _tests__utilities_docker_infra
    import tests._utilities.fixture_loaders as _tests__utilities_fixture_loaders

    fixture_loaders = _tests__utilities_fixture_loaders

    _ = (
        TestFixtures,
        _DockerInfraUtils,
        _FixtureLoaderUtils,
        docker_infra,
        fixture_loaders,
    )
_LAZY_IMPORTS = {
    "TestFixtures": "tests._utilities.fixture_loaders",
    "_DockerInfraUtils": "tests._utilities.docker_infra",
    "_FixtureLoaderUtils": "tests._utilities.fixture_loaders",
    "docker_infra": "tests._utilities.docker_infra",
    "fixture_loaders": "tests._utilities.fixture_loaders",
}

__all__ = [
    "TestFixtures",
    "_DockerInfraUtils",
    "_FixtureLoaderUtils",
    "docker_infra",
    "fixture_loaders",
]


install_lazy_exports(__name__, globals(), _LAZY_IMPORTS)
