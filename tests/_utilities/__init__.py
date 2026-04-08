# AUTO-GENERATED FILE — DO NOT EDIT MANUALLY.
# Regenerate with: make gen
#
"""Utilities package."""

from __future__ import annotations

from flext_core.lazy import install_lazy_exports

_LAZY_IMPORTS = {
    "_DockerInfraUtils": ("tests._utilities.docker_infra", "_DockerInfraUtils"),
    "_FixtureLoaderUtils": ("tests._utilities.fixture_loaders", "_FixtureLoaderUtils"),
    "docker_infra": "tests._utilities.docker_infra",
    "fixture_loaders": "tests._utilities.fixture_loaders",
}


install_lazy_exports(__name__, globals(), _LAZY_IMPORTS, publish_all=False)
