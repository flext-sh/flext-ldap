# AUTO-GENERATED FILE — DO NOT EDIT MANUALLY.
# Regenerate with: make codegen
#
"""Utilities package."""

from __future__ import annotations

from typing import TYPE_CHECKING

from flext_core.lazy import cleanup_submodule_namespace, lazy_getattr

if TYPE_CHECKING:
    from flext_core.typings import FlextTypes

    from .docker_infra import _DockerInfraUtils
    from .fixture_loaders import TestFixtures, _FixtureLoaderUtils

_LAZY_IMPORTS: dict[str, tuple[str, str]] = {
    "TestFixtures": ("tests._utilities.fixture_loaders", "TestFixtures"),
    "_DockerInfraUtils": ("tests._utilities.docker_infra", "_DockerInfraUtils"),
    "_FixtureLoaderUtils": ("tests._utilities.fixture_loaders", "_FixtureLoaderUtils"),
}

__all__ = [
    "TestFixtures",
    "_DockerInfraUtils",
    "_FixtureLoaderUtils",
]


def __getattr__(name: str) -> FlextTypes.ModuleExport:
    """Lazy-load module attributes on first access (PEP 562)."""
    return lazy_getattr(name, _LAZY_IMPORTS, globals(), __name__)


def __dir__() -> list[str]:
    """Return list of available attributes for dir() and autocomplete."""
    return sorted(__all__)


cleanup_submodule_namespace(__name__, _LAZY_IMPORTS)
