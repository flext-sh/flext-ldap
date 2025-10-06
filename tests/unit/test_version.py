"""Regression tests for the flext_ldap version metadata module."""

from __future__ import annotations

import importlib
from collections.abc import Mapping

from flext_ldap.version import VERSION, FlextLDAPVersion


def test_module_exports_are_minimal() -> None:
    """Only the standardized dunder exports should be present."""
    module = importlib.import_module("flext_ldap.__version__")

    assert module.__version__ == VERSION.version
    assert module.__version_info__ == VERSION.version_info

    forbidden = {
        "__author__",
        "__maintainer__",
        "__project__",
        "__license__",
        "__description__",
    }
    assert forbidden.isdisjoint(module.__dict__), forbidden


def test_version_singleton_matches_metadata() -> None:
    """The exported VERSION instance should mirror current metadata."""
    assert isinstance(VERSION, FlextLDAPVersion)

    current = FlextLDAPVersion.current()
    assert current.version == VERSION.version
    assert current.project == VERSION.project
    assert current.version_info == VERSION.version_info


def test_metadata_accessors() -> None:
    """Primary metadata attributes remain reachable from the wrapper."""
    assert VERSION.author
    assert VERSION.maintainer
    assert isinstance(VERSION.urls, Mapping)
    assert VERSION.requires_python is None or isinstance(VERSION.requires_python, str)
