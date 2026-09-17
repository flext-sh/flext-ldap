"""Pytest bootstrap for flext-ldap local package resolution."""

from __future__ import annotations

from pathlib import Path

from flext_tests.pytest_bootstrap import install_local_packages

install_local_packages(Path(__file__).resolve().parent)
