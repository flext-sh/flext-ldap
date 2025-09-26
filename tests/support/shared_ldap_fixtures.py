"""Shared LDAP fixtures for integration tests.

This module provides fixtures and utilities for LDAP integration tests
that require Docker containers.
"""

from __future__ import annotations

from collections.abc import Callable

import pytest

from flext_tests import FlextTestDocker


def check_docker_available() -> bool:
    """Check if Docker is available and running using FlextTestDocker."""
    try:
        docker_manager = FlextTestDocker()

        # Use FlextTestDocker to check Docker availability
        version_result = docker_manager.get_docker_version()

        return version_result.is_success
    except Exception:
        return False


def skip_if_no_docker(func: Callable) -> Callable:
    """Decorator to skip test if Docker is not available."""
    return pytest.mark.skipif(
        not check_docker_available(), reason="Docker not available or not running"
    )(func)


__all__ = ["check_docker_available", "skip_if_no_docker"]
