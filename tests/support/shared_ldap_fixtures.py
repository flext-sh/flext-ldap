"""Shared LDAP fixtures for integration tests.

This module provides fixtures and utilities for LDAP integration tests
that require Docker containers.
"""

from __future__ import annotations

import subprocess
from collections.abc import Callable

import pytest


def check_docker_available() -> bool:
    """Check if Docker is available and running."""
    try:
        result = subprocess.run(
            ["/usr/bin/docker", "info"],
            check=False,
            capture_output=True,
            text=True,
            timeout=10,
        )
        return result.returncode == 0
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return False


def skip_if_no_docker(func: Callable) -> Callable:
    """Decorator to skip test if Docker is not available."""
    return pytest.mark.skipif(
        not check_docker_available(), reason="Docker not available or not running"
    )(func)


__all__ = ["check_docker_available", "skip_if_no_docker"]
