#!/usr/bin/env python3
"""Example of running FLEXT-LDAP examples with shared Docker OpenLDAP container.

This script automatically starts the shared OpenLDAP container and runs examples against it.
Uses the same container definition as flext-ldif and other FLEXT projects to avoid conflicts.

Copyright (c) 2025 FLEXT Contributors
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

import asyncio
import importlib
import importlib.util
import os
import types
from pathlib import Path

from flext_core import FlextLogger
from flext_tests import FlextTestDocker

logger = FlextLogger(__name__)


def _load_module_spec(module_name: str, file_path: Path) -> types.ModuleType:
    """Load a module spec and return the module.

    Returns:
        types.ModuleType: The loaded module.

    Raises:
        ImportError: If module spec creation or loading fails.

    """
    spec = importlib.util.spec_from_file_location(module_name, str(file_path))
    if not spec:
        msg = f"Failed to create module spec for {module_name}"
        raise ImportError(msg)
    if not spec.loader:
        msg = f"Module spec has no loader for {module_name}"
        raise ImportError(msg)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def start_openldap_container() -> bool:
    """Start shared OpenLDAP container for testing.

    Returns:
        bool: True if container started successfully, False otherwise.

    """
    try:
        # Use FlextTestDocker for container management
        docker_manager = FlextTestDocker()
        result = docker_manager.start_container("flext-openldap-test")
        return result.is_success

    except (RuntimeError, ValueError, TypeError):
        logger.exception("Failed to start shared OpenLDAP container")
        return False


def stop_openldap_container() -> None:
    """Stop and remove shared OpenLDAP container."""
    try:
        # Use FlextTestDocker for container management
        docker_manager = FlextTestDocker()
        docker_manager.stop_container("flext-openldap-test", remove=False)
    except (RuntimeError, ValueError, TypeError) as e:
        logger.warning("Failed to stop shared container: %s", e)


async def run_examples_with_docker() -> None:
    """Run FLEXT-LDAP examples against shared Docker OpenLDAP."""
    # Set environment variables for shared container
    os.environ.update(
        {
            "LDAP_TEST_SERVER": "ldap://localhost:3390",
            "LDAP_TEST_BIND_DN": "cn=REDACTED_LDAP_BIND_PASSWORD,dc=flext,dc=local",
            "LDAP_TEST_PASSWORD": "REDACTED_LDAP_BIND_PASSWORD123",
            "LDAP_TEST_BASE_DN": "dc=flext,dc=local",
        },
    )

    # Run the integrated example (best-effort)
    try:
        integrated_path = Path(__file__).parent / "integrated_ldap_service.py"
        integrated_module: types.ModuleType = _load_module_spec(
            "integrated_ldap_service",
            integrated_path,
        )
        main_func = integrated_module.main
        await main_func()
    except Exception:
        logger.exception("Integrated example failed")

    # Run the simple client example (best-effort)
    try:
        simple_path = Path(__file__).parent / "03_ldap_simple_client.py"
        simple_module: types.ModuleType = _load_module_spec(
            "ldap_simple_client",
            simple_path,
        )
        main_func = simple_module.main
        await main_func()
    except Exception:
        logger.exception("Simple client example failed")


async def main() -> None:
    """Run the main execution function."""
    # Start container
    if not start_openldap_container():
        return

    try:
        # Run examples
        await run_examples_with_docker()

    finally:
        # Always cleanup
        stop_openldap_container()


if __name__ == "__main__":
    # Check if Docker is available using FlextTestDocker
    try:
        docker_manager = FlextTestDocker()
        # Test Docker connectivity
        if not docker_manager.get_container_status("test-container").is_success:
            logger.info("Docker is accessible for container management")
    except Exception as e:
        logger.exception("Docker connectivity check failed")
        raise SystemExit(1) from e

    asyncio.run(main())
