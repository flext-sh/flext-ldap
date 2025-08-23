#!/usr/bin/env python3
"""Example of running FLEXT-LDAP examples with Docker OpenLDAP container.

This script automatically starts an OpenLDAP container and runs examples against it.
Perfect for testing and demonstration without needing a manual LDAP setup.

Copyright (c) 2025 FLEXT Contributors
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

import asyncio
import importlib
import importlib.util
import logging
import os
import time
import types
from pathlib import Path

import docker
from docker import errors as docker_errors

logger = logging.getLogger(__name__)


def _load_module_spec(module_name: str, file_path: Path) -> types.ModuleType:
    """Load a module spec and return the module."""
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
    """Start OpenLDAP container for testing."""
    try:
        client = docker.from_env()
        # Stop any existing container
        try:
            existing = client.containers.get("flext-ldap-example")
            try:
                existing.stop()
            finally:
                existing.remove(force=True)
        except docker_errors.NotFound:
            logger.debug("No existing container to stop", exc_info=True)

        # Start new container
        env = {
            "LDAP_ORGANISATION": "FLEXT Example Org",
            "LDAP_DOMAIN": "internal.invalid",
            "LDAP_ADMIN_PASSWORD": "REDACTED_LDAP_BIND_PASSWORD123",
            "LDAP_CONFIG_PASSWORD": "config123",
            "LDAP_READONLY_USER": "false",
            "LDAP_RFC2307BIS_SCHEMA": "true",
            "LDAP_BACKEND": "mdb",
            "LDAP_TLS": "false",
            "LDAP_REMOVE_CONFIG_AFTER_SETUP": "true",
        }
        client.containers.run(
            image="osixia/openldap:1.5.0",
            name="flext-ldap-example",
            detach=True,
            ports={"389/tcp": 3389},
            environment=env,
        )

        # Wait for container to be ready
        from os import getenv  # noqa: PLC0415

        ldap3 = importlib.import_module("ldap3")
        server = ldap3.Server("localhost", port=389, get_info=ldap3.ALL)
        for _attempt in range(30):
            try:
                with ldap3.Connection(
                    server,
                    user="cn=REDACTED_LDAP_BIND_PASSWORD,dc=flext,dc=local",
                    password=getenv("LDAP_TEST_PASSWORD", ""),
                    auto_bind=True,
                ) as conn:
                    if conn.bound:
                        return True
            except Exception:
                time.sleep(1)

        return False

    except (RuntimeError, ValueError, TypeError):
        logger.exception("Failed to start OpenLDAP container")
        return False


def stop_openldap_container() -> None:
    """Stop and remove OpenLDAP container."""
    try:
        client = docker.from_env()
        try:
            c = client.containers.get("flext-ldap-example")
            try:
                c.stop()
            finally:
                c.remove(force=True)
        except docker_errors.NotFound:
            logger.debug("Container not found when stopping", exc_info=True)
    except (RuntimeError, ValueError, TypeError) as e:
        logger.warning("Failed to stop container: %s", e)


async def run_examples_with_docker() -> None:
    """Run FLEXT-LDAP examples against Docker OpenLDAP."""
    # Set environment variables for container
    os.environ.update(
        {
            "LDAP_TEST_SERVER": "ldap://localhost:3389",
            "LDAP_TEST_BIND_DN": "cn=REDACTED_LDAP_BIND_PASSWORD,dc=flext,dc=local",
            "LDAP_TEST_PASSWORD": "REDACTED_LDAP_BIND_PASSWORD123",
            "LDAP_TEST_BASE_DN": "dc=flext,dc=local",
        },
    )

    # Run the integrated example (best-effort)
    try:
        integrated_path = Path(__file__).parent / "integrated_ldap_service.py"
        integrated_module: types.ModuleType = _load_module_spec("integrated_ldap_service", integrated_path)
        main_func = getattr(integrated_module, "main")
        await main_func()
    except Exception:
        logger.exception("Integrated example failed")

    # Run the simple client example (best-effort)
    try:
        simple_path = Path(__file__).parent / "ldap_simple_client_example.py"
        simple_module: types.ModuleType = _load_module_spec("ldap_simple_client_example", simple_path)
        main_func = getattr(simple_module, "main")
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
    # Check if Docker is available by listing containers
    try:
        docker_client = docker.from_env()
        # Check connectivity by listing containers
        _ = docker_client.containers.list()
    except Exception as e:
        raise SystemExit(1) from e

    asyncio.run(main())
