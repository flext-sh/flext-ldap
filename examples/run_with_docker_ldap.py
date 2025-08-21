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
import logging
import os
import time
from pathlib import Path

import docker
from docker import errors as docker_errors

logger = logging.getLogger(__name__)


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
            "LDAP_DOMAIN": "flext.local",
            "LDAP_ADMIN_PASSWORD": "admin123",
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
                    user="cn=admin,dc=flext,dc=local",
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
            "LDAP_TEST_BIND_DN": "cn=admin,dc=flext,dc=local",
            "LDAP_TEST_PASSWORD": "admin123",
            "LDAP_TEST_BASE_DN": "dc=flext,dc=local",
        },
    )

    # Run the integrated example (best-effort)
    try:
        import importlib.util

        integrated_path = Path(__file__).parent / "integrated_ldap_service.py"
        spec = importlib.util.spec_from_file_location(
            "integrated_ldap_service",
            str(integrated_path),
        )
        assert spec
        assert spec.loader
        integrated_module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(integrated_module)
        await integrated_module.main()
    except Exception:
        logger.exception("Integrated example failed")

    # Run the simple client example (best-effort)
    try:
        import importlib.util

        simple_path = Path(__file__).parent / "ldap_simple_client_example.py"
        spec = importlib.util.spec_from_file_location(
            "ldap_simple_client_example",
            str(simple_path),
        )
        assert spec
        assert spec.loader
        simple_module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(simple_module)
        await simple_module.main()
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
    # Check if Docker is available by pinging the daemon
    try:
        docker.from_env().ping()
    except Exception:
        raise SystemExit(1)

    asyncio.run(main())
