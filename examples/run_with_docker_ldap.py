#!/usr/bin/env python3
"""Example of running FLEXT-LDAP examples with Docker OpenLDAP container.

This script automatically starts an OpenLDAP container and runs examples against it.
Perfect for testing and demonstration without needing a manual LDAP setup.

Copyright (c) 2025 FLEXT Contributors
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

import asyncio
import contextlib
import os
import sys
import time
from pathlib import Path

import docker
from integrated_ldap_service import main as integrated_main
from ldap_simple_client_example import main as simple_main


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
        except docker.errors.NotFound:
            pass

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
        from os import getenv

        from ldap3 import ALL, Connection, Server

        server = Server("localhost", port=389, get_info=ALL)
        for _attempt in range(30):
            try:
                with Connection(
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
        except docker.errors.NotFound:
            pass
    except (RuntimeError, ValueError, TypeError):
        pass


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

    # Run the integrated example
    try:
        sys.path.insert(0, str(Path(__file__).parent))

        await integrated_main()

    except (RuntimeError, ValueError, TypeError):
        pass

    # Run the simple client example
    with contextlib.suppress(RuntimeError, ValueError, TypeError):
        await simple_main()


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
        sys.exit(1)

    asyncio.run(main())
