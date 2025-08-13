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
import shutil
import subprocess
import sys
import time
from pathlib import Path

from integrated_ldap_service import main as integrated_main
from ldap_simple_client_example import main as simple_main


def start_openldap_container() -> bool:
    """Start OpenLDAP container for testing."""
    try:
        # Stop any existing container
        docker_path = shutil.which("docker") or "docker"
        subprocess.run(
            [docker_path, "stop", "flext-ldap-example"],
            check=False,
        )
        subprocess.run(
            [docker_path, "rm", "flext-ldap-example"],
            check=False,
        )

        # Start new container
        cmd = [
            docker_path,
            "run",
            "-d",
            "--name",
            "flext-ldap-example",
            "-p",
            "3389:389",
            "-e",
            "LDAP_ORGANISATION=FLEXT Example Org",
            "-e",
            "LDAP_DOMAIN=flext.local",
            "-e",
            "LDAP_ADMIN_PASSWORD=admin123",
            "-e",
            "LDAP_CONFIG_PASSWORD=config123",
            "-e",
            "LDAP_READONLY_USER=false",
            "-e",
            "LDAP_RFC2307BIS_SCHEMA=true",
            "-e",
            "LDAP_BACKEND=mdb",
            "-e",
            "LDAP_TLS=false",
            "-e",
            "LDAP_REMOVE_CONFIG_AFTER_SETUP=true",
            "osixia/openldap:1.5.0",
        ]
        subprocess.run(cmd, check=True)

        # Wait for container to be ready
        for _attempt in range(30):
            try:
                result = subprocess.run(
                    [
                        docker_path,
                        "exec",
                        "flext-ldap-example",
                        "ldapsearch",
                        "-x",
                        "-H",
                        "ldap://localhost:389",
                        "-D",
                        "cn=admin,dc=flext,dc=local",
                        "-w",
                        "admin123",
                        "-b",
                        "dc=flext,dc=local",
                        "-s",
                        "base",
                        "(objectClass=*)",
                    ],
                    capture_output=True,
                    check=True,
                )

                if result.returncode == 0:
                    return True

            except subprocess.CalledProcessError:
                time.sleep(1)

        return False

    except (RuntimeError, ValueError, TypeError):
        return False


def stop_openldap_container() -> None:
    """Stop and remove OpenLDAP container."""
    try:
        docker_path = shutil.which("docker") or "docker"
        subprocess.run([docker_path, "stop", "flext-ldap-example"], check=False)
        subprocess.run([docker_path, "rm", "flext-ldap-example"], check=False)
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
    # Check if Docker is available
    try:
        docker_path = shutil.which("docker") or "docker"
        subprocess.run([docker_path, "--version"], check=True, capture_output=True)
    except (subprocess.CalledProcessError, FileNotFoundError):
        sys.exit(1)

    asyncio.run(main())
