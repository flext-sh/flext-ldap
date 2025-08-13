"""Global pytest configuration for FLEXT-LDAP tests.

This module provides fixtures for OpenLDAP container management and test configuration.
"""

from __future__ import annotations

import os
import time
from contextlib import asynccontextmanager
from functools import lru_cache
from typing import TYPE_CHECKING

try:
    import docker  # type: ignore[import-not-found]
except Exception:  # pragma: no cover - docker may be unavailable in CI
    docker = None  # type: ignore[assignment]
import pytest

from flext_ldap.constants import FlextLdapScope
from flext_ldap.infrastructure import FlextLdapClient
from flext_ldap.models import FlextLdapDistinguishedName, FlextLdapFilter

if TYPE_CHECKING:
    from collections.abc import AsyncGenerator, Generator

    from docker.client import DockerClient
    from docker.models.containers import Container

# OpenLDAP Container Configuration
OPENLDAP_IMAGE = "osixia/openldap:1.5.0"
OPENLDAP_CONTAINER_NAME = "flext-ldap-test-server"
OPENLDAP_PORT = 3390  # Use non-standard port to avoid conflicts
OPENLDAP_ADMIN_PASSWORD = "REDACTED_LDAP_BIND_PASSWORD123"
OPENLDAP_DOMAIN = "internal.invalid"
OPENLDAP_BASE_DN = f"dc={',dc='.join(OPENLDAP_DOMAIN.split('.'))}"
OPENLDAP_ADMIN_DN = f"cn=REDACTED_LDAP_BIND_PASSWORD,{OPENLDAP_BASE_DN}"

# Test Environment Variables
TEST_ENV_VARS = {
    "LDAP_TEST_SERVER": f"ldap://localhost:{OPENLDAP_PORT}",
    "LDAP_TEST_BIND_DN": OPENLDAP_ADMIN_DN,
    "LDAP_TEST_PASSWORD": OPENLDAP_ADMIN_PASSWORD,
    "LDAP_TEST_BASE_DN": OPENLDAP_BASE_DN,
}


class OpenLDAPContainerManager:
    """Manages OpenLDAP Docker container for testing."""

    def __init__(self) -> None:
        """Initialize the container manager."""
        self.client: DockerClient = docker.from_env()
        self.container: Container | None = None

    def start_container(self) -> Container:
        """Start OpenLDAP container with proper configuration."""
        # Stop and remove existing container if it exists
        self.stop_container()

        # Start new container
        self.container = self.client.containers.run(
            OPENLDAP_IMAGE,
            name=OPENLDAP_CONTAINER_NAME,
            ports={"389/tcp": OPENLDAP_PORT},
            environment={
                "LDAP_ORGANISATION": "FLEXT Test Org",
                "LDAP_DOMAIN": OPENLDAP_DOMAIN,
                "LDAP_ADMIN_PASSWORD": OPENLDAP_ADMIN_PASSWORD,
                "LDAP_CONFIG_PASSWORD": "config123",
                "LDAP_READONLY_USER": "false",
                "LDAP_RFC2307BIS_SCHEMA": "true",
                "LDAP_BACKEND": "mdb",
                "LDAP_TLS": "false",
                "LDAP_REMOVE_CONFIG_AFTER_SETUP": "true",
                "LDAP_SSL_HELPER_PREFIX": "ldap",
            },
            detach=True,
            remove=True,  # Automatically remove when stopped
        )

        # Wait for container to be ready
        self._wait_for_container_ready()

        return self.container

    def stop_container(self) -> None:
        """Stop and remove OpenLDAP container."""
        try:
            # Try to get existing container by name (handles both running and stopped)
            existing = self.client.containers.get(OPENLDAP_CONTAINER_NAME)
            if existing.status in {"running", "created", "paused"}:
                existing.stop(timeout=5)
            existing.remove(force=True)
        except docker.errors.NotFound:
            pass  # Container doesn't exist, nothing to stop
        except docker.errors.APIError as e:
            # Handle conflicts (409) - another process is already removing
            if e.status_code == 409:
                pass  # Container removal already in progress - that's fine
            else:
                # Re-raise other API errors
                raise
        except (RuntimeError, ValueError, TypeError):
            # Try to force remove by name if getting by ID fails
            from contextlib import suppress

            with suppress(RuntimeError, ValueError, TypeError, docker.errors.APIError):
                self.client.api.remove_container(OPENLDAP_CONTAINER_NAME, force=True)

        self.container = None

    def _raise_container_error(self, msg: str) -> None:
        """Raise container error with message."""
        raise RuntimeError(msg)

    def _wait_for_container_ready(self, timeout: int = 30) -> None:
        """Wait for OpenLDAP container to be ready to accept connections."""
        if not self.container:
            no_container_msg = "No container to wait for"
            raise RuntimeError(no_container_msg)

        start_time = time.time()
        while time.time() - start_time < timeout:
            try:
                # Check if container is still running
                self.container.reload()
                if self.container.status != "running":
                    start_fail_msg: str = (
                        f"Container failed to start: {self.container.status}"
                    )
                    self._raise_container_error(start_fail_msg)

                # Try to connect to LDAP port
                exec_result = self.container.exec_run(
                    [
                        "ldapsearch",
                        "-x",
                        "-H",
                        "ldap://localhost:389",
                        "-D",
                        OPENLDAP_ADMIN_DN,
                        "-w",
                        OPENLDAP_ADMIN_PASSWORD,
                        "-b",
                        OPENLDAP_BASE_DN,
                        "-s",
                        "base",
                        "(objectClass=*)",
                    ],
                    demux=True,
                )

                if exec_result.exit_code == 0:
                    # Success! Container is ready
                    return

            except (RuntimeError, ValueError, TypeError):
                pass  # Continue waiting

            time.sleep(1)

        timeout_msg: str = (
            f"OpenLDAP container failed to become ready within {timeout} seconds"
        )
        raise RuntimeError(timeout_msg)

    def is_container_running(self) -> bool:
        """Check if the OpenLDAP container is running."""
        if not self.container:
            return False

        try:
            self.container.reload()
            return self.container.status == "running"
        except (RuntimeError, ValueError, TypeError):
            return False

    def get_logs(self) -> str:
        """Get container logs for debugging."""
        if not self.container:
            return "No container running"

        try:
            return self.container.logs().decode()
        except (RuntimeError, ValueError, TypeError) as e:
            return f"Failed to get logs: {e}"


# Container manager accessor without module-level mutable global
@lru_cache(maxsize=1)
def _get_container_manager() -> OpenLDAPContainerManager:
    return OpenLDAPContainerManager()


@pytest.fixture(scope="session")
def docker_openldap_container() -> Generator[Container]:
    """Session-scoped fixture that provides OpenLDAP Docker container.

    This fixture starts an OpenLDAP container at the beginning of the test session
    and stops it at the end. The container is shared across all tests.
    """
    if docker is None:
        pytest.skip("Docker not installed; skipping integration container fixture")
    manager = _get_container_manager()
    # Start container
    container = manager.start_container()

    # Set environment variables for tests
    for key, value in TEST_ENV_VARS.items():
        os.environ[key] = value

    yield container

    # Cleanup
    manager.stop_container()

    # Clean up environment variables
    for key in TEST_ENV_VARS:
        os.environ.pop(key, None)


@pytest.fixture
def ldap_test_config(docker_openldap_container: Container) -> dict[str, object]:
    """Provide LDAP test configuration for individual tests."""
    return {
        "server_url": TEST_ENV_VARS["LDAP_TEST_SERVER"],
        "bind_dn": TEST_ENV_VARS["LDAP_TEST_BIND_DN"],
        "password": TEST_ENV_VARS["LDAP_TEST_PASSWORD"],
        "base_dn": TEST_ENV_VARS["LDAP_TEST_BASE_DN"],
        "container": docker_openldap_container,
    }


async def _cleanup_ldap_entries_under_dn(
    client: FlextLdapClient, connection_id: str, dn: str
) -> None:
    """Clean up LDAP entries under a DN to reduce nested control flow."""
    # Try to delete all entries under the specified DN
    search_result = await client.search(
        connection_id,
        FlextLdapDistinguishedName(dn=dn),
        FlextLdapFilter(filter_string="(objectClass=*)"),
        scope=FlextLdapScope.SUB,
    )

    # Early return if search failed or no data
    if not search_result.success or not search_result.data:
        return

    # Delete entries (except the OU itself)
    for entry in search_result.data:
        entry_dn = entry.get("dn", "")
        if entry_dn and entry_dn != dn:
            await client.delete_entry(
                connection_id, FlextLdapDistinguishedName(dn=str(entry_dn))
            )


@pytest.fixture
async def clean_ldap_container(
    ldap_test_config: dict[str, object],
) -> dict[str, object]:
    """Provide a clean LDAP container by removing test entries.

    This fixture ensures each test starts with a clean LDAP directory
    by removing any test entries that might have been left behind.
    """
    client = FlextLdapClient()

    # Connect to LDAP
    connect_result = await client.connect(
        str(ldap_test_config["server_url"]),
        str(ldap_test_config["bind_dn"]),
        str(ldap_test_config["password"]),
    )

    if connect_result.success:
        connection_id = str(connect_result.data)

        try:
            # Clean up test entries
            test_dns = [
                f"ou=users,{ldap_test_config['base_dn']}",
                f"ou=groups,{ldap_test_config['base_dn']}",
            ]

            for dn in test_dns:
                await _cleanup_ldap_entries_under_dn(client, connection_id, dn)

        finally:
            await client.disconnect(connection_id)

    return ldap_test_config


@asynccontextmanager
async def temporary_ldap_entry(
    client: FlextLdapClient,
    connection_id: str,
    dn: str,
    attributes: dict[str, list[str]],
) -> AsyncGenerator[str]:
    """Context manager for temporary LDAP entries that are auto-cleaned."""
    try:
        # Create entry
        result = await client.create_entry(
            connection_id, FlextLdapDistinguishedName(dn=dn), attributes
        )
        if not result.success:
            msg: str = f"Failed to create temporary entry {dn}: {result.error}"
            raise RuntimeError(msg)

        yield dn

    finally:
        # Auto-cleanup
        import contextlib

        with contextlib.suppress(RuntimeError, ValueError, TypeError):
            await client.delete_entry(connection_id, FlextLdapDistinguishedName(dn=dn))


# Mark integration tests
def pytest_configure(config: pytest.Config) -> None:
    """Configure pytest markers."""
    config.addinivalue_line(
        "markers",
        "integration: marks tests as integration tests requiring Docker",
    )


def pytest_collection_modifyitems(
    config: pytest.Config, items: list[pytest.Item]
) -> None:
    """Automatically mark integration tests based on file path."""
    for item in items:
        # Mark tests in integration directory
        if "integration" in str(item.fspath):
            item.add_marker(pytest.mark.integration)
