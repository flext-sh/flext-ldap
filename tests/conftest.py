"""Pytest configuration and fixtures for flext-ldap tests.

Reuses fixtures from tests.bak, adapted for new API structure.
Uses FlextTestDocker for container management.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

from collections.abc import Generator
from pathlib import Path

import pytest
from flext_core import FlextLogger
from flext_ldif.services.parser import FlextLdifParser
from flext_tests import FlextTestDocker
from ldap3 import Connection, Server

from flext_ldap import FlextLdap
from flext_ldap.adapters.ldap3 import Ldap3Adapter
from flext_ldap.config import FlextLdapConfig
from flext_ldap.models import FlextLdapModels
from flext_ldap.services.connection import FlextLdapConnection
from flext_ldap.services.operations import FlextLdapOperations
from tests.fixtures.loader import LdapTestFixtures

logger = FlextLogger(__name__)

# Register FlextTestDocker pytest fixtures in this module's namespace
FlextTestDocker.register_pytest_fixtures(namespace=globals())


# =============================================================================
# DOCKER CONTAINER FIXTURES (using FlextTestDocker)
# =============================================================================


@pytest.fixture(scope="session")
def ldap_container(
    docker_control: FlextTestDocker,  # From FlextTestDocker
) -> dict[str, object]:
    """Session-scoped LDAP container configuration.

    Uses FlextTestDocker to manage flext-openldap-test container.
    Container is automatically started/stopped by FlextTestDocker.

    Args:
        docker_control: FlextTestDocker instance from fixture

    Returns:
        dict with connection parameters

    """
    # Use the actual container name from SHARED_CONTAINERS
    container_name = "flext-openldap-test"
    container_config = FlextTestDocker.SHARED_CONTAINERS.get(container_name)

    if not container_config:
        pytest.skip(f"Container {container_name} not found in SHARED_CONTAINERS")

    # Get compose file path
    compose_file = str(container_config["compose_file"])
    if not compose_file.startswith("/"):
        # Relative path, make it absolute from workspace root
        # Workspace root is /home/marlonsc/flext
        workspace_root = Path("/home/marlonsc/flext")
        compose_file = str(workspace_root / compose_file)

    # Check if container is running, if not start it using docker-compose
    status = docker_control.get_container_status(container_name)
    if not status.is_success or (
        isinstance(status.value, FlextTestDocker.ContainerInfo)
        and status.value.status != FlextTestDocker.ContainerStatus.RUNNING
    ):
        # Container doesn't exist or not running, start it using docker-compose
        start_result = docker_control.start_compose_stack(compose_file)
        if start_result.is_failure:
            pytest.skip(f"Failed to start LDAP container: {start_result.error}")

    # Provide connection info (matches docker-compose.openldap.yml)
    container_info: dict[str, object] = {
        "server_url": "ldap://localhost:3390",
        "host": "localhost",
        "bind_dn": "cn=admin,dc=flext,dc=local",
        "password": "admin123",  # From docker-compose.openldap.yml
        "base_dn": "dc=flext,dc=local",
        "port": 3390,
        "use_ssl": False,
    }

    return container_info


# =============================================================================
# CONFIGURATION FIXTURES
# =============================================================================


@pytest.fixture(scope="module")
def ldap_parser() -> FlextLdifParser:
    """Get standard LDIF parser instance for tests.

    Module-scoped to match ldap_client fixture scope for performance.
    """
    return FlextLdifParser()


@pytest.fixture(scope="module")
def ldap_config(ldap_container: dict[str, object]) -> FlextLdapConfig:
    """Get standard LDAP connection configuration.

    Module-scoped to match ldap_client fixture scope for performance.
    """
    port_value = ldap_container["port"]
    port_int = int(port_value) if isinstance(port_value, (int, str)) else 3390

    return FlextLdapConfig(
        ldap_host=str(ldap_container["host"]),
        ldap_port=port_int,
        ldap_use_ssl=False,
        ldap_bind_dn=str(ldap_container["bind_dn"]),
        ldap_bind_password=str(ldap_container["password"]),
    )


@pytest.fixture(scope="module")
def connection_config(
    ldap_container: dict[str, object],
) -> FlextLdapModels.ConnectionConfig:
    """Create connection configuration for testing.

    Module-scoped to match ldap_client fixture scope for performance.
    """
    port_value = ldap_container["port"]
    port_int = int(port_value) if isinstance(port_value, (int, str)) else 3390

    return FlextLdapModels.ConnectionConfig(
        host=str(ldap_container["host"]),
        port=port_int,
        use_ssl=False,
        bind_dn=str(ldap_container["bind_dn"]),
        bind_password=str(ldap_container["password"]),
    )


@pytest.fixture
def search_options(ldap_container: dict[str, object]) -> FlextLdapModels.SearchOptions:
    """Create search options for testing."""
    return FlextLdapModels.SearchOptions(
        base_dn=str(ldap_container["base_dn"]),
        filter_str="(objectClass=*)",
        scope="SUBTREE",
    )


# =============================================================================
# LDAP CLIENT FIXTURES
# =============================================================================


@pytest.fixture(scope="module")
def ldap_client(
    connection_config: FlextLdapModels.ConnectionConfig,
    ldap_test_data_loader: Connection,
    ldap_config: FlextLdapConfig,
    ldap_parser: FlextLdifParser,
) -> Generator[FlextLdap]:
    """Get configured LDAP client instance with real connection.

    Module-scoped to reuse connection across tests in same module for performance.
    Tests should clean up their own data to avoid state corruption.
    Ensures OUs exist via ldap_test_data_loader fixture.
    """
    # Ensure OUs exist (ldap_test_data_loader creates them)
    _ = ldap_test_data_loader

    client = FlextLdap(config=ldap_config, parser=ldap_parser)

    # Connect to the LDAP server
    connect_result = client.connect(connection_config)
    if connect_result.is_failure:
        pytest.skip(f"Failed to connect to LDAP server: {connect_result.error}")

    yield client

    # Disconnect when done - CRITICAL for cleanup
    try:
        client.disconnect()
    except Exception as e:
        logger.warning("LDAP client disconnection failed: %s", e)


# =============================================================================
# TEST DATA FIXTURES
# =============================================================================


@pytest.fixture(scope="session")
def ldap_test_data_loader(
    ldap_container: dict[str, object],
) -> Generator[Connection]:
    """Session-scoped test data loader for LDAP integration tests.

    Creates real LDAP connection and initializes comprehensive test data.
    Test data is cleaned up after all tests complete.

    Uses FlextTestDocker managed container.
    """
    try:
        # Create connection to LDAP server (managed by FlextTestDocker)
        server = Server("ldap://localhost:3390", get_info="ALL")
        connection = Connection(
            server,
            user=str(ldap_container["bind_dn"]),
            password=str(ldap_container["password"]),
            auto_bind=True,
            auto_referrals=False,
        )

        # Create organizational units if they don't exist
        ous = [
            ("ou=people,dc=flext,dc=local", "people"),
            ("ou=groups,dc=flext,dc=local", "groups"),
            ("ou=system,dc=flext,dc=local", "system"),
        ]

        for ou_dn, ou_name in ous:
            try:
                _ = connection.add(
                    ou_dn,
                    attributes={
                        "objectClass": ["organizationalUnit", "top"],
                        "ou": ou_name,
                    },
                )
            except Exception:
                pass  # OU might already exist

        yield connection

        # Cleanup after all tests
        try:
            # Delete test entries (but keep OUs)
            test_dns = [
                "uid=testuser,ou=people,dc=flext,dc=local",
                "uid=testuser2,ou=people,dc=flext,dc=local",
                "uid=testuser3,ou=people,dc=flext,dc=local",
                "cn=testgroup,ou=groups,dc=flext,dc=local",
                "cn=testgroup2,ou=groups,dc=flext,dc=local",
            ]
            for dn in test_dns:
                try:
                    _ = connection.delete(dn)
                except Exception:
                    pass  # Entry might not exist

        except Exception:
            pass  # Cleanup failure is non-critical

        # Close connection
        if connection.bound:
            connection.unbind()

    except Exception as e:
        logger.exception("Failed to initialize test data loader")
        pytest.skip(f"Test data loader initialization failed: {e!s}")


# =============================================================================
# FIXTURE DATA LOADERS
# =============================================================================


@pytest.fixture
def test_users_json() -> list[dict[str, object]]:
    """Load test users from JSON fixture file."""
    return LdapTestFixtures.load_users_json()


@pytest.fixture
def test_groups_json() -> list[dict[str, object]]:
    """Load test groups from JSON fixture file."""
    return LdapTestFixtures.load_groups_json()


@pytest.fixture
def base_ldif_content() -> str:
    """Load base LDIF structure from fixture file."""
    return LdapTestFixtures.load_base_ldif()


@pytest.fixture
def base_ldif_entries() -> list[object]:
    """Load and parse base LDIF structure to Entry models."""
    return LdapTestFixtures.load_base_ldif_entries()


@pytest.fixture
def test_user_entry(test_users_json: list[dict[str, object]]) -> dict[str, object]:
    """Get first test user as Entry-compatible dict."""
    if not test_users_json:
        pytest.skip("No test users available")

    return LdapTestFixtures.convert_user_json_to_entry(test_users_json[0])


@pytest.fixture
def test_group_entry(test_groups_json: list[dict[str, object]]) -> dict[str, object]:
    """Get first test group as Entry-compatible dict."""
    if not test_groups_json:
        pytest.skip("No test groups available")

    return LdapTestFixtures.convert_group_json_to_entry(test_groups_json[0])


# =============================================================================
# SAMPLE TEST DATA
# =============================================================================


SAMPLE_USER_ENTRY = {
    "dn": "cn=testuser,ou=people,dc=flext,dc=local",
    "attributes": {
        "cn": ["testuser"],
        "sn": ["User"],
        "givenName": ["Test"],
        "uid": ["testuser"],
        "mail": ["testuser@flext.local"],
        "objectClass": ["inetOrgPerson", "organizationalPerson", "person", "top"],
        "userPassword": ["test123"],
    },
}

SAMPLE_GROUP_ENTRY = {
    "dn": "cn=testgroup,ou=groups,dc=flext,dc=local",
    "attributes": {
        "cn": ["testgroup"],
        "objectClass": ["groupOfNames", "top"],
        "member": ["cn=testuser,ou=people,dc=flext,dc=local"],
    },
}


@pytest.fixture
def ldap_connection(
    ldap_config: FlextLdapConfig,
    ldap_parser: FlextLdifParser,
) -> FlextLdapConnection:
    """Get FlextLdapConnection instance for testing."""
    return FlextLdapConnection(config=ldap_config, parser=ldap_parser)


@pytest.fixture
def ldap_operations(ldap_connection: FlextLdapConnection) -> FlextLdapOperations:
    """Get FlextLdapOperations instance for testing."""
    return FlextLdapOperations(connection=ldap_connection)


@pytest.fixture
def ldap3_adapter(ldap_parser: FlextLdifParser) -> Ldap3Adapter:
    """Get Ldap3Adapter instance for testing."""
    return Ldap3Adapter(parser=ldap_parser)


@pytest.fixture
def flext_ldap_instance(
    ldap_config: FlextLdapConfig,
    ldap_parser: FlextLdifParser,
) -> FlextLdap:
    """Get FlextLdap instance without connection."""
    return FlextLdap(config=ldap_config, parser=ldap_parser)
