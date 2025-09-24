"""Test configuration for flext-ldap.

This module imports all test fixtures and provides global test configuration.
"""

from collections.abc import Generator

import pytest

from flext_tests import FlextTestDocker

from .support.fixtures import (
    clean_ldap_container,
    clean_ldap_state,
    custom_event_loop,
    flext_ldap_api,
    flext_ldap_config,
    flext_ldap_validations,
    ldap_api,
    ldap_connection,
    multiple_test_groups,
    multiple_test_users,
    real_ldap_server,
    sample_connection_config,
    sample_valid_dn,
    sample_valid_email,
    sample_valid_filter,
    shared_ldap_client,
    shared_ldap_connection_config,
    test_group_data,
    test_ldap_config,
    test_user_data,
)


@pytest.fixture(scope="session")
def docker_control() -> FlextTestDocker:
    """Provide Docker control instance for tests."""
    return FlextTestDocker()


@pytest.fixture(scope="session")
def shared_ldap_config() -> dict[str, str]:
    """Shared LDAP configuration for integration tests."""
    return {
        "server_url": "ldap://localhost:3390",
        "bind_dn": "cn=REDACTED_LDAP_BIND_PASSWORD,dc=flext,dc=local",
        "password": "REDACTED_LDAP_BIND_PASSWORD123",
        "base_dn": "dc=flext,dc=local",
    }


@pytest.fixture(scope="session")
def shared_ldap_container(docker_control: FlextTestDocker) -> Generator[str]:
    """Managed LDAP container using FlextTestDocker with auto-start."""
    result = docker_control.start_container("flext-openldap-test")
    if result.is_failure:
        pytest.skip(f"Failed to start LDAP container: {result.error}")

    yield "flext-openldap-test"

    docker_control.stop_container("flext-openldap-test", remove=False)


@pytest.fixture(scope="session")
def shared_ldap_container_manager(docker_control: FlextTestDocker) -> FlextTestDocker:
    """Docker control manager for LDAP containers."""
    return docker_control


@pytest.fixture
def shared_ldif_data() -> str:
    """Shared LDIF test data."""
    return """dn: dc=flext,dc=local
objectClass: dcObject
objectClass: organization
dc: flext
o: FLEXT Organization

dn: ou=people,dc=flext,dc=local
objectClass: organizationalUnit
ou: people

dn: uid=john.doe,ou=people,dc=flext,dc=local
objectClass: inetOrgPerson
uid: john.doe
cn: John Doe
sn: Doe
mail: john.doe@internal.invalid
"""


@pytest.fixture
def skip_if_no_docker() -> None:
    """Dummy fixture - Docker availability checked elsewhere."""
    return


__all__ = [
    "clean_ldap_container",
    "clean_ldap_state",
    "custom_event_loop",
    "flext_ldap_api",
    "flext_ldap_config",
    "flext_ldap_validations",
    "ldap_api",
    "ldap_connection",
    "multiple_test_groups",
    "multiple_test_users",
    "real_ldap_server",
    "sample_connection_config",
    "sample_valid_dn",
    "sample_valid_email",
    "sample_valid_filter",
    "shared_ldap_client",
    "shared_ldap_config",
    "shared_ldap_connection_config",
    "shared_ldap_container",
    "shared_ldap_container_manager",
    "shared_ldif_data",
    "skip_if_no_docker",
    "test_group_data",
    "test_ldap_config",
    "test_user_data",
]
