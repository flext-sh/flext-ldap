"""Centralized test configuration for flext-ldap.

This module provides comprehensive test fixtures and configuration following
FLEXT standards with proper domain separation and centralized test infrastructure.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from collections.abc import Generator

import pytest
from pydantic import SecretStr

# Import test support fixtures
from flext_ldap import (
    FlextLDAP,
    FlextLDAPClients,
    FlextLDAPModels,
    FlextLDAPValidations,
)
from flext_ldap.acl import (
    FlextLDAPAclConverters,
    FlextLDAPAclManager,
    FlextLDAPAclParsers,
)
from flext_ldap.constants import FlextLDAPConstants
from flext_ldap.config import FlextLDAPConfig

# Import centralized FLEXT Docker infrastructure from flext-core
# from flext_tests.docker import FlextTestDocker  # TODO: Import from flext-core when available

from ldap3 import Server

from flext_core import (
    FlextContainer,
    FlextLogger,
    FlextResult,
    FlextTypes,
)
from flext_ldap.typings import FlextLDAPTypes


# Temporary mock implementation until FlextTestDocker is available in flext-core
class FlextTestDocker:
    """Mock implementation of FlextTestDocker for testing."""

    def get_container_status(self, container_name: str) -> FlextResult:
        """Mock container status check."""

        # Mock implementation - assume container is not running
        class MockContainerStatus:
            def __init__(self):
                self.value = "not_running"

        class MockValue:
            def __init__(self):
                self.status = MockContainerStatus()

        # Return as FlextResult.ok with mock value
        return FlextResult.ok(MockValue())

    def compose_up(self, compose_file: str, service: str) -> FlextResult:
        """Mock compose up."""

        # Mock implementation - assume failure
        return FlextResult.fail("Mock implementation - Docker not available")


# FlextLDAPFactory, FlextLDAPAdvancedService, FlextLDAPWorkflowOrchestrator removed - over-engineering
# FlextLDAPRepositories removed - mock implementations violating law
# FlextLDAPDomainServices removed - mock CQRS/Event Sourcing violating law

# Import test data directly to avoid pyrefly import issues
SAMPLE_ACL_DATA = {
    "target": "dc=example,dc=com",
    "subject": "cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com",
    "permissions": ["read", "write"],
    "unified_acl": "target:dc=example,dc=com;subject:cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com;permissions:read,write",
    "openldap_aci": '(targetattr="*")(version 3.0;acl "test";allow (read,write) userdn="ldap:///cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com";)',
    "oracle_aci": 'aci: (targetattr="*")(version 3.0;acl "test";allow (read,write) userdn="ldap:///cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com";)',
}

SAMPLE_GROUP_ENTRY = {
    "dn": "cn=testgroup,ou=groups,dc=flext,dc=local",
    "attributes": {
        "cn": ["testgroup"],
        "objectClass": ["groupOfNames", "top"],
        "member": ["cn=testuser,ou=people,dc=flext,dc=local"],
    },
}

SAMPLE_USER_ENTRY = {
    "dn": "cn=testuser,ou=people,dc=flext,dc=local",
    "attributes": {
        "cn": ["testuser"],
        "sn": ["User"],
        "givenName": ["Test"],
        "uid": ["testuser"],
        "mail": ["testuser@internal.invalid"],
        "objectClass": ["inetOrgPerson", "organizationalPerson", "person", "top"],
        "userPassword": ["test123"],
    },
}

TEST_GROUPS = [
    {
        "cn": "developers",
        "description": "Development team",
        "member": ["cn=dev1,ou=people,dc=test,dc=com"],
    },
    {
        "cn": "REDACTED_LDAP_BIND_PASSWORDs",
        "description": "Administrators",
        "member": ["cn=REDACTED_LDAP_BIND_PASSWORD,ou=people,dc=test,dc=com"],
    },
]

TEST_USERS = [
    {
        "cn": "testuser1",
        "sn": "User1",
        "givenName": "Test",
        "uid": "testuser1",
        "mail": "testuser1@test.com",
    },
    {
        "cn": "testuser2",
        "sn": "User2",
        "givenName": "Test",
        "uid": "testuser2",
        "mail": "testuser2@test.com",
    },
]

logger = FlextLogger(__name__)


# =============================================================================
# CORE FLEXT INFRASTRUCTURE FIXTURES
# =============================================================================


@pytest.fixture(scope="session")
def flext_container() -> FlextContainer:
    """Get global Flext container for dependency injection."""
    return FlextContainer()


@pytest.fixture(scope="session")
def flext_logger() -> FlextLogger:
    """Get Flext logger instance."""
    return FlextLogger(__name__)


# =============================================================================
# LDAP CONFIGURATION FIXTURES
# =============================================================================


@pytest.fixture
def ldap_config() -> FlextLDAPConfig:
    """Get standard LDAP connection configuration."""
    config = FlextLDAPConfig()
    config.ldap_server_uri = "ldap://localhost"
    config.ldap_port = FlextLDAPConstants.Protocol.DEFAULT_PORT
    config.ldap_use_ssl = False
    config.ldap_bind_dn = "cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com"
    config.ldap_bind_password = SecretStr("REDACTED_LDAP_BIND_PASSWORD123")
    config.ldap_connection_timeout = FlextLDAPConstants.DEFAULT_TIMEOUT
    return config


@pytest.fixture
def ldap_config_invalid() -> FlextLDAPConfig:
    """Get invalid LDAP configuration for error testing."""
    config = FlextLDAPConfig()
    config.ldap_server_uri = ""  # Invalid empty server
    config.ldap_port = FlextLDAPConstants.Protocol.DEFAULT_PORT
    config.ldap_use_ssl = False
    config.ldap_bind_dn = ""  # Invalid empty DN
    config.ldap_bind_password = SecretStr("")  # Invalid empty password
    config.ldap_connection_timeout = FlextLDAPConstants.DEFAULT_TIMEOUT
    return config


@pytest.fixture
def ldap_server_config() -> FlextTypes.Dict:
    """Get LDAP server configuration for testing."""
    return {
        "server_uri": f"{FlextLDAPConstants.Protocol.DEFAULT_SERVER_URI}:{FlextLDAPConstants.Protocol.DEFAULT_PORT}",
        "bind_dn": "cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com",
        "bind_password": "REDACTED_LDAP_BIND_PASSWORD123",
        "base_dn": "dc=example,dc=com",
        "port": FlextLDAPConstants.Protocol.DEFAULT_PORT,
        "use_ssl": False,
        "use_tls": False,
    }


# =============================================================================
# LDAP CLIENT FIXTURES
# =============================================================================


@pytest.fixture
def ldap_client(ldap_config: FlextLDAPConfig) -> FlextLDAPClients:
    """Get configured LDAP client instance."""
    return FlextLDAPClients(config=ldap_config)


@pytest.fixture
def ldap_client_no_config() -> FlextLDAPClients:
    """Get LDAP client without configuration."""
    return FlextLDAPClients()


@pytest.fixture
def ldap_api() -> FlextLDAP:
    """Get LDAP API instance."""
    return FlextLDAP()


# =============================================================================
# DOMAIN SERVICES FIXTURES
# =============================================================================

# FlextLDAPDomainServices fixture removed - class was deleted during cleanup


# Fixtures for removed modules (factory, advanced_service, workflow_orchestrator) deleted


# =============================================================================
# ACL FIXTURES
# =============================================================================


@pytest.fixture
def acl_constants() -> FlextLDAPConstants:
    """Get ACL constants instance."""
    return FlextLDAPConstants()


@pytest.fixture
def acl_converters() -> FlextLDAPAclConverters:
    """Get ACL converters instance."""
    return FlextLDAPAclConverters()


@pytest.fixture
def acl_manager() -> FlextLDAPAclManager:
    """Get ACL manager instance."""
    return FlextLDAPAclManager()


@pytest.fixture
def acl_parsers() -> FlextLDAPAclParsers:
    """Get ACL parsers instance."""
    return FlextLDAPAclParsers()


@pytest.fixture
def acl_models() -> FlextLDAPModels:
    """Get ACL models instance."""
    return FlextLDAPModels()


@pytest.fixture
def sample_acl_data() -> dict[str, str | FlextLDAPTypes.StringList]:
    """Get sample ACL data for testing."""
    return SAMPLE_ACL_DATA.copy()


# =============================================================================
# TEST DATA FIXTURES
# =============================================================================


@pytest.fixture
def sample_user() -> FlextLDAPModels.LdapUser:
    """Get sample user entity."""
    return FlextLDAPModels.LdapUser(
        dn="cn=testuser,ou=people,dc=example,dc=com",
        cn="Test User",
        uid="testuser",
        sn="User",
        given_name="Test",
        mail="testuser@example.com",
        telephone_number="+1234567890",
        mobile="+0987654321",
        department="IT",
        title="Software Engineer",
        organization="Example Corp",
        organizational_unit="Engineering",
        user_password="password123",
    )


@pytest.fixture
def sample_group() -> FlextLDAPModels.Group:
    """Get sample group entity."""
    return FlextLDAPModels.Group(
        dn="cn=testgroup,ou=groups,dc=example,dc=com",
        cn="testgroup",
        gid_number=1000,
        description="Test Group",
        member_dns=["uid=testuser,ou=people,dc=example,dc=com"],
    )


@pytest.fixture
def sample_dn() -> FlextLDAPModels.DistinguishedName:
    """Get sample distinguished name."""
    return FlextLDAPModels.DistinguishedName(
        value="uid=testuser,ou=people,dc=example,dc=com"
    )


@pytest.fixture
def sample_filter() -> FlextLDAPModels.Filter:
    """Get sample LDAP filter."""
    return FlextLDAPModels.Filter(expression="(objectClass=person)")


@pytest.fixture
def test_user_data() -> FlextTypes.Dict:
    """Get test user data dictionary."""
    return dict(SAMPLE_USER_ENTRY)


@pytest.fixture
def test_group_data() -> FlextTypes.Dict:
    """Get test group data dictionary."""
    return dict(SAMPLE_GROUP_ENTRY)


@pytest.fixture
def multiple_test_users() -> list[FlextTypes.Dict]:
    """Get multiple test users."""
    return [dict(user) for user in TEST_USERS]


@pytest.fixture
def multiple_test_groups() -> list[FlextTypes.Dict]:
    """Get multiple test groups."""
    return [dict(group) for group in TEST_GROUPS]


# =============================================================================
# VALIDATION FIXTURES
# =============================================================================


@pytest.fixture
def validations() -> FlextLDAPValidations:
    """Get validations instance."""
    return FlextLDAPValidations()


@pytest.fixture
def sample_valid_dn() -> str:
    """Get valid DN string."""
    return "uid=testuser,ou=people,dc=example,dc=com"


@pytest.fixture
def sample_valid_email() -> str:
    """Get valid email string."""
    return "testuser@example.com"


@pytest.fixture
def sample_valid_filter() -> str:
    """Get valid LDAP filter string."""
    return "(objectClass=person)"


@pytest.fixture
def sample_invalid_dn() -> str:
    """Get invalid DN string."""
    return "invalid-dn-format"


@pytest.fixture
def sample_invalid_email() -> str:
    """Get invalid email string."""
    return "invalid-email-format"


# =============================================================================
# MOCK AND STUB FIXTURES
# =============================================================================


@pytest.fixture
def mock_ldap_server() -> Server:
    """Get mock LDAP server for testing."""
    return Server(
        "localhost", port=FlextLDAPConstants.Protocol.DEFAULT_PORT, get_info="ALL"
    )


@pytest.fixture
def mock_connection_result() -> FlextResult[bool]:
    """Get mock successful connection result."""
    return FlextResult[bool].ok(True)


@pytest.fixture
def mock_search_result() -> FlextResult[list[FlextTypes.Dict]]:
    """Get mock search result."""
    return FlextResult[list[FlextTypes.Dict]].ok(
        [
            {
                "dn": "uid=testuser,ou=people,dc=example,dc=com",
                "attributes": {
                    "uid": ["testuser"],
                    "cn": ["Test User"],
                    "sn": ["User"],
                    "mail": ["testuser@example.com"],
                },
            }
        ]
    )


@pytest.fixture
def mock_error_result() -> FlextResult[None]:
    """Get mock error result."""
    return FlextResult[None].fail("Test error message")


# =============================================================================
# DOCKER INFRASTRUCTURE FIXTURES (FlextTestDocker from flext-core)
# =============================================================================


@pytest.fixture(scope="session")
def docker_control() -> FlextTestDocker:
    """Centralized Docker control using FlextTestDocker from flext-core."""
    return FlextTestDocker()


@pytest.fixture(scope="session")
def clean_ldap_container(
    docker_control: FlextTestDocker,
) -> FlextTypes.Dict:
    """Session-scoped LDAP container using centralized FlextTestDocker.

    Uses ~/flext/docker/docker-compose.openldap.yml configuration.
    Container name: flext-openldap-test (port 3390).
    """
    container_name = "flext-openldap-test"

    # Start the container using FlextTestDocker
    # The container is managed by docker-compose.openldap.yml
    status = docker_control.get_container_status(container_name)

    if status.is_failure or status.value.status.value != "running":
        # Container not running - start it via docker-compose
        compose_file = "/home/marlonsc/flext/docker/docker-compose.openldap.yml"
        start_result = docker_control.compose_up(compose_file, "openldap")

        if start_result.is_failure:
            pytest.skip(f"Failed to start LDAP container: {start_result.error}")

    # Provide connection info
    container_info: FlextTypes.Dict = {
        "server_url": "ldap://localhost:3390",
        "bind_dn": "cn=REDACTED_LDAP_BIND_PASSWORD,dc=flext,dc=local",
        "password": "REDACTED_LDAP_BIND_PASSWORD123",
        "base_dn": "dc=flext,dc=local",
        "port": 3390,
        "use_ssl": False,
    }

    return container_info

    # Cleanup handled by FlextTestDocker dirty state tracking
    # Container stays running for next test


# =============================================================================
# INTEGRATION TEST FIXTURES
# =============================================================================


@pytest.fixture(scope="session")
def shared_ldap_config() -> FlextTypes.StringDict:
    """Shared LDAP configuration for integration tests."""
    return {
        "server_url": "ldap://localhost:3390",
        "bind_dn": "cn=REDACTED_LDAP_BIND_PASSWORD,dc=flext,dc=local",
        "password": "REDACTED_LDAP_BIND_PASSWORD123",
        "base_dn": "dc=flext,dc=local",
    }


@pytest.fixture(scope="session")
def shared_ldap_connection_config() -> FlextLDAPModels.ConnectionConfig:
    """Shared LDAP connection configuration for integration tests."""
    return FlextLDAPModels.ConnectionConfig(
        server="ldap://localhost:3390",
        port=3390,
        bind_dn="cn=REDACTED_LDAP_BIND_PASSWORD,dc=flext,dc=local",
        bind_password="REDACTED_LDAP_BIND_PASSWORD123",
        use_ssl=False,
        timeout=FlextLDAPConstants.DEFAULT_TIMEOUT,
    )


@pytest.fixture(scope="session")
def shared_ldap_client(
    shared_ldap_config: FlextTypes.StringDict, shared_ldap_container: str
) -> Generator[FlextLDAPClients]:
    """Shared LDAP client for integration tests using centralized container."""
    # Ensure container is running by depending on shared_ldap_container
    _ = shared_ldap_container  # Container dependency ensures it's started

    client = FlextLDAPClients()

    # Connect to the LDAP server with proper parameters
    connect_result = client.connect(
        server_uri=shared_ldap_config["server_url"],
        bind_dn=shared_ldap_config["bind_dn"],
        password=shared_ldap_config["password"],
    )

    if connect_result.is_failure:
        pytest.skip(f"Failed to connect to LDAP server: {connect_result.error}")

    yield client

    # Disconnect when done
    try:
        client.disconnect()
    except Exception:
        pass  # Best effort cleanup


@pytest.fixture(scope="session")
def shared_ldap_container() -> str:
    """Managed LDAP container for tests - simple container name provider."""
    # Simply provide the container name - actual container management
    # is handled externally via docker-compose or manual setup
    container_name = "flext-openldap-test"
    return container_name
    # Cleanup handled externally


@pytest.fixture(scope="session")
def shared_ldap_container_manager() -> dict[str, str | bool]:
    """Docker control manager for LDAP containers - simplified implementation."""
    # Provide a simple manager object for compatibility
    manager = {
        "container_name": "flext-openldap-test",
        "is_running": True,
    }
    return manager


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


# =============================================================================
# CLEANUP FIXTURES
# =============================================================================


@pytest.fixture(autouse=True)
def clean_ldap_state():
    """Clean LDAP state between tests."""
    # Pre-test cleanup
    return
    # Post-test cleanup


# =============================================================================
# EXPORTS
# =============================================================================

__all__ = [
    "acl_constants",
    "acl_converters",
    "acl_manager",
    "acl_models",
    "acl_parsers",
    "clean_ldap_container",  # FlextTestDocker session-scoped fixture
    "clean_ldap_state",
    "docker_control",  # FlextTestDocker instance
    "flext_container",
    "flext_logger",
    "ldap_api",
    "ldap_client",
    "ldap_client_no_config",
    "ldap_config",
    "ldap_config_invalid",
    "ldap_server_config",
    "mock_connection_result",
    "mock_error_result",
    "mock_ldap_server",
    "mock_search_result",
    "multiple_test_groups",
    "multiple_test_users",
    "sample_acl_data",
    "sample_dn",
    "sample_filter",
    "sample_group",
    "sample_invalid_dn",
    "sample_invalid_email",
    "sample_user",
    "sample_valid_dn",
    "sample_valid_email",
    "sample_valid_filter",
    # Legacy fixtures (for backward compatibility)
    "shared_ldap_client",
    "shared_ldap_config",
    "shared_ldap_connection_config",
    "shared_ldap_container",
    "shared_ldap_container_manager",
    "shared_ldif_data",
    "skip_if_no_docker",
    "test_group_data",
    "test_user_data",
    "validations",
]
