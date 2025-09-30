"""Centralized test configuration for flext-ldap.

This module provides comprehensive test fixtures and configuration following
FLEXT standards with proper domain separation and centralized test infrastructure.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import asyncio
from collections.abc import AsyncGenerator, Generator
from typing import Any, TYPE_CHECKING

import pytest
from ldap3 import Server

from flext_core import (
    FlextBus,
    FlextContainer,
    FlextDispatcher,
    FlextLogger,
    FlextModels,
    FlextProcessors,
    FlextRegistry,
    FlextResult,
)

# Import centralized Docker fixtures

if TYPE_CHECKING:
    pass
from flext_ldap import (
    FlextLdapAPI,
    FlextLdapClient,
    FlextLdapModels,
    FlextLdapValidations,
)
from flext_ldap.constants import FlextLdapConstants
from flext_ldap.acl import (
    FlextLdapAclConstants,
    FlextLdapAclConverters,
    FlextLdapAclManager,
    FlextLdapAclModels,
    FlextLdapAclParsers,
)
from flext_ldap.domain_services import FlextLdapDomainServices
from flext_ldap.factory import FlextLdapFactory
from flext_ldap.repositories import FlextLdapRepositories
from flext_ldap.services import FlextLdapAdvancedService
from flext_ldap.workflows import FlextLdapWorkflowOrchestrator

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
    return FlextContainer.get_global()


@pytest.fixture(scope="session")
def flext_logger() -> FlextLogger:
    """Get Flext logger instance."""
    return FlextLogger(__name__)


@pytest.fixture(scope="session")
def event_loop() -> Generator[asyncio.AbstractEventLoop]:
    """Create event loop for async tests."""
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    yield loop
    loop.close()


# =============================================================================
# LDAP CONFIGURATION FIXTURES
# =============================================================================


@pytest.fixture
def ldap_config() -> FlextLdapModels.ConnectionConfig:
    """Get standard LDAP connection configuration."""
    return FlextLdapModels.ConnectionConfig(
        server="localhost",
        port=FlextLdapConstants.Protocol.DEFAULT_PORT,
        use_ssl=False,
        bind_dn="cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com",
        bind_password="REDACTED_LDAP_BIND_PASSWORD123",
        timeout=FlextLdapConstants.DEFAULT_TIMEOUT,
    )


@pytest.fixture
def ldap_config_invalid() -> FlextLdapModels.ConnectionConfig:
    """Get invalid LDAP configuration for error testing."""
    return FlextLdapModels.ConnectionConfig(
        server="",  # Invalid empty server
        port=FlextLdapConstants.Protocol.DEFAULT_PORT,
        use_ssl=False,
        bind_dn="",  # Invalid empty DN
        bind_password="",  # Invalid empty password
        timeout=FlextLdapConstants.DEFAULT_TIMEOUT,
    )


@pytest.fixture
def ldap_server_config() -> dict[str, Any]:
    """Get LDAP server configuration for testing."""
    return {
        "server_uri": f"{FlextLdapConstants.Protocol.DEFAULT_SERVER_URI}:{FlextLdapConstants.Protocol.DEFAULT_PORT}",
        "bind_dn": "cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com",
        "bind_password": "REDACTED_LDAP_BIND_PASSWORD123",
        "base_dn": "dc=example,dc=com",
        "port": FlextLdapConstants.Protocol.DEFAULT_PORT,
        "use_ssl": False,
        "use_tls": False,
    }


# =============================================================================
# LDAP CLIENT FIXTURES
# =============================================================================


@pytest.fixture
def ldap_client(ldap_config: FlextLdapModels.ConnectionConfig) -> FlextLdapClient:
    """Get configured LDAP client instance."""
    return FlextLdapClient(config=ldap_config)


@pytest.fixture
def ldap_client_no_config() -> FlextLdapClient:
    """Get LDAP client without configuration."""
    return FlextLdapClient()


@pytest.fixture
def ldap_api() -> FlextLdapAPI:
    """Get LDAP API instance."""
    return FlextLdapAPI()


# =============================================================================
# DOMAIN SERVICES FIXTURES
# =============================================================================


@pytest.fixture
def domain_services() -> FlextLdapDomainServices:
    """Get domain services instance."""
    # Create mock instances for the required parameters
    config = FlextModels.CqrsConfig.Handler(
        handler_id="test_handler", handler_name="test_handler"
    )
    client = FlextLdapClient()
    container = FlextContainer()
    dispatcher = FlextDispatcher()
    bus = FlextBus()
    processors = FlextProcessors()
    registry = FlextRegistry(dispatcher=dispatcher)

    return FlextLdapDomainServices(
        config=config,
        client=client,
        container=container,
        bus=bus,
        dispatcher=dispatcher,
        processors=processors,
        registry=registry,
    )


@pytest.fixture
def advanced_service() -> FlextLdapAdvancedService:
    """Get advanced service instance."""
    # Create mock instances for the required parameters
    config = FlextModels.CqrsConfig.Handler(
        handler_id="test_handler", handler_name="test_handler"
    )
    client = FlextLdapClient()

    return FlextLdapAdvancedService(config=config, client=client)


@pytest.fixture
def workflow_orchestrator(
    ldap_client: FlextLdapClient,
) -> FlextLdapWorkflowOrchestrator:
    """Get workflow orchestrator instance."""
    config = FlextModels.CqrsConfig.Handler(
        handler_id="workflow_orchestrator_001",
        handler_name="LDAP Workflow Orchestrator",
        handler_type="command",
        handler_mode="command",
    )
    return FlextLdapWorkflowOrchestrator(config=config, client=ldap_client)


@pytest.fixture
def factory() -> FlextLdapFactory:
    """Get factory instance."""
    config = FlextModels.CqrsConfig.Handler(
        handler_id="test-handler", handler_name="test-handler"
    )
    return FlextLdapFactory(config=config)


# =============================================================================
# REPOSITORY FIXTURES
# =============================================================================


@pytest.fixture
def user_repository(
    ldap_client: FlextLdapClient,
) -> FlextLdapRepositories.UserRepository:
    """Get user repository instance."""
    return FlextLdapRepositories.UserRepository(client=ldap_client)


@pytest.fixture
def group_repository(
    ldap_client: FlextLdapClient,
) -> FlextLdapRepositories.GroupRepository:
    """Get group repository instance."""
    return FlextLdapRepositories.GroupRepository(client=ldap_client)


@pytest.fixture
def base_repository(
    ldap_client: FlextLdapClient,
) -> FlextLdapRepositories.UserRepository:
    """Get base repository instance."""
    return FlextLdapRepositories.UserRepository(client=ldap_client)


# =============================================================================
# ACL FIXTURES
# =============================================================================


@pytest.fixture
def acl_constants() -> FlextLdapAclConstants:
    """Get ACL constants instance."""
    return FlextLdapAclConstants()


@pytest.fixture
def acl_converters() -> FlextLdapAclConverters:
    """Get ACL converters instance."""
    return FlextLdapAclConverters()


@pytest.fixture
def acl_manager() -> FlextLdapAclManager:
    """Get ACL manager instance."""
    return FlextLdapAclManager()


@pytest.fixture
def acl_parsers() -> FlextLdapAclParsers:
    """Get ACL parsers instance."""
    return FlextLdapAclParsers()


@pytest.fixture
def acl_models() -> FlextLdapAclModels:
    """Get ACL models instance."""
    return FlextLdapAclModels()


@pytest.fixture
def sample_acl_data() -> dict[str, Any]:
    """Get sample ACL data for testing."""
    return SAMPLE_ACL_DATA.copy()


# =============================================================================
# TEST DATA FIXTURES
# =============================================================================


@pytest.fixture
def sample_user() -> FlextLdapModels.LdapUser:
    """Get sample user entity."""
    return FlextLdapModels.LdapUser(
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
def sample_group() -> FlextLdapModels.Group:
    """Get sample group entity."""
    return FlextLdapModels.Group(
        dn="cn=testgroup,ou=groups,dc=example,dc=com",
        cn="testgroup",
        gid_number=1000,
        description="Test Group",
        member_dns=["uid=testuser,ou=people,dc=example,dc=com"],
    )


@pytest.fixture
def sample_dn() -> FlextLdapModels.DistinguishedName:
    """Get sample distinguished name."""
    return FlextLdapModels.DistinguishedName(
        value="uid=testuser,ou=people,dc=example,dc=com"
    )


@pytest.fixture
def sample_filter() -> FlextLdapModels.Filter:
    """Get sample LDAP filter."""
    return FlextLdapModels.Filter(expression="(objectClass=person)")


@pytest.fixture
def test_user_data() -> dict[str, object]:
    """Get test user data dictionary."""
    return dict(SAMPLE_USER_ENTRY)


@pytest.fixture
def test_group_data() -> dict[str, object]:
    """Get test group data dictionary."""
    return dict(SAMPLE_GROUP_ENTRY)


@pytest.fixture
def multiple_test_users() -> list[dict[str, object]]:
    """Get multiple test users."""
    return [dict(user) for user in TEST_USERS]


@pytest.fixture
def multiple_test_groups() -> list[dict[str, object]]:
    """Get multiple test groups."""
    return [dict(group) for group in TEST_GROUPS]


# =============================================================================
# VALIDATION FIXTURES
# =============================================================================


@pytest.fixture
def validations() -> FlextLdapValidations:
    """Get validations instance."""
    return FlextLdapValidations()


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
        "localhost", port=FlextLdapConstants.Protocol.DEFAULT_PORT, get_info="ALL"
    )


@pytest.fixture
def mock_connection_result() -> FlextResult[bool]:
    """Get mock successful connection result."""
    return FlextResult[bool].ok(True)


@pytest.fixture
def mock_search_result() -> FlextResult[list[dict[str, Any]]]:
    """Get mock search result."""
    return FlextResult[list[dict[str, Any]]].ok(
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
# INTEGRATION TEST FIXTURES
# =============================================================================


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
def shared_ldap_connection_config() -> FlextLdapModels.ConnectionConfig:
    """Shared LDAP connection configuration for integration tests."""
    return FlextLdapModels.ConnectionConfig(
        server="ldap://localhost:3390",
        port=3390,
        bind_dn="cn=REDACTED_LDAP_BIND_PASSWORD,dc=flext,dc=local",
        bind_password="REDACTED_LDAP_BIND_PASSWORD123",
        use_ssl=False,
        timeout=FlextLdapConstants.DEFAULT_TIMEOUT,
    )


@pytest.fixture(scope="session")
async def shared_ldap_client(
    shared_ldap_config: dict[str, str], shared_ldap_container: str
) -> AsyncGenerator[FlextLdapClient, None]:
    """Shared LDAP client for integration tests using centralized container."""
    # Ensure container is running by depending on shared_ldap_container
    _ = shared_ldap_container  # Container dependency ensures it's started

    client = FlextLdapClient()

    # Connect to the LDAP server with proper parameters
    connect_result = await client.connect(
        server_uri=shared_ldap_config["server_url"],
        bind_dn=shared_ldap_config["bind_dn"],
        password=shared_ldap_config["password"],
    )

    if connect_result.is_failure:
        pytest.skip(f"Failed to connect to LDAP server: {connect_result.error}")

    yield client

    # Disconnect when done
    try:
        await client.disconnect()
    except Exception:
        pass  # Best effort cleanup


@pytest.fixture(scope="session")
def shared_ldap_container() -> Generator[str]:
    """Managed LDAP container for tests - simple container name provider."""
    # Simply provide the container name - actual container management
    # is handled externally via docker-compose or manual setup
    container_name = "flext-openldap-test"
    yield container_name
    # Cleanup handled externally


@pytest.fixture(scope="session")
def shared_ldap_container_manager() -> Generator[dict[str, Any]]:
    """Docker control manager for LDAP containers - simplified implementation."""
    # Provide a simple manager object for compatibility
    manager = {
        "container_name": "flext-openldap-test",
        "is_running": True,
    }
    yield manager


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
def clean_ldap_state() -> None:
    """Clean LDAP state before and after each test."""
    # Pre-test cleanup - skip for now as we don't have test entries yet
    return
    # Post-test cleanup - skip cleanup when we don't have actual test entries
    # The cleanup should be handled by specific test fixtures that create entries


@pytest.fixture(autouse=True)
def clean_ldap_container():
    """Clean LDAP container state."""
    # Pre-test cleanup
    yield
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
    "advanced_service",
    "base_repository",
    "clean_ldap_container",
    "clean_ldap_state",
    "domain_services",
    "event_loop",
    "factory",
    "flext_container",
    "flext_logger",
    "group_repository",
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
    "shared_ldap_client",
    "shared_ldap_config",
    "shared_ldap_connection_config",
    "shared_ldap_container",
    "shared_ldap_container_manager",
    "shared_ldif_data",
    "skip_if_no_docker",
    "test_group_data",
    "test_user_data",
    "user_repository",
    "validations",
    "workflow_orchestrator",
]
