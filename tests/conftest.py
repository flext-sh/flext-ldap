"""Test configuration for flext-ldap.

Provides pytest fixtures and configuration for testing LDAP functionality
using flext-core patterns and real LDAP integration.
"""

from __future__ import annotations

import os
from typing import TYPE_CHECKING, Any

import pytest

from flext_ldap.config import FlextLDAPSettings

if TYPE_CHECKING:
    from collections.abc import AsyncGenerator, Generator


# Test environment setup
@pytest.fixture(autouse=True)
def set_test_environment() -> Generator[None]:
    """Set test environment variables."""
    os.environ["FLEXT_ENV"] = "test"
    os.environ["FLEXT_LOG_LEVEL"] = "debug"
    yield
    # Cleanup
    os.environ.pop("FLEXT_ENV", None)
    os.environ.pop("FLEXT_LOG_LEVEL", None)


@pytest.fixture
def ldap_settings() -> FlextLDAPSettings:
    """Provide test LDAP settings."""
    return FlextLDAPSettings()  # Use defaults for testing


# LDAP test configuration
@pytest.fixture
def ldap_test_config() -> dict[str, Any]:
    """LDAP configuration for testing."""
    return {
        "server": "localhost",
        "port": 389,
        "bind_dn": "cn=admin,dc=test,dc=com",
        "password": "admin_password",
        "use_ssl": False,
        "timeout": 30,
        "base_dn": "dc=test,dc=com",
    }


@pytest.fixture
def ldap_test_data() -> dict[str, Any]:
    """Test data for LDAP operations."""
    return {
        "users": [
            {
                "dn": "cn=testuser1,ou=users,dc=test,dc=com",
                "attributes": {
                    "cn": ["testuser1"],
                    "mail": ["testuser1@test.com"],
                    "objectClass": ["inetOrgPerson"],
                    "sn": ["User1"],
                    "uid": ["testuser1"],
                },
            },
            {
                "dn": "cn=testuser2,ou=users,dc=test,dc=com",
                "attributes": {
                    "cn": ["testuser2"],
                    "mail": ["testuser2@test.com"],
                    "objectClass": ["inetOrgPerson"],
                    "sn": ["User2"],
                    "uid": ["testuser2"],
                },
            },
        ],
        "groups": [
            {
                "dn": "cn=testgroup1,ou=groups,dc=test,dc=com",
                "attributes": {
                    "cn": ["testgroup1"],
                    "description": ["Test Group 1"],
                    "member": ["cn=testuser1,ou=users,dc=test,dc=com"],
                    "objectClass": ["groupOfNames"],
                },
            },
        ],
    }


# LDAP client fixtures
@pytest.fixture
async def ldap_client(ldap_test_config: dict[str, Any]) -> AsyncGenerator[Any]:
    """LDAP client for testing."""
    from flext_ldap.client import LDAPClient
    from flext_ldap.config import LDAPConnectionConfig

    config = LDAPConnectionConfig(**ldap_test_config)
    return LDAPClient(config)

    # Note: In real tests, this would connect to a test LDAP server
    # For unit tests, this can be mocked as needed


# Pytest markers for test categorization
def pytest_configure(config: pytest.Config) -> None:
    """Configure pytest markers."""
    config.addinivalue_line("markers", "unit: Unit tests")
    config.addinivalue_line("markers", "integration: Integration tests")
    config.addinivalue_line("markers", "e2e: End-to-end tests")
    config.addinivalue_line("markers", "ldap: LDAP-specific tests")
    config.addinivalue_line("markers", "oracle: Oracle OID tests")
    config.addinivalue_line("markers", "slow: Slow tests")


# Service fixtures using flext-core patterns
@pytest.fixture
async def ldap_connection_service() -> AsyncGenerator[Any]:
    """LDAP connection service for testing."""
    from flext_ldap.application.services import LDAPConnectionService

    return LDAPConnectionService()


# Oracle OID test fixtures
@pytest.fixture
def oracle_oid_config() -> dict[str, Any]:
    """Oracle OID test configuration."""
    return {
        "server": "oracle-oid.test.com",
        "port": 389,
        "bind_dn": "cn=orcladmin,cn=Users,dc=example,dc=com",
        "password": "oracle_password",
        "oracle_oid_mode": True,
        "base_dn": "dc=example,dc=com",
    }


@pytest.fixture
def oracle_test_data() -> dict[str, Any]:
    """Oracle OID test data."""
    return {
        "oracle_users": [
            {
                "dn": "cn=oracleuser,cn=Users,dc=example,dc=com",
                "attributes": {
                    "cn": ["oracleuser"],
                    "orclPassword": ["encrypted_password"],
                    "objectClass": ["orclUser", "inetOrgPerson"],
                    "mail": ["oracle@example.com"],
                },
            },
        ],
        "oracle_containers": [
            {
                "dn": "cn=container1,dc=example,dc=com",
                "attributes": {
                    "cn": ["container1"],
                    "objectClass": ["orclContainer"],
                    "description": ["Oracle Container"],
                },
            },
        ],
    }
