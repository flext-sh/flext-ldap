"""Centralized fixtures for all unit tests.

Provides parametrized, reusable fixtures built on existing helpers to maximize
code reuse across all test modules. Uses LdapTestDataFactory and test constants.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from collections.abc import Generator

import pytest
from flext_ldif import FlextLdif, FlextLdifModels

from flext_ldap import FlextLdap
from flext_ldap.config import FlextLdapConfig
from flext_ldap.models import FlextLdapModels
from flext_ldap.services.connection import FlextLdapConnection
from flext_ldap.services.operations import FlextLdapOperations

from ..fixtures.constants import TestConstants
from ..helpers.test_helpers import LdapTestDataFactory

# ===== DATA FACTORIES =====


@pytest.fixture
def ldap_data_factory() -> LdapTestDataFactory:
    """Provide LdapTestDataFactory for test data generation."""
    return LdapTestDataFactory()


# ===== CONFIGURATION FIXTURES =====


@pytest.fixture
def config_with_defaults() -> FlextLdapConfig:
    """Provide FlextLdapConfig with default values."""
    return FlextLdapConfig()


@pytest.fixture
def config_custom(ldap_data_factory: LdapTestDataFactory) -> FlextLdapConfig:
    """Provide FlextLdapConfig with custom host/port."""
    return FlextLdapConfig(
        host="custom.example.com",
        port=3390,
    )


# ===== LDAP INSTANCE FIXTURES =====


@pytest.fixture(autouse=True)
def reset_ldap_singleton() -> Generator[None]:
    """Auto-reset FlextLdap instance before and after each unit test.

    Note: FlextLdap is no longer a singleton (wrapper pattern removed).
    This fixture maintains test isolation by creating fresh instances per test.
    """
    yield None  # noqa: PT022  # Fixture is intentionally empty but needed for test isolation


@pytest.fixture
def ldif_instance() -> FlextLdif:
    """Provide FlextLdif singleton instance."""
    return FlextLdif.get_instance()


@pytest.fixture
def ldap_instance(ldif_instance: FlextLdif) -> FlextLdap:
    """Provide FlextLdap instance with FlextLdif."""
    config = FlextLdapConfig()
    connection = FlextLdapConnection(config=config, parser=ldif_instance.parser)
    operations = FlextLdapOperations(connection=connection)
    return FlextLdap(connection=connection, operations=operations, ldif=ldif_instance)


@pytest.fixture
def ldap_instance_custom(
    ldif_instance: FlextLdif,
    config_custom: FlextLdapConfig,
) -> FlextLdap:
    """Provide FlextLdap instance with custom config."""
    connection = FlextLdapConnection(config=config_custom, parser=ldif_instance.parser)
    operations = FlextLdapOperations(connection=connection)
    return FlextLdap(connection=connection, operations=operations, ldif=ldif_instance)


# ===== MODEL FIXTURES =====


@pytest.fixture
def search_options(
    ldap_data_factory: LdapTestDataFactory,
) -> FlextLdapModels.SearchOptions:
    """Provide default SearchOptions for testing."""
    return ldap_data_factory.create_search_options()


@pytest.fixture
def test_entry(ldap_data_factory: LdapTestDataFactory) -> FlextLdifModels.Entry:
    """Provide test entry using factory."""
    return ldap_data_factory.create_entry(
        dn=TestConstants.TEST_USER_DN,
        cn=["testuser"],
    )


@pytest.fixture
def connection_config(
    ldap_data_factory: LdapTestDataFactory,
    request: pytest.FixtureRequest,
) -> FlextLdapModels.ConnectionConfig:
    """Provide ConnectionConfig for testing.

    Uses container credentials if ldap_container fixture is available,
    otherwise uses default test credentials.
    """
    # Try to get ldap_container fixture (from root conftest) if available
    try:
        ldap_container = request.getfixturevalue("ldap_container")
        # Use container credentials
        port_value = ldap_container.get("port", 3390)
        port_int = int(port_value) if isinstance(port_value, (int, str)) else 3390
        return FlextLdapModels.ConnectionConfig(
            host=str(ldap_container.get("host", "localhost")),
            port=port_int,
            use_ssl=False,
            bind_dn=str(ldap_container.get("bind_dn", TestConstants.DEFAULT_BIND_DN)),
            bind_password=str(
                ldap_container.get("password", TestConstants.DEFAULT_BIND_PASSWORD),
            ),
        )
    except pytest.FixtureLookupError:
        # Fallback to default test credentials
        return ldap_data_factory.create_connection_config()


# ===== CONSTANTS FIXTURES =====


@pytest.fixture
def test_constants() -> type[TestConstants]:
    """Provide TestConstants class for assertion data."""
    return TestConstants


@pytest.fixture
def test_user_dn() -> str:
    """Provide test user DN."""
    return TestConstants.TEST_USER_DN


@pytest.fixture
def test_group_dn() -> str:
    """Provide test group DN."""
    return TestConstants.TEST_GROUP_DN


@pytest.fixture
def default_base_dn() -> str:
    """Provide default base DN."""
    return TestConstants.DEFAULT_BASE_DN


# ===== PARAMETRIZED CONFIGURATIONS =====


@pytest.fixture(
    params=[
        {"host": "localhost", "port": 389},
        {"host": "ldap.example.com", "port": 389},
        {"host": "secure.example.com", "port": 636},
    ],
)
def config_variants(request: pytest.FixtureRequest) -> tuple[str, int]:
    """Parametrized fixture providing different host/port combinations."""
    return request.param["host"], request.param["port"]


__all__ = [
    "config_custom",
    "config_variants",
    "config_with_defaults",
    "connection_config",
    "default_base_dn",
    "ldap_data_factory",
    "ldap_instance",
    "ldap_instance_custom",
    "ldif_instance",
    "reset_ldap_singleton",
    "search_options",
    "test_constants",
    "test_entry",
    "test_group_dn",
    "test_user_dn",
]
