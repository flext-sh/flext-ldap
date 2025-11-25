"""Centralized fixtures for all unit tests.

Provides parametrized, reusable fixtures built on existing helpers to maximize
code reuse across all test modules. Uses LdapTestDataFactory and test constants.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import pytest
from flext_ldif import FlextLdif, FlextLdifParser

from flext_ldap import FlextLdap
from flext_ldap.config import FlextLdapConfig
from flext_ldap.models import FlextLdapModels

from ..fixtures.constants import TestConstants
from ..helpers.test_helpers import LdapTestDataFactory, FlextLdapTestHelpers


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
def reset_ldap_singleton() -> None:
    """Auto-reset FlextLdap singleton before and after each unit test."""
    FlextLdap._reset_instance()
    yield
    FlextLdap._reset_instance()


@pytest.fixture
def ldif_instance() -> FlextLdif:
    """Provide FlextLdif singleton instance."""
    return FlextLdif.get_instance()


@pytest.fixture
def ldap_instance(ldif_instance: FlextLdif) -> FlextLdap:
    """Provide FlextLdap singleton instance with FlextLdif."""
    return FlextLdap.get_instance(ldif=ldif_instance)


@pytest.fixture
def ldap_instance_custom(
    ldif_instance: FlextLdif,
    config_custom: FlextLdapConfig,
) -> FlextLdap:
    """Provide FlextLdap singleton instance with custom config."""
    return FlextLdap.get_instance(config=config_custom, ldif=ldif_instance)


# ===== MODEL FIXTURES =====


@pytest.fixture
def search_options(ldap_data_factory: LdapTestDataFactory) -> FlextLdapModels.SearchOptions:
    """Provide default SearchOptions for testing."""
    return ldap_data_factory.create_search_options()


@pytest.fixture
def test_entry(ldap_data_factory: LdapTestDataFactory) -> FlextLdapModels.Entry:
    """Provide test entry using factory."""
    return ldap_data_factory.create_entry(
        dn=TestConstants.TEST_USER_DN,
        cn=["testuser"],
    )


@pytest.fixture
def connection_config(
    ldap_data_factory: LdapTestDataFactory,
) -> FlextLdapModels.ConnectionConfig:
    """Provide ConnectionConfig for testing."""
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
    ]
)
def config_variants(request) -> tuple[str, int]:
    """Parametrized fixture providing different host/port combinations."""
    return request.param["host"], request.param["port"]


__all__ = [
    "ldap_data_factory",
    "config_with_defaults",
    "config_custom",
    "reset_ldap_singleton",
    "ldif_instance",
    "ldap_instance",
    "ldap_instance_custom",
    "search_options",
    "test_entry",
    "connection_config",
    "test_constants",
    "test_user_dn",
    "test_group_dn",
    "default_base_dn",
    "config_variants",
]
