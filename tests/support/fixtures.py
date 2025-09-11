"""Test fixtures for LDAP testing.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

import asyncio
from collections.abc import AsyncGenerator, Generator

import pytest
from flext_core import FlextLogger, FlextTypes

from flext_ldap import FlextLDAPApi, FlextLDAPConnectionConfig

from .helpers import cleanup_test_entries, search_entries
from .ldap_server import LdapTestServer, get_test_ldap_config
from .test_data import SAMPLE_GROUP_ENTRY, SAMPLE_USER_ENTRY, TEST_GROUPS, TEST_USERS

logger = FlextLogger(__name__)


@pytest.fixture(scope="session")
async def real_ldap_server() -> AsyncGenerator[LdapTestServer]:
    """Start and manage real LDAP server for testing."""
    server = LdapTestServer()

    # Start the server
    start_result = await server.start()
    if not start_result.is_success:
        raise RuntimeError(f"Failed to start LDAP server: {start_result.error}")

    # Setup test data
    setup_result = await server.setup_test_data()
    if not setup_result.is_success:
        logger.warning(f"Failed to setup test data: {setup_result.error}")

    try:
        yield server
    finally:
        # Clean up
        stop_result = await server.stop()
        if not stop_result.is_success:
            logger.warning(f"Failed to stop LDAP server: {stop_result.error}")


@pytest.fixture
async def ldap_connection(
    real_ldap_server: LdapTestServer,
) -> AsyncGenerator[FlextLDAPConnectionConfig]:
    """Get LDAP connection configuration for testing."""
    return real_ldap_server.get_connection_config()


@pytest.fixture
async def ldap_api() -> AsyncGenerator[FlextLDAPApi]:
    """Get configured LDAP API instance."""
    return FlextLDAPApi()


@pytest.fixture
def test_user_data() -> FlextTypes.Core.Dict:
    """Get test user data."""
    return SAMPLE_USER_ENTRY.copy()


@pytest.fixture
def test_group_data() -> FlextTypes.Core.Dict:
    """Get test group data."""
    return SAMPLE_GROUP_ENTRY.copy()


@pytest.fixture
def multiple_test_users() -> list[FlextTypes.Core.Dict]:
    """Get multiple test users data."""
    return [user.copy() for user in TEST_USERS]


@pytest.fixture
def multiple_test_groups() -> list[FlextTypes.Core.Dict]:
    """Get multiple test groups data."""
    return [group.copy() for group in TEST_GROUPS]


@pytest.fixture
def test_ldap_config() -> FlextLDAPConnectionConfig:
    """Get test LDAP configuration."""
    return get_test_ldap_config()


# Synchronous fixtures for compatibility
@pytest.fixture(scope="session")
def event_loop() -> Generator[asyncio.AbstractEventLoop]:
    """Create event loop for the test session."""
    loop = asyncio.new_event_loop()
    try:
        yield loop
    finally:
        loop.close()


@pytest.fixture
async def clean_ldap_state(
    ldap_connection: FlextLDAPConnectionConfig,
) -> AsyncGenerator[None]:
    """Ensure clean LDAP state for each test."""
    # helpers already imported at top

    # Clean up before test
    search_result = await search_entries(
        ldap_connection,
        "dc=flext,dc=local",
        "(|(objectClass=person)(objectClass=groupOfNames))",
    )

    if search_result.is_success:
        dns_to_cleanup = [entry["dn"] for entry in search_result.value]
        if dns_to_cleanup:
            await cleanup_test_entries(ldap_connection, dns_to_cleanup)

    yield

    # Clean up after test
    search_result = await search_entries(
        ldap_connection,
        "dc=flext,dc=local",
        "(|(objectClass=person)(objectClass=groupOfNames))",
    )

    if search_result.is_success:
        dns_to_cleanup = [entry["dn"] for entry in search_result.value]
        if dns_to_cleanup:
            await cleanup_test_entries(ldap_connection, dns_to_cleanup)
