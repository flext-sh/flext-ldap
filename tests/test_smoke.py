"""Smoke tests for LDAP container connectivity (REGRA 5: 100% REAL, NO MOCKS).

This module tests flext-ldap smoke functionality using advanced Python 3.13 patterns:
- Single class architecture with nested test organization
- Factory patterns for test data generation
- Enum-based test categorization
- Dynamic test generation for edge cases
- Maximum code reuse through flext-core flext_tests helpers

Tests verify:
1. LDAP container is running and responsive
2. FlextLdap API imports correctly
3. Basic connection works


Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

from collections.abc import Callable
from enum import StrEnum

import pytest
from flext_core import r
from ldap3 import Connection, Server

from flext_ldap import (
    FlextLdap,
    FlextLdapConfig,
    FlextLdapConnection,
    FlextLdapOperations,
    m,
)

from .typings import LdapContainerDict

# Mark entire module as smoke tests
pytestmark = pytest.mark.smoke


class TestsFlextLdapSmoke:
    """Smoke tests for flext-ldap using single class architecture.

    This class contains all smoke tests using factory patterns and advanced
    Python 3.13 features for maximum code reuse and test coverage.

    Architecture: Single class per module following FLEXT patterns.
    Uses t, c, p, m, u, s for test support and e, r, d, x from flext-core.
    """

    class Category(StrEnum):
        """Test categories for smoke tests."""

        CONTAINER_HEALTH = "container_health"
        API_IMPORTS = "api_imports"
        BASIC_CONNECTION = "basic_connection"

    class DataFactories:
        """Factory methods for generating test data across all smoke tests."""

        @staticmethod
        def create_ldap3_server(ldap_container: LdapContainerDict) -> Server:
            """Factory for ldap3 Server objects."""
            return Server(
                ldap_container["server_url"],
                get_info="ALL",
            )

        @staticmethod
        def create_ldap3_connection(
            server: Server,
            ldap_container: LdapContainerDict,
        ) -> Connection:
            """Factory for ldap3 Connection objects."""
            return Connection(
                server,
                user=ldap_container["bind_dn"],
                password=ldap_container["password"],
                auto_bind=True,  # REAL bind attempt
            )

        @staticmethod
        def create_flext_config(ldap_container: LdapContainerDict) -> FlextLdapConfig:
            """Factory for FlextLdapConfig objects."""
            return FlextLdapConfig(
                host=ldap_container["host"],
                port=ldap_container["port"],
                use_ssl=ldap_container["use_ssl"],
                bind_dn=ldap_container["bind_dn"],
                bind_password=ldap_container["password"],
            )

        @staticmethod
        def create_connection_config(
            ldap_container: LdapContainerDict,
        ) -> m.ConnectionConfig:
            """Factory for ConnectionConfig objects."""
            return m.ConnectionConfig(
                host=ldap_container["host"],
                port=ldap_container["port"],
                use_ssl=ldap_container["use_ssl"],
                bind_dn=ldap_container["bind_dn"],
                bind_password=ldap_container["password"],
            )

    class Assertions:
        """Assertion helpers for smoke tests across all test methods."""

        @staticmethod
        def assert_connection_bound(connection: Connection) -> None:
            """Assert that LDAP connection is bound."""
            assert connection.bound, "LDAP server not responding to bind"

        @staticmethod
        def assert_server_info_available(connection: Connection) -> None:
            """Assert that LDAP server info is available."""
            assert connection.server.info is not None, "LDAP server info not available"
            assert connection.server.info.naming_contexts is not None, (
                "LDAP naming contexts not available"
            )

        @staticmethod
        def assert_api_instantiated(api: FlextLdap | None) -> None:
            """Assert that FlextLdap API is instantiated."""
            assert api is not None, "FlextLdap API instantiation failed"

        @staticmethod
        def assert_models_accessible() -> None:
            """Assert that m (FlextLdapModels) class is accessible."""
            assert m is not None, "m (FlextLdapModels) not accessible"

        @staticmethod
        def assert_connection_success(
            result: r[bool],
        ) -> None:
            """Assert that connection operation succeeded."""
            assert result.is_success, f"Connection failed: {result.error}"

    def test_ldap_container_health(self, ldap_container: LdapContainerDict) -> None:
        """SMOKE TEST: LDAP container is responsive (REGRA 5: REAL connection).

        This is the minimal test that must pass for ANY other test to work.
        Uses REAL ldap3 Connection (NO MOCKS).

        Args:
            ldap_container: Container connection info from fixture

        """
        # Create REAL ldap3 Server object
        server = TestsFlextLdapSmoke.DataFactories.create_ldap3_server(ldap_container)

        # Create REAL ldap3 Connection
        connection = TestsFlextLdapSmoke.DataFactories.create_ldap3_connection(
            server,
            ldap_container,
        )

        # Verify REAL connection is bound
        TestsFlextLdapSmoke.Assertions.assert_connection_bound(connection)

        # Verify REAL server info is available (schema loaded)
        TestsFlextLdapSmoke.Assertions.assert_server_info_available(connection)

        # REAL unbind (typed wrapper for mypy strict)
        unbind_func: Callable[[], None] = connection.unbind
        unbind_func()

    def test_flext_ldap_api_imports(self) -> None:
        """SMOKE TEST: FlextLdap API imports without errors (REGRA 5: REAL code).

        Verifies that the API can be imported and instantiated.
        Does NOT test connection - that's in test_ldap_container_health.
        """
        # Instantiate REAL FlextLdap object (requires connection and operations)

        # but services pass complex objects via __init__ which are validated at runtime
        config = FlextLdapConfig()
        connection = FlextLdapConnection(config=config)
        operations = FlextLdapOperations(connection=connection)
        api = FlextLdap(
            connection=connection,
            operations=operations,
        )
        TestsFlextLdapSmoke.Assertions.assert_api_instantiated(api)

        # Verify models are accessible
        TestsFlextLdapSmoke.Assertions.assert_models_accessible()

    def test_flext_ldap_basic_connection(
        self,
        ldap_container: LdapContainerDict,
    ) -> None:
        """SMOKE TEST: FlextLdap can connect to container (REGRA 5: REAL operations).

        Tests basic connectivity through FlextLdap API.
        Uses REAL LDAP container and connection (NO MOCKS).

        Args:
            ldap_container: Container connection info

        """
        # Create REAL config from container info
        config = TestsFlextLdapSmoke.DataFactories.create_flext_config(ldap_container)

        # Create REAL connection and operations instances

        # but services pass complex objects via __init__ which are validated at runtime
        connection = FlextLdapConnection(config=config)
        operations = FlextLdapOperations(connection=connection)

        # Create REAL FlextLdap instance with dependency injection
        client = FlextLdap(connection=connection, operations=operations)

        # Create REAL connection config
        conn_config = TestsFlextLdapSmoke.DataFactories.create_connection_config(
            ldap_container,
        )

        # Attempt REAL connection
        result = client.connect(conn_config)

        # Verify success
        TestsFlextLdapSmoke.Assertions.assert_connection_success(result)

        # REAL disconnect
        client.disconnect()
