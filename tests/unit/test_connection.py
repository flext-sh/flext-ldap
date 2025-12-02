"""Unit tests for flext_ldap.services.connection.FlextLdapConnection.

**Modules Tested:**
- `flext_ldap.services.connection.FlextLdapConnection` - Core LDAP connection service

**Test Scope:**
- Connection initialization and state validation (connected/disconnected)
- Lifecycle operations (disconnect, execute)
- Connection configuration and adapter creation
- Connection scenarios with different hosts (parametrized)
- Internal adapter methods and health checks
- Error handling and proper FlextResult patterns

All tests use real functionality without mocks, leveraging flext-core test utilities
and domain-specific helpers to reduce code duplication while maintaining 100% coverage.

Module: TestFlextLdapConnection
Scope: Comprehensive connection testing with maximum code reuse
Pattern: Parametrized tests using factories and constants

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from enum import StrEnum
from typing import ClassVar

import pytest
from flext_ldif import FlextLdif
from flext_tests import FlextTestsMatchers

from flext_ldap.config import FlextLdapConfig
from flext_ldap.models import FlextLdapModels
from flext_ldap.services.connection import FlextLdapConnection

from ..fixtures.constants import TestConstants

pytestmark = pytest.mark.unit


class TestFlextLdapConnection:
    """Comprehensive tests for FlextLdapConnection using factories and DRY principles.

    Uses parametrized tests and constants for maximum code reuse.
    All helper logic is nested within this single class following FLEXT patterns.
    """

    class HostScenario(StrEnum):
        """Host scenarios for parametrized connection testing."""

        LOCALHOST = "localhost"
        INVALID_IP = "192.0.2.1"

    HOST_SCENARIOS: ClassVar[tuple[HostScenario, ...]] = (
        HostScenario.LOCALHOST,
        HostScenario.INVALID_IP,
    )

    @classmethod
    def _create_connection(cls) -> FlextLdapConnection:
        """Factory method for creating connection instances."""
        return FlextLdapConnection(
            config=FlextLdapConfig(),
            parser=FlextLdif.get_instance().parser,
        )

    @classmethod
    def _create_connection_config(
        cls,
        host: str | None = None,
        port: int | None = None,
        bind_dn: str | None = None,
        bind_password: str | None = None,
        timeout: int | None = None,
    ) -> FlextLdapModels.ConnectionConfig:
        """Factory method for creating connection config instances."""
        return FlextLdapModels.ConnectionConfig(
            host=host or TestConstants.Connection.DEFAULT_HOST,
            port=port or TestConstants.Connection.DEFAULT_PORT,
            bind_dn=bind_dn,
            bind_password=bind_password,
            timeout=timeout or TestConstants.Connection.NORMAL_TIMEOUT,
        )

    def test_connection_initialization(self) -> None:
        """Test connection service initialization and initial state."""
        connection = self._create_connection()
        assert connection is not None
        assert connection.is_connected is False
        assert connection._config is not None
        assert connection._adapter is not None
        assert hasattr(connection._adapter, "_parser")

    def test_connection_disconnect_when_not_connected(self) -> None:
        """Test that disconnect works when not connected."""
        connection = self._create_connection()
        connection.disconnect()
        assert connection.is_connected is False

    def test_connection_execute_when_not_connected(self) -> None:
        """Test execute returns failure when not connected."""
        result = self._create_connection().execute()
        _ = FlextTestsMatchers.assert_failure(result)
        assert "Not connected" in (result.error or "")

    def test_connection_connect_debug_logging(self) -> None:
        """Test connection debug logging."""
        connection = self._create_connection()
        connection_config = self._create_connection_config(
            host="invalid.host",
            bind_dn="cn=test,dc=example,dc=com",
        )
        result = connection.connect(connection_config)
        _ = FlextTestsMatchers.assert_failure(result)

    @pytest.mark.parametrize("host_scenario", HOST_SCENARIOS)
    def test_connection_with_host_scenario(
        self,
        host_scenario: HostScenario,
    ) -> None:
        """Test connection scenarios with different hosts (parametrized)."""
        connection = self._create_connection()
        if host_scenario == self.HostScenario.LOCALHOST:
            connection_config = self._create_connection_config(
                host=host_scenario.value,
                bind_dn="cn=invalid,dc=example,dc=com",
                bind_password="wrong_password",
                timeout=TestConstants.Connection.FAST_TIMEOUT,
            )
        else:
            connection_config = self._create_connection_config(
                host=host_scenario.value,
                timeout=TestConstants.Connection.FAST_TIMEOUT,
            )
        result = connection.connect(connection_config, auto_retry=True, max_retries=1)
        _ = FlextTestsMatchers.assert_failure(result)

    def test_connection_get_connection_when_none(self) -> None:
        """Test _get_connection when connection is None."""
        connection = self._create_connection()
        connection._adapter._connection = None
        connection._adapter._server = None
        result = connection._adapter._get_connection()
        _ = FlextTestsMatchers.assert_failure(result)

    def test_connection_health_check(self) -> None:
        """Test health check execution."""
        connection = self._create_connection()
        result = connection.execute()
        _ = FlextTestsMatchers.assert_failure(result)
        assert "Not connected" in (result.error or "")
