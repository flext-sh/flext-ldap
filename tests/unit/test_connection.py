"""Unit tests for flext_ldap.services.connection.FlextLdapConnection.

**Modules Tested:**
- flext_ldap.services.connection.FlextLdapConnection: Core LDAP connection service

**Scope:**
- Connection initialization and state validation (connected/disconnected)
- Lifecycle operations (disconnect, execute)
- Connection configuration and adapter creation
- Connection scenarios with different hosts (parametrized)
- Internal adapter methods and health checks
- Error handling and proper FlextResult patterns

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from enum import StrEnum

import pytest
from flext_ldif import FlextLdif
from flext_ldif.services.parser import FlextLdifParser

from flext_ldap.config import FlextLdapConfig
from flext_ldap.models import FlextLdapModels
from flext_ldap.services.connection import FlextLdapConnection

pytestmark = pytest.mark.unit


class HostScenario(StrEnum):
    """Host scenarios for parametrized connection testing using Python 3.13 StrEnum."""

    LOCALHOST = "localhost"
    INVALID_IP = "192.0.2.1"


class TestFlextLdapConnection:
    """Tests for FlextLdapConnection service.

    Single class per module with flat test methods covering:
    - Connection initialization and state validation
    - Lifecycle operations (disconnect, execute)
    - Connection configuration and adapter creation
    - Host scenarios (localhost, invalid IP) with parametrization
    - Internal adapter methods and health checks
    - Error handling and proper FlextResult patterns

    Uses Python 3.13 StrEnum for host scenario parametrization.
    """

    # Host scenarios for parametrization
    HOST_SCENARIOS: tuple[HostScenario, ...] = (
        HostScenario.LOCALHOST,
        HostScenario.INVALID_IP,
    )

    # Shared parser instance
    PARSER: FlextLdifParser = FlextLdif.get_instance().parser

    @staticmethod
    def _create_connection(
        config: FlextLdapConfig | None = None,
        parser: FlextLdifParser | None = None,
    ) -> FlextLdapConnection:
        """Create FlextLdapConnection instance."""
        return FlextLdapConnection(
            config=config or FlextLdapConfig.get_instance(),
            parser=parser or TestFlextLdapConnection.PARSER,
        )

    @staticmethod
    def _create_connection_config(
        host: str = "localhost",
        port: int = 389,
        bind_dn: str | None = None,
        timeout: int | None = None,
        *,
        use_ssl: bool = False,
    ) -> FlextLdapModels.ConnectionConfig:
        """Create connection configuration."""
        if timeout is not None:
            return FlextLdapModels.ConnectionConfig(
                host=host,
                port=port,
                bind_dn=bind_dn,
                timeout=timeout,
                use_ssl=use_ssl,
            )
        return FlextLdapModels.ConnectionConfig(
            host=host,
            port=port,
            bind_dn=bind_dn,
            use_ssl=use_ssl,
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
        # Should not raise exception
        connection.disconnect()
        assert connection.is_connected is False

    def test_connection_execute_when_not_connected(self) -> None:
        """Test execute returns failure when not connected."""
        connection = self._create_connection()
        result = connection.execute()
        assert result.is_failure
        assert result.error is not None
        assert "Not connected" in result.error

    def test_connection_connect_debug_logging(self) -> None:
        """Test connection debug logging."""
        connection = self._create_connection()
        connection_config = self._create_connection_config(
            host="invalid.host",
            bind_dn="cn=test,dc=example,dc=com",
        )
        # This will fail but should trigger debug logging
        result = connection.connect(connection_config)
        assert result.is_failure

    @pytest.mark.parametrize("host_scenario", HOST_SCENARIOS)
    def test_connection_with_host_scenario(
        self,
        host_scenario: HostScenario,
    ) -> None:
        """Test connection scenarios with different hosts (parametrized)."""
        connection = self._create_connection()
        connection_config = self._create_connection_config(
            host=host_scenario.value,
            timeout=1,
        )
        result = connection.connect(connection_config, auto_retry=True, max_retries=1)
        # Both scenarios should fail (no LDAP server available in unit test)
        assert result.is_failure

    def test_connection_get_connection_when_none(self) -> None:
        """Test _get_connection when connection is None."""
        connection = self._create_connection()
        # Force connection to None to test the path
        connection._adapter._connection = None
        connection._adapter._server = None
        # This should return failure since not connected
        result = connection._adapter._get_connection()
        assert result.is_failure

    def test_connection_health_check(self) -> None:
        """Test health check execution."""
        connection = self._create_connection()
        result = connection.execute()
        assert result.is_failure  # Should fail when not connected
        assert result.error is not None
        assert "Not connected" in result.error
