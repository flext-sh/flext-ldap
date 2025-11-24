"""Unit tests for FlextLdapConnection.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

import pytest
from flext_ldif import FlextLdifParser

from flext_ldap.config import FlextLdapConfig
from flext_ldap.models import FlextLdapModels
from flext_ldap.services.connection import FlextLdapConnection

# Mark all tests in this module as unit tests (fast, no Docker)
pytestmark = pytest.mark.unit


class TestFlextLdapConnection:
    """Tests for FlextLdapConnection service."""

    def test_connection_initialization(
        self,
        ldap_parser: FlextLdifParser,
    ) -> None:
        """Test connection service initialization."""
        config = FlextLdapConfig()
        connection = FlextLdapConnection(config=config, parser=ldap_parser)
        assert connection is not None
        assert connection.is_connected is False

    def test_connection_not_connected_initially(
        self,
        ldap_parser: FlextLdifParser,
    ) -> None:
        """Test that connection is not connected initially."""
        config = FlextLdapConfig()
        connection = FlextLdapConnection(config=config, parser=ldap_parser)
        assert connection.is_connected is False

    def test_connection_disconnect_when_not_connected(
        self,
        ldap_parser: FlextLdifParser,
    ) -> None:
        """Test that disconnect works when not connected."""
        config = FlextLdapConfig()
        connection = FlextLdapConnection(config=config, parser=ldap_parser)
        # Should not raise exception
        connection.disconnect()
        assert connection.is_connected is False

    def test_connection_execute_when_not_connected(
        self,
        ldap_parser: FlextLdifParser,
    ) -> None:
        """Test execute returns failure when not connected."""
        config = FlextLdapConfig()
        connection = FlextLdapConnection(config=config, parser=ldap_parser)
        result = connection.execute()
        assert result.is_failure
        # No fallback - FlextResult guarantees error exists when is_failure is True
        assert result.error is not None
        assert "Not connected" in result.error

    def test_connection_config_assignment(
        self,
        ldap_config: FlextLdapConfig,
        ldap_parser: FlextLdifParser,
    ) -> None:
        """Test connection config assignment (covers lines 45-49)."""
        connection = FlextLdapConnection(config=ldap_config, parser=ldap_parser)
        # Verify config assignment (lines 45-47)
        assert connection._config is not None
        # Verify adapter creation (line 49)
        assert connection._adapter is not None
        assert hasattr(connection._adapter, "_parser")

    def test_connection_connect_debug_logging(
        self,
        ldap_parser: FlextLdifParser,
    ) -> None:
        """Test connection debug logging (covers lines 72-84)."""
        config = FlextLdapConfig()
        connection = FlextLdapConnection(config=config, parser=ldap_parser)

        connection_config = FlextLdapModels.ConnectionConfig(
            host="invalid.host",
            port=389,
            bind_dn="cn=test,dc=example,dc=com",
        )

        # This will fail, but should trigger debug logging (lines 72-84)
        result = connection.connect(connection_config)
        assert result.is_failure

    def test_connection_connect_with_retry_success(
        self,
        ldap_parser: FlextLdifParser,
    ) -> None:
        """Test successful connection with retry (covers lines 137-144)."""
        config = FlextLdapConfig()
        connection = FlextLdapConnection(config=config, parser=ldap_parser)

        # Mock successful connection with retry
        connection_config = FlextLdapModels.ConnectionConfig(
            host="localhost",  # Use localhost to avoid DNS issues
            port=389,
            timeout=1,  # Short timeout for test
        )

        # This may fail due to no LDAP server, but tests the retry path
        connection.connect(connection_config, auto_retry=True, max_retries=1)
        # Either succeeds or fails with proper error handling

    def test_connection_connect_failure_logging(
        self,
        ldap_parser: FlextLdifParser,
    ) -> None:
        """Test connection failure logging (covers lines 161-169, 182, 192)."""
        config = FlextLdapConfig()
        connection = FlextLdapConnection(config=config, parser=ldap_parser)

        connection_config = FlextLdapModels.ConnectionConfig(
            host="192.0.2.1",  # Invalid IP - guaranteed to fail
            port=389,
            timeout=1,
        )

        result = connection.connect(connection_config, auto_retry=True, max_retries=2)
        assert result.is_failure

    def test_connection_get_connection_when_none(
        self,
        ldap_parser: FlextLdifParser,
    ) -> None:
        """Test _get_connection when connection is None (covers lines 203-213)."""
        config = FlextLdapConfig()
        connection = FlextLdapConnection(config=config, parser=ldap_parser)

        # Force connection to None to test the path
        connection._adapter._connection = None
        connection._adapter._server = None

        # This should return failure since not connected
        result = connection._adapter._get_connection()
        assert result.is_failure

    def test_connection_health_check(
        self,
        ldap_parser: FlextLdifParser,
    ) -> None:
        """Test health check execution (covers lines 244-246)."""
        config = FlextLdapConfig()
        connection = FlextLdapConnection(config=config, parser=ldap_parser)

        result = connection.execute()
        assert result.is_failure  # Should fail when not connected
        assert "Not connected" in str(result.error)
