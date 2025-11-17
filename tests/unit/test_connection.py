"""Unit tests for FlextLdapConnection.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

from flext_ldif.services.parser import FlextLdifParser

from flext_ldap.config import FlextLdapConfig
from flext_ldap.services.connection import FlextLdapConnection


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
