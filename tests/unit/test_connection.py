"""Unit tests for FlextLdapConnection.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

from flext_ldap.services.connection import FlextLdapConnection


class TestFlextLdapConnection:
    """Tests for FlextLdapConnection service."""

    def test_connection_initialization(self) -> None:
        """Test connection service initialization."""
        connection = FlextLdapConnection()
        assert connection is not None
        assert connection.is_connected is False

    def test_connection_not_connected_initially(self) -> None:
        """Test that connection is not connected initially."""
        connection = FlextLdapConnection()
        assert connection.is_connected is False

    def test_connection_disconnect_when_not_connected(self) -> None:
        """Test that disconnect works when not connected."""
        connection = FlextLdapConnection()
        # Should not raise exception
        connection.disconnect()
        assert connection.is_connected is False

    def test_connection_execute_when_not_connected(self) -> None:
        """Test execute returns failure when not connected."""
        connection = FlextLdapConnection()
        result = connection.execute()
        assert result.is_failure
        assert "Not connected" in (result.error or "")
