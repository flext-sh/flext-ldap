"""Unit tests for FlextLdapClient connection lifecycle operations.

Tests connection management: connect, disconnect, bind, unbind, is_connected.
Uses optimized session-scoped Docker LDAP fixtures for performance.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import pytest

from flext_ldap import FlextLdapClient, FlextLdapModels
from flext_core import FlextTypes


@pytest.mark.unit
class TestFlextLdapClientConnection:
    """Test FlextLdapClient connection lifecycle operations."""

    def test_client_initialization_no_config(self) -> None:
        """Test client can be initialized without configuration."""
        client = FlextLdapClient()
        assert client is not None
        assert not client.is_connected()

    def test_client_initialization_with_config(self) -> None:
        """Test client initialization with configuration."""
        config = FlextLdapModels.ConnectionConfig(
            server="ldap://localhost:3390",
            port=3390,
            bind_dn="cn=admin,dc=flext,dc=local",
            bind_password="admin123",
            use_ssl=False,
        )
        client = FlextLdapClient(config=config)
        assert client is not None
        assert not client.is_connected()

    def test_is_connected_before_connection(self) -> None:
        """Test is_connected returns False before connecting."""
        client = FlextLdapClient()
        assert not client.is_connected()

    def test_connect_missing_server_uri(self) -> None:
        """Test connect fails with invalid (empty) server URI."""
        client = FlextLdapClient()
        result = client.connect(
            server_uri="",  # Invalid empty URI
            bind_dn="cn=admin,dc=flext,dc=local",
            password="admin123",
        )
        assert result.is_failure
        assert (
            result.error
            and result.error
            and "server" in result.error.lower()
            or result.error
            and "uri" in result.error.lower()
        )

    def test_connect_missing_bind_dn(self) -> None:
        """Test connect fails with invalid (empty) bind DN."""
        client = FlextLdapClient()
        result = client.connect(
            server_uri="ldap://localhost:3390",
            bind_dn="",  # Invalid empty DN
            password="admin123",
        )
        assert result.is_failure
        assert (
            result.error
            and result.error
            and "dn" in result.error.lower()
            or result.error
            and "bind" in result.error.lower()
        )

    def test_connect_missing_password(self) -> None:
        """Test connect fails with invalid (empty) password."""
        client = FlextLdapClient()
        result = client.connect(
            server_uri="ldap://localhost:3390",
            bind_dn="cn=admin,dc=flext,dc=local",
            password="",  # Invalid empty password
        )
        assert result.is_failure
        assert result.error and result.error and "password" in result.error.lower()

    def test_disconnect_before_connect(self) -> None:
        """Test disconnect returns success even if not connected."""
        client = FlextLdapClient()
        result = client.disconnect()
        # Should succeed gracefully (idempotent)
        assert result.is_success


@pytest.mark.integration
@pytest.mark.docker
class TestFlextLdapClientConnectionIntegration:
    """Integration tests for FlextLdapClient connection with real LDAP server."""

    def test_connect_success(self, clean_ldap_container: FlextTypes.Dict) -> None:
        """Test successful connection to LDAP server."""
        client = FlextLdapClient()

        # Connect using container info
        result = client.connect(
            server_uri=str(clean_ldap_container["server_url"]),
            bind_dn=str(clean_ldap_container["bind_dn"]),
            password=str(clean_ldap_container["password"]),
        )

        assert result.is_success
        assert result.value is True
        assert client.is_connected()

        # Cleanup
        client.disconnect()

    def test_connect_invalid_credentials(
        self, clean_ldap_container: FlextTypes.Dict
    ) -> None:
        """Test connection fails with invalid credentials."""
        client = FlextLdapClient()

        # Attempt connection with wrong password
        result = client.connect(
            server_uri=str(clean_ldap_container["server_url"]),
            bind_dn=str(clean_ldap_container["bind_dn"]),
            password="wrong_password",
        )

        assert result.is_failure
        assert (
            result.error
            and "invalid credentials" in result.error.lower()
            or result.error
            and "bind" in result.error.lower()
        )
        assert not client.is_connected()

    def test_connect_invalid_bind_dn(
        self, clean_ldap_container: FlextTypes.Dict
    ) -> None:
        """Test connection fails with invalid bind DN."""
        client = FlextLdapClient()

        # Attempt connection with invalid DN
        result = client.connect(
            server_uri=str(clean_ldap_container["server_url"]),
            bind_dn="cn=invalid,dc=flext,dc=local",
            password=str(clean_ldap_container["password"]),
        )

        assert result.is_failure
        assert not client.is_connected()

    def test_disconnect_after_connect(
        self, clean_ldap_container: FlextTypes.Dict
    ) -> None:
        """Test disconnect after successful connection."""
        client = FlextLdapClient()

        # Connect
        connect_result = client.connect(
            server_uri=str(clean_ldap_container["server_url"]),
            bind_dn=str(clean_ldap_container["bind_dn"]),
            password=str(clean_ldap_container["password"]),
        )
        assert connect_result.is_success
        assert client.is_connected()

        # Disconnect
        disconnect_result = client.disconnect()
        assert disconnect_result.is_success
        assert not client.is_connected()

    def test_reconnect_after_disconnect(
        self, clean_ldap_container: FlextTypes.Dict
    ) -> None:
        """Test can reconnect after disconnect."""
        client = FlextLdapClient()

        # First connection
        result1 = client.connect(
            server_uri=str(clean_ldap_container["server_url"]),
            bind_dn=str(clean_ldap_container["bind_dn"]),
            password=str(clean_ldap_container["password"]),
        )
        assert result1.is_success
        assert client.is_connected()

        # Disconnect
        disconnect_result = client.disconnect()
        assert disconnect_result.is_success
        assert not client.is_connected()

        # Reconnect
        result2 = client.connect(
            server_uri=str(clean_ldap_container["server_url"]),
            bind_dn=str(clean_ldap_container["bind_dn"]),
            password=str(clean_ldap_container["password"]),
        )
        assert result2.is_success
        assert client.is_connected()

        # Cleanup
        client.disconnect()

    def test_test_connection_success(
        self, clean_ldap_container: FlextTypes.Dict
    ) -> None:
        """Test test_connection method validates connectivity."""
        client = FlextLdapClient()

        # Connect first
        client.connect(
            server_uri=str(clean_ldap_container["server_url"]),
            bind_dn=str(clean_ldap_container["bind_dn"]),
            password=str(clean_ldap_container["password"]),
        )

        # Test connection
        result = client.test_connection()
        assert result.is_success
        assert result.value is True

        # Cleanup
        client.disconnect()

    def test_test_connection_not_connected(self) -> None:
        """Test test_connection fails when not connected."""
        client = FlextLdapClient()

        result = client.test_connection()
        assert result.is_failure
        assert result.error and result.error and "not connected" in result.error.lower()

    def test_bind_after_connect(self, clean_ldap_container: FlextTypes.Dict) -> None:
        """Test bind operation after connection."""
        client = FlextLdapClient()

        # Connect
        client.connect(
            server_uri=str(clean_ldap_container["server_url"]),
            bind_dn=str(clean_ldap_container["bind_dn"]),
            password=str(clean_ldap_container["password"]),
        )

        # Bind (rebind with same credentials)
        bind_result = client.bind(
            bind_dn=str(clean_ldap_container["bind_dn"]),
            password=str(clean_ldap_container["password"]),
        )
        assert bind_result.is_success

        # Cleanup
        client.disconnect()

    def test_unbind_after_connect(self, clean_ldap_container: FlextTypes.Dict) -> None:
        """Test unbind operation after connection."""
        client = FlextLdapClient()

        # Connect
        client.connect(
            server_uri=str(clean_ldap_container["server_url"]),
            bind_dn=str(clean_ldap_container["bind_dn"]),
            password=str(clean_ldap_container["password"]),
        )
        assert client.is_connected()

        # Unbind
        unbind_result = client.unbind()
        assert unbind_result.is_success
        assert not client.is_connected()

    def test_session_id_persistence(
        self, clean_ldap_container: FlextTypes.Dict
    ) -> None:
        """Test session ID persists across connection lifecycle."""
        client = FlextLdapClient()

        # Get initial session ID
        session_id_1 = client.session_id

        # Connect
        client.connect(
            server_uri=str(clean_ldap_container["server_url"]),
            bind_dn=str(clean_ldap_container["bind_dn"]),
            password=str(clean_ldap_container["password"]),
        )

        # Session ID should be same
        session_id_2 = client.session_id
        assert session_id_1 == session_id_2

        # Disconnect
        client.disconnect()

        # Session ID should still be same
        session_id_3 = client.session_id
        assert session_id_1 == session_id_3


@pytest.mark.integration
@pytest.mark.docker
@pytest.mark.slow
class TestFlextLdapClientConnectionEdgeCases:
    """Edge case tests for FlextLdapClient connection management."""

    def test_multiple_disconnect_calls_idempotent(
        self, clean_ldap_container: FlextTypes.Dict
    ) -> None:
        """Test multiple disconnect calls are idempotent."""
        client = FlextLdapClient()

        # Connect
        client.connect(
            server_uri=str(clean_ldap_container["server_url"]),
            bind_dn=str(clean_ldap_container["bind_dn"]),
            password=str(clean_ldap_container["password"]),
        )

        # Disconnect multiple times
        result1 = client.disconnect()
        assert result1.is_success

        result2 = client.disconnect()
        assert result2.is_success

        result3 = client.disconnect()
        assert result3.is_success

    def test_connect_overrides_config(
        self, clean_ldap_container: FlextTypes.Dict
    ) -> None:
        """Test connect parameters override config object."""
        # Create config with wrong credentials
        config = FlextLdapModels.ConnectionConfig(
            server="ldap://wrong-server:389",
            port=389,
            bind_dn="cn=wrong,dc=example,dc=com",
            bind_password="wrong",
            use_ssl=False,
        )
        client = FlextLdapClient(config=config)

        # Connect with correct parameters (should override config)
        result = client.connect(
            server_uri=str(clean_ldap_container["server_url"]),
            bind_dn=str(clean_ldap_container["bind_dn"]),
            password=str(clean_ldap_container["password"]),
        )
        assert result.is_success
        assert client.is_connected()

        # Cleanup
        client.disconnect()
