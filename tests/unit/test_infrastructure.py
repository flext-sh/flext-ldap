"""Unit tests for FLEXT LDAP infrastructure components."""

from __future__ import annotations

from unittest.mock import Mock, patch

import pytest

from flext_ldap.infrastructure import (
    FlextLdapClient,
    FlextLdapConverter,
)


class TestFlextLdapConverter:
    """Test LDAP data type converter."""

    def test_converter_initialization(self) -> None:
        """Test converter initialization."""
        converter = FlextLdapConverter()
        assert converter is not None

    def test_detect_type_email(self) -> None:
        """Test email detection."""
        converter = FlextLdapConverter()

        result = converter.detect_type("test@example.com")
        assert result == "email"

        result = converter.detect_type("user.name@domain.org")
        assert result == "email"

    def test_detect_type_dn(self) -> None:
        """Test DN detection."""
        converter = FlextLdapConverter()

        result = converter.detect_type("cn=test,dc=example,dc=com")
        assert result == "dn"

        result = converter.detect_type("uid=user,ou=people,dc=domain,dc=org")
        assert result == "dn"

    def test_detect_type_uid(self) -> None:
        """Test UID detection."""
        converter = FlextLdapConverter()

        result = converter.detect_type("testuser")
        assert result == "uid"

        result = converter.detect_type("user123")
        assert result == "uid"

    def test_convert_to_dn_from_email(self) -> None:
        """Test conversion from email to DN."""
        converter = FlextLdapConverter()

        result = converter.convert_to_dn(
            "test@example.com", "ou=users,dc=example,dc=com",
        )
        assert "test" in result
        assert "ou=users,dc=example,dc=com" in result

    def test_convert_to_dn_from_uid(self) -> None:
        """Test conversion from UID to DN."""
        converter = FlextLdapConverter()

        result = converter.convert_to_dn("testuser", "ou=users,dc=example,dc=com")
        assert "testuser" in result
        assert "ou=users,dc=example,dc=com" in result

    def test_convert_to_dn_from_dn(self) -> None:
        """Test conversion from DN to DN (identity)."""
        converter = FlextLdapConverter()

        dn = "cn=test,ou=users,dc=example,dc=com"
        result = converter.convert_to_dn(dn, "ou=users,dc=example,dc=com")
        assert result == dn


class TestFlextLdapClient:
    """Test LDAP simple client infrastructure."""

    def test_client_initialization(self) -> None:
        """Test client initialization."""
        client = FlextLdapClient()
        assert client is not None

    @pytest.mark.asyncio
    async def test_connect_with_invalid_server(self) -> None:
        """Test connection with invalid server."""
        client = FlextLdapClient()

        result = await client.connect("ldap://invalid.server.test")
        assert not result.is_success
        assert result.error is not None
        assert "connection" in result.error.lower() or "failed" in result.error.lower()

    @pytest.mark.asyncio
    async def test_connect_with_malformed_uri(self) -> None:
        """Test connection with malformed URI."""
        client = FlextLdapClient()

        result = await client.connect("invalid://uri")
        assert not result.is_success

    @pytest.mark.asyncio
    async def test_disconnect_without_connection(self) -> None:
        """Test disconnect without prior connection."""
        client = FlextLdapClient()

        result = await client.disconnect()
        # Should handle gracefully
        assert result.is_success or (result.error and "not connected" in result.error.lower())

    @pytest.mark.asyncio
    async def test_search_without_connection(self) -> None:
        """Test search without connection."""
        client = FlextLdapClient()

        result = await client.search(
            base_dn="dc=example,dc=com", search_filter="(objectClass=person)",
        )
        assert not result.is_success
        assert result.error is not None
        assert (
            "not connected" in result.error.lower()
            or "connection" in result.error.lower()
        )

    @patch("flext_ldap.infrastructure.Connection")
    @pytest.mark.asyncio
    async def test_connect_success_mock(self, mock_connection_class: Mock) -> None:  # type: ignore[misc]
        """Test successful connection with mocked LDAP library."""
        # Setup mock
        mock_connection = Mock()
        mock_connection.bind.return_value = True
        mock_connection_class.return_value = mock_connection

        client = FlextLdapClient()

        result = await client.connect(
            server_uri="ldap://localhost",
            bind_dn="cn=admin,dc=example,dc=com",
            bind_password="password",
        )

        assert result.is_success

    @patch("flext_ldap.infrastructure.Connection")
    @pytest.mark.asyncio
    async def test_search_success_mock(self, mock_connection_class: Mock) -> None:  # type: ignore[misc]
        """Test successful search with mocked LDAP library."""
        # Setup mock
        mock_connection = Mock()
        mock_connection.bind.return_value = True
        mock_connection.search.return_value = True
        mock_connection.entries = []
        mock_connection_class.return_value = mock_connection

        client = FlextLdapClient()

        # Connect first
        await client.connect("ldap://localhost")

        # Then search
        result = await client.search(
            base_dn="dc=example,dc=com", search_filter="(objectClass=person)",
        )

        assert result.is_success
        assert isinstance(result.data, list)

    def test_is_connected_initially_false(self) -> None:
        """Test that client is not connected initially."""
        client = FlextLdapClient()
        assert not client.is_connected()

    @patch("flext_ldap.infrastructure.Connection")
    def test_is_connected_after_mock_connection(  # type: ignore[misc]
        self, mock_connection_class: Mock,
    ) -> None:
        """Test connection status after mocked connection."""
        # Setup mock
        mock_connection = Mock()
        mock_connection.bind.return_value = True
        mock_connection_class.return_value = mock_connection

        client = FlextLdapClient()

        # Manually set connection for testing
        client._connection = mock_connection

        assert client.is_connected()


class TestInfrastructureErrorHandling:
    """Test error handling in infrastructure components."""

    @pytest.mark.asyncio
    async def test_client_handles_ldap_exceptions(self) -> None:
        """Test that client properly handles LDAP exceptions."""
        client = FlextLdapClient()

        # Test with various invalid inputs
        result = await client.connect("")
        assert not result.is_success

        search_result = await client.search("", "")
        assert not search_result.is_success

    def test_converter_handles_invalid_input(self) -> None:
        """Test that converter handles invalid input gracefully."""
        converter = FlextLdapConverter()

        # Test with empty string
        result = converter.detect_type("")
        assert result == "uid"  # Default fallback

        # Test with None (should handle gracefully)
        try:
            result = converter.detect_type(None)
            # If it doesn't raise an exception, it should return a reasonable default
            assert result is not None
        except (TypeError, AttributeError):
            # It's also acceptable to raise a type error for None input
            pass
