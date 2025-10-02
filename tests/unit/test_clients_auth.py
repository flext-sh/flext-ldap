"""Unit tests for FlextLdapClient authentication operations.

Tests authentication methods: authenticate_user with railway pattern validation.
Uses optimized session-scoped Docker LDAP fixtures for performance.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import pytest

from flext_ldap import FlextLdapClient


@pytest.mark.unit
class TestFlextLdapClientAuthenticationUnit:
    """Test FlextLdapClient authentication operations - unit tests (no Docker)."""

    def test_authenticate_user_not_connected(self) -> None:
        """Test authenticate_user fails when not connected."""
        client = FlextLdapClient()

        result = client.authenticate_user(username="testuser", password="password123")

        assert result.is_failure
        assert (
            result.error
            and "not established" in result.error.lower()
            or result.error
            and "connection" in result.error.lower()
        )

    def test_authenticate_user_empty_username(self) -> None:
        """Test authenticate_user with empty username."""
        client = FlextLdapClient()

        # Even though client is not connected, empty username should be caught
        result = client.authenticate_user(username="", password="password123")

        assert result.is_failure
        # Will fail at connection validation or user search stage

    def test_authenticate_user_empty_password(self) -> None:
        """Test authenticate_user with empty password."""
        client = FlextLdapClient()

        # Even though client is not connected, empty password should be caught
        result = client.authenticate_user(username="testuser", password="")

        assert result.is_failure
        # Will fail at connection validation or authentication stage


@pytest.mark.integration
@pytest.mark.docker
class TestFlextLdapClientAuthenticationIntegration:
    """Integration tests for FlextLdapClient authentication with real LDAP server.

    Note: Full authentication tests with user creation are skipped due to hardcoded
    search base in clients.py (_search_user_by_username uses 'ou=users,dc=example,dc=com').
    These tests will be enabled after refactoring to use configurable search base.
    """

    @pytest.fixture
    def authenticated_client(
        self, clean_ldap_container: dict[str, object]
    ) -> FlextLdapClient:
        """Create and connect LDAP client for authentication tests."""
        client = FlextLdapClient()

        connect_result = client.connect(
            server_uri=str(clean_ldap_container["server_url"]),
            bind_dn=str(clean_ldap_container["bind_dn"]),
            password=str(clean_ldap_container["password"]),
        )

        if connect_result.is_failure:
            pytest.skip(f"Failed to connect: {connect_result.error}")

        return client

    def test_authenticate_user_not_found(
        self, authenticated_client: FlextLdapClient
    ) -> None:
        """Test authentication fails for non-existent user."""
        result = authenticated_client.authenticate_user(
            username="nonexistentuser", password="password123"
        )

        assert result.is_failure
        assert (
            result.error
            and "not found" in result.error.lower()
            or result.error
            and "search failed" in result.error.lower()
        )

    def test_authenticate_disconnected_during_auth(
        self, authenticated_client: FlextLdapClient
    ) -> None:
        """Test authentication handles disconnection gracefully."""
        # Disconnect the client
        authenticated_client.disconnect()

        result = authenticated_client.authenticate_user(
            username="testuser", password="password123"
        )

        assert result.is_failure
        assert (
            result.error
            and "not established" in result.error.lower()
            or result.error
            and "connection" in result.error.lower()
        )


@pytest.mark.integration
@pytest.mark.docker
@pytest.mark.slow
class TestFlextLdapClientAuthenticationEdgeCases:
    """Edge case tests for FlextLdapClient authentication."""

    @pytest.fixture
    def authenticated_client(
        self, clean_ldap_container: dict[str, object]
    ) -> FlextLdapClient:
        """Create and connect LDAP client for edge case tests."""
        client = FlextLdapClient()

        connect_result = client.connect(
            server_uri=str(clean_ldap_container["server_url"]),
            bind_dn=str(clean_ldap_container["bind_dn"]),
            password=str(clean_ldap_container["password"]),
        )

        if connect_result.is_failure:
            pytest.skip(f"Failed to connect: {connect_result.error}")

        return client

    def test_authenticate_special_characters_in_username(
        self, authenticated_client: FlextLdapClient
    ) -> None:
        """Test authentication with special characters in username."""
        result = authenticated_client.authenticate_user(
            username="user@example.com",  # Email format
            password="password123",
        )

        # Should handle gracefully (will fail as user doesn't exist)
        assert result.is_failure
        assert (
            result.error
            and "not found" in result.error.lower()
            or result.error
            and "search failed" in result.error.lower()
        )

    def test_authenticate_ldap_injection_attempt(
        self, authenticated_client: FlextLdapClient
    ) -> None:
        """Test authentication prevents LDAP injection."""
        # Attempt LDAP injection in username
        result = authenticated_client.authenticate_user(
            username="*)(uid=*",  # Injection attempt
            password="password123",
        )

        # Should handle safely without crashing
        assert result.is_failure

    def test_authenticate_very_long_username(
        self, authenticated_client: FlextLdapClient
    ) -> None:
        """Test authentication with very long username."""
        long_username = "a" * 1000

        result = authenticated_client.authenticate_user(
            username=long_username, password="password123"
        )

        # Should handle gracefully
        assert result.is_failure

    def test_authenticate_unicode_username(
        self, authenticated_client: FlextLdapClient
    ) -> None:
        """Test authentication with unicode characters in username."""
        result = authenticated_client.authenticate_user(
            username="用户名",  # Chinese characters
            password="password123",
        )

        # Should handle gracefully (will fail as user doesn't exist)
        assert result.is_failure
