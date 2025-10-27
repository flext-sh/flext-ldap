"""Integration tests for FlextLdapClients with real LDAP operations.

These tests validate all FlextLdapClients functionality using real LDAP operations
against a Docker-based OpenLDAP test server. All tests use actual LDAP protocol
operations - NO mocks or stubs.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

from collections.abc import Generator

import pytest

from flext_ldap.clients import FlextLdapClients
from flext_ldap.config import FlextLdapConfig


@pytest.mark.integration
@pytest.mark.docker
class TestFlextLdapClientsConnection:
    """Integration tests for FlextLdapClients connection management."""

    def test_connect_with_valid_credentials(
        self, clean_ldap_container: dict[str, object]
    ) -> None:
        """Test successful connection to LDAP server with valid credentials."""
        client = FlextLdapClients()

        result = client.connect(
            server_uri=str(clean_ldap_container["server_url"]),
            bind_dn=str(clean_ldap_container["bind_dn"]),
            password=str(clean_ldap_container["password"]),
        )

        assert result.is_success
        assert client.is_connected
        client.unbind()

    def test_connect_with_invalid_server(self) -> None:
        """Test connection failure with invalid server URI."""
        client = FlextLdapClients()

        result = client.connect(
            server_uri="ldap://nonexistent.invalid:3390",
            bind_dn="cn=REDACTED_LDAP_BIND_PASSWORD,dc=test,dc=com",
            password="password123",
        )

        assert result.is_failure
        assert not client.is_connected

    def test_connect_with_invalid_credentials(
        self, clean_ldap_container: dict[str, object]
    ) -> None:
        """Test connection failure with invalid credentials."""
        client = FlextLdapClients()

        result = client.connect(
            server_uri=str(clean_ldap_container["server_url"]),
            bind_dn=str(clean_ldap_container["bind_dn"]),
            password="wrong_password",
        )

        assert result.is_failure
        assert not client.is_connected

    def test_disconnect_before_connect(self) -> None:
        """Test unbind when not connected (idempotent)."""
        client = FlextLdapClients()
        result = client.unbind()
        assert result.is_success

    def test_reconnect_after_disconnect(
        self, clean_ldap_container: dict[str, object]
    ) -> None:
        """Test reconnection after disconnect."""
        client = FlextLdapClients()

        # First connection
        result1 = client.connect(
            server_uri=str(clean_ldap_container["server_url"]),
            bind_dn=str(clean_ldap_container["bind_dn"]),
            password=str(clean_ldap_container["password"]),
        )
        assert result1.is_success
        assert client.is_connected

        # Disconnect
        disconnect_result = client.unbind()
        assert disconnect_result.is_success
        assert not client.is_connected

        # Reconnect
        result2 = client.connect(
            server_uri=str(clean_ldap_container["server_url"]),
            bind_dn=str(clean_ldap_container["bind_dn"]),
            password=str(clean_ldap_container["password"]),
        )
        assert result2.is_success
        assert client.is_connected
        client.unbind()


@pytest.mark.integration
@pytest.mark.docker
class TestFlextLdapClientsSearch:
    """Integration tests for FlextLdapClients search operations."""

    @pytest.fixture
    def authenticated_client(
        self, clean_ldap_container: dict[str, object]
    ) -> Generator[FlextLdapClients]:
        """Create authenticated LDAP client for searches with proper cleanup."""
        client = FlextLdapClients()

        connect_result = client.connect(
            server_uri=str(clean_ldap_container["server_url"]),
            bind_dn=str(clean_ldap_container["bind_dn"]),
            password=str(clean_ldap_container["password"]),
        )

        if connect_result.is_failure:
            pytest.skip(f"Failed to connect: {connect_result.error}")

        yield client

        # Cleanup: unbind after test completes
        if client.is_connected:
            try:
                client.unbind()
            except Exception:
                pass  # Ignore errors during cleanup

    def test_search_base_scope(self, authenticated_client: FlextLdapClients) -> None:
        """Test search with BASE scope on root entry."""
        result = authenticated_client.search(
            base_dn="dc=flext,dc=local",
            filter_str="(objectClass=*)",
            scope="BASE",
        )
        assert result.is_success
        entries = result.unwrap()
        assert len(entries) >= 1

    def test_search_subtree_scope(self, authenticated_client: FlextLdapClients) -> None:
        """Test search with SUBTREE scope."""
        result = authenticated_client.search(
            base_dn="dc=flext,dc=local",
            filter_str="(objectClass=organizationalUnit)",
            scope="SUBTREE",
        )
        assert result.is_success

    def test_search_with_attribute_filter(
        self, authenticated_client: FlextLdapClients
    ) -> None:
        """Test search with attribute-based filter."""
        result = authenticated_client.search(
            base_dn="dc=flext,dc=local",
            filter_str="(uid=*)",
            scope="SUBTREE",
        )
        assert result.is_success

    def test_search_no_results(self, authenticated_client: FlextLdapClients) -> None:
        """Test search that returns no results."""
        result = authenticated_client.search(
            base_dn="dc=flext,dc=local",
            filter_str="(uid=nonexistent)",
            scope="SUBTREE",
        )
        assert result.is_success
        entries = result.unwrap()
        assert len(entries) == 0


@pytest.mark.unit
class TestFlextLdapClientsValidation:
    """Unit tests for FlextLdapClients validation and error handling."""

    def test_client_initialization_no_config(self) -> None:
        """Test client initialization without configuration."""
        client = FlextLdapClients()
        assert not client.is_connected

    def test_client_initialization_with_config(self) -> None:
        """Test client initialization with configuration."""
        # Create a minimal valid config
        config = FlextLdapConfig()
        client = FlextLdapClients(config=config)
        assert not client.is_connected

    def test_connect_missing_server_uri(self) -> None:
        """Test connect with empty server URI."""
        client = FlextLdapClients()

        result = client.connect(
            server_uri="",
            bind_dn="cn=REDACTED_LDAP_BIND_PASSWORD,dc=test,dc=com",
            password="test",
        )

        assert result.is_failure

    def test_connect_missing_bind_dn(self) -> None:
        """Test connect with empty bind DN."""
        client = FlextLdapClients()

        result = client.connect(
            server_uri="ldap://localhost:389",
            bind_dn="",
            password="test",
        )

        assert result.is_failure

    def test_connect_missing_password(self) -> None:
        """Test connect with empty password."""
        client = FlextLdapClients()

        result = client.connect(
            server_uri="ldap://localhost:389",
            bind_dn="cn=REDACTED_LDAP_BIND_PASSWORD,dc=test,dc=com",
            password="",
        )

        assert result.is_failure

    def test_search_not_connected(self) -> None:
        """Test search operation when not connected."""
        client = FlextLdapClients()

        result = client.search(
            base_dn="dc=test,dc=com",
            filter_str="(objectClass=*)",
            scope="SUBTREE",
        )
        assert result.is_failure

    def test_add_entry_not_connected(self) -> None:
        """Test add entry operation when not connected."""
        client = FlextLdapClients()

        result = client.add_entry(
            dn="uid=test,ou=people,dc=test,dc=com",
            attributes={
                "uid": "test",
                "cn": "Test User",
            },
        )
        assert result.is_failure

    def test_delete_entry_not_connected(self) -> None:
        """Test delete entry operation when not connected."""
        client = FlextLdapClients()

        result = client.delete_entry("uid=test,ou=people,dc=test,dc=com")
        assert result.is_failure


__all__ = [
    "TestFlextLdapClientsConnection",
    "TestFlextLdapClientsSearch",
    "TestFlextLdapClientsValidation",
]


@pytest.mark.integration
@pytest.mark.docker
class TestFlextLdapClientsAuthentication:
    """Integration tests for FlextLdapClients authentication."""

    @pytest.fixture
    def authenticated_client(
        self, clean_ldap_container: dict[str, object]
    ) -> Generator[FlextLdapClients]:
        """Create authenticated LDAP client with proper cleanup."""
        client = FlextLdapClients()

        connect_result = client.connect(
            server_uri=str(clean_ldap_container["server_url"]),
            bind_dn=str(clean_ldap_container["bind_dn"]),
            password=str(clean_ldap_container["password"]),
        )

        if connect_result.is_failure:
            pytest.skip(f"Failed to connect: {connect_result.error}")

        yield client

        # Cleanup: unbind after test completes
        if client.is_connected:
            try:
                client.unbind()
            except Exception:
                pass  # Ignore errors during cleanup

    def test_connection_is_authenticated(
        self, authenticated_client: FlextLdapClients
    ) -> None:
        """Test that connected client is authenticated."""
        assert authenticated_client.is_connected

        result = authenticated_client.test_connection()
        assert result.is_success
        assert result.unwrap() is True

    def test_authentication_with_correct_credentials(
        self, clean_ldap_container: dict[str, object]
    ) -> None:
        """Test authentication with correct credentials."""
        client = FlextLdapClients()

        result = client.connect(
            server_uri=str(clean_ldap_container["server_url"]),
            bind_dn=str(clean_ldap_container["bind_dn"]),
            password=str(clean_ldap_container["password"]),
        )

        assert result.is_success
        assert client.is_connected
        client.unbind()

    def test_authentication_with_wrong_credentials(
        self, clean_ldap_container: dict[str, object]
    ) -> None:
        """Test authentication failure with wrong credentials."""
        client = FlextLdapClients()

        result = client.connect(
            server_uri=str(clean_ldap_container["server_url"]),
            bind_dn=str(clean_ldap_container["bind_dn"]),
            password="wrong_password_xyz123",
        )

        assert result.is_failure
        assert not client.is_connected


@pytest.mark.integration
@pytest.mark.docker
class TestFlextLdapClientsModify:
    """Integration tests for FlextLdapClients modification operations."""

    @pytest.fixture
    def authenticated_client(
        self, clean_ldap_container: dict[str, object]
    ) -> Generator[FlextLdapClients]:
        """Create authenticated LDAP client for modifications with proper cleanup."""
        client = FlextLdapClients()

        connect_result = client.connect(
            server_uri=str(clean_ldap_container["server_url"]),
            bind_dn=str(clean_ldap_container["bind_dn"]),
            password=str(clean_ldap_container["password"]),
        )

        if connect_result.is_failure:
            pytest.skip(f"Failed to connect: {connect_result.error}")

        yield client

        # Cleanup: unbind after test completes
        if client.is_connected:
            try:
                client.unbind()
            except Exception:
                pass  # Ignore errors during cleanup

    def test_add_entry_creates_new_user(
        self, authenticated_client: FlextLdapClients
    ) -> None:
        """Test adding a new user entry to LDAP."""
        test_dn = "uid=test_add_user,ou=people,dc=flext,dc=local"

        # Add entry
        result = authenticated_client.add_entry(
            dn=test_dn,
            attributes={
                "uid": "test_add_user",
                "cn": "Test Add User",
                "sn": "User",
                "mail": "test.add@internal.invalid",
                "objectClass": ["inetOrgPerson", "top"],
            },
        )
        assert result.is_success

        # Verify entry was created
        search_result = authenticated_client.search(
            base_dn=test_dn,
            filter_str="(objectClass=*)",
            scope="BASE",
        )
        assert search_result.is_success
        entries = search_result.unwrap()
        assert len(entries) == 1

        # Cleanup
        authenticated_client.delete_entry(test_dn)

    def test_add_entry_with_multiple_values(
        self, authenticated_client: FlextLdapClients
    ) -> None:
        """Test adding entry with multi-valued attributes."""
        test_dn = "uid=test_multi_mail,ou=people,dc=flext,dc=local"

        # Add entry with multiple mail addresses
        result = authenticated_client.add_entry(
            dn=test_dn,
            attributes={
                "uid": "test_multi_mail",
                "cn": "Test Multi Mail",
                "sn": "User",
                "mail": ["primary@internal.invalid", "secondary@internal.invalid"],
                "objectClass": ["inetOrgPerson", "top"],
            },
        )
        assert result.is_success

        # Cleanup
        authenticated_client.delete_entry(test_dn)

    def test_delete_entry_removes_user(
        self, authenticated_client: FlextLdapClients
    ) -> None:
        """Test deleting a user entry from LDAP."""
        test_dn = "uid=test_del_user,ou=people,dc=flext,dc=local"

        # Create entry
        authenticated_client.add_entry(
            dn=test_dn,
            attributes={
                "uid": "test_del_user",
                "cn": "Test Delete User",
                "sn": "User",
                "objectClass": ["inetOrgPerson", "top"],
            },
        )

        # Verify it exists
        search_result = authenticated_client.search(
            base_dn=test_dn,
            filter_str="(objectClass=*)",
            scope="BASE",
        )
        assert len(search_result.unwrap()) == 1

        # Delete it
        delete_result = authenticated_client.delete_entry(test_dn)
        assert delete_result.is_success

        # Verify it's gone
        search_result = authenticated_client.search(
            base_dn=test_dn,
            filter_str="(objectClass=*)",
            scope="BASE",
        )
        assert len(search_result.unwrap()) == 0

    def test_delete_nonexistent_entry_fails(
        self, authenticated_client: FlextLdapClients
    ) -> None:
        """Test deleting nonexistent entry returns error."""
        result = authenticated_client.delete_entry(
            "uid=nonexistent,ou=people,dc=flext,dc=local"
        )
        assert result.is_failure


@pytest.mark.integration
@pytest.mark.docker
class TestFlextLdapClientsEdgeCases:
    """Edge cases and error scenarios with real LDAP."""

    @pytest.fixture
    def authenticated_client(
        self, clean_ldap_container: dict[str, object]
    ) -> Generator[FlextLdapClients]:
        """Create authenticated LDAP client with proper cleanup."""
        client = FlextLdapClients()

        connect_result = client.connect(
            server_uri=str(clean_ldap_container["server_url"]),
            bind_dn=str(clean_ldap_container["bind_dn"]),
            password=str(clean_ldap_container["password"]),
        )

        if connect_result.is_failure:
            pytest.skip(f"Failed to connect: {connect_result.error}")

        yield client

        # Cleanup: unbind after test completes
        if client.is_connected:
            try:
                client.unbind()
            except Exception:
                pass  # Ignore errors during cleanup

    def test_search_with_invalid_filter_syntax(
        self, authenticated_client: FlextLdapClients
    ) -> None:
        """Test search with malformed LDAP filter."""
        result = authenticated_client.search(
            base_dn="dc=flext,dc=local",
            filter_str="(objectClass=*",  # Missing closing paren
            scope="SUBTREE",
        )
        # Should fail or return empty
        assert result.is_failure or len(result.unwrap()) == 0

    def test_search_large_result_set(
        self, authenticated_client: FlextLdapClients
    ) -> None:
        """Test search with pagination for large result sets."""
        result = authenticated_client.search(
            base_dn="dc=flext,dc=local",
            filter_str="(objectClass=*)",
            scope="SUBTREE",
            page_size=10,  # Small page size to test pagination
        )
        assert result.is_success

    def test_special_characters_in_dn(
        self, authenticated_client: FlextLdapClients
    ) -> None:
        """Test handling of special characters in DN."""
        # DN with comma in CN (requires escaping)
        test_dn = r"cn=Smith\, John,ou=people,dc=flext,dc=local"

        result = authenticated_client.add_entry(
            dn=test_dn,
            attributes={
                "cn": "Smith, John",
                "sn": "Smith",
                "objectClass": ["person", "top"],
            },
        )
        assert result.is_success

        # Cleanup
        authenticated_client.delete_entry(test_dn)

    def test_empty_search_result(self, authenticated_client: FlextLdapClients) -> None:
        """Test search that returns empty result."""
        result = authenticated_client.search(
            base_dn="ou=nonexistent,dc=flext,dc=local",
            filter_str="(objectClass=*)",
            scope="SUBTREE",
        )
        # Should fail or return empty list
        if result.is_success:
            assert len(result.unwrap()) == 0
        else:
            assert result.is_failure


__all__ += [
    "TestFlextLdapClientsAuthentication",
    "TestFlextLdapClientsEdgeCases",
    "TestFlextLdapClientsModify",
]
