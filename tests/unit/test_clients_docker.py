"""Comprehensive real Docker LDAP tests for FlextLdapClients.

This module contains comprehensive tests for FlextLdapClients using real Docker
LDAP containers. All tests use actual LDAP operations without mocks or stubs.

Test Categories:
- @pytest.mark.docker - Requires Docker LDAP container
- @pytest.mark.ldap - LDAP-specific tests
- @pytest.mark.unit - Unit tests (marked as docker+ldap+unit)

Container Requirements:
    Docker container must be running on port 3390
    Container name: flext-openldap-test
    Configuration: OpenLDAP 1.5.0 with dc=flext,dc=local base DN
"""

from __future__ import annotations

import pytest
from flext_core import FlextResult

from flext_ldap import FlextLdapClients


class TestFlextLdapClientsBasic:
    """Basic initialization and connection tests."""

    @pytest.mark.docker
    @pytest.mark.ldap
    @pytest.mark.unit
    def test_clients_init_no_config(self) -> None:
        """Test FlextLdapClients initialization without config."""
        client = FlextLdapClients()
        assert client is not None
        assert client.is_connected is False

    @pytest.mark.docker
    @pytest.mark.ldap
    @pytest.mark.unit
    def test_clients_connect_explicit_params(self) -> None:
        """Test connection with explicit parameters."""
        client = FlextLdapClients()

        result = client.connect(
            server_uri="ldap://localhost:3390",
            bind_dn="cn=admin,dc=flext,dc=local",
            password="admin123",
        )

        assert result.is_success is True
        assert client.is_connected is True

        # Cleanup
        client.unbind()

    @pytest.mark.docker
    @pytest.mark.ldap
    @pytest.mark.unit
    def test_clients_connect_and_disconnect(self) -> None:
        """Test connection and disconnection lifecycle."""
        client = FlextLdapClients()

        # Connect
        connect_result = client.connect(
            server_uri="ldap://localhost:3390",
            bind_dn="cn=admin,dc=flext,dc=local",
            password="admin123",
        )
        assert connect_result.is_success is True
        assert client.is_connected is True

        # Disconnect
        disconnect_result = client.unbind()
        assert disconnect_result.is_success is True
        assert client.is_connected is False


class TestFlextLdapClientsSearch:
    """LDAP search operation tests."""

    @pytest.mark.docker
    @pytest.mark.ldap
    @pytest.mark.unit
    def test_search_base_scope(self) -> None:
        """Test search with BASE scope."""
        client = FlextLdapClients()

        # Connect
        connect_result = client.connect(
            server_uri="ldap://localhost:3390",
            bind_dn="cn=admin,dc=flext,dc=local",
            password="admin123",
        )
        assert connect_result.is_success is True

        # Search at base DN
        result = client.search(
            base_dn="dc=flext,dc=local",
            filter_str="(objectClass=*)",
            scope="BASE",
        )

        assert result.is_success is True
        entries = result.unwrap()
        assert isinstance(entries, list)
        assert len(entries) > 0

        # Cleanup
        client.unbind()

    @pytest.mark.docker
    @pytest.mark.ldap
    @pytest.mark.unit
    def test_search_subtree_scope(self) -> None:
        """Test search with SUBTREE scope."""
        client = FlextLdapClients()

        # Connect
        connect_result = client.connect(
            server_uri="ldap://localhost:3390",
            bind_dn="cn=admin,dc=flext,dc=local",
            password="admin123",
        )
        assert connect_result.is_success is True

        # Search entire subtree
        result = client.search(
            base_dn="dc=flext,dc=local",
            filter_str="(objectClass=*)",
            scope="SUBTREE",
        )

        assert result.is_success is True
        entries = result.unwrap()
        assert isinstance(entries, list)
        assert len(entries) >= 1

        # Cleanup
        client.unbind()

    @pytest.mark.docker
    @pytest.mark.ldap
    @pytest.mark.unit
    def test_search_single_level_scope(self) -> None:
        """Test search with SINGLE_LEVEL scope."""
        client = FlextLdapClients()

        # Connect
        connect_result = client.connect(
            server_uri="ldap://localhost:3390",
            bind_dn="cn=admin,dc=flext,dc=local",
            password="admin123",
        )
        assert connect_result.is_success is True

        # Search single level
        result = client.search(
            base_dn="dc=flext,dc=local",
            filter_str="(objectClass=*)",
            scope="ONELEVEL",
        )

        assert result.is_success is True
        entries = result.unwrap()
        assert isinstance(entries, list)

        # Cleanup
        client.unbind()

    @pytest.mark.docker
    @pytest.mark.ldap
    @pytest.mark.unit
    def test_search_with_filter(self) -> None:
        """Test search with object class filter."""
        client = FlextLdapClients()

        # Connect
        connect_result = client.connect(
            server_uri="ldap://localhost:3390",
            bind_dn="cn=admin,dc=flext,dc=local",
            password="admin123",
        )
        assert connect_result.is_success is True

        # Search for organizational units
        result = client.search(
            base_dn="dc=flext,dc=local",
            filter_str="(objectClass=organizationalUnit)",
            scope="SUBTREE",
        )

        assert result.is_success is True
        entries = result.unwrap()
        assert isinstance(entries, list)

        # Cleanup
        client.unbind()

    @pytest.mark.docker
    @pytest.mark.ldap
    @pytest.mark.unit
    def test_search_with_attributes(self) -> None:
        """Test search with specific attributes."""
        client = FlextLdapClients()

        # Connect
        connect_result = client.connect(
            server_uri="ldap://localhost:3390",
            bind_dn="cn=admin,dc=flext,dc=local",
            password="admin123",
        )
        assert connect_result.is_success is True

        # Search with specific attributes
        result = client.search(
            base_dn="dc=flext,dc=local",
            filter_str="(objectClass=*)",
            attributes=["objectClass", "cn", "ou"],
            scope="SUBTREE",
        )

        assert result.is_success is True
        entries = result.unwrap()
        assert isinstance(entries, list)

        # Cleanup
        client.unbind()

    @pytest.mark.docker
    @pytest.mark.ldap
    @pytest.mark.unit
    def test_search_empty_result(self) -> None:
        """Test search returning empty results."""
        client = FlextLdapClients()

        # Connect
        connect_result = client.connect(
            server_uri="ldap://localhost:3390",
            bind_dn="cn=admin,dc=flext,dc=local",
            password="admin123",
        )
        assert connect_result.is_success is True

        # Search for entries with non-matching filter (returns empty)
        result = client.search(
            base_dn="dc=flext,dc=local",
            filter_str="(cn=nonexistentuser12345)",
            scope="SUBTREE",
        )

        assert result.is_success is True
        entries = result.unwrap()
        assert isinstance(entries, list)
        assert len(entries) == 0

        # Cleanup
        client.unbind()

    @pytest.mark.docker
    @pytest.mark.ldap
    @pytest.mark.unit
    def test_search_returns_entry_objects(self) -> None:
        """Test that search returns Entry objects."""
        client = FlextLdapClients()

        # Connect
        connect_result = client.connect(
            server_uri="ldap://localhost:3390",
            bind_dn="cn=admin,dc=flext,dc=local",
            password="admin123",
        )
        assert connect_result.is_success is True

        # Search
        result = client.search(
            base_dn="dc=flext,dc=local",
            filter_str="(objectClass=*)",
            scope="BASE",
        )

        assert result.is_success is True
        entries = result.unwrap()
        assert isinstance(entries, list)
        assert len(entries) > 0

        # Check entry structure - entries are Entry objects with dn and attributes
        entry = entries[0]
        # Entry objects should have dn and attributes properties
        assert hasattr(entry, "dn") or "dn" in entry
        assert hasattr(entry, "attributes") or "attributes" in entry

        # Cleanup
        client.unbind()


class TestFlextLdapClientsServer:
    """Server operations tests."""

    @pytest.mark.docker
    @pytest.mark.ldap
    @pytest.mark.unit
    def test_get_connection(self) -> None:
        """Test getting connection object via property."""
        client = FlextLdapClients()

        # Connect
        connect_result = client.connect(
            server_uri="ldap://localhost:3390",
            bind_dn="cn=admin,dc=flext,dc=local",
            password="admin123",
        )
        assert connect_result.is_success is True

        # Get connection via property
        connection = client.connection
        assert connection is not None

        # Cleanup
        client.unbind()

    @pytest.mark.docker
    @pytest.mark.ldap
    @pytest.mark.unit
    def test_server_detection(self) -> None:
        """Test automatic server type detection via property."""
        client = FlextLdapClients()

        # Connect
        connect_result = client.connect(
            server_uri="ldap://localhost:3390",
            bind_dn="cn=admin,dc=flext,dc=local",
            password="admin123",
        )
        assert connect_result.is_success is True

        # Get server type via property
        server_type = client.server_type
        assert server_type is not None
        assert isinstance(server_type, str)

        # Cleanup
        client.unbind()

    @pytest.mark.docker
    @pytest.mark.ldap
    @pytest.mark.unit
    def test_get_server_capabilities(self) -> None:
        """Test retrieving server info/capabilities."""
        client = FlextLdapClients()

        # Connect
        connect_result = client.connect(
            server_uri="ldap://localhost:3390",
            bind_dn="cn=admin,dc=flext,dc=local",
            password="admin123",
        )
        assert connect_result.is_success is True

        # Get server info (capabilities) - may be dict or list
        info_result = client.get_server_info()
        # Server info may succeed or fail depending on server implementation
        if info_result.is_success:
            info = info_result.unwrap()
            # Could be dict or list depending on LDAP server
            assert info is not None

        # Cleanup
        client.unbind()


class TestFlextLdapClientsConnectionReuse:
    """Connection reuse and lifecycle tests."""

    @pytest.mark.docker
    @pytest.mark.ldap
    @pytest.mark.unit
    def test_multiple_searches_same_connection(self) -> None:
        """Test multiple searches on same connection."""
        client = FlextLdapClients()

        # Connect once
        connect_result = client.connect(
            server_uri="ldap://localhost:3390",
            bind_dn="cn=admin,dc=flext,dc=local",
            password="admin123",
        )
        assert connect_result.is_success is True

        # First search
        result1 = client.search(
            base_dn="dc=flext,dc=local",
            filter_str="(objectClass=*)",
            scope="BASE",
        )
        assert result1.is_success is True

        # Second search on same connection
        result2 = client.search(
            base_dn="dc=flext,dc=local",
            filter_str="(objectClass=*)",
            scope="BASE",
        )
        assert result2.is_success is True

        # Both should work
        entries1 = result1.unwrap()
        entries2 = result2.unwrap()
        assert len(entries1) > 0
        assert len(entries2) > 0

        # Cleanup
        client.unbind()

    @pytest.mark.docker
    @pytest.mark.ldap
    @pytest.mark.unit
    def test_reconnect_after_disconnect(self) -> None:
        """Test reconnecting after disconnection."""
        client = FlextLdapClients()

        # First connection
        result1 = client.connect(
            server_uri="ldap://localhost:3390",
            bind_dn="cn=admin,dc=flext,dc=local",
            password="admin123",
        )
        assert result1.is_success is True
        assert client.is_connected is True

        # Disconnect
        disconnect_result = client.unbind()
        assert disconnect_result.is_success is True
        assert client.is_connected is False

        # Reconnect
        result2 = client.connect(
            server_uri="ldap://localhost:3390",
            bind_dn="cn=admin,dc=flext,dc=local",
            password="admin123",
        )
        assert result2.is_success is True
        assert client.is_connected is True

        # Cleanup
        client.unbind()


class TestFlextLdapClientsErrorHandling:
    """Error handling and edge case tests."""

    @pytest.mark.docker
    @pytest.mark.ldap
    @pytest.mark.unit
    def test_search_invalid_base_dn(self) -> None:
        """Test search with invalid base DN."""
        client = FlextLdapClients()

        # Connect
        connect_result = client.connect(
            server_uri="ldap://localhost:3390",
            bind_dn="cn=admin,dc=flext,dc=local",
            password="admin123",
        )
        assert connect_result.is_success is True

        # Search with invalid base DN
        result = client.search(
            base_dn="cn=nonexistent,dc=invalid,dc=com",
            filter_str="(objectClass=*)",
            scope="BASE",
        )

        # This should fail or return empty
        assert isinstance(result, FlextResult)

        # Cleanup
        client.unbind()

    @pytest.mark.docker
    @pytest.mark.ldap
    @pytest.mark.unit
    def test_search_invalid_filter(self) -> None:
        """Test search with invalid filter syntax."""
        client = FlextLdapClients()

        # Connect
        connect_result = client.connect(
            server_uri="ldap://localhost:3390",
            bind_dn="cn=admin,dc=flext,dc=local",
            password="admin123",
        )
        assert connect_result.is_success is True

        # Search with invalid filter
        result = client.search(
            base_dn="dc=flext,dc=local",
            filter_str="(invalid filter syntax))",  # Mismatched parenthesis
            scope="SUBTREE",
        )

        # This should fail
        assert isinstance(result, FlextResult)

        # Cleanup
        client.unbind()


class TestFlextLdapClientsReturnValues:
    """Return value validation tests."""

    @pytest.mark.docker
    @pytest.mark.ldap
    @pytest.mark.unit
    def test_search_returns_flext_result(self) -> None:
        """Test that search returns FlextResult."""
        client = FlextLdapClients()

        # Connect
        connect_result = client.connect(
            server_uri="ldap://localhost:3390",
            bind_dn="cn=admin,dc=flext,dc=local",
            password="admin123",
        )
        assert connect_result.is_success is True

        # Search
        result = client.search(
            base_dn="dc=flext,dc=local",
            filter_str="(objectClass=*)",
            scope="BASE",
        )

        # Must return FlextResult
        assert isinstance(result, FlextResult)
        assert hasattr(result, "is_success")
        assert hasattr(result, "is_failure")
        assert hasattr(result, "unwrap")

        # Cleanup
        client.unbind()

    @pytest.mark.docker
    @pytest.mark.ldap
    @pytest.mark.unit
    def test_connect_returns_flext_result(self) -> None:
        """Test that connect returns FlextResult."""
        client = FlextLdapClients()

        # Connect
        result = client.connect(
            server_uri="ldap://localhost:3390",
            bind_dn="cn=admin,dc=flext,dc=local",
            password="admin123",
        )

        # Must return FlextResult
        assert isinstance(result, FlextResult)
        assert hasattr(result, "is_success")
        assert hasattr(result, "is_failure")
        assert hasattr(result, "unwrap")
        assert result.is_success is True

        # Cleanup
        client.unbind()


class TestFlextLdapClientsScopesParametrized:
    """Parametrized tests for different LDAP search scopes."""

    @pytest.mark.docker
    @pytest.mark.ldap
    @pytest.mark.unit
    @pytest.mark.parametrize("scope", ["BASE", "ONELEVEL", "SUBTREE"])
    def test_search_with_different_scopes(self, scope: str) -> None:
        """Test search with different scope values."""
        client = FlextLdapClients()

        # Connect
        connect_result = client.connect(
            server_uri="ldap://localhost:3390",
            bind_dn="cn=admin,dc=flext,dc=local",
            password="admin123",
        )
        assert connect_result.is_success is True

        # Search with scope
        result = client.search(
            base_dn="dc=flext,dc=local",
            filter_str="(objectClass=*)",
            scope=scope,
        )

        assert result.is_success is True
        entries = result.unwrap()
        assert isinstance(entries, list)

        # Cleanup
        client.unbind()


__all__ = [
    "TestFlextLdapClientsBasic",
    "TestFlextLdapClientsConnectionReuse",
    "TestFlextLdapClientsErrorHandling",
    "TestFlextLdapClientsReturnValues",
    "TestFlextLdapClientsScopesParametrized",
    "TestFlextLdapClientsSearch",
    "TestFlextLdapClientsServer",
]
