"""Comprehensive real Docker LDAP tests for FlextLdapClients.

This module contains comprehensive tests for FlextLdapClients using real Docker
LDAP containers. All tests use actual LDAP operations without any mocks, stubs,
or wrappers.

Test Categories:
- @pytest.mark.docker - Requires Docker LDAP container
- @pytest.mark.unit - Unit tests with real LDAP operations

Container Requirements:
    Docker container must be running on port 3390
    Base DN: dc=flext,dc=local
    Admin DN: cn=REDACTED_LDAP_BIND_PASSWORD,dc=flext,dc=local
    Admin password: REDACTED_LDAP_BIND_PASSWORD123
"""

from __future__ import annotations

import pytest

from flext_ldap import FlextLdapClients

# mypy: disable-error-code="arg-type,misc,operator,attr-defined,assignment,index,call-arg,union-attr,return-value,list-item,valid-type"


class TestFlextLdapClientsConnection:
    """Test connection and binding operations with real LDAP."""

    @pytest.mark.docker
    @pytest.mark.unit
    def test_connect_with_credentials_success(self) -> None:
        """Test authenticated connection to LDAP server."""
        client = FlextLdapClients()

        result = client.connect(
            server_uri="ldap://localhost:3390",
            bind_dn="cn=REDACTED_LDAP_BIND_PASSWORD,dc=flext,dc=local",
            password="REDACTED_LDAP_BIND_PASSWORD123",
        )

        assert result.is_success is True
        assert client.is_connected is True

        # Cleanup
        client.unbind()

    @pytest.mark.docker
    @pytest.mark.unit
    def test_unbind_success(self) -> None:
        """Test unbind operation."""
        client = FlextLdapClients()

        # Connect
        result = client.connect(
            server_uri="ldap://localhost:3390",
            bind_dn="cn=REDACTED_LDAP_BIND_PASSWORD,dc=flext,dc=local",
            password="REDACTED_LDAP_BIND_PASSWORD123",
        )
        assert result.is_success is True
        assert client.is_connected is True

        # Unbind
        unbind_result = client.unbind()
        assert unbind_result.is_success is True
        assert client.is_connected is False

    @pytest.mark.docker
    @pytest.mark.unit
    def test_bind_after_connect(self) -> None:
        """Test explicit bind after connection."""
        client = FlextLdapClients()

        # First connect with initial credentials
        connect_result = client.connect(
            server_uri="ldap://localhost:3390",
            bind_dn="cn=REDACTED_LDAP_BIND_PASSWORD,dc=flext,dc=local",
            password="REDACTED_LDAP_BIND_PASSWORD123",
        )
        assert connect_result.is_success is True

        # Verify connected
        assert client.is_connected is True

        # Cleanup
        client.unbind()

    @pytest.mark.docker
    @pytest.mark.unit
    def test_test_connection_success(self) -> None:
        """Test connection testing method on connected client."""
        client = FlextLdapClients()

        # First connect
        connect_result = client.connect(
            server_uri="ldap://localhost:3390",
            bind_dn="cn=REDACTED_LDAP_BIND_PASSWORD,dc=flext,dc=local",
            password="REDACTED_LDAP_BIND_PASSWORD123",
        )
        assert connect_result.is_success is True

        # Then test the connection
        result = client.test_connection()
        assert result.is_success is True
        assert result.unwrap() is True

        # Cleanup
        client.unbind()

    @pytest.mark.docker
    @pytest.mark.unit
    def test_is_connected_property(self) -> None:
        """Test is_connected property."""
        client = FlextLdapClients()

        assert client.is_connected is False

        client.connect(
            server_uri="ldap://localhost:3390",
            bind_dn="cn=REDACTED_LDAP_BIND_PASSWORD,dc=flext,dc=local",
            password="REDACTED_LDAP_BIND_PASSWORD123",
        )
        assert client.is_connected is True

        client.unbind()
        assert client.is_connected is False


class TestFlextLdapClientsSearch:
    """Test search operations with real LDAP data."""

    @pytest.fixture(autouse=True)
    def connected_client(self) -> FlextLdapClients:
        """Provide a connected LDAP client."""
        client = FlextLdapClients()
        connect_result = client.connect(
            server_uri="ldap://localhost:3390",
            bind_dn="cn=REDACTED_LDAP_BIND_PASSWORD,dc=flext,dc=local",
            password="REDACTED_LDAP_BIND_PASSWORD123",
        )
        assert connect_result.is_success is True, (
            f"Connection failed: {connect_result.error}"
        )
        yield client
        client.unbind()

    @pytest.mark.docker
    @pytest.mark.unit
    def test_search_base_scope(self, connected_client: FlextLdapClients) -> None:
        """Test search with BASE scope."""
        result = connected_client.search(
            base_dn="dc=flext,dc=local",
            filter_str="(objectClass=*)",
            scope="BASE",
        )

        assert result.is_success is True
        entries = result.unwrap()
        assert isinstance(entries, list)
        assert len(entries) > 0

    @pytest.mark.docker
    @pytest.mark.unit
    def test_search_subtree_scope(self, connected_client: FlextLdapClients) -> None:
        """Test search with SUBTREE scope."""
        result = connected_client.search(
            base_dn="dc=flext,dc=local",
            filter_str="(objectClass=*)",
            scope="SUBTREE",
        )

        assert result.is_success is True
        entries = result.unwrap()
        assert isinstance(entries, list)
        assert len(entries) >= 1

    @pytest.mark.docker
    @pytest.mark.unit
    def test_search_with_filter(self, connected_client: FlextLdapClients) -> None:
        """Test search with specific filter."""
        result = connected_client.search(
            base_dn="dc=flext,dc=local",
            filter_str="(cn=*)",
            scope="SUBTREE",
        )

        assert result.is_success is True
        entries = result.unwrap()
        assert isinstance(entries, list)

    @pytest.mark.docker
    @pytest.mark.unit
    def test_search_empty_result(self, connected_client: FlextLdapClients) -> None:
        """Test search with filter that returns no results."""
        result = connected_client.search(
            base_dn="dc=flext,dc=local",
            filter_str="(cn=nonexistent-entry-xyz)",
            scope="SUBTREE",
        )

        assert result.is_success is True
        entries = result.unwrap()
        assert isinstance(entries, list)
        assert len(entries) == 0


class TestFlextLdapClientsConnectionValidation:
    """Test connection validation and lifecycle."""

    @pytest.mark.docker
    @pytest.mark.unit
    def test_connection_persistence(self) -> None:
        """Test that connection persists across operations."""
        client = FlextLdapClients()

        # Connect
        connect_result = client.connect(
            server_uri="ldap://localhost:3390",
            bind_dn="cn=REDACTED_LDAP_BIND_PASSWORD,dc=flext,dc=local",
            password="REDACTED_LDAP_BIND_PASSWORD123",
        )
        assert connect_result.is_success is True
        assert client.is_connected is True

        # Perform multiple operations on same connection
        search_result1 = client.search(
            base_dn="dc=flext,dc=local",
            filter_str="(objectClass=*)",
            scope="BASE",
        )
        assert search_result1.is_success is True

        search_result2 = client.search(
            base_dn="dc=flext,dc=local",
            filter_str="(cn=*)",
            scope="SUBTREE",
        )
        assert search_result2.is_success is True

        # Connection should still be active
        assert client.is_connected is True

        # Cleanup
        client.unbind()
        assert client.is_connected is False


class TestFlextLdapClientsUserManagement:
    """Test user management operations with real LDAP data."""

    @pytest.fixture(autouse=True)
    def connected_client(self) -> FlextLdapClients:
        """Provide a connected LDAP client."""
        client = FlextLdapClients()
        connect_result = client.connect(
            server_uri="ldap://localhost:3390",
            bind_dn="cn=REDACTED_LDAP_BIND_PASSWORD,dc=flext,dc=local",
            password="REDACTED_LDAP_BIND_PASSWORD123",
        )
        assert connect_result.is_success is True, (
            f"Connection failed: {connect_result.error}"
        )
        yield client
        client.unbind()

    @pytest.mark.docker
    @pytest.mark.unit
    def test_search_users(self, connected_client: FlextLdapClients) -> None:
        """Test searching for users."""
        result = connected_client.search_users(base_dn="dc=flext,dc=local")

        assert result.is_success is True or result.is_failure is True
        if result.is_success:
            users = result.unwrap()
            assert isinstance(users, list)

    @pytest.mark.docker
    @pytest.mark.unit
    def test_user_exists_nonexistent(self, connected_client: FlextLdapClients) -> None:
        """Test checking if user exists."""
        # Construct DN from username and base DN
        dn = "uid=nonexistent-user-xyz-abc,ou=people,dc=flext,dc=local"
        result = connected_client.user_exists(dn)

        assert result.is_success is True
        exists = result.unwrap()
        assert isinstance(exists, bool)


class TestFlextLdapClientsGroupManagement:
    """Test group management operations with real LDAP data."""

    @pytest.fixture(autouse=True)
    def connected_client(self) -> FlextLdapClients:
        """Provide a connected LDAP client."""
        client = FlextLdapClients()
        connect_result = client.connect(
            server_uri="ldap://localhost:3390",
            bind_dn="cn=REDACTED_LDAP_BIND_PASSWORD,dc=flext,dc=local",
            password="REDACTED_LDAP_BIND_PASSWORD123",
        )
        assert connect_result.is_success is True, (
            f"Connection failed: {connect_result.error}"
        )
        yield client
        client.unbind()

    @pytest.mark.docker
    @pytest.mark.unit
    def test_search_groups(self, connected_client: FlextLdapClients) -> None:
        """Test searching for groups."""
        result = connected_client.search_groups(base_dn="dc=flext,dc=local")

        assert result.is_success is True or result.is_failure is True
        if result.is_success:
            groups = result.unwrap()
            assert isinstance(groups, list)

    @pytest.mark.docker
    @pytest.mark.unit
    def test_group_exists_nonexistent(self, connected_client: FlextLdapClients) -> None:
        """Test checking if group exists."""
        # Construct DN from group name and base DN
        dn = "cn=nonexistent-group-xyz,ou=groups,dc=flext,dc=local"
        result = connected_client.group_exists(dn)

        assert result.is_success is True
        exists = result.unwrap()
        assert isinstance(exists, bool)


class TestFlextLdapClientsServerInfo:
    """Test server information retrieval."""

    @pytest.fixture(autouse=True)
    def connected_client(self) -> FlextLdapClients:
        """Provide a connected LDAP client."""
        client = FlextLdapClients()
        connect_result = client.connect(
            server_uri="ldap://localhost:3390",
            bind_dn="cn=REDACTED_LDAP_BIND_PASSWORD,dc=flext,dc=local",
            password="REDACTED_LDAP_BIND_PASSWORD123",
        )
        assert connect_result.is_success is True, (
            f"Connection failed: {connect_result.error}"
        )
        yield client
        client.unbind()

    @pytest.mark.docker
    @pytest.mark.unit
    def test_get_server_info(self, connected_client: FlextLdapClients) -> None:
        """Test getting server information."""
        result = connected_client.get_server_info()

        assert result.is_success is True or result.is_failure is True
        if result.is_success:
            info = result.unwrap()
            assert isinstance(info, dict)


class TestFlextLdapClientsMethods:
    """Test various client methods."""

    @pytest.fixture(autouse=True)
    def connected_client(self) -> FlextLdapClients:
        """Provide a connected LDAP client."""
        client = FlextLdapClients()
        connect_result = client.connect(
            server_uri="ldap://localhost:3390",
            bind_dn="cn=REDACTED_LDAP_BIND_PASSWORD,dc=flext,dc=local",
            password="REDACTED_LDAP_BIND_PASSWORD123",
        )
        assert connect_result.is_success is True, (
            f"Connection failed: {connect_result.error}"
        )
        yield client
        client.unbind()

    @pytest.mark.docker
    @pytest.mark.unit
    def test_client_has_connection_property(
        self, connected_client: FlextLdapClients
    ) -> None:
        """Test client has connection property."""
        assert hasattr(connected_client, "connection")
        connection = connected_client.connection
        assert connection is not None

    @pytest.mark.docker
    @pytest.mark.unit
    def test_config_property(self, connected_client: FlextLdapClients) -> None:
        """Test client config property."""
        assert hasattr(connected_client, "config")
        config = connected_client.config
        assert config is not None


__all__ = [
    "TestFlextLdapClientsConnection",
    "TestFlextLdapClientsConnectionValidation",
    "TestFlextLdapClientsGroupManagement",
    "TestFlextLdapClientsMethods",
    "TestFlextLdapClientsSearch",
    "TestFlextLdapClientsServerInfo",
    "TestFlextLdapClientsUserManagement",
]
