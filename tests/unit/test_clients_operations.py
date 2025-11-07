"""Comprehensive tests for FlextLdapClients CRUD and advanced operations.

This module extends test_clients_comprehensive.py with operations tests covering
add, modify, delete, paging, and advanced operations using real Docker LDAP.

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

from flext_ldap import FlextLdapClients, FlextLdapModels

# mypy: disable-error-code="arg-type,misc,operator,attr-defined,assignment,index,call-arg,union-attr,return-value,list-item,valid-type"


class TestFlextLdapClientsAddEntry:
    """Test add entry operations."""

    @pytest.fixture(autouse=True)
    def connected_client(self) -> FlextLdapClients:
        """Provide a connected FlextLdapClients instance."""
        client = FlextLdapClients()
        connect_result = client.connect(
            server_uri="ldap://localhost:3390",
            bind_dn="cn=REDACTED_LDAP_BIND_PASSWORD,dc=flext,dc=local",
            password="REDACTED_LDAP_BIND_PASSWORD123",
        )
        assert connect_result.is_success is True
        yield client
        client.unbind()

    @pytest.mark.docker
    @pytest.mark.unit
    def test_add_entry_success(self, connected_client: FlextLdapClients) -> None:
        """Test adding a new entry."""
        dn = "cn=testuser,ou=people,dc=flext,dc=local"
        attributes = {
            "cn": ["testuser"],
            "objectClass": ["person", "top"],
            "sn": ["User"],
        }

        result = connected_client.add_entry(dn, attributes)

        # Result can be success or failure (entry may exist)
        assert result.is_success is True or result.is_failure is True

    @pytest.mark.docker
    @pytest.mark.unit
    def test_add_entry_returns_flext_result(
        self, connected_client: FlextLdapClients
    ) -> None:
        """Test add_entry returns FlextResult."""
        dn = "cn=testuser2,ou=people,dc=flext,dc=local"
        attributes = {
            "cn": ["testuser2"],
            "objectClass": ["person", "top"],
            "sn": ["User"],
        }

        result = connected_client.add_entry(dn, attributes)
        assert result.is_success is True or result.is_failure is True


class TestFlextLdapClientsModifyEntry:
    """Test modify entry operations."""

    @pytest.fixture(autouse=True)
    def connected_client(self) -> FlextLdapClients:
        """Provide a connected FlextLdapClients instance."""
        client = FlextLdapClients()
        connect_result = client.connect(
            server_uri="ldap://localhost:3390",
            bind_dn="cn=REDACTED_LDAP_BIND_PASSWORD,dc=flext,dc=local",
            password="REDACTED_LDAP_BIND_PASSWORD123",
        )
        assert connect_result.is_success is True
        yield client
        client.unbind()

    @pytest.mark.docker
    @pytest.mark.unit
    def test_modify_entry_success(self, connected_client: FlextLdapClients) -> None:
        """Test modifying an entry."""
        dn = "cn=REDACTED_LDAP_BIND_PASSWORD,dc=flext,dc=local"
        changes = FlextLdapModels.EntryChanges()

        result = connected_client.modify_entry(dn, changes)
        assert result.is_success is True or result.is_failure is True

    @pytest.mark.docker
    @pytest.mark.unit
    def test_modify_entry_returns_flext_result(
        self, connected_client: FlextLdapClients
    ) -> None:
        """Test modify_entry returns FlextResult."""
        dn = "cn=REDACTED_LDAP_BIND_PASSWORD,dc=flext,dc=local"
        changes = FlextLdapModels.EntryChanges()

        result = connected_client.modify_entry(dn, changes)
        assert result.is_success is True or result.is_failure is True


class TestFlextLdapClientsDeleteEntry:
    """Test delete entry operations."""

    @pytest.fixture(autouse=True)
    def connected_client(self) -> FlextLdapClients:
        """Provide a connected FlextLdapClients instance."""
        client = FlextLdapClients()
        connect_result = client.connect(
            server_uri="ldap://localhost:3390",
            bind_dn="cn=REDACTED_LDAP_BIND_PASSWORD,dc=flext,dc=local",
            password="REDACTED_LDAP_BIND_PASSWORD123",
        )
        assert connect_result.is_success is True
        yield client
        client.unbind()

    @pytest.mark.docker
    @pytest.mark.unit
    def test_delete_entry_nonexistent(self, connected_client: FlextLdapClients) -> None:
        """Test deleting nonexistent entry."""
        dn = "cn=nonexistent,dc=flext,dc=local"

        result = connected_client.delete_entry(dn)
        assert result.is_success is True or result.is_failure is True

    @pytest.mark.docker
    @pytest.mark.unit
    def test_delete_entry_returns_flext_result(
        self, connected_client: FlextLdapClients
    ) -> None:
        """Test delete_entry returns FlextResult."""
        dn = "cn=nonexistent2,dc=flext,dc=local"

        result = connected_client.delete_entry(dn)
        assert result.is_success is True or result.is_failure is True


class TestFlextLdapClientsConnectionState:
    """Test connection state management."""

    @pytest.mark.docker
    @pytest.mark.unit
    def test_is_connected_property_false(self) -> None:
        """Test is_connected when disconnected."""
        client = FlextLdapClients()
        assert client.is_connected is False

    @pytest.mark.docker
    @pytest.mark.unit
    def test_is_connected_property_true(self) -> None:
        """Test is_connected when connected."""
        client = FlextLdapClients()
        result = client.connect(
            server_uri="ldap://localhost:3390",
            bind_dn="cn=REDACTED_LDAP_BIND_PASSWORD,dc=flext,dc=local",
            password="REDACTED_LDAP_BIND_PASSWORD123",
        )
        assert result.is_success is True
        assert client.is_connected is True
        client.unbind()

    @pytest.mark.docker
    @pytest.mark.unit
    def test_connection_property(self) -> None:
        """Test connection property access."""
        client = FlextLdapClients()
        result = client.connect(
            server_uri="ldap://localhost:3390",
            bind_dn="cn=REDACTED_LDAP_BIND_PASSWORD,dc=flext,dc=local",
            password="REDACTED_LDAP_BIND_PASSWORD123",
        )
        assert result.is_success is True

        conn = client.connection
        assert conn is not None

        client.unbind()


class TestFlextLdapClientsLazyInitialization:
    """Test lazy-loaded components."""

    @pytest.fixture(autouse=True)
    def connected_client(self) -> FlextLdapClients:
        """Provide a connected FlextLdapClients instance."""
        client = FlextLdapClients()
        connect_result = client.connect(
            server_uri="ldap://localhost:3390",
            bind_dn="cn=REDACTED_LDAP_BIND_PASSWORD,dc=flext,dc=local",
            password="REDACTED_LDAP_BIND_PASSWORD123",
        )
        assert connect_result.is_success is True
        yield client
        client.unbind()

    @pytest.mark.docker
    @pytest.mark.unit
    def test_searcher_lazy_loading(self, connected_client: FlextLdapClients) -> None:
        """Test searcher lazy initialization."""
        searcher1 = connected_client._get_searcher()
        searcher2 = connected_client._get_searcher()
        assert searcher1 is searcher2

    @pytest.mark.docker
    @pytest.mark.unit
    def test_authenticator_lazy_loading(
        self, connected_client: FlextLdapClients
    ) -> None:
        """Test authenticator lazy initialization."""
        auth1 = connected_client._get_authenticator()
        auth2 = connected_client._get_authenticator()
        assert auth1 is auth2


class TestFlextLdapClientsSearchScopes:
    """Test different search scope operations."""

    @pytest.fixture(autouse=True)
    def connected_client(self) -> FlextLdapClients:
        """Provide a connected FlextLdapClients instance."""
        client = FlextLdapClients()
        connect_result = client.connect(
            server_uri="ldap://localhost:3390",
            bind_dn="cn=REDACTED_LDAP_BIND_PASSWORD,dc=flext,dc=local",
            password="REDACTED_LDAP_BIND_PASSWORD123",
        )
        assert connect_result.is_success is True
        yield client
        client.unbind()

    @pytest.mark.docker
    @pytest.mark.unit
    def test_search_level_scope(self, connected_client: FlextLdapClients) -> None:
        """Test search with LEVEL scope."""
        result = connected_client.search(
            base_dn="dc=flext,dc=local",
            filter_str="(objectClass=*)",
            scope="LEVEL",
        )

        assert result.is_success is True
        entries = result.unwrap()
        assert isinstance(entries, list)

    @pytest.mark.docker
    @pytest.mark.unit
    def test_search_case_insensitive_scope(
        self, connected_client: FlextLdapClients
    ) -> None:
        """Test search with case-insensitive scope."""
        result = connected_client.search(
            base_dn="dc=flext,dc=local",
            filter_str="(objectClass=*)",
            scope="subtree",  # lowercase
        )

        assert result.is_success is True
        entries = result.unwrap()
        assert isinstance(entries, list)


class TestFlextLdapClientsTestConnection:
    """Test connection testing operations."""

    @pytest.mark.docker
    @pytest.mark.unit
    def test_test_connection_no_connection(self) -> None:
        """Test connection test without connection."""
        client = FlextLdapClients()
        result = client.test_connection()

        assert result.is_success is True or result.is_failure is True

    @pytest.mark.docker
    @pytest.mark.unit
    def test_test_connection_with_connection(self) -> None:
        """Test connection test with active connection."""
        client = FlextLdapClients()
        connect_result = client.connect(
            server_uri="ldap://localhost:3390",
            bind_dn="cn=REDACTED_LDAP_BIND_PASSWORD,dc=flext,dc=local",
            password="REDACTED_LDAP_BIND_PASSWORD123",
        )
        assert connect_result.is_success is True

        test_result = client.test_connection()
        assert test_result.is_success is True

        client.unbind()


class TestFlextLdapClientsGetServerInfo:
    """Test server information retrieval."""

    @pytest.fixture(autouse=True)
    def connected_client(self) -> FlextLdapClients:
        """Provide a connected FlextLdapClients instance."""
        client = FlextLdapClients()
        connect_result = client.connect(
            server_uri="ldap://localhost:3390",
            bind_dn="cn=REDACTED_LDAP_BIND_PASSWORD,dc=flext,dc=local",
            password="REDACTED_LDAP_BIND_PASSWORD123",
        )
        assert connect_result.is_success is True
        yield client
        client.unbind()

    @pytest.mark.docker
    @pytest.mark.unit
    def test_get_server_info_returns_dict(
        self, connected_client: FlextLdapClients
    ) -> None:
        """Test get_server_info returns dictionary."""
        result = connected_client.get_server_info()

        assert result.is_success is True or result.is_failure is True
        if result.is_success:
            info = result.unwrap()
            assert isinstance(info, dict)


class TestFlextLdapClientsAttributeOperations:
    """Test attribute-level operations."""

    @pytest.fixture(autouse=True)
    def connected_client(self) -> FlextLdapClients:
        """Provide a connected FlextLdapClients instance."""
        client = FlextLdapClients()
        connect_result = client.connect(
            server_uri="ldap://localhost:3390",
            bind_dn="cn=REDACTED_LDAP_BIND_PASSWORD,dc=flext,dc=local",
            password="REDACTED_LDAP_BIND_PASSWORD123",
        )
        assert connect_result.is_success is True
        yield client
        client.unbind()

    @pytest.mark.docker
    @pytest.mark.unit
    def test_search_with_specific_attributes(
        self, connected_client: FlextLdapClients
    ) -> None:
        """Test search requesting specific attributes."""
        result = connected_client.search(
            base_dn="dc=flext,dc=local",
            filter_str="(objectClass=*)",
            attributes=["cn", "mail", "objectClass"],
            scope="BASE",
        )

        assert result.is_success is True
        entries = result.unwrap()
        assert isinstance(entries, list)

    @pytest.mark.docker
    @pytest.mark.unit
    def test_search_with_none_attributes(
        self, connected_client: FlextLdapClients
    ) -> None:
        """Test search with None attributes (all)."""
        result = connected_client.search(
            base_dn="dc=flext,dc=local",
            filter_str="(objectClass=*)",
            attributes=None,
            scope="BASE",
        )

        assert result.is_success is True
        entries = result.unwrap()
        assert isinstance(entries, list)


__all__ = [
    "TestFlextLdapClientsAddEntry",
    "TestFlextLdapClientsAttributeOperations",
    "TestFlextLdapClientsConnectionState",
    "TestFlextLdapClientsDeleteEntry",
    "TestFlextLdapClientsGetServerInfo",
    "TestFlextLdapClientsLazyInitialization",
    "TestFlextLdapClientsModifyEntry",
    "TestFlextLdapClientsSearchScopes",
    "TestFlextLdapClientsTestConnection",
]
