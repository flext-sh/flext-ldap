"""Real coverage tests for flext_ldap.clients module.

These tests execute actual code from the clients module to achieve real test coverage.
They test the LDAP client logic, error handling, and integration patterns.
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import ldap3
import pytest
from ldap3.core.exceptions import LDAPException

from flext_ldap import (
    SCOPE_MAP,
    FlextLdapClient,
    FlextLdapSearchRequest,
    FlextLdapSearchResponse,
    LdapAttributeDict,
)


class TestFlextLdapClientRealExecution:
    """Test FlextLdapClient with real code execution."""

    def test_client_instantiation_real(self) -> None:
        """Test client can be instantiated - real instantiation."""
        client = FlextLdapClient()

        # Verify real initialization
        assert client._connection is None
        assert client._server is None
        assert hasattr(client, "connect")
        assert hasattr(client, "search")
        assert hasattr(client, "add")
        assert hasattr(client, "modify")
        assert hasattr(client, "delete")
        assert hasattr(client, "bind")
        assert hasattr(client, "unbind")
        assert hasattr(client, "is_connected")

    def test_is_connected_property_real(self) -> None:
        """Test is_connected property logic - real property execution."""
        client = FlextLdapClient()

        # Initially not connected
        assert not client.is_connected

        # Mock connection but not bound
        mock_connection = MagicMock()
        mock_connection.bound = False
        client._connection = mock_connection
        assert not client.is_connected

        # Mock connection and bound
        mock_connection.bound = True
        assert client.is_connected

        # No connection
        client._connection = None
        assert not client.is_connected

    def test_scope_map_constants_real(self) -> None:
        """Test SCOPE_MAP constants are correctly mapped - real constants."""
        # Verify real scope mapping logic
        assert SCOPE_MAP["base"] == ldap3.BASE
        assert SCOPE_MAP["one"] == ldap3.LEVEL
        assert SCOPE_MAP["onelevel"] == ldap3.LEVEL
        assert SCOPE_MAP["sub"] == ldap3.SUBTREE
        assert SCOPE_MAP["subtree"] == ldap3.SUBTREE

        # Test subordinates fallback logic
        expected_subordinates = getattr(ldap3, "SUBORDINATES", ldap3.SUBTREE)
        assert SCOPE_MAP["subordinates"] == expected_subordinates

    async def test_connect_parses_uri_real(self) -> None:
        """Test connect parses URI correctly - real URI parsing execution."""
        client = FlextLdapClient()

        # Mock Server and Connection to avoid actual connection
        with (
            patch("flext_ldap.clients.ldap3.Server") as mock_server_class,
            patch("flext_ldap.clients.ldap3.Connection") as mock_connection_class,
        ):
            # Setup mocks
            mock_server = MagicMock()
            mock_server_class.return_value = mock_server

            mock_connection = MagicMock()
            mock_connection.bound = True
            mock_connection_class.return_value = mock_connection

            # Test LDAP URI parsing
            result = await client.connect("ldap://testhost:389", "cn=admin", "password")

            # Verify real URI parsing logic was executed
            assert result.is_success
            mock_server_class.assert_called_once_with(
                host="testhost", port=389, use_ssl=False, get_info=ldap3.ALL, tls=None
            )

    async def test_connect_handles_ldaps_uri_real(self) -> None:
        """Test connect handles LDAPS URI with SSL - real SSL logic execution."""
        client = FlextLdapClient()

        # Mock Server and Connection
        with (
            patch("flext_ldap.clients.ldap3.Server") as mock_server_class,
            patch("flext_ldap.clients.ldap3.Connection") as mock_connection_class,
            patch("flext_ldap.clients.ldap3.Tls") as mock_tls_class,
        ):
            # Setup mocks
            mock_server = MagicMock()
            mock_server_class.return_value = mock_server

            mock_connection = MagicMock()
            mock_connection.bound = True
            mock_connection_class.return_value = mock_connection

            mock_tls = MagicMock()
            mock_tls_class.return_value = mock_tls

            # Test LDAPS URI parsing
            result = await client.connect(
                "ldaps://secure.example.com:636", "cn=admin", "password"
            )

            # Verify real LDAPS parsing and SSL setup
            assert result.is_success
            mock_server_class.assert_called_once_with(
                host="secure.example.com",
                port=636,
                use_ssl=True,
                get_info=ldap3.ALL,
                tls=mock_tls,
            )

            # Verify TLS configuration
            mock_tls_class.assert_called_once()

    async def test_connect_handles_default_ports_real(self) -> None:
        """Test connect uses default ports - real default port logic."""
        client = FlextLdapClient()

        # Mock Server and Connection
        with (
            patch("flext_ldap.clients.ldap3.Server") as mock_server_class,
            patch("flext_ldap.clients.ldap3.Connection") as mock_connection_class,
        ):
            # Setup mocks
            mock_server = MagicMock()
            mock_server_class.return_value = mock_server

            mock_connection = MagicMock()
            mock_connection.bound = True
            mock_connection_class.return_value = mock_connection

            # Test default LDAP port
            await client.connect("ldap://example.com", "cn=admin", "password")
            mock_server_class.assert_called_with(
                host="example.com",
                port=389,  # Default LDAP port
                use_ssl=False,
                get_info=ldap3.ALL,
                tls=None,
            )

            mock_server_class.reset_mock()

            # Test default LDAPS port
            await client.connect("ldaps://example.com", "cn=admin", "password")

            # Verify the call was made with LDAPS settings
            call_args = mock_server_class.call_args
            assert call_args[1]["host"] == "example.com"
            assert call_args[1]["port"] == 636  # Default LDAPS port
            assert call_args[1]["use_ssl"] is True
            assert call_args[1]["get_info"] == ldap3.ALL
            assert call_args[1]["tls"] is not None  # TLS object should be created

    async def test_connect_handles_bind_failure_real(self) -> None:
        """Test connect handles bind failure - real bind failure handling."""
        client = FlextLdapClient()

        # Mock Server and Connection with bind failure
        with (
            patch("flext_ldap.clients.ldap3.Server") as mock_server_class,
            patch("flext_ldap.clients.ldap3.Connection") as mock_connection_class,
        ):
            # Setup mocks - connection not bound
            mock_server = MagicMock()
            mock_server_class.return_value = mock_server

            mock_connection = MagicMock()
            mock_connection.bound = False  # Bind failed
            mock_connection_class.return_value = mock_connection

            # Execute real bind failure handling
            result = await client.connect(
                "ldap://example.com", "cn=invalid", "wrongpass"
            )

            # Verify real bind failure handling
            assert not result.is_success
            assert "Failed to bind to LDAP server" in (result.error or "")

    async def test_connect_handles_ldap_exception_real(self) -> None:
        """Test connect handles LDAP exceptions - real exception handling."""
        client = FlextLdapClient()

        # Mock Server to raise LDAPException
        with patch("flext_ldap.clients.ldap3.Server") as mock_server_class:
            mock_server_class.side_effect = LDAPException("Connection failed")

            # Execute real exception handling
            result = await client.connect("ldap://badhost", "cn=admin", "password")

            # Verify real exception handling
            assert not result.is_success
            assert "LDAP connection failed" in (result.error or "")
            assert "Connection failed" in (result.error or "")

    async def test_connect_handles_generic_exception_real(self) -> None:
        """Test connect handles generic exceptions - real exception handling."""
        client = FlextLdapClient()

        # Mock Server to raise generic exception
        with patch("flext_ldap.clients.ldap3.Server") as mock_server_class:
            mock_server_class.side_effect = ValueError("Invalid host")

            # Execute real exception handling
            result = await client.connect("invalid://uri", "cn=admin", "password")

            # Verify real exception handling
            assert not result.is_success
            assert "Connection error" in (result.error or "")
            assert "Invalid host" in (result.error or "")

    async def test_search_not_connected_real(self) -> None:
        """Test search when not connected - real connection check."""
        client = FlextLdapClient()

        # Create search request
        search_request = FlextLdapSearchRequest(
            base_dn="dc=example,dc=com",
            scope="subtree",
            filter_str="(objectClass=*)",
            attributes=None,
            size_limit=100,
            time_limit=30,
        )

        # Execute real connection check
        result = await client.search(search_request)

        # Verify real connection check logic
        assert not result.is_success
        assert "Not connected to LDAP server" in (result.error or "")

    async def test_search_scope_mapping_real(self) -> None:
        """Test search maps scope correctly - real scope mapping execution."""
        client = FlextLdapClient()

        # Mock connection
        mock_connection = MagicMock()
        mock_connection.bound = True
        client._connection = mock_connection

        # Mock search method and utilities
        with patch("flext_ldap.clients.FlextLdapUtilities") as mock_utils:
            mock_utils.safe_ldap3_search_result.return_value = True
            mock_utils.safe_ldap3_entries_list.return_value = []

            mock_connection.search.return_value = True

            # Test different scopes
            test_scopes = [
                ("base", ldap3.BASE),
                ("one", ldap3.LEVEL),
                ("onelevel", ldap3.LEVEL),
                ("sub", ldap3.SUBTREE),
                ("subtree", ldap3.SUBTREE),
                ("unknown", ldap3.SUBTREE),  # Should default to SUBTREE
            ]

            for scope_name, expected_constant in test_scopes:
                search_request = FlextLdapSearchRequest(
                    base_dn="dc=example,dc=com",
                    scope=scope_name,
                    filter_str="(objectClass=*)",
                    attributes=None,
                    size_limit=100,
                    time_limit=30,
                )

                # Execute real scope mapping
                await client.search(search_request)

                # Verify real scope mapping was used
                mock_connection.search.assert_called()
                call_args = mock_connection.search.call_args
                assert call_args[1]["search_scope"] == expected_constant

                mock_connection.reset_mock()

    async def test_search_handles_search_failure_real(self) -> None:
        """Test search handles search failure - real search failure handling."""
        client = FlextLdapClient()

        # Mock connection
        mock_connection = MagicMock()
        mock_connection.bound = True
        client._connection = mock_connection

        # Mock search method and utilities to simulate failure
        with patch("flext_ldap.clients.FlextLdapUtilities") as mock_utils:
            mock_utils.safe_ldap3_search_result.return_value = False
            mock_utils.safe_ldap3_connection_result.return_value = (
                "Search failed: invalid filter"
            )

            mock_connection.search.return_value = False

            search_request = FlextLdapSearchRequest(
                base_dn="dc=example,dc=com",
                scope="subtree",
                filter_str="(invalid filter)",
                attributes=None,
                size_limit=100,
                time_limit=30,
            )

            # Execute real search failure handling
            result = await client.search(search_request)

            # Verify real search failure handling
            assert not result.is_success
            assert "Search failed: Search failed: invalid filter" in (
                result.error or ""
            )

    async def test_search_processes_entries_real(self) -> None:
        """Test search processes entries correctly - real entry processing."""
        client = FlextLdapClient()

        # Mock connection
        mock_connection = MagicMock()
        mock_connection.bound = True
        client._connection = mock_connection

        # Mock search method and utilities
        with patch("flext_ldap.clients.FlextLdapUtilities") as mock_utils:
            mock_utils.safe_ldap3_search_result.return_value = True

            # Mock entries
            mock_entry1 = MagicMock()
            mock_entry2 = MagicMock()
            mock_utils.safe_ldap3_entries_list.return_value = [mock_entry1, mock_entry2]

            # Mock entry data
            mock_utils.safe_ldap3_entry_dn.side_effect = [
                "cn=user1,ou=users,dc=example,dc=com",
                "cn=user2,ou=users,dc=example,dc=com",
            ]
            mock_utils.safe_ldap3_entry_attributes_list.side_effect = [
                ["cn", "uid", "mail"],
                ["cn", "uid"],
            ]
            mock_utils.safe_ldap3_attribute_values.side_effect = [
                # Entry 1 attributes
                ["user1"],  # cn
                ["user1"],  # uid
                ["user1@example.com"],  # mail
                # Entry 2 attributes
                ["user2"],  # cn
                ["user2"],  # uid
            ]

            mock_connection.search.return_value = True

            search_request = FlextLdapSearchRequest(
                base_dn="ou=users,dc=example,dc=com",
                scope="subtree",
                filter_str="(objectClass=person)",
                attributes=None,
                size_limit=100,
                time_limit=30,
            )

            # Execute real entry processing
            result = await client.search(search_request)

            # Verify real entry processing
            assert result.is_success
            assert isinstance(result.value, FlextLdapSearchResponse)
            assert result.value.total_count == 2
            assert len(result.value.entries) == 2

            # Verify entry data
            entry1 = result.value.entries[0]
            assert entry1["dn"] == "cn=user1,ou=users,dc=example,dc=com"
            assert entry1["cn"] == "user1"
            assert entry1["uid"] == "user1"
            assert entry1["mail"] == "user1@example.com"

            entry2 = result.value.entries[1]
            assert entry2["dn"] == "cn=user2,ou=users,dc=example,dc=com"
            assert entry2["cn"] == "user2"
            assert entry2["uid"] == "user2"

    async def test_search_handles_ldap_exception_real(self) -> None:
        """Test search handles LDAP exceptions - real exception handling."""
        client = FlextLdapClient()

        # Mock connection
        mock_connection = MagicMock()
        mock_connection.bound = True
        mock_connection.search.side_effect = LDAPException("Search timeout")
        client._connection = mock_connection

        search_request = FlextLdapSearchRequest(
            base_dn="dc=example,dc=com",
            scope="subtree",
            filter_str="(objectClass=*)",
            attributes=None,
            size_limit=100,
            time_limit=30,
        )

        # Execute real LDAP exception handling
        result = await client.search(search_request)

        # Verify real exception handling
        assert not result.is_success
        assert "Search failed: Search timeout" in (result.error or "")

    async def test_search_handles_generic_exception_real(self) -> None:
        """Test search handles generic exceptions - real exception handling."""
        client = FlextLdapClient()

        # Mock connection
        mock_connection = MagicMock()
        mock_connection.bound = True
        mock_connection.search.side_effect = ValueError("Invalid search parameters")
        client._connection = mock_connection

        search_request = FlextLdapSearchRequest(
            base_dn="dc=example,dc=com",
            scope="subtree",
            filter_str="(objectClass=*)",
            attributes=None,
            size_limit=100,
            time_limit=30,
        )

        # Execute real generic exception handling
        result = await client.search(search_request)

        # Verify real exception handling
        assert not result.is_success
        assert "Search error: Invalid search parameters" in (result.error or "")

    async def test_add_not_connected_real(self) -> None:
        """Test add when not connected - real connection check."""
        client = FlextLdapClient()

        attributes: LdapAttributeDict = {
            "objectClass": ["person", "inetOrgPerson"],
            "cn": "testuser",
            "uid": "testuser",
        }

        # Execute real connection check
        result = await client.add("cn=testuser,ou=users,dc=example,dc=com", attributes)

        # Verify real connection check logic
        assert not result.is_success
        assert "Not connected to LDAP server" in (result.error or "")

    async def test_add_success_real(self) -> None:
        """Test successful add operation - real add execution."""
        client = FlextLdapClient()

        # Mock connection
        mock_connection = MagicMock()
        mock_connection.bound = True
        mock_connection.add.return_value = True
        client._connection = mock_connection

        attributes: LdapAttributeDict = {
            "objectClass": ["person", "inetOrgPerson"],
            "cn": "testuser",
            "uid": "testuser",
        }

        # Execute real add operation
        result = await client.add("cn=testuser,ou=users,dc=example,dc=com", attributes)

        # Verify real add execution
        assert result.is_success
        mock_connection.add.assert_called_once_with(
            "cn=testuser,ou=users,dc=example,dc=com", attributes=attributes
        )

    async def test_add_failure_real(self) -> None:
        """Test add operation failure - real failure handling."""
        client = FlextLdapClient()

        # Mock connection with add failure
        mock_connection = MagicMock()
        mock_connection.bound = True
        mock_connection.add.return_value = False
        mock_connection.result = {"description": "Already exists"}
        client._connection = mock_connection

        attributes: LdapAttributeDict = {"objectClass": ["person"], "cn": "duplicate"}

        # Execute real add failure handling
        result = await client.add("cn=duplicate,dc=example,dc=com", attributes)

        # Verify real failure handling
        assert not result.is_success
        assert "Add failed:" in (result.error or "")

    async def test_add_ldap_exception_real(self) -> None:
        """Test add handles LDAP exceptions - real exception handling."""
        client = FlextLdapClient()

        # Mock connection with exception
        mock_connection = MagicMock()
        mock_connection.bound = True
        mock_connection.add.side_effect = LDAPException("Schema violation")
        client._connection = mock_connection

        attributes: LdapAttributeDict = {"invalid": "data"}

        # Execute real LDAP exception handling
        result = await client.add("cn=test,dc=example,dc=com", attributes)

        # Verify real exception handling
        assert not result.is_success
        assert "Add failed: Schema violation" in (result.error or "")

    async def test_modify_not_connected_real(self) -> None:
        """Test modify when not connected - real connection check."""
        client = FlextLdapClient()

        attributes: LdapAttributeDict = {"description": "modified"}

        # Execute real connection check
        result = await client.modify("cn=testuser,dc=example,dc=com", attributes)

        # Verify real connection check logic
        assert not result.is_success
        assert "Not connected to LDAP server" in (result.error or "")

    async def test_modify_success_real(self) -> None:
        """Test successful modify operation - real modify execution."""
        client = FlextLdapClient()

        # Mock connection
        mock_connection = MagicMock()
        mock_connection.bound = True
        mock_connection.modify.return_value = True
        client._connection = mock_connection

        attributes: LdapAttributeDict = {
            "description": "updated description",
            "mail": "new@example.com",
        }

        # Execute real modify operation
        result = await client.modify("cn=testuser,dc=example,dc=com", attributes)

        # Verify real modify execution and changes format
        assert result.is_success
        mock_connection.modify.assert_called_once()
        call_args = mock_connection.modify.call_args
        assert call_args[0][0] == "cn=testuser,dc=example,dc=com"

        # Verify changes dictionary format (MODIFY_REPLACE)
        changes = call_args[0][1]
        assert "description" in changes
        assert changes["description"] == [(ldap3.MODIFY_REPLACE, "updated description")]
        assert "mail" in changes
        assert changes["mail"] == [(ldap3.MODIFY_REPLACE, "new@example.com")]

    async def test_modify_failure_real(self) -> None:
        """Test modify operation failure - real failure handling."""
        client = FlextLdapClient()

        # Mock connection with modify failure
        mock_connection = MagicMock()
        mock_connection.bound = True
        mock_connection.modify.return_value = False
        mock_connection.result = {"description": "No such object"}
        client._connection = mock_connection

        attributes: LdapAttributeDict = {"description": "test"}

        # Execute real modify failure handling
        result = await client.modify("cn=nonexistent,dc=example,dc=com", attributes)

        # Verify real failure handling
        assert not result.is_success
        assert "Modify failed:" in (result.error or "")

    async def test_delete_not_connected_real(self) -> None:
        """Test delete when not connected - real connection check."""
        client = FlextLdapClient()

        # Execute real connection check
        result = await client.delete("cn=testuser,dc=example,dc=com")

        # Verify real connection check logic
        assert not result.is_success
        assert "Not connected to LDAP server" in (result.error or "")

    async def test_delete_success_real(self) -> None:
        """Test successful delete operation - real delete execution."""
        client = FlextLdapClient()

        # Mock connection
        mock_connection = MagicMock()
        mock_connection.bound = True
        mock_connection.delete.return_value = True
        client._connection = mock_connection

        # Execute real delete operation
        result = await client.delete("cn=testuser,dc=example,dc=com")

        # Verify real delete execution
        assert result.is_success
        mock_connection.delete.assert_called_once_with("cn=testuser,dc=example,dc=com")

    async def test_delete_failure_real(self) -> None:
        """Test delete operation failure - real failure handling."""
        client = FlextLdapClient()

        # Mock connection with delete failure
        mock_connection = MagicMock()
        mock_connection.bound = True
        mock_connection.delete.return_value = False
        mock_connection.result = {"description": "No such object"}
        client._connection = mock_connection

        # Execute real delete failure handling
        result = await client.delete("cn=nonexistent,dc=example,dc=com")

        # Verify real failure handling
        assert not result.is_success
        assert "Delete failed:" in (result.error or "")

    async def test_bind_no_connection_real(self) -> None:
        """Test bind when no connection exists - real connection check."""
        client = FlextLdapClient()

        # Execute real connection check
        result = await client.bind("cn=testuser,dc=example,dc=com", "password")

        # Verify real connection check logic
        assert not result.is_success
        assert "No connection established" in (result.error or "")

    async def test_bind_success_real(self) -> None:
        """Test successful bind operation - real bind execution."""
        client = FlextLdapClient()

        # Mock connection
        mock_connection = MagicMock()
        client._connection = mock_connection

        # Mock FlextLdapUtilities
        with patch("flext_ldap.clients.FlextLdapUtilities") as mock_utils:
            mock_utils.safe_ldap3_rebind_result.return_value = True

            # Execute real bind operation
            result = await client.bind("cn=testuser,dc=example,dc=com", "password")

            # Verify real bind execution
            assert result.is_success
            mock_utils.safe_ldap3_rebind_result.assert_called_once_with(
                mock_connection, "cn=testuser,dc=example,dc=com", "password"
            )

    async def test_bind_failure_real(self) -> None:
        """Test bind operation failure - real failure handling."""
        client = FlextLdapClient()

        # Mock connection
        mock_connection = MagicMock()
        client._connection = mock_connection

        # Mock FlextLdapUtilities
        with patch("flext_ldap.clients.FlextLdapUtilities") as mock_utils:
            mock_utils.safe_ldap3_rebind_result.return_value = False
            mock_utils.safe_ldap3_connection_result.return_value = "Invalid credentials"

            # Execute real bind failure handling
            result = await client.bind("cn=invalid,dc=example,dc=com", "wrongpass")

            # Verify real failure handling
            assert not result.is_success
            assert "Bind failed: Invalid credentials" in (result.error or "")

    async def test_unbind_no_connection_real(self) -> None:
        """Test unbind when no connection - real unbind logic."""
        client = FlextLdapClient()

        # Execute real unbind with no connection
        result = await client.unbind()

        # Verify real unbind logic (should succeed when no connection)
        assert result.is_success

    async def test_unbind_success_real(self) -> None:
        """Test successful unbind operation - real unbind execution."""
        client = FlextLdapClient()

        # Mock connection
        mock_connection = MagicMock()
        client._connection = mock_connection
        client._server = MagicMock()

        # Execute real unbind operation
        result = await client.unbind()

        # Verify real unbind execution
        assert result.is_success
        mock_connection.unbind.assert_called_once()
        assert client._connection is None
        assert client._server is None

    async def test_unbind_ldap_exception_real(self) -> None:
        """Test unbind handles LDAP exceptions - real exception handling."""
        client = FlextLdapClient()

        # Mock connection with exception
        mock_connection = MagicMock()
        mock_connection.unbind.side_effect = LDAPException("Unbind failed")
        client._connection = mock_connection

        # Execute real LDAP exception handling
        result = await client.unbind()

        # Verify real exception handling
        assert not result.is_success
        assert "Unbind failed: Unbind failed" in (result.error or "")

    def test_destructor_cleanup_real(self) -> None:
        """Test destructor cleanup logic - real cleanup execution."""
        client = FlextLdapClient()

        # Mock connection that is bound
        mock_connection = MagicMock()
        mock_connection.bound = True
        client._connection = mock_connection

        # Execute real destructor cleanup
        client.__del__()

        # Verify real cleanup was called
        mock_connection.unbind.assert_called_once()

    def test_destructor_handles_exceptions_real(self) -> None:
        """Test destructor handles exceptions silently - real exception handling."""
        client = FlextLdapClient()

        # Mock connection that raises exception
        mock_connection = MagicMock()
        mock_connection.bound = True
        mock_connection.unbind.side_effect = Exception("Cleanup error")
        client._connection = mock_connection

        # Execute real destructor cleanup - should not raise exception
        try:
            client.__del__()
        except Exception as e:
            pytest.fail(
                f"Destructor should handle exceptions silently, but raised: {e}"
            )

    def test_destructor_no_connection_real(self) -> None:
        """Test destructor when no connection - real no-op logic."""
        client = FlextLdapClient()

        # No connection set
        assert client._connection is None

        # Execute real destructor - should not fail
        try:
            client.__del__()
        except Exception as e:
            pytest.fail(
                f"Destructor should handle no connection gracefully, but raised: {e}"
            )


class TestFlextLdapClientIntegrationReal:
    """Test FlextLdapClient integration patterns with real execution."""

    async def test_full_operation_flow_real(self) -> None:
        """Test full client operation flow - real workflow execution."""
        client = FlextLdapClient()

        # Mock all components for full workflow
        with (
            patch("flext_ldap.clients.ldap3.Server") as mock_server_class,
            patch("flext_ldap.clients.ldap3.Connection") as mock_connection_class,
            patch("flext_ldap.clients.FlextLdapUtilities") as mock_utils,
        ):
            # Setup connection mocks
            mock_server = MagicMock()
            mock_server_class.return_value = mock_server

            mock_connection = MagicMock()
            mock_connection.bound = True
            mock_connection_class.return_value = mock_connection

            # Setup operation mocks
            mock_connection.add.return_value = True
            mock_connection.search.return_value = True
            mock_connection.modify.return_value = True
            mock_connection.delete.return_value = True

            mock_utils.safe_ldap3_search_result.return_value = True
            mock_utils.safe_ldap3_entries_list.return_value = []
            mock_utils.safe_ldap3_rebind_result.return_value = True

            # Execute real full workflow

            # 1. Connect
            connect_result = await client.connect(
                "ldap://example.com", "cn=admin", "password"
            )
            assert connect_result.is_success
            assert client.is_connected

            # 2. Add entry
            add_result = await client.add(
                "cn=test,dc=example,dc=com", {"objectClass": ["person"]}
            )
            assert add_result.is_success

            # 3. Search
            search_request = FlextLdapSearchRequest(
                base_dn="dc=example,dc=com",
                scope="subtree",
                filter_str="(cn=test)",
                attributes=None,
                size_limit=10,
                time_limit=30,
            )
            search_result = await client.search(search_request)
            assert search_result.is_success

            # 4. Modify
            modify_result = await client.modify(
                "cn=test,dc=example,dc=com", {"description": "modified"}
            )
            assert modify_result.is_success

            # 5. Bind as different user
            bind_result = await client.bind("cn=test,dc=example,dc=com", "userpass")
            assert bind_result.is_success

            # 6. Delete
            delete_result = await client.delete("cn=test,dc=example,dc=com")
            assert delete_result.is_success

            # 7. Unbind
            unbind_result = await client.unbind()
            assert unbind_result.is_success
            assert not client.is_connected

    async def test_error_consistency_real(self) -> None:
        """Test error message consistency across operations - real error handling."""
        client = FlextLdapClient()

        # Test consistent "not connected" errors
        search_result = await client.search(
            FlextLdapSearchRequest(
                base_dn="dc=test",
                scope="base",
                filter_str="(objectClass=*)",
                attributes=None,
                size_limit=1,
                time_limit=30,
            )
        )
        add_result = await client.add("cn=test,dc=test", {})
        modify_result = await client.modify("cn=test,dc=test", {})
        delete_result = await client.delete("cn=test,dc=test")

        # All should have consistent error messages
        not_connected_msg = "Not connected to LDAP server"
        assert not_connected_msg in (search_result.error or "")
        assert not_connected_msg in (add_result.error or "")
        assert not_connected_msg in (modify_result.error or "")
        assert not_connected_msg in (delete_result.error or "")

    def test_logging_integration_real(self) -> None:
        """Test logging integration - real logging execution."""
        client = FlextLdapClient()

        # Test logging is properly configured
        with patch("flext_ldap.clients.logger") as mock_logger:
            # Mock connection for successful operations
            mock_connection = MagicMock()
            mock_connection.bound = True
            mock_connection.add.return_value = True
            client._connection = mock_connection

            # Execute operation that should log

            asyncio.run(
                client.add("cn=test,dc=example,dc=com", {"objectClass": ["person"]})
            )

            # Verify logging was called
            mock_logger.info.assert_called()
            call_args = mock_logger.info.call_args
            assert "Entry added" in call_args[0][0]
            assert call_args[1]["extra"]["dn"] == "cn=test,dc=example,dc=com"
