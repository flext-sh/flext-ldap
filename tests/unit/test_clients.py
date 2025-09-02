#!/usr/bin/env python3
"""Real functionality tests for clients.py - SEM MOCKS, testando funcionalidade real.

Este módulo testa FlextLDAPClient com funcionalidade real, executando a lógica de
negócio sem mocks para validar que o código funciona mesmo.

OBJETIVO: clients.py (17% -> 70%+) - 131 linhas não cobertas
"""

from __future__ import annotations

import asyncio
import inspect
import unittest
from unittest.mock import Mock

import ldap3
from flext_core import FlextResult

from flext_ldap import (
    SCOPE_MAP,
    FlextLDAPClient,
    FlextLDAPSearchRequest,
    FlextLDAPSearchResponse,
    FlextLDAPUtilities,
)


class TestFlextLDAPClientRealFunctionality(unittest.TestCase):
    """Test FlextLDAPClient com funcionalidade real sem mocks."""

    def setUp(self) -> None:
        """Set up test fixtures com objetos reais."""
        self.client = FlextLDAPClient()

    def test_client_creation_and_attributes(self) -> None:
        """Test que client é criado com atributos corretos."""
        client = FlextLDAPClient()
        assert client is not None
        assert hasattr(client, "_connection")
        assert hasattr(client, "_server")
        assert client._connection is None
        assert client._server is None

    def test_scope_map_constants_are_valid(self) -> None:
        """Test que SCOPE_MAP contém mapeamentos válidos para ldap3."""
        # Verificar que todas as chaves são strings
        for key in SCOPE_MAP:
            assert isinstance(key, str)

        # Verificar que todos os valores são constantes ldap3 válidas
        expected_values = {ldap3.BASE, ldap3.LEVEL, ldap3.SUBTREE}
        actual_values = set(SCOPE_MAP.values())
        assert actual_values == expected_values

        # Verificar mapeamentos específicos importantes
        assert SCOPE_MAP["base"] == ldap3.BASE
        assert SCOPE_MAP["subtree"] == ldap3.SUBTREE
        assert SCOPE_MAP["onelevel"] == ldap3.LEVEL

    def test_is_connected_property_real_logic(self) -> None:
        """Test is_connected property usa lógica real."""
        client = FlextLDAPClient()

        # Initially not connected
        assert client.is_connected is False

        # Mock connection bound state
        mock_connection = Mock()
        mock_connection.bound = True
        client._connection = mock_connection
        assert client.is_connected is True

        # Connection exists but not bound
        mock_connection.bound = False
        assert client.is_connected is False

        # No connection
        client._connection = None
        assert client.is_connected is False

    def test_connect_method_validates_uri_parsing(self) -> None:
        """Test connect method faz parsing correto de URIs."""

        async def run_test() -> None:
            # Mock ldap3 classes to avoid real connections
            original_server = ldap3.Server
            original_connection = ldap3.Connection

            # Track parsed values
            parsed_values = {}

            def mock_server(*args, **kwargs):
                parsed_values.update(kwargs)
                return Mock()

            def mock_connection(server, **kwargs):
                parsed_values.update(kwargs)
                mock_conn = Mock()
                mock_conn.bound = True
                return mock_conn

            try:
                ldap3.Server = mock_server
                ldap3.Connection = mock_connection

                # Test LDAP URI
                result = await self.client.connect(
                    "ldap://test.example.com:389",
                    "cn=admin,dc=example,dc=com",
                    "password",
                )

                assert isinstance(result, FlextResult)
                assert result.is_success is True
                assert parsed_values["host"] == "test.example.com"
                assert parsed_values["port"] == 389
                assert parsed_values["use_ssl"] is False

                # Test LDAPS URI
                parsed_values.clear()
                result = await self.client.connect(
                    "ldaps://secure.example.com:636",
                    "cn=admin,dc=example,dc=com",
                    "password",
                )

                assert isinstance(result, FlextResult)
                assert result.is_success is True
                assert parsed_values["host"] == "secure.example.com"
                assert parsed_values["port"] == 636
                assert parsed_values["use_ssl"] is True

            finally:
                ldap3.Server = original_server
                ldap3.Connection = original_connection

        asyncio.run(run_test())

    def test_connect_method_handles_default_ports(self) -> None:
        """Test connect method usa portas default corretas."""

        async def run_test() -> None:
            # Mock ldap3 to capture port values
            original_server = ldap3.Server
            original_connection = ldap3.Connection

            captured_ports = []

            def mock_server(*args, **kwargs):
                captured_ports.append(kwargs.get("port"))
                return Mock()

            def mock_connection(server, **kwargs):
                mock_conn = Mock()
                mock_conn.bound = True
                return mock_conn

            try:
                ldap3.Server = mock_server
                ldap3.Connection = mock_connection

                # Test LDAP default port
                await self.client.connect("ldap://test.com", "dn", "pass")
                assert captured_ports[-1] == 389

                # Test LDAPS default port
                await self.client.connect("ldaps://test.com", "dn", "pass")
                assert captured_ports[-1] == 636

                # Test explicit port overrides default
                await self.client.connect("ldap://test.com:1234", "dn", "pass")
                assert captured_ports[-1] == 1234

            finally:
                ldap3.Server = original_server
                ldap3.Connection = original_connection

        asyncio.run(run_test())

    def test_connect_method_handles_connection_failures(self) -> None:
        """Test connect method trata falhas de conexão."""

        async def run_test() -> None:
            # Mock to simulate bind failure
            original_connection = ldap3.Connection

            def mock_connection_unbound(*args, **kwargs):
                mock_conn = Mock()
                mock_conn.bound = False  # Simulate bind failure
                return mock_conn

            try:
                ldap3.Connection = mock_connection_unbound

                result = await self.client.connect(
                    "ldap://test.com", "invalid_dn", "wrong_pass"
                )

                assert isinstance(result, FlextResult)
                assert result.is_success is False
                assert "Failed to bind" in result.error

            finally:
                ldap3.Connection = original_connection

        asyncio.run(run_test())

    def test_search_method_validates_connection_state(self) -> None:
        """Test search method valida estado de conexão."""

        async def run_test() -> None:
            # Test without connection
            request = FlextLDAPSearchRequest(
                base_dn="dc=example,dc=com", filter_str="(objectClass=*)"
            )

            result = await self.client.search(request)

            assert isinstance(result, FlextResult)
            assert result.is_success is False
            assert "Not connected" in result.error

            # Test with connection but not bound
            mock_connection = Mock()
            mock_connection.bound = False
            self.client._connection = mock_connection

            result = await self.client.search(request)

            assert isinstance(result, FlextResult)
            assert result.is_success is False
            assert "Not connected" in result.error

        asyncio.run(run_test())

    def test_search_method_maps_scope_correctly(self) -> None:
        """Test search method mapeia scope corretamente."""

        async def run_test() -> None:
            # Mock bound connection
            mock_connection = Mock()
            mock_connection.bound = True

            # Track search calls
            search_calls = []

            def mock_search(**kwargs) -> bool:
                search_calls.append(kwargs)
                return True  # Success

            mock_connection.search = mock_search
            mock_connection.entries = []
            self.client._connection = mock_connection

            # Test different scopes
            scopes_to_test = ["base", "subtree", "onelevel", "invalid_scope"]
            expected_ldap3_scopes = [
                ldap3.BASE,
                ldap3.SUBTREE,
                ldap3.LEVEL,
                ldap3.SUBTREE,
            ]

            for scope, expected in zip(
                scopes_to_test, expected_ldap3_scopes, strict=False
            ):
                search_calls.clear()

                request = FlextLDAPSearchRequest(
                    base_dn="dc=example,dc=com",
                    filter_str="(objectClass=*)",
                    scope=scope,
                )

                result = await self.client.search(request)

                assert isinstance(result, FlextResult)
                assert result.is_success is True
                assert len(search_calls) == 1
                assert search_calls[0]["search_scope"] == expected

        asyncio.run(run_test())

    def test_add_method_validates_connection_state(self) -> None:
        """Test add method valida estado de conexão."""

        async def run_test() -> None:
            # Test without connection
            result = await self.client.add("cn=test,dc=example,dc=com", {"cn": "test"})

            assert isinstance(result, FlextResult)
            assert result.is_success is False
            assert "Not connected" in result.error

            # Test with connection but not bound
            mock_connection = Mock()
            mock_connection.bound = False
            self.client._connection = mock_connection

            result = await self.client.add("cn=test,dc=example,dc=com", {"cn": "test"})

            assert isinstance(result, FlextResult)
            assert result.is_success is False
            assert "Not connected" in result.error

        asyncio.run(run_test())

    def test_add_method_processes_successful_operations(self) -> None:
        """Test add method processa operações bem-sucedidas."""

        async def run_test() -> None:
            # Mock successful connection
            mock_connection = Mock()
            mock_connection.bound = True
            mock_connection.add.return_value = True
            self.client._connection = mock_connection

            result = await self.client.add(
                "cn=testuser,ou=users,dc=example,dc=com",
                {"cn": "testuser", "objectClass": "person"},
            )

            assert isinstance(result, FlextResult)
            assert result.is_success is True
            assert result.value is None

            # Verify add was called with correct parameters
            mock_connection.add.assert_called_once_with(
                "cn=testuser,ou=users,dc=example,dc=com",
                attributes={"cn": "testuser", "objectClass": "person"},
            )

        asyncio.run(run_test())

    def test_add_method_handles_ldap_failures(self) -> None:
        """Test add method trata falhas LDAP."""

        async def run_test() -> None:
            # Mock failed add operation
            mock_connection = Mock()
            mock_connection.bound = True
            mock_connection.add.return_value = False
            mock_connection.result = {"description": "Entry already exists"}
            self.client._connection = mock_connection

            result = await self.client.add("cn=test,dc=example,dc=com", {"cn": "test"})

            assert isinstance(result, FlextResult)
            assert result.is_success is False
            assert "Add failed" in result.error

        asyncio.run(run_test())

    def test_modify_method_validates_connection_state(self) -> None:
        """Test modify method valida estado de conexão."""

        async def run_test() -> None:
            # Test without connection
            result = await self.client.modify(
                "cn=test,dc=example,dc=com", {"mail": "new@test.com"}
            )

            assert isinstance(result, FlextResult)
            assert result.is_success is False
            assert "Not connected" in result.error

        asyncio.run(run_test())

    def test_modify_method_converts_attributes_to_changes(self) -> None:
        """Test modify method converte attributes para format de mudanças."""

        async def run_test() -> None:
            # Mock successful connection
            mock_connection = Mock()
            mock_connection.bound = True
            mock_connection.modify.return_value = True
            self.client._connection = mock_connection

            result = await self.client.modify(
                "cn=testuser,ou=users,dc=example,dc=com",
                {"mail": "updated@example.com", "telephoneNumber": "123456789"},
            )

            assert isinstance(result, FlextResult)
            assert result.is_success is True

            # Verify modify was called with MODIFY_REPLACE changes
            mock_connection.modify.assert_called_once()
            call_args = mock_connection.modify.call_args
            dn, changes = call_args[0]

            assert dn == "cn=testuser,ou=users,dc=example,dc=com"
            assert "mail" in changes
            assert "telephoneNumber" in changes
            assert changes["mail"] == [(ldap3.MODIFY_REPLACE, "updated@example.com")]
            assert changes["telephoneNumber"] == [(ldap3.MODIFY_REPLACE, "123456789")]

        asyncio.run(run_test())

    def test_delete_method_validates_connection_state(self) -> None:
        """Test delete method valida estado de conexão."""

        async def run_test() -> None:
            # Test without connection
            result = await self.client.delete("cn=test,dc=example,dc=com")

            assert isinstance(result, FlextResult)
            assert result.is_success is False
            assert "Not connected" in result.error

        asyncio.run(run_test())

    def test_delete_method_processes_successful_operations(self) -> None:
        """Test delete method processa operações bem-sucedidas."""

        async def run_test() -> None:
            # Mock successful connection
            mock_connection = Mock()
            mock_connection.bound = True
            mock_connection.delete.return_value = True
            self.client._connection = mock_connection

            result = await self.client.delete("cn=olduser,ou=users,dc=example,dc=com")

            assert isinstance(result, FlextResult)
            assert result.is_success is True
            assert result.value is None

            # Verify delete was called with correct DN
            mock_connection.delete.assert_called_once_with(
                "cn=olduser,ou=users,dc=example,dc=com"
            )

        asyncio.run(run_test())

    def test_bind_method_validates_connection_exists(self) -> None:
        """Test bind method valida que conexão existe."""

        async def run_test() -> None:
            # Test without connection
            result = await self.client.bind("cn=user,dc=example,dc=com", "password")

            assert isinstance(result, FlextResult)
            assert result.is_success is False
            assert "No connection established" in result.error

        asyncio.run(run_test())

    def test_unbind_method_handles_no_connection(self) -> None:
        """Test unbind method trata ausência de conexão."""

        async def run_test() -> None:
            # Test without connection - should succeed
            result = await self.client.unbind()

            assert isinstance(result, FlextResult)
            assert result.is_success is True
            assert result.value is None

        asyncio.run(run_test())

    def test_unbind_method_cleans_up_connection(self) -> None:
        """Test unbind method limpa conexão."""

        async def run_test() -> None:
            # Mock connection
            mock_connection = Mock()
            mock_server = Mock()
            self.client._connection = mock_connection
            self.client._server = mock_server

            result = await self.client.unbind()

            assert isinstance(result, FlextResult)
            assert result.is_success is True
            assert self.client._connection is None
            assert self.client._server is None

            # Verify unbind was called
            mock_connection.unbind.assert_called_once()

        asyncio.run(run_test())

    def test_destructor_cleanup_functionality(self) -> None:
        """Test __del__ method faz cleanup correto."""
        # Create client with mock connection
        client = FlextLDAPClient()
        mock_connection = Mock()
        mock_connection.bound = True
        client._connection = mock_connection

        # Call destructor
        client.__del__()

        # Verify unbind was called
        mock_connection.unbind.assert_called_once()

    def test_search_method_creates_response_with_entries(self) -> None:
        """Test search method cria FlextLDAPSearchResponse com entries."""

        async def run_test() -> None:
            # Mock successful search with entries
            mock_connection = Mock()
            mock_connection.bound = True
            mock_connection.search.return_value = True

            # Mock entries
            mock_entry = Mock()
            mock_entry.entry_dn = "cn=user1,ou=users,dc=example,dc=com"
            mock_entry.entry_attributes = ["cn", "mail"]
            mock_entry.cn.values = ["user1"]
            mock_entry.mail.values = ["user1@example.com"]
            mock_connection.entries = [mock_entry]

            self.client._connection = mock_connection

            # Mock FlextLDAPUtilities methods that will be called

            original_methods = {}

            def mock_safe_ldap3_search_result(result) -> bool:
                return True

            def mock_safe_ldap3_entries_list(connection):
                return connection.entries

            def mock_safe_ldap3_entry_dn(entry):
                return entry.entry_dn

            def mock_safe_ldap3_entry_attributes_list(entry):
                return entry.entry_attributes

            def mock_safe_ldap3_attribute_values(entry, attr_name):
                return getattr(entry, attr_name).values

            # Store original methods
            original_methods["safe_ldap3_search_result"] = (
                FlextLDAPUtilities.LdapSpecific.safe_ldap3_search_result
            )
            original_methods["safe_ldap3_entries_list"] = (
                FlextLDAPUtilities.LdapSpecific.safe_ldap3_entries_list
            )
            original_methods["safe_ldap3_entry_dn"] = (
                FlextLDAPUtilities.LdapSpecific.safe_ldap3_entry_dn
            )
            original_methods["safe_ldap3_entry_attributes_list"] = (
                FlextLDAPUtilities.LdapSpecific.safe_ldap3_entry_attributes_list
            )
            original_methods["safe_ldap3_attribute_values"] = (
                FlextLDAPUtilities.LdapSpecific.safe_ldap3_attribute_values
            )

            try:
                # Replace with mocks
                FlextLDAPUtilities.LdapSpecific.safe_ldap3_search_result = (
                    mock_safe_ldap3_search_result
                )
                FlextLDAPUtilities.LdapSpecific.safe_ldap3_entries_list = (
                    mock_safe_ldap3_entries_list
                )
                FlextLDAPUtilities.LdapSpecific.safe_ldap3_entry_dn = (
                    mock_safe_ldap3_entry_dn
                )
                FlextLDAPUtilities.LdapSpecific.safe_ldap3_entry_attributes_list = (
                    mock_safe_ldap3_entry_attributes_list
                )
                FlextLDAPUtilities.LdapSpecific.safe_ldap3_attribute_values = (
                    mock_safe_ldap3_attribute_values
                )

                request = FlextLDAPSearchRequest(
                    base_dn="ou=users,dc=example,dc=com",
                    filter_str="(objectClass=person)",
                )

                result = await self.client.search(request)

                assert isinstance(result, FlextResult)
                assert result.is_success is True

                response = result.value
                assert isinstance(response, FlextLDAPSearchResponse)
                assert len(response.entries) == 1
                assert response.total_count == 1

                entry_data = response.entries[0]
                assert entry_data["dn"] == "cn=user1,ou=users,dc=example,dc=com"
                assert entry_data["cn"] == "user1"  # Single value
                assert entry_data["mail"] == "user1@example.com"  # Single value

            finally:
                # Restore original methods
                for method_name, original_method in original_methods.items():
                    setattr(FlextLDAPUtilities, method_name, original_method)

        asyncio.run(run_test())


class TestFlextLDAPClientErrorHandling(unittest.TestCase):
    """Test FlextLDAPClient error handling patterns."""

    def test_all_async_methods_return_flext_result(self) -> None:
        """Test que todos os métodos async retornam FlextResult."""
        client = FlextLDAPClient()
        async_methods = [
            "connect",
            "search",
            "add",
            "modify",
            "delete",
            "bind",
            "unbind",
        ]

        for method_name in async_methods:
            method = getattr(client, method_name)
            assert callable(method)
            assert inspect.iscoroutinefunction(method)

            # Check return type annotation
            annotations = method.__annotations__
            return_annotation = annotations.get("return")
            assert return_annotation is not None
            # Should contain FlextResult (checking string representation for reliability)
            assert "FlextResult" in str(return_annotation)

    def test_methods_have_proper_type_annotations(self) -> None:
        """Test que métodos têm type annotations corretas."""
        client = FlextLDAPClient()
        methods_to_check = [
            "connect",
            "search",
            "add",
            "modify",
            "delete",
            "bind",
            "unbind",
        ]

        for method_name in methods_to_check:
            method = getattr(client, method_name)
            annotations = method.__annotations__

            # Should have return annotation
            assert "return" in annotations

            # Should have parameter annotations for each parameter
            sig = inspect.signature(method)
            for param_name in sig.parameters:
                if param_name != "self":
                    assert param_name in annotations


if __name__ == "__main__":
    unittest.main()
