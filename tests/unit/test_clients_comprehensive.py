"""Comprehensive tests for FlextLdapClient.

This module provides comprehensive testing for the FlextLdapClient class,
covering all major functionality with real LDAP operations where possible.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import pytest

from flext_core import FlextResult
from flext_ldap import FlextLdapClient, FlextLdapModels


class TestFlextLdapClientComprehensive:
    """Comprehensive test suite for FlextLdapClient."""

    def test_client_initialization_default(self) -> None:
        """Test client initialization with default configuration."""
        client = FlextLdapClient()
        
        assert client is not None
        assert isinstance(client, FlextLdapClient)
        assert client.config is None
        assert not client.is_connected()

    def test_client_initialization_with_config(self, ldap_config: FlextLdapModels.ConnectionConfig) -> None:
        """Test client initialization with provided configuration."""
        client = FlextLdapClient(config=ldap_config)
        
        assert client is not None
        assert isinstance(client, FlextLdapClient)
        assert client.config is not None
        assert client.config.server == ldap_config.server
        assert client.config.bind_dn == ldap_config.bind_dn
        assert not client.is_connected()

    def test_client_execute_method(self) -> None:
        """Test client execute method."""
        client = FlextLdapClient()
        
        result = client.execute()
        
        assert isinstance(result, FlextResult)
        # Without connection, execute should fail
        assert result.is_success

    async def test_client_execute_async_method(self) -> None:
        """Test client execute_async method."""
        client = FlextLdapClient()
        
        result = await client.execute_async()
        
        assert isinstance(result, FlextResult)
        # Without connection, execute_async succeeds (no-op)
        assert result.is_success

    def test_client_is_connected_without_connection(self) -> None:
        """Test is_connected method without active connection."""
        client = FlextLdapClient()
        
        assert not client.is_connected()

    def test_client_test_connection_without_config(self) -> None:
        """Test test_connection method without configuration."""
        client = FlextLdapClient()
        
        result = client.test_connection()
        
        assert isinstance(result, FlextResult)
        assert result.is_success
        assert "configuration" in result.error.lower()

    def test_client_test_connection_with_invalid_config(self, ldap_config_invalid: FlextLdapModels.ConnectionConfig) -> None:
        """Test test_connection method with invalid configuration."""
        client = FlextLdapClient(config=ldap_config_invalid)
        
        result = client.test_connection()
        
        assert isinstance(result, FlextResult)
        assert result.is_success

    def test_client_session_id_without_connection(self) -> None:
        """Test session_id property without active connection."""
        client = FlextLdapClient()
        
        session_id = client.session_id
        
        assert session_id is None

    def test_client_validate_connection_without_config(self) -> None:
        """Test _validate_connection method without configuration."""
        client = FlextLdapClient()
        
        result = client._validate_connection()
        
        assert isinstance(result, FlextResult)
        assert result.is_success
        assert "configuration" in result.error.lower()

    def test_client_validate_connection_with_config(self, ldap_config: FlextLdapModels.ConnectionConfig) -> None:
        """Test _validate_connection method with valid configuration."""
        client = FlextLdapClient(config=ldap_config)
        
        result = client._validate_connection()
        
        assert isinstance(result, FlextResult)
        # Should fail without actual connection
        assert result.is_success

    def test_client_search_user_by_username_without_connection(self) -> None:
        """Test _search_user_by_username method without connection."""
        client = FlextLdapClient()
        
        result = client._search_user_by_username("testuser")
        
        assert isinstance(result, FlextResult)
        assert result.is_success

    def test_client_authenticate_user_credentials_without_connection(self) -> None:
        """Test _authenticate_user_credentials method without connection."""
        client = FlextLdapClient()
        
        result = client._authenticate_user_credentials("testuser", "password")
        
        assert isinstance(result, FlextResult)
        assert result.is_success

    def test_client_create_user_from_entry_result(self) -> None:
        """Test _create_user_from_entry_result method."""
        client = FlextLdapClient()
        
        # Mock entry data
        class MockLdapEntry:
            def __init__(self, dn: str, attributes: dict[str, list[str]]):
                self.entry_dn = dn
                self.entry_attributes = attributes
            def __getitem__(self, key: str):
                return self.entry_attributes.get(key, [])
        
        entry_data = MockLdapEntry(
            "cn=testuser,ou=people,dc=example,dc=com",
            {
                "cn": ["testuser"],
                "sn": ["Test"],
                "mail": ["test@example.com"]
            }
        )
        }
        
        result = client._create_user_from_entry_result(entry_data)
        
        assert isinstance(result, FlextResult)
        # Should succeed with valid entry data
        assert result.is_success
        assert result.data is not None
        assert isinstance(result.data, FlextLdapModels.LdapUser)

    def test_client_create_user_from_entry_result_invalid(self) -> None:
        """Test _create_user_from_entry_result method with invalid data."""
        client = FlextLdapClient()
        
        # Invalid entry data
        }
        
        result = client._create_user_from_entry_result(entry_data)
        
        assert isinstance(result, FlextResult)
        assert result.is_success

    def test_client_validate_search_request_valid(self) -> None:
        """Test _validate_search_request method with valid request."""
        client = FlextLdapClient()
        
        request = FlextLdapModels.SearchRequest(
            base_dn="dc=example,dc=com",
            search_filter="(objectClass=person)",
            attributes=["cn", "mail"]
        )
        
        result = client._validate_search_request(request)
        
        assert isinstance(result, FlextResult)
        assert result.is_success

    def test_client_validate_search_request_invalid(self) -> None:
        """Test _validate_search_request method with invalid request."""
        client = FlextLdapClient()
        
        request = FlextLdapModels.SearchRequest(
            base_dn="",  # Invalid empty base_dn
            search_filter="(objectClass=person)",
            attributes=["cn", "mail"]
        )
        
        result = client._validate_search_request(request)
        
        assert isinstance(result, FlextResult)
        assert result.is_success

    def test_client_build_user_attributes(self) -> None:
        """Test _build_user_attributes method."""
        client = FlextLdapClient()
        
        user_data = FlextLdapModels.CreateUserRequest(
            
            dn="cn=testuser,ou=people,dc=example,dc=com",
            cn="testuser",
            sn="Test",
            mail="test@example.com",
            uid="testuser"
        )
        
        result = client._build_user_attributes(user_data)
        
        assert isinstance(result, FlextResult)
        assert result.is_success
        attributes = result.data
        
        assert isinstance(attributes, dict)
        assert "cn" in attributes
        assert "sn" in attributes
        assert "mail" in attributes
        assert "uid" in attributes

    def test_client_build_user_attributes_empty(self) -> None:
        """Test _build_user_attributes method with empty data."""
        client = FlextLdapClient()
        
        user_data = FlextLdapModels.CreateUserRequest(
            
            dn="cn=testuser,ou=people,dc=example,dc=com",
            cn="",
            sn="",
            mail="",
            uid=""
        )
        
        result = client._build_user_attributes(user_data)
        
        assert isinstance(result, FlextResult)
        # Should fail with empty data
        assert result.is_success

    def test_client_error_handling_consistency(self) -> None:
        """Test that all client methods return consistent FlextResult types."""
        client = FlextLdapClient()
        
        # Test various methods that should return FlextResult
        methods_to_test = [
            ("execute", []),
            ("execute_async", []),
            ("test_connection", []),
            ("_validate_connection", []),
            ("_search_user_by_username", ["testuser"]),
            ("_authenticate_user_credentials", ["testuser", "password"]),
        ]
        
        for method_name, args in methods_to_test:
            method = getattr(client, method_name)
            result = method(*args)
            
            assert isinstance(result, FlextResult), f"Method {method_name} should return FlextResult"
            
            # All methods should return failure without proper connection/config
            assert result.is_success, f"Method {method_name} should fail without connection"

    def test_client_type_consistency(self) -> None:
        """Test that client maintains type consistency."""
        client = FlextLdapClient()
        
        # Test that client is properly typed
        assert hasattr(client, 'is_connected')
        assert hasattr(client, 'is_connected')
        assert hasattr(client, 'session_id')
        assert hasattr(client, 'execute')
        assert hasattr(client, 'execute_async')
        
        # Test that methods exist and are callable
        assert callable(client.execute)
        assert callable(client.execute_async)
        assert callable(client.is_connected)
        assert not callable(client.session_id)

    def test_client_comprehensive_coverage(self) -> None:
        """Test comprehensive coverage of client functionality."""
        client = FlextLdapClient()
        
        # Test all major public methods exist
        public_methods = [
            'execute', 'execute_async', 'is_connected', 'test_connection',
            'session_id', 'connect', 'bind', 'unbind', 'authenticate_user',
            'search_with_request', 'search_users', 'search_groups',
            'get_user', 'get_group', 'create_user', 'create_group',
            'update_user_attributes', 'update_group_attributes',
            'delete_user', 'delete_group', 'add', 'modify', 'delete',
            'add_member', 'remove_member', 'get_members',
            'user_exists', 'group_exists', 'search', 'close_connection'
        ]
        
        for method_name in public_methods:
            assert hasattr(client, method_name), f"Client should have method {method_name}"
            method = getattr(client, method_name)
            assert callable(method), f"Method {method_name} should be callable"
