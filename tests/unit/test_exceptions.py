"""Comprehensive tests for FlextLdapExceptions.

This module provides complete test coverage for the FlextLdapExceptions class
following FLEXT standards with proper domain separation and centralized fixtures.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from flext_ldap import FlextLdapExceptions


class TestFlextLdapExceptions:
    """Comprehensive test suite for FlextLdapExceptions."""

    def test_exceptions_initialization(self) -> None:
        """Test exceptions initialization."""
        exceptions = FlextLdapExceptions()
        assert exceptions is not None
        assert hasattr(exceptions, "_container")
        assert hasattr(exceptions, "_logger")

    def test_connection_error_creation(self) -> None:
        """Test connection error creation."""
        exceptions = FlextLdapExceptions()

        error = exceptions.connection_error("Connection failed", "ldap://localhost:389")

        assert isinstance(error, Exception)
        assert "Connection failed" in str(error)
        assert "ldap://localhost:389" in str(error)

    def test_connection_error_with_ldap_code(self) -> None:
        """Test connection error with LDAP result code."""
        exceptions = FlextLdapExceptions()

        error = exceptions.connection_error(
            "Connection failed", "ldap://localhost:389", ldap_code=49
        )

        assert isinstance(error, Exception)
        assert "Connection failed" in str(error)
        assert "ldap://localhost:389" in str(error)
        assert "49" in str(error)

    def test_authentication_error_creation(self) -> None:
        """Test authentication error creation."""
        exceptions = FlextLdapExceptions()

        error = exceptions.authentication_error(
            "Invalid credentials", "cn=admin,dc=example,dc=com"
        )

        assert isinstance(error, Exception)
        assert "Invalid credentials" in str(error)
        assert "cn=admin,dc=example,dc=com" in str(error)

    def test_authentication_error_branches(self) -> None:
        """Test authentication error with different branches."""
        exceptions = FlextLdapExceptions()

        # Test with username
        error1 = exceptions.authentication_error("Invalid credentials", "testuser")
        assert isinstance(error1, Exception)
        assert "testuser" in str(error1)

        # Test with DN
        error2 = exceptions.authentication_error(
            "Invalid credentials", "cn=admin,dc=example,dc=com"
        )
        assert isinstance(error2, Exception)
        assert "cn=admin,dc=example,dc=com" in str(error2)

    def test_search_error_creation(self) -> None:
        """Test search error creation."""
        exceptions = FlextLdapExceptions()

        error = exceptions.search_error(
            "Search failed", "(objectClass=person)", "dc=example,dc=com"
        )

        assert isinstance(error, Exception)
        assert "Search failed" in str(error)
        assert "(objectClass=person)" in str(error)
        assert "dc=example,dc=com" in str(error)

    def test_search_error_with_context(self) -> None:
        """Test search error with additional context."""
        exceptions = FlextLdapExceptions()

        error = exceptions.search_error(
            "Search failed",
            "(objectClass=person)",
            "dc=example,dc=com",
            context="Large result set",
        )

        assert isinstance(error, Exception)
        assert "Search failed" in str(error)
        assert "Large result set" in str(error)

    def test_operation_error_creation(self) -> None:
        """Test operation error creation."""
        exceptions = FlextLdapExceptions()

        error = exceptions.operation_error(
            "Add failed", "uid=testuser,ou=people,dc=example,dc=com"
        )

        assert isinstance(error, Exception)
        assert "Add failed" in str(error)
        assert "uid=testuser,ou=people,dc=example,dc=com" in str(error)

    def test_operation_error_with_target(self) -> None:
        """Test operation error with target information."""
        exceptions = FlextLdapExceptions()

        error = exceptions.operation_error(
            "Modify failed",
            "uid=testuser,ou=people,dc=example,dc=com",
            target="cn attribute",
        )

        assert isinstance(error, Exception)
        assert "Modify failed" in str(error)
        assert "cn attribute" in str(error)

    def test_validation_error_creation(self) -> None:
        """Test validation error creation."""
        exceptions = FlextLdapExceptions()

        error = exceptions.validation_error("Invalid DN format", "invalid-dn")

        assert isinstance(error, Exception)
        assert "Invalid DN format" in str(error)
        assert "invalid-dn" in str(error)

    def test_validation_error_with_field_details(self) -> None:
        """Test validation error with field details."""
        exceptions = FlextLdapExceptions()

        error = exceptions.validation_error(
            "Invalid email format", "test@invalid", field="mail"
        )

        assert isinstance(error, Exception)
        assert "Invalid email format" in str(error)
        assert "test@invalid" in str(error)
        assert "mail" in str(error)

    def test_configuration_error_creation(self) -> None:
        """Test configuration error creation."""
        exceptions = FlextLdapExceptions()

        error = exceptions.configuration_error(
            "Invalid server URI", "ldap://invalid-server"
        )

        assert isinstance(error, Exception)
        assert "Invalid server URI" in str(error)
        assert "ldap://invalid-server" in str(error)

    def test_configuration_error_with_section(self) -> None:
        """Test configuration error with section information."""
        exceptions = FlextLdapExceptions()

        error = exceptions.configuration_error(
            "Missing required field", "bind_dn", section="connection"
        )

        assert isinstance(error, Exception)
        assert "Missing required field" in str(error)
        assert "bind_dn" in str(error)
        assert "connection" in str(error)

    def test_type_error_creation(self) -> None:
        """Test type error creation."""
        exceptions = FlextLdapExceptions()

        error = exceptions.type_error(
            "Invalid attribute type", "cn", expected_type="string"
        )

        assert isinstance(error, Exception)
        assert "Invalid attribute type" in str(error)
        assert "cn" in str(error)
        assert "string" in str(error)

    def test_type_error_with_type_info(self) -> None:
        """Test type error with type information."""
        exceptions = FlextLdapExceptions()

        error = exceptions.type_error(
            "Invalid attribute type", "cn", expected_type="string", actual_type="int"
        )

        assert isinstance(error, Exception)
        assert "Invalid attribute type" in str(error)
        assert "string" in str(error)
        assert "int" in str(error)

    def test_ldap_error_creation(self) -> None:
        """Test LDAP error creation."""
        exceptions = FlextLdapExceptions()

        error = exceptions.ldap_error("LDAP operation failed", "search", ldap_code=32)

        assert isinstance(error, Exception)
        assert "LDAP operation failed" in str(error)
        assert "search" in str(error)
        assert "32" in str(error)

    def test_ldap_error_with_operation_and_code(self) -> None:
        """Test LDAP error with operation and code."""
        exceptions = FlextLdapExceptions()

        error = exceptions.ldap_error("LDAP operation failed", "add", ldap_code=68)

        assert isinstance(error, Exception)
        assert "LDAP operation failed" in str(error)
        assert "add" in str(error)
        assert "68" in str(error)

    def test_user_error_creation(self) -> None:
        """Test user error creation."""
        exceptions = FlextLdapExceptions()

        error = exceptions.user_error("User not found", "testuser")

        assert isinstance(error, Exception)
        assert "User not found" in str(error)
        assert "testuser" in str(error)

    def test_user_error_with_all_fields(self) -> None:
        """Test user error with all fields."""
        exceptions = FlextLdapExceptions()

        error = exceptions.user_error(
            "User creation failed",
            "testuser",
            operation="create",
            reason="Duplicate UID",
        )

        assert isinstance(error, Exception)
        assert "User creation failed" in str(error)
        assert "testuser" in str(error)
        assert "create" in str(error)
        assert "Duplicate UID" in str(error)

    def test_group_error_creation(self) -> None:
        """Test group error creation."""
        exceptions = FlextLdapExceptions()

        error = exceptions.group_error("Group not found", "testgroup")

        assert isinstance(error, Exception)
        assert "Group not found" in str(error)
        assert "testgroup" in str(error)

    def test_group_error_with_operation(self) -> None:
        """Test group error with operation."""
        exceptions = FlextLdapExceptions()

        error = exceptions.group_error(
            "Group creation failed", "testgroup", operation="create"
        )

        assert isinstance(error, Exception)
        assert "Group creation failed" in str(error)
        assert "testgroup" in str(error)
        assert "create" in str(error)

    def test_factory_methods_connection_failed_with_different_params(self) -> None:
        """Test connection failed factory method with different parameters."""
        exceptions = FlextLdapExceptions()

        # Test with minimal parameters
        error1 = exceptions.connection_failed("Connection timeout")
        assert isinstance(error1, Exception)
        assert "Connection timeout" in str(error1)

        # Test with server URI
        error2 = exceptions.connection_failed(
            "Connection timeout", server_uri="ldap://localhost:389"
        )
        assert isinstance(error2, Exception)
        assert "ldap://localhost:389" in str(error2)

        # Test with LDAP code
        error3 = exceptions.connection_failed("Connection timeout", ldap_code=81)
        assert isinstance(error3, Exception)
        assert "81" in str(error3)

    def test_factory_methods_with_ldap_result_codes(self) -> None:
        """Test factory methods with LDAP result codes."""
        exceptions = FlextLdapExceptions()

        # Test various LDAP result codes
        ldap_codes = [32, 49, 68, 81, 82]

        for code in ldap_codes:
            error = exceptions.ldap_error(
                "LDAP operation failed", "test", ldap_code=code
            )
            assert isinstance(error, Exception)
            assert str(code) in str(error)

    def test_exception_inheritance(self) -> None:
        """Test that all exceptions inherit from base exception."""
        exceptions = FlextLdapExceptions()

        # Test that all created exceptions are instances of Exception
        error_types = [
            exceptions.connection_error("test", "test"),
            exceptions.authentication_error("test", "test"),
            exceptions.search_error("test", "test", "test"),
            exceptions.operation_error("test", "test"),
            exceptions.validation_error("test", "test"),
            exceptions.configuration_error("test", "test"),
            exceptions.type_error("test", "test", "str"),
            exceptions.ldap_error("test", "test"),
            exceptions.user_error("test", "test"),
            exceptions.group_error("test", "test"),
        ]

        for error in error_types:
            assert isinstance(error, Exception)

    def test_exception_string_representations(self) -> None:
        """Test exception string representations."""
        exceptions = FlextLdapExceptions()

        # Test that all exceptions have meaningful string representations
        error = exceptions.connection_error("Connection failed", "ldap://localhost:389")
        error_str = str(error)

        assert isinstance(error_str, str)
        assert len(error_str) > 0
        assert "Connection failed" in error_str
        assert "ldap://localhost:389" in error_str

    def test_exception_error_messages(self) -> None:
        """Test exception error messages."""
        exceptions = FlextLdapExceptions()

        # Test that error messages are informative
        error = exceptions.validation_error(
            "Invalid DN format", "invalid-dn", field="dn"
        )
        error_str = str(error)

        assert "Invalid DN format" in error_str
        assert "invalid-dn" in error_str
        assert "dn" in error_str

    def test_exception_context_information(self) -> None:
        """Test exception context information."""
        exceptions = FlextLdapExceptions()

        # Test that exceptions include relevant context
        error = exceptions.search_error(
            "Search failed",
            "(objectClass=person)",
            "dc=example,dc=com",
            context="Large result set",
        )
        error_str = str(error)

        assert "Search failed" in error_str
        assert "(objectClass=person)" in error_str
        assert "dc=example,dc=com" in error_str
        assert "Large result set" in error_str

    def test_exception_ldap_code_information(self) -> None:
        """Test exception LDAP code information."""
        exceptions = FlextLdapExceptions()

        # Test that LDAP codes are included when provided
        error = exceptions.ldap_error("LDAP operation failed", "search", ldap_code=32)
        error_str = str(error)

        assert "LDAP operation failed" in error_str
        assert "search" in error_str
        assert "32" in error_str

    def test_exception_operation_information(self) -> None:
        """Test exception operation information."""
        exceptions = FlextLdapExceptions()

        # Test that operation information is included
        error = exceptions.operation_error(
            "Modify failed",
            "uid=testuser,ou=people,dc=example,dc=com",
            target="cn attribute",
        )
        error_str = str(error)

        assert "Modify failed" in error_str
        assert "uid=testuser,ou=people,dc=example,dc=com" in error_str
        assert "cn attribute" in error_str

    def test_exception_field_information(self) -> None:
        """Test exception field information."""
        exceptions = FlextLdapExceptions()

        # Test that field information is included
        error = exceptions.validation_error(
            "Invalid email format", "test@invalid", field="mail"
        )
        error_str = str(error)

        assert "Invalid email format" in error_str
        assert "test@invalid" in error_str
        assert "mail" in error_str

    def test_exception_section_information(self) -> None:
        """Test exception section information."""
        exceptions = FlextLdapExceptions()

        # Test that section information is included
        error = exceptions.configuration_error(
            "Missing required field", "bind_dn", section="connection"
        )
        error_str = str(error)

        assert "Missing required field" in error_str
        assert "bind_dn" in error_str
        assert "connection" in error_str

    def test_exception_type_information(self) -> None:
        """Test exception type information."""
        exceptions = FlextLdapExceptions()

        # Test that type information is included
        error = exceptions.type_error(
            "Invalid attribute type", "cn", expected_type="string", actual_type="int"
        )
        error_str = str(error)

        assert "Invalid attribute type" in error_str
        assert "cn" in error_str
        assert "string" in error_str
        assert "int" in error_str

    def test_exception_user_information(self) -> None:
        """Test exception user information."""
        exceptions = FlextLdapExceptions()

        # Test that user information is included
        error = exceptions.user_error(
            "User creation failed",
            "testuser",
            operation="create",
            reason="Duplicate UID",
        )
        error_str = str(error)

        assert "User creation failed" in error_str
        assert "testuser" in error_str
        assert "create" in error_str
        assert "Duplicate UID" in error_str

    def test_exception_group_information(self) -> None:
        """Test exception group information."""
        exceptions = FlextLdapExceptions()

        # Test that group information is included
        error = exceptions.group_error(
            "Group creation failed", "testgroup", operation="create"
        )
        error_str = str(error)

        assert "Group creation failed" in error_str
        assert "testgroup" in error_str
        assert "create" in error_str

    def test_exception_integration_complete_workflow(self) -> None:
        """Test complete exception workflow integration."""
        exceptions = FlextLdapExceptions()

        # Test complete workflow with different exception types
        connection_error = exceptions.connection_error(
            "Connection failed", "ldap://localhost:389"
        )
        assert isinstance(connection_error, Exception)

        auth_error = exceptions.authentication_error(
            "Invalid credentials", "cn=admin,dc=example,dc=com"
        )
        assert isinstance(auth_error, Exception)

        search_error = exceptions.search_error(
            "Search failed", "(objectClass=person)", "dc=example,dc=com"
        )
        assert isinstance(search_error, Exception)

        operation_error = exceptions.operation_error(
            "Add failed", "uid=testuser,ou=people,dc=example,dc=com"
        )
        assert isinstance(operation_error, Exception)

        validation_error = exceptions.validation_error(
            "Invalid DN format", "invalid-dn"
        )
        assert isinstance(validation_error, Exception)

        config_error = exceptions.configuration_error(
            "Invalid server URI", "ldap://invalid-server"
        )
        assert isinstance(config_error, Exception)

        type_error = exceptions.type_error(
            "Invalid attribute type", "cn", expected_type="string"
        )
        assert isinstance(type_error, Exception)

        ldap_error = exceptions.ldap_error(
            "LDAP operation failed", "search", ldap_code=32
        )
        assert isinstance(ldap_error, Exception)

        user_error = exceptions.user_error("User not found", "testuser")
        assert isinstance(user_error, Exception)

        group_error = exceptions.group_error("Group not found", "testgroup")
        assert isinstance(group_error, Exception)

    def test_exception_error_handling_consistency(self) -> None:
        """Test consistent error handling across exception methods."""
        exceptions = FlextLdapExceptions()

        # Test that all exception methods return Exception instances
        exception_methods = [
            lambda: exceptions.connection_error("test", "test"),
            lambda: exceptions.authentication_error("test", "test"),
            lambda: exceptions.search_error("test", "test", "test"),
            lambda: exceptions.operation_error("test", "test"),
            lambda: exceptions.validation_error("test", "test"),
            lambda: exceptions.configuration_error("test", "test"),
            lambda: exceptions.type_error("test", "test", "str"),
            lambda: exceptions.ldap_error("test", "test"),
            lambda: exceptions.user_error("test", "test"),
            lambda: exceptions.group_error("test", "test"),
        ]

        for method in exception_methods:
            error = method()
            assert isinstance(error, Exception)
            assert len(str(error)) > 0

    def test_exception_performance_large_datasets(self) -> None:
        """Test exception performance with large datasets."""
        exceptions = FlextLdapExceptions()

        # Test creating many exceptions
        for i in range(100):
            error = exceptions.connection_error(
                f"Connection failed {i}", f"ldap://server{i}:389"
            )
            assert isinstance(error, Exception)
            assert str(i) in str(error)
