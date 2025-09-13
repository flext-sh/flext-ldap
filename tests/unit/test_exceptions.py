
from __future__ import annotations

from flext_ldap.exceptions import FlextLDAPExceptions

to reach 100% coverage systematically.


Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import Type


class TestExceptionStringRepresentations:
    """Test exception string representations - covers missing __str__ branches."""

    def test_ldap_error_with_operation_and_code(self) -> None:
        """Test FlextLDAPExceptions.Error basic functionality."""

        error = FlextLDAPExceptions.Error(
            "Base error",
            context={"operation": "test_operation", "ldap_result_code": "50"},
        )
        result_str = str(error)
        assert "Base error" in result_str
        # FlextExceptions.BaseError format: [GENERIC_ERROR] message
        assert "[GENERIC_ERROR]" in result_str

    def test_connection_error_with_ldap_code(self) -> None:
        """Test FlextLDAPExceptions.LdapConnectionError basic functionality."""

        error = FlextLDAPExceptions.LdapConnectionError(
            "Connection failed",
            server_uri="ldap://test.com:389",
        )
        result_str = str(error)
        assert "Connection failed" in result_str
        # FlextExceptions.ConnectionError format: [CONNECTION_ERROR] message
        assert "[CONNECTION_ERROR]" in result_str

    def test_authentication_error_branches(self) -> None:
        """Test FlextLDAPExceptions.AuthenticationError basic functionality."""

        error = FlextLDAPExceptions.AuthenticationError(
            "Auth failed",
            bind_dn="cn=user,dc=test",
            ldap_result_code="49",
        )
        result_str = str(error)
        assert "Auth failed" in result_str
        # FlextExceptions.AuthenticationError format: [AUTHENTICATION_ERROR] message
        assert "[AUTHENTICATION_ERROR]" in result_str

    def test_search_error_with_context(self) -> None:
        """Test FlextLDAPExceptions.SearchError (OperationError alias) basic functionality."""

        error = FlextLDAPExceptions.SearchError(
            "Search failed",
            base_dn="ou=users,dc=test",
            search_filter="(uid=test)",
            ldap_result_code="32",
        )
        result_str = str(error)
        assert "Search failed" in result_str
        # FlextExceptions.OperationError format: [OPERATION_ERROR] message
        assert "[OPERATION_ERROR]" in result_str

    def test_operation_error_with_target(self) -> None:
        """Test FlextLDAPExceptions.OperationError basic functionality."""

        error = FlextLDAPExceptions.OperationError(
            "Operation failed",
            operation_type="modify",
            target_dn="cn=test,ou=users",
            ldap_result_code="68",
        )
        result_str = str(error)
        assert "Operation failed" in result_str
        # FlextExceptions.OperationError format: [OPERATION_ERROR] message
        assert "[OPERATION_ERROR]" in result_str

    def test_user_error_with_all_fields(self) -> None:
        """Test FlextLDAPExceptions.UserError basic functionality."""

        error = FlextLDAPExceptions.UserError(
            "User error",
            user_dn="cn=test,ou=users",
            uid="testuser",
            validation_field="mail",
        )
        result_str = str(error)
        assert "User error" in result_str
        # FlextExceptions.UserError format: [TYPE_ERROR] message
        assert "[TYPE_ERROR]" in result_str

    def test_validation_error_with_field_details(self) -> None:
        """Test FlextLDAPExceptions.ValidationError basic functionality."""

        error = FlextLDAPExceptions.ValidationError(
            "Validation failed",
            field_name="email",
            field_value="invalid@",
            validation_rule="email_format",
        )
        result_str = str(error)
        assert "Validation failed" in result_str
        # FlextExceptions.ValidationError format: [VALIDATION_ERROR] message
        assert "[VALIDATION_ERROR]" in result_str

    def test_type_error_with_type_info(self) -> None:
        """Test FlextLDAPExceptions.LdapTypeError (TypeError alias) basic functionality."""

        error = FlextLDAPExceptions.LdapTypeError(
            "Type error",
            expected_type="int",
            actual_type="str",
            attribute_name="port",
        )
        result_str = str(error)
        assert "Type error" in result_str
        # FlextExceptions.TypeError format: [TYPE_ERROR] message
        assert "[TYPE_ERROR]" in result_str

    def test_configuration_error_with_section(self) -> None:
        """Test FlextLDAPExceptions.ConfigurationError basic functionality."""

        error = FlextLDAPExceptions.ConfigurationError(
            "Config error",
            config_key="server",
            config_section="ldap",
        )
        result_str = str(error)
        assert "Config error" in result_str
        # FlextExceptions.ConfigurationError format: [CONFIGURATION_ERROR] message
        assert "[CONFIGURATION_ERROR]" in result_str


class TestExceptionFactoryMethods:
    """Test FlextLDAPExceptions.Factory methods - covers factory method branches."""

    def test_connection_failed_with_different_params(self) -> None:
        """Test connection error creation with different parameters."""

        # Create connection errors with different parameters
        error1 = FlextLDAPExceptions.LdapConnectionError(
            "Connection timeout to server1"
        )
        error2 = FlextLDAPExceptions.LdapConnectionError(
            "Port error connecting to server2"
        )

        assert isinstance(error1, FlextLDAPExceptions.LdapConnectionError)
        assert isinstance(error2, FlextLDAPExceptions.LdapConnectionError)
        assert "server1" in str(error1)
        assert "server2" in str(error2)

    def test_factory_with_ldap_result_codes(self) -> None:
        """Test exception creation with LDAP result codes."""

        # Create authentication error with result code
        auth_error = FlextLDAPExceptions.AuthenticationError(
            "Authentication failed for cn=user (LDAP result code: 49)"
        )
        assert isinstance(auth_error, FlextLDAPExceptions.AuthenticationError)
        assert "49" in str(auth_error)

        # Create search error with result code
        search_error = FlextLDAPExceptions.SearchError(
            "Search failed for ou=users with filter (uid=test), error: Not found (LDAP result code: 32)"
        )
        assert isinstance(search_error, FlextLDAPExceptions.SearchError)
        assert "32" in str(search_error)

        # Create user error with uid and code
        user_error = FlextLDAPExceptions.UserError(
            "User creation failed for cn=newuser (uid: newuser, LDAP result code: 68)"
        )
        assert isinstance(user_error, FlextLDAPExceptions.UserError)
        assert "newuser" in str(user_error)
        assert "68" in str(user_error)

        # Create validation error
        val_error = FlextLDAPExceptions.ValidationError(
            "Validation failed for field: error"
        )
        assert isinstance(val_error, FlextLDAPExceptions.ValidationError)

        # Create configuration error with section
        config_error = FlextLDAPExceptions.ConfigurationError(
            "Configuration error in section 'section' for key: error"
        )
        assert isinstance(config_error, FlextLDAPExceptions.ConfigurationError)
        assert "section" in str(config_error)


class TestExceptionInheritance:
    """Test exception inheritance and isinstance checks."""

    def test_all_exceptions_inherit_from_base(self) -> None:
        """Test that all custom exceptions inherit from FlextLDAPExceptions.Error."""

        exceptions = [
            FlextLDAPExceptions.LdapConnectionError("test"),
            FlextLDAPExceptions.AuthenticationError("test"),
            FlextLDAPExceptions.SearchError(
                "test",
                base_dn="base",
                search_filter="filter",
            ),
            FlextLDAPExceptions.OperationError("test"),
            FlextLDAPExceptions.UserError("test"),
            FlextLDAPExceptions.ValidationError("test"),
            FlextLDAPExceptions.LdapTypeError("test"),
            FlextLDAPExceptions.ConfigurationError("test", config_key="key"),
        ]

        for exception in exceptions:
            assert isinstance(exception, FlextLDAPExceptions.Error)
            assert isinstance(exception, Exception)
