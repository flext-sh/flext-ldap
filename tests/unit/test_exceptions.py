"""Focused tests to boost exceptions.py coverage to 100%.

This test file targets specific uncovered lines in exceptions.py
to reach 100% coverage systematically.
"""

from __future__ import annotations

from flext_ldap.exceptions import FlextLDAPExceptions


class TestExceptionStringRepresentations:
    """Test exception string representations - covers missing __str__ branches."""

    def test_ldap_error_with_operation_and_code(self) -> None:
        """Test FlextLDAPExceptions.Error __str__ with operation and ldap_result_code."""
        # Covers lines 70-77, 78-86
        error = FlextLDAPExceptions.Error(
            "Base error", operation="test_operation", ldap_result_code="50"
        )
        result_str = str(error)
        assert "Base error" in result_str
        assert "test_operation" in result_str
        assert "50" in result_str

    def test_connection_error_with_ldap_code(self) -> None:
        """Test FlextLDAPExceptions.LdapConnectionError with ldap_result_code."""
        # Covers lines 127, 129, 131
        error = FlextLDAPExceptions.LdapConnectionError(
            "Connection failed", server_uri="ldap://test.com:389"
        )
        result_str = str(error)
        assert "Connection failed" in result_str
        assert "ldap://test.com" in result_str
        assert "389" in result_str

    def test_authentication_error_branches(self) -> None:
        """Test FlextLDAPExceptions.AuthenticationError string formatting branches."""
        # Covers lines 165-171
        error = FlextLDAPExceptions.AuthenticationError(
            "Auth failed", bind_dn="cn=user,dc=test", ldap_result_code="49"
        )
        result_str = str(error)
        assert "Auth failed" in result_str
        assert "cn=user,dc=test" in result_str

    def test_search_error_with_context(self) -> None:
        """Test FlextLDAPExceptions.SearchError with all context fields."""
        # Covers lines 211-219
        error = FlextLDAPExceptions.SearchError(
            "Search failed",
            base_dn="ou=users,dc=test",
            search_filter="(uid=test)",
            ldap_result_code="32",
        )
        result_str = str(error)
        assert "Search failed" in result_str
        assert "ou=users,dc=test" in result_str
        assert "(uid=test)" in result_str

    def test_operation_error_with_target(self) -> None:
        """Test FlextLDAPExceptions.OperationError with target_dn."""
        # Covers lines 252-258
        error = FlextLDAPExceptions.OperationError(
            "Operation failed",
            operation_type="modify",
            target_dn="cn=test,ou=users",
            ldap_result_code="68",
        )
        result_str = str(error)
        assert "Operation failed" in result_str
        assert "modify" in result_str
        assert "cn=test,ou=users" in result_str

    def test_user_error_with_all_fields(self) -> None:
        """Test FlextLDAPExceptions.UserError with all optional fields."""
        # Covers lines 296-304
        error = FlextLDAPExceptions.UserError(
            "User error",
            user_dn="cn=test,ou=users",
            uid="testuser",
            validation_field="mail",
        )
        result_str = str(error)
        assert "User error" in result_str
        assert "cn=test,ou=users" in result_str
        assert "testuser" in result_str

    def test_validation_error_with_field_details(self) -> None:
        """Test FlextLDAPExceptions.ValidationError with field details."""
        # Covers lines 336-344
        error = FlextLDAPExceptions.ValidationError(
            "Validation failed",
            field_name="email",
            field_value="invalid@",
            validation_rule="email_format",
        )
        result_str = str(error)
        assert "Validation failed" in result_str
        assert "email" in result_str
        assert "invalid@" in result_str

    def test_type_error_with_type_info(self) -> None:
        """Test FlextLDAPExceptions.LdapTypeError with type information."""
        # Covers lines 381-393
        error = FlextLDAPExceptions.LdapTypeError(
            "Type error", expected_type="int", actual_type="str", attribute_name="port"
        )
        result_str = str(error)
        assert "Type error" in result_str
        assert "int" in result_str
        assert "str" in result_str

    def test_configuration_error_with_section(self) -> None:
        """Test FlextLDAPExceptions.ConfigurationError with config section."""
        # Covers lines 423-429
        error = FlextLDAPExceptions.ConfigurationError(
            "Config error", config_key="server", config_section="ldap"
        )
        result_str = str(error)
        assert "Config error" in result_str
        assert "server" in result_str
        assert "ldap" in result_str


class TestExceptionFactoryMethods:
    """Test FlextLDAPExceptions.Factory methods - covers factory method branches."""

    def test_connection_failed_with_different_params(self) -> None:
        """Test connection_failed factory method variations."""
        # Covers lines 461-469
        conn_params1 = FlextLDAPExceptions.ConnectionParams(
            server_uri="server1", error="timeout"
        )
        conn_params2 = FlextLDAPExceptions.ConnectionParams(
            server_uri="server2", error="port error"
        )
        error1 = FlextLDAPExceptions.Factory.connection_failed(conn_params1)
        error2 = FlextLDAPExceptions.Factory.connection_failed(conn_params2)

        assert isinstance(error1, FlextLDAPExceptions.LdapConnectionError)
        assert isinstance(error2, FlextLDAPExceptions.LdapConnectionError)
        assert "server1" in str(error1)
        assert "server2" in str(error2)

    def test_factory_with_ldap_result_codes(self) -> None:
        """Test factory methods with ldap_result_code parameter."""
        # Covers lines 510-511, 525-529, 545-546, 563-570, 586-587, 603-604

        # authentication_failed with code
        auth_error = FlextLDAPExceptions.Factory.authentication_failed(
            "cn=user", ldap_result_code="49"
        )
        assert isinstance(auth_error, FlextLDAPExceptions.AuthenticationError)
        assert "49" in str(auth_error)

        # search_failed with code
        search_error = FlextLDAPExceptions.Factory.search_failed(
            "ou=users", "(uid=test)", "Not found", ldap_result_code="32"
        )
        assert isinstance(search_error, FlextLDAPExceptions.SearchError)
        assert "32" in str(search_error)

        # user_creation_failed with uid and code
        user_error = FlextLDAPExceptions.Factory.user_creation_failed(
            "cn=newuser", "Creation failed", uid="newuser", ldap_result_code="68"
        )
        assert isinstance(user_error, FlextLDAPExceptions.UserError)
        assert "newuser" in str(user_error)
        assert "68" in str(user_error)

        # validation_failed
        val_error = FlextLDAPExceptions.Factory.validation_failed("field", "error")
        assert isinstance(val_error, FlextLDAPExceptions.ValidationError)

        # configuration_error with section
        config_error = FlextLDAPExceptions.Factory.configuration_error(
            "key", "error", config_section="section"
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
                "test", base_dn="base", search_filter="filter"
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
