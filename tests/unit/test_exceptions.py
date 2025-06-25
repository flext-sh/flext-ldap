"""🔥🔥🔥🔥 ULTRA Unit Tests for LDAP Exception Modules.

Tests all custom LDAP exception classes for proper behavior, inheritance,
error handling, and message formatting.

ZERO TOLERANCE TESTING PRINCIPLES:
✅ Exception Inheritance Validation
✅ Error Message Formatting
✅ Exception Attributes Testing
✅ Chain Exception Handling
✅ Custom Exception Behavior
✅ Error Code Validation
"""

from typing import NoReturn

import pytest

from ldap_core_shared.exceptions import (
    AuthenticationError,
    ConnectionError,
    LDAPError,
    MigrationError,
    SchemaError,
    ValidationError,
)
from ldap_core_shared.exceptions.auth import (
    AccountLockedError,
    AuthorizationError,
    InvalidCredentialsError,
)
from ldap_core_shared.exceptions.base import LDAPError as LDAPBaseException
from ldap_core_shared.exceptions.connection import (
    SSLError,
    TimeoutError,
)
from ldap_core_shared.exceptions.migration import (
    MigrationConfigurationError,
    MigrationDataError,
    MigrationValidationError,
)
from ldap_core_shared.exceptions.schema import (
    SchemaComparisonError,
    SchemaDiscoveryError,
    SchemaMappingError,
)
from ldap_core_shared.exceptions.validation import (
    DNValidationError,
    LDIFValidationError,
    SchemaValidationError,
)


class TestLDAPBaseException:
    """🔥🔥🔥🔥 Test base LDAP exception."""

    def test_base_exception_creation(self) -> None:
        """Test basic exception creation."""
        exc = LDAPBaseException("Test error message")

        assert str(exc) == "Test error message"
        assert exc.message == "Test error message"

    def test_base_exception_with_details(self) -> None:
        """Test exception with additional details."""
        details = {"server": "ldap.example.com", "port": 389}
        exc = LDAPBaseException("Connection failed", details=details)

        assert exc.message == "Connection failed"
        assert exc.details == details
        assert exc.details["server"] == "ldap.example.com"

    def test_base_exception_with_error_code(self) -> None:
        """Test exception with error code."""
        exc = LDAPBaseException("Invalid credentials", error_code="E001")

        assert exc.error_code == "E001"
        assert exc.message == "Invalid credentials"

    def test_base_exception_inheritance(self) -> None:
        """Test exception inheritance."""
        exc = LDAPBaseException("Test")

        assert isinstance(exc, Exception)
        assert isinstance(exc, LDAPBaseException)


class TestLDAPError:
    """🔥🔥🔥🔥 Test general LDAP error."""

    def test_ldap_error_creation(self) -> None:
        """Test LDAP error creation."""
        exc = LDAPError("LDAP operation failed")

        assert str(exc) == "LDAP operation failed"
        assert isinstance(exc, LDAPBaseException)

    def test_ldap_error_with_ldap_code(self) -> None:
        """Test LDAP error with LDAP result code."""
        exc = LDAPError("Search failed", ldap_code=32)

        assert exc.ldap_code == 32
        assert exc.message == "Search failed"

    def test_ldap_error_chaining(self) -> None:
        """Test LDAP error with original exception."""
        original = ValueError("Invalid filter")
        exc = LDAPError("Filter error", original_error=original)

        assert exc.original_error == original
        assert exc.__cause__ == original


class TestAuthenticationError:
    """🔥🔥🔥🔥 Test authentication errors."""

    def test_authentication_error_basic(self) -> None:
        """Test basic authentication error."""
        exc = AuthenticationError("Invalid credentials")

        assert str(exc) == "Invalid credentials"
        assert isinstance(exc, LDAPError)

    def test_invalid_credentials_error(self) -> None:
        """Test invalid credentials error."""
        exc = InvalidCredentialsError(
            "Bad username or password", bind_dn="cn=user,dc=example,dc=com"
        )

        assert exc.context["bind_dn"] == "cn=user,dc=example,dc=com"
        assert "Bad username or password" in str(exc)
        assert exc.error_code == "49"

    def test_account_locked_error(self) -> None:
        """Test account locked error."""
        exc = AccountLockedError(
            "Account is locked", bind_dn="cn=admin,dc=example,dc=com"
        )

        assert exc.context["bind_dn"] == "cn=admin,dc=example,dc=com"
        assert isinstance(exc, AuthenticationError)
        assert exc.error_code == "775"

    def test_authorization_error(self) -> None:
        """Test authorization error."""
        exc = AuthorizationError(
            "Access denied",
            operation="search",
            target_dn="ou=users,dc=example,dc=com",
            required_permission="read",
        )

        assert exc.context["operation"] == "search"
        assert exc.context["target_dn"] == "ou=users,dc=example,dc=com"
        assert exc.context["required_permission"] == "read"
        assert "Access denied" in str(exc)


class TestConnectionError:
    """🔥🔥🔥🔥 Test connection errors."""

    def test_connection_error_basic(self) -> None:
        """Test basic connection error."""
        exc = ConnectionError("Cannot connect to server")

        assert str(exc) == "Cannot connect to server"
        assert isinstance(exc, LDAPError)

    def test_timeout_error(self) -> None:
        """Test connection timeout error."""
        exc = TimeoutError("Connection timed out", operation="search", timeout_value=30)

        assert exc.context["timeout_value"] == 30
        assert "Connection timed out" in str(exc)

    def test_ssl_error(self) -> None:
        """Test SSL/TLS error."""
        exc = SSLError(
            "SSL certificate validation failed", ssl_details={"error": "expired"}
        )

        assert exc.context["ssl_details"]["error"] == "expired"
        assert isinstance(exc, ConnectionError)

    def test_connection_error_with_host(self) -> None:
        """Test connection error with host information."""
        exc = ConnectionError("Host unreachable", host="ldap.example.com", port=389)

        assert exc.context["host"] == "ldap.example.com"
        assert exc.context["port"] == 389
        assert "Host unreachable" in str(exc)


class TestValidationError:
    """🔥🔥🔥🔥 Test validation errors."""

    def test_validation_error_basic(self) -> None:
        """Test basic validation error."""
        exc = ValidationError("Invalid input data")

        assert str(exc) == "Invalid input data"
        assert isinstance(exc, LDAPError)

    def test_dn_validation_error(self) -> None:
        """Test DN validation error."""
        exc = DNValidationError("Invalid DN format", invalid_dn="invalid_dn")

        assert exc.context["invalid_dn"] == "invalid_dn"
        assert "Invalid DN format" in str(exc)

    def test_ldif_validation_error(self) -> None:
        """Test LDIF validation error."""
        exc = LDIFValidationError(
            "Invalid LDIF format", line_number=10, invalid_content="invalid line"
        )

        assert exc.context["line_number"] == 10
        assert exc.context["invalid_content"] == "invalid line"
        assert isinstance(exc, ValidationError)

    def test_schema_validation_error(self) -> None:
        """Test schema validation error."""
        exc = SchemaValidationError(
            "Schema validation failed", schema_issue="missing required attribute"
        )

        assert exc.context["schema_issue"] == "missing required attribute"
        assert isinstance(exc, ValidationError)


class TestSchemaError:
    """🔥🔥🔥🔥 Test schema errors."""

    def test_schema_error_basic(self) -> None:
        """Test basic schema error."""
        exc = SchemaError("Schema validation failed")

        assert str(exc) == "Schema validation failed"
        assert isinstance(exc, LDAPError)

    def test_schema_discovery_error(self) -> None:
        """Test schema discovery error."""
        exc = SchemaDiscoveryError(
            "Schema discovery failed",
            server="ldap.example.com",
            discovery_type="automatic",
        )

        assert exc.context["server"] == "ldap.example.com"
        assert exc.context["discovery_type"] == "automatic"
        assert "Schema discovery failed" in str(exc)

    def test_schema_comparison_error(self) -> None:
        """Test schema comparison error."""
        exc = SchemaComparisonError(
            "Schema comparison failed", source_schema="schema1", target_schema="schema2"
        )

        assert exc.context["source_schema"] == "schema1"
        assert exc.context["target_schema"] == "schema2"
        assert isinstance(exc, SchemaError)

    def test_schema_mapping_error(self) -> None:
        """Test schema mapping error."""
        exc = SchemaMappingError(
            "Schema mapping failed",
            source_attribute="cn",
            target_attribute="commonName",
        )

        assert exc.context["source_attribute"] == "cn"
        assert exc.context["target_attribute"] == "commonName"
        assert "Schema mapping failed" in str(exc)


class TestMigrationError:
    """🔥🔥🔥🔥 Test migration errors."""

    def test_migration_error_basic(self) -> None:
        """Test basic migration error."""
        exc = MigrationError("Migration process failed")

        assert str(exc) == "Migration process failed"
        assert isinstance(exc, LDAPError)

    def test_migration_validation_error(self) -> None:
        """Test migration validation error."""
        exc = MigrationValidationError(
            "Migration validation failed",
            validation_rule="required_fields",
            failed_entries=10,
        )

        assert exc.context["validation_rule"] == "required_fields"
        assert exc.context["failed_entries"] == 10
        assert "Migration validation failed" in str(exc)

    def test_migration_data_error(self) -> None:
        """Test migration data error."""
        exc = MigrationDataError(
            "Data integrity check failed",
            affected_entries=100,
            corruption_type="encoding",
        )

        assert exc.context["affected_entries"] == 100
        assert exc.context["corruption_type"] == "encoding"
        assert isinstance(exc, MigrationError)

    def test_migration_configuration_error(self) -> None:
        """Test migration configuration error."""
        exc = MigrationConfigurationError(
            "Invalid configuration", config_key="batch_size", config_value="invalid"
        )

        assert exc.context["config_key"] == "batch_size"
        assert exc.context["config_value"] == "invalid"
        assert "Invalid configuration" in str(exc)


class TestExceptionChaining:
    """🔥🔥🔥🔥 Test exception chaining and context."""

    def test_exception_from_chain(self) -> None:
        """Test creating exception from another exception."""
        original = ValueError("Original error")

        try:
            raise original
        except ValueError as e:
            ldap_exc = LDAPError("LDAP error occurred")
            ldap_exc.__cause__ = e

            assert ldap_exc.__cause__ == original
            assert str(ldap_exc) == "LDAP error occurred"

    def test_nested_exception_handling(self) -> None:
        """Test nested exception handling."""
        try:
            try:
                msg = "Timeout occurred"
                raise TimeoutError(msg, operation="search", timeout_value=30)
            except TimeoutError as conn_err:
                msg = "Auth failed after timeout"
                raise AuthenticationError(msg) from conn_err
        except AuthenticationError as auth_err:
            assert isinstance(auth_err.__cause__, TimeoutError)
            assert auth_err.__cause__.context["timeout_value"] == 30

    def test_exception_context_preservation(self) -> None:
        """Test that exception context is preserved."""

        def inner_function() -> NoReturn:
            msg = "Inner error"
            raise ValueError(msg)

        def outer_function() -> None:
            try:
                inner_function()
            except ValueError:
                msg = "Outer LDAP error"
                raise LDAPError(msg)

        with pytest.raises(LDAPError) as exc_info:
            outer_function()

        assert "Outer LDAP error" in str(exc_info.value)
        assert exc_info.value.__context__ is not None


class TestExceptionFormatting:
    """🔥🔥🔥🔥 Test exception message formatting."""

    def test_exception_str_representation(self) -> None:
        """Test string representation of exceptions."""
        exc = ConnectionError("Connection failed", host="ldap.example.com", port=389)

        str_repr = str(exc)
        assert "Connection failed" in str_repr
        # May include additional context in string representation

    def test_exception_repr_representation(self) -> None:
        """Test repr representation of exceptions."""
        exc = AuthenticationError("Auth failed", error_code="E001")

        repr_str = repr(exc)
        assert "AuthenticationError" in repr_str

    def test_exception_with_multiple_attributes(self) -> None:
        """Test exception with multiple custom attributes."""
        exc = LDAPError(
            "Complex error",
            error_code="E123",
            ldap_code=49,
            details={"server": "test.com", "operation": "bind"},
        )

        assert exc.error_code == "E123"
        assert exc.ldap_code == 49
        assert exc.details["server"] == "test.com"
        assert exc.details["operation"] == "bind"


class TestExceptionUtils:
    """🔥🔥🔥🔥 Test exception utility functions."""

    def test_exception_categorization(self) -> None:
        """Test exception categorization."""
        # Test that exceptions are properly categorized
        auth_exc = AuthenticationError("Auth error")
        conn_exc = ConnectionError("Conn error")
        valid_exc = ValidationError("Valid error")

        assert isinstance(auth_exc, LDAPError)
        assert isinstance(conn_exc, LDAPError)
        assert isinstance(valid_exc, LDAPError)

        # Test specific types
        assert not isinstance(auth_exc, ConnectionError)
        assert not isinstance(conn_exc, AuthenticationError)

    def test_exception_hierarchy(self) -> None:
        """Test exception hierarchy is correct."""
        # Test inheritance chain
        specific_exc = InvalidCredentialsError("Cred error")

        assert isinstance(specific_exc, InvalidCredentialsError)
        assert isinstance(specific_exc, AuthenticationError)
        assert isinstance(specific_exc, LDAPError)
        assert isinstance(specific_exc, LDAPBaseException)
        assert isinstance(specific_exc, Exception)


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
