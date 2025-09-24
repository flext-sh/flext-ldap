"""Comprehensive unit tests for LDAP exceptions.

This module provides comprehensive unit tests for all LDAP exception classes,
testing initialization, inheritance, custom attributes, context building,
and string representations.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import pytest

from flext_core import FlextExceptions
from flext_ldap import FlextLdapExceptions


class TestLdapConnectionError:
    """Test LdapConnectionError exception."""

    def test_connection_error_init_with_server_uri(self) -> None:
        """Test connection error initialization with server URI."""
        server_uri = "ldap://localhost:389"
        error = FlextLdapExceptions.LdapConnectionError(
            "Connection failed", server_uri=server_uri
        )

        assert error.message == "Connection failed"
        assert error.server_uri == server_uri
        assert "Connection failed" in str(error)

    def test_connection_error_inherits_from_flext_exceptions(self) -> None:
        """Test connection error inherits from FlextExceptions.ConnectionError."""
        error = FlextLdapExceptions.LdapConnectionError("Connection failed")

        assert isinstance(error, FlextExceptions.ConnectionError)
        assert isinstance(error, FlextExceptions.BaseError)

    def test_connection_error_with_context(self) -> None:
        """Test connection error with additional context."""
        error = FlextLdapExceptions.LdapConnectionError(
            "Connection timeout",
            server_uri="ldaps://ldap.example.com:636",
            context={"timeout": 30, "retry_count": 3},
        )

        assert error.server_uri == "ldaps://ldap.example.com:636"
        assert "Connection timeout" in str(error)


class TestLdapAuthenticationError:
    """Test LdapAuthenticationError exception."""

    def test_authentication_error_init_with_bind_dn(self) -> None:
        """Test authentication error initialization with bind DN."""
        bind_dn = "cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com"
        error = FlextLdapExceptions.LdapAuthenticationError(
            "Authentication failed", bind_dn=bind_dn
        )

        assert error.message == "Authentication failed"
        assert error.bind_dn == bind_dn

    def test_authentication_error_inherits_from_flext_exceptions(self) -> None:
        """Test authentication error inherits from FlextExceptions.AuthenticationError."""
        error = FlextLdapExceptions.LdapAuthenticationError("Auth failed")

        assert isinstance(error, FlextExceptions.AuthenticationError)
        assert isinstance(error, FlextExceptions.BaseError)

    def test_authentication_error_with_none_bind_dn(self) -> None:
        """Test authentication error with None bind DN."""
        error = FlextLdapExceptions.LdapAuthenticationError(
            "Invalid credentials", bind_dn=None
        )

        assert error.bind_dn is None
        assert "Invalid credentials" in str(error)


class TestLdapSearchError:
    """Test LdapSearchError exception."""

    def test_search_error_init_with_params(self) -> None:
        """Test search error initialization with base DN and filter."""
        error = FlextLdapExceptions.LdapSearchError(
            "Search failed",
            base_dn="ou=users,dc=example,dc=com",
            filter_str="(objectClass=person)",
        )

        assert error.message == "Search failed"
        assert error.base_dn == "ou=users,dc=example,dc=com"
        assert error.filter_str == "(objectClass=person)"

    def test_search_error_inherits_from_operation_error(self) -> None:
        """Test search error inherits from FlextExceptions.OperationError."""
        error = FlextLdapExceptions.LdapSearchError("Search failed")

        assert isinstance(error, FlextExceptions.OperationError)
        assert isinstance(error, FlextExceptions.BaseError)

    def test_search_error_context_building(self) -> None:
        """Test search error builds context correctly."""
        error = FlextLdapExceptions.LdapSearchError(
            "Search timeout", base_dn="dc=test,dc=com", filter_str="(cn=*)"
        )

        assert error.base_dn == "dc=test,dc=com"
        assert error.filter_str == "(cn=*)"


class TestLdapModifyError:
    """Test LdapModifyError exception."""

    def test_modify_error_init_with_modifications(self) -> None:
        """Test modify error initialization with modifications."""
        modifications: list[tuple[str, str, object]] = [
            ("MODIFY_REPLACE", "mail", "new@example.com")
        ]
        error = FlextLdapExceptions.LdapModifyError(
            "Modify failed",
            dn="uid=user,ou=users,dc=example,dc=com",
            modifications=modifications,
        )

        assert error.message == "Modify failed"
        assert error.dn == "uid=user,ou=users,dc=example,dc=com"
        assert error.modifications == modifications

    def test_modify_error_inherits_from_operation_error(self) -> None:
        """Test modify error inherits from FlextExceptions.OperationError."""
        error = FlextLdapExceptions.LdapModifyError("Modify failed")

        assert isinstance(error, FlextExceptions.OperationError)

    def test_modify_error_with_empty_modifications(self) -> None:
        """Test modify error with empty modifications list."""
        error = FlextLdapExceptions.LdapModifyError(
            "No modifications", dn="uid=test,dc=example,dc=com", modifications=[]
        )

        assert error.modifications == []


class TestLdapAddError:
    """Test LdapAddError exception."""

    def test_add_error_init_with_object_classes(self) -> None:
        """Test add error initialization with object classes."""
        error = FlextLdapExceptions.LdapAddError(
            "Add failed",
            dn="uid=newuser,ou=users,dc=example,dc=com",
            object_classes=["person", "organizationalPerson"],
        )

        assert error.message == "Add failed"
        assert error.dn == "uid=newuser,ou=users,dc=example,dc=com"
        assert error.object_classes == ["person", "organizationalPerson"]

    def test_add_error_inherits_from_operation_error(self) -> None:
        """Test add error inherits from FlextExceptions.OperationError."""
        error = FlextLdapExceptions.LdapAddError("Add failed")

        assert isinstance(error, FlextExceptions.OperationError)


class TestLdapDeleteError:
    """Test LdapDeleteError exception."""

    def test_delete_error_init_with_dn(self) -> None:
        """Test delete error initialization with DN."""
        error = FlextLdapExceptions.LdapDeleteError(
            "Delete failed", dn="uid=olduser,ou=users,dc=example,dc=com"
        )

        assert error.message == "Delete failed"
        assert error.dn == "uid=olduser,ou=users,dc=example,dc=com"

    def test_delete_error_inherits_from_operation_error(self) -> None:
        """Test delete error inherits from FlextExceptions.OperationError."""
        error = FlextLdapExceptions.LdapDeleteError("Delete failed")

        assert isinstance(error, FlextExceptions.OperationError)


class TestLdapValidationError:
    """Test LdapValidationError exception."""

    def test_validation_error_init_with_field(self) -> None:
        """Test validation error initialization with LDAP field."""
        error = FlextLdapExceptions.LdapValidationError(
            "Invalid email format", ldap_field="mail"
        )

        assert error.message == "Invalid email format"
        assert error.ldap_field == "mail"

    def test_validation_error_inherits_from_validation_error(self) -> None:
        """Test validation error inherits from FlextExceptions.ValidationError."""
        error = FlextLdapExceptions.LdapValidationError("Validation failed")

        assert isinstance(error, FlextExceptions.ValidationError)


class TestLdapConfigurationError:
    """Test LdapConfigurationError exception."""

    def test_configuration_error_init_with_config_key(self) -> None:
        """Test configuration error initialization with config key."""
        error = FlextLdapExceptions.LdapConfigurationError(
            "Missing configuration", ldap_config_key="server_url"
        )

        assert error.message == "Missing configuration"
        assert error.ldap_config_key == "server_url"

    def test_configuration_error_inherits_from_configuration_error(self) -> None:
        """Test configuration error inherits from FlextExceptions.ConfigurationError."""
        error = FlextLdapExceptions.LdapConfigurationError("Config error")

        assert isinstance(error, FlextExceptions.ConfigurationError)

    def test_configuration_error_with_config_file(self) -> None:
        """Test configuration error with config_file parameter."""
        error = FlextLdapExceptions.LdapConfigurationError(
            "Invalid config file",
            ldap_config_key="bind_dn",
            config_file="/etc/ldap/ldap.conf",
        )

        assert error.ldap_config_key == "bind_dn"
        assert "Invalid config file" in str(error)


class TestLdapTimeoutError:
    """Test LdapTimeoutError exception."""

    def test_timeout_error_init_with_operation(self) -> None:
        """Test timeout error initialization with operation."""
        error = FlextLdapExceptions.LdapTimeoutError(
            "Operation timed out", operation="search"
        )

        assert error.message == "Operation timed out"
        assert error.operation == "search"

    def test_timeout_error_inherits_from_timeout_error(self) -> None:
        """Test timeout error inherits from FlextExceptions.TimeoutError."""
        error = FlextLdapExceptions.LdapTimeoutError("Timeout")

        assert isinstance(error, FlextExceptions.TimeoutError)

    def test_timeout_error_with_timeout_seconds(self) -> None:
        """Test timeout error with timeout_seconds parameter."""
        error = FlextLdapExceptions.LdapTimeoutError(
            "Search timeout", operation="search", timeout_seconds=30
        )

        assert error.operation == "search"
        assert "Search timeout" in str(error)


class TestLdapEntryNotFoundError:
    """Test LdapEntryNotFoundError exception."""

    def test_entry_not_found_error_init_with_dn(self) -> None:
        """Test entry not found error initialization with DN."""
        error = FlextLdapExceptions.LdapEntryNotFoundError(
            "Entry not found", dn="uid=missing,ou=users,dc=example,dc=com"
        )

        assert error.message == "Entry not found"
        assert error.dn == "uid=missing,ou=users,dc=example,dc=com"

    def test_entry_not_found_error_inherits_from_not_found_error(self) -> None:
        """Test entry not found error inherits from FlextExceptions.NotFoundError."""
        error = FlextLdapExceptions.LdapEntryNotFoundError("Not found")

        assert isinstance(error, FlextExceptions.NotFoundError)


class TestLdapEntryAlreadyExistsError:
    """Test LdapEntryAlreadyExistsError exception."""

    def test_entry_already_exists_error_init_with_dn(self) -> None:
        """Test entry already exists error initialization with DN."""
        error = FlextLdapExceptions.LdapEntryAlreadyExistsError(
            "Entry already exists", dn="uid=duplicate,ou=users,dc=example,dc=com"
        )

        assert error.message == "Entry already exists"
        assert error.dn == "uid=duplicate,ou=users,dc=example,dc=com"

    def test_entry_already_exists_error_inherits_from_already_exists_error(
        self,
    ) -> None:
        """Test entry already exists error inherits from FlextExceptions.AlreadyExistsError."""
        error = FlextLdapExceptions.LdapEntryAlreadyExistsError("Exists")

        assert isinstance(error, FlextExceptions.AlreadyExistsError)


class TestExceptionStringRepresentations:
    """Test exception string representations."""

    def test_connection_error_string_representation(self) -> None:
        """Test connection error string representation."""
        error = FlextLdapExceptions.LdapConnectionError(
            "Failed to connect to LDAP server", server_uri="ldap://localhost:389"
        )

        error_str = str(error)
        assert "Failed to connect to LDAP server" in error_str

    def test_authentication_error_string_representation(self) -> None:
        """Test authentication error string representation."""
        error = FlextLdapExceptions.LdapAuthenticationError(
            "Invalid bind credentials", bind_dn="cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com"
        )

        error_str = str(error)
        assert "Invalid bind credentials" in error_str

    def test_search_error_string_representation(self) -> None:
        """Test search error string representation."""
        error = FlextLdapExceptions.LdapSearchError(
            "Search operation failed",
            base_dn="dc=example,dc=com",
            filter_str="(objectClass=*)",
        )

        error_str = str(error)
        assert "Search operation failed" in error_str


class TestExceptionInheritance:
    """Test exception inheritance hierarchy."""

    def test_all_exceptions_inherit_from_base_error(self) -> None:
        """Test all LDAP exceptions inherit from FlextExceptions.BaseError."""
        exception_classes = [
            FlextLdapExceptions.LdapConnectionError,
            FlextLdapExceptions.LdapAuthenticationError,
            FlextLdapExceptions.LdapSearchError,
            FlextLdapExceptions.LdapModifyError,
            FlextLdapExceptions.LdapAddError,
            FlextLdapExceptions.LdapDeleteError,
            FlextLdapExceptions.LdapValidationError,
            FlextLdapExceptions.LdapConfigurationError,
            FlextLdapExceptions.LdapTimeoutError,
            FlextLdapExceptions.LdapEntryNotFoundError,
            FlextLdapExceptions.LdapEntryAlreadyExistsError,
        ]

        for exc_class in exception_classes:
            error = exc_class("Test error")
            assert isinstance(error, FlextExceptions.BaseError), (
                f"{exc_class.__name__} should inherit from FlextExceptions.BaseError"
            )

    def test_operation_errors_inherit_from_operation_error(self) -> None:
        """Test operation-related errors inherit from OperationError."""
        operation_errors = [
            FlextLdapExceptions.LdapSearchError,
            FlextLdapExceptions.LdapModifyError,
            FlextLdapExceptions.LdapAddError,
            FlextLdapExceptions.LdapDeleteError,
        ]

        for exc_class in operation_errors:
            error = exc_class("Test error")
            assert isinstance(error, FlextExceptions.OperationError), (
                f"{exc_class.__name__} should inherit from OperationError"
            )


class TestExceptionFactoryMethods:
    """Test exception factory methods and creation patterns."""

    @pytest.mark.parametrize(
        "server_uri",
        [
            "ldap://localhost:389",
            "ldaps://ldap.example.com:636",
            "ldap://192.168.1.100:389",
        ],
    )
    def test_connection_error_with_various_server_uris(self, server_uri: str) -> None:
        """Test connection error with various server URIs."""
        error = FlextLdapExceptions.LdapConnectionError(
            "Connection failed", server_uri=server_uri
        )

        assert error.server_uri == server_uri

    @pytest.mark.parametrize(
        "bind_dn",
        [
            "cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com",
            "uid=user,ou=people,dc=example,dc=com",
            "cn=readonly,ou=system,dc=example,dc=com",
        ],
    )
    def test_authentication_error_with_various_bind_dns(self, bind_dn: str) -> None:
        """Test authentication error with various bind DNs."""
        error = FlextLdapExceptions.LdapAuthenticationError(
            "Authentication failed", bind_dn=bind_dn
        )

        assert error.bind_dn == bind_dn

    @pytest.mark.parametrize(
        "filter_str",
        [
            "(objectClass=person)",
            "(cn=test*)",
            "(&(objectClass=person)(mail=*@example.com))",
        ],
    )
    def test_search_error_with_various_filters(self, filter_str: str) -> None:
        """Test search error with various LDAP filters."""
        error = FlextLdapExceptions.LdapSearchError(
            "Search failed", filter_str=filter_str
        )

        assert error.filter_str == filter_str
