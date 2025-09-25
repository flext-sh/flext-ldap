"""Comprehensive tests for FlextLdapValidations.

This module provides complete test coverage for the FlextLdapValidations class
following FLEXT standards with proper domain separation and centralized fixtures.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from unittest.mock import patch

from flext_core import FlextResult
from flext_ldap import FlextLdapValidations


class TestFlextLdapValidations:
    """Comprehensive test suite for FlextLdapValidations."""

    def test_validations_initialization(
        self, validations: FlextLdapValidations
    ) -> None:
        """Test validations initialization."""
        assert validations is not None
        assert hasattr(validations, "_container")
        assert hasattr(validations, "_logger")

    def test_validate_dn_success(
        self, validations: FlextLdapValidations, sample_valid_dn: str
    ) -> None:
        """Test successful DN validation."""
        result = validations.validate_dn(sample_valid_dn)

        assert result.is_success
        assert result.data is True

    def test_validate_dn_failure(
        self, validations: FlextLdapValidations, sample_invalid_dn: str
    ) -> None:
        """Test DN validation failure."""
        result = validations.validate_dn(sample_invalid_dn)

        assert result.is_failure
        assert "Invalid DN format" in result.error

    def test_validate_dn_empty(self, validations: FlextLdapValidations) -> None:
        """Test DN validation with empty string."""
        result = validations.validate_dn("")

        assert result.is_failure
        assert "DN cannot be empty" in result.error

    def test_validate_dn_none(self, validations: FlextLdapValidations) -> None:
        """Test DN validation with None."""
        result = validations.validate_dn(None)

        assert result.is_failure
        assert "DN cannot be None" in result.error

    def test_validate_dn_whitespace_only(
        self, validations: FlextLdapValidations
    ) -> None:
        """Test DN validation with whitespace only."""
        result = validations.validate_dn("   ")

        assert result.is_failure
        assert "DN cannot be empty" in result.error

    def test_validate_email_success(
        self, validations: FlextLdapValidations, sample_valid_email: str
    ) -> None:
        """Test successful email validation."""
        result = validations.validate_email(sample_valid_email)

        assert result.is_success
        assert result.data is True

    def test_validate_email_failure(
        self, validations: FlextLdapValidations, sample_invalid_email: str
    ) -> None:
        """Test email validation failure."""
        result = validations.validate_email(sample_invalid_email)

        assert result.is_failure
        assert "Invalid email format" in result.error

    def test_validate_email_empty(self, validations: FlextLdapValidations) -> None:
        """Test email validation with empty string."""
        result = validations.validate_email("")

        assert result.is_failure
        assert "Email cannot be empty" in result.error

    def test_validate_email_none(self, validations: FlextLdapValidations) -> None:
        """Test email validation with None."""
        result = validations.validate_email(None)

        assert result.is_failure
        assert "Email cannot be None" in result.error

    def test_validate_email_with_flext_models_error(
        self, validations: FlextLdapValidations
    ) -> None:
        """Test email validation with FlextModels error."""
        with patch.object(validations, "_validate_with_flext_models") as mock_validate:
            mock_validate.return_value = FlextResult[bool].fail(
                "FlextModels validation failed"
            )

            result = validations.validate_email("test@example.com")

            assert result.is_failure
            assert "FlextModels validation failed" in result.error

    def test_validate_filter_success(
        self, validations: FlextLdapValidations, sample_valid_filter: str
    ) -> None:
        """Test successful filter validation."""
        result = validations.validate_filter(sample_valid_filter)

        assert result.is_success
        assert result.data is True

    def test_validate_filter_failure(self, validations: FlextLdapValidations) -> None:
        """Test filter validation failure."""
        result = validations.validate_filter("invalid-filter")

        assert result.is_failure
        assert "Invalid filter format" in result.error

    def test_validate_filter_empty(self, validations: FlextLdapValidations) -> None:
        """Test filter validation with empty string."""
        result = validations.validate_filter("")

        assert result.is_failure
        assert "Filter cannot be empty" in result.error

    def test_validate_filter_none(self, validations: FlextLdapValidations) -> None:
        """Test filter validation with None."""
        result = validations.validate_filter(None)

        assert result.is_failure
        assert "Filter cannot be None" in result.error

    def test_validate_password_success(self, validations: FlextLdapValidations) -> None:
        """Test successful password validation."""
        result = validations.validate_password("validpassword123")

        assert result.is_success
        assert result.data is True

    def test_validate_password_too_short(
        self, validations: FlextLdapValidations
    ) -> None:
        """Test password validation with too short password."""
        result = validations.validate_password("123")

        assert result.is_failure
        assert "Password too short" in result.error

    def test_validate_password_too_long(
        self, validations: FlextLdapValidations
    ) -> None:
        """Test password validation with too long password."""
        long_password = "a" * 1000  # Very long password
        result = validations.validate_password(long_password)

        assert result.is_failure
        assert "Password too long" in result.error

    def test_validate_password_empty(self, validations: FlextLdapValidations) -> None:
        """Test password validation with empty string."""
        result = validations.validate_password("")

        assert result.is_failure
        assert "Password cannot be empty" in result.error

    def test_validate_password_none(self, validations: FlextLdapValidations) -> None:
        """Test password validation with None."""
        result = validations.validate_password(None)

        assert result.is_failure
        assert "Password cannot be None" in result.error

    def test_validate_attributes_success(
        self, validations: FlextLdapValidations
    ) -> None:
        """Test successful attributes validation."""
        attributes = ["cn", "sn", "mail", "uid"]
        result = validations.validate_attributes(attributes)

        assert result.is_success
        assert result.data is True

    def test_validate_attributes_empty(self, validations: FlextLdapValidations) -> None:
        """Test attributes validation with empty list."""
        result = validations.validate_attributes([])

        assert result.is_failure
        assert "Attributes cannot be empty" in result.error

    def test_validate_attributes_none(self, validations: FlextLdapValidations) -> None:
        """Test attributes validation with None."""
        result = validations.validate_attributes(None)

        assert result.is_failure
        assert "Attributes cannot be None" in result.error

    def test_validate_attributes_invalid_format(
        self, validations: FlextLdapValidations
    ) -> None:
        """Test attributes validation with invalid format."""
        attributes = ["cn", "", "mail"]  # Empty attribute
        result = validations.validate_attributes(attributes)

        assert result.is_failure
        assert "Invalid attribute format" in result.error

    def test_validate_server_uri_success(
        self, validations: FlextLdapValidations
    ) -> None:
        """Test successful server URI validation."""
        result = validations.validate_server_uri("ldap://localhost:389")

        assert result.is_success
        assert result.data is True

    def test_validate_server_uri_ldaps(self, validations: FlextLdapValidations) -> None:
        """Test server URI validation with LDAPS."""
        result = validations.validate_server_uri("ldaps://localhost:636")

        assert result.is_success
        assert result.data is True

    def test_validate_server_uri_failure(
        self, validations: FlextLdapValidations
    ) -> None:
        """Test server URI validation failure."""
        result = validations.validate_server_uri("invalid-uri")

        assert result.is_failure
        assert "Invalid server URI format" in result.error

    def test_validate_server_uri_empty(self, validations: FlextLdapValidations) -> None:
        """Test server URI validation with empty string."""
        result = validations.validate_server_uri("")

        assert result.is_failure
        assert "Server URI cannot be empty" in result.error

    def test_validate_server_uri_none(self, validations: FlextLdapValidations) -> None:
        """Test server URI validation with None."""
        result = validations.validate_server_uri(None)

        assert result.is_failure
        assert "Server URI cannot be None" in result.error

    def test_validate_port_success(self, validations: FlextLdapValidations) -> None:
        """Test successful port validation."""
        result = validations.validate_port(389)

        assert result.is_success
        assert result.data is True

    def test_validate_port_ldaps(self, validations: FlextLdapValidations) -> None:
        """Test port validation with LDAPS port."""
        result = validations.validate_port(636)

        assert result.is_success
        assert result.data is True

    def test_validate_port_invalid(self, validations: FlextLdapValidations) -> None:
        """Test port validation with invalid port."""
        result = validations.validate_port(99999)

        assert result.is_failure
        assert "Invalid port number" in result.error

    def test_validate_port_negative(self, validations: FlextLdapValidations) -> None:
        """Test port validation with negative port."""
        result = validations.validate_port(-1)

        assert result.is_failure
        assert "Invalid port number" in result.error

    def test_validate_port_none(self, validations: FlextLdapValidations) -> None:
        """Test port validation with None."""
        result = validations.validate_port(None)

        assert result.is_failure
        assert "Port cannot be None" in result.error

    def test_validate_timeout_success(self, validations: FlextLdapValidations) -> None:
        """Test successful timeout validation."""
        result = validations.validate_timeout(30)

        assert result.is_success
        assert result.data is True

    def test_validate_timeout_zero(self, validations: FlextLdapValidations) -> None:
        """Test timeout validation with zero."""
        result = validations.validate_timeout(0)

        assert result.is_success
        assert result.data is True

    def test_validate_timeout_negative(self, validations: FlextLdapValidations) -> None:
        """Test timeout validation with negative value."""
        result = validations.validate_timeout(-1)

        assert result.is_failure
        assert "Timeout cannot be negative" in result.error

    def test_validate_timeout_none(self, validations: FlextLdapValidations) -> None:
        """Test timeout validation with None."""
        result = validations.validate_timeout(None)

        assert result.is_failure
        assert "Timeout cannot be None" in result.error

    def test_validate_size_limit_success(
        self, validations: FlextLdapValidations
    ) -> None:
        """Test successful size limit validation."""
        result = validations.validate_size_limit(100)

        assert result.is_success
        assert result.data is True

    def test_validate_size_limit_zero(self, validations: FlextLdapValidations) -> None:
        """Test size limit validation with zero."""
        result = validations.validate_size_limit(0)

        assert result.is_success
        assert result.data is True

    def test_validate_size_limit_negative(
        self, validations: FlextLdapValidations
    ) -> None:
        """Test size limit validation with negative value."""
        result = validations.validate_size_limit(-1)

        assert result.is_failure
        assert "Size limit cannot be negative" in result.error

    def test_validate_size_limit_none(self, validations: FlextLdapValidations) -> None:
        """Test size limit validation with None."""
        result = validations.validate_size_limit(None)

        assert result.is_failure
        assert "Size limit cannot be None" in result.error

    def test_validate_scope_success(self, validations: FlextLdapValidations) -> None:
        """Test successful scope validation."""
        result = validations.validate_scope("subtree")

        assert result.is_success
        assert result.data is True

    def test_validate_scope_base(self, validations: FlextLdapValidations) -> None:
        """Test scope validation with base scope."""
        result = validations.validate_scope("base")

        assert result.is_success
        assert result.data is True

    def test_validate_scope_one(self, validations: FlextLdapValidations) -> None:
        """Test scope validation with one scope."""
        result = validations.validate_scope("one")

        assert result.is_success
        assert result.data is True

    def test_validate_scope_invalid(self, validations: FlextLdapValidations) -> None:
        """Test scope validation with invalid scope."""
        result = validations.validate_scope("invalid")

        assert result.is_failure
        assert "Invalid scope" in result.error

    def test_validate_scope_empty(self, validations: FlextLdapValidations) -> None:
        """Test scope validation with empty string."""
        result = validations.validate_scope("")

        assert result.is_failure
        assert "Scope cannot be empty" in result.error

    def test_validate_scope_none(self, validations: FlextLdapValidations) -> None:
        """Test scope validation with None."""
        result = validations.validate_scope(None)

        assert result.is_failure
        assert "Scope cannot be None" in result.error

    def test_validate_modify_operation_success(
        self, validations: FlextLdapValidations
    ) -> None:
        """Test successful modify operation validation."""
        result = validations.validate_modify_operation("MODIFY_REPLACE")

        assert result.is_success
        assert result.data is True

    def test_validate_modify_operation_add(
        self, validations: FlextLdapValidations
    ) -> None:
        """Test modify operation validation with MODIFY_ADD."""
        result = validations.validate_modify_operation("MODIFY_ADD")

        assert result.is_success
        assert result.data is True

    def test_validate_modify_operation_delete(
        self, validations: FlextLdapValidations
    ) -> None:
        """Test modify operation validation with MODIFY_DELETE."""
        result = validations.validate_modify_operation("MODIFY_DELETE")

        assert result.is_success
        assert result.data is True

    def test_validate_modify_operation_invalid(
        self, validations: FlextLdapValidations
    ) -> None:
        """Test modify operation validation with invalid operation."""
        result = validations.validate_modify_operation("INVALID_OPERATION")

        assert result.is_failure
        assert "Invalid modify operation" in result.error

    def test_validate_modify_operation_empty(
        self, validations: FlextLdapValidations
    ) -> None:
        """Test modify operation validation with empty string."""
        result = validations.validate_modify_operation("")

        assert result.is_failure
        assert "Modify operation cannot be empty" in result.error

    def test_validate_modify_operation_none(
        self, validations: FlextLdapValidations
    ) -> None:
        """Test modify operation validation with None."""
        result = validations.validate_modify_operation(None)

        assert result.is_failure
        assert "Modify operation cannot be None" in result.error

    def test_validate_object_class_success(
        self, validations: FlextLdapValidations
    ) -> None:
        """Test successful object class validation."""
        result = validations.validate_object_class("inetOrgPerson")

        assert result.is_success
        assert result.data is True

    def test_validate_object_class_organizational_person(
        self, validations: FlextLdapValidations
    ) -> None:
        """Test object class validation with organizationalPerson."""
        result = validations.validate_object_class("organizationalPerson")

        assert result.is_success
        assert result.data is True

    def test_validate_object_class_group(
        self, validations: FlextLdapValidations
    ) -> None:
        """Test object class validation with groupOfNames."""
        result = validations.validate_object_class("groupOfNames")

        assert result.is_success
        assert result.data is True

    def test_validate_object_class_invalid(
        self, validations: FlextLdapValidations
    ) -> None:
        """Test object class validation with invalid class."""
        result = validations.validate_object_class("invalidClass")

        assert result.is_failure
        assert "Invalid object class" in result.error

    def test_validate_object_class_empty(
        self, validations: FlextLdapValidations
    ) -> None:
        """Test object class validation with empty string."""
        result = validations.validate_object_class("")

        assert result.is_failure
        assert "Object class cannot be empty" in result.error

    def test_validate_object_class_none(
        self, validations: FlextLdapValidations
    ) -> None:
        """Test object class validation with None."""
        result = validations.validate_object_class(None)

        assert result.is_failure
        assert "Object class cannot be None" in result.error

    def test_validate_connection_config_success(
        self, validations: FlextLdapValidations
    ) -> None:
        """Test successful connection config validation."""
        config = {
            "server_uri": "ldap://localhost:389",
            "bind_dn": "cn=admin,dc=example,dc=com",
            "password": "admin123",
            "base_dn": "dc=example,dc=com",
        }

        result = validations.validate_connection_config(config)

        assert result.is_success
        assert result.data is True

    def test_validate_connection_config_missing_fields(
        self, validations: FlextLdapValidations
    ) -> None:
        """Test connection config validation with missing fields."""
        config = {
            "server_uri": "ldap://localhost:389"
            # Missing bind_dn, password, base_dn
        }

        result = validations.validate_connection_config(config)

        assert result.is_failure
        assert "Missing required fields" in result.error

    def test_validate_connection_config_invalid_fields(
        self, validations: FlextLdapValidations
    ) -> None:
        """Test connection config validation with invalid fields."""
        config = {
            "server_uri": "invalid-uri",
            "bind_dn": "cn=admin,dc=example,dc=com",
            "password": "admin123",
            "base_dn": "dc=example,dc=com",
        }

        result = validations.validate_connection_config(config)

        assert result.is_failure
        assert "Invalid server URI" in result.error

    def test_validate_connection_config_none(
        self, validations: FlextLdapValidations
    ) -> None:
        """Test connection config validation with None."""
        result = validations.validate_connection_config(None)

        assert result.is_failure
        assert "Config cannot be None" in result.error

    def test_validations_integration_complete_workflow(
        self, validations: FlextLdapValidations
    ) -> None:
        """Test complete validations workflow integration."""
        # Test complete workflow
        dn_result = validations.validate_dn("uid=testuser,ou=people,dc=example,dc=com")
        assert dn_result.is_success

        email_result = validations.validate_email("testuser@example.com")
        assert email_result.is_success

        filter_result = validations.validate_filter("(objectClass=person)")
        assert filter_result.is_success

        password_result = validations.validate_password("validpassword123")
        assert password_result.is_success

        attributes_result = validations.validate_attributes(["cn", "sn", "mail"])
        assert attributes_result.is_success

        server_uri_result = validations.validate_server_uri("ldap://localhost:389")
        assert server_uri_result.is_success

        port_result = validations.validate_port(389)
        assert port_result.is_success

        timeout_result = validations.validate_timeout(30)
        assert timeout_result.is_success

        scope_result = validations.validate_scope("subtree")
        assert scope_result.is_success

        modify_result = validations.validate_modify_operation("MODIFY_REPLACE")
        assert modify_result.is_success

        object_class_result = validations.validate_object_class("inetOrgPerson")
        assert object_class_result.is_success

    def test_validations_error_handling_consistency(
        self, validations: FlextLdapValidations
    ) -> None:
        """Test consistent error handling across validation methods."""
        # Test consistent None handling
        dn_result = validations.validate_dn(None)
        assert dn_result.is_failure
        assert "None" in dn_result.error

        email_result = validations.validate_email(None)
        assert email_result.is_failure
        assert "None" in email_result.error

        filter_result = validations.validate_filter(None)
        assert filter_result.is_failure
        assert "None" in filter_result.error

        password_result = validations.validate_password(None)
        assert password_result.is_failure
        assert "None" in password_result.error

        attributes_result = validations.validate_attributes(None)
        assert attributes_result.is_failure
        assert "None" in attributes_result.error

        server_uri_result = validations.validate_server_uri(None)
        assert server_uri_result.is_failure
        assert "None" in server_uri_result.error

        port_result = validations.validate_port(None)
        assert port_result.is_failure
        assert "None" in port_result.error

        timeout_result = validations.validate_timeout(None)
        assert timeout_result.is_failure
        assert "None" in timeout_result.error

        scope_result = validations.validate_scope(None)
        assert scope_result.is_failure
        assert "None" in scope_result.error

        modify_result = validations.validate_modify_operation(None)
        assert modify_result.is_failure
        assert "None" in modify_result.error

        object_class_result = validations.validate_object_class(None)
        assert object_class_result.is_failure
        assert "None" in object_class_result.error

    def test_validations_performance_large_datasets(
        self, validations: FlextLdapValidations
    ) -> None:
        """Test validations performance with large datasets."""
        # Test large attributes list
        large_attributes = [f"attr{i}" for i in range(1000)]
        attributes_result = validations.validate_attributes(large_attributes)
        assert attributes_result.is_success

        # Test multiple validations
        for i in range(100):
            dn_result = validations.validate_dn(
                f"uid=user{i},ou=people,dc=example,dc=com"
            )
            assert dn_result.is_success

            email_result = validations.validate_email(f"user{i}@example.com")
            assert email_result.is_success

            filter_result = validations.validate_filter(f"(uid=user{i})")
            assert filter_result.is_success
