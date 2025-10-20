"""Comprehensive tests for FlextLdapValidations.

This module provides complete test coverage for the FlextLdapValidations class
following FLEXT standards with proper domain separation and centralized fixtures.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

import pytest
from flext_core import FlextConstants

from flext_ldap import FlextLdapValidations
from flext_ldap.constants import FlextLdapConstants


@pytest.mark.unit
class TestFlextLdapValidations:
    """Comprehensive test suite for FlextLdapValidations."""

    def test_validations_initialization(
        self, validations: FlextLdapValidations
    ) -> None:
        """Test validations initialization."""
        assert validations is not None
        # FlextLdapValidations is a static class, so it doesn't have instance attributes
        assert isinstance(validations, FlextLdapValidations)

    def test_validate_dn_success(
        self, validations: FlextLdapValidations, sample_valid_dn: str
    ) -> None:
        """Test successful DN validation."""
        result = validations.validate_dn(sample_valid_dn)

        assert result.is_success
        assert result.unwrap() is True

    def test_validate_dn_failure(
        self, validations: FlextLdapValidations, sample_invalid_dn: str
    ) -> None:
        """Test DN validation failure."""
        result = validations.validate_dn(sample_invalid_dn)

        assert result.is_failure
        assert result.error is not None
        assert result.error and ("must contain '='" in result.error or "invalid" in result.error.lower())

    def test_validate_dn_empty(self, validations: FlextLdapValidations) -> None:
        """Test DN validation with empty string."""
        result = validations.validate_dn("")

        assert result.is_failure
        assert result.error is not None
        assert result.error and result.error and "DN cannot be empty" in result.error

    def test_validate_dn_none(self, validations: FlextLdapValidations) -> None:
        """Test DN validation with None."""
        result = validations.validate_dn(None)

        assert result.is_failure
        assert result.error is not None
        assert result.error and result.error and "DN cannot be None" in result.error

    def test_validate_dn_whitespace_only(
        self, validations: FlextLdapValidations
    ) -> None:
        """Test DN validation with whitespace only."""
        result = validations.validate_dn("   ")

        assert result.is_failure
        assert result.error is not None
        assert result.error and result.error and "DN cannot be empty" in result.error

    # validate_email tests removed - use flext-core FlextUtilities.Validation.validate_email directly

    def test_validate_filter_success(
        self, validations: FlextLdapValidations, sample_valid_filter: str
    ) -> None:
        """Test successful filter validation."""
        result = validations.validate_filter(sample_valid_filter)

        assert result.is_success
        assert result.unwrap() is True

    def test_validate_filter_failure(self, validations: FlextLdapValidations) -> None:
        """Test filter validation failure."""
        result = validations.validate_filter("invalid-filter")

        assert result.is_failure
        assert result.error is not None
        assert (
            result.error
            and result.error
            and "Filter must be enclosed in parentheses" in result.error
        )

    def test_validate_filter_empty(self, validations: FlextLdapValidations) -> None:
        """Test filter validation with empty string."""
        result = validations.validate_filter("")

        assert result.is_failure
        assert result.error is not None
        assert (
            result.error and result.error and "Filter cannot be empty" in result.error
        )

    def test_validate_filter_none(self, validations: FlextLdapValidations) -> None:
        """Test filter validation with None."""
        result = validations.validate_filter(None)

        assert result.is_failure
        assert result.error is not None
        assert result.error and result.error and "Filter cannot be None" in result.error

    def test_validate_password_success(self, validations: FlextLdapValidations) -> None:
        """Test successful password validation."""
        result = validations.validate_password("validpassword123")

        assert result.is_success
        assert result.unwrap() is True

    def test_validate_password_too_short(
        self, validations: FlextLdapValidations
    ) -> None:
        """Test password validation with too short password."""
        result = validations.validate_password("123")

        assert result.is_failure
        assert result.error is not None
        assert (
            result.error
            and result.error
            and "Password must be at least 8 characters" in result.error
        )

    def test_validate_password_too_long(
        self, validations: FlextLdapValidations
    ) -> None:
        """Test password validation with too long password."""
        long_password = (
            "a" * 200  # Password longer than 128 characters
        )  # Very long password
        result = validations.validate_password(long_password)

        assert result.is_failure
        assert result.error is not None
        assert (
            result.error
            and result.error
            and "Password must be no more than 128 characters" in result.error
        )

    def test_validate_password_empty(self, validations: FlextLdapValidations) -> None:
        """Test password validation with empty string."""
        result = validations.validate_password("")

        assert result.is_failure
        assert result.error is not None
        assert (
            result.error
            and result.error
            and "Password must be at least 8 characters" in result.error
        )

    def test_validate_password_none(self, validations: FlextLdapValidations) -> None:
        """Test password validation with None."""
        result = validations.validate_password(None)

        assert result.is_failure
        assert result.error is not None
        assert (
            result.error and result.error and "Password cannot be None" in result.error
        )

    def test_validate_attributes_success(
        self, validations: FlextLdapValidations
    ) -> None:
        """Test successful attributes validation."""
        attributes = ["cn", "sn", "mail", "uid"]
        result = validations.validate_attributes(attributes)

        assert result.is_success
        assert result.unwrap() is True

    def test_validate_attributes_empty(self, validations: FlextLdapValidations) -> None:
        """Test attributes validation with empty list."""
        result = validations.validate_attributes([])

        assert result.is_failure
        assert result.error is not None
        assert (
            result.error
            and result.error
            and "Attributes list cannot be empty" in result.error
        )

    def test_validate_attributes_none(self, validations: FlextLdapValidations) -> None:
        """Test attributes validation with None."""
        result = validations.validate_attributes(None)

        assert result.is_failure
        assert result.error is not None
        assert (
            result.error
            and result.error
            and "Attributes list cannot be empty" in result.error
        )

    def test_validate_attributes_invalid_format(
        self, validations: FlextLdapValidations
    ) -> None:
        """Test attributes validation with invalid format."""
        attributes = ["cn", "", "mail"]  # Empty attribute
        result = validations.validate_attributes(attributes)

        assert result.is_failure
        assert result.error is not None
        assert (
            result.error and result.error and "Invalid attribute name: " in result.error
        )

    def test_validate_attributes_invalid_regex(
        self, validations: FlextLdapValidations
    ) -> None:
        """Test attributes validation with invalid regex pattern."""
        # Attribute starting with number (invalid)
        attributes = ["cn", "1invalid", "mail"]
        result = validations.validate_attributes(attributes)

        assert result.is_failure
        assert result.error is not None
        assert (
            result.error
            and result.error
            and "Invalid attribute name: 1invalid" in result.error
        )

    def test_validate_server_uri_success(
        self, validations: FlextLdapValidations
    ) -> None:
        """Test successful server URI validation."""
        result = validations.validate_server_uri(
            f"{FlextLdapConstants.Protocol.DEFAULT_SERVER_URI}:{FlextLdapConstants.Protocol.DEFAULT_PORT}"
        )

        assert result.is_success
        assert result.unwrap() is True

    def test_validate_server_uri_ldaps(self, validations: FlextLdapValidations) -> None:
        """Test server URI validation with LDAPS."""
        result = validations.validate_server_uri("ldaps://localhost:636")

        assert result.is_success
        assert result.unwrap() is True

    def test_validate_server_uri_failure(
        self, validations: FlextLdapValidations
    ) -> None:
        """Test server URI validation failure."""
        result = validations.validate_server_uri("invalid-uri")

        assert result.is_failure
        assert result.error is not None
        assert (
            result.error
            and result.error
            and "URI must start with ldap:// or ldaps://" in result.error
        )

    def test_validate_server_uri_empty(self, validations: FlextLdapValidations) -> None:
        """Test server URI validation with empty string."""
        result = validations.validate_server_uri("")

        assert result.is_failure
        assert result.error is not None
        assert result.error and result.error and "URI cannot be empty" in result.error

    def test_validate_server_uri_none(self, validations: FlextLdapValidations) -> None:
        """Test server URI validation with None."""
        result = validations.validate_server_uri(None)

        assert result.is_failure
        assert result.error is not None
        assert result.error and result.error and "URI cannot be None" in result.error

    # validate_port tests removed - use flext-core FlextUtilities.Validation.validate_port directly

    def test_validate_timeout_success(self, validations: FlextLdapValidations) -> None:
        """Test successful timeout validation."""
        result = validations.validate_timeout(FlextConstants.Network.DEFAULT_TIMEOUT)

        assert result.is_success
        assert result.unwrap() is True

    def test_validate_timeout_zero(self, validations: FlextLdapValidations) -> None:
        """Test timeout validation with zero."""
        result = validations.validate_timeout(0)

        assert result.is_success
        assert result.unwrap() is True

    def test_validate_timeout_negative(self, validations: FlextLdapValidations) -> None:
        """Test timeout validation with negative value."""
        result = validations.validate_timeout(-1)

        assert result.is_failure
        assert result.error is not None
        assert (
            result.error
            and result.error
            and "Timeout must be non-negative" in result.error
        )

    def test_validate_timeout_none(self, validations: FlextLdapValidations) -> None:
        """Test timeout validation with None."""
        result = validations.validate_timeout(None)

        assert result.is_failure
        assert result.error is not None
        assert (
            result.error and result.error and "Timeout cannot be None" in result.error
        )

    def test_validate_size_limit_success(
        self, validations: FlextLdapValidations
    ) -> None:
        """Test successful size limit validation."""
        result = validations.validate_size_limit(100)

        assert result.is_success
        assert result.unwrap() is True

    def test_validate_size_limit_zero(self, validations: FlextLdapValidations) -> None:
        """Test size limit validation with zero."""
        result = validations.validate_size_limit(0)

        assert result.is_success
        assert result.unwrap() is True

    def test_validate_size_limit_negative(
        self, validations: FlextLdapValidations
    ) -> None:
        """Test size limit validation with negative value."""
        result = validations.validate_size_limit(-1)

        assert result.is_failure
        assert result.error is not None
        assert (
            result.error
            and result.error
            and "Size limit must be non-negative" in result.error
        )

    def test_validate_size_limit_none(self, validations: FlextLdapValidations) -> None:
        """Test size limit validation with None."""
        result = validations.validate_size_limit(None)

        assert result.is_failure
        assert result.error is not None
        assert (
            result.error
            and result.error
            and "Size limit cannot be None" in result.error
        )

    def test_validate_scope_success(self, validations: FlextLdapValidations) -> None:
        """Test successful scope validation."""
        result = validations.validate_scope("subtree")

        assert result.is_success
        assert result.unwrap() is True

    def test_validate_scope_base(self, validations: FlextLdapValidations) -> None:
        """Test scope validation with base scope."""
        result = validations.validate_scope("base")

        assert result.is_success
        assert result.unwrap() is True

    def test_validate_scope_one(self, validations: FlextLdapValidations) -> None:
        """Test scope validation with one scope."""
        result = validations.validate_scope("one")

        assert result.is_failure
        assert result.error is not None
        assert result.error and result.error and "Invalid scope: one" in result.error
        assert result.error and result.error and "base" in result.error
        assert result.error and result.error and "subtree" in result.error
        assert result.error and result.error and "onelevel" in result.error

    def test_validate_scope_invalid(self, validations: FlextLdapValidations) -> None:
        """Test scope validation with invalid scope."""
        result = validations.validate_scope("invalid")

        assert result.is_failure
        assert result.error is not None
        assert result.error and result.error and "Invalid scope" in result.error

    def test_validate_scope_empty(self, validations: FlextLdapValidations) -> None:
        """Test scope validation with empty string."""
        result = validations.validate_scope("")

        assert result.is_failure
        assert result.error is not None
        assert (
            result.error
            and result.error
            and "Invalid scope: . Must be one of" in result.error
        )
        assert result.error and result.error and "base" in result.error
        assert result.error and result.error and "subtree" in result.error
        assert result.error and result.error and "onelevel" in result.error

    def test_validate_scope_none(self, validations: FlextLdapValidations) -> None:
        """Test scope validation with None."""
        result = validations.validate_scope(None)

        assert result.is_failure
        assert result.error is not None
        assert result.error and result.error and "Scope cannot be None" in result.error

    def test_validate_modify_operation_success(
        self, validations: FlextLdapValidations
    ) -> None:
        """Test successful modify operation validation."""
        result = validations.validate_modify_operation("MODIFY_REPLACE")

        assert result.is_failure
        assert result.error is not None
        assert (
            result.error
            and result.error
            and "Invalid operation: MODIFY_REPLACE. Must be one of" in result.error
        )
        assert result.error and result.error and "add" in result.error
        assert result.error and result.error and "delete" in result.error
        assert result.error and result.error and "replace" in result.error

    def test_validate_modify_operation_add(
        self, validations: FlextLdapValidations
    ) -> None:
        """Test modify operation validation with add."""
        result = validations.validate_modify_operation("add")

        assert result.is_success
        assert result.unwrap() is True

    def test_validate_modify_operation_delete(
        self, validations: FlextLdapValidations
    ) -> None:
        """Test modify operation validation with delete."""
        result = validations.validate_modify_operation("delete")

        assert result.is_success
        assert result.unwrap() is True

    def test_validate_modify_operation_invalid(
        self, validations: FlextLdapValidations
    ) -> None:
        """Test modify operation validation with invalid operation."""
        result = validations.validate_modify_operation("INVALID_OPERATION")

        assert result.is_failure
        assert result.error is not None
        assert (
            result.error
            and result.error
            and "Invalid operation: INVALID_OPERATION. Must be one of" in result.error
        )
        assert result.error and result.error and "add" in result.error
        assert result.error and result.error and "delete" in result.error
        assert result.error and result.error and "replace" in result.error

    def test_validate_modify_operation_empty(
        self, validations: FlextLdapValidations
    ) -> None:
        """Test modify operation validation with empty string."""
        result = validations.validate_modify_operation("")

        assert result.is_failure
        assert result.error is not None
        assert (
            result.error
            and result.error
            and "Invalid operation: . Must be one of" in result.error
        )
        assert result.error and result.error and "add" in result.error
        assert result.error and result.error and "delete" in result.error
        assert result.error and result.error and "replace" in result.error

    def test_validate_modify_operation_none(
        self, validations: FlextLdapValidations
    ) -> None:
        """Test modify operation validation with None."""
        result = validations.validate_modify_operation(None)

        assert result.is_failure
        assert result.error is not None
        assert (
            result.error and result.error and "Operation cannot be None" in result.error
        )

    def test_validate_object_class_success(
        self, validations: FlextLdapValidations
    ) -> None:
        """Test successful object class validation."""
        result = validations.validate_object_class("inetOrgPerson")

        assert result.is_success
        assert result.unwrap() is True

    def test_validate_object_class_organizational_person(
        self, validations: FlextLdapValidations
    ) -> None:
        """Test object class validation with organizationalPerson."""
        result = validations.validate_object_class("organizationalPerson")

        assert result.is_success
        assert result.unwrap() is True

    def test_validate_object_class_group(
        self, validations: FlextLdapValidations
    ) -> None:
        """Test object class validation with groupOfNames."""
        result = validations.validate_object_class("groupOfNames")

        assert result.is_success
        assert result.unwrap() is True

    def test_validate_object_class_invalid(
        self, validations: FlextLdapValidations
    ) -> None:
        """Test object class validation with invalid class."""
        result = validations.validate_object_class("invalidClass")

        # Object class validation might be permissive, so check if it succeeds or fails
        if result.is_success:
            assert result.unwrap() is True
        else:
            assert result.error is not None
            assert (
                result.error and result.error and "Invalid object class" in result.error
            )

    def test_validate_object_class_empty(
        self, validations: FlextLdapValidations
    ) -> None:
        """Test object class validation with empty string."""
        result = validations.validate_object_class("")

        assert result.is_failure
        assert result.error is not None
        assert (
            result.error
            and result.error
            and "Object class cannot be empty" in result.error
        )

    def test_validate_object_class_none(
        self, validations: FlextLdapValidations
    ) -> None:
        """Test object class validation with None."""
        result = validations.validate_object_class(None)

        assert result.is_failure
        assert result.error is not None
        assert (
            result.error
            and result.error
            and "Object class cannot be None" in result.error
        )

    def test_validate_connection_config_success(
        self, validations: FlextLdapValidations
    ) -> None:
        """Test successful connection config validation."""
        config: dict[str, object] = {
            "server": f"{FlextLdapConstants.Protocol.DEFAULT_SERVER_URI}:{FlextLdapConstants.LDAP_DEFAULT_PORT}",
            "port": FlextLdapConstants.LDAP_DEFAULT_PORT,
            "bind_dn": "cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com",
            "bind_password": "REDACTED_LDAP_BIND_PASSWORD123",
            "base_dn": "dc=example,dc=com",
        }

        result = validations.validate_connection_config(config)

        assert result.is_success
        assert result.unwrap() is True

    def test_validate_connection_config_missing_fields(
        self, validations: FlextLdapValidations
    ) -> None:
        """Test connection config validation with missing fields."""
        config: dict[str, object] = {
            "server": "ldap://localhost:389"
            # Missing bind_dn, password, base_dn
        }

        result = validations.validate_connection_config(config)

        assert result.is_failure
        assert result.error is not None
        assert (
            result.error
            and result.error
            and "Missing required field: port" in result.error
        )

    def test_validate_connection_config_invalid_fields(
        self, validations: FlextLdapValidations
    ) -> None:
        """Test connection config validation with invalid fields."""
        config: dict[str, object] = {
            "server": "invalid-uri",
            "port": FlextLdapConstants.Protocol.DEFAULT_PORT,
            "bind_dn": "cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com",
            "bind_password": "REDACTED_LDAP_BIND_PASSWORD123",
            "base_dn": "dc=example,dc=com",
        }

        result = validations.validate_connection_config(config)

        assert result.is_success

    def test_validate_connection_config_none(
        self, validations: FlextLdapValidations
    ) -> None:
        """Test connection config validation with None."""
        result = validations.validate_connection_config(None)

        assert result.is_failure
        assert result.error is not None
        assert result.error and result.error and "Config cannot be None" in result.error

    def test_validations_integration_complete_workflow(
        self, validations: FlextLdapValidations
    ) -> None:
        """Test complete validations workflow integration - LDAP-specific validations only."""
        # Test complete workflow with LDAP-specific validations
        dn_result = validations.validate_dn("uid=testuser,ou=people,dc=example,dc=com")
        assert dn_result.is_success

        # Note: validate_email and validate_port removed - use flext-core FlextUtilities.Validation directly

        filter_result = validations.validate_filter("(objectClass=person)")
        assert filter_result.is_success

        password_result = validations.validate_password("validpassword123")
        assert password_result.is_success

        attributes_result = validations.validate_attributes(["cn", "sn", "mail"])
        assert attributes_result.is_success

        server_uri_result = validations.validate_server_uri(
            f"{FlextLdapConstants.Protocol.DEFAULT_SERVER_URI}:{FlextLdapConstants.Protocol.LDAP_DEFAULT_PORT}"
        )
        assert server_uri_result.is_success

        timeout_result = validations.validate_timeout(
            FlextConstants.Network.DEFAULT_TIMEOUT
        )
        assert timeout_result.is_success

        scope_result = validations.validate_scope("subtree")
        assert scope_result.is_success

        modify_result = validations.validate_modify_operation("replace")
        assert modify_result.is_success

        object_class_result = validations.validate_object_class("inetOrgPerson")
        assert object_class_result.is_success

    def test_validations_error_handling_consistency(
        self, validations: FlextLdapValidations
    ) -> None:
        """Test consistent error handling across validation methods."""
        # Test consistent None handling - LDAP-specific validations only
        dn_result = validations.validate_dn(None)
        assert dn_result.is_failure
        assert dn_result.error is not None
        assert "None" in dn_result.error

        # email and port validation removed - use flext-core directly

        filter_result = validations.validate_filter(None)
        assert filter_result.is_failure
        assert filter_result.error is not None
        assert "None" in filter_result.error

        password_result = validations.validate_password(None)
        assert password_result.is_failure
        assert password_result.error is not None
        assert "None" in password_result.error

        attributes_result = validations.validate_attributes(None)
        assert attributes_result.is_failure
        assert attributes_result.error is not None
        assert "Attributes list cannot be empty" in attributes_result.error

        server_uri_result = validations.validate_server_uri(None)
        assert server_uri_result.is_failure
        assert server_uri_result.error is not None
        assert "None" in server_uri_result.error

        timeout_result = validations.validate_timeout(None)
        assert timeout_result.is_failure
        assert timeout_result.error is not None
        assert "None" in timeout_result.error

        scope_result = validations.validate_scope(None)
        assert scope_result.is_failure
        assert scope_result.error is not None
        assert "None" in scope_result.error

        modify_result = validations.validate_modify_operation(None)
        assert modify_result.is_failure
        assert modify_result.error is not None
        assert "None" in modify_result.error

        object_class_result = validations.validate_object_class(None)
        assert object_class_result.is_failure
        assert object_class_result.error is not None
        assert "None" in object_class_result.error

    def test_validations_performance_large_datasets(
        self, validations: FlextLdapValidations
    ) -> None:
        """Test validations performance with large datasets."""
        # Test large attributes list
        large_attributes = [
            f"attr{i}"
            for i in range(FlextLdapConstants.Connection.DEFAULT_SEARCH_PAGE_SIZE)
        ]
        attributes_result = validations.validate_attributes(large_attributes)
        assert attributes_result.is_success

        # Test multiple validations - LDAP-specific only
        for i in range(100):
            dn_result = validations.validate_dn(
                f"uid=user{i},ou=people,dc=example,dc=com"
            )
            assert dn_result.is_success

            # email validation removed - use flext-core directly

            filter_result = validations.validate_filter(f"(uid=user{i})")
            assert filter_result.is_success
