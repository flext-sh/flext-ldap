"""Comprehensive tests for FlextLdapUtilities.

This module provides complete test coverage for the FlextLdapUtilities class
following FLEXT standards with proper domain separation and centralized fixtures.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from flext_ldap import FlextLdapUtilities


class TestFlextLdapUtilities:
    """Comprehensive test suite for FlextLdapUtilities."""

    def test_utilities_initialization(self) -> None:
        """Test utilities initialization."""
        utilities = FlextLdapUtilities()
        assert utilities is not None
        # FlextLdapUtilities extends FlextUtilities but doesn't have _container and _logger
        assert hasattr(utilities, "LdapTypeGuards")
        assert hasattr(utilities, "LdapProcessing")
        assert hasattr(utilities, "LdapConversion")

    def test_normalize_dn_success(self) -> None:
        """Test successful DN normalization."""
        utilities = FlextLdapUtilities()

        result = utilities.normalize_dn("  uid=testuser,ou=people,dc=example,dc=com  ")

        assert result.is_success
        assert result.data == "uid=testuser,ou=people,dc=example,dc=com"

    def test_normalize_dn_empty(self) -> None:
        """Test DN normalization with empty string."""
        utilities = FlextLdapUtilities()

        result = utilities.normalize_dn("")

        assert result.is_failure
        assert "DN must be a non-empty string" in result.error

    def test_normalize_dn_none(self) -> None:
        """Test DN normalization with None."""
        utilities = FlextLdapUtilities()

        result = utilities.normalize_dn(None)

        # assert result.is_failure
        assert result.error is not None
        assert "DN must be a non-empty string" in result.error

    def test_normalize_filter_success(self) -> None:
        """Test successful filter normalization."""
        utilities = FlextLdapUtilities()

        result = utilities.normalize_filter("  (objectClass=person)  ")

        assert result.is_success
        assert result.is_success
        assert result.data == "(objectClass=person)"

    def test_normalize_filter_empty(self) -> None:
        """Test filter normalization with empty string."""
        utilities = FlextLdapUtilities()

        result = utilities.normalize_filter("")

        assert result.is_failure
        assert result.error is not None

    def test_normalize_filter_none(self) -> None:
        """Test filter normalization with None."""
        utilities = FlextLdapUtilities()

        result = utilities.normalize_filter(None)

        # assert result.is_failure
        assert result.error is not None
        assert "Filter must be a non-empty string" in result.error

    def test_normalize_attributes_success(self) -> None:
        """Test successful attributes normalization."""
        utilities = FlextLdapUtilities()

        result = utilities.normalize_attributes(["  cn  ", "  sn  ", "  mail  "])

        assert result.is_success
        assert result.data == ["cn", "sn", "mail"]

    def test_normalize_attributes_string(self) -> None:
        """Test attributes normalization with string input."""
        utilities = FlextLdapUtilities()

        result = utilities.normalize_attributes(["cn", "sn", "mail"])

        assert result.is_success
        assert result.data == ["cn", "sn", "mail"]

    def test_normalize_attributes_empty(self) -> None:
        """Test attributes normalization with empty list."""
        utilities = FlextLdapUtilities()

        result = utilities.normalize_attributes([])

        assert result.is_failure
        assert result.error is not None

    def test_normalize_attributes_none(self) -> None:
        """Test attributes normalization with None."""
        utilities = FlextLdapUtilities()

        result = utilities.normalize_attributes(None)

        # assert result.is_failure
        assert result.error is not None
        assert "Attributes list cannot be empty" in result.error

    def test_attributes_to_dict_success(self) -> None:
        """Test successful attributes to dict conversion."""
        utilities = FlextLdapUtilities()

        attributes = ["cn", "sn", "mail"]
        values = [["Test User"], ["User"], ["testuser@example.com"]]

        result = utilities.LdapConversion.attributes_to_dict(attributes, values)

        assert result.is_success
        assert result.value == {
            "cn": "Test User",
            "sn": "User",
            "mail": "testuser@example.com",
        }

    def test_attributes_to_dict_mismatched_lengths(self) -> None:
        """Test attributes to dict with mismatched lengths."""
        utilities = FlextLdapUtilities()

        attributes = ["cn", "sn", "mail"]
        values = [["Test User"], ["User"]]  # Missing mail values

        result = utilities.LdapConversion.attributes_to_dict(attributes, values)

        # assert result.is_failure
        assert result.error is not None
        assert "Attribute names and values length mismatch" in result.error

    def test_attributes_to_dict_empty(self) -> None:
        """Test attributes to dict with empty inputs."""
        utilities = FlextLdapUtilities()

        result = utilities.LdapConversion.attributes_to_dict([], [])

        assert result.is_success
        assert result.value == {}

    def test_dict_to_attributes_success(self) -> None:
        """Test successful dict to attributes conversion."""
        utilities = FlextLdapUtilities()

        data_dict = {
            "cn": "Test User",
            "sn": "User",
            "mail": "testuser@example.com",
        }

        result = utilities.dict_to_attributes(data_dict)

        assert result.is_success
        assert result.data == (
            ["cn", "sn", "mail"],
            ["Test User", "User", "testuser@example.com"],
        )

    def test_dict_to_attributes_empty(self) -> None:
        """Test dict to attributes with empty dict."""
        utilities = FlextLdapUtilities()

        result = utilities.dict_to_attributes({})

        assert result.is_success
        assert result.data == ([], [])

    def test_dict_to_attributes_none(self) -> None:
        """Test dict to attributes with None."""
        utilities = FlextLdapUtilities()

        import pytest

        with pytest.raises(AttributeError):
            utilities.dict_to_attributes(None)

    def test_type_guards_is_ldap_dn_valid(self) -> None:
        """Test is_ldap_dn type guard with valid DN."""
        utilities = FlextLdapUtilities()

        result = utilities.is_ldap_dn("uid=testuser,ou=people,dc=example,dc=com")

        assert result is True

    def test_type_guards_is_ldap_dn_invalid(self) -> None:
        """Test is_ldap_dn type guard with invalid DN."""
        utilities = FlextLdapUtilities()

        result = utilities.is_ldap_dn("invalid-dn-format")

        assert result is False

    def test_type_guards_is_ldap_dn_none(self) -> None:
        """Test is_ldap_dn type guard with None."""
        utilities = FlextLdapUtilities()

        result = utilities.is_ldap_dn(None)

        assert result is False

    def test_type_guards_is_ldap_dn_empty(self) -> None:
        """Test is_ldap_dn type guard with empty string."""
        utilities = FlextLdapUtilities()

        result = utilities.is_ldap_dn("")

        assert result is False

    def test_type_guards_is_ldap_filter_valid(self) -> None:
        """Test is_ldap_filter type guard with valid filter."""
        utilities = FlextLdapUtilities()

        result = utilities.is_ldap_filter("(objectClass=person)")

        assert result is True

    def test_type_guards_is_ldap_filter_invalid(self) -> None:
        """Test is_ldap_filter type guard with invalid filter."""
        utilities = FlextLdapUtilities()

        result = utilities.is_ldap_filter("invalid-filter")

        assert result is False

    def test_type_guards_is_ldap_filter_none(self) -> None:
        """Test is_ldap_filter type guard with None."""
        utilities = FlextLdapUtilities()

        result = utilities.is_ldap_filter(None)

        assert result is False

    def test_type_guards_is_string_list_valid(self) -> None:
        """Test is_string_list type guard with valid string list."""
        utilities = FlextLdapUtilities()

        result = utilities.is_string_list(["cn", "sn", "mail"])

        assert result is True

    def test_type_guards_is_string_list_mixed_types(self) -> None:
        """Test is_string_list type guard with mixed types."""
        utilities = FlextLdapUtilities()

        result = utilities.is_string_list(["cn", 123, "mail"])

        assert result is False

    def test_type_guards_is_string_list_non_list(self) -> None:
        """Test is_string_list type guard with non-list."""
        utilities = FlextLdapUtilities()

        result = utilities.is_string_list("not-a-list")

        assert result is False

    def test_type_guards_is_string_list_none(self) -> None:
        """Test is_string_list type guard with None."""
        utilities = FlextLdapUtilities()

        result = utilities.is_string_list(None)

        assert result is False

    def test_type_guards_is_bytes_list_valid(self) -> None:
        """Test is_bytes_list type guard with valid bytes list."""
        utilities = FlextLdapUtilities()

        result = utilities.is_bytes_list([b"cn", b"sn", b"mail"])

        assert result is True

    def test_type_guards_is_bytes_list_mixed_types(self) -> None:
        """Test is_bytes_list type guard with mixed types."""
        utilities = FlextLdapUtilities()

        result = utilities.is_bytes_list([b"cn", "sn", b"mail"])

        assert result is False

    def test_type_guards_is_bytes_list_non_list(self) -> None:
        """Test is_bytes_list type guard with non-list."""
        utilities = FlextLdapUtilities()

        result = utilities.is_bytes_list(b"not-a-list")

        assert result is False

    def test_type_guards_is_bytes_list_none(self) -> None:
        """Test is_bytes_list type guard with None."""
        utilities = FlextLdapUtilities()

        result = utilities.is_bytes_list(None)

        assert result is False

    def test_type_guards_is_ldap_attribute_value_valid_string(self) -> None:
        """Test is_ldap_attribute_value type guard with valid string."""
        utilities = FlextLdapUtilities()

        result = utilities.is_ldap_attribute_value("test value")

        assert result is True

    def test_type_guards_is_ldap_attribute_value_valid_bytes(self) -> None:
        """Test is_ldap_attribute_value type guard with valid bytes."""
        utilities = FlextLdapUtilities()

        result = utilities.is_ldap_attribute_value(b"test value")

        assert result is True

    def test_type_guards_is_ldap_attribute_value_invalid(self) -> None:
        """Test is_ldap_attribute_value type guard with invalid value."""
        utilities = FlextLdapUtilities()

        result = utilities.is_ldap_attribute_value(123)

        assert result is False

    def test_type_guards_is_ldap_attribute_value_none(self) -> None:
        """Test is_ldap_attribute_value type guard with None."""
        utilities = FlextLdapUtilities()

        result = utilities.is_ldap_attribute_value(None)

        assert result is False

    def test_type_guards_is_ldap_attributes_dict_valid(self) -> None:
        """Test is_ldap_attributes_dict type guard with valid dict."""
        utilities = FlextLdapUtilities()

        result = utilities.is_ldap_attributes_dict({
            "cn": "Test User",
            "sn": "User",
        })

        assert result is True

    def test_type_guards_is_ldap_attributes_dict_invalid(self) -> None:
        """Test is_ldap_attributes_dict type guard with invalid dict."""
        utilities = FlextLdapUtilities()

        result = utilities.is_ldap_attributes_dict({
            "cn": "Test User",  # String values are valid
            "sn": "User",
        })

        assert result is True

    def test_type_guards_is_ldap_attributes_dict_non_dict(self) -> None:
        """Test is_ldap_attributes_dict type guard with non-dict."""
        utilities = FlextLdapUtilities()

        result = utilities.is_ldap_attributes_dict("not-a-dict")

        assert result is False

    def test_type_guards_is_ldap_attributes_dict_none(self) -> None:
        """Test is_ldap_attributes_dict type guard with None."""
        utilities = FlextLdapUtilities()

        result = utilities.is_ldap_attributes_dict(None)

        assert result is False

    def test_type_guards_is_ldap_entry_data_valid(self) -> None:
        """Test is_ldap_entry_data type guard with valid entry."""
        utilities = FlextLdapUtilities()

        result = utilities.is_ldap_entry_data({
            "dn": "uid=testuser,ou=people,dc=example,dc=com",
            "attributes": {"cn": "Test User", "sn": "User"},
        })

        assert result is True

    def test_type_guards_is_ldap_entry_data_missing_dn(self) -> None:
        """Test is_ldap_entry_data type guard with missing DN."""
        utilities = FlextLdapUtilities()

        result = utilities.is_ldap_entry_data({
            "attributes": {"cn": "Test User", "sn": "User"}
        })

        assert result is False

    def test_type_guards_is_ldap_entry_data_missing_attributes(self) -> None:
        """Test is_ldap_entry_data type guard with missing attributes."""
        utilities = FlextLdapUtilities()

        result = utilities.is_ldap_entry_data({
            "dn": "uid=testuser,ou=people,dc=example,dc=com"
        })

        assert result is True

    def test_type_guards_is_ldap_entry_data_non_dict(self) -> None:
        """Test is_ldap_entry_data type guard with non-dict."""
        utilities = FlextLdapUtilities()

        result = utilities.is_ldap_entry_data("not-a-dict")

        assert result is False

    def test_type_guards_is_ldap_entry_data_none(self) -> None:
        """Test is_ldap_entry_data type guard with None."""
        utilities = FlextLdapUtilities()

        result = utilities.is_ldap_entry_data(None)

        assert result is False

    def test_type_guards_is_ldap_search_result_valid(self) -> None:
        """Test is_ldap_search_result type guard with valid result."""
        utilities = FlextLdapUtilities()

        result = utilities.is_ldap_search_result([
            {
                "dn": "uid=testuser,ou=people,dc=example,dc=com",
                "attributes": {"cn": "Test User"},
            }
        ])

        assert result is True

    def test_type_guards_is_ldap_search_result_invalid_entries(self) -> None:
        """Test is_ldap_search_result type guard with invalid entries."""
        utilities = FlextLdapUtilities()

        result = utilities.is_ldap_search_result([
            "invalid-entry"  # Should be dict
        ])

        assert result is False

    def test_type_guards_is_ldap_search_result_non_list(self) -> None:
        """Test is_ldap_search_result type guard with non-list."""
        utilities = FlextLdapUtilities()

        result = utilities.is_ldap_search_result("not-a-list")

        assert result is False

    def test_type_guards_is_ldap_search_result_none(self) -> None:
        """Test is_ldap_search_result type guard with None."""
        utilities = FlextLdapUtilities()

        result = utilities.is_ldap_search_result(None)

        assert result is False

    def test_type_guards_is_connection_result_valid(self) -> None:
        """Test is_connection_result type guard with valid result."""
        utilities = FlextLdapUtilities()

        result = utilities.is_connection_result({
            "server": "localhost",
            "port": 389,
            "use_ssl": False,
        })

        assert result is True

    def test_type_guards_is_connection_result_missing_fields(self) -> None:
        """Test is_connection_result type guard with missing fields."""
        utilities = FlextLdapUtilities()

        result = utilities.LdapTypeGuards.is_connection_result({
            "connected": True
            # Missing server_uri and bind_dn
        })

        assert result is False

    def test_type_guards_is_connection_result_non_dict(self) -> None:
        """Test is_connection_result type guard with non-dict."""
        utilities = FlextLdapUtilities()

        result = utilities.LdapTypeGuards.is_connection_result("not-a-dict")

        assert result is False

    def test_type_guards_is_connection_result_none(self) -> None:
        """Test is_connection_result type guard with None."""
        utilities = FlextLdapUtilities()

        result = utilities.is_connection_result(None)

        assert result is False

    def test_ensure_string_list_string_input(self) -> None:
        """Test ensure_string_list with string input."""
        utilities = FlextLdapUtilities()

        result = utilities.LdapTypeGuards.ensure_string_list("cn,sn,mail")

        # assert result.is_success
        assert result == ["cn,sn,mail"]

    def test_ensure_string_list_list_input(self) -> None:
        """Test ensure_string_list with list input."""
        utilities = FlextLdapUtilities()

        result = utilities.LdapTypeGuards.ensure_string_list(["cn", "sn", "mail"])

        # assert result.is_success
        assert result == ["cn", "sn", "mail"]

    def test_ensure_string_list_mixed_types(self) -> None:
        """Test ensure_string_list with mixed types."""
        utilities = FlextLdapUtilities()

        result = utilities.LdapTypeGuards.ensure_string_list(["cn", 123, "mail"])

        # assert result.is_success
        assert result == ["cn", "123", "mail"]  # Converted to strings

    def test_ensure_string_list_empty(self) -> None:
        """Test ensure_string_list with empty list."""
        utilities = FlextLdapUtilities()

        result = utilities.LdapTypeGuards.ensure_string_list([])

        # assert result.is_success
        assert result == []

    def test_ensure_string_list_none(self) -> None:
        """Test ensure_string_list with None."""
        utilities = FlextLdapUtilities()

        result = utilities.ensure_string_list(None)

        assert result.is_success
        assert result.data == ["None"]

    def test_ensure_ldap_dn_valid(self) -> None:
        """Test ensure_ldap_dn with valid DN."""
        utilities = FlextLdapUtilities()

        result = utilities.ensure_ldap_dn("uid=testuser,ou=people,dc=example,dc=com")

        assert result.is_success
        assert result.is_success
        assert result.data == "uid=testuser,ou=people,dc=example,dc=com"

    def test_ensure_ldap_dn_invalid(self) -> None:
        """Test ensure_ldap_dn with invalid DN."""
        utilities = FlextLdapUtilities()

        result = utilities.ensure_ldap_dn("invalid-dn-format")

        # assert result.is_failure
        assert "DN must contain at least one '=' character" in result.error

    def test_ensure_ldap_dn_empty(self) -> None:
        """Test ensure_ldap_dn with empty string."""
        utilities = FlextLdapUtilities()

        result = utilities.ensure_ldap_dn("")

        # assert result.is_failure
        assert "DN cannot be empty" in result.error

    def test_ensure_ldap_dn_none(self) -> None:
        """Test ensure_ldap_dn with None."""
        utilities = FlextLdapUtilities()

        result = utilities.ensure_ldap_dn(None)

        assert result.is_failure
        assert "DN must be a string" in result.error

    def test_utilities_integration_complete_workflow(self) -> None:
        """Test complete utilities workflow integration."""
        utilities = FlextLdapUtilities()

        # Test complete workflow
        dn_result = utilities.normalize_dn(
            "  uid=testuser,ou=people,dc=example,dc=com  "
        )
        assert dn_result.is_success

        filter_result = utilities.normalize_filter("  (objectClass=person)  ")
        assert filter_result.is_success

        attributes_result = utilities.normalize_attributes([
            "  cn  ",
            "  sn  ",
            "  mail  ",
        ])
        assert attributes_result.is_success

        # Test type guards
        dn_valid = utilities.is_ldap_dn(dn_result.data)
        assert dn_valid is True

        filter_valid = utilities.is_ldap_filter(filter_result.data)
        assert filter_valid is True

        attributes_valid = utilities.is_string_list(attributes_result.data)
        assert attributes_valid is True

        # Test conversion
        data_dict = {
            "cn": "Test User",
            "sn": "User",
            "mail": "testuser@example.com",
        }

        dict_result = utilities.dict_to_attributes(data_dict)
        assert dict_result.is_success

        attributes, values = dict_result.data
        attr_dict_result = utilities.LdapConversion.attributes_to_dict(
            attributes, values
        )
        assert attr_dict_result.is_success
        assert attr_dict_result.data == data_dict

    def test_utilities_error_handling_consistency(self) -> None:
        """Test consistent error handling across utility methods."""
        utilities = FlextLdapUtilities()

        # Test consistent None handling
        dn_result = utilities.normalize_dn(None)
        assert dn_result.is_failure
        assert dn_result.error is not None
        assert "DN must be a non-empty string" in dn_result.error

        filter_result = utilities.normalize_filter(None)
        assert filter_result.is_failure
        assert filter_result.error is not None
        assert "Filter must be a non-empty string" in filter_result.error

        attributes_result = utilities.normalize_attributes(None)
        assert attributes_result.is_failure
        assert attributes_result.error is not None
        assert "Attributes list cannot be empty" in attributes_result.error

        # dict_to_attributes raises AttributeError for None input
        import pytest

        with pytest.raises(AttributeError):
            utilities.dict_to_attributes(None)

    def test_utilities_performance_large_datasets(self) -> None:
        """Test utilities performance with large datasets."""
        utilities = FlextLdapUtilities()

        # Test large attributes list
        large_attributes = [f"attr{i}" for i in range(1000)]
        large_values = [[f"value{i}"] for i in range(1000)]

        dict_result = utilities.LdapConversion.attributes_to_dict(
            large_attributes, large_values
        )
        assert dict_result.is_success
        assert len(dict_result.data) == 1000

        # Test conversion back
        attributes, values = utilities.dict_to_attributes(dict_result.data).data
        assert len(attributes) == 1000
        assert len(values) == 1000

        # Test type guard performance
        for i in range(100):
            dn_valid = utilities.is_ldap_dn(f"uid=user{i},ou=people,dc=example,dc=com")
            assert dn_valid is True
