"""Additional tests for FlextLdapTypeGuards to achieve high coverage.

Target missing methods and edge cases in type_guards.py for maximum coverage improvement.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import pytest

from flext_ldap.type_guards import FlextLdapTypeGuards


class TestFlextLdapTypeGuardsMissingCoverage:
    """Tests targeting specific uncovered lines in type_guards.py."""

    def test_ensure_string_list_coverage(self) -> None:
        """Test ensure_string_list method with all code paths."""
        # Test single string input
        result = FlextLdapTypeGuards.ensure_string_list("test")
        assert result == ["test"]

        # Test list of strings input (valid list)
        valid_list = ["one", "two", "three"]
        result = FlextLdapTypeGuards.ensure_string_list(valid_list)
        assert result == valid_list
        assert result is valid_list  # Should return same object

        # Test list with non-string items (conversion path)
        mixed_list = [1, 2.5, True, None]
        result = FlextLdapTypeGuards.ensure_string_list(mixed_list)
        assert result == ["1", "2.5", "True", "None"]

        # Test non-list, non-string input (fallback path)
        result = FlextLdapTypeGuards.ensure_string_list(42)
        assert result == ["42"]

        # Test object input
        result = FlextLdapTypeGuards.ensure_string_list({"key": "value"})
        assert result == ["{'key': 'value'}"]

    def test_ensure_ldap_dn_coverage(self) -> None:
        """Test ensure_ldap_dn method with all code paths."""
        # Test valid DN input (direct return path)
        valid_dn = "cn=test,dc=example,dc=com"
        result = FlextLdapTypeGuards.ensure_ldap_dn(valid_dn)
        assert result == valid_dn
        assert result is valid_dn  # Should return same object

        # Test string with equals (conversion path)
        string_with_equals = "attribute=value"
        result = FlextLdapTypeGuards.ensure_ldap_dn(string_with_equals)
        assert result == string_with_equals

        # Test invalid input that cannot be converted (error path)
        with pytest.raises(ValueError, match=r"Cannot convert .* to valid LDAP DN"):
            FlextLdapTypeGuards.ensure_ldap_dn("no-equals-sign")

        with pytest.raises(ValueError, match=r"Cannot convert .* to valid LDAP DN"):
            FlextLdapTypeGuards.ensure_ldap_dn("")

        with pytest.raises(ValueError, match=r"Cannot convert .* to valid LDAP DN"):
            FlextLdapTypeGuards.ensure_ldap_dn(None)

        with pytest.raises(ValueError, match=r"Cannot convert .* to valid LDAP DN"):
            FlextLdapTypeGuards.ensure_ldap_dn(123)

    def test_has_error_attribute_coverage(self) -> None:
        """Test has_error_attribute type guard."""

        # Test objects with error attribute
        class HasError:
            error = "some error"

        class HasErrorMethod:
            def error(self) -> str:
                return "error"

        class HasErrorProperty:
            @property
            def error(self) -> str:
                return "property error"

        assert FlextLdapTypeGuards.has_error_attribute(HasError())
        assert FlextLdapTypeGuards.has_error_attribute(HasErrorMethod())
        assert FlextLdapTypeGuards.has_error_attribute(HasErrorProperty())

        # Test objects without error attribute
        class NoError:
            pass

        assert not FlextLdapTypeGuards.has_error_attribute(NoError())
        assert not FlextLdapTypeGuards.has_error_attribute("string")
        assert not FlextLdapTypeGuards.has_error_attribute(123)
        assert not FlextLdapTypeGuards.has_error_attribute([])
        assert not FlextLdapTypeGuards.has_error_attribute({})

    def test_has_is_success_attribute_coverage(self) -> None:
        """Test has_is_success_attribute type guard."""

        # Test objects with is_success attribute
        class HasIsSuccess:
            is_success = True

        class HasIsSuccessMethod:
            def is_success(self) -> bool:
                return True

        class HasIsSuccessProperty:
            @property
            def is_success(self) -> bool:
                return False

        assert FlextLdapTypeGuards.has_is_success_attribute(HasIsSuccess())
        assert FlextLdapTypeGuards.has_is_success_attribute(HasIsSuccessMethod())
        assert FlextLdapTypeGuards.has_is_success_attribute(HasIsSuccessProperty())

        # Test objects without is_success attribute
        class NoIsSuccess:
            pass

        assert not FlextLdapTypeGuards.has_is_success_attribute(NoIsSuccess())
        assert not FlextLdapTypeGuards.has_is_success_attribute("string")
        assert not FlextLdapTypeGuards.has_is_success_attribute(123)
        assert not FlextLdapTypeGuards.has_is_success_attribute([])
        assert not FlextLdapTypeGuards.has_is_success_attribute({})

    def test_is_connection_result_coverage(self) -> None:
        """Test is_connection_result type guard."""
        # Test valid connection results
        valid_results = [
            {"status": "connected"},
            {"status": "disconnected", "extra": "data"},
            {"status": "", "other": "fields"},
        ]

        for result in valid_results:
            assert FlextLdapTypeGuards.is_connection_result(result)

        # Test invalid connection results
        invalid_results = [
            {},  # Missing status
            {"status": 123},  # Non-string status
            {"status": None},  # None status
            {"other": "field"},  # No status field
            "not a dict",  # Not a dict
            None,  # None
            [],  # List
            123,  # Number
        ]

        for result in invalid_results:
            assert not FlextLdapTypeGuards.is_connection_result(result)

    def test_is_bytes_list_coverage(self) -> None:
        """Test is_bytes_list type guard."""
        # Test valid bytes lists
        valid_lists = [
            [b"byte1", b"byte2"],
            [b"single"],
            [],  # Empty list is valid
        ]

        for lst in valid_lists:
            assert FlextLdapTypeGuards.is_bytes_list(lst)

        # Test invalid bytes lists
        invalid_lists = [
            ["string1", "string2"],  # Strings not bytes
            [b"byte1", "string2"],  # Mixed types
            [123, 456],  # Numbers
            "not a list",  # Not a list
            None,  # None
            {},  # Dict
        ]

        for lst in invalid_lists:
            assert not FlextLdapTypeGuards.is_bytes_list(lst)

    def test_is_string_list_coverage(self) -> None:
        """Test is_string_list type guard with edge cases."""
        # Test valid string lists
        valid_lists = [
            ["str1", "str2"],
            ["single"],
            [],  # Empty list is valid
            ["", "empty", "strings"],  # Empty strings are valid
        ]

        for lst in valid_lists:
            assert FlextLdapTypeGuards.is_string_list(lst)

        # Test invalid string lists
        invalid_lists = [
            [b"byte1", b"byte2"],  # Bytes not strings
            ["str1", 123],  # Mixed types
            [None, "string"],  # None in list
            "not a list",  # Not a list
            None,  # None
            {},  # Dict
            123,  # Number
        ]

        for lst in invalid_lists:
            assert not FlextLdapTypeGuards.is_string_list(lst)

    def test_is_ldap_entry_data_attributes_handling(self) -> None:
        """Test is_ldap_entry_data with special attributes handling."""
        # Test entry data with valid attributes dict
        valid_entry = {
            "dn": "cn=test,dc=example,dc=com",
            "attributes": {
                "cn": ["test"],
                "mail": "test@example.com",
                "objectClass": ["person", "top"],
            },
        }
        assert FlextLdapTypeGuards.is_ldap_entry_data(valid_entry)

        # Test entry data with invalid attributes dict
        invalid_attributes_entry = {
            "dn": "cn=test,dc=example,dc=com",
            "attributes": {
                123: ["invalid key"],  # Non-string key
                "valid": ["value"],
            },
        }
        assert not FlextLdapTypeGuards.is_ldap_entry_data(invalid_attributes_entry)

        # Test entry data with various valid attribute types
        mixed_types_entry = {
            "dn": "cn=test,dc=example,dc=com",
            "string_attr": "string_value",
            "bytes_attr": b"bytes_value",
            "list_attr": ["list", "value"],
            "int_attr": 123,
            "bool_attr": True,
            "dict_attr": {"nested": "dict"},
        }
        assert FlextLdapTypeGuards.is_ldap_entry_data(mixed_types_entry)

        # Test entry data with invalid attribute type
        invalid_type_entry = {
            "dn": "cn=test,dc=example,dc=com",
            "invalid_attr": complex(1, 2),  # Invalid type
        }
        assert not FlextLdapTypeGuards.is_ldap_entry_data(invalid_type_entry)

    def test_edge_cases_boundary_conditions(self) -> None:
        """Test edge cases and boundary conditions."""
        # Test empty string DN
        assert not FlextLdapTypeGuards.is_ldap_dn("")

        # Test minimal valid DN
        assert FlextLdapTypeGuards.is_ldap_dn("a=b")

        # Test DN with just equals but no value
        assert not FlextLdapTypeGuards.is_ldap_dn("attr=")

        # Test DN with just equals but no attribute
        assert not FlextLdapTypeGuards.is_ldap_dn("=value")

        # Test whitespace handling in DN
        assert FlextLdapTypeGuards.is_ldap_dn("  attr = value  ")

        # Test empty attribute value list
        assert FlextLdapTypeGuards.is_ldap_attribute_value([])

        # Test empty attributes dict
        assert FlextLdapTypeGuards.is_ldap_attributes_dict({})

        # Test empty search result list
        assert FlextLdapTypeGuards.is_ldap_search_result([])
