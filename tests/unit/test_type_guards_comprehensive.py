"""Comprehensive tests for LDAP type guards.

- Target type_guards.py for high coverage impact
- Test all guard methods with edge cases
- Real functional validation, no mocks

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from flext_ldap.type_guards import FlextLDAPTypeGuards


class TestFlextLDAPTypeGuardsComprehensive:
    """Comprehensive functional tests for LDAP type guards."""

    def test_is_ldap_dn_valid_dns(self) -> None:
        """Test is_ldap_dn with valid DN formats."""
        FlextLDAPTypeGuards()

        # Standard valid DNs
        valid_dns = [
            "cn=john,ou=users,dc=example,dc=com",
            "uid=jdoe,ou=people,dc=company,dc=org",
            "ou=groups,dc=test,dc=local",
            "dc=example,dc=com",
            "cn=admin",
            "uid=user123",
            "o=organization",
            "c=US",
        ]

        for dn in valid_dns:
            assert FlextLDAPTypeGuards.is_ldap_dn(dn), f"Should validate DN: {dn}"

    def test_is_ldap_dn_complex_valid_dns(self) -> None:
        """Test is_ldap_dn with complex but valid DN formats."""
        complex_dns = [
            "cn=John Doe,ou=users,dc=example,dc=com",  # Spaces in name
            "cn=user,with,comma,ou=test,dc=example,dc=com",  # Commas in value
            "cn=user=with=equals,ou=test,dc=example,dc=com",  # Equals in value
            "cn=user+sn=doe,ou=people,dc=example,dc=com",  # Multi-valued RDN
            "cn=user,ou=department/subdivision,dc=example,dc=com",  # Slash in OU
            "uid=user@domain.com,ou=users,dc=example,dc=com",  # Email-like UID
        ]

        for dn in complex_dns:
            assert FlextLDAPTypeGuards.is_ldap_dn(dn), (
                f"Should validate complex DN: {dn}"
            )

    def test_is_ldap_dn_invalid_dns(self) -> None:
        """Test is_ldap_dn with invalid DN formats."""
        invalid_dns = [
            "",  # Empty string
            "   ",  # Only whitespace
            "invalid_dn_without_equals",  # No equals sign
            "=value_without_attribute",  # No attribute name
            "attribute=",  # No value
            "attr= ",  # Only whitespace value
            " =value",  # Only whitespace attribute
            "=",  # Just equals
            "attr",  # Just attribute name
            "123",  # Just number
        ]

        for invalid_dn in invalid_dns:
            assert not FlextLDAPTypeGuards.is_ldap_dn(invalid_dn), (
                f"Should reject invalid DN: {invalid_dn}"
            )

    def test_is_ldap_dn_non_string_types(self) -> None:
        """Test is_ldap_dn with non-string types."""
        non_string_values: list[object] = [
            None,
            123,
            [],
            {},
            set(),
            True,
            False,
            b"cn=test",  # bytes
            ("cn", "test"),  # tuple
        ]

        for value in non_string_values:
            assert not FlextLDAPTypeGuards.is_ldap_dn(value), (
                f"Should reject non-string: {type(value)}"
            )

    def test_is_ldap_attribute_value_valid_string_values(self) -> None:
        """Test is_ldap_attribute_value with valid string values."""
        valid_strings = [
            "simple_value",
            "Value with spaces",
            "value123",
            "value@domain.com",
            "value/with/slashes",
            "value-with-dashes",
            "value_with_underscores",
            "",  # Empty string is valid LDAP attribute value
        ]

        for value in valid_strings:
            assert FlextLDAPTypeGuards.is_ldap_attribute_value(value), (
                f"Should accept string: {value}"
            )

    def test_is_ldap_attribute_value_valid_bytes_values(self) -> None:
        """Test is_ldap_attribute_value with valid bytes values."""
        valid_bytes = [
            b"byte_value",
            b"bytes with spaces",
            b"",  # Empty bytes
            b"\x00\x01\x02",  # Binary data
        ]

        for value in valid_bytes:
            assert FlextLDAPTypeGuards.is_ldap_attribute_value(value), (
                f"Should accept bytes: {value!r}"
            )

    def test_is_ldap_attribute_value_valid_list_values(self) -> None:
        """Test is_ldap_attribute_value with valid list values."""
        valid_lists = [
            ["value1", "value2"],
            ["single_value"],
            [],  # Empty list
            [b"bytes1", b"bytes2"],
            ["mixed", b"types"],
        ]

        for value in valid_lists:
            assert FlextLDAPTypeGuards.is_ldap_attribute_value(value), (
                f"Should accept list: {value}"
            )

    def test_is_ldap_attribute_value_invalid_types(self) -> None:
        """Test is_ldap_attribute_value with invalid types."""
        invalid_values = [
            None,
            123,
            123.45,
            {},
            set(),
            True,
            False,
            {"key": "value"},  # dict
            object(),  # arbitrary object
        ]

        for value in invalid_values:
            assert not FlextLDAPTypeGuards.is_ldap_attribute_value(value), (
                f"Should reject type: {type(value)}"
            )

    def test_is_ldap_attributes_dict_valid_dictionaries(self) -> None:
        """Test is_ldap_attributes_dict with valid attribute dictionaries."""
        valid_attrs = [
            {"cn": ["John Doe"]},
            {"uid": ["jdoe"], "mail": ["john@example.com"]},
            {"objectClass": ["person", "organizationalPerson"]},
            {},  # Empty dict is valid
            {"attr": []},  # Empty list value
            {"attr": [""]},  # Empty string in list
            {"binary": [b"data"]},  # Bytes values
        ]

        for attrs in valid_attrs:
            assert FlextLDAPTypeGuards.is_ldap_attributes_dict(attrs), (
                f"Should accept attributes: {attrs}"
            )

    def test_is_ldap_attributes_dict_invalid_structures(self) -> None:
        """Test is_ldap_attributes_dict with invalid structures."""
        invalid_attrs: list[object] = [
            None,
            "not_a_dict",
            123,
            [],
            {"key": 123},  # Invalid value type (not string/bytes/list)
            {"key": {"nested": "dict"}},  # Nested dict not allowed
            {123: ["value"]},  # Non-string key
        ]

        for attrs in invalid_attrs:
            assert not FlextLDAPTypeGuards.is_ldap_attributes_dict(attrs), (
                f"Should reject attributes: {attrs}"
            )

    def test_is_ldap_entry_data_valid_entries(self) -> None:
        """Test is_ldap_entry_data with valid entry data structures."""
        valid_entries = [
            {
                "dn": "cn=john,ou=users,dc=example,dc=com",
                "attributes": {"cn": ["John Doe"], "uid": ["jdoe"]},
            },
            {"dn": "uid=test,dc=test", "attributes": {}},
            {
                "dn": "ou=groups,dc=example,dc=com",
                "attributes": {"objectClass": ["organizationalUnit"]},
            },
        ]

        for entry in valid_entries:
            assert FlextLDAPTypeGuards.is_ldap_entry_data(entry), (
                f"Should accept entry: {entry}"
            )

    def test_is_ldap_entry_data_invalid_entries(self) -> None:
        """Test is_ldap_entry_data with invalid entry data structures."""
        invalid_entries: list[object] = [
            None,
            {},  # Missing required dn key
            {"attributes": {}},  # Missing dn
            {"dn": 123, "attributes": {}},  # Invalid dn type
            {"dn": "invalid_dn", "attributes": {}},  # Invalid DN format (no equals)
            {
                "dn": "cn=test",
                "attributes": {"key": object()},
            },  # Invalid attribute value type
            {
                "dn": "cn=test",
                "attributes": {123: ["value"]},
            },  # Non-string key in attributes
            {
                "dn": "cn=test",
                "unsupported_type": complex(1, 2),
            },  # Unsupported value type
        ]

        for entry in invalid_entries:
            assert not FlextLDAPTypeGuards.is_ldap_entry_data(entry), (
                f"Should reject entry: {entry}"
            )

    def test_is_ldap_search_result_valid_results(self) -> None:
        """Test is_ldap_search_result with valid search result structures."""
        valid_results = [
            [
                {"dn": "cn=user1,dc=test", "attributes": {"cn": ["User 1"]}},
                {"dn": "cn=user2,dc=test", "attributes": {"cn": ["User 2"]}},
            ],
            [],  # Empty list is valid
            [{"dn": "cn=admin,dc=example,dc=com"}],
        ]

        for result in valid_results:
            assert FlextLDAPTypeGuards.is_ldap_search_result(result), (
                f"Should accept result: {result}"
            )

    def test_is_ldap_search_result_invalid_results(self) -> None:
        """Test is_ldap_search_result with invalid search result structures."""
        invalid_results: list[object] = [
            None,
            {},  # Dict instead of list
            "not_list",  # String instead of list
            123,  # Number instead of list
            [{"invalid": "entry"}],  # Missing dn key
            [{"dn": "invalid_dn"}],  # Invalid DN format
            [{"dn": 123}],  # Non-string dn
            ["not_dict"],  # Non-dict entry
        ]

        for result in invalid_results:
            assert not FlextLDAPTypeGuards.is_ldap_search_result(result), (
                f"Should reject result: {result}"
            )

    def test_type_guards_edge_cases_and_boundaries(self) -> None:
        """Test type guards with edge cases and boundary conditions."""
        # Test very long DN
        long_dn = "cn=" + "a" * 1000 + ",ou=test,dc=example,dc=com"
        assert FlextLDAPTypeGuards.is_ldap_dn(long_dn), "Should accept very long DN"

        # Test DN with Unicode characters
        unicode_dn = "cn=José García,ou=users,dc=example,dc=com"
        assert FlextLDAPTypeGuards.is_ldap_dn(unicode_dn), "Should accept Unicode DN"

        # Test attribute with very long value
        long_value = "a" * 10000
        assert FlextLDAPTypeGuards.is_ldap_attribute_value(long_value), (
            "Should accept very long value"
        )

        # Test attributes with many keys
        many_attrs = {f"attr{i}": [f"value{i}"] for i in range(100)}
        assert FlextLDAPTypeGuards.is_ldap_attributes_dict(many_attrs), (
            "Should accept many attributes"
        )

    def test_type_guards_consistency_across_calls(self) -> None:
        """Test that type guards return consistent results across multiple calls."""
        test_values = [
            ("cn=test,dc=example,dc=com", True),
            ("invalid_dn", False),
            ("simple_string", True),  # For attribute value
            (123, False),  # For attribute value
        ]

        # Test DN validation consistency
        for value, expected in test_values[:2]:
            for _ in range(10):  # Multiple calls
                result = FlextLDAPTypeGuards.is_ldap_dn(value)
                assert result == expected, f"Inconsistent result for DN: {value}"

        # Test attribute value validation consistency
        for value, expected in test_values[2:]:
            for _ in range(10):  # Multiple calls
                result = FlextLDAPTypeGuards.is_ldap_attribute_value(value)
                assert result == expected, (
                    f"Inconsistent result for attr value: {value}"
                )
