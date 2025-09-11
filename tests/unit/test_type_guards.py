"""Unit tests for FLEXT-LDAP type guard functions.

Tests type guard functions for proper type narrowing and validation.


Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from flext_core import FlextTypes

from flext_ldap import FlextLDAPTypeGuards, LdapAttributeDict


class TestLdapTypeGuards:
    """Test LDAP type guard functions for proper type validation."""

    def test_is_ldap_dn_with_valid_dns(self) -> None:
        """Test LDAP DN type guard with valid DN strings."""
        valid_dns = [
            "cn=John Doe,ou=users,dc=example,dc=com",
            "uid=john.doe,ou=people,dc=test,dc=local",
            "cn=REDACTED_LDAP_BIND_PASSWORD,dc=ldap,dc=server",
            "ou=groups,dc=company,dc=org",
            "dc=root",
        ]

        for dn in valid_dns:
            assert FlextLDAPTypeGuards.is_ldap_dn(dn), (
                f"Valid DN should pass type guard: {dn}"
            )

    def test_is_ldap_dn_with_invalid_values(self) -> None:
        """Test LDAP DN type guard with invalid values."""
        invalid_values: FlextTypes.Core.List = [
            None,
            123,
            [],
            {},
            "",
            "invalid dn",
            "cn=",
            "=value",
        ]

        for value in invalid_values:
            assert not FlextLDAPTypeGuards.is_ldap_dn(value), (
                f"Invalid value should fail DN type guard: {value}"
            )

    def test_is_ldap_attribute_value_with_string_values(self) -> None:
        """Test LDAP attribute value type guard with string values."""
        valid_string_values = [
            "John Doe",
            "REDACTED_LDAP_BIND_PASSWORD@example.com",
            "",
            "123",
            "special-chars_$%",
        ]

        for value in valid_string_values:
            assert FlextLDAPTypeGuards.is_ldap_attribute_value(value), (
                f"String value should pass: {value}"
            )

    def test_is_ldap_attribute_value_with_list_values(self) -> None:
        """Test LDAP attribute value type guard with list values."""
        valid_list_values = [
            ["value1", "value2"],
            ["single_value"],
            [],
            ["REDACTED_LDAP_BIND_PASSWORD@example.com", "user@test.com"],
            ["123", "456", "789"],
        ]

        for value in valid_list_values:
            assert FlextLDAPTypeGuards.is_ldap_attribute_value(value), (
                f"List value should pass: {value}"
            )

    def test_is_ldap_attribute_value_with_invalid_values(self) -> None:
        """Test LDAP attribute value type guard with invalid values."""
        invalid_values = [
            None,
            123,
            {},
            {"key": "value"},
            [123, 456],  # List with non-string values
            ["valid", 123],  # Mixed list
            object(),
        ]

        for value in invalid_values:
            assert not FlextLDAPTypeGuards.is_ldap_attribute_value(value), (
                f"Invalid value should fail: {value!r}"
            )

    def test_is_ldap_attributes_with_valid_attributes(self) -> None:
        """Test LDAP attributes type guard with valid attribute dictionaries."""
        valid_attributes = [
            {"cn": ["John Doe"], "sn": ["Doe"]},
            {"mail": "REDACTED_LDAP_BIND_PASSWORD@example.com"},
            {"objectClass": ["person", "inetOrgPerson"]},
            {"uid": "john.doe", "mail": ["john@example.com", "john.doe@example.com"]},
            {},  # Empty dict is valid
        ]

        for attrs in valid_attributes:
            assert FlextLDAPTypeGuards.is_ldap_attributes_dict(attrs), (
                f"Valid attributes should pass: {attrs}"
            )

    def test_is_ldap_attributes_with_invalid_values(self) -> None:
        """Test LDAP attributes type guard with invalid values."""
        invalid_values = [
            None,
            "string",
            123,
            [],
            {"key": 123},  # Non-string/list value
            {"key": [123, 456]},  # List with non-string values
            {"key": {"nested": "dict"}},  # Nested dict
            object(),
        ]

        for value in invalid_values:
            assert not FlextLDAPTypeGuards.is_ldap_attributes_dict(value), (
                f"Invalid value should fail attributes guard: {value}"
            )

    def test_is_ldap_entry_data_with_valid_entries(self) -> None:
        """Test LDAP entry data type guard with valid entry data."""
        valid_entries = [
            {
                "dn": "cn=John Doe,ou=users,dc=example,dc=com",
                "attributes": {"cn": ["John Doe"], "sn": ["Doe"]},
            },
            {
                "dn": "uid=REDACTED_LDAP_BIND_PASSWORD,dc=test,dc=local",
                "attributes": {"uid": "REDACTED_LDAP_BIND_PASSWORD", "mail": "REDACTED_LDAP_BIND_PASSWORD@internal.invalid"},
            },
            {"dn": "ou=groups,dc=example,dc=com", "attributes": {}},
        ]

        for entry in valid_entries:
            assert FlextLDAPTypeGuards.is_ldap_entry_data(entry), (
                f"Valid entry should pass: {entry}"
            )

    def test_is_ldap_entry_data_with_invalid_entries(self) -> None:
        """Test LDAP entry data type guard with invalid entry data."""
        invalid_entries: FlextTypes.Core.List = [
            None,
            "string",
            123,
            [],
            {},  # Missing required fields
            {"attributes": {"cn": ["test"]}},  # Missing dn
            {"dn": 123, "attributes": {}},  # Invalid dn type
            {"dn": "", "mail": "test"},  # Empty dn
            {
                "dn": "invalid",
                "data": object(),
            },  # Invalid attribute value type (object)
        ]

        for entry in invalid_entries:
            assert not FlextLDAPTypeGuards.is_ldap_entry_data(entry), (
                f"Invalid entry should fail: {entry}"
            )

    def test_is_ldap_search_result_with_valid_results(self) -> None:
        """Test LDAP search result type guard with valid search results."""
        valid_results = [
            [],  # Empty result
            [
                {
                    "dn": "cn=John Doe,ou=users,dc=example,dc=com",
                    "attributes": {"cn": ["John Doe"], "sn": ["Doe"]},
                },
            ],
            [
                {
                    "dn": "uid=user1,ou=people,dc=test,dc=local",
                    "attributes": {"uid": "user1", "mail": "user1@internal.invalid"},
                },
                {
                    "dn": "uid=user2,ou=people,dc=test,dc=local",
                    "attributes": {"uid": "user2", "mail": "user2@internal.invalid"},
                },
            ],
        ]

        for result in valid_results:
            assert FlextLDAPTypeGuards.is_ldap_search_result(result), (
                f"Valid search result should pass: {result}"
            )

    def test_is_ldap_search_result_with_invalid_results(self) -> None:
        """Test LDAP search result type guard with invalid search results."""
        invalid_results: FlextTypes.Core.List = [
            None,
            "string",
            123,
            {},
            ["string_in_list"],  # List with non-dict entries
            [123, 456],  # List with non-dict entries
            [{"invalid": "entry"}],  # List with invalid entry structure
            [{"dn": "test"}],  # List with incomplete entries
            [{"dn": 123, "attributes": {}}],  # List with invalid entry types
        ]

        for result in invalid_results:
            assert not FlextLDAPTypeGuards.is_ldap_search_result(result), (
                f"Invalid search result should fail: {result}"
            )

    def test_type_guard_with_mixed_data_types(self) -> None:
        """Test type guards handle mixed and complex data types correctly."""
        # Test complex valid LDAP attributes
        complex_attrs: LdapAttributeDict = {
            "objectClass": ["inetOrgPerson", "person", "organizationalPerson"],
            "cn": ["John Doe", "John D. Doe", "J. Doe"],
            "sn": "Doe",
            "givenName": "John",
            "mail": ["john.doe@example.com", "jdoe@example.com"],
            "telephoneNumber": ["+1-555-123-4567", "+1-555-987-6543"],
            "description": "Senior Software Engineer",
        }

        assert FlextLDAPTypeGuards.is_ldap_attributes_dict(complex_attrs)

        # Test complex valid entry data
        complex_entry = {
            "dn": "cn=John Doe,ou=engineering,ou=people,dc=company,dc=com",
            "attributes": complex_attrs,
        }

        assert FlextLDAPTypeGuards.is_ldap_entry_data(complex_entry)

        # Test complex valid search result
        complex_result = [complex_entry]

        assert FlextLDAPTypeGuards.is_ldap_search_result(complex_result)

    def test_type_guard_edge_cases(self) -> None:
        """Test type guards with edge cases and boundary conditions."""
        # Empty string DN - should be invalid
        assert not FlextLDAPTypeGuards.is_ldap_dn("")

        # Very long DN - should still be valid if properly formatted
        long_dn = "cn=" + "x" * 100 + ",ou=test,dc=example,dc=com"
        assert FlextLDAPTypeGuards.is_ldap_dn(long_dn)

        # Empty attributes - should be valid
        assert FlextLDAPTypeGuards.is_ldap_attributes_dict({})

        # Empty search result - should be valid
        assert FlextLDAPTypeGuards.is_ldap_search_result([])

        # Attributes with empty list values - should be valid
        attrs_with_empty_lists: LdapAttributeDict = {
            "cn": [],
            "mail": ["user@example.com"],
            "description": "",
        }
        assert FlextLDAPTypeGuards.is_ldap_attributes_dict(attrs_with_empty_lists)

    def test_type_guard_with_simple_real_data(self) -> None:
        """Test type guards with simple realistic LDAP data."""
        user_entry = {
            "dn": "uid=john.doe,ou=people,dc=example,dc=com",
            "cn": "John Doe",
            "mail": "john.doe@example.com",
        }

        assert FlextLDAPTypeGuards.is_ldap_entry_data(user_entry)
        assert FlextLDAPTypeGuards.is_ldap_dn(user_entry["dn"])
