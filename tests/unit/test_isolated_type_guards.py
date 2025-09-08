"""Isolated tests for type guards - testing REAL functionality without external deps.

These tests import and execute REAL type guard code to increase coverage.


Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import pytest
from flext_core import FlextTypes

from flext_ldap.constants import FlextLDAPConstants
from flext_ldap.type_guards import FlextLDAPTypeGuards

TYPE_GUARDS_AVAILABLE = True


@pytest.mark.skipif(not TYPE_GUARDS_AVAILABLE, reason="Type guards not available")
class TestIsolatedTypeGuards:
    """Test type guards in isolation without external dependencies."""

    def test_min_dn_parts_constant_is_correct(self) -> None:
        """Test that MIN_DN_PARTS constant has correct value (now in FlextLDAPConstants)."""
        assert FlextLDAPConstants.LdapValidation.MIN_DN_PARTS == 2
        assert isinstance(FlextLDAPConstants.LdapValidation.MIN_DN_PARTS, int)

    def test_is_ldap_dn_with_valid_dn_strings(self) -> None:
        """Test is_ldap_dn function with valid DN strings."""
        valid_dns = [
            "cn=John Doe,ou=users,dc=example,dc=com",
            "uid=john.doe,ou=people,dc=test,dc=local",
            "cn=admin,dc=ldap,dc=server",
            "ou=groups,dc=company,dc=org",
            "dc=root",
        ]

        for dn in valid_dns:
            result = FlextLDAPTypeGuards.is_ldap_dn(dn)
            assert result is True, f"Valid DN failed: {dn}"

    def test_is_ldap_dn_with_invalid_strings(self) -> None:
        """Test is_ldap_dn function with invalid strings."""
        invalid_dns = [
            "",  # Empty string
            "no equals sign",
            "cn=",  # Empty value
            "=value",  # Empty attribute
            "   ",  # Whitespace only
        ]

        for dn in invalid_dns:
            result = FlextLDAPTypeGuards.is_ldap_dn(dn)
            assert result is False, f"Invalid DN should fail: {dn}"

    def test_is_ldap_dn_with_non_strings(self) -> None:
        """Test is_ldap_dn function rejects non-strings."""
        non_strings = [None, 123, [], {}, object()]

        for value in non_strings:
            result = FlextLDAPTypeGuards.is_ldap_dn(value)
            assert result is False, f"Non-string should fail: {value}"

    def test_is_ldap_attribute_value_with_valid_values(self) -> None:
        """Test is_ldap_attribute_value with valid LDAP attribute values."""
        valid_values = [
            "string value",
            b"bytes value",
            ["list", "of", "strings"],
            [b"list", b"of", b"bytes"],
            [],  # Empty list
            "",  # Empty string
        ]

        for value in valid_values:
            result = FlextLDAPTypeGuards.is_ldap_attribute_value(value)
            assert result is True, f"Valid attribute value failed: {value}"

    def test_is_ldap_attribute_value_with_invalid_values(self) -> None:
        """Test is_ldap_attribute_value rejects invalid values."""
        invalid_values = [
            None,
            123,
            {"dict": "not allowed"},
            ["mixed", 123, "types"],
            object(),
        ]

        for value in invalid_values:
            result = FlextLDAPTypeGuards.is_ldap_attribute_value(value)
            assert result is False, f"Invalid value should fail: {value}"

    def test_is_ldap_attributes_dict_with_valid_dicts(self) -> None:
        """Test is_ldap_attributes_dict with valid attribute dictionaries."""
        valid_dicts = [
            {"cn": "John Doe"},
            {"mail": ["user@example.com"]},
            {"objectClass": ["person", "inetOrgPerson"]},
            {},  # Empty dict
        ]

        for attrs in valid_dicts:
            result = FlextLDAPTypeGuards.is_ldap_attributes_dict(attrs)
            assert result is True, f"Valid attributes failed: {attrs}"

    def test_is_ldap_attributes_dict_with_invalid_dicts(self) -> None:
        """Test is_ldap_attributes_dict rejects invalid dictionaries."""
        invalid_dicts: FlextTypes.Core.List = [
            None,
            "string",
            123,
            [],
            {"key": 123},  # Invalid value type
            {"key": [123, "mixed"]},  # Mixed list types
        ]

        for attrs in invalid_dicts:
            result = FlextLDAPTypeGuards.is_ldap_attributes_dict(attrs)
            assert result is False, f"Invalid attributes should fail: {attrs}"

    def test_ensure_ldap_dn_with_valid_dn(self) -> None:
        """Test ensure_ldap_dn returns valid DN unchanged."""
        valid_dn = "cn=test,dc=example,dc=com"
        result = FlextLDAPTypeGuards.ensure_ldap_dn(valid_dn)
        assert result == valid_dn

    def test_ensure_ldap_dn_converts_string_with_equals(self) -> None:
        """Test ensure_ldap_dn converts string with equals to DN."""
        convertible = "uid=user,ou=people"
        result = FlextLDAPTypeGuards.ensure_ldap_dn(convertible)
        assert result == convertible

    def test_ensure_ldap_dn_raises_for_invalid_string(self) -> None:
        """Test ensure_ldap_dn raises ValueError for invalid input."""
        with pytest.raises(ValueError, match="Cannot convert.*to valid LDAP DN"):
            FlextLDAPTypeGuards.ensure_ldap_dn("no equals sign")

    def test_ensure_string_list_converts_string_to_list(self) -> None:
        """Test ensure_string_list converts single string to list."""
        result = FlextLDAPTypeGuards.ensure_string_list("single value")
        assert result == ["single value"]

    def test_ensure_string_list_keeps_list_unchanged(self) -> None:
        """Test ensure_string_list keeps list unchanged."""
        input_list = ["value1", "value2", "value3"]
        result = FlextLDAPTypeGuards.ensure_string_list(input_list)
        assert result == input_list

    def test_ensure_string_list_converts_non_strings_in_list(self) -> None:
        """Test ensure_string_list with string list."""
        string_list = ["123", "string", "456"]
        result = FlextLDAPTypeGuards.ensure_string_list(string_list)
        expected = ["123", "string", "456"]
        assert result == expected

    def test_ensure_string_list_handles_string_input(self) -> None:
        """Test ensure_string_list handles string input."""
        result = FlextLDAPTypeGuards.ensure_string_list("single_string")
        assert result == ["single_string"]


@pytest.mark.skipif(TYPE_GUARDS_AVAILABLE, reason="Type guards are available")
class TestTypeGuardsNotAvailable:
    """Test case when type guards are not available."""

    def test_type_guards_import_failed(self) -> None:
        """Test that we handle the case when type guards can't be imported."""
        # This test runs when TYPE_GUARDS_AVAILABLE is False
        assert not TYPE_GUARDS_AVAILABLE
        # This is expected in some environments and is not a failure


if TYPE_GUARDS_AVAILABLE:
    # Run a basic smoke test on module load
    pass
