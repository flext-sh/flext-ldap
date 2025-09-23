"""Comprehensive tests for type_guards module.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

import pytest

from flext_ldap.type_guards import FlextLdapTypeGuards


class TestEnsureStringList:
    """Test ensure_string_list type guard."""

    def test_string_to_list(self) -> None:
        """Test converting string to list."""
        result = FlextLdapTypeGuards.ensure_string_list("test")
        assert result == ["test"]

    def test_string_list_passthrough(self) -> None:
        """Test string list passes through."""
        result = FlextLdapTypeGuards.ensure_string_list(["a", "b", "c"])
        assert result == ["a", "b", "c"]

    def test_mixed_list_conversion(self) -> None:
        """Test mixed types list gets converted to strings."""
        result = FlextLdapTypeGuards.ensure_string_list([1, "two", 3.0])
        assert result == ["1", "two", "3.0"]

    def test_non_string_conversion(self) -> None:
        """Test non-string types get converted to single-item list."""
        result = FlextLdapTypeGuards.ensure_string_list(42)
        assert result == ["42"]

    def test_none_conversion(self) -> None:
        """Test None gets converted to single-item list."""
        result = FlextLdapTypeGuards.ensure_string_list(None)
        assert result == ["None"]

    def test_empty_list(self) -> None:
        """Test empty list remains empty."""
        result = FlextLdapTypeGuards.ensure_string_list([])
        assert result == []


class TestEnsureLdapDn:
    """Test ensure_ldap_dn type guard."""

    def test_valid_simple_dn(self) -> None:
        """Test valid simple DN."""
        result = FlextLdapTypeGuards.ensure_ldap_dn("cn=test,dc=example,dc=com")
        assert result == "cn=test,dc=example,dc=com"

    def test_valid_dn_with_spaces(self) -> None:
        """Test valid DN with spaces gets trimmed."""
        result = FlextLdapTypeGuards.ensure_ldap_dn("  cn=test,dc=example,dc=com  ")
        assert result == "cn=test,dc=example,dc=com"

    def test_invalid_non_string(self) -> None:
        """Test non-string raises TypeError."""
        with pytest.raises(TypeError, match="LDAP DN must be a string"):
            FlextLdapTypeGuards.ensure_ldap_dn(123)

    def test_invalid_empty_string(self) -> None:
        """Test empty string raises ValueError."""
        with pytest.raises(ValueError, match="LDAP DN cannot be empty"):
            FlextLdapTypeGuards.ensure_ldap_dn("")

    def test_invalid_whitespace_only(self) -> None:
        """Test whitespace-only string raises ValueError."""
        with pytest.raises(ValueError, match="LDAP DN cannot be empty"):
            FlextLdapTypeGuards.ensure_ldap_dn("   ")

    def test_invalid_no_equals_sign(self) -> None:
        """Test DN without equals sign raises ValueError."""
        with pytest.raises(ValueError, match="must contain at least one '=' sign"):
            FlextLdapTypeGuards.ensure_ldap_dn("cn,dc")

    def test_invalid_empty_component(self) -> None:
        """Test DN with empty component raises ValueError."""
        with pytest.raises(ValueError, match="cannot have empty components"):
            FlextLdapTypeGuards.ensure_ldap_dn("cn=test,,dc=com")

    def test_invalid_component_no_equals(self) -> None:
        """Test DN component without equals raises ValueError."""
        with pytest.raises(ValueError, match="Each LDAP DN component must contain"):
            FlextLdapTypeGuards.ensure_ldap_dn("cn=test,invalid")

    def test_invalid_empty_attribute_name(self) -> None:
        """Test DN with empty attribute name raises ValueError."""
        with pytest.raises(ValueError, match="attribute name cannot be empty"):
            FlextLdapTypeGuards.ensure_ldap_dn("=test,dc=example")

    def test_invalid_empty_attribute_value(self) -> None:
        """Test DN with empty attribute value raises ValueError."""
        with pytest.raises(ValueError, match="attribute value cannot be empty"):
            FlextLdapTypeGuards.ensure_ldap_dn("cn=,dc=example")


class TestHasAttributes:
    """Test attribute checking type guards."""

    def test_has_error_attribute_true(self) -> None:
        """Test has_error_attribute returns True for object with error."""

        class WithError:
            error = "test error"

        assert FlextLdapTypeGuards.has_error_attribute(WithError())

    def test_has_error_attribute_false(self) -> None:
        """Test has_error_attribute returns False for object without error."""

        class WithoutError:
            pass

        assert not FlextLdapTypeGuards.has_error_attribute(WithoutError())

    def test_has_is_success_attribute_true(self) -> None:
        """Test has_is_success_attribute returns True for object with is_success."""

        class WithSuccess:
            is_success = True

        assert FlextLdapTypeGuards.has_is_success_attribute(WithSuccess())

    def test_has_is_success_attribute_false(self) -> None:
        """Test has_is_success_attribute returns False for object without is_success."""

        class WithoutSuccess:
            pass

        assert not FlextLdapTypeGuards.has_is_success_attribute(WithoutSuccess())


class TestIsConnectionResult:
    """Test is_connection_result type guard."""

    def test_valid_connection_result(self) -> None:
        """Test valid connection result dict."""
        result = {
            "server": "ldap://localhost",
            "port": 389,
            "use_ssl": False,
        }
        assert FlextLdapTypeGuards.is_connection_result(result)

    def test_invalid_missing_server(self) -> None:
        """Test invalid connection result missing server."""
        result = {"port": 389, "use_ssl": False}
        assert not FlextLdapTypeGuards.is_connection_result(result)

    def test_invalid_missing_port(self) -> None:
        """Test invalid connection result missing port."""
        result = {"server": "ldap://localhost", "use_ssl": False}
        assert not FlextLdapTypeGuards.is_connection_result(result)

    def test_invalid_missing_use_ssl(self) -> None:
        """Test invalid connection result missing use_ssl."""
        result = {"server": "ldap://localhost", "port": 389}
        assert not FlextLdapTypeGuards.is_connection_result(result)

    def test_invalid_non_dict(self) -> None:
        """Test non-dict returns False."""
        assert not FlextLdapTypeGuards.is_connection_result("not a dict")


class TestIsBytesList:
    """Test is_bytes_list type guard."""

    def test_valid_bytes_list(self) -> None:
        """Test valid bytes list."""
        assert FlextLdapTypeGuards.is_bytes_list([b"test", b"data"])

    def test_empty_bytes_list(self) -> None:
        """Test empty list returns True."""
        assert FlextLdapTypeGuards.is_bytes_list([])

    def test_invalid_mixed_types(self) -> None:
        """Test mixed types returns False."""
        assert not FlextLdapTypeGuards.is_bytes_list([b"test", "string"])

    def test_invalid_non_list(self) -> None:
        """Test non-list returns False."""
        assert not FlextLdapTypeGuards.is_bytes_list(b"single bytes")


class TestIsStringList:
    """Test is_string_list type guard."""

    def test_valid_string_list(self) -> None:
        """Test valid string list."""
        assert FlextLdapTypeGuards.is_string_list(["a", "b", "c"])

    def test_empty_string_list(self) -> None:
        """Test empty list returns True."""
        assert FlextLdapTypeGuards.is_string_list([])

    def test_invalid_mixed_types(self) -> None:
        """Test mixed types returns False."""
        assert not FlextLdapTypeGuards.is_string_list(["test", 123])

    def test_invalid_non_list(self) -> None:
        """Test non-list returns False."""
        assert not FlextLdapTypeGuards.is_string_list("single string")


class TestIsLdapEntryData:
    """Test is_ldap_entry_data type guard."""

    def test_valid_entry_with_dn_only(self) -> None:
        """Test valid entry with DN only."""
        entry = {"dn": "cn=test,dc=example,dc=com"}
        assert FlextLdapTypeGuards.is_ldap_entry_data(entry)

    def test_valid_entry_with_attributes(self) -> None:
        """Test valid entry with DN and attributes."""
        entry = {
            "dn": "cn=test,dc=example,dc=com",
            "attributes": {"cn": "test", "objectClass": ["person"]},
        }
        assert FlextLdapTypeGuards.is_ldap_entry_data(entry)

    def test_invalid_non_dict(self) -> None:
        """Test non-dict returns False."""
        assert not FlextLdapTypeGuards.is_ldap_entry_data("not a dict")

    def test_invalid_missing_dn(self) -> None:
        """Test missing DN returns False."""
        entry = {"attributes": {"cn": "test"}}
        assert not FlextLdapTypeGuards.is_ldap_entry_data(entry)

    def test_invalid_non_dict_attributes(self) -> None:
        """Test non-dict attributes returns False."""
        entry = {"dn": "cn=test,dc=example,dc=com", "attributes": "invalid"}
        assert not FlextLdapTypeGuards.is_ldap_entry_data(entry)


class TestIsLdapDn:
    """Test is_ldap_dn type guard."""

    def test_valid_simple_dn(self) -> None:
        """Test valid simple DN."""
        assert FlextLdapTypeGuards.is_ldap_dn("cn=test,dc=example,dc=com")

    def test_valid_complex_dn(self) -> None:
        """Test valid complex DN."""
        assert FlextLdapTypeGuards.is_ldap_dn("uid=user,ou=users,dc=example,dc=com")

    def test_invalid_non_string(self) -> None:
        """Test non-string returns False."""
        assert not FlextLdapTypeGuards.is_ldap_dn(123)

    def test_invalid_empty_string(self) -> None:
        """Test empty string returns False."""
        assert not FlextLdapTypeGuards.is_ldap_dn("")

    def test_invalid_whitespace_only(self) -> None:
        """Test whitespace-only returns False."""
        assert not FlextLdapTypeGuards.is_ldap_dn("   ")

    def test_invalid_no_equals(self) -> None:
        """Test string without equals returns False."""
        assert not FlextLdapTypeGuards.is_ldap_dn("cn,dc")

    def test_invalid_empty_component(self) -> None:
        """Test DN with empty component returns False."""
        assert not FlextLdapTypeGuards.is_ldap_dn("cn=test,,dc=com")

    def test_invalid_component_no_equals(self) -> None:
        """Test DN component without equals returns False."""
        assert not FlextLdapTypeGuards.is_ldap_dn("cn=test,invalid")

    def test_invalid_empty_attribute(self) -> None:
        """Test DN with empty attribute returns False."""
        assert not FlextLdapTypeGuards.is_ldap_dn("=test,dc=com")

    def test_invalid_empty_value(self) -> None:
        """Test DN with empty value returns False."""
        assert not FlextLdapTypeGuards.is_ldap_dn("cn=,dc=com")


class TestIsLdapAttributeValue:
    """Test is_ldap_attribute_value type guard."""

    def test_valid_string_value(self) -> None:
        """Test valid string value."""
        assert FlextLdapTypeGuards.is_ldap_attribute_value("test")

    def test_valid_bytes_value(self) -> None:
        """Test valid bytes value."""
        assert FlextLdapTypeGuards.is_ldap_attribute_value(b"test")

    def test_valid_string_list(self) -> None:
        """Test valid string list."""
        assert FlextLdapTypeGuards.is_ldap_attribute_value(["a", "b"])

    def test_valid_bytes_list(self) -> None:
        """Test valid bytes list."""
        assert FlextLdapTypeGuards.is_ldap_attribute_value([b"a", b"b"])

    def test_valid_mixed_str_bytes_list(self) -> None:
        """Test valid mixed string/bytes list."""
        assert FlextLdapTypeGuards.is_ldap_attribute_value(["str", b"bytes"])

    def test_invalid_int_value(self) -> None:
        """Test invalid int value."""
        assert not FlextLdapTypeGuards.is_ldap_attribute_value(123)

    def test_invalid_mixed_list(self) -> None:
        """Test invalid mixed types list."""
        assert not FlextLdapTypeGuards.is_ldap_attribute_value(["str", 123])


class TestIsLdapAttributesDict:
    """Test is_ldap_attributes_dict type guard."""

    def test_valid_string_attributes(self) -> None:
        """Test valid string attributes."""
        attrs = {"cn": "test", "sn": "user"}
        assert FlextLdapTypeGuards.is_ldap_attributes_dict(attrs)

    def test_valid_list_attributes(self) -> None:
        """Test valid list attributes."""
        attrs = {"objectClass": ["person", "top"]}
        assert FlextLdapTypeGuards.is_ldap_attributes_dict(attrs)

    def test_valid_mixed_attributes(self) -> None:
        """Test valid mixed attributes."""
        attrs = {"cn": "test", "objectClass": ["person", "top"], "photo": b"data"}
        assert FlextLdapTypeGuards.is_ldap_attributes_dict(attrs)

    def test_invalid_non_dict(self) -> None:
        """Test non-dict returns False."""
        assert not FlextLdapTypeGuards.is_ldap_attributes_dict("not a dict")

    def test_invalid_non_string_key(self) -> None:
        """Test non-string key returns False."""
        attrs = {123: "value"}
        assert not FlextLdapTypeGuards.is_ldap_attributes_dict(attrs)

    def test_invalid_value_type(self) -> None:
        """Test invalid value type returns False."""
        attrs = {"cn": 123}
        assert not FlextLdapTypeGuards.is_ldap_attributes_dict(attrs)


class TestIsLdapSearchResult:
    """Test is_ldap_search_result type guard."""

    def test_valid_empty_result(self) -> None:
        """Test valid empty result."""
        assert FlextLdapTypeGuards.is_ldap_search_result([])

    def test_valid_single_entry(self) -> None:
        """Test valid single entry result."""
        result = [{"dn": "cn=test,dc=example,dc=com"}]
        assert FlextLdapTypeGuards.is_ldap_search_result(result)

    def test_valid_multiple_entries(self) -> None:
        """Test valid multiple entries result."""
        result = [
            {"dn": "cn=test1,dc=example,dc=com", "attributes": {"cn": "test1"}},
            {"dn": "cn=test2,dc=example,dc=com", "attributes": {"cn": "test2"}},
        ]
        assert FlextLdapTypeGuards.is_ldap_search_result(result)

    def test_invalid_non_list(self) -> None:
        """Test non-list returns False."""
        assert not FlextLdapTypeGuards.is_ldap_search_result("not a list")

    def test_invalid_non_dict_item(self) -> None:
        """Test non-dict item returns False."""
        result = ["not a dict"]
        assert not FlextLdapTypeGuards.is_ldap_search_result(result)

    def test_invalid_entry_data(self) -> None:
        """Test invalid entry data returns False."""
        result = [{"invalid": "entry"}]  # Missing dn
        assert not FlextLdapTypeGuards.is_ldap_search_result(result)
