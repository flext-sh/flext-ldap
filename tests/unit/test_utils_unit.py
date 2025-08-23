"""Unit tests for FLEXT-LDAP utility functions.

Tests utility classes and functions without external dependencies.
"""

from __future__ import annotations

from typing import Any

from flext_ldap.utils import FlextLdapUtilities, FlextLdapUtils


class TestFlextLdapUtilities:
    """Test FLEXT LDAP utility class methods."""

    def test_create_ldap_attributes_with_string_values(self) -> None:
        """Test creating LDAP attributes from string values."""
        raw_attrs = {"cn": ["John Doe"], "sn": ["Doe"], "mail": ["john@example.com"]}

        result = FlextLdapUtilities.create_ldap_attributes(raw_attrs)

        assert isinstance(result, dict)
        assert "cn" in result
        assert isinstance(result["cn"], list)
        assert result["cn"] == ["John Doe"]
        assert result["sn"] == ["Doe"]
        assert result["mail"] == ["john@example.com"]

    def test_create_ldap_attributes_with_list_values(self) -> None:
        """Test creating LDAP attributes from list values."""
        raw_attrs = {
            "objectClass": ["inetOrgPerson", "person"],
            "mail": ["john@example.com", "john.doe@example.com"],
            "cn": ["John Doe"],
        }

        result = FlextLdapUtilities.create_ldap_attributes(raw_attrs)

        assert isinstance(result, dict)
        assert result["objectClass"] == ["inetOrgPerson", "person"]
        assert result["mail"] == ["john@example.com", "john.doe@example.com"]
        assert result["cn"] == ["John Doe"]

    def test_create_typed_ldap_attributes_with_mixed_values(self) -> None:
        """Test creating typed LDAP attributes with mixed values."""
        raw_attrs = {
            "cn": "John Doe",
            "objectClass": ["inetOrgPerson", "person"],
            "sn": "Doe",
            "mail": ["john@example.com", "john.doe@example.com"],
        }

        result = FlextLdapUtilities.create_typed_ldap_attributes(raw_attrs)

        assert result["cn"] == "John Doe"
        assert result["objectClass"] == ["inetOrgPerson", "person"]
        assert result["sn"] == "Doe"
        assert result["mail"] == ["john@example.com", "john.doe@example.com"]

    def test_create_ldap_attributes_with_empty_dict(self) -> None:
        """Test creating LDAP attributes from empty dictionary."""
        result = FlextLdapUtilities.create_ldap_attributes({})

        assert isinstance(result, dict)
        assert len(result) == 0

    def test_create_typed_ldap_attributes_with_none_values(self) -> None:
        """Test creating typed LDAP attributes handles None values."""
        raw_attrs: dict[str, Any] = {
            "cn": "John Doe",
            "description": None,
            "mail": "john@example.com",
        }

        result = FlextLdapUtilities.create_typed_ldap_attributes(raw_attrs)

        assert result["cn"] == "John Doe"
        assert result["mail"] == "john@example.com"
        assert result["description"] == "None"  # None converted to string

    def test_validate_dn_with_standard_dn(self) -> None:
        """Test DN validation with standard DN format."""
        dn = "cn=John Doe,ou=users,dc=example,dc=com"

        result = FlextLdapUtils.validate_dn(dn)

        assert result is True

    def test_validate_dn_with_spaces_and_case(self) -> None:
        """Test DN validation handles spaces and case variations."""
        dn = "CN=John  Doe, OU=Users, DC=Example, DC=Com"

        result = FlextLdapUtils.validate_dn(dn)

        assert result is True

    def test_validate_dn_with_empty_string(self) -> None:
        """Test DN validation with empty string."""
        result = FlextLdapUtils.validate_dn("")

        assert result is False

    def test_validate_dn_format_with_valid_dn(self) -> None:
        """Test DN format validation with valid DN."""
        valid_dns = [
            "cn=John Doe,ou=users,dc=example,dc=com",
            "uid=john.doe,ou=people,dc=test,dc=local",
            "cn=REDACTED_LDAP_BIND_PASSWORD,dc=ldap,dc=server",
        ]

        for dn in valid_dns:
            result = FlextLdapUtils.validate_dn(dn)
            assert result is True, f"Valid DN should pass validation: {dn}"

    def test_validate_dn_format_with_invalid_dn(self) -> None:
        """Test DN format validation with invalid DN."""
        invalid_dns = ["", "invalid", "cn=", "=value", "malformed dn string"]

        for dn in invalid_dns:
            result = FlextLdapUtils.validate_dn(dn)
            assert result is False, f"Invalid DN should fail validation: {dn}"

    def test_safe_get_first_value_from_list(self) -> None:
        """Test safely getting first value from attribute list."""
        attributes = {"cn": ["John Doe", "J. Doe"], "mail": "john@example.com"}

        result = FlextLdapUtilities.safe_get_first_value(attributes, "cn")
        assert result == "John Doe"

        result = FlextLdapUtilities.safe_get_first_value(attributes, "mail")
        assert result == "john@example.com"

    def test_safe_get_first_value_from_missing_key(self) -> None:
        """Test safely getting first value from missing key."""
        attributes = {"cn": ["John Doe"]}

        result = FlextLdapUtilities.safe_get_first_value(attributes, "mail")
        assert result is None

    def test_safe_convert_external_dict_to_ldap_attributes(self) -> None:
        """Test safely converting external dict to LDAP attributes."""
        external_dict = {"cn": ["John Doe"], "mail": "john@example.com"}

        result = FlextLdapUtilities.safe_convert_external_dict_to_ldap_attributes(
            external_dict
        )

        assert isinstance(result, dict)
        assert result["cn"] == ["John Doe"]
        assert result["mail"] == "john@example.com"

    def test_validate_attribute_name_with_valid_name(self) -> None:
        """Test LDAP attribute name validation with valid names."""
        valid_names = ["cn", "mail", "sn", "objectClass", "displayName"]

        for name in valid_names:
            result = FlextLdapUtils.validate_attribute_name(name)
            assert result is True, f"Valid attribute name should pass: {name}"

    def test_validate_attribute_name_with_invalid_name(self) -> None:
        """Test LDAP attribute name validation with invalid names."""
        invalid_names = ["", "123invalid", "cn$invalid", "@invalid"]

        for name in invalid_names:
            result = FlextLdapUtils.validate_attribute_name(name)
            assert result is False, f"Invalid attribute name should fail: {name}"

    def test_validate_attribute_value_with_valid_value(self) -> None:
        """Test LDAP attribute value validation with valid values."""
        valid_values = ["John Doe", "john@example.com", "123", "valid-value_test"]

        for value in valid_values:
            result = FlextLdapUtils.validate_attribute_value(value)
            assert result is True, f"Valid attribute value should pass: {value}"

    def test_sanitize_attribute_name_with_special_characters(self) -> None:
        """Test LDAP attribute name sanitization with special characters."""
        dangerous_inputs = [
            "user*",
            "test(user)",
            "REDACTED_LDAP_BIND_PASSWORD\\user",
            "user&group",
            "test|value",
            "user=REDACTED_LDAP_BIND_PASSWORD",
        ]

        for input_str in dangerous_inputs:
            result = FlextLdapUtils.sanitize_attribute_name(input_str)
            assert isinstance(result, str)
            # Should sanitize dangerous characters

    def test_sanitize_attribute_name_with_safe_input(self) -> None:
        """Test LDAP attribute name sanitization with safe input."""
        safe_inputs = ["cn", "mail", "sn", "objectClass", "displayName"]

        for input_str in safe_inputs:
            result = FlextLdapUtils.sanitize_attribute_name(input_str)
            # Safe inputs should remain mostly unchanged
            assert isinstance(result, str)
            assert len(result) > 0

    def test_extract_error_message_with_result(self) -> None:
        """Test extracting error message from FlextResult."""

        # Mock a result-like object with error
        class MockResult:
            is_success = False
            error = "Test error message"

        result = FlextLdapUtilities.extract_error_message(MockResult())
        assert result == "Test error message"

    def test_extract_error_message_with_default(self) -> None:
        """Test extracting error message with default."""

        # Mock a successful result
        class MockSuccessResult:
            is_success = True

        result = FlextLdapUtilities.extract_error_message(MockSuccessResult())
        assert result == "Unknown error"

    def test_is_successful_result_with_success(self) -> None:
        """Test checking if result is successful."""

        class MockSuccessResult:
            is_success = True

        result = FlextLdapUtilities.is_successful_result(MockSuccessResult())
        assert result is True

    def test_is_successful_result_with_failure(self) -> None:
        """Test checking if result is not successful."""

        class MockFailResult:
            is_success = False

        result = FlextLdapUtilities.is_successful_result(MockFailResult())
        assert result is False

    def test_safe_convert_value_to_str_with_bytes(self) -> None:
        """Test safely converting bytes to string."""
        byte_value = b"test value"

        result = FlextLdapUtilities.safe_convert_value_to_str(byte_value)
        assert result == "test value"

    def test_safe_convert_value_to_str_with_string(self) -> None:
        """Test safely converting string to string."""
        string_value = "test value"

        result = FlextLdapUtilities.safe_convert_value_to_str(string_value)
        assert result == "test value"

    def test_safe_convert_value_to_str_with_none(self) -> None:
        """Test safely converting None to string."""
        result = FlextLdapUtilities.safe_convert_value_to_str(None)
        assert result == ""

    def test_safe_convert_list_to_strings(self) -> None:
        """Test safely converting list of values to strings."""
        values = ["test1", b"test2", 123, None, ""]

        result = FlextLdapUtilities.safe_convert_list_to_strings(values)
        assert "test1" in result
        assert "test2" in result
        assert "123" in result

    def test_safe_list_conversion_with_list(self) -> None:
        """Test safely converting list to list of strings."""
        values = ["test1", "test2", 123]

        result = FlextLdapUtilities.safe_list_conversion(values)
        assert result == ["test1", "test2", "123"]

    def test_safe_list_conversion_with_single_value(self) -> None:
        """Test safely converting single value to list of strings."""
        value = "single_value"

        result = FlextLdapUtilities.safe_list_conversion(value)
        assert result == ["single_value"]

    def test_safe_list_conversion_with_none(self) -> None:
        """Test safely converting None to empty list."""
        result = FlextLdapUtilities.safe_list_conversion(None)
        assert result == []
