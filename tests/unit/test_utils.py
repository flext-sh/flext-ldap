"""REAL utils tests - testing actual utils functionality without mocks.

These tests execute REAL utils code to increase coverage and validate functionality.
"""

from __future__ import annotations

from typing import Never

import pytest
from flext_core import FlextResult

# Test real utilities functionality
from flext_ldap.utilities import FlextLDAPUtilities


class TestRealFlextLDAPUtilities:
    """Test REAL FlextLDAPUtilities class functionality."""

    def test_is_successful_result_with_successful_result(self) -> None:
        """Test is_successful_result with successful FlextResult."""
        # Create a real successful result
        success_result = FlextResult[str].ok("test_value")

        # Should detect success correctly
        result = FlextLDAPUtilities.LdapConverters.is_successful_result(success_result)
        assert result is True

    def test_is_successful_result_with_failed_result(self) -> None:
        """Test is_successful_result with failed FlextResult."""
        # Create a real failed result
        failed_result = FlextResult[str].fail("test_error")

        # Should detect failure correctly
        result = FlextLDAPUtilities.LdapConverters.is_successful_result(failed_result)
        assert result is False

    def test_is_successful_result_with_non_result_object(self) -> None:
        """Test is_successful_result with non-FlextResult objects."""
        non_results = [
            None,
            "string",
            123,
            [],
            {},
            object(),
        ]

        for obj in non_results:
            result = FlextLDAPUtilities.LdapConverters.is_successful_result(obj)
            assert result is False

    def test_is_successful_result_with_mock_success_object(self) -> None:
        """Test is_successful_result with object that has is_success attribute."""

        # Create object with is_success attribute
        class MockSuccessObject:
            def __init__(self, is_success: bool) -> None:
                self.is_success = is_success

        success_obj = MockSuccessObject(True)
        failed_obj = MockSuccessObject(False)

        assert (
            FlextLDAPUtilities.LdapConverters.is_successful_result(success_obj) is True
        )
        assert (
            FlextLDAPUtilities.LdapConverters.is_successful_result(failed_obj) is False
        )

    def test_create_typed_ldap_attributes_with_strings(self) -> None:
        """Test create_typed_ldap_attributes with string values."""
        input_attrs = {
            "cn": "John Doe",
            "mail": "john@example.com",
            "sn": "Doe",
        }

        result = FlextLDAPUtilities.LdapConverters.safe_convert_external_dict_to_ldap_attributes(
            input_attrs
        )

        # Should keep strings as strings (actual behavior)
        assert isinstance(result, dict)
        assert result["cn"] == "John Doe"  # Single strings stay single
        assert result["mail"] == "john@example.com"  # Single strings stay single
        assert result["sn"] == "Doe"  # Single strings stay single

    def test_create_typed_ldap_attributes_with_lists(self) -> None:
        """Test create_typed_ldap_attributes with list values."""
        input_attrs = {
            "objectClass": ["person", "inetOrgPerson"],
            "mail": ["primary@example.com", "secondary@example.com"],
            "cn": ["John Doe"],
        }

        result = FlextLDAPUtilities.LdapConverters.safe_convert_external_dict_to_ldap_attributes(
            input_attrs
        )

        # Should preserve lists, convert items to strings
        assert isinstance(result, dict)
        assert result["objectClass"] == ["person", "inetOrgPerson"]
        assert result["mail"] == ["primary@example.com", "secondary@example.com"]
        assert result["cn"] == ["John Doe"]

    def test_create_typed_ldap_attributes_with_mixed_types(self) -> None:
        """Test create_typed_ldap_attributes with mixed value types."""
        input_attrs = {
            "cn": "John Doe",  # String
            "objectClass": ["person", "inetOrgPerson"],  # List of strings
            "uidNumber": 1001,  # Integer
            "active": True,  # Boolean
            "gidNumbers": [100, 101, 102],  # List of integers
        }

        result = FlextLDAPUtilities.LdapConverters.safe_convert_external_dict_to_ldap_attributes(
            input_attrs
        )

        # Should convert properly - lists stay lists, singles stay singles
        assert isinstance(result, dict)
        assert result["cn"] == "John Doe"  # Single string stays single
        assert result["objectClass"] == ["person", "inetOrgPerson"]  # List stays list
        assert result["uidNumber"] == "1001"  # Single value converted to string
        assert result["active"] == "True"  # Single boolean converted to string
        assert result["gidNumbers"] == [
            "100",
            "101",
            "102",
        ]  # List converted to string list

    def test_create_typed_ldap_attributes_with_empty_dict(self) -> None:
        """Test create_typed_ldap_attributes with empty input."""
        input_attrs: dict[str, object] = {}

        result = FlextLDAPUtilities.LdapConverters.safe_convert_external_dict_to_ldap_attributes(
            input_attrs
        )

        # Should return empty dict
        assert isinstance(result, dict)
        assert len(result) == 0

    def test_create_typed_ldap_attributes_with_empty_lists(self) -> None:
        """Test create_typed_ldap_attributes with empty list values."""
        input_attrs = {
            "cn": "John Doe",
            "emptyAttr": [],
            "mail": ["test@example.com"],
        }

        result = FlextLDAPUtilities.LdapConverters.safe_convert_external_dict_to_ldap_attributes(
            input_attrs
        )

        # Should handle empty lists
        assert isinstance(result, dict)
        assert result["cn"] == "John Doe"  # Single string stays single
        assert result["emptyAttr"] == []
        assert result["mail"] == ["test@example.com"]

    def test_create_typed_ldap_attributes_preserves_bytes(self) -> None:
        """Test create_typed_ldap_attributes handles bytes correctly."""
        input_attrs = {
            "cn": "John Doe",
            "jpegPhoto": b"binary_photo_data",
            "certificates": [b"cert1", b"cert2"],
        }

        result = FlextLDAPUtilities.LdapConverters.safe_convert_external_dict_to_ldap_attributes(
            input_attrs
        )

        # Should handle bytes appropriately
        assert isinstance(result, dict)
        assert result["cn"] == "John Doe"  # Single string input -> single string output
        # Single bytes remain as bytes (preserved per line 56-57 in utils.py)
        assert result["jpegPhoto"] == b"binary_photo_data"
        assert isinstance(result["certificates"], list)
        assert len(result["certificates"]) == 2


class TestRealFlextLDAPValidation:
    """Test REAL FlextLDAPUtilities.Validation class functionality."""

    def test_validate_non_empty_string_with_valid_strings(self) -> None:
        """Test validate_non_empty_string with valid string values."""
        valid_strings = [
            "test",
            "John Doe",
            "user@example.com",
            "cn=test,dc=example,dc=com",
            "a",  # Single character
            "   trimmed   ",  # Should be trimmed
        ]

        for test_string in valid_strings:
            result = FlextLDAPUtilities.Validation.validate_non_empty_string(
                test_string, "test_field"
            )
            assert isinstance(result, str)
            assert len(result.strip()) > 0

    def test_validate_non_empty_string_with_empty_strings(self) -> None:
        """Test validate_non_empty_string rejects empty strings."""
        empty_strings = [
            "",
            "   ",  # Whitespace only
            "\t\n",  # Tabs and newlines
        ]

        for empty_string in empty_strings:
            with pytest.raises(ValueError):
                FlextLDAPUtilities.Validation.validate_non_empty_string(
                    empty_string, "test_field"
                )

    def test_validate_non_empty_string_with_non_strings(self) -> None:
        """Test validate_non_empty_string rejects non-string values."""
        non_strings = [
            None,
            123,
            [],
            {},
            object(),
            True,
            False,
        ]

        for non_string in non_strings:
            with pytest.raises((
                AttributeError,
                ValueError,
            )):  # Different errors for different types
                FlextLDAPUtilities.Validation.validate_non_empty_string(
                    non_string, "test_field"
                )

    def test_validate_non_empty_string_trims_whitespace(self) -> None:
        """Test validate_non_empty_string trims whitespace."""
        test_cases = [
            ("  test  ", "test"),
            ("\ttest\n", "test"),
            ("   John Doe   ", "John Doe"),
            (" a ", "a"),
        ]

        for input_str, expected in test_cases:
            result = FlextLDAPUtilities.Validation.validate_non_empty_string(
                input_str, "test_field"
            )
            assert result == expected

    def test_validate_dn_field_with_valid_dns(self) -> None:
        """Test validate_dn_field with valid DN strings."""
        valid_dns = [
            "cn=John Doe,ou=users,dc=example,dc=com",
            "uid=john.doe,ou=people,dc=test,dc=local",
            "ou=groups,dc=company,dc=org",
            "dc=root",
            "mail=test@example.com,cn=users,dc=example,dc=com",
        ]

        for dn in valid_dns:
            result = FlextLDAPUtilities.DnParser.validate_dn_field(dn)
            assert isinstance(result, str)
            assert len(result.strip()) > 0
            assert result == dn  # Should return as-is for valid DNs

    def test_validate_dn_field_with_empty_strings(self) -> None:
        """Test validate_dn_field rejects empty DN strings."""
        empty_dns = [
            "",
            "   ",
            "\t\n",
        ]

        for empty_dn in empty_dns:
            with pytest.raises(ValueError):
                FlextLDAPUtilities.DnParser.validate_dn_field(empty_dn)

    def test_validate_filter_field_with_valid_filters(self) -> None:
        """Test validate_filter_field with valid LDAP filter strings."""
        valid_filters = [
            "(objectClass=person)",
            "(&(cn=John*)(mail=*@example.com))",
            "(|(uid=john)(cn=John Doe))",
            "(!(objectClass=computer))",
            "(mail=*)",
            "objectClass=*",  # Simple filter
        ]

        for filter_str in valid_filters:
            result = FlextLDAPUtilities.Validation.validate_filter_field(filter_str)
            assert isinstance(result, str)
            assert len(result.strip()) > 0
            assert result == filter_str

    def test_validate_filter_field_with_empty_strings(self) -> None:
        """Test validate_filter_field rejects empty filter strings."""
        empty_filters = [
            "",
            "   ",
            "\t\n",
        ]

        for empty_filter in empty_filters:
            with pytest.raises(ValueError):
                FlextLDAPUtilities.Validation.validate_filter_field(empty_filter)

    def test_validate_uri_field_with_valid_uris(self) -> None:
        """Test validate_uri_field with valid URI strings."""
        valid_servers = [
            "ldap://localhost:389",
            "ldaps://secure.ldap.example.com:636",
            "ldap://192.168.1.100:389",
        ]

        for server in valid_servers:
            result = FlextLDAPUtilities.Validation.validate_uri_field(server)
            assert isinstance(result, str)
            assert len(result.strip()) > 0
            assert result == server

    def test_validate_uri_field_with_empty_strings(self) -> None:
        """Test validate_uri_field rejects empty URI strings."""
        empty_servers = [
            "",
            "   ",
            "\t\n",
        ]

        for empty_server in empty_servers:
            with pytest.raises(ValueError):
                FlextLDAPUtilities.Validation.validate_uri_field(empty_server)

    def test_validate_base_dn_field_with_valid_base_dns(self) -> None:
        """Test validate_base_dn_field with valid base DN strings."""
        valid_base_dns = [
            "dc=example,dc=com",
            "ou=users,dc=company,dc=org",
            "cn=config",
            "dc=root",
            "ou=people,dc=test,dc=local",
        ]

        for base_dn in valid_base_dns:
            result = FlextLDAPUtilities.Validation.validate_base_dn_field(base_dn)
            assert isinstance(result, str)
            assert len(result.strip()) > 0
            assert result == base_dn

    def test_validate_base_dn_field_with_empty_strings(self) -> None:
        """Test validate_base_dn_field rejects empty base DN strings."""
        empty_base_dns = [
            "",
            "   ",
            "\t\n",
        ]

        for empty_base_dn in empty_base_dns:
            with pytest.raises(ValueError):
                FlextLDAPUtilities.Validation.validate_base_dn_field(empty_base_dn)

    def test_validate_cn_field_with_valid_cns(self) -> None:
        """Test validate_cn_field with valid CN strings."""
        valid_usernames = [
            "john.doe",
            "user123",
            "admin",
            "test_user",
            "john@example.com",  # Email as username
            "Jane Doe",  # Space in username
        ]

        for username in valid_usernames:
            result = FlextLDAPUtilities.Validation.validate_cn_field(username)
            assert isinstance(result, str)
            assert len(result.strip()) > 0
            assert result == username

    def test_validate_cn_field_with_empty_strings(self) -> None:
        """Test validate_cn_field rejects empty CN strings."""
        empty_usernames = [
            "",
            "   ",
            "\t\n",
        ]

        for empty_username in empty_usernames:
            with pytest.raises(ValueError):
                FlextLDAPUtilities.Validation.validate_cn_field(empty_username)


class TestRealUtilitiesIntegration:
    """Test REAL integration patterns for utilities."""

    def test_utilities_work_with_real_flext_result(self) -> None:
        """Test utilities integrate properly with real FlextResult objects."""
        # Test with successful FlextResult
        success_result = FlextResult[dict[str, str]].ok({"test": "data"})
        assert (
            FlextLDAPUtilities.LdapConverters.is_successful_result(success_result)
            is True
        )

        # Test with failed FlextResult
        error_result = FlextResult[dict[str, str]].fail("Test error message")
        assert (
            FlextLDAPUtilities.LdapConverters.is_successful_result(error_result)
            is False
        )

        # Verify FlextResult properties are accessible
        assert success_result.is_success is True
        assert error_result.is_success is False
        assert success_result.value == {"test": "data"}
        assert error_result.error == "Test error message"

    def test_validation_helpers_provide_consistent_error_messages(self) -> None:
        """Test validation helpers provide consistent error messages."""
        test_cases = [
            (FlextLDAPUtilities.DnParser.validate_dn_field, ""),
            (FlextLDAPUtilities.Validation.validate_filter_field, ""),
            (FlextLDAPUtilities.Validation.validate_uri_field, ""),
            (FlextLDAPUtilities.Validation.validate_base_dn_field, ""),
            (FlextLDAPUtilities.Validation.validate_cn_field, ""),
        ]

        for validator_func, empty_input in test_cases:
            try:
                validator_func(empty_input)
                pytest.fail(
                    f"Validator {validator_func.__name__} should have raised ValueError"
                )
            except ValueError as e:
                error_message = str(e)
                # Should have informative error message
                assert len(error_message) > 0
                # Should contain field information
                assert any(
                    word in error_message.lower()
                    for word in ["field", "empty", "required", "invalid"]
                ), f"Error message not informative: {error_message}"

    def test_create_typed_ldap_attributes_integration_with_real_data(self) -> None:
        """Test create_typed_ldap_attributes with realistic LDAP data."""
        # Simulate real LDAP entry attributes
        user_attributes = {
            "objectClass": ["person", "inetOrgPerson", "posixAccount"],
            "cn": "John Doe",
            "sn": "Doe",
            "givenName": "John",
            "uid": "john.doe",
            "uidNumber": 1001,
            "gidNumber": 100,
            "homeDirectory": "/home/john.doe",
            "loginShell": "/bin/bash",
            "mail": ["john.doe@example.com", "jdoe@example.com"],
            "telephoneNumber": "555-1234",
            "description": "Test user account",
        }

        result = FlextLDAPUtilities.LdapConverters.safe_convert_external_dict_to_ldap_attributes(
            user_attributes
        )

        # Verify all attributes are properly converted
        assert isinstance(result, dict)
        assert len(result) == len(user_attributes)

        # Verify list attributes remain lists
        assert isinstance(result["objectClass"], list)
        assert result["objectClass"] == ["person", "inetOrgPerson", "posixAccount"]
        assert isinstance(result["mail"], list)
        assert result["mail"] == ["john.doe@example.com", "jdoe@example.com"]

        # Verify single values remain as single values (str/bytes)
        assert result["cn"] == "John Doe"
        assert result["uidNumber"] == "1001"  # Converted to string

        # Verify proper type handling - lists stay lists, singles stay singles
        list_attrs = ["objectClass", "mail"]
        for attr_name in list_attrs:
            assert isinstance(result[attr_name], list), (
                f"Attribute {attr_name} should be list"
            )
            for value in result[attr_name]:
                assert isinstance(value, str), (
                    f"Value {value!r} in {attr_name} should be string"
                )


class TestRealUtilitiesErrorHandling:
    """Test REAL error handling in utilities."""

    def test_utilities_handle_edge_cases_gracefully(self) -> None:
        """Test utilities handle edge cases without crashing."""
        # Test with None input
        try:
            FlextLDAPUtilities.LdapConverters.safe_convert_external_dict_to_ldap_attributes(
                None
            )
            # Should not crash, but may raise AttributeError
        except AttributeError:
            pass  # Expected for None input - 'NoneType' has no attribute 'items'

        # Test with non-dict input
        try:
            FlextLDAPUtilities.LdapConverters.safe_convert_external_dict_to_ldap_attributes(
                "not a dict"
            )
            # Should not crash, but may raise AttributeError
        except (AttributeError, TypeError):
            pass  # Expected for non-dict input

    def test_validation_helpers_provide_detailed_errors(self) -> None:
        """Test validation helpers provide detailed error information."""
        validators = [
            FlextLDAPUtilities.DnParser.validate_dn_field,
            FlextLDAPUtilities.Validation.validate_filter_field,
            FlextLDAPUtilities.Validation.validate_uri_field,
            FlextLDAPUtilities.Validation.validate_base_dn_field,
            FlextLDAPUtilities.Validation.validate_cn_field,
        ]

        for validator in validators:
            # Test with None - testing error handling
            with pytest.raises((ValueError, TypeError)) as exc_info:
                validator(None)
            assert len(str(exc_info.value)) > 5  # Should have error message

            # Test with non-string - testing error handling
            with pytest.raises((ValueError, TypeError, AttributeError)) as exc_info:
                validator(123)
            assert len(str(exc_info.value)) > 10  # Should have detailed message

    def test_is_successful_result_handles_malformed_objects(self) -> None:
        """Test is_successful_result handles objects with malformed is_success attribute."""

        # Test object with is_success property that raises exception
        class MalformedObject:
            @property
            def is_success(self) -> Never:
                msg = "Malformed is_success property"
                raise RuntimeError(msg)

        malformed_obj = MalformedObject()

        # Should raise exception when property access fails (current implementation)
        with pytest.raises(RuntimeError, match="Malformed is_success property"):
            FlextLDAPUtilities.LdapConverters.is_successful_result(malformed_obj)
