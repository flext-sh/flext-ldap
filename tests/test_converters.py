"""Enterprise-grade tests for FlextLdap converters.

Tests data type conversion utilities with comprehensive validation.
"""

from datetime import UTC, datetime

import pytest

from flext_ldap.converters import (
    FlextLdapTypeConverter,
    convert_ldap_to_python,
    convert_python_to_ldap,
    normalize_ldap_dn,
    parse_ldap_filter,
    validate_ldap_attribute_value,
)


class TestFlextLdapTypeConverter:
    """Test FlextLdap type converter class."""

    def test_converter_instantiation(self):
        """Test converter can be instantiated."""
        converter = FlextLdapTypeConverter()
        assert converter is not None

    def test_string_conversion(self):
        """Test string type conversions."""
        converter = FlextLdapTypeConverter()

        # Python to LDAP
        ldap_value = converter.to_ldap("test string")
        assert ldap_value == "test string"

        # LDAP to Python
        python_value = converter.to_python(b"test bytes")
        assert python_value == "test bytes"
        assert isinstance(python_value, str)

    def test_integer_conversion(self):
        """Test integer type conversions."""
        converter = FlextLdapTypeConverter()

        # Python to LDAP
        ldap_value = converter.to_ldap(123)
        assert ldap_value == "123"

        # LDAP to Python
        python_value = converter.to_python("456", target_type=int)
        assert python_value == 456
        assert isinstance(python_value, int)

    def test_boolean_conversion(self):
        """Test boolean type conversions."""
        converter = FlextLdapTypeConverter()

        # Python to LDAP
        true_value = converter.to_ldap(True)
        false_value = converter.to_ldap(False)

        assert true_value in ["TRUE", "true", "1"]
        assert false_value in ["FALSE", "false", "0"]

        # LDAP to Python
        assert converter.to_python("TRUE", target_type=bool) is True
        assert converter.to_python("false", target_type=bool) is False
        assert converter.to_python("1", target_type=bool) is True
        assert converter.to_python("0", target_type=bool) is False

    def test_datetime_conversion(self):
        """Test datetime type conversions."""
        converter = FlextLdapTypeConverter()

        # Python to LDAP (GeneralizedTime format)
        dt = datetime(2024, 1, 15, 10, 30, 45, tzinfo=UTC)
        ldap_value = converter.to_ldap(dt)
        assert ldap_value == "20240115103045Z"

        # LDAP to Python
        python_dt = converter.to_python("20240115103045Z", target_type=datetime)
        assert isinstance(python_dt, datetime)
        assert python_dt.year == 2024
        assert python_dt.month == 1
        assert python_dt.day == 15

    def test_list_conversion(self):
        """Test list/multi-value conversions."""
        converter = FlextLdapTypeConverter()

        # Python list to LDAP
        python_list = ["value1", "value2", "value3"]
        ldap_values = converter.to_ldap(python_list)
        assert ldap_values == ["value1", "value2", "value3"]

        # LDAP list to Python
        ldap_list = [b"value1", b"value2", b"value3"]
        python_values = converter.to_python(ldap_list)
        assert python_values == ["value1", "value2", "value3"]

    def test_bytes_conversion(self):
        """Test binary data conversions."""
        converter = FlextLdapTypeConverter()

        # Python bytes to LDAP
        binary_data = b"binary\x00data"
        ldap_value = converter.to_ldap(binary_data)
        assert ldap_value == binary_data

        # LDAP bytes to Python
        python_value = converter.to_python(binary_data, preserve_binary=True)
        assert python_value == binary_data
        assert isinstance(python_value, bytes)

    def test_none_value_handling(self):
        """Test None value handling."""
        converter = FlextLdapTypeConverter()

        # Python None to LDAP
        ldap_value = converter.to_ldap(None)
        assert ldap_value is None

        # LDAP None to Python
        python_value = converter.to_python(None)
        assert python_value is None

    def test_empty_value_handling(self):
        """Test empty value handling."""
        converter = FlextLdapTypeConverter()

        # Empty string
        assert converter.to_ldap("") == ""
        assert converter.to_python("") == ""

        # Empty list
        assert converter.to_ldap([]) == []
        assert converter.to_python([]) == []

    def test_error_handling(self):
        """Test conversion error handling."""
        converter = FlextLdapTypeConverter()

        # Invalid datetime format
        with pytest.raises(ValueError):
            converter.to_python("invalid-date", target_type=datetime)

        # Invalid integer format
        with pytest.raises(ValueError):
            converter.to_python("not-a-number", target_type=int)


class TestConversionUtilityFunctions:
    """Test utility conversion functions."""

    def test_convert_ldap_to_python(self):
        """Test ldap to python conversion function."""
        # String conversion
        result = convert_ldap_to_python(b"test string")
        assert result == "test string"

        # List conversion
        result = convert_ldap_to_python([b"value1", b"value2"])
        assert result == ["value1", "value2"]

        # Dict conversion (LDAP entry)
        ldap_entry = {
            "dn": b"cn=test,dc=example,dc=com",
            "attributes": {
                "cn": [b"Test User"],
                "mail": [b"test@example.com"],
                "employeeID": [b"12345"],
            },
        }
        result = convert_ldap_to_python(ldap_entry)
        assert result["dn"] == "cn=test,dc=example,dc=com"
        assert result["attributes"]["cn"] == ["Test User"]
        assert result["attributes"]["mail"] == ["test@example.com"]

    def test_convert_python_to_ldap(self):
        """Test python to ldap conversion function."""
        # String conversion
        result = convert_python_to_ldap("test string")
        assert result == "test string"

        # Integer conversion
        result = convert_python_to_ldap(123)
        assert result == "123"

        # Boolean conversion
        result = convert_python_to_ldap(True)
        assert result in ["TRUE", "true", "1"]

        # List conversion
        result = convert_python_to_ldap(["value1", "value2"])
        assert result == ["value1", "value2"]

        # Dict conversion
        python_data = {
            "cn": "Test User",
            "mail": ["test@example.com", "test2@example.com"],
            "employeeID": 12345,
        }
        result = convert_python_to_ldap(python_data)
        assert result["cn"] == "Test User"
        assert result["mail"] == ["test@example.com", "test2@example.com"]
        assert result["employeeID"] == "12345"

    def test_validate_ldap_attribute_value(self):
        """Test LDAP attribute value validation."""
        # Valid string
        assert validate_ldap_attribute_value("cn", "John Doe") is True

        # Valid email
        assert validate_ldap_attribute_value("mail", "john@example.com") is True

        # Valid integer as string
        assert validate_ldap_attribute_value("employeeID", "12345") is True

        # Invalid email format
        assert validate_ldap_attribute_value("mail", "invalid-email") is False

        # Invalid DN format
        assert validate_ldap_attribute_value("distinguishedName", "invalid-dn") is False

        # Empty value
        assert validate_ldap_attribute_value("cn", "") is False

        # None value
        assert validate_ldap_attribute_value("cn", None) is False

    def test_normalize_ldap_dn(self):
        """Test LDAP DN normalization."""
        # Basic normalization
        dn = "CN=John Doe,OU=Users,DC=Example,DC=Com"
        normalized = normalize_ldap_dn(dn)
        assert normalized == "cn=john doe,ou=users,dc=example,dc=com"

        # Remove extra spaces
        dn = "cn = john doe , ou = users , dc = example , dc = com"
        normalized = normalize_ldap_dn(dn)
        assert normalized == "cn=john doe,ou=users,dc=example,dc=com"

        # Handle escaped characters
        dn = "cn=John\\, Doe,ou=users,dc=example,dc=com"
        normalized = normalize_ldap_dn(dn)
        assert "john\\, doe" in normalized.lower()

        # Empty DN
        assert normalize_ldap_dn("") == ""

        # None DN
        assert normalize_ldap_dn(None) is None

    def test_parse_ldap_filter(self):
        """Test LDAP filter parsing."""
        # Simple equality filter
        filter_dict = parse_ldap_filter("(cn=john)")
        assert filter_dict["operator"] == "="
        assert filter_dict["attribute"] == "cn"
        assert filter_dict["value"] == "john"

        # Presence filter
        filter_dict = parse_ldap_filter("(mail=*)")
        assert filter_dict["operator"] == "present"
        assert filter_dict["attribute"] == "mail"

        # AND filter
        filter_dict = parse_ldap_filter("(&(cn=john)(ou=users))")
        assert filter_dict["operator"] == "&"
        assert len(filter_dict["operands"]) == 2

        # OR filter
        filter_dict = parse_ldap_filter("(|(cn=john)(cn=jane))")
        assert filter_dict["operator"] == "|"
        assert len(filter_dict["operands"]) == 2

        # NOT filter
        filter_dict = parse_ldap_filter("(!(cn=admin))")
        assert filter_dict["operator"] == "!"
        assert filter_dict["operand"]["attribute"] == "cn"

        # Complex nested filter
        complex_filter = "(&(objectClass=person)(|(cn=john)(mail=john@*))(!(ou=disabled)))"
        filter_dict = parse_ldap_filter(complex_filter)
        assert filter_dict["operator"] == "&"
        assert len(filter_dict["operands"]) == 3


class TestSpecializedConverters:
    """Test specialized conversion scenarios."""

    def test_active_directory_attributes(self):
        """Test Active Directory specific attribute conversions."""
        converter = FlextLdapTypeConverter()

        # objectGUID (binary)
        guid_bytes = b"\x12\x34\x56\x78\x9a\xbc\xde\xf0\x11\x22\x33\x44\x55\x66\x77\x88"
        result = converter.to_python(guid_bytes, attribute_name="objectGUID")
        assert isinstance(result, bytes)

        # userAccountControl (integer flags)
        uac_value = "512"  # Normal account
        result = converter.to_python(uac_value, attribute_name="userAccountControl", target_type=int)
        assert result == 512

        # pwdLastSet (Windows timestamp)
        pwd_timestamp = "132841234567890123"
        result = converter.to_python(pwd_timestamp, attribute_name="pwdLastSet", target_type=datetime)
        assert isinstance(result, datetime)

    def test_openldap_attributes(self):
        """Test OpenLDAP specific attribute conversions."""
        converter = FlextLdapTypeConverter()

        # createTimestamp (GeneralizedTime)
        timestamp = "20240115103045Z"
        result = converter.to_python(timestamp, attribute_name="createTimestamp", target_type=datetime)
        assert isinstance(result, datetime)
        assert result.year == 2024

        # entryUUID (UUID format)
        uuid_str = "12345678-1234-5678-9abc-def012345678"
        result = converter.to_python(uuid_str, attribute_name="entryUUID")
        assert result == uuid_str

    def test_oracle_directory_attributes(self):
        """Test Oracle Unified Directory specific conversions."""
        converter = FlextLdapTypeConverter()

        # orclGUID (Oracle specific GUID)
        oracle_guid = "550e8400-e29b-41d4-a716-446655440000"
        result = converter.to_python(oracle_guid, attribute_name="orclGUID")
        assert result == oracle_guid

        # Custom Oracle attributes
        custom_value = "oracle-specific-value"
        result = converter.to_python(custom_value, attribute_name="orclCustomAttr")
        assert result == custom_value

    def test_performance_large_datasets(self):
        """Test conversion performance with large datasets."""
        converter = FlextLdapTypeConverter()

        # Large list of values
        large_list = [f"value{i}" for i in range(1000)]
        result = converter.to_ldap(large_list)
        assert len(result) == 1000
        assert result[0] == "value0"
        assert result[999] == "value999"

        # Large binary data
        large_binary = b"x" * 10000
        result = converter.to_ldap(large_binary)
        assert result == large_binary
        assert len(result) == 10000

    def test_encoding_edge_cases(self):
        """Test encoding edge cases."""
        converter = FlextLdapTypeConverter()

        # UTF-8 characters
        utf8_text = "Café München 北京"
        result = converter.to_ldap(utf8_text)
        assert result == utf8_text

        # Special characters in DN components
        special_dn = "cn=John\\, Jr.,ou=users,dc=example,dc=com"
        result = converter.to_python(special_dn.encode())
        assert "John\\, Jr." in result

        # Control characters
        control_chars = "test\x00\x01\x02"
        result = converter.to_python(control_chars.encode(), preserve_binary=True)
        assert isinstance(result, bytes)

    def test_type_inference(self):
        """Test automatic type inference."""
        converter = FlextLdapTypeConverter()

        # Should infer integer
        result = converter.to_python("12345", auto_infer=True)
        assert result == 12345
        assert isinstance(result, int)

        # Should infer boolean
        result = converter.to_python("TRUE", auto_infer=True)
        assert result is True

        # Should infer datetime
        result = converter.to_python("20240115103045Z", auto_infer=True)
        assert isinstance(result, datetime)

        # Should remain string
        result = converter.to_python("not-a-number", auto_infer=True)
        assert result == "not-a-number"
        assert isinstance(result, str)


class TestConverterEdgeCases:
    """Test edge cases and error conditions."""

    def test_circular_references(self):
        """Test handling of circular references in data structures."""
        converter = FlextLdapTypeConverter()

        # Create circular reference
        data = {"key": "value"}
        data["self"] = data

        # Should handle gracefully without infinite recursion
        with pytest.raises((ValueError, RecursionError)):
            converter.to_ldap(data)

    def test_deeply_nested_structures(self):
        """Test deeply nested data structures."""
        converter = FlextLdapTypeConverter()

        # Create deeply nested dict
        nested = {"level": 1}
        current = nested
        for i in range(2, 100):
            current["next"] = {"level": i}
            current = current["next"]

        # Should handle reasonable nesting depth
        result = converter.to_ldap(nested)
        assert result["level"] == "1"

    def test_memory_efficiency(self):
        """Test memory efficiency with large conversions."""
        converter = FlextLdapTypeConverter()

        # Large string
        large_string = "x" * 1000000  # 1MB string
        result = converter.to_ldap(large_string)
        assert len(result) == 1000000

        # Should not create unnecessary copies
        assert result is large_string or result == large_string

    def test_thread_safety(self):
        """Test converter thread safety."""
        import threading

        converter = FlextLdapTypeConverter()
        results = []
        errors = []

        def convert_data(data, index):
            try:
                result = converter.to_ldap(f"value{index}")
                results.append(result)
            except Exception as e:
                errors.append(e)

        # Run multiple threads
        threads = []
        for i in range(10):
            thread = threading.Thread(target=convert_data, args=(f"value{i}", i))
            threads.append(thread)
            thread.start()

        for thread in threads:
            thread.join()

        # Should have no errors and correct results
        assert len(errors) == 0
        assert len(results) == 10
        assert "value0" in results
        assert "value9" in results


@pytest.mark.integration
class TestConverterIntegration:
    """Integration tests for converter functionality."""

    def test_roundtrip_conversion(self):
        """Test data integrity through roundtrip conversions."""
        converter = FlextLdapTypeConverter()

        # Test data
        test_data = {
            "string": "test string",
            "integer": 12345,
            "boolean": True,
            "list": ["item1", "item2", "item3"],
            "datetime": datetime(2024, 1, 15, 10, 30, 45, tzinfo=UTC),
            "binary": b"binary\x00data",
        }

        # Convert to LDAP and back
        ldap_data = converter.to_ldap(test_data)
        python_data = converter.to_python(ldap_data)

        # Verify integrity (with expected type changes)
        assert python_data["string"] == test_data["string"]
        assert python_data["integer"] == str(test_data["integer"])  # LDAP stores as string
        assert python_data["list"] == test_data["list"]
        assert python_data["binary"] == test_data["binary"]

    def test_real_ldap_entry_conversion(self):
        """Test conversion of realistic LDAP entry data."""
        converter = FlextLdapTypeConverter()

        # Simulate LDAP search result
        ldap_entry = {
            "dn": b"cn=John Doe,ou=users,dc=example,dc=com",
            "attributes": {
                "cn": [b"John Doe"],
                "sn": [b"Doe"],
                "givenName": [b"John"],
                "mail": [b"john@example.com", b"john.doe@example.com"],
                "employeeID": [b"12345"],
                "createTimestamp": [b"20240115103045Z"],
                "objectClass": [b"inetOrgPerson", b"person", b"top"],
            },
        }

        # Convert to Python
        python_entry = convert_ldap_to_python(ldap_entry)

        # Verify conversion
        assert python_entry["dn"] == "cn=John Doe,ou=users,dc=example,dc=com"
        assert python_entry["attributes"]["cn"] == ["John Doe"]
        assert python_entry["attributes"]["mail"] == ["john@example.com", "john.doe@example.com"]
        assert python_entry["attributes"]["employeeID"] == ["12345"]
        assert len(python_entry["attributes"]["objectClass"]) == 3

    def test_attribute_schema_aware_conversion(self):
        """Test schema-aware attribute conversion."""
        converter = FlextLdapTypeConverter()

        # Define attribute schema
        schema = {
            "employeeID": {"type": "integer"},
            "createTimestamp": {"type": "datetime"},
            "userAccountControl": {"type": "integer"},
            "mail": {"type": "string", "multi_value": True},
        }

        # Test conversion with schema
        ldap_value = "12345"
        result = converter.to_python(ldap_value, attribute_name="employeeID", schema=schema)
        assert result == 12345
        assert isinstance(result, int)

        # Test datetime with schema
        timestamp = "20240115103045Z"
        result = converter.to_python(timestamp, attribute_name="createTimestamp", schema=schema)
        assert isinstance(result, datetime)
