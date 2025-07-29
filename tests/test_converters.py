"""Enterprise-grade tests for FlextLdap converters.

# Constants
EXPECTED_BULK_SIZE = 2
EXPECTED_DATA_COUNT = 3

Tests data type conversion utilities with comprehensive validation.
"""

import threading


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
        if ldap_value != "test string":
            raise AssertionError(f"Expected {"test string"}, got {ldap_value}")

        # LDAP to Python
        python_value = converter.to_python(b"test bytes")
        if python_value != "test bytes":
            raise AssertionError(f"Expected {"test bytes"}, got {python_value}")
        assert isinstance(python_value, str)

    def test_integer_conversion(self):
        """Test integer type conversions."""
        converter = FlextLdapTypeConverter()

        # Python to LDAP
        ldap_value = converter.to_ldap(123)
        if ldap_value != "123":
            raise AssertionError(f"Expected {"123"}, got {ldap_value}")

        # LDAP to Python
        python_value = converter.to_python("456", target_type=int)
        if python_value != 456:
            raise AssertionError(f"Expected {456}, got {python_value}")
        assert isinstance(python_value, int)

    def test_boolean_conversion(self):
        """Test boolean type conversions."""
        converter = FlextLdapTypeConverter()

        # Python to LDAP
        true_value = converter.to_ldap(True)
        false_value = converter.to_ldap(False)

        if true_value not in {"TRUE", "true", "1"}:

            raise AssertionError(f"Expected {true_value} in {{"TRUE", "true", "1"}}")
        assert false_value in {"FALSE", "false", "0"}

        # LDAP to Python
        if not (converter.to_python("TRUE", target_type=bool)):
            raise AssertionError(f"Expected True, got {converter.to_python("TRUE", target_type=bool)}")
        if converter.to_python("false", target_type=bool):
            raise AssertionError(f"Expected False, got {converter.to_python("false", target_type=bool)}")
        if not (converter.to_python("1", target_type=bool)):
            raise AssertionError(f"Expected True, got {converter.to_python("1", target_type=bool)}")
        if converter.to_python("0", target_type=bool):
            raise AssertionError(f"Expected False, got {converter.to_python("0", target_type=bool)}")

    def test_datetime_conversion(self):
        """Test datetime type conversions."""
        converter = FlextLdapTypeConverter()

        # Python to LDAP (GeneralizedTime format)
        dt = datetime(2024, 1, 15, 10, 30, 45, tzinfo=UTC)
        ldap_value = converter.to_ldap(dt)
        if ldap_value != "20240115103045Z":
            raise AssertionError(f"Expected {"20240115103045Z"}, got {ldap_value}")

        # LDAP to Python
        python_dt = converter.to_python("20240115103045Z", target_type=datetime)
        assert isinstance(python_dt, datetime)
        if python_dt.year != 2024:
            raise AssertionError(f"Expected {2024}, got {python_dt.year}")
        assert python_dt.month == 1
        if python_dt.day != 15:
            raise AssertionError(f"Expected {15}, got {python_dt.day}")

    def test_list_conversion(self):
        """Test list/multi-value conversions."""
        converter = FlextLdapTypeConverter()

        # Python list to LDAP
        python_list = ["value1", "value2", "value3"]
        ldap_values = converter.to_ldap(python_list)
        if ldap_values != ["value1", "value2", "value3"]:
            raise AssertionError(f"Expected {["value1", "value2", "value3"]}, got {ldap_values}")

        # LDAP list to Python
        ldap_list = [b"value1", b"value2", b"value3"]
        python_values = converter.to_python(ldap_list)
        if python_values != ["value1", "value2", "value3"]:
            raise AssertionError(f"Expected {["value1", "value2", "value3"]}, got {python_values}")

    def test_bytes_conversion(self):
        """Test binary data conversions."""
        converter = FlextLdapTypeConverter()

        # Python bytes to LDAP
        binary_data = b"binary\x00data"
        ldap_value = converter.to_ldap(binary_data)
        if ldap_value != binary_data:
            raise AssertionError(f"Expected {binary_data}, got {ldap_value}")

        # LDAP bytes to Python
        python_value = converter.to_python(binary_data, preserve_binary=True)
        if python_value != binary_data:
            raise AssertionError(f"Expected {binary_data}, got {python_value}")
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
        if converter.to_ldap("") != "":
            raise AssertionError(f"Expected {""}, got {converter.to_ldap("")}")
        assert converter.to_python("") == ""

        # Empty list
        if converter.to_ldap([]) != []:
            raise AssertionError(f"Expected {[]}, got {converter.to_ldap([])}")
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
        if result != "test string":
            raise AssertionError(f"Expected {"test string"}, got {result}")

        # List conversion
        result = convert_ldap_to_python([b"value1", b"value2"])
        if result != ["value1", "value2"]:
            raise AssertionError(f"Expected {["value1", "value2"]}, got {result}")

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
        if result["dn"] != "cn=test,dc=example,dc=com":
            raise AssertionError(f"Expected {"cn=test,dc=example,dc=com"}, got {result["dn"]}")
        assert result["attributes"]["cn"] == ["Test User"]
        if result["attributes"]["mail"] != ["test@example.com"]:
            raise AssertionError(f"Expected {["test@example.com"]}, got {result["attributes"]["mail"]}")

    def test_convert_python_to_ldap(self):
        """Test python to ldap conversion function."""
        # String conversion
        result = convert_python_to_ldap("test string")
        if result != "test string":
            raise AssertionError(f"Expected {"test string"}, got {result}")

        # Integer conversion
        result = convert_python_to_ldap(123)
        if result != "123":
            raise AssertionError(f"Expected {"123"}, got {result}")

        # Boolean conversion
        result = convert_python_to_ldap(True)
        if result not in {"TRUE", "true", "1"}:
            raise AssertionError(f"Expected {result} in {{"TRUE", "true", "1"}}")

        # List conversion
        result = convert_python_to_ldap(["value1", "value2"])
        if result != ["value1", "value2"]:
            raise AssertionError(f"Expected {["value1", "value2"]}, got {result}")

        # Dict conversion
        python_data = {
            "cn": "Test User",
            "mail": ["test@example.com", "test2@example.com"],
            "employeeID": 12345,
        }
        result = convert_python_to_ldap(python_data)
        if result["cn"] != "Test User":
            raise AssertionError(f"Expected {"Test User"}, got {result["cn"]}")
        assert result["mail"] == ["test@example.com", "test2@example.com"]
        if result["employeeID"] != "12345":
            raise AssertionError(f"Expected {"12345"}, got {result["employeeID"]}")

    def test_validate_ldap_attribute_value(self):
        """Test LDAP attribute value validation."""
        # Valid string
        if not (validate_ldap_attribute_value("cn", "John Doe")):
            raise AssertionError(f"Expected True, got {validate_ldap_attribute_value("cn", "John Doe")}")

        # Valid email
        if not (validate_ldap_attribute_value("mail", "john@example.com")):
            raise AssertionError(f"Expected True, got {validate_ldap_attribute_value("mail", "john@example.com")}")

        # Valid integer as string
        if not (validate_ldap_attribute_value("employeeID", "12345")):
            raise AssertionError(f"Expected True, got {validate_ldap_attribute_value("employeeID", "12345")}")

        # Invalid email format
        if validate_ldap_attribute_value("mail", "invalid-email"):
            raise AssertionError(f"Expected False, got {validate_ldap_attribute_value("mail", "invalid-email")}")

        # Invalid DN format
        if validate_ldap_attribute_value("distinguishedName", "invalid-dn"):
            raise AssertionError(f"Expected False, got {validate_ldap_attribute_value("distinguishedName", "invalid-dn")}")

        # Empty value
        if validate_ldap_attribute_value("cn", ""):
            raise AssertionError(f"Expected False, got {validate_ldap_attribute_value("cn", "")}")

        # None value
        if validate_ldap_attribute_value("cn", None):
            raise AssertionError(f"Expected False, got {validate_ldap_attribute_value("cn", None)}")

    def test_normalize_ldap_dn(self):
        """Test LDAP DN normalization."""
        # Basic normalization
        dn = "CN=John Doe,OU=Users,DC=Example,DC=Com"
        normalized = normalize_ldap_dn(dn)
        if normalized != "cn=john doe,ou=users,dc=example,dc=com":
            raise AssertionError(f"Expected {"cn=john doe,ou=users,dc=example,dc=com"}, got {normalized}")

        # Remove extra spaces
        dn = "cn = john doe , ou = users , dc = example , dc = com"
        normalized = normalize_ldap_dn(dn)
        if normalized != "cn=john doe,ou=users,dc=example,dc=com":
            raise AssertionError(f"Expected {"cn=john doe,ou=users,dc=example,dc=com"}, got {normalized}")

        # Handle escaped characters
        dn = "cn=John\\, Doe,ou=users,dc=example,dc=com"
        normalized = normalize_ldap_dn(dn)
        if "john\\, doe" not in normalized.lower():
            raise AssertionError(f"Expected {"john\\, doe"} in {normalized.lower()}")

        # Empty DN
        if normalize_ldap_dn("") != "":
            raise AssertionError(f"Expected {""}, got {normalize_ldap_dn("")}")

        # None DN
        assert normalize_ldap_dn(None) is None

    def test_parse_ldap_filter(self):
        """Test LDAP filter parsing."""
        # Simple equality filter
        filter_dict = parse_ldap_filter("(cn=john)")
        if filter_dict["operator"] != "=":
            raise AssertionError(f"Expected {"="}, got {filter_dict["operator"]}")
        assert filter_dict["attribute"] == "cn"
        if filter_dict["value"] != "john":
            raise AssertionError(f"Expected {"john"}, got {filter_dict["value"]}")

        # Presence filter
        filter_dict = parse_ldap_filter("(mail=*)")
        if filter_dict["operator"] != "present":
            raise AssertionError(f"Expected {"present"}, got {filter_dict["operator"]}")
        assert filter_dict["attribute"] == "mail"

        # AND filter
        filter_dict = parse_ldap_filter("(&(cn=john)(ou=users))")
        if filter_dict["operator"] != "&":
            raise AssertionError(f"Expected {"&"}, got {filter_dict["operator"]}")
        assert len(filter_dict["operands"]) == EXPECTED_BULK_SIZE

        # OR filter
        filter_dict = parse_ldap_filter("(|(cn=john)(cn=jane))")
        if filter_dict["operator"] != "|":
            raise AssertionError(f"Expected {"|"}, got {filter_dict["operator"]}")
        assert len(filter_dict["operands"]) == EXPECTED_BULK_SIZE

        # NOT filter
        filter_dict = parse_ldap_filter("(!(cn=admin))")
        if filter_dict["operator"] != "!":
            raise AssertionError(f"Expected {"!"}, got {filter_dict["operator"]}")
        assert filter_dict["operand"]["attribute"] == "cn"

        # Complex nested filter
        complex_filter = "(&(objectClass=person)(|(cn=john)(mail=john@*))(!(ou=disabled)))"
        filter_dict = parse_ldap_filter(complex_filter)
        if filter_dict["operator"] != "&":
            raise AssertionError(f"Expected {"&"}, got {filter_dict["operator"]}")
        assert len(filter_dict["operands"]) == EXPECTED_DATA_COUNT


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
        if result != 512:
            raise AssertionError(f"Expected {512}, got {result}")

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
        if result.year != 2024:
            raise AssertionError(f"Expected {2024}, got {result.year}")

        # entryUUID (UUID format)
        uuid_str = "12345678-1234-5678-9abc-def012345678"
        result = converter.to_python(uuid_str, attribute_name="entryUUID")
        if result != uuid_str:
            raise AssertionError(f"Expected {uuid_str}, got {result}")

    def test_oracle_directory_attributes(self):
        """Test Oracle Unified Directory specific conversions."""
        converter = FlextLdapTypeConverter()

        # orclGUID (Oracle specific GUID)
        oracle_guid = "550e8400-e29b-41d4-a716-446655440000"
        result = converter.to_python(oracle_guid, attribute_name="orclGUID")
        if result != oracle_guid:
            raise AssertionError(f"Expected {oracle_guid}, got {result}")

        # Custom Oracle attributes
        custom_value = "oracle-specific-value"
        result = converter.to_python(custom_value, attribute_name="orclCustomAttr")
        if result != custom_value:
            raise AssertionError(f"Expected {custom_value}, got {result}")

    def test_performance_large_datasets(self):
        """Test conversion performance with large datasets."""
        converter = FlextLdapTypeConverter()

        # Large list of values
        large_list = [f"value{i}" for i in range(1000)]
        result = converter.to_ldap(large_list)
        if len(result) != 1000:
            raise AssertionError(f"Expected {1000}, got {len(result)}")
        assert result[0] == "value0"
        if result[999] != "value999":
            raise AssertionError(f"Expected {"value999"}, got {result[999]}")

        # Large binary data
        large_binary = b"x" * 10000
        result = converter.to_ldap(large_binary)
        if result != large_binary:
            raise AssertionError(f"Expected {large_binary}, got {result}")
        assert len(result) == 10000

    def test_encoding_edge_cases(self):
        """Test encoding edge cases."""
        converter = FlextLdapTypeConverter()

        # UTF-8 characters
        utf8_text = "Café München 北京"
        result = converter.to_ldap(utf8_text)
        if result != utf8_text:
            raise AssertionError(f"Expected {utf8_text}, got {result}")

        # Special characters in DN components
        special_dn = "cn=John\\, Jr.,ou=users,dc=example,dc=com"
        result = converter.to_python(special_dn.encode())
        if "John\\, Jr." not in result:
            raise AssertionError(f"Expected {"John\\, Jr."} in {result}")

        # Control characters
        control_chars = "test\x00\x01\x02"
        result = converter.to_python(control_chars.encode(), preserve_binary=True)
        assert isinstance(result, bytes)

    def test_type_inference(self):
        """Test automatic type inference."""
        converter = FlextLdapTypeConverter()

        # Should infer integer
        result = converter.to_python("12345", auto_infer=True)
        if result != 12345:
            raise AssertionError(f"Expected {12345}, got {result}")
        assert isinstance(result, int)

        # Should infer boolean
        result = converter.to_python("TRUE", auto_infer=True)
        if not (result):
            raise AssertionError(f"Expected True, got {result}")

        # Should infer datetime
        result = converter.to_python("20240115103045Z", auto_infer=True)
        assert isinstance(result, datetime)

        # Should remain string
        result = converter.to_python("not-a-number", auto_infer=True)
        if result != "not-a-number":
            raise AssertionError(f"Expected {"not-a-number"}, got {result}")
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
        if result["level"] != "1":
            raise AssertionError(f"Expected {"1"}, got {result["level"]}")

    def test_memory_efficiency(self):
        """Test memory efficiency with large conversions."""
        converter = FlextLdapTypeConverter()

        # Large string
        large_string = "x" * 1000000  # 1MB string
        result = converter.to_ldap(large_string)
        if len(result) != 1000000:
            raise AssertionError(f"Expected {1000000}, got {len(result)}")

        # Should not create unnecessary copies
        if result is large_string or result != large_string:
            raise AssertionError(f"Expected {large_string}, got {result is large_string or result}")

    def test_thread_safety(self):
        """Test converter thread safety."""


        converter = FlextLdapTypeConverter()
        results = []
        errors = []

        def convert_data(data, index):
            try:
                result = converter.to_ldap(f"value{index}")
                results.append(result)
            except (RuntimeError, ValueError, TypeError) as e:
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
        if len(errors) != 0:
            raise AssertionError(f"Expected {0}, got {len(errors)}")
        assert len(results) == 10
        if "value0" not in results:
            raise AssertionError(f"Expected {"value0"} in {results}")
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
        if python_data["string"] != test_data["string"]:
            raise AssertionError(f"Expected {test_data["string"]}, got {python_data["string"]}")
        assert python_data["integer"] == str(test_data["integer"])  # LDAP stores as string
        if python_data["list"] != test_data["list"]:
            raise AssertionError(f"Expected {test_data["list"]}, got {python_data["list"]}")
        assert python_data["binary"] == test_data["binary"]

    def test_real_ldap_entry_conversion(self):
        """Test conversion of realistic LDAP entry data."""
        FlextLdapTypeConverter()

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
        if python_entry["dn"] != "cn=John Doe,ou=users,dc=example,dc=com":
            raise AssertionError(f"Expected {"cn=John Doe,ou=users,dc=example,dc=com"}, got {python_entry["dn"]}")
        assert python_entry["attributes"]["cn"] == ["John Doe"]
        if python_entry["attributes"]["mail"] != ["john@example.com", "john.doe@example.com"]:
            raise AssertionError(f"Expected {["john@example.com", "john.doe@example.com"]}, got {python_entry["attributes"]["mail"]}")
        assert python_entry["attributes"]["employeeID"] == ["12345"]
        if len(python_entry["attributes"]["objectClass"]) != EXPECTED_DATA_COUNT:
            raise AssertionError(f"Expected {3}, got {len(python_entry["attributes"]["objectClass"])}")

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
        if result != 12345:
            raise AssertionError(f"Expected {12345}, got {result}")
        assert isinstance(result, int)

        # Test datetime with schema
        timestamp = "20240115103045Z"
        result = converter.to_python(timestamp, attribute_name="createTimestamp", schema=schema)
        assert isinstance(result, datetime)
