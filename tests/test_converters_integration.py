"""Test converters module integration.

Integration tests for flext_ldap.converters to increase coverage.
"""

from flext_ldap.converters import FlextLdapConverterConstants, FlextLdapDataType


class TestFlextLdapConverterConstants:
    """Test converter constants."""

    def test_converter_constants_values(self):
        """Test that constants have expected values."""
        assert FlextLdapConverterConstants.LDAP_TIME_FORMAT_LONG == 15
        assert FlextLdapConverterConstants.LDAP_TIME_FORMAT_SHORT == 13

    def test_constants_are_integers(self):
        """Test that constants are proper integers."""
        assert isinstance(FlextLdapConverterConstants.LDAP_TIME_FORMAT_LONG, int)
        assert isinstance(FlextLdapConverterConstants.LDAP_TIME_FORMAT_SHORT, int)


class TestFlextLdapDataType:
    """Test data type enum."""

    def test_data_type_enum_values(self):
        """Test enum values exist."""
        # Test specific enum access
        assert FlextLdapDataType.STRING.value == "string"
        assert FlextLdapDataType.INTEGER.value == "integer"
        assert FlextLdapDataType.BOOLEAN.value == "boolean"
        assert FlextLdapDataType.DATE_TIME.value == "datetime"
        assert FlextLdapDataType.BINARY.value == "binary"

    def test_enum_completeness(self):
        """Test enum has expected data types."""
        data_types = [member.value for member in FlextLdapDataType]

        # Should have common data types
        expected_types = ["string", "integer", "boolean", "datetime", "binary"]
        for expected_type in expected_types:
            assert expected_type in data_types, f"Missing data type: {expected_type}"

    def test_enum_properties(self):
        """Test enum name access."""
        assert FlextLdapDataType.STRING.name == "STRING"
        assert FlextLdapDataType.INTEGER.name == "INTEGER"
        assert FlextLdapDataType.BOOLEAN.name == "BOOLEAN"

    def test_enum_iteration(self):
        """Test that we can iterate over enum."""
        type_count = len(list(FlextLdapDataType))
        assert type_count > 0, "Enum should have members"

        # Test all members are accessible
        for data_type in FlextLdapDataType:
            assert hasattr(data_type, 'name')
            assert hasattr(data_type, 'value')
