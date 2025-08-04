#!/usr/bin/env python3
"""Teste direto do converters.py para aumentar coverage.

Teste focado e direto das classes e enums básicos.
"""

import sys
sys.path.insert(0, 'src')

from flext_ldap.converters import FlextLdapConverterConstants, FlextLdapDataType

def test_converter_constants():
    """Testa constantes do converter."""
    # Test constants exist and have expected values
    assert FlextLdapConverterConstants.LDAP_TIME_FORMAT_LONG == 15
    assert FlextLdapConverterConstants.LDAP_TIME_FORMAT_SHORT == 13

    print("✅ test_converter_constants PASSED")

def test_data_type_enum():
    """Testa enum de tipos de dados."""
    # Test enum values exist
    data_types = [member.value for member in FlextLdapDataType]

    # Should have common data types
    expected_types = ["string", "integer", "boolean", "datetime", "binary"]
    for expected_type in expected_types:
        assert expected_type in data_types, f"Missing data type: {expected_type}"

    # Test specific enum access
    assert FlextLdapDataType.STRING.value == "string"
    assert FlextLdapDataType.INTEGER.value == "integer"
    assert FlextLdapDataType.BOOLEAN.value == "boolean"

    print("✅ test_data_type_enum PASSED")

def test_enum_properties():
    """Testa propriedades do enum."""
    # Test that we can iterate over enum
    type_count = len(list(FlextLdapDataType))
    assert type_count > 0, "Enum should have members"

    # Test enum name access
    assert FlextLdapDataType.STRING.name == "STRING"
    assert FlextLdapDataType.INTEGER.name == "INTEGER"

    print("✅ test_enum_properties PASSED")

if __name__ == "__main__":
    test_converter_constants()
    test_data_type_enum()
    test_enum_properties()
    print("🎉 ALL CONVERTERS TESTS PASSED - Coverage increased!")
