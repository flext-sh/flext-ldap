#!/usr/bin/env python3
"""Teste direto do utils.py para aumentar coverage.

Teste focado e direto, sem dependências complexas.
"""

import sys
sys.path.insert(0, 'src')

from flext_ldap.utils import flext_ldap_escape_filter_chars, flext_ldap_escape_filter_value

def test_escape_filter_chars():
    """Testa escape de caracteres especiais."""
    # Test basic escaping
    result = flext_ldap_escape_filter_chars("test*value")
    expected = r"test\2avalue"
    assert result == expected, f"Expected {expected}, got {result}"

    # Test parentheses
    result = flext_ldap_escape_filter_chars("(test)")
    expected = r"\28test\29"
    assert result == expected, f"Expected {expected}, got {result}"

    # Test backslash
    result = flext_ldap_escape_filter_chars("test\\value")
    expected = r"test\5cvalue"
    assert result == expected, f"Expected {expected}, got {result}"

    print("✅ test_escape_filter_chars PASSED")

def test_escape_filter_value():
    """Testa escape de valores de filtro."""
    # Test basic value
    result = flext_ldap_escape_filter_value("normal_value")
    assert result == "normal_value"

    # Test special characters
    result = flext_ldap_escape_filter_value("value*with(special)")
    expected = r"value\2awith\28special\29"
    assert result == expected, f"Expected {expected}, got {result}"

    print("✅ test_escape_filter_value PASSED")

if __name__ == "__main__":
    test_escape_filter_chars()
    test_escape_filter_value()
    print("🎉 ALL UTILS TESTS PASSED - Coverage increased!")
