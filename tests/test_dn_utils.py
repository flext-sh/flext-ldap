from typing import Any

"""
Tests for DN utilities.

Comprehensive tests for DN parsing, validation, and manipulation utilities
to ensure correctness across all LDAP operations.
"""

import pytest

from ldap_core_shared.utils.dn_utils import (
    build_dn,
    escape_dn_value,
    extract_attribute_value,
    find_common_base_dn,
    get_dn_depth,
    get_parent_dn,
    get_rdn,
    is_child_dn,
    normalize_dn,
    parse_dn,
    replace_base_dn,
    rewrite_dn_base,
    split_dn_components,
    unescape_dn_value,
    validate_dn_format,
)


class TestParseDn:
    """Test DN parsing functionality."""

    def test_simple_dn_parsing(self) -> Any:
        """Test parsing simple DN."""
        dn = parse_dn("cn=john,ou=users,dc=example,dc=com")

        assert len(dn.components) == 4
        assert dn.components[0].attribute == "cn"
        assert dn.components[0].value == "john"
        assert dn.components[1].attribute == "ou"
        assert dn.components[1].value == "users"

    def test_empty_dn_parsing(self) -> Any:
        """Test parsing empty DN."""
        with pytest.raises(ValueError, match="DN cannot be empty"):
            parse_dn("")

        with pytest.raises(ValueError, match="DN cannot be empty"):
            parse_dn("   ")

    def test_invalid_dn_parsing(self) -> Any:
        """Test parsing invalid DN format."""
        with pytest.raises(ValueError):
            parse_dn("invalid_format")

        with pytest.raises(ValueError):
            parse_dn("cn=john,invalid,dc=com")


class TestNormalizeDn:
    """Test DN normalization."""

    def test_attribute_case_normalization(self) -> Any:
        """Test attribute name case normalization."""
        normalized = normalize_dn("CN=John,OU=Users,DC=Example,DC=Com")

        assert "cn=John" in normalized
        assert "ou=Users" in normalized
        assert "dc=Example" in normalized
        assert "dc=Com" in normalized

    def test_whitespace_normalization(self) -> Any:
        """Test whitespace normalization."""
        normalized = normalize_dn("cn= John ,ou= Users , dc=example,dc=com")

        assert "cn=John" in normalized
        assert "ou=Users" in normalized


class TestChildDn:
    """Test child DN relationships."""

    def test_direct_child(self) -> Any:
        """Test direct child relationship."""
        child = "cn=john,ou=users,dc=example,dc=com"
        parent = "ou=users,dc=example,dc=com"

        assert is_child_dn(child, parent) is True

    def test_indirect_child(self) -> Any:
        """Test indirect child relationship."""
        child = "cn=john,ou=users,dc=example,dc=com"
        grandparent = "dc=example,dc=com"

        assert is_child_dn(child, grandparent) is True

    def test_not_child(self) -> Any:
        """Test non-child relationship."""
        dn1 = "cn=john,ou=users,dc=example,dc=com"
        dn2 = "cn=jane,ou=REDACTED_LDAP_BIND_PASSWORDs,dc=example,dc=com"

        assert is_child_dn(dn1, dn2) is False

    def test_same_dn(self) -> Any:
        """Test same DN (not child of itself)."""
        dn = "cn=john,ou=users,dc=example,dc=com"

        assert is_child_dn(dn, dn) is False

    def test_parent_child_reversed(self) -> Any:
        """Test parent as child of its child."""
        child = "cn=john,ou=users,dc=example,dc=com"
        parent = "ou=users,dc=example,dc=com"

        assert is_child_dn(parent, child) is False


class TestParentDn:
    """Test parent DN extraction."""

    def test_get_parent_simple(self) -> Any:
        """Test getting parent of simple DN."""
        dn = "cn=john,ou=users,dc=example,dc=com"
        parent = get_parent_dn(dn)

        assert parent == "ou=users,dc=example,dc=com"

    def test_get_parent_single_component(self) -> Any:
        """Test getting parent of single component DN."""
        dn = "dc=com"
        parent = get_parent_dn(dn)

        assert parent is None

    def test_get_parent_two_components(self) -> Any:
        """Test getting parent of two component DN."""
        dn = "ou=users,dc=com"
        parent = get_parent_dn(dn)

        assert parent == "dc=com"


class TestRdn:
    """Test RDN extraction."""

    def test_get_rdn_simple(self) -> Any:
        """Test getting RDN of simple DN."""
        dn = "cn=john,ou=users,dc=example,dc=com"
        rdn = get_rdn(dn)

        assert rdn == "cn=john"

    def test_get_rdn_single_component(self) -> Any:
        """Test getting RDN of single component DN."""
        dn = "dc=com"
        rdn = get_rdn(dn)

        assert rdn == "dc=com"


class TestReplaceBaseDn:
    """Test base DN replacement."""

    def test_replace_simple_base(self) -> Any:
        """Test replacing simple base DN."""
        dn = "cn=john,ou=users,dc=example,dc=com"
        old_base = "dc=example,dc=com"
        new_base = "dc=newdomain,dc=org"

        result = replace_base_dn(dn, old_base, new_base)

        assert result == "cn=john,ou=users,dc=newdomain,dc=org"

    def test_replace_complex_base(self) -> Any:
        """Test replacing complex base DN."""
        dn = "cn=john,ou=users,ou=people,dc=example,dc=com"
        old_base = "ou=people,dc=example,dc=com"
        new_base = "ou=employees,dc=newdomain,dc=org"

        result = replace_base_dn(dn, old_base, new_base)

        assert result == "cn=john,ou=users,ou=employees,dc=newdomain,dc=org"

    def test_replace_invalid_base(self) -> Any:
        """Test replacing with invalid base DN."""
        dn = "cn=john,ou=users,dc=example,dc=com"
        invalid_base = "dc=other,dc=com"
        new_base = "dc=newdomain,dc=org"

        with pytest.raises(
            ValueError, match="DN is not a child of the specified base DN"
        ):
            replace_base_dn(dn, invalid_base, new_base)


class TestEscapeDnValue:
    """Test DN value escaping."""

    def test_escape_comma(self) -> Any:
        """Test escaping comma in DN value."""
        value = "Smith, John"
        escaped = escape_dn_value(value)

        assert escaped == "Smith\\, John"

    def test_escape_backslash(self) -> Any:
        """Test escaping backslash in DN value."""
        value = "Domain\\User"
        escaped = escape_dn_value(value)

        assert escaped == "Domain\\\\User"

    def test_escape_quotes(self) -> Any:
        """Test escaping quotes in DN value."""
        value = 'John "Johnny" Doe'
        escaped = escape_dn_value(value)

        assert escaped == 'John \\"Johnny\\" Doe'

    def test_escape_leading_space(self) -> Any:
        """Test escaping leading space."""
        value = " John"
        escaped = escape_dn_value(value)

        assert escaped == "\\ John"

    def test_escape_trailing_space(self) -> Any:
        """Test escaping trailing space."""
        value = "John "
        escaped = escape_dn_value(value)

        assert escaped == "John\\ "

    def test_escape_multiple_chars(self) -> Any:
        """Test escaping multiple special characters."""
        value = 'Smith, John + "Junior" <REDACTED_LDAP_BIND_PASSWORD>'
        escaped = escape_dn_value(value)

        assert "\\" in escaped
        assert "Smith\\," in escaped
        assert "\\+" in escaped


class TestUnescapeDnValue:
    """Test DN value unescaping."""

    def test_unescape_comma(self) -> Any:
        """Test unescaping comma."""
        escaped = "Smith\\, John"
        unescaped = unescape_dn_value(escaped)

        assert unescaped == "Smith, John"

    def test_unescape_backslash(self) -> Any:
        """Test unescaping backslash."""
        escaped = "Domain\\\\User"
        unescaped = unescape_dn_value(escaped)

        assert unescaped == "Domain\\User"

    def test_unescape_space(self) -> Any:
        """Test unescaping spaces."""
        escaped = "\\ John\\ "
        unescaped = unescape_dn_value(escaped)

        assert unescaped == " John "


class TestExtractAttributeValue:
    """Test attribute value extraction from DN."""

    def test_extract_existing_attribute(self) -> Any:
        """Test extracting existing attribute."""
        dn = "cn=john,ou=users,dc=example,dc=com"

        assert extract_attribute_value(dn, "cn") == "john"
        assert extract_attribute_value(dn, "ou") == "users"
        assert extract_attribute_value(dn, "dc") == "example"

    def test_extract_case_insensitive(self) -> Any:
        """Test case-insensitive attribute extraction."""
        dn = "cn=john,ou=users,dc=example,dc=com"

        assert extract_attribute_value(dn, "CN") == "john"
        assert extract_attribute_value(dn, "OU") == "users"
        assert extract_attribute_value(dn, "DC") == "example"

    def test_extract_nonexistent_attribute(self) -> Any:
        """Test extracting non-existent attribute."""
        dn = "cn=john,ou=users,dc=example,dc=com"

        assert extract_attribute_value(dn, "uid") is None
        assert extract_attribute_value(dn, "mail") is None

    def test_extract_from_invalid_dn(self) -> Any:
        """Test extracting from invalid DN."""
        invalid_dn = "invalid_dn_format"

        assert extract_attribute_value(invalid_dn, "cn") is None


class TestBuildDn:
    """Test DN building from components."""

    def test_build_simple_dn(self) -> Any:
        """Test building simple DN."""
        components = [("cn", "john"), ("ou", "users"), ("dc", "example"), ("dc", "com")]
        dn = build_dn(components)

        assert dn == "cn=john,ou=users,dc=example,dc=com"

    def test_build_dn_with_escaping(self) -> Any:
        """Test building DN with special characters."""
        components = [("cn", "Smith, John"), ("ou", "users"), ("dc", "example")]
        dn = build_dn(components)

        assert "Smith\\, John" in dn


class TestSplitDnComponents:
    """Test splitting DN into components."""

    def test_split_simple_dn(self) -> Any:
        """Test splitting simple DN."""
        dn = "cn=john,ou=users,dc=example,dc=com"
        components = split_dn_components(dn)

        expected = [("cn", "john"), ("ou", "users"), ("dc", "example"), ("dc", "com")]
        assert components == expected

    def test_split_invalid_dn(self) -> Any:
        """Test splitting invalid DN."""
        invalid_dn = "invalid_format"
        components = split_dn_components(invalid_dn)

        assert components == []


class TestValidateDnFormat:
    """Test DN format validation."""

    def test_validate_valid_dn(self) -> Any:
        """Test validating valid DN."""
        valid_dn = "cn=john,ou=users,dc=example,dc=com"
        is_valid, error = validate_dn_format(valid_dn)

        assert is_valid is True
        assert error is None

    def test_validate_empty_dn(self) -> Any:
        """Test validating empty DN."""
        is_valid, error = validate_dn_format("")

        assert is_valid is False
        assert "DN cannot be empty" in error

    def test_validate_invalid_dn(self) -> Any:
        """Test validating invalid DN."""
        invalid_dn = "invalid_format"
        is_valid, error = validate_dn_format(invalid_dn)

        assert is_valid is False
        assert error is not None


class TestGetDnDepth:
    """Test DN depth calculation."""

    def test_depth_simple_dn(self) -> Any:
        """Test depth of simple DN."""
        dn = "cn=john,ou=users,dc=example,dc=com"
        depth = get_dn_depth(dn)

        assert depth == 4

    def test_depth_single_component(self) -> Any:
        """Test depth of single component DN."""
        dn = "dc=com"
        depth = get_dn_depth(dn)

        assert depth == 1

    def test_depth_invalid_dn(self) -> Any:
        """Test depth of invalid DN."""
        invalid_dn = "invalid_format"
        depth = get_dn_depth(invalid_dn)

        assert depth == 0


class TestFindCommonBaseDn:
    """Test finding common base DN."""

    def test_find_common_base_simple(self) -> Any:
        """Test finding common base of simple DNs."""
        dns = [
            "cn=john,ou=users,dc=example,dc=com",
            "cn=jane,ou=users,dc=example,dc=com",
            "cn=REDACTED_LDAP_BIND_PASSWORD,ou=REDACTED_LDAP_BIND_PASSWORDs,dc=example,dc=com",
        ]

        common_base = find_common_base_dn(dns)

        assert common_base == "dc=example,dc=com"

    def test_find_common_base_deeper(self) -> Any:
        """Test finding deeper common base."""
        dns = [
            "cn=john,ou=developers,ou=users,dc=example,dc=com",
            "cn=jane,ou=testers,ou=users,dc=example,dc=com",
        ]

        common_base = find_common_base_dn(dns)

        assert common_base == "ou=users,dc=example,dc=com"

    def test_find_common_base_no_common(self) -> Any:
        """Test finding common base with no common elements."""
        dns = ["cn=john,dc=example,dc=com", "cn=jane,dc=other,dc=org"]

        common_base = find_common_base_dn(dns)

        assert common_base is None

    def test_find_common_base_empty_list(self) -> Any:
        """Test finding common base of empty list."""
        common_base = find_common_base_dn([])

        assert common_base is None

    def test_find_common_base_single_dn(self) -> Any:
        """Test finding common base of single DN."""
        dns = ["cn=john,ou=users,dc=example,dc=com"]
        common_base = find_common_base_dn(dns)

        assert common_base == "ou=users,dc=example,dc=com"


class TestRewriteDnBase:
    """Test DN base rewriting."""

    def test_rewrite_matching_base(self) -> Any:
        """Test rewriting with matching base."""
        dn = "cn=john,ou=users,dc=example,dc=com"
        mappings = {"dc=example,dc=com": "dc=newdomain,dc=org"}

        result = rewrite_dn_base(dn, mappings)

        assert result == "cn=john,ou=users,dc=newdomain,dc=org"

    def test_rewrite_no_matching_base(self) -> Any:
        """Test rewriting with no matching base."""
        dn = "cn=john,ou=users,dc=example,dc=com"
        mappings = {"dc=other,dc=com": "dc=newdomain,dc=org"}

        result = rewrite_dn_base(dn, mappings)

        # Should return original DN unchanged
        assert result == dn

    def test_rewrite_multiple_mappings(self) -> Any:
        """Test rewriting with multiple mappings."""
        dn = "cn=john,ou=users,dc=example,dc=com"
        mappings = {
            "dc=other,dc=com": "dc=wrong,dc=org",
            "dc=example,dc=com": "dc=correct,dc=org",
            "ou=users,dc=example,dc=com": "ou=people,dc=example,dc=com",
        }

        result = rewrite_dn_base(dn, mappings)

        # Should use the most specific matching base
        assert result == "cn=john,ou=people,dc=example,dc=com"
