"""Tests for LDAP utilities."""

from datetime import UTC, datetime
from urllib.parse import urlparse

import pytest

from flext_ldap.utils import (
    build_dn,
    build_filter,
    compare_dns,
    escape_filter_chars,
    escape_filter_value,
    format_generalized_time,
    format_ldap_timestamp,
    is_valid_ldap_url,
    normalize_attribute_name,
    normalize_dn,
    parse_dn,
    parse_generalized_time,
    parse_ldap_url,
    split_dn,
    validate_dn,
)


class TestFilterEscaping:
    """Test LDAP filter escaping utilities."""

    def test_escape_filter_chars_basic(self) -> None:
        """Test escaping of basic special characters."""
        result = escape_filter_chars("test*value")
        assert result == "test\\2avalue"

    def test_escape_filter_chars_all_special(self) -> None:
        """Test escaping all special characters."""
        input_str = "test*()\\test"
        result = escape_filter_chars(input_str)
        assert result == "test\\2a\\28\\29\\5ctest"

    def test_escape_filter_chars_null_byte(self) -> None:
        """Test escaping null byte."""
        input_str = "test\x00value"
        result = escape_filter_chars(input_str)
        assert result == "test\\00value"

    def test_escape_filter_chars_empty_string(self) -> None:
        """Test escaping empty string."""
        result = escape_filter_chars("")
        assert result == ""

    def test_escape_filter_value_alias(self) -> None:
        """Test that escape_filter_value is an alias."""
        test_str = "test*value"
        assert escape_filter_value(test_str) == escape_filter_chars(test_str)


class TestGeneralizedTime:
    """Test LDAP generalized time utilities."""

    def test_parse_generalized_time_with_z(self) -> None:
        """Test parsing generalized time with Z suffix."""
        time_str = "20231215143022Z"
        result = parse_generalized_time(time_str)

        expected = datetime(2023, 12, 15, 14, 30, 22, tzinfo=UTC)
        assert result == expected

    def test_parse_generalized_time_without_z(self) -> None:
        """Test parsing generalized time without Z suffix."""
        time_str = "20231215143022"
        result = parse_generalized_time(time_str)

        expected = datetime(
            2023, 12, 15, 14, 30, 22,
        )  # No timezone when Z suffix absent
        assert result == expected

    def test_format_generalized_time_with_timezone(self) -> None:
        """Test formatting datetime with timezone."""
        dt = datetime(2023, 12, 15, 14, 30, 22, tzinfo=UTC)
        result = format_generalized_time(dt)
        assert result == "20231215143022Z"

    def test_format_generalized_time_without_timezone(self) -> None:
        """Test formatting datetime without timezone."""
        dt = datetime(2023, 12, 15, 14, 30, 22, tzinfo=UTC)
        result = format_generalized_time(dt)
        assert result == "20231215143022Z"


class TestDNUtilities:
    """Test DN (Distinguished Name) utilities."""

    def test_validate_dn_valid(self) -> None:
        """Test validating valid DN."""
        dn = "cn=user,ou=people,dc=example,dc=com"
        assert validate_dn(dn) is True

    def test_validate_dn_invalid_empty(self) -> None:
        """Test validating empty DN."""
        assert validate_dn("") is False

    def test_validate_dn_invalid_no_equals(self) -> None:
        """Test validating DN without equals sign."""
        dn = "cn user,ou people"
        assert validate_dn(dn) is False

    def test_normalize_dn(self) -> None:
        """Test DN normalization."""
        dn = "CN=User,OU=People,DC=Example,DC=Com"
        result = normalize_dn(dn)
        assert result == "cn=user,ou=people,dc=example,dc=com"

    def test_normalize_dn_with_spaces(self) -> None:
        """Test DN normalization with spaces."""
        dn = " CN = User , OU = People "
        result = normalize_dn(dn)
        assert result == "cn=user,ou=people"

    def test_split_dn(self) -> None:
        """Test splitting DN into components."""
        dn = "cn=user,ou=people,dc=example,dc=com"
        result = split_dn(dn)
        expected = ["cn=user", "ou=people", "dc=example", "dc=com"]
        assert result == expected

    def test_split_dn_empty(self) -> None:
        """Test splitting empty DN."""
        result = split_dn("")
        assert result == []

    def test_split_dn_with_spaces(self) -> None:
        """Test splitting DN with spaces."""
        dn = " cn=user , ou=people , dc=example "
        result = split_dn(dn)
        expected = ["cn=user", "ou=people", "dc=example"]
        assert result == expected

    def test_compare_dns_equal(self) -> None:
        """Test comparing equal DNs."""
        dn1 = "CN=User,OU=People,DC=Example,DC=Com"
        dn2 = "cn=user,ou=people,dc=example,dc=com"
        assert compare_dns(dn1, dn2) is True

    def test_compare_dns_different(self) -> None:
        """Test comparing different DNs."""
        dn1 = "cn=user1,ou=people,dc=example,dc=com"
        dn2 = "cn=user2,ou=people,dc=example,dc=com"
        assert compare_dns(dn1, dn2) is False


class TestFilterBuilding:
    """Test LDAP filter building utilities."""

    def test_build_filter_and(self) -> None:
        """Test building AND filter."""
        conditions = {"cn": "john", "sn": "doe"}
        result = build_filter("and", conditions)
        assert result == "(&(cn=john)(sn=doe))"

    def test_build_filter_or(self) -> None:
        """Test building OR filter."""
        conditions = {"cn": "john", "sn": "doe"}
        result = build_filter("or", conditions)
        assert result == "(|(cn=john)(sn=doe))"

    def test_build_filter_not_single(self) -> None:
        """Test building NOT filter with single condition."""
        conditions = {"cn": "john"}
        result = build_filter("not", conditions)
        assert result == "(!(cn=john))"

    def test_build_filter_not_multiple(self) -> None:
        """Test building NOT filter with multiple conditions."""
        conditions = {"cn": "john", "sn": "doe"}
        result = build_filter("not", conditions)
        assert result == "(!(&(cn=john)(sn=doe)))"

    def test_build_filter_empty_conditions(self) -> None:
        """Test building filter with empty conditions."""
        result = build_filter("and", {})
        assert result == ""

    def test_build_filter_invalid_operator(self) -> None:
        """Test building filter with invalid operator."""
        conditions = {"cn": "john"}
        result = build_filter("invalid", conditions)
        assert result == ""

    def test_build_filter_escapes_values(self) -> None:
        """Test that filter building escapes special characters."""
        conditions = {"cn": "john*"}
        result = build_filter("and", conditions)
        assert result == "(&(cn=john\\2a))"


class TestLDAPURLUtilities:
    """Test LDAP URL utilities."""

    def test_is_valid_ldap_url_ldap(self) -> None:
        """Test validating LDAP URL."""
        url = "ldap://localhost:389"
        assert is_valid_ldap_url(url) is True

    def test_is_valid_ldap_url_ldaps(self) -> None:
        """Test validating LDAPS URL."""
        url = "ldaps://localhost:636"
        assert is_valid_ldap_url(url) is True

    def test_is_valid_ldap_url_invalid_scheme(self) -> None:
        """Test validating URL with invalid scheme."""
        url = "http://localhost:389"
        assert is_valid_ldap_url(url) is False

    def test_is_valid_ldap_url_invalid_format(self) -> None:
        """Test validating malformed URL."""
        url = "not-a-url"
        assert is_valid_ldap_url(url) is False

    def test_parse_ldap_url_basic(self) -> None:
        """Test parsing basic LDAP URL."""
        url = "ldap://localhost:389"
        result = parse_ldap_url(url)

        expected = {
            "scheme": "ldap",
            "host": "localhost",
            "port": 389,
            "base_dn": "",
            "attributes": [],
            "scope": "sub",
            "filter": "(objectClass=*)",
        }
        assert result == expected

    def test_parse_ldap_url_ldaps(self) -> None:
        """Test parsing LDAPS URL."""
        url = "ldaps://localhost"
        result = parse_ldap_url(url)
        assert result["scheme"] == "ldaps"
        assert result["port"] == 636

    def test_parse_ldap_url_with_base_dn(self) -> None:
        """Test parsing LDAP URL with base DN."""
        url = "ldap://localhost:389/dc=example,dc=com"
        result = parse_ldap_url(url)
        assert result["base_dn"] == "dc=example,dc=com"

    def test_parse_ldap_url_complex(self) -> None:
        """Test parsing complex LDAP URL with all components."""
        url = "ldap://localhost:389/dc=example,dc=com?cn,sn?onelevel?(cn=john)"
        result = parse_ldap_url(url)

        assert result["base_dn"] == "dc=example,dc=com"
        assert result["attributes"] == ["cn", "sn"]
        assert result["scope"] == "onelevel"
        assert result["filter"] == "(cn=john)"


class TestDNParsing:
    """Test DN parsing and building utilities."""

    def test_parse_dn(self) -> None:
        """Test parsing DN into components."""
        dn = "cn=john,ou=people,dc=example,dc=com"
        result = parse_dn(dn)

        expected = [
            {"attribute": "cn", "value": "john"},
            {"attribute": "ou", "value": "people"},
            {"attribute": "dc", "value": "example"},
            {"attribute": "dc", "value": "com"},
        ]
        assert result == expected

    def test_parse_dn_with_spaces(self) -> None:
        """Test parsing DN with spaces."""
        dn = " cn = john , ou = people "
        result = parse_dn(dn)

        expected = [
            {"attribute": "cn", "value": "john"},
            {"attribute": "ou", "value": "people"},
        ]
        assert result == expected

    def test_build_dn(self) -> None:
        """Test building DN from components."""
        components = [
            {"attribute": "cn", "value": "john"},
            {"attribute": "ou", "value": "people"},
            {"attribute": "dc", "value": "example"},
            {"attribute": "dc", "value": "com"},
        ]
        result = build_dn(components)
        assert result == "cn=john,ou=people,dc=example,dc=com"

    def test_build_dn_empty(self) -> None:
        """Test building DN from empty components."""
        result = build_dn([])
        assert result == ""


class TestMiscUtilities:
    """Test miscellaneous utilities."""

    def test_normalize_attribute_name(self) -> None:
        """Test normalizing attribute names."""
        assert normalize_attribute_name("CN") == "cn"
        assert normalize_attribute_name(" sn ") == "sn"
        assert normalize_attribute_name("ObjectClass") == "objectclass"

    def test_format_ldap_timestamp_datetime(self) -> None:
        """Test formatting datetime as LDAP timestamp."""
        dt = datetime(2023, 12, 15, 14, 30, 22, tzinfo=UTC)
        result = format_ldap_timestamp(dt)
        assert result == "20231215143022Z"

    def test_format_ldap_timestamp_string(self) -> None:
        """Test formatting string timestamp (passthrough)."""
        timestamp_str = "20231215143022Z"
        result = format_ldap_timestamp(timestamp_str)
        assert result == timestamp_str

    def test_format_ldap_timestamp_protocol_object(self) -> None:
        """Test formatting object with strftime method."""

        class MockTimestamp:
            def strftime(self, fmt: str) -> str:  # noqa: ARG002
                return "20231215143022Z"

        mock_ts = MockTimestamp()
        result = format_ldap_timestamp(mock_ts)
        assert result == "20231215143022Z"
