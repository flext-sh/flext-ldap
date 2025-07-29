"""Tests for LDAP utilities."""

from datetime import UTC, datetime

from flext_ldap.utils import (
    flext_ldap_build_dn as build_dn,
    flext_ldap_build_filter as build_filter,
    flext_ldap_compare_dns as compare_dns,
    flext_ldap_escape_filter_chars as escape_filter_chars,
    flext_ldap_escape_filter_value as escape_filter_value,
    flext_ldap_format_generalized_time as format_generalized_time,
    flext_ldap_format_timestamp as format_ldap_timestamp,
    flext_ldap_is_valid_url as is_valid_ldap_url,
    flext_ldap_normalize_attribute_name as normalize_attribute_name,
    flext_ldap_normalize_dn as normalize_dn,
    flext_ldap_parse_dn as parse_dn,
    flext_ldap_parse_generalized_time as parse_generalized_time,
    flext_ldap_parse_url as parse_ldap_url,
    flext_ldap_split_dn as split_dn,
    flext_ldap_validate_dn as validate_dn,
)


class TestFilterEscaping:
    """Test LDAP filter escaping utilities."""

    def test_escape_filter_chars_basic(self) -> None:
        """Test escaping of basic special characters."""
        result = escape_filter_chars("test*value")
        if result != "test\\2avalue":
            raise AssertionError(f"Expected {"test\\2avalue"}, got {result}")

    def test_escape_filter_chars_all_special(self) -> None:
        """Test escaping all special characters."""
        input_str = "test*()\\test"
        result = escape_filter_chars(input_str)
        if result != "test\\2a\\28\\29\\5ctest":
            raise AssertionError(f"Expected {"test\\2a\\28\\29\\5ctest"}, got {result}")

    def test_escape_filter_chars_null_byte(self) -> None:
        """Test escaping null byte."""
        input_str = "test\x00value"
        result = escape_filter_chars(input_str)
        if result != "test\\00value":
            raise AssertionError(f"Expected {"test\\00value"}, got {result}")

    def test_escape_filter_chars_empty_string(self) -> None:
        """Test escaping empty string."""
        result = escape_filter_chars("")
        if result != "":
            raise AssertionError(f"Expected {""}, got {result}")

    def test_escape_filter_value_alias(self) -> None:
        """Test that escape_filter_value is an alias."""
        test_str = "test*value"
        if escape_filter_value(test_str) != escape_filter_chars(test_str):
            raise AssertionError(f"Expected {escape_filter_chars(test_str)}, got {escape_filter_value(test_str)}")


class TestGeneralizedTime:
    """Test LDAP generalized time utilities."""

    def test_parse_generalized_time_with_z(self) -> None:
        """Test parsing generalized time with Z suffix."""
        time_str = "20231215143022Z"
        result = parse_generalized_time(time_str)

        expected = datetime(2023, 12, 15, 14, 30, 22, tzinfo=UTC)
        if result != expected:
            raise AssertionError(f"Expected {expected}, got {result}")

    def test_parse_generalized_time_without_z(self) -> None:
        """Test parsing generalized time without Z suffix."""
        time_str = "20231215143022"
        result = parse_generalized_time(time_str)

        expected = datetime(
            2023,
            12,
            15,
            14,
            30,
            22,
        )  # No timezone when Z suffix absent
        if result != expected:
            raise AssertionError(f"Expected {expected}, got {result}")

    def test_format_generalized_time_with_timezone(self) -> None:
        """Test formatting datetime with timezone."""
        dt = datetime(2023, 12, 15, 14, 30, 22, tzinfo=UTC)
        result = format_generalized_time(dt)
        if result != "20231215143022Z":
            raise AssertionError(f"Expected {"20231215143022Z"}, got {result}")

    def test_format_generalized_time_without_timezone(self) -> None:
        """Test formatting datetime without timezone."""
        dt = datetime(2023, 12, 15, 14, 30, 22, tzinfo=UTC)
        result = format_generalized_time(dt)
        if result != "20231215143022Z":
            raise AssertionError(f"Expected {"20231215143022Z"}, got {result}")


class TestDNUtilities:
    """Test DN (Distinguished Name) utilities."""

    def test_validate_dn_valid(self) -> None:
        """Test validating valid DN."""
        dn = "cn=user,ou=people,dc=example,dc=com"
        if not (validate_dn(dn)):
            raise AssertionError(f"Expected True, got {validate_dn(dn)}")

    def test_validate_dn_invalid_empty(self) -> None:
        """Test validating empty DN."""
        if validate_dn(""):
            raise AssertionError(f"Expected False, got {validate_dn("")}")\ n
    def test_validate_dn_invalid_no_equals(self) -> None:
        """Test validating DN without equals sign."""
        dn = "cn user,ou people"
        if validate_dn(dn):
            raise AssertionError(f"Expected False, got {validate_dn(dn)}")\ n
    def test_normalize_dn(self) -> None:
        """Test DN normalization."""
        dn = "CN=User,OU=People,DC=Example,DC=Com"
        result = normalize_dn(dn)
        if result != "cn=user,ou=people,dc=example,dc=com":
            raise AssertionError(f"Expected {"cn=user,ou=people,dc=example,dc=com"}, got {result}")

    def test_normalize_dn_with_spaces(self) -> None:
        """Test DN normalization with spaces."""
        dn = " CN = User , OU = People "
        result = normalize_dn(dn)
        if result != "cn=user,ou=people":
            raise AssertionError(f"Expected {"cn=user,ou=people"}, got {result}")

    def test_split_dn(self) -> None:
        """Test splitting DN into components."""
        dn = "cn=user,ou=people,dc=example,dc=com"
        result = split_dn(dn)
        expected = ["cn=user", "ou=people", "dc=example", "dc=com"]
        if result != expected:
            raise AssertionError(f"Expected {expected}, got {result}")

    def test_split_dn_empty(self) -> None:
        """Test splitting empty DN."""
        result = split_dn("")
        if result != []:
            raise AssertionError(f"Expected {[]}, got {result}")

    def test_split_dn_with_spaces(self) -> None:
        """Test splitting DN with spaces."""
        dn = " cn=user , ou=people , dc=example "
        result = split_dn(dn)
        expected = ["cn=user", "ou=people", "dc=example"]
        if result != expected:
            raise AssertionError(f"Expected {expected}, got {result}")

    def test_compare_dns_equal(self) -> None:
        """Test comparing equal DNs."""
        dn1 = "CN=User,OU=People,DC=Example,DC=Com"
        dn2 = "cn=user,ou=people,dc=example,dc=com"
        if not (compare_dns(dn1, dn2)):
            raise AssertionError(f"Expected True, got {compare_dns(dn1, dn2)}")

    def test_compare_dns_different(self) -> None:
        """Test comparing different DNs."""
        dn1 = "cn=user1,ou=people,dc=example,dc=com"
        dn2 = "cn=user2,ou=people,dc=example,dc=com"
        if compare_dns(dn1, dn2):
            raise AssertionError(f"Expected False, got {compare_dns(dn1, dn2)}")\ n

class TestFilterBuilding:
    """Test LDAP filter building utilities."""

    def test_build_filter_and(self) -> None:
        """Test building AND filter."""
        conditions = {"cn": "john", "sn": "doe"}
        result = build_filter("and", conditions)
        if result != "(&(cn=john)(sn=doe))":
            raise AssertionError(f"Expected {"(&(cn=john)(sn=doe))"}, got {result}")

    def test_build_filter_or(self) -> None:
        """Test building OR filter."""
        conditions = {"cn": "john", "sn": "doe"}
        result = build_filter("or", conditions)
        if result != "(|(cn=john)(sn=doe))":
            raise AssertionError(f"Expected {"(|(cn=john)(sn=doe))"}, got {result}")

    def test_build_filter_not_single(self) -> None:
        """Test building NOT filter with single condition."""
        conditions = {"cn": "john"}
        result = build_filter("not", conditions)
        if result != "(!(cn=john))":
            raise AssertionError(f"Expected {"(!(cn=john))"}, got {result}")

    def test_build_filter_not_multiple(self) -> None:
        """Test building NOT filter with multiple conditions."""
        conditions = {"cn": "john", "sn": "doe"}
        result = build_filter("not", conditions)
        if result != "(!(&(cn=john)(sn=doe)))":
            raise AssertionError(f"Expected {"(!(&(cn=john)(sn=doe)))"}, got {result}")

    def test_build_filter_empty_conditions(self) -> None:
        """Test building filter with empty conditions."""
        result = build_filter("and", {})
        if result != "":
            raise AssertionError(f"Expected {""}, got {result}")

    def test_build_filter_invalid_operator(self) -> None:
        """Test building filter with invalid operator."""
        conditions = {"cn": "john"}
        result = build_filter("invalid", conditions)
        if result != "":
            raise AssertionError(f"Expected {""}, got {result}")

    def test_build_filter_escapes_values(self) -> None:
        """Test that filter building escapes special characters."""
        conditions = {"cn": "john*"}
        result = build_filter("and", conditions)
        if result != "(&(cn=john\\2a))":
            raise AssertionError(f"Expected {"(&(cn=john\\2a))"}, got {result}")


class TestLDAPURLUtilities:
    """Test LDAP URL utilities."""

    def test_is_valid_ldap_url_ldap(self) -> None:
        """Test validating LDAP URL."""
        url = "ldap://localhost:389"
        if not (is_valid_ldap_url(url)):
            raise AssertionError(f"Expected True, got {is_valid_ldap_url(url)}")

    def test_is_valid_ldap_url_ldaps(self) -> None:
        """Test validating LDAPS URL."""
        url = "ldaps://localhost:636"
        if not (is_valid_ldap_url(url)):
            raise AssertionError(f"Expected True, got {is_valid_ldap_url(url)}")

    def test_is_valid_ldap_url_invalid_scheme(self) -> None:
        """Test validating URL with invalid scheme."""
        url = "http://localhost:389"
        if is_valid_ldap_url(url):
            raise AssertionError(f"Expected False, got {is_valid_ldap_url(url)}")\ n
    def test_is_valid_ldap_url_invalid_format(self) -> None:
        """Test validating malformed URL."""
        url = "not-a-url"
        if is_valid_ldap_url(url):
            raise AssertionError(f"Expected False, got {is_valid_ldap_url(url)}")\ n
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
        if result != expected:
            raise AssertionError(f"Expected {expected}, got {result}")

    def test_parse_ldap_url_ldaps(self) -> None:
        """Test parsing LDAPS URL."""
        url = "ldaps://localhost"
        result = parse_ldap_url(url)
        if result["scheme"] != "ldaps":
            raise AssertionError(f"Expected {"ldaps"}, got {result["scheme"]}")
        assert result["port"] == 636

    def test_parse_ldap_url_with_base_dn(self) -> None:
        """Test parsing LDAP URL with base DN."""
        url = "ldap://localhost:389/dc=example,dc=com"
        result = parse_ldap_url(url)
        if result["base_dn"] != "dc=example,dc=com":
            raise AssertionError(f"Expected {"dc=example,dc=com"}, got {result["base_dn"]}")

    def test_parse_ldap_url_complex(self) -> None:
        """Test parsing complex LDAP URL with all components."""
        url = "ldap://localhost:389/dc=example,dc=com?cn,sn?onelevel?(cn=john)"
        result = parse_ldap_url(url)

        if result["base_dn"] != "dc=example,dc=com":

            raise AssertionError(f"Expected {"dc=example,dc=com"}, got {result["base_dn"]}")
        assert result["attributes"] == ["cn", "sn"]
        if result["scope"] != "onelevel":
            raise AssertionError(f"Expected {"onelevel"}, got {result["scope"]}")
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
        if result != expected:
            raise AssertionError(f"Expected {expected}, got {result}")

    def test_parse_dn_with_spaces(self) -> None:
        """Test parsing DN with spaces."""
        dn = " cn = john , ou = people "
        result = parse_dn(dn)

        expected = [
            {"attribute": "cn", "value": "john"},
            {"attribute": "ou", "value": "people"},
        ]
        if result != expected:
            raise AssertionError(f"Expected {expected}, got {result}")

    def test_build_dn(self) -> None:
        """Test building DN from components."""
        components = [
            {"attribute": "cn", "value": "john"},
            {"attribute": "ou", "value": "people"},
            {"attribute": "dc", "value": "example"},
            {"attribute": "dc", "value": "com"},
        ]
        result = build_dn(components)
        if result != "cn=john,ou=people,dc=example,dc=com":
            raise AssertionError(f"Expected {"cn=john,ou=people,dc=example,dc=com"}, got {result}")

    def test_build_dn_empty(self) -> None:
        """Test building DN from empty components."""
        result = build_dn([])
        if result != "":
            raise AssertionError(f"Expected {""}, got {result}")


class TestMiscUtilities:
    """Test miscellaneous utilities."""

    def test_normalize_attribute_name(self) -> None:
        """Test normalizing attribute names."""
        if normalize_attribute_name("CN") != "cn":
            raise AssertionError(f"Expected {"cn"}, got {normalize_attribute_name("CN")}")
        assert normalize_attribute_name(" sn ") == "sn"
        if normalize_attribute_name("ObjectClass") != "objectclass":
            raise AssertionError(f"Expected {"objectclass"}, got {normalize_attribute_name("ObjectClass")}")

    def test_format_ldap_timestamp_datetime(self) -> None:
        """Test formatting datetime as LDAP timestamp."""
        dt = datetime(2023, 12, 15, 14, 30, 22, tzinfo=UTC)
        result = format_ldap_timestamp(dt)
        if result != "20231215143022Z":
            raise AssertionError(f"Expected {"20231215143022Z"}, got {result}")

    def test_format_ldap_timestamp_string(self) -> None:
        """Test formatting string timestamp (passthrough)."""
        timestamp_str = "20231215143022Z"
        result = format_ldap_timestamp(timestamp_str)
        if result != timestamp_str:
            raise AssertionError(f"Expected {timestamp_str}, got {result}")

    def test_format_ldap_timestamp_protocol_object(self) -> None:
        """Test formatting object with strftime method."""

        class MockTimestamp:
            def strftime(self, fmt: str) -> str:
                return "20231215143022Z"

        mock_ts = MockTimestamp()
        result = format_ldap_timestamp(mock_ts)
        if result != "20231215143022Z":
            raise AssertionError(f"Expected {"20231215143022Z"}, got {result}")
