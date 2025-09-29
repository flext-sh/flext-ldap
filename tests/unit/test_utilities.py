"""Unit tests for flext-ldap utilities module."""

from __future__ import annotations

from flext_ldap.utilities import FlextLdapUtilities


class TestFlextLdapUtilities:
    """Tests for FlextLdapUtilities class."""

    def test_utilities_initialization(self) -> None:
        """Test utilities initialization."""
        utilities = FlextLdapUtilities()
        assert utilities is not None

    def test_normalize_dn_valid(self) -> None:
        """Test DN normalization with valid DN."""
        dn = "  cn=user, ou=people , dc=example,dc=com  "
        result = FlextLdapUtilities.normalize_dn(dn)
        assert result.is_success
        assert result.data == "cn=user, ou=people , dc=example,dc=com"

    def test_normalize_dn_empty(self) -> None:
        """Test DN normalization with empty DN."""
        result = FlextLdapUtilities.normalize_dn("")
        assert result.is_failure
        assert result.error is not None
        assert "DN must be a non-empty string" in result.error

    def test_normalize_filter_valid(self) -> None:
        """Test filter normalization with valid filter."""
        filter_str = "  ( objectClass = person )  "
        result = FlextLdapUtilities.normalize_filter(filter_str)
        assert result.is_success
        assert result.data == "( objectClass = person )"

    def test_normalize_filter_empty(self) -> None:
        """Test filter normalization with empty filter."""
        result = FlextLdapUtilities.normalize_filter("")
        assert result.is_failure
        assert result.error is not None
        assert "Filter must be a non-empty string" in result.error

    def test_normalize_attributes_valid(self) -> None:
        """Test attributes normalization with valid list."""
        attrs = ["cn", "", "mail", "  ", "uid"]
        result = FlextLdapUtilities.normalize_attributes(attrs)
        assert result.is_success
        assert result.data == ["cn", "mail", "uid"]

    def test_normalize_attributes_empty(self) -> None:
        """Test attributes normalization with empty list."""
        result = FlextLdapUtilities.normalize_attributes([])
        assert result.is_failure
        assert result.error is not None
        assert "Attributes list cannot be empty" in result.error

    def test_is_ldap_dn_valid(self) -> None:
        """Test LDAP DN validation with valid DN."""
        assert FlextLdapUtilities.is_ldap_dn("cn=user,dc=example,dc=com") is True

    def test_is_ldap_dn_invalid(self) -> None:
        """Test LDAP DN validation with invalid DN."""
        assert FlextLdapUtilities.is_ldap_dn("invalid-dn") is False
        assert FlextLdapUtilities.is_ldap_dn("") is False
        assert FlextLdapUtilities.is_ldap_dn(None) is False
        assert FlextLdapUtilities.is_ldap_dn(123) is False

    def test_is_ldap_filter_valid(self) -> None:
        """Test LDAP filter validation with valid filter."""
        assert FlextLdapUtilities.is_ldap_filter("(objectClass=person)") is True

    def test_is_ldap_filter_invalid(self) -> None:
        """Test LDAP filter validation with invalid filter."""
        assert FlextLdapUtilities.is_ldap_filter("invalid-filter") is False
        assert FlextLdapUtilities.is_ldap_filter("") is False
        assert FlextLdapUtilities.is_ldap_filter(None) is False

    def test_is_string_list_valid(self) -> None:
        """Test string list validation with valid list."""
        assert FlextLdapUtilities.is_string_list(["a", "b", "c"]) is True
        assert FlextLdapUtilities.is_string_list([]) is True

    def test_is_string_list_invalid(self) -> None:
        """Test string list validation with invalid list."""
        assert FlextLdapUtilities.is_string_list(["a", 1, "c"]) is False
        assert FlextLdapUtilities.is_string_list("not-a-list") is False
        assert FlextLdapUtilities.is_string_list(None) is False

    def test_is_bytes_list_valid(self) -> None:
        """Test bytes list validation with valid list."""
        assert FlextLdapUtilities.is_bytes_list([b"a", b"b"]) is True
        assert FlextLdapUtilities.is_bytes_list([]) is True

    def test_is_bytes_list_invalid(self) -> None:
        """Test bytes list validation with invalid list."""
        assert FlextLdapUtilities.is_bytes_list([b"a", "b"]) is False
        assert FlextLdapUtilities.is_bytes_list("not-a-list") is False

    def test_is_ldap_attribute_value_valid(self) -> None:
        """Test LDAP attribute value validation."""
        assert FlextLdapUtilities.is_ldap_attribute_value("string") is True
        assert (
            FlextLdapUtilities.is_ldap_attribute_value(["list", "of", "strings"])
            is True
        )
        assert FlextLdapUtilities.is_ldap_attribute_value([b"bytes"]) is True

    def test_is_ldap_attribute_value_invalid(self) -> None:
        """Test LDAP attribute value validation with invalid values."""
        assert FlextLdapUtilities.is_ldap_attribute_value(123) is False
        assert FlextLdapUtilities.is_ldap_attribute_value(None) is False

    def test_is_ldap_attributes_dict_valid(self) -> None:
        """Test LDAP attributes dict validation."""
        attrs = {"cn": ["John Doe"], "mail": ["john@example.com"]}
        assert FlextLdapUtilities.is_ldap_attributes_dict(attrs) is True

    def test_is_ldap_attributes_dict_invalid(self) -> None:
        """Test LDAP attributes dict validation with invalid dict."""
        assert FlextLdapUtilities.is_ldap_attributes_dict({"key": 123}) is False
        assert FlextLdapUtilities.is_ldap_attributes_dict("not-a-dict") is False

    def test_dict_to_attributes_valid(self) -> None:
        """Test dict to LDAP attributes conversion."""
        data: dict[str, object] = {"cn": "John Doe", "mail": "john@example.com"}
        result = FlextLdapUtilities.dict_to_attributes(data)
        assert result.is_success
        assert isinstance(result.data, tuple)
        names, values = result.data
        assert "cn" in names
        assert "mail" in names
        assert "John Doe" in values
        assert "john@example.com" in values

    def test_dict_to_attributes_empty(self) -> None:
        """Test dict to LDAP attributes conversion with empty dict."""
        result = FlextLdapUtilities.dict_to_attributes({})
        assert result.is_success
        names, values = result.data
        assert names == []
        assert values == []

    def test_attributes_to_dict_valid(self) -> None:
        """Test LDAP attributes to dict conversion."""
        names: list[str] = ["cn", "mail"]
        values: list[object] = ["John Doe", "john@example.com"]
        result = FlextLdapUtilities.attributes_to_dict(names, values)
        assert result.is_success
        assert isinstance(result.data, dict)
        assert result.data["cn"] == "John Doe"
        assert result.data["mail"] == "john@example.com"

    def test_attributes_to_dict_empty(self) -> None:
        """Test LDAP attributes to dict conversion with empty lists."""
        result = FlextLdapUtilities.attributes_to_dict([], [])
        assert result.is_success
        assert result.data == {}

    def test_ensure_ldap_dn_valid(self) -> None:
        """Test LDAP DN validation and normalization."""
        dn = "cn=user,dc=example,dc=com"
        result = FlextLdapUtilities.ensure_ldap_dn(dn)
        assert result.is_success
        assert result.data == dn

    def test_ensure_ldap_dn_invalid(self) -> None:
        """Test LDAP DN validation with invalid DN."""
        result = FlextLdapUtilities.ensure_ldap_dn("")
        assert result.is_failure
        assert result.error is not None
        assert "DN cannot be empty" in result.error

    def test_ensure_string_list_valid(self) -> None:
        """Test string list validation and conversion."""
        data = ["a", "b", "c"]
        result = FlextLdapUtilities.ensure_string_list(data)
        assert result.is_success
        assert result.data == ["a", "b", "c"]

    def test_ensure_string_list_single_string(self) -> None:
        """Test string list validation with single string."""
        result = FlextLdapUtilities.ensure_string_list("single")
        assert result.is_success
        assert result.data == ["single"]

    def test_ensure_string_list_invalid(self) -> None:
        """Test string list validation with invalid data."""
        result = FlextLdapUtilities.ensure_string_list(123)
        assert result.is_success
        assert result.data == ["123"]  # The function converts any value to string


class TestFlextLdapUtilitiesLdapTypeGuards:
    """Tests for FlextLdapUtilities.TypeGuards nested class."""

    def test_ensure_string_list_valid_list(self) -> None:
        """Test string list conversion with valid list."""
        result = FlextLdapUtilities.TypeGuards.ensure_string_list(["a", "b"])
        assert result == ["a", "b"]

    def test_ensure_string_list_single_string(self) -> None:
        """Test string list conversion with single string."""
        result = FlextLdapUtilities.TypeGuards.ensure_string_list("test")
        assert result == ["test"]

    def test_ensure_string_list_empty_list(self) -> None:
        """Test string list conversion with empty list."""
        result = FlextLdapUtilities.TypeGuards.ensure_string_list([])
        assert result == []

    def test_is_string_list_valid(self) -> None:
        """Test string list type guard."""
        assert FlextLdapUtilities.TypeGuards.is_string_list(["a", "b"]) is True
        assert FlextLdapUtilities.TypeGuards.is_string_list([]) is True

    def test_is_string_list_invalid(self) -> None:
        """Test string list type guard with invalid data."""
        assert FlextLdapUtilities.TypeGuards.is_string_list([1, 2]) is False
        assert FlextLdapUtilities.TypeGuards.is_string_list("string") is False

    def test_is_bytes_list_valid(self) -> None:
        """Test bytes list type guard."""
        assert FlextLdapUtilities.TypeGuards.is_bytes_list([b"a", b"b"]) is True

    def test_is_bytes_list_invalid(self) -> None:
        """Test bytes list type guard with invalid data."""
        assert FlextLdapUtilities.TypeGuards.is_bytes_list(["a", "b"]) is False

    def test_ensure_ldap_dn_valid(self) -> None:
        """Test LDAP DN validation."""
        dn = "cn=user,dc=example,dc=com"
        result = FlextLdapUtilities.TypeGuards.ensure_ldap_dn(dn)
        assert result == dn

    def test_ensure_ldap_dn_whitespace(self) -> None:
        """Test LDAP DN validation with whitespace."""
        result = FlextLdapUtilities.TypeGuards.ensure_ldap_dn("  cn=user  ")
        assert result == "cn=user"


class TestFlextLdapUtilitiesLdapProcessing:
    """Tests for FlextLdapUtilities.Processing nested class."""

    def test_normalize_dn_success(self) -> None:
        """Test DN normalization success case."""
        dn = "cn=user , ou=people ,dc=example,dc=com"
        result = FlextLdapUtilities.Processing.normalize_dn(dn)
        assert result.is_success
        normalized = result.data
        assert "cn=user , ou=people ,dc=example,dc=com" in normalized

    def test_normalize_dn_failure(self) -> None:
        """Test DN normalization failure case."""
        result = FlextLdapUtilities.Processing.normalize_dn("")
        assert result.is_failure
        assert result.error is not None

    def test_normalize_filter_success(self) -> None:
        """Test filter normalization success case."""
        filter_str = "( objectClass = person )"
        result = FlextLdapUtilities.Processing.normalize_filter(filter_str)
        assert result.is_success
        assert "( objectClass = person )" in result.data

    def test_normalize_filter_failure(self) -> None:
        """Test filter normalization failure case."""
        result = FlextLdapUtilities.Processing.normalize_filter("")
        assert result.is_failure
        assert result.error is not None

    def test_normalize_attributes_success(self) -> None:
        """Test attributes normalization success case."""
        attrs = ["cn", "", "mail", "  ", "uid", "sn"]
        result = FlextLdapUtilities.Processing.normalize_attributes(attrs)
        assert result.is_success
        assert "cn" in result.data
        assert "mail" in result.data
        assert "uid" in result.data
        assert "sn" in result.data
        assert len(result.data) == 4  # Empty strings filtered out

    def test_normalize_attributes_failure(self) -> None:
        """Test attributes normalization failure case."""
        result = FlextLdapUtilities.Processing.normalize_attributes([])
        assert result.is_failure
        assert result.error is not None

    def test_attributes_to_dict_success(self) -> None:
        """Test attributes to dict conversion success case."""
        names: list[str] = ["cn", "mail"]
        values: list[object] = ["John", "john@example.com"]
        result = FlextLdapUtilities.Conversion.attributes_to_dict(names, values)
        assert result.is_success
        assert result.data["cn"] == "John"
        assert result.data["mail"] == "john@example.com"

    def test_attributes_to_dict_mismatch(self) -> None:
        """Test attributes to dict conversion with mismatched lengths."""
        names: list[str] = ["cn", "mail"]
        values: list[object] = ["John"]  # Missing one value
        result = FlextLdapUtilities.Conversion.attributes_to_dict(names, values)
        assert result.is_failure
        assert result.error is not None
        assert "length mismatch" in result.error
