"""Tests for LDAP domain value objects."""

from urllib.parse import urlparse

import pytest
from pydantic import ValidationError

from flext_ldap.domain.values import (
    FlextLdapAttributesValue,
    FlextLdapConnectionInfo,
    FlextLdapCreateUserRequest,
    FlextLdapDistinguishedName,
    FlextLdapFilterValue,
    FlextLdapObjectClass,
    FlextLdapScopeEnum,
    FlextLdapUri,
)


class TestFlextLdapScopeEnum:
    """Test LDAP scope enumeration."""

    def test_scope_values(self) -> None:
        """Test all scope enum values."""
        assert FlextLdapScopeEnum.BASE.value == "base"
        assert FlextLdapScopeEnum.ONE_LEVEL.value == "onelevel"
        assert FlextLdapScopeEnum.SUBTREE.value == "subtree"

    def test_scope_membership(self) -> None:
        """Test scope membership."""
        valid_scopes = ["base", "onelevel", "subtree"]
        for scope in valid_scopes:
            assert scope in FlextLdapScopeEnum


class TestFlextLdapDistinguishedName:
    """Test distinguished name value object."""

    def test_valid_dn_creation(self) -> None:
        """Test creating valid DN."""
        dn = FlextLdapDistinguishedName(value="cn=admin,dc=example,dc=org")
        assert dn.value == "cn=admin,dc=example,dc=org"
        assert str(dn) == "cn=admin,dc=example,dc=org"

    def test_complex_dn_creation(self) -> None:
        """Test creating complex DN with multiple components."""
        complex_dn = "uid=user,ou=people,ou=department,dc=company,dc=com"
        dn = FlextLdapDistinguishedName(value=complex_dn)
        assert dn.value == complex_dn

    def test_dn_validation_empty_string(self) -> None:
        """Test DN validation with empty string."""
        with pytest.raises(ValidationError):
            FlextLdapDistinguishedName(value="")

    def test_dn_validation_no_equals(self) -> None:
        """Test DN validation without equals sign."""
        with pytest.raises(ValidationError):
            FlextLdapDistinguishedName(value="invalid_dn")

    def test_dn_validation_invalid_component(self) -> None:
        """Test DN validation with invalid component."""
        with pytest.raises(ValidationError):
            FlextLdapDistinguishedName(value="cn=admin,invalid,dc=org")

    def test_dn_validation_empty_attribute_name(self) -> None:
        """Test DN validation with empty attribute name."""
        with pytest.raises(ValidationError):
            FlextLdapDistinguishedName(value="=admin,dc=example,dc=org")

    def test_dn_validation_empty_attribute_value(self) -> None:
        """Test DN validation with empty attribute value."""
        with pytest.raises(ValidationError):
            FlextLdapDistinguishedName(value="cn=,dc=example,dc=org")

    def test_get_rdn(self) -> None:
        """Test getting relative distinguished name."""
        dn = FlextLdapDistinguishedName(value="cn=admin,dc=example,dc=org")
        assert dn.get_rdn() == "cn=admin"

    def test_get_rdn_with_spaces(self) -> None:
        """Test getting RDN with spaces."""
        dn = FlextLdapDistinguishedName(value="cn=admin , dc=example , dc=org")
        assert dn.get_rdn() == "cn=admin"

    def test_get_parent_dn(self) -> None:
        """Test getting parent DN."""
        dn = FlextLdapDistinguishedName(value="cn=admin,dc=example,dc=org")
        parent = dn.get_parent_dn()
        assert parent is not None
        assert parent.value == "dc=example,dc=org"

    def test_get_parent_dn_root(self) -> None:
        """Test getting parent DN for root DN."""
        dn = FlextLdapDistinguishedName(value="dc=org")
        parent = dn.get_parent_dn()
        assert parent is None

    def test_get_components(self) -> None:
        """Test getting DN components."""
        dn = FlextLdapDistinguishedName(value="cn=admin,ou=users,dc=example,dc=org")
        components = dn.get_components()
        expected = ["cn=admin", "ou=users", "dc=example", "dc=org"]
        assert components == expected

    def test_get_components_with_spaces(self) -> None:
        """Test getting DN components with spaces."""
        dn = FlextLdapDistinguishedName(value="cn=admin , ou=users , dc=example")
        components = dn.get_components()
        expected = ["cn=admin", "ou=users", "dc=example"]
        assert components == expected

    def test_is_child_of_true(self) -> None:
        """Test is_child_of returns True for child relationship."""
        child = FlextLdapDistinguishedName(value="cn=admin,dc=example,dc=org")
        parent = FlextLdapDistinguishedName(value="dc=example,dc=org")
        assert child.is_child_of(parent) is True

    def test_is_child_of_false(self) -> None:
        """Test is_child_of returns False for non-child relationship."""
        dn1 = FlextLdapDistinguishedName(value="cn=admin,dc=example,dc=org")
        dn2 = FlextLdapDistinguishedName(value="dc=other,dc=org")
        assert dn1.is_child_of(dn2) is False

    def test_is_child_of_case_insensitive(self) -> None:
        """Test is_child_of is case insensitive."""
        child = FlextLdapDistinguishedName(value="cn=admin,DC=EXAMPLE,DC=ORG")
        parent = FlextLdapDistinguishedName(value="dc=example,dc=org")
        assert child.is_child_of(parent) is True

    def test_domain_rules_validation_success(self) -> None:
        """Test domain rules validation with valid DN."""
        dn = FlextLdapDistinguishedName(value="cn=admin,dc=example,dc=org")
        # Should not raise
        dn.validate_domain_rules()

    def test_domain_rules_validation_empty(self) -> None:
        """Test domain rules validation with empty DN."""
        # This should be caught by field validator first
        with pytest.raises(ValidationError):
            FlextLdapDistinguishedName(value="")


class TestFlextLdapFilterValue:
    """Test LDAP filter value object."""

    def test_valid_filter_creation(self) -> None:
        """Test creating valid LDAP filter."""
        filter_val = FlextLdapFilterValue(value="(cn=admin)")
        assert filter_val.value == "(cn=admin)"
        assert str(filter_val) == "(cn=admin)"

    def test_complex_filter_creation(self) -> None:
        """Test creating complex LDAP filter."""
        complex_filter = "(&(cn=admin)(objectClass=person))"
        filter_val = FlextLdapFilterValue(value=complex_filter)
        assert filter_val.value == complex_filter

    def test_filter_validation_empty(self) -> None:
        """Test filter validation with empty string."""
        with pytest.raises(ValidationError):
            FlextLdapFilterValue(value="")

    def test_filter_validation_no_parentheses(self) -> None:
        """Test filter validation without parentheses."""
        with pytest.raises(ValidationError):
            FlextLdapFilterValue(value="cn=admin")

    def test_filter_validation_unbalanced_parentheses(self) -> None:
        """Test filter validation with unbalanced parentheses."""
        with pytest.raises(ValidationError):
            FlextLdapFilterValue(value="((cn=admin)")

    def test_filter_validation_missing_closing(self) -> None:
        """Test filter validation missing closing parentheses."""
        with pytest.raises(ValidationError):
            FlextLdapFilterValue(value="(cn=admin")

    def test_equals_filter_creation(self) -> None:
        """Test creating equality filter."""
        filter_val = FlextLdapFilterValue.equals("cn", "admin")
        assert filter_val.value == "(cn=admin)"

    def test_present_filter_creation(self) -> None:
        """Test creating presence filter."""
        filter_val = FlextLdapFilterValue.present("mail")
        assert filter_val.value == "(mail=*)"

    def test_and_filters_single(self) -> None:
        """Test AND operation with single filter."""
        filter1 = FlextLdapFilterValue(value="(cn=admin)")
        result = FlextLdapFilterValue.and_filters(filter1)
        assert result.value == "(cn=admin)"

    def test_and_filters_multiple(self) -> None:
        """Test AND operation with multiple filters."""
        filter1 = FlextLdapFilterValue(value="(cn=admin)")
        filter2 = FlextLdapFilterValue(value="(objectClass=person)")
        result = FlextLdapFilterValue.and_filters(filter1, filter2)
        assert result.value == "(&(cn=admin)(objectClass=person))"

    def test_and_filters_empty(self) -> None:
        """Test AND operation with no filters."""
        with pytest.raises(ValueError, match="At least one filter required"):
            FlextLdapFilterValue.and_filters()

    def test_or_filters_single(self) -> None:
        """Test OR operation with single filter."""
        filter1 = FlextLdapFilterValue(value="(cn=admin)")
        result = FlextLdapFilterValue.or_filters(filter1)
        assert result.value == "(cn=admin)"

    def test_or_filters_multiple(self) -> None:
        """Test OR operation with multiple filters."""
        filter1 = FlextLdapFilterValue(value="(cn=admin)")
        filter2 = FlextLdapFilterValue(value="(cn=user)")
        result = FlextLdapFilterValue.or_filters(filter1, filter2)
        assert result.value == "(|(cn=admin)(cn=user))"

    def test_or_filters_empty(self) -> None:
        """Test OR operation with no filters."""
        with pytest.raises(ValueError, match="At least one filter required"):
            FlextLdapFilterValue.or_filters()

    def test_domain_rules_validation_success(self) -> None:
        """Test domain rules validation with valid filter."""
        filter_val = FlextLdapFilterValue(value="(cn=admin)")
        # Should not raise
        filter_val.validate_domain_rules()

    def test_domain_rules_validation_empty(self) -> None:
        """Test domain rules validation with empty filter."""
        # This should be caught by field validator first
        with pytest.raises(ValidationError):
            FlextLdapFilterValue(value="")


class TestFlextLdapUri:
    """Test LDAP URI value object."""

    def test_valid_ldap_uri(self) -> None:
        """Test creating valid LDAP URI."""
        uri = FlextLdapUri(value="ldap://localhost:389")
        assert uri.value == "ldap://localhost:389"
        assert str(uri) == "ldap://localhost:389"

    def test_valid_ldaps_uri(self) -> None:
        """Test creating valid LDAPS URI."""
        uri = FlextLdapUri(value="ldaps://secure.example.com:636")
        assert uri.value == "ldaps://secure.example.com:636"

    def test_uri_validation_empty(self) -> None:
        """Test URI validation with empty string."""
        with pytest.raises(ValidationError):
            FlextLdapUri(value="")

    def test_uri_validation_invalid_scheme(self) -> None:
        """Test URI validation with invalid scheme."""
        with pytest.raises(ValidationError):
            FlextLdapUri(value="http://example.com")

    def test_uri_validation_no_hostname(self) -> None:
        """Test URI validation without hostname."""
        with pytest.raises(ValidationError):
            FlextLdapUri(value="ldap://")

    def test_hostname_property(self) -> None:
        """Test hostname property."""
        uri = FlextLdapUri(value="ldap://example.com:389")
        assert uri.hostname == "example.com"

    def test_hostname_property_no_port(self) -> None:
        """Test hostname property without explicit port."""
        uri = FlextLdapUri(value="ldap://example.com")
        assert uri.hostname == "example.com"

    def test_port_property_explicit(self) -> None:
        """Test port property with explicit port."""
        uri = FlextLdapUri(value="ldap://example.com:1389")
        assert uri.port == 1389

    def test_port_property_default_ldap(self) -> None:
        """Test port property with default LDAP port."""
        uri = FlextLdapUri(value="ldap://example.com")
        assert uri.port == 389

    def test_port_property_default_ldaps(self) -> None:
        """Test port property with default LDAPS port."""
        uri = FlextLdapUri(value="ldaps://example.com")
        assert uri.port == 636

    def test_is_secure_false(self) -> None:
        """Test is_secure property for LDAP."""
        uri = FlextLdapUri(value="ldap://example.com")
        assert uri.is_secure is False

    def test_is_secure_true(self) -> None:
        """Test is_secure property for LDAPS."""
        uri = FlextLdapUri(value="ldaps://example.com")
        assert uri.is_secure is True

    def test_domain_rules_validation_success(self) -> None:
        """Test domain rules validation with valid URI."""
        uri = FlextLdapUri(value="ldap://example.com:389")
        # Should not raise
        uri.validate_domain_rules()


class TestFlextLdapObjectClass:
    """Test LDAP object class value object."""

    def test_valid_object_class(self) -> None:
        """Test creating valid object class."""
        obj_class = FlextLdapObjectClass(name="inetOrgPerson")
        assert obj_class.name == "inetOrgPerson"
        assert str(obj_class) == "inetOrgPerson"

    def test_object_class_with_hyphen(self) -> None:
        """Test object class with hyphen."""
        obj_class = FlextLdapObjectClass(name="organizational-person")
        assert obj_class.name == "organizational-person"

    def test_object_class_with_underscore(self) -> None:
        """Test object class with underscore."""
        obj_class = FlextLdapObjectClass(name="inet_org_person")
        assert obj_class.name == "inet_org_person"

    def test_object_class_validation_empty(self) -> None:
        """Test object class validation with empty name."""
        with pytest.raises(ValidationError):
            FlextLdapObjectClass(name="")

    def test_object_class_validation_spaces(self) -> None:
        """Test object class validation with only spaces."""
        with pytest.raises(ValidationError):
            FlextLdapObjectClass(name="   ")

    def test_object_class_validation_invalid_chars(self) -> None:
        """Test object class validation with invalid characters."""
        with pytest.raises(ValidationError):
            FlextLdapObjectClass(name="invalid@class")

    def test_domain_rules_validation_success(self) -> None:
        """Test domain rules validation with valid object class."""
        obj_class = FlextLdapObjectClass(name="inetOrgPerson")
        # Should not raise
        obj_class.validate_domain_rules()


class TestFlextLdapAttributesValue:
    """Test LDAP attributes value object."""

    def test_empty_attributes_creation(self) -> None:
        """Test creating empty attributes."""
        attrs = FlextLdapAttributesValue()
        assert attrs.attributes == {}

    def test_attributes_with_values(self) -> None:
        """Test creating attributes with values."""
        attrs_dict = {
            "cn": ["Test User"],
            "mail": ["test@example.org", "alt@example.org"],
            "objectClass": ["inetOrgPerson"]
        }
        attrs = FlextLdapAttributesValue(attributes=attrs_dict)
        assert attrs.attributes == attrs_dict

    def test_get_single_value_exists(self) -> None:
        """Test getting single value for existing attribute."""
        attrs = FlextLdapAttributesValue(attributes={"cn": ["Test User"]})
        assert attrs.get_single_value("cn") == "Test User"

    def test_get_single_value_multiple(self) -> None:
        """Test getting single value for attribute with multiple values."""
        attrs = FlextLdapAttributesValue(
            attributes={"mail": ["first@example.org", "second@example.org"]}
        )
        assert attrs.get_single_value("mail") == "first@example.org"

    def test_get_single_value_not_exists(self) -> None:
        """Test getting single value for non-existent attribute."""
        attrs = FlextLdapAttributesValue()
        assert attrs.get_single_value("nonexistent") is None

    def test_get_values_exists(self) -> None:
        """Test getting all values for existing attribute."""
        values = ["first@example.org", "second@example.org"]
        attrs = FlextLdapAttributesValue(attributes={"mail": values})
        assert attrs.get_values("mail") == values

    def test_get_values_not_exists(self) -> None:
        """Test getting all values for non-existent attribute."""
        attrs = FlextLdapAttributesValue()
        assert attrs.get_values("nonexistent") == []

    def test_has_attribute_true(self) -> None:
        """Test has_attribute returns True for existing attribute."""
        attrs = FlextLdapAttributesValue(attributes={"cn": ["Test"]})
        assert attrs.has_attribute("cn") is True

    def test_has_attribute_false(self) -> None:
        """Test has_attribute returns False for non-existent attribute."""
        attrs = FlextLdapAttributesValue()
        assert attrs.has_attribute("nonexistent") is False

    def test_add_value_new_attribute(self) -> None:
        """Test adding value to new attribute."""
        attrs = FlextLdapAttributesValue()
        new_attrs = attrs.add_value("cn", "Test User")
        assert new_attrs.get_single_value("cn") == "Test User"

    def test_add_value_existing_attribute(self) -> None:
        """Test adding value to existing attribute."""
        attrs = FlextLdapAttributesValue(attributes={"mail": ["first@example.org"]})
        new_attrs = attrs.add_value("mail", "second@example.org")
        expected_vals = ["first@example.org", "second@example.org"]
        assert new_attrs.get_values("mail") == expected_vals

    def test_add_value_immutability(self) -> None:
        """Test that add_value creates new instance."""
        original_attrs = {"cn": ["Original"]}
        attrs = FlextLdapAttributesValue(attributes=original_attrs)
        new_attrs = attrs.add_value("cn", "New")

        # Should create a new instance
        assert attrs is not new_attrs
        # New should have both values
        assert "New" in new_attrs.get_values("cn")
        assert len(new_attrs.get_values("cn")) == 2

    def test_remove_value_exists(self) -> None:
        """Test removing existing value."""
        attrs = FlextLdapAttributesValue(
            attributes={"mail": ["keep@example.org", "remove@example.org"]}
        )
        new_attrs = attrs.remove_value("mail", "remove@example.org")
        assert new_attrs.get_values("mail") == ["keep@example.org"]

    def test_remove_value_last_value(self) -> None:
        """Test removing last value removes attribute."""
        attrs = FlextLdapAttributesValue(attributes={"cn": ["Only Value"]})
        new_attrs = attrs.remove_value("cn", "Only Value")
        assert not new_attrs.has_attribute("cn")

    def test_remove_value_nonexistent_attribute(self) -> None:
        """Test removing value from non-existent attribute."""
        attrs = FlextLdapAttributesValue()
        new_attrs = attrs.remove_value("nonexistent", "value")
        assert new_attrs.attributes == {}

    def test_remove_value_nonexistent_value(self) -> None:
        """Test removing non-existent value."""
        original_values = ["keep@example.org"]
        attrs = FlextLdapAttributesValue(attributes={"mail": original_values})
        new_attrs = attrs.remove_value("mail", "nonexistent@example.org")
        assert new_attrs.get_values("mail") == original_values

    def test_domain_rules_validation_success(self) -> None:
        """Test domain rules validation with valid attributes."""
        attrs = FlextLdapAttributesValue(attributes={"cn": ["Test User"]})
        # Should not raise
        attrs.validate_domain_rules()

    def test_domain_rules_validation_empty_name(self) -> None:
        """Test domain rules validation with empty attribute name."""
        attrs = FlextLdapAttributesValue(attributes={"": ["value"]})
        with pytest.raises(ValueError, match="Attribute name cannot be empty"):
            attrs.validate_domain_rules()

    def test_domain_rules_validation_empty_values(self) -> None:
        """Test domain rules validation with empty values list."""
        attrs = FlextLdapAttributesValue(attributes={"cn": []})
        with pytest.raises(ValueError, match="must have at least one value"):
            attrs.validate_domain_rules()


class TestFlextLdapConnectionInfo:
    """Test LDAP connection info value object."""

    def test_connection_info_creation(self) -> None:
        """Test creating connection info."""
        uri = FlextLdapUri(value="ldap://example.com:389")
        dn = FlextLdapDistinguishedName(value="cn=admin,dc=example,dc=org")

        info = FlextLdapConnectionInfo(
            server_uri=uri,
            bind_dn=dn,
            is_authenticated=True,
            is_secure=False,
            protocol_version=3
        )

        assert info.server_uri == uri
        assert info.bind_dn == dn
        assert info.is_authenticated is True
        assert info.is_secure is False
        assert info.protocol_version == 3

    def test_connection_info_defaults(self) -> None:
        """Test connection info with default values."""
        uri = FlextLdapUri(value="ldap://example.com:389")
        info = FlextLdapConnectionInfo(server_uri=uri)

        assert info.bind_dn is None
        assert info.is_authenticated is False
        assert info.is_secure is False
        assert info.protocol_version == 3

    def test_connection_string_authenticated(self) -> None:
        """Test connection string for authenticated connection."""
        uri = FlextLdapUri(value="ldaps://example.com:636")
        info = FlextLdapConnectionInfo(
            server_uri=uri,
            is_authenticated=True,
            is_secure=True
        )

        expected = "ldaps://example.com:636 (authenticated, secure)"
        assert info.connection_string == expected

    def test_connection_string_anonymous(self) -> None:
        """Test connection string for anonymous connection."""
        uri = FlextLdapUri(value="ldap://example.com:389")
        info = FlextLdapConnectionInfo(server_uri=uri)

        expected = "ldap://example.com:389 (anonymous, insecure)"
        assert info.connection_string == expected

    def test_domain_rules_validation_success(self) -> None:
        """Test domain rules validation with valid connection info."""
        uri = FlextLdapUri(value="ldap://example.com:389")
        info = FlextLdapConnectionInfo(server_uri=uri)
        # Should not raise
        info.validate_domain_rules()

    def test_domain_rules_validation_invalid_protocol(self) -> None:
        """Test domain rules validation with invalid protocol version."""
        uri = FlextLdapUri(value="ldap://example.com:389")
        info = FlextLdapConnectionInfo(server_uri=uri, protocol_version=1)
        with pytest.raises(ValueError, match="Protocol version must be 2 or 3"):
            info.validate_domain_rules()


class TestFlextLdapCreateUserRequest:
    """Test LDAP create user request value object."""

    def test_create_user_request_minimal(self) -> None:
        """Test creating user request with minimal required fields."""
        request = FlextLdapCreateUserRequest(
            dn="uid=testuser,ou=users,dc=example,dc=org",
            uid="testuser",
            cn="Test User",
            sn="User"
        )

        assert request.dn == "uid=testuser,ou=users,dc=example,dc=org"
        assert request.uid == "testuser"
        assert request.cn == "Test User"
        assert request.sn == "User"
        assert request.mail is None

    def test_create_user_request_full(self) -> None:
        """Test creating user request with all fields."""
        request = FlextLdapCreateUserRequest(
            dn="uid=testuser,ou=users,dc=example,dc=org",
            uid="testuser",
            cn="Test User",
            sn="User",
            mail="test@example.org",
            phone="+1234567890",
            ou="Engineering",
            department="IT",
            title="Developer",
            object_classes=["inetOrgPerson", "organizationalPerson"]
        )

        assert request.mail == "test@example.org"
        assert request.phone == "+1234567890"
        assert request.ou == "Engineering"
        assert request.department == "IT"
        assert request.title == "Developer"
        assert request.object_classes == ["inetOrgPerson", "organizationalPerson"]

    def test_dn_validation_empty(self) -> None:
        """Test DN validation with empty DN."""
        with pytest.raises(ValidationError):
            FlextLdapCreateUserRequest(
                dn="",
                uid="testuser",
                cn="Test User",
                sn="User"
            )

    def test_dn_validation_whitespace(self) -> None:
        """Test DN validation with whitespace-only DN."""
        with pytest.raises(ValidationError):
            FlextLdapCreateUserRequest(
                dn="   ",
                uid="testuser",
                cn="Test User",
                sn="User"
            )

    def test_dn_strips_whitespace(self) -> None:
        """Test DN strips leading/trailing whitespace."""
        request = FlextLdapCreateUserRequest(
            dn="  uid=testuser,ou=users,dc=example,dc=org  ",
            uid="testuser",
            cn="Test User",
            sn="User"
        )
        assert request.dn == "uid=testuser,ou=users,dc=example,dc=org"

    def test_required_field_validation_uid(self) -> None:
        """Test required field validation for UID."""
        with pytest.raises(ValidationError):
            FlextLdapCreateUserRequest(
                dn="uid=testuser,ou=users,dc=example,dc=org",
                uid="",
                cn="Test User",
                sn="User"
            )

    def test_required_field_validation_cn(self) -> None:
        """Test required field validation for CN."""
        with pytest.raises(ValidationError):
            FlextLdapCreateUserRequest(
                dn="uid=testuser,ou=users,dc=example,dc=org",
                uid="testuser",
                cn="   ",
                sn="User"
            )

    def test_required_field_validation_sn(self) -> None:
        """Test required field validation for SN."""
        with pytest.raises(ValidationError):
            FlextLdapCreateUserRequest(
                dn="uid=testuser,ou=users,dc=example,dc=org",
                uid="testuser",
                cn="Test User",
                sn=""
            )

    def test_required_fields_strip_whitespace(self) -> None:
        """Test required fields strip whitespace."""
        request = FlextLdapCreateUserRequest(
            dn="uid=testuser,ou=users,dc=example,dc=org",
            uid="  testuser  ",
            cn="  Test User  ",
            sn="  User  "
        )

        assert request.uid == "testuser"
        assert request.cn == "Test User"
        assert request.sn == "User"

    def test_domain_rules_validation_success(self) -> None:
        """Test domain rules validation with valid request."""
        request = FlextLdapCreateUserRequest(
            dn="uid=testuser,ou=users,dc=example,dc=org",
            uid="testuser",
            cn="Test User",
            sn="User",
            mail="test@example.org"
        )
        # Should not raise
        request.validate_domain_rules()

    def test_domain_rules_validation_invalid_email(self) -> None:
        """Test domain rules validation with invalid email."""
        request = FlextLdapCreateUserRequest(
            dn="uid=testuser,ou=users,dc=example,dc=org",
            uid="testuser",
            cn="Test User",
            sn="User",
            mail="invalid-email"
        )
        with pytest.raises(ValueError, match="Email must be valid format"):
            request.validate_domain_rules()

