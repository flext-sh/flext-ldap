"""Enterprise-grade tests for FlextLdap value objects.

Tests all value objects with comprehensive validation.
"""


import pytest

from flext_ldap.values import (
    FlextLdapAttributesValue,
    FlextLdapConnectionInfo,
    FlextLdapCreateUserRequest,
    FlextLdapDistinguishedName,
    FlextLdapExtendedEntry,
    FlextLdapFilterValue,
    FlextLdapObjectClass,
    FlextLdapScopeEnum,
    FlextLdapUri,
)


class TestFlextLdapDistinguishedName:
    """Test DN value object."""

    def test_dn_creation_valid(self):
        """Test DN creation with valid format."""
        dn = FlextLdapDistinguishedName(value="cn=john,ou=users,dc=example,dc=com")

        assert str(dn) == "cn=john,ou=users,dc=example,dc=com"
        assert dn.get_rdn() == "cn=john"

    def test_dn_creation_invalid(self):
        """Test DN creation with invalid format."""
        with pytest.raises(ValueError):
            FlextLdapDistinguishedName(value="invalid-dn")

        with pytest.raises(ValueError):
            FlextLdapDistinguishedName(value="")

    def test_dn_parent_operations(self):
        """Test DN parent operations."""
        dn = FlextLdapDistinguishedName(value="cn=john,ou=users,dc=example,dc=com")

        parent = dn.get_parent_dn()
        assert parent is not None
        assert parent.value == "ou=users,dc=example,dc=com"

        # Test root DN
        root_dn = FlextLdapDistinguishedName(value="dc=com")
        assert root_dn.get_parent_dn() is None

    def test_dn_components(self):
        """Test DN component operations."""
        dn = FlextLdapDistinguishedName(value="cn=john,ou=users,dc=example,dc=com")

        components = dn.get_components()
        expected = ["cn=john", "ou=users", "dc=example", "dc=com"]
        assert components == expected

    def test_dn_hierarchy(self):
        """Test DN hierarchy relationships."""
        child_dn = FlextLdapDistinguishedName(value="cn=john,ou=users,dc=example,dc=com")
        parent_dn = FlextLdapDistinguishedName(value="ou=users,dc=example,dc=com")
        unrelated_dn = FlextLdapDistinguishedName(value="ou=groups,dc=example,dc=com")

        assert child_dn.is_child_of(parent_dn)
        assert not child_dn.is_child_of(unrelated_dn)

    def test_dn_validation_rules(self):
        """Test DN domain validation."""
        dn = FlextLdapDistinguishedName(value="cn=test,dc=example,dc=com")

        # Should not raise exception
        dn.validate_domain_rules()

        # Test invalid DN
        invalid_dn = FlextLdapDistinguishedName.__new__(FlextLdapDistinguishedName)
        invalid_dn.value = ""

        with pytest.raises(ValueError):
            invalid_dn.validate_domain_rules()


class TestFlextLdapFilterValue:
    """Test LDAP filter value object."""

    def test_filter_creation_valid(self):
        """Test filter creation with valid format."""
        filter_obj = FlextLdapFilterValue(value="(cn=john)")

        assert str(filter_obj) == "(cn=john)"

    def test_filter_creation_invalid(self):
        """Test filter creation with invalid format."""
        with pytest.raises(ValueError):
            FlextLdapFilterValue(value="cn=john")  # Missing parentheses

        with pytest.raises(ValueError):
            FlextLdapFilterValue(value="(cn=john")  # Unbalanced

    def test_filter_equals(self):
        """Test equals filter creation."""
        filter_obj = FlextLdapFilterValue.equals("cn", "john")
        assert filter_obj.value == "(cn=john)"

    def test_filter_present(self):
        """Test presence filter creation."""
        filter_obj = FlextLdapFilterValue.present("mail")
        assert filter_obj.value == "(mail=*)"

    def test_filter_and_combination(self):
        """Test AND filter combination."""
        filter1 = FlextLdapFilterValue.equals("cn", "john")
        filter2 = FlextLdapFilterValue.equals("ou", "users")

        combined = FlextLdapFilterValue.and_filters(filter1, filter2)
        assert combined.value == "(&(cn=john)(ou=users))"

    def test_filter_or_combination(self):
        """Test OR filter combination."""
        filter1 = FlextLdapFilterValue.equals("cn", "john")
        filter2 = FlextLdapFilterValue.equals("cn", "jane")

        combined = FlextLdapFilterValue.or_filters(filter1, filter2)
        assert combined.value == "(|(cn=john)(cn=jane))"

    def test_filter_enhanced_methods(self):
        """Test enhanced filter methods from models.py consolidation."""
        # Test contains
        contains_filter = FlextLdapFilterValue.contains("mail", "example")
        assert contains_filter.value == "(mail=*example*)"

        # Test starts_with
        starts_filter = FlextLdapFilterValue.starts_with("cn", "john")
        assert starts_filter.value == "(cn=john*)"

        # Test ends_with
        ends_filter = FlextLdapFilterValue.ends_with("mail", "com")
        assert ends_filter.value == "(mail=*com)"

        # Test not_equals
        not_filter = FlextLdapFilterValue.not_equals("cn", "admin")
        assert not_filter.value == "(!(cn=admin))"

    def test_filter_operators(self):
        """Test filter operators from models.py consolidation."""
        filter1 = FlextLdapFilterValue.equals("cn", "john")
        filter2 = FlextLdapFilterValue.equals("ou", "users")

        # Test __and__ operator
        and_result = filter1 & filter2
        assert and_result.value == "(&(cn=john)(ou=users))"

        # Test __or__ operator
        or_result = filter1 | filter2
        assert or_result.value == "(|(cn=john)(ou=users))"

    def test_filter_business_filters(self):
        """Test business-specific filters."""
        # Test person filter
        person_filter = FlextLdapFilterValue.person_filter()
        assert person_filter.value == "(objectClass=person)"

        # Test group filter
        group_filter = FlextLdapFilterValue.group_filter()
        assert "(objectClass=group)" in group_filter.value
        assert "(objectClass=groupOfNames)" in group_filter.value


class TestFlextLdapUri:
    """Test LDAP URI value object."""

    def test_uri_creation_valid(self):
        """Test URI creation with valid format."""
        uri = FlextLdapUri(value="ldap://example.com:389")

        assert str(uri) == "ldap://example.com:389"
        assert uri.hostname == "example.com"
        assert uri.port == 389
        assert not uri.is_secure

    def test_uri_creation_secure(self):
        """Test secure URI creation."""
        uri = FlextLdapUri(value="ldaps://example.com:636")

        assert uri.is_secure
        assert uri.port == 636

    def test_uri_creation_invalid(self):
        """Test URI creation with invalid format."""
        with pytest.raises(ValueError):
            FlextLdapUri(value="http://example.com")  # Wrong scheme

        with pytest.raises(ValueError):
            FlextLdapUri(value="ldap://")  # No hostname

    def test_uri_port_defaults(self):
        """Test URI port defaults."""
        ldap_uri = FlextLdapUri(value="ldap://example.com")
        assert ldap_uri.port == 389

        ldaps_uri = FlextLdapUri(value="ldaps://example.com")
        assert ldaps_uri.port == 636


class TestFlextLdapScopeEnum:
    """Test LDAP scope enumeration."""

    def test_scope_values(self):
        """Test scope enumeration values."""
        assert FlextLdapScopeEnum.BASE == "base"
        assert FlextLdapScopeEnum.ONE_LEVEL == "onelevel"
        assert FlextLdapScopeEnum.SUBTREE == "subtree"

    def test_scope_legacy_mappings(self):
        """Test legacy scope mappings from models.py consolidation."""
        assert FlextLdapScopeEnum.ONE == "onelevel"
        assert FlextLdapScopeEnum.SUB == "subtree"


class TestFlextLdapObjectClass:
    """Test LDAP object class value object."""

    def test_object_class_creation(self):
        """Test object class creation."""
        obj_class = FlextLdapObjectClass(name="inetOrgPerson")

        assert str(obj_class) == "inetOrgPerson"

    def test_object_class_validation(self):
        """Test object class name validation."""
        with pytest.raises(ValueError):
            FlextLdapObjectClass(name="")  # Empty name

        with pytest.raises(ValueError):
            FlextLdapObjectClass(name="invalid@class")  # Invalid characters


class TestFlextLdapAttributesValue:
    """Test LDAP attributes value object."""

    def test_attributes_creation(self):
        """Test attributes creation."""
        attrs = FlextLdapAttributesValue(attributes={
            "cn": ["John Doe"],
            "mail": ["john@example.com", "john.doe@example.com"],
            "objectClass": ["inetOrgPerson", "person"],
        })

        assert attrs.get_single_value("cn") == "John Doe"
        assert len(attrs.get_values("mail")) == 2
        assert attrs.has_attribute("objectClass")

    def test_attributes_operations(self):
        """Test attribute operations."""
        attrs = FlextLdapAttributesValue()

        # Test adding values
        updated = attrs.add_value("cn", "John Doe")
        assert updated.get_single_value("cn") == "John Doe"
        assert not attrs.has_attribute("cn")  # Immutable

        # Test removing values
        removed = updated.remove_value("cn", "John Doe")
        assert not removed.has_attribute("cn")

    def test_attributes_validation(self):
        """Test attributes domain validation."""
        # Test invalid attributes
        invalid_attrs = FlextLdapAttributesValue.__new__(FlextLdapAttributesValue)
        invalid_attrs.attributes = {"": ["value"]}  # Empty name

        with pytest.raises(ValueError):
            invalid_attrs.validate_domain_rules()


class TestFlextLdapConnectionInfo:
    """Test LDAP connection info value object."""

    def test_connection_info_creation(self):
        """Test connection info creation."""
        uri = FlextLdapUri(value="ldaps://example.com:636")

        conn_info = FlextLdapConnectionInfo(
            server_uri=uri,
            is_authenticated=True,
            is_secure=True,
        )

        assert conn_info.is_authenticated
        assert conn_info.is_secure
        assert "authenticated" in conn_info.connection_string
        assert "secure" in conn_info.connection_string

    def test_connection_info_validation(self):
        """Test connection info validation."""
        uri = FlextLdapUri(value="ldap://example.com")

        # Test valid connection info
        conn_info = FlextLdapConnectionInfo(
            server_uri=uri,
            protocol_version=3,
        )
        conn_info.validate_domain_rules()  # Should not raise

        # Test invalid protocol version
        invalid_info = FlextLdapConnectionInfo.__new__(FlextLdapConnectionInfo)
        invalid_info.server_uri = uri
        invalid_info.protocol_version = 1  # Invalid

        with pytest.raises(ValueError):
            invalid_info.validate_domain_rules()


class TestFlextLdapCreateUserRequest:
    """Test user creation request value object."""

    def test_user_request_creation(self):
        """Test user request creation."""
        request = FlextLdapCreateUserRequest(
            dn="cn=john.doe,ou=users,dc=example,dc=com",
            uid="john.doe",
            cn="John Doe",
            sn="Doe",
            mail="john.doe@example.com",
            phone="+1-555-0123",
        )

        assert request.dn == "cn=john.doe,ou=users,dc=example,dc=com"
        assert request.uid == "john.doe"
        assert request.mail == "john.doe@example.com"

    def test_user_request_validation(self):
        """Test user request validation."""
        # Test valid request
        request = FlextLdapCreateUserRequest(
            dn="cn=test,dc=example,dc=com",
            uid="test",
            cn="Test",
            sn="User",
        )
        request.validate_domain_rules()  # Should not raise

        # Test invalid email
        with pytest.raises(ValueError):
            FlextLdapCreateUserRequest(
                dn="cn=test,dc=example,dc=com",
                uid="test",
                cn="Test",
                sn="User",
                mail="invalid-email",
            )

    def test_user_request_field_validation(self):
        """Test individual field validation."""
        # Test empty required fields
        with pytest.raises(ValueError):
            FlextLdapCreateUserRequest(
                dn="",  # Empty DN
                uid="test",
                cn="Test",
                sn="User",
            )

        with pytest.raises(ValueError):
            FlextLdapCreateUserRequest(
                dn="cn=test,dc=example,dc=com",
                uid="",  # Empty UID
                cn="Test",
                sn="User",
            )


class TestFlextLdapExtendedEntry:
    """Test extended LDAP entry from models.py consolidation."""

    def test_extended_entry_creation(self):
        """Test extended entry creation."""
        entry = FlextLdapExtendedEntry(
            dn="cn=john,ou=users,dc=example,dc=com",
            attributes={
                "cn": ["John Doe"],
                "uid": ["john"],
                "mail": ["john@example.com"],
                "objectClass": ["inetOrgPerson", "person"],
            },
        )

        assert entry.get_cn() == "John Doe"
        assert entry.get_uid() == "john"
        assert entry.get_mail() == "john@example.com"

    def test_extended_entry_type_detection(self):
        """Test entry type detection methods."""
        person_entry = FlextLdapExtendedEntry(
            dn="cn=john,dc=example,dc=com",
            attributes={"objectClass": ["person", "inetOrgPerson"]},
        )

        group_entry = FlextLdapExtendedEntry(
            dn="cn=admins,dc=example,dc=com",
            attributes={"objectClass": ["groupOfNames"]},
        )

        assert person_entry.is_person()
        assert not person_entry.is_group()

        assert group_entry.is_group()
        assert not group_entry.is_person()

    def test_extended_entry_attribute_access(self):
        """Test extended entry attribute access methods."""
        entry = FlextLdapExtendedEntry(
            dn="cn=test,dc=example,dc=com",
            attributes={
                "cn": ["Test User"],
                "mail": ["test@example.com", "test.user@example.com"],
            },
        )

        # Test single attribute access
        assert entry.get_single_attribute("cn") == "Test User"
        assert entry.get_single_attribute("nonexistent") is None

        # Test multi-value attribute access
        mail_values = entry.get_attribute("mail")
        assert len(mail_values) == 2
        assert "test@example.com" in mail_values

        # Test attribute existence check
        assert entry.has_attribute("cn")
        assert not entry.has_attribute("nonexistent")


class TestValueObjectImmutability:
    """Test immutability patterns across value objects."""

    def test_dn_immutability(self):
        """Test DN immutability."""
        dn = FlextLdapDistinguishedName(value="cn=test,dc=example,dc=com")

        # Value objects should be immutable
        original_value = dn.value

        # Any operations should not modify original
        parent_dn = dn.get_parent_dn()
        assert dn.value == original_value
        assert parent_dn is not dn

    def test_attributes_immutability(self):
        """Test attributes immutability."""
        attrs = FlextLdapAttributesValue(attributes={"cn": ["test"]})

        # Operations should return new instances
        updated = attrs.add_value("mail", "test@example.com")

        assert not attrs.has_attribute("mail")
        assert updated.has_attribute("mail")
        assert attrs is not updated
