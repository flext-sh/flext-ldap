"""Enterprise-grade tests for FlextLdap value objects.

Tests all value objects with comprehensive validation.
"""

import pytest

# Constants
EXPECTED_BULK_SIZE = 2
EXPECTED_DATA_COUNT = 3
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

    def test_dn_creation_valid(self) -> None:
        """Test DN creation with valid format."""
        dn = FlextLdapDistinguishedName(value="cn=john,ou=users,dc=example,dc=com")

        if str(dn) != "cn=john,ou=users,dc=example,dc=com":
            msg = f"Expected {'cn=john,ou=users,dc=example,dc=com'}, got {dn!s}"
            raise AssertionError(msg)
        assert dn.get_rdn() == "cn=john"

    def test_dn_creation_invalid(self) -> None:
        """Test DN creation with invalid format."""
        with pytest.raises(ValueError):
            FlextLdapDistinguishedName(value="invalid-dn")

        with pytest.raises(ValueError):
            FlextLdapDistinguishedName(value="")

    def test_dn_parent_operations(self) -> None:
        """Test DN parent operations."""
        dn = FlextLdapDistinguishedName(value="cn=john,ou=users,dc=example,dc=com")

        parent = dn.get_parent_dn()
        assert parent is not None
        if parent.value != "ou=users,dc=example,dc=com":
            msg = f"Expected {'ou=users,dc=example,dc=com'}, got {parent.value}"
            raise AssertionError(msg)

        # Test root DN
        root_dn = FlextLdapDistinguishedName(value="dc=com")
        assert root_dn.get_parent_dn() is None

    def test_dn_components(self) -> None:
        """Test DN component operations."""
        dn = FlextLdapDistinguishedName(value="cn=john,ou=users,dc=example,dc=com")

        components = dn.get_components()
        expected = ["cn=john", "ou=users", "dc=example", "dc=com"]
        if components != expected:
            msg = f"Expected {expected}, got {components}"
            raise AssertionError(msg)

    def test_dn_hierarchy(self) -> None:
        """Test DN hierarchy relationships."""
        child_dn = FlextLdapDistinguishedName(
            value="cn=john,ou=users,dc=example,dc=com"
        )
        parent_dn = FlextLdapDistinguishedName(value="ou=users,dc=example,dc=com")
        unrelated_dn = FlextLdapDistinguishedName(value="ou=groups,dc=example,dc=com")

        assert child_dn.is_child_of(parent_dn)
        assert not child_dn.is_child_of(unrelated_dn)

    def test_dn_validation_rules(self) -> None:
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

    def test_filter_creation_valid(self) -> None:
        """Test filter creation with valid format."""
        filter_obj = FlextLdapFilterValue(value="(cn=john)")

        if str(filter_obj) != "(cn=john)":
            msg = f"Expected {'(cn=john)'}, got {filter_obj!s}"
            raise AssertionError(msg)

    def test_filter_creation_invalid(self) -> None:
        """Test filter creation with invalid format."""
        with pytest.raises(ValueError):
            FlextLdapFilterValue(value="cn=john")  # Missing parentheses

        with pytest.raises(ValueError):
            FlextLdapFilterValue(value="(cn=john")  # Unbalanced

    def test_filter_equals(self) -> None:
        """Test equals filter creation."""
        filter_obj = FlextLdapFilterValue.equals("cn", "john")
        if filter_obj.value != "(cn=john)":
            msg = f"Expected {'(cn=john)'}, got {filter_obj.value}"
            raise AssertionError(msg)

    def test_filter_present(self) -> None:
        """Test presence filter creation."""
        filter_obj = FlextLdapFilterValue.present("mail")
        if filter_obj.value != "(mail=*)":
            msg = f"Expected {'(mail=*)'}, got {filter_obj.value}"
            raise AssertionError(msg)

    def test_filter_and_combination(self) -> None:
        """Test AND filter combination."""
        filter1 = FlextLdapFilterValue.equals("cn", "john")
        filter2 = FlextLdapFilterValue.equals("ou", "users")

        combined = FlextLdapFilterValue.and_filters(filter1, filter2)
        if combined.value != "(&(cn=john)(ou=users))":
            msg = f"Expected {'(&(cn=john)(ou=users))'}, got {combined.value}"
            raise AssertionError(msg)

    def test_filter_or_combination(self) -> None:
        """Test OR filter combination."""
        filter1 = FlextLdapFilterValue.equals("cn", "john")
        filter2 = FlextLdapFilterValue.equals("cn", "jane")

        combined = FlextLdapFilterValue.or_filters(filter1, filter2)
        if combined.value != "(|(cn=john)(cn=jane))":
            msg = f"Expected {'(|(cn=john)(cn=jane))'}, got {combined.value}"
            raise AssertionError(msg)

    def test_filter_enhanced_methods(self) -> None:
        """Test enhanced filter methods from models.py consolidation."""
        # Test contains
        contains_filter = FlextLdapFilterValue.contains("mail", "example")
        if contains_filter.value != "(mail=*example*)":
            msg = f"Expected {'(mail=*example*)'}, got {contains_filter.value}"
            raise AssertionError(msg)

        # Test starts_with
        starts_filter = FlextLdapFilterValue.starts_with("cn", "john")
        if starts_filter.value != "(cn=john*)":
            msg = f"Expected {'(cn=john*)'}, got {starts_filter.value}"
            raise AssertionError(msg)

        # Test ends_with
        ends_filter = FlextLdapFilterValue.ends_with("mail", "com")
        if ends_filter.value != "(mail=*com)":
            msg = f"Expected {'(mail=*com)'}, got {ends_filter.value}"
            raise AssertionError(msg)

        # Test not_equals
        not_filter = FlextLdapFilterValue.not_equals("cn", "REDACTED_LDAP_BIND_PASSWORD")
        if not_filter.value != "(!(cn=REDACTED_LDAP_BIND_PASSWORD))":
            msg = f"Expected {'(!(cn=REDACTED_LDAP_BIND_PASSWORD))'}, got {not_filter.value}"
            raise AssertionError(msg)

    def test_filter_operators(self) -> None:
        """Test filter operators from models.py consolidation."""
        filter1 = FlextLdapFilterValue.equals("cn", "john")
        filter2 = FlextLdapFilterValue.equals("ou", "users")

        # Test __and__ operator
        and_result = filter1 & filter2
        if and_result.value != "(&(cn=john)(ou=users))":
            msg = f"Expected {'(&(cn=john)(ou=users))'}, got {and_result.value}"
            raise AssertionError(msg)

        # Test __or__ operator
        or_result = filter1 | filter2
        if or_result.value != "(|(cn=john)(ou=users))":
            msg = f"Expected {'(|(cn=john)(ou=users))'}, got {or_result.value}"
            raise AssertionError(msg)

    def test_filter_business_filters(self) -> None:
        """Test business-specific filters."""
        # Test person filter
        person_filter = FlextLdapFilterValue.person_filter()
        if person_filter.value != "(objectClass=person)":
            msg = f"Expected {'(objectClass=person)'}, got {person_filter.value}"
            raise AssertionError(msg)

        # Test group filter
        group_filter = FlextLdapFilterValue.group_filter()
        if "(objectClass=group)" not in group_filter.value:
            msg = f"Expected {'(objectClass=group)'} in {group_filter.value}"
            raise AssertionError(msg)
        assert "(objectClass=groupOfNames)" in group_filter.value


class TestFlextLdapUri:
    """Test LDAP URI value object."""

    def test_uri_creation_valid(self) -> None:
        """Test URI creation with valid format."""
        uri = FlextLdapUri(value="ldap://example.com:389")

        if str(uri) != "ldap://example.com:389":
            msg = f"Expected {'ldap://example.com:389'}, got {uri!s}"
            raise AssertionError(msg)
        assert uri.hostname == "example.com"
        if uri.port != 389:
            msg = f"Expected {389}, got {uri.port}"
            raise AssertionError(msg)
        assert not uri.is_secure

    def test_uri_creation_secure(self) -> None:
        """Test secure URI creation."""
        uri = FlextLdapUri(value="ldaps://example.com:636")

        assert uri.is_secure
        if uri.port != 636:
            msg = f"Expected {636}, got {uri.port}"
            raise AssertionError(msg)

    def test_uri_creation_invalid(self) -> None:
        """Test URI creation with invalid format."""
        with pytest.raises(ValueError):
            FlextLdapUri(value="http://example.com")  # Wrong scheme

        with pytest.raises(ValueError):
            FlextLdapUri(value="ldap://")  # No hostname

    def test_uri_port_defaults(self) -> None:
        """Test URI port defaults."""
        ldap_uri = FlextLdapUri(value="ldap://example.com")
        if ldap_uri.port != 389:
            msg = f"Expected {389}, got {ldap_uri.port}"
            raise AssertionError(msg)

        ldaps_uri = FlextLdapUri(value="ldaps://example.com")
        if ldaps_uri.port != 636:
            msg = f"Expected {636}, got {ldaps_uri.port}"
            raise AssertionError(msg)


class TestFlextLdapScopeEnum:
    """Test LDAP scope enumeration."""

    def test_scope_values(self) -> None:
        """Test scope enumeration values."""
        if FlextLdapScopeEnum.BASE != "base":
            msg = f"Expected {'base'}, got {FlextLdapScopeEnum.BASE}"
            raise AssertionError(msg)
        assert FlextLdapScopeEnum.ONE_LEVEL == "onelevel"
        if FlextLdapScopeEnum.SUBTREE != "subtree":
            msg = f"Expected {'subtree'}, got {FlextLdapScopeEnum.SUBTREE}"
            raise AssertionError(msg)

    def test_scope_legacy_mappings(self) -> None:
        """Test legacy scope mappings from models.py consolidation."""
        if FlextLdapScopeEnum.ONE != "onelevel":
            msg = f"Expected {'onelevel'}, got {FlextLdapScopeEnum.ONE}"
            raise AssertionError(msg)
        assert FlextLdapScopeEnum.SUB == "subtree"


class TestFlextLdapObjectClass:
    """Test LDAP object class value object."""

    def test_object_class_creation(self) -> None:
        """Test object class creation."""
        obj_class = FlextLdapObjectClass(name="inetOrgPerson")

        if str(obj_class) != "inetOrgPerson":
            msg = f"Expected {'inetOrgPerson'}, got {obj_class!s}"
            raise AssertionError(msg)

    def test_object_class_validation(self) -> None:
        """Test object class name validation."""
        with pytest.raises(ValueError):
            FlextLdapObjectClass(name="")  # Empty name

        with pytest.raises(ValueError):
            FlextLdapObjectClass(name="invalid@class")  # Invalid characters


class TestFlextLdapAttributesValue:
    """Test LDAP attributes value object."""

    def test_attributes_creation(self) -> None:
        """Test attributes creation."""
        attrs = FlextLdapAttributesValue(
            attributes={
                "cn": ["John Doe"],
                "mail": ["john@example.com", "john.doe@example.com"],
                "objectClass": ["inetOrgPerson", "person"],
            }
        )

        if attrs.get_single_value("cn") != "John Doe":
            msg = f"Expected {'John Doe'}, got {attrs.get_single_value('cn')}"
            raise AssertionError(msg)
        assert len(attrs.get_values("mail")) == EXPECTED_BULK_SIZE
        assert attrs.has_attribute("objectClass")

    def test_attributes_operations(self) -> None:
        """Test attribute operations."""
        attrs = FlextLdapAttributesValue()

        # Test adding values
        updated = attrs.add_value("cn", "John Doe")
        if updated.get_single_value("cn") != "John Doe":
            msg = f"Expected {'John Doe'}, got {updated.get_single_value('cn')}"
            raise AssertionError(msg)
        assert not attrs.has_attribute("cn")  # Immutable

        # Test removing values
        removed = updated.remove_value("cn", "John Doe")
        assert not removed.has_attribute("cn")

    def test_attributes_validation(self) -> None:
        """Test attributes domain validation."""
        # Test invalid attributes
        invalid_attrs = FlextLdapAttributesValue.__new__(FlextLdapAttributesValue)
        invalid_attrs.attributes = {"": ["value"]}  # Empty name

        with pytest.raises(ValueError):
            invalid_attrs.validate_domain_rules()


class TestFlextLdapConnectionInfo:
    """Test LDAP connection info value object."""

    def test_connection_info_creation(self) -> None:
        """Test connection info creation."""
        uri = FlextLdapUri(value="ldaps://example.com:636")

        conn_info = FlextLdapConnectionInfo(
            server_uri=uri,
            is_authenticated=True,
            is_secure=True,
        )

        assert conn_info.is_authenticated
        assert conn_info.is_secure
        if "authenticated" not in conn_info.connection_string:
            msg = f"Expected {'authenticated'} in {conn_info.connection_string}"
            raise AssertionError(msg)
        assert "secure" in conn_info.connection_string

    def test_connection_info_validation(self) -> None:
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

    def test_user_request_creation(self) -> None:
        """Test user request creation."""
        request = FlextLdapCreateUserRequest(
            dn="cn=john.doe,ou=users,dc=example,dc=com",
            uid="john.doe",
            cn="John Doe",
            sn="Doe",
            mail="john.doe@example.com",
            phone="+1-555-0123",
        )

        if request.dn != "cn=john.doe,ou=users,dc=example,dc=com":
            msg = (
                f"Expected {'cn=john.doe,ou=users,dc=example,dc=com'}, got {request.dn}"
            )
            raise AssertionError(msg)
        assert request.uid == "john.doe"
        if request.mail != "john.doe@example.com":
            msg = f"Expected {'john.doe@example.com'}, got {request.mail}"
            raise AssertionError(msg)

    def test_user_request_validation(self) -> None:
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

    def test_user_request_field_validation(self) -> None:
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

    def test_extended_entry_creation(self) -> None:
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

        if entry.get_cn() != "John Doe":
            msg = f"Expected {'John Doe'}, got {entry.get_cn()}"
            raise AssertionError(msg)
        assert entry.get_uid() == "john"
        if entry.get_mail() != "john@example.com":
            msg = f"Expected {'john@example.com'}, got {entry.get_mail()}"
            raise AssertionError(msg)

    def test_extended_entry_type_detection(self) -> None:
        """Test entry type detection methods."""
        person_entry = FlextLdapExtendedEntry(
            dn="cn=john,dc=example,dc=com",
            attributes={"objectClass": ["person", "inetOrgPerson"]},
        )

        group_entry = FlextLdapExtendedEntry(
            dn="cn=REDACTED_LDAP_BIND_PASSWORDs,dc=example,dc=com",
            attributes={"objectClass": ["groupOfNames"]},
        )

        assert person_entry.is_person()
        assert not person_entry.is_group()

        assert group_entry.is_group()
        assert not group_entry.is_person()

    def test_extended_entry_attribute_access(self) -> None:
        """Test extended entry attribute access methods."""
        entry = FlextLdapExtendedEntry(
            dn="cn=test,dc=example,dc=com",
            attributes={
                "cn": ["Test User"],
                "mail": ["test@example.com", "test.user@example.com"],
            },
        )

        # Test single attribute access
        if entry.get_single_attribute("cn") != "Test User":
            msg = f"Expected {'Test User'}, got {entry.get_single_attribute('cn')}"
            raise AssertionError(msg)
        assert entry.get_single_attribute("nonexistent") is None

        # Test multi-value attribute access
        mail_values = entry.get_attribute("mail")
        if len(mail_values) != EXPECTED_BULK_SIZE:
            msg = f"Expected {2}, got {len(mail_values)}"
            raise AssertionError(msg)
        if "test@example.com" not in mail_values:
            msg = f"Expected {'test@example.com'} in {mail_values}"
            raise AssertionError(msg)

        # Test attribute existence check
        assert entry.has_attribute("cn")
        assert not entry.has_attribute("nonexistent")


class TestValueObjectImmutability:
    """Test immutability patterns across value objects."""

    def test_dn_immutability(self) -> None:
        """Test DN immutability."""
        dn = FlextLdapDistinguishedName(value="cn=test,dc=example,dc=com")

        # Value objects should be immutable
        original_value = dn.value

        # Any operations should not modify original
        parent_dn = dn.get_parent_dn()
        if dn.value != original_value:
            msg = f"Expected {original_value}, got {dn.value}"
            raise AssertionError(msg)
        assert parent_dn is not dn

    def test_attributes_immutability(self) -> None:
        """Test attributes immutability."""
        attrs = FlextLdapAttributesValue(attributes={"cn": ["test"]})

        # Operations should return new instances
        updated = attrs.add_value("mail", "test@example.com")

        assert not attrs.has_attribute("mail")
        assert updated.has_attribute("mail")
        assert attrs is not updated
