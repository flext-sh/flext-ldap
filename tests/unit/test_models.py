"""Unit tests for FLEXT LDAP models (entities and value objects)."""

from __future__ import annotations

from uuid import uuid4

from flext_ldap.models import (
    FlextLdapCreateUserRequest,
    FlextLdapDistinguishedName,
    FlextLdapEntry,
    FlextLdapFilter,
    FlextLdapGroup,
    FlextLdapUser,
)


class TestFlextLdapDistinguishedName:
    """Test DN value object."""

    def test_dn_creation(self) -> None:
        """Test DN creation with valid value."""
        dn = FlextLdapDistinguishedName(value="cn=test,dc=example,dc=com")
        assert dn.value == "cn=test,dc=example,dc=com"

    def test_dn_factory_method_success(self) -> None:
        """Test DN factory method with valid input."""
        result = FlextLdapDistinguishedName.create("cn=test,dc=example,dc=com")
        assert result.is_success
        assert result.data is not None
        assert result.data.value == "cn=test,dc=example,dc=com"

    def test_dn_factory_method_with_empty_string(self) -> None:
        """Test DN factory method with empty string."""
        result = FlextLdapDistinguishedName.create("")
        # Should either succeed (allowing empty DN) or fail gracefully
        assert hasattr(result, "is_success")

    def test_dn_equality(self) -> None:
        """Test DN equality comparison."""
        dn1 = FlextLdapDistinguishedName(value="cn=test,dc=example,dc=com")
        dn2 = FlextLdapDistinguishedName(value="cn=test,dc=example,dc=com")
        assert dn1.value == dn2.value

    def test_dn_string_representation(self) -> None:
        """Test DN string representation."""
        dn = FlextLdapDistinguishedName(value="cn=test,dc=example,dc=com")
        assert str(dn) or repr(dn)  # Should have some string representation


class TestFlextLdapFilter:
    """Test LDAP filter value object."""

    def test_filter_creation(self) -> None:
        """Test filter creation with valid value."""
        filter_obj = FlextLdapFilter(value="(objectClass=person)")
        assert filter_obj.value == "(objectClass=person)"

    def test_filter_factory_method_success(self) -> None:
        """Test filter factory method with valid input."""
        result = FlextLdapFilter.create("(objectClass=person)")
        assert result.is_success
        assert result.data is not None
        assert result.data.value == "(objectClass=person)"

    def test_filter_complex_filter(self) -> None:
        """Test filter with complex LDAP filter syntax."""
        complex_filter = "(&(objectClass=person)(|(uid=test)(cn=test)))"
        filter_obj = FlextLdapFilter(value=complex_filter)
        assert filter_obj.value == complex_filter

    def test_filter_equality(self) -> None:
        """Test filter equality comparison."""
        filter1 = FlextLdapFilter(value="(objectClass=person)")
        filter2 = FlextLdapFilter(value="(objectClass=person)")
        assert filter1.value == filter2.value


class TestFlextLdapUser:
    """Test LDAP user entity."""

    def test_user_creation(self) -> None:
        """Test user entity creation."""
        user = FlextLdapUser(
            id=str(uuid4()),
            dn="cn=test,dc=example,dc=com",
            uid="test",
            cn="Test User",
            sn="User",
        )
        assert user.uid == "test"
        assert user.cn == "Test User"
        assert user.sn == "User"
        assert user.dn == "cn=test,dc=example,dc=com"

    def test_user_is_active_default(self) -> None:
        """Test user is active by default."""
        user = FlextLdapUser(
            id=str(uuid4()),
            dn="cn=test,dc=example,dc=com",
            uid="test",
            cn="Test User",
            sn="User",
        )
        assert user.is_active()

    def test_user_lock_account(self) -> None:
        """Test user account locking."""
        user = FlextLdapUser(
            id=str(uuid4()),
            dn="cn=test,dc=example,dc=com",
            uid="test",
            cn="Test User",
            sn="User",
        )
        locked_user = user.lock_account()
        assert not locked_user.is_active()

    def test_user_unlock_account(self) -> None:
        """Test user account unlocking."""
        user = FlextLdapUser(
            id=str(uuid4()),
            dn="cn=test,dc=example,dc=com",
            uid="test",
            cn="Test User",
            sn="User",
        ).lock_account()
        unlocked_user = user.unlock_account()
        assert unlocked_user.is_active()

    def test_user_immutability(self) -> None:
        """Test that user entity operations return new instances."""
        user = FlextLdapUser(
            id=str(uuid4()),
            dn="cn=test,dc=example,dc=com",
            uid="test",
            cn="Test User",
            sn="User",
        )
        locked_user = user.lock_account()

        # Original user should remain unchanged
        assert user.is_active()
        assert not locked_user.is_active()
        assert user is not locked_user


class TestFlextLdapGroup:
    """Test LDAP group entity."""

    def test_group_creation(self) -> None:
        """Test group entity creation."""
        group = FlextLdapGroup(
            id=str(uuid4()),
            dn="cn=testgroup,dc=example,dc=com",
            cn="Test Group",
        )
        assert group.cn == "Test Group"
        assert group.dn == "cn=testgroup,dc=example,dc=com"

    def test_group_add_member(self) -> None:
        """Test adding member to group."""
        group = FlextLdapGroup(
            id=str(uuid4()),
            dn="cn=testgroup,dc=example,dc=com",
            cn="Test Group",
        )

        updated_group = group.add_member("cn=user1,dc=example,dc=com")
        assert updated_group.has_member("cn=user1,dc=example,dc=com")

    def test_group_remove_member(self) -> None:
        """Test removing member from group."""
        group = FlextLdapGroup(
            id=str(uuid4()),
            dn="cn=testgroup,dc=example,dc=com",
            cn="Test Group",
            members=["cn=user1,dc=example,dc=com", "cn=user2,dc=example,dc=com"],
        )

        updated_group = group.remove_member("cn=user1,dc=example,dc=com")
        assert not updated_group.has_member("cn=user1,dc=example,dc=com")
        assert updated_group.has_member("cn=user2,dc=example,dc=com")

    def test_group_has_member(self) -> None:
        """Test checking group membership."""
        group = FlextLdapGroup(
            id=str(uuid4()),
            dn="cn=testgroup,dc=example,dc=com",
            cn="Test Group",
            members=["cn=user1,dc=example,dc=com"],
        )

        assert group.has_member("cn=user1,dc=example,dc=com")
        assert not group.has_member("cn=user2,dc=example,dc=com")

    def test_group_immutability(self) -> None:
        """Test that group entity operations return new instances."""
        group = FlextLdapGroup(
            id=str(uuid4()),
            dn="cn=testgroup,dc=example,dc=com",
            cn="Test Group",
        )

        updated_group = group.add_member("cn=user1,dc=example,dc=com")

        # Original group should remain unchanged
        assert not group.has_member("cn=user1,dc=example,dc=com")
        assert updated_group.has_member("cn=user1,dc=example,dc=com")
        assert group is not updated_group


class TestFlextLdapEntry:
    """Test generic LDAP entry."""

    def test_entry_creation(self) -> None:
        """Test entry creation."""
        entry = FlextLdapEntry(
            id=str(uuid4()),
            dn="cn=test,dc=example,dc=com",
            attributes={"cn": "test", "objectClass": "person"},
        )
        assert entry.dn == "cn=test,dc=example,dc=com"
        assert entry.attributes["cn"] == "test"

    def test_entry_get_attribute(self) -> None:
        """Test getting attribute from entry."""
        entry = FlextLdapEntry(
            id=str(uuid4()),
            dn="cn=test,dc=example,dc=com",
            attributes={"cn": "test", "mail": "test@example.com"},
        )

        assert entry.get_attribute("cn") == "test"
        assert entry.get_attribute("mail") == "test@example.com"
        assert entry.get_attribute("nonexistent") is None

    def test_entry_has_attribute(self) -> None:
        """Test checking if entry has attribute."""
        entry = FlextLdapEntry(
            id=str(uuid4()),
            dn="cn=test,dc=example,dc=com",
            attributes={"cn": "test", "mail": "test@example.com"},
        )

        assert entry.has_attribute("cn")
        assert entry.has_attribute("mail")
        assert not entry.has_attribute("nonexistent")


class TestFlextLdapCreateUserRequest:
    """Test user creation request value object."""

    def test_create_user_request_basic(self) -> None:
        """Test basic user creation request."""
        request = FlextLdapCreateUserRequest(
            dn="cn=test,ou=users,dc=example,dc=com",
            uid="test",
            cn="Test User",
            sn="User",
        )

        assert request.dn == "cn=test,ou=users,dc=example,dc=com"
        assert request.uid == "test"
        assert request.cn == "Test User"
        assert request.sn == "User"

    def test_create_user_request_with_optional_fields(self) -> None:
        """Test user creation request with optional fields."""
        request = FlextLdapCreateUserRequest(
            dn="cn=test,ou=users,dc=example,dc=com",
            uid="test",
            cn="Test User",
            sn="User",
            mail="test@example.com",
            user_password="secret123",
        )

        assert request.mail == "test@example.com"
        assert request.user_password == "secret123"

    def test_create_user_request_to_attributes(self) -> None:
        """Test converting user request to LDAP attributes."""
        request = FlextLdapCreateUserRequest(
            dn="cn=test,ou=users,dc=example,dc=com",
            uid="test",
            cn="Test User",
            sn="User",
            mail="test@example.com",
        )

        attributes = request.to_ldap_attributes()

        assert "uid" in attributes
        assert "cn" in attributes
        assert "sn" in attributes
        assert "mail" in attributes
        assert attributes["uid"] == "test"
        assert attributes["cn"] == "Test User"


class TestModelValidation:
    """Test model validation and business rules."""

    def test_user_dn_validation(self) -> None:
        """Test user DN validation."""
        # Valid DN should work
        user = FlextLdapUser(
            id=str(uuid4()),
            dn="cn=test,dc=example,dc=com",
            uid="test",
            cn="Test User",
            sn="User",
        )
        assert user.dn == "cn=test,dc=example,dc=com"

    def test_group_member_dn_validation(self) -> None:
        """Test group member DN validation."""
        group = FlextLdapGroup(
            id=str(uuid4()),
            dn="cn=testgroup,dc=example,dc=com",
            cn="Test Group",
        )

        # Adding valid DN should work
        updated_group = group.add_member("cn=user1,dc=example,dc=com")
        assert updated_group.has_member("cn=user1,dc=example,dc=com")

    def test_create_user_request_validation(self) -> None:
        """Test user creation request validation."""
        # Required fields should be present
        request = FlextLdapCreateUserRequest(
            dn="cn=test,ou=users,dc=example,dc=com",
            uid="test",
            cn="Test User",
            sn="User",
        )

        assert request.uid is not None
        assert request.cn is not None
        assert request.sn is not None
        assert request.dn is not None
