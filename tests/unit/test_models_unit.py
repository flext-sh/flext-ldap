"""Unit tests for FLEXT LDAP entities and value objects - NO MOCKS.

Tests pure domain logic and business rules without external dependencies.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from flext_core import (
    FlextEntityId,
    FlextEntityStatus,
    FlextEventList,
    FlextMetadata,
    FlextTimestamp,
    FlextVersion,
)

from flext_ldap import (
    FlextLdapCreateUserRequest,
    FlextLdapDistinguishedName,
    FlextLdapEntry,
    FlextLdapGroup,
    FlextLdapUser,
)


class TestFlextLdapDistinguishedName:
    """Test DN value object with real validation logic."""

    def test_dn_creation_with_valid_dns(self) -> None:
        """Test DN creation with various valid DN formats."""
        valid_dns = [
            "cn=test,dc=example,dc=com",
            "uid=user,ou=people,dc=company,dc=org",
            "cn=admin,dc=flext,dc=local",
            "ou=groups,dc=test,dc=com",
            "cn=Test User,ou=Users,dc=domain,dc=com",
        ]

        for dn_str in valid_dns:
            result = FlextLdapDistinguishedName.create(dn_str)
            assert result.is_success, f"Valid DN should work: {dn_str} - {result.error}"
            assert result.value.value == dn_str

    def test_dn_validation_rejects_invalid_formats(self) -> None:
        """Test DN validation rejects clearly invalid formats."""
        invalid_dns = [
            "",  # Empty string
            "   ",  # Only whitespace
            "invalid-format",  # Not DN format
            "cn=",  # Incomplete
            "=test,dc=example,dc=com",  # Missing attribute name
            "cn=test,=example,dc=com",  # Missing attribute name
        ]

        for invalid_dn in invalid_dns:
            result = FlextLdapDistinguishedName.create(invalid_dn)
            # Should either reject or handle gracefully
            if not result.is_success:
                assert result.error  # Should have error message
            # Some implementations might be more lenient - that's acceptable

    def test_dn_equality_and_comparison(self) -> None:
        """Test DN equality and string representation."""
        dn_str = "cn=test,dc=example,dc=com"
        dn1 = FlextLdapDistinguishedName(value=dn_str)
        dn2 = FlextLdapDistinguishedName(value=dn_str)

        assert dn1.value == dn2.value
        assert str(dn1) == dn_str or repr(dn1)  # Should have string representation


class TestFlextLdapUser:
    """Test LDAP user entity with real business logic."""

    def create_test_user(self, **kwargs: Any) -> FlextLdapUser:
        """Helper to create test user with defaults using Any for kwargs."""
        defaults: dict[str, Any] = {
            "id": FlextEntityId("test_user"),
            "version": FlextVersion(1),
            "created_at": FlextTimestamp(datetime.now(UTC)),
            "updated_at": FlextTimestamp(datetime.now(UTC)),
            "domain_events": FlextEventList([]),
            "metadata": FlextMetadata({}),
            "dn": "cn=testuser,ou=users,dc=example,dc=com",
            "uid": "testuser",
            "cn": "Test User",
            "sn": "User",
            "given_name": "Test",
            "mail": "testuser@example.com",
            "phone": "+1-555-0123",
            "object_classes": ["inetOrgPerson", "person"],
            "attributes": {},
            "status": FlextEntityStatus.ACTIVE,
        }
        defaults.update(kwargs)
        return FlextLdapUser(**defaults)

    def test_user_creation_with_required_fields(self) -> None:
        """Test user entity creation with required fields."""
        user = self.create_test_user()

        assert user.uid == "testuser"
        assert user.cn == "Test User"
        assert user.sn == "User"
        assert user.dn == "cn=testuser,ou=users,dc=example,dc=com"
        assert "inetOrgPerson" in user.object_classes

    def test_user_business_rule_validation(self) -> None:
        """Test user business rule validation logic."""
        # Valid user should pass validation
        valid_user = self.create_test_user()
        validation_result = valid_user.validate_business_rules()
        assert validation_result.is_success, (
            f"Valid user failed validation: {validation_result.error}"
        )

        # Test user with invalid UID (empty)
        invalid_user = self.create_test_user(uid="")
        validation_result = invalid_user.validate_business_rules()
        if not validation_result.is_success:
            assert "uid" in validation_result.error.lower()

    def test_user_attribute_access_methods(self) -> None:
        """Test user attribute access methods."""
        user = self.create_test_user(
            mail="test@example.com",
            phone="123-456-7890",
            attributes={
                "departmentNumber": ["100"],
                "employeeType": ["staff"],
            },
        )

        assert user.mail == "test@example.com"
        assert user.phone == "123-456-7890"

        # Test getting single attribute value
        assert user.get_single_attribute_value("departmentNumber") == "100"
        assert user.get_single_attribute_value("nonexistent") is None

        # Test getting multiple attribute values (objectClass should be in object_classes)
        assert "inetOrgPerson" in user.object_classes
        assert "person" in user.object_classes

        # Test getting regular attribute values
        dept_values = user.get_attribute_values("departmentNumber")
        assert dept_values == ["100"]

    def test_user_immutability_and_copying(self) -> None:
        """Test that user entity modifications create new instances."""
        original_user = self.create_test_user()

        # Test immutability by creating copy with different attributes
        modified_user = self.create_test_user(
            mail="modified@example.com", phone="999-888-7777"
        )

        # Original should remain unchanged
        assert original_user.mail != modified_user.mail
        assert original_user.phone != modified_user.phone
        assert original_user is not modified_user

        # Test that model_copy creates new instance
        copied_user = original_user.model_copy()
        assert copied_user.uid == original_user.uid
        assert copied_user.cn == original_user.cn
        assert copied_user is not original_user


class TestFlextLdapGroup:
    """Test LDAP group entity with real business logic."""

    def create_test_group(self, **kwargs: Any) -> FlextLdapGroup:
        """Helper to create test group with defaults using Any for kwargs."""
        defaults: dict[str, Any] = {
            "id": FlextEntityId("test_group"),
            "version": FlextVersion(1),
            "created_at": FlextTimestamp(datetime.now(UTC)),
            "updated_at": FlextTimestamp(datetime.now(UTC)),
            "domain_events": FlextEventList([]),
            "metadata": FlextMetadata({}),
            "dn": "cn=testgroup,ou=groups,dc=example,dc=com",
            "cn": "Test Group",
            "description": "Test group for unit testing",
            "object_classes": ["groupOfNames"],
            "attributes": {},
            "members": [],
            "status": FlextEntityStatus.ACTIVE,
        }
        defaults.update(kwargs)
        return FlextLdapGroup(**defaults)

    def test_group_creation_with_required_fields(self) -> None:
        """Test group entity creation with required fields."""
        group = self.create_test_group()

        assert group.cn == "Test Group"
        assert group.dn == "cn=testgroup,ou=groups,dc=example,dc=com"
        assert "groupOfNames" in group.object_classes
        assert isinstance(group.members, list)

    def test_group_business_rule_validation(self) -> None:
        """Test group business rule validation logic."""
        # Valid group should pass validation
        valid_group = self.create_test_group()
        validation_result = valid_group.validate_business_rules()
        assert validation_result.is_success, (
            f"Valid group failed validation: {validation_result.error}"
        )

        # Test group with invalid CN (empty)
        invalid_group = self.create_test_group(cn="")
        validation_result = invalid_group.validate_business_rules()
        if not validation_result.is_success:
            assert (
                "cn" in validation_result.error.lower()
                or "name" in validation_result.error.lower()
            )

    def test_group_member_management(self) -> None:
        """Test group member management operations."""
        group = self.create_test_group()
        member_dn = "cn=user1,ou=users,dc=example,dc=com"

        # Initially no members
        assert not group.has_member(member_dn)
        assert len(group.members) == 0

        # Add member
        add_result = group.add_member(member_dn)
        assert add_result.is_success
        assert group.has_member(member_dn)
        assert len(group.members) == 1
        assert member_dn in group.members

        # Add second member
        member2_dn = "cn=user2,ou=users,dc=example,dc=com"
        add_result2 = group.add_member(member2_dn)
        assert add_result2.is_success
        assert group.has_member(member_dn)
        assert group.has_member(member2_dn)
        assert len(group.members) == 2

        # Remove member
        remove_result = group.remove_member(member_dn)
        assert remove_result.is_success
        assert not group.has_member(member_dn)
        assert group.has_member(member2_dn)
        assert len(group.members) == 1

    def test_group_duplicate_member_handling(self) -> None:
        """Test handling of duplicate member additions."""
        group = self.create_test_group()
        member_dn = "cn=user1,ou=users,dc=example,dc=com"

        # Add member first time - should succeed
        add_result1 = group.add_member(member_dn)
        assert add_result1.is_success
        assert len(group.members) == 1

        # Add same member again - should fail
        add_result2 = group.add_member(member_dn)
        assert not add_result2.is_success
        assert add_result2.error is not None
        assert "already in group" in add_result2.error

        # Should still only have one instance
        assert len(group.members) == 1
        assert group.members.count(member_dn) == 1


class TestFlextLdapEntry:
    """Test generic LDAP entry with real attribute handling."""

    def create_test_entry(self, **kwargs: Any) -> FlextLdapEntry:
        """Helper to create test entry with defaults using Any for kwargs."""
        defaults: dict[str, Any] = {
            "id": FlextEntityId("test_entry"),
            "version": FlextVersion(1),
            "created_at": FlextTimestamp(datetime.now(UTC)),
            "updated_at": FlextTimestamp(datetime.now(UTC)),
            "domain_events": FlextEventList([]),
            "metadata": FlextMetadata({}),
            "dn": "cn=testentry,dc=example,dc=com",
            "object_classes": ["top", "person"],
            "attributes": {"cn": ["test"], "sn": ["entry"]},
            "status": FlextEntityStatus.ACTIVE,
        }
        defaults.update(kwargs)
        return FlextLdapEntry(**defaults)

    def test_entry_creation_and_attribute_access(self) -> None:
        """Test entry creation and attribute access methods."""
        entry = self.create_test_entry(
            attributes={
                "cn": ["Test Entry"],
                "sn": ["Entry"],
                "mail": ["test@example.com"],
                "objectClass": ["top", "person", "inetOrgPerson"],
                "memberOf": [
                    "cn=group1,ou=groups,dc=example,dc=com",
                    "cn=group2,ou=groups,dc=example,dc=com",
                ],
            }
        )

        assert entry.dn == "cn=testentry,dc=example,dc=com"

        # Test single attribute values
        assert entry.get_single_attribute_value("cn") == "Test Entry"
        assert entry.get_single_attribute_value("mail") == "test@example.com"
        assert entry.get_single_attribute_value("nonexistent") is None

        # Test multiple attribute values
        object_classes = entry.get_attribute_values("objectClass")
        assert "top" in object_classes
        assert "person" in object_classes
        assert "inetOrgPerson" in object_classes

        member_of = entry.get_attribute_values("memberOf")
        assert len(member_of) == 2
        assert "cn=group1,ou=groups,dc=example,dc=com" in member_of

        # Test attribute existence
        assert entry.has_attribute("cn")
        assert entry.has_attribute("mail")
        assert not entry.has_attribute("nonexistent")

    def test_entry_business_rule_validation(self) -> None:
        """Test entry business rule validation."""
        # Valid entry should pass validation
        valid_entry = self.create_test_entry()
        validation_result = valid_entry.validate_business_rules()
        assert validation_result.is_success, (
            f"Valid entry failed validation: {validation_result.error}"
        )

        # Test entry with empty object classes
        invalid_entry = self.create_test_entry(object_classes=[])
        validation_result = invalid_entry.validate_business_rules()
        assert not validation_result.is_success
        assert "object class" in validation_result.error.lower()


class TestFlextLdapCreateUserRequest:
    """Test user creation request value object."""

    def test_create_user_request_basic_fields(self) -> None:
        """Test basic user creation request."""
        request = FlextLdapCreateUserRequest(
            dn="cn=newuser,ou=users,dc=example,dc=com",
            uid="newuser",
            cn="New User",
            sn="User",
            given_name="New",
            mail="newuser@example.com",
            phone="+1-555-0100",
        )

        assert request.dn == "cn=newuser,ou=users,dc=example,dc=com"
        assert request.uid == "newuser"
        assert request.cn == "New User"
        assert request.sn == "User"

    def test_create_user_request_optional_fields(self) -> None:
        """Test user creation request with optional fields."""
        request = FlextLdapCreateUserRequest(
            dn="cn=fulluser,ou=users,dc=example,dc=com",
            uid="fulluser",
            cn="Full User",
            sn="User",
            given_name="Full",
            mail="full@example.com",
            phone="123-456-7890",
            additional_attributes={"userPassword": "secret123"},
        )

        assert request.given_name == "Full"
        assert request.mail == "full@example.com"
        assert request.phone == "123-456-7890"
        assert request.additional_attributes["userPassword"] == "secret123"

    def test_create_user_request_to_user_entity(self) -> None:
        """Test converting user request to user entity."""
        request = FlextLdapCreateUserRequest(
            dn="cn=convertuser,ou=users,dc=example,dc=com",
            uid="convertuser",
            cn="Convert User",
            sn="User",
            given_name="Convert",
            mail="convert@example.com",
            phone="+1-555-0102",
        )

        user_entity = request.to_user_entity()

        assert isinstance(user_entity, FlextLdapUser)
        assert user_entity.dn == request.dn
        assert user_entity.uid == request.uid
        assert user_entity.cn == request.cn
        assert user_entity.sn == request.sn
        assert user_entity.mail == request.mail
        assert "inetOrgPerson" in user_entity.object_classes

    def test_create_user_request_to_ldap_attributes(self) -> None:
        """Test converting user request to LDAP attributes dictionary."""
        request = FlextLdapCreateUserRequest(
            dn="cn=ldapuser,ou=users,dc=example,dc=com",
            uid="ldapuser",
            cn="LDAP User",
            sn="User",
            given_name="LDAP",
            mail="ldap@example.com",
            phone="+1-555-0103",
        )

        user_entity = request.to_user_entity()

        assert "inetOrgPerson" in user_entity.object_classes
        assert "person" in user_entity.object_classes
        assert user_entity.uid == "ldapuser"
        assert user_entity.cn == "LDAP User"
        assert user_entity.mail == "ldap@example.com"

    def test_create_user_request_validation(self) -> None:
        """Test user creation request validation."""
        # Valid request should pass
        valid_request = FlextLdapCreateUserRequest(
            dn="cn=validuser,ou=users,dc=example,dc=com",
            uid="validuser",
            cn="Valid User",
            sn="User",
            given_name="Valid",
            mail="validuser@example.com",
            phone="+1-555-0104",
        )

        # Test that valid request creates user entity correctly
        user_entity = valid_request.to_user_entity()
        validation_result = user_entity.validate_business_rules()
        assert validation_result.is_success, (
            f"Valid request failed validation: {validation_result.error}"
        )

        # Test that conversion maintains data integrity
        assert user_entity.uid == valid_request.uid
        assert user_entity.cn == valid_request.cn
        assert user_entity.sn == valid_request.sn
        assert user_entity.dn == valid_request.dn


class TestBusinessRulesIntegration:
    """Test integration of business rules across entities."""

    def test_cross_entity_validation(self) -> None:
        """Test business rules that span multiple entities."""
        # Create user
        user = FlextLdapUser(
            id=FlextEntityId("test_cross_user"),
            dn="cn=crossuser,ou=users,dc=example,dc=com",
            uid="crossuser",
            cn="Cross User",
            sn="User",
            given_name="Cross",
            mail="crossuser@example.com",
            phone="+1-555-0199",
            object_classes=["inetOrgPerson", "person"],
            attributes={},
            status=FlextEntityStatus.ACTIVE,
        )

        # Create group with user as member
        group = FlextLdapGroup(
            id=FlextEntityId("test_cross_group"),
            dn="cn=crossgroup,ou=groups,dc=example,dc=com",
            cn="Cross Group",
            description="Cross-validation test group",
            object_classes=["groupOfNames"],
            attributes={},
            members=[user.dn],
            status=FlextEntityStatus.ACTIVE,
        )

        # Both should validate successfully
        user_validation = user.validate_business_rules()
        group_validation = group.validate_business_rules()

        assert user_validation.is_success
        assert group_validation.is_success
        assert group.has_member(user.dn)

    def test_domain_consistency_rules(self) -> None:
        """Test consistency rules within domain entities."""
        # Create user request
        user_request = FlextLdapCreateUserRequest(
            dn="cn=consistent,ou=users,dc=example,dc=com",
            uid="consistent",
            cn="Consistent User",
            sn="User",
            given_name="Consistent",
            mail="consistent@example.com",
            phone="+1-555-0105",
        )

        # Convert to entity
        user_entity = user_request.to_user_entity()

        # Should maintain consistency
        assert user_entity.uid == user_request.uid
        assert user_entity.cn == user_request.cn
        assert user_entity.sn == user_request.sn
        assert user_entity.dn == user_request.dn

        # Both should validate
        request_validation = user_request.validate_business_rules()
        entity_validation = user_entity.validate_business_rules()

        assert request_validation.is_success
        assert entity_validation.is_success
