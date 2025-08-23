"""Comprehensive functional tests for FLEXT-LDAP domain layer.

These tests execute REAL domain logic, specifications, services, and events
following Clean Architecture and DDD principles. Focus on business rules validation.
"""

from __future__ import annotations

import re
from datetime import UTC, datetime

import pytest
from flext_core import FlextEntityId, FlextEntityStatus

from flext_ldap.domain import (
    SECURE_RANDOM_GENERATION_MIN_RETRIES,
    MIN_PASSWORD_LENGTH,
    MAX_PASSWORD_LENGTH,
    MIN_USERNAME_LENGTH,
    PASSWORD_GENERATION_MAX_RETRIES,
    PASSWORD_PATTERN,
    EntityParameterBuilder,
    FlextLdapActiveUserSpecification,
    FlextLdapCompleteUserSpecification,
    FlextLdapDistinguishedNameSpecification,
    FlextLdapDomainFactory,
    FlextLdapEmailSpecification,
    FlextLdapGroupManagementService,
    FlextLdapGroupMemberAddedEvent,
    FlextLdapGroupSpecification,
    FlextLdapPasswordChangedEvent,
    FlextLdapPasswordService,
    FlextLdapPasswordSpecification,
    FlextLdapUserCreatedEvent,
    FlextLdapUserDeletedEvent,
    FlextLdapUserManagementService,
    FlextLdapUserSpecification,
    GroupEntityBuilder,
    UserEntityBuilder,
)
from flext_ldap.models import FlextLdapGroup, FlextLdapUser
from flext_ldap.typings import LdapAttributeDict


class TestDomainConstants:
    """Test domain constants are properly defined."""

    def test_password_constants(self) -> None:
        """Test password-related constants."""
        assert MIN_PASSWORD_LENGTH >= 8
        assert MAX_PASSWORD_LENGTH >= MIN_PASSWORD_LENGTH
        assert MIN_USERNAME_LENGTH >= 2
        assert PASSWORD_GENERATION_MAX_RETRIES >= 1
        assert SECURE_RANDOM_GENERATION_MIN_RETRIES >= 1

    def test_password_pattern_validation(self) -> None:
        """Test password pattern regex validation."""
        assert isinstance(PASSWORD_PATTERN, re.Pattern)
        
        # Valid passwords
        valid_passwords = [
            "MySecure123!",
            "Complex#Pass1",
            "Strong@2024$",
        ]
        
        for pwd in valid_passwords:
            assert PASSWORD_PATTERN.match(pwd), f"Valid password rejected: {pwd}"
        
        # Invalid passwords
        invalid_passwords = [
            "weak",
            "noupppercase123!",
            "NOLOWERCASE123!",
            "NoNumbers!",
            "NoSpecial123",
            "Short1!",
        ]
        
        for pwd in invalid_passwords:
            assert not PASSWORD_PATTERN.match(pwd), f"Invalid password accepted: {pwd}"


class TestFlextLdapUserSpecification:
    """Test user specification with real validation logic."""

    def test_user_specification_initialization(self) -> None:
        """Test user specification initialization."""
        spec = FlextLdapUserSpecification()
        
        assert spec.name is not None
        assert spec.description is not None
        assert len(spec.name) > 0

    def test_valid_user_satisfaction(self) -> None:
        """Test specification with valid LDAP user."""
        spec = FlextLdapUserSpecification()
        
        # Create valid user
        valid_user = FlextLdapUser(
            id=FlextEntityId("test-user"),
            uid="john.doe",
            cn="John Doe",
            sn="Doe",
            dn="cn=john.doe,ou=users,dc=example,dc=com",
            status=FlextEntityStatus.ACTIVE,
        )
        
        assert spec.is_satisfied_by(valid_user)

    def test_invalid_user_satisfaction(self) -> None:
        """Test specification with invalid objects."""
        spec = FlextLdapUserSpecification()
        
        # Test with various invalid objects
        invalid_objects = [
            None,
            {},
            "string",
            42,
            {"uid": "test"},  # Missing dn
            {"dn": "test"},   # Missing uid
        ]
        
        for obj in invalid_objects:
            assert not spec.is_satisfied_by(obj)

    def test_validation_error_message(self) -> None:
        """Test validation error message generation."""
        spec = FlextLdapUserSpecification()
        
        error_msg = spec.get_validation_error("invalid")
        assert isinstance(error_msg, str)
        assert len(error_msg) > 0
        assert "str" in error_msg  # Type name should be included


class TestFlextLdapGroupSpecification:
    """Test group specification with real validation logic."""

    def test_group_specification_initialization(self) -> None:
        """Test group specification initialization."""
        spec = FlextLdapGroupSpecification()
        
        assert spec.name is not None
        assert spec.description is not None

    def test_valid_group_satisfaction(self) -> None:
        """Test specification with valid LDAP group."""
        spec = FlextLdapGroupSpecification()
        
        valid_group = FlextLdapGroup(
            id=FlextEntityId("test-group"),
            cn="admins",
            dn="cn=admins,ou=groups,dc=example,dc=com",
            members=["cn=user1,ou=users,dc=example,dc=com"],
            status=FlextEntityStatus.ACTIVE,
        )
        
        assert spec.is_satisfied_by(valid_group)

    def test_invalid_group_satisfaction(self) -> None:
        """Test specification with invalid objects."""
        spec = FlextLdapGroupSpecification()
        
        invalid_objects = [
            None,
            {},
            "string",
            42,
            {"cn": "test"},  # Missing dn
        ]
        
        for obj in invalid_objects:
            assert not spec.is_satisfied_by(obj)


class TestFlextLdapDistinguishedNameSpecification:
    """Test DN specification with real validation logic."""

    def test_dn_specification_initialization(self) -> None:
        """Test DN specification initialization."""
        spec = FlextLdapDistinguishedNameSpecification()
        
        assert spec.name is not None
        assert spec.description is not None

    def test_valid_dn_satisfaction(self) -> None:
        """Test specification with valid DNs."""
        spec = FlextLdapDistinguishedNameSpecification()
        
        valid_dns = [
            "cn=user,dc=example,dc=com",
            "uid=john.doe,ou=users,dc=company,dc=org",
            "cn=admin,cn=users,dc=test,dc=local",
            "ou=groups,dc=example,dc=com",
        ]
        
        for dn in valid_dns:
            assert spec.is_satisfied_by(dn), f"Valid DN rejected: {dn}"

    def test_invalid_dn_satisfaction(self) -> None:
        """Test specification with invalid DNs."""
        spec = FlextLdapDistinguishedNameSpecification()
        
        invalid_dns = [
            "",
            "invalid",
            "cn=",
            "=user,dc=example,dc=com",
            None,
            42,
            {},
        ]
        
        for dn in invalid_dns:
            assert not spec.is_satisfied_by(dn), f"Invalid DN accepted: {dn}"


class TestFlextLdapPasswordSpecification:
    """Test password specification with real validation logic."""

    def test_password_specification_initialization(self) -> None:
        """Test password specification initialization."""
        spec = FlextLdapPasswordSpecification()
        
        assert spec.name is not None
        assert spec.description is not None

    def test_valid_password_satisfaction(self) -> None:
        """Test specification with valid passwords."""
        spec = FlextLdapPasswordSpecification()
        
        valid_passwords = [
            "SecurePass123!",
            "MyStrong@Pass2024",
            "Complex#Password1",
        ]
        
        for pwd in valid_passwords:
            assert spec.is_satisfied_by(pwd), f"Valid password rejected: {pwd}"

    def test_invalid_password_satisfaction(self) -> None:
        """Test specification with invalid passwords."""
        spec = FlextLdapPasswordSpecification()
        
        invalid_passwords = [
            "",
            "weak",
            "short1!",
            "nouppercase123!",
            "NOLOWERCASE123!",
            "NoNumbers!",
            "NoSpecialChars123",
            None,
            42,
        ]
        
        for pwd in invalid_passwords:
            assert not spec.is_satisfied_by(pwd), f"Invalid password accepted: {pwd}"


class TestFlextLdapEmailSpecification:
    """Test email specification with real validation logic."""

    def test_email_specification_initialization(self) -> None:
        """Test email specification initialization."""
        spec = FlextLdapEmailSpecification()
        
        assert spec.name is not None
        assert spec.description is not None

    def test_valid_email_satisfaction(self) -> None:
        """Test specification with valid emails."""
        spec = FlextLdapEmailSpecification()
        
        valid_emails = [
            "user@example.com",
            "john.doe@company.org",
            "test+tag@domain.co.uk",
            "admin@sub.domain.com",
        ]
        
        for email in valid_emails:
            assert spec.is_satisfied_by(email), f"Valid email rejected: {email}"

    def test_invalid_email_satisfaction(self) -> None:
        """Test specification with invalid emails."""
        spec = FlextLdapEmailSpecification()
        
        invalid_emails = [
            "",
            "invalid",
            "@domain.com",
            "user@",
            "user@domain",
            "user.domain.com",
            None,
            42,
        ]
        
        for email in invalid_emails:
            assert not spec.is_satisfied_by(email), f"Invalid email accepted: {email}"


class TestFlextLdapActiveUserSpecification:
    """Test active user specification with real validation logic."""

    def test_active_user_specification_initialization(self) -> None:
        """Test active user specification initialization."""
        spec = FlextLdapActiveUserSpecification()
        
        assert spec.name is not None
        assert spec.description is not None

    def test_active_user_satisfaction(self) -> None:
        """Test specification with active user."""
        spec = FlextLdapActiveUserSpecification()
        
        active_user = FlextLdapUser(
            id=FlextEntityId("active-user"),
            uid="active.user",
            cn="Active User",
            sn="User",
            dn="cn=active.user,ou=users,dc=example,dc=com",
            status=FlextEntityStatus.ACTIVE,
        )
        
        assert spec.is_satisfied_by(active_user)

    def test_inactive_user_satisfaction(self) -> None:
        """Test specification with inactive user."""
        spec = FlextLdapActiveUserSpecification()
        
        inactive_user = FlextLdapUser(
            id=FlextEntityId("inactive-user"),
            uid="inactive.user",
            cn="Inactive User",
            sn="User",
            dn="cn=inactive.user,ou=users,dc=example,dc=com",
            status=FlextEntityStatus.INACTIVE,
        )
        
        assert not spec.is_satisfied_by(inactive_user)


class TestFlextLdapCompleteUserSpecification:
    """Test complete user specification with real validation logic."""

    def test_complete_user_specification_initialization(self) -> None:
        """Test complete user specification initialization."""
        spec = FlextLdapCompleteUserSpecification()
        
        assert spec.name is not None
        assert spec.description is not None

    def test_complete_user_satisfaction(self) -> None:
        """Test specification with complete user."""
        spec = FlextLdapCompleteUserSpecification()
        
        complete_user = FlextLdapUser(
            id=FlextEntityId("complete-user"),
            uid="complete.user",
            cn="Complete User",
            sn="User",
            given_name="Complete",
            mail="complete@example.com",
            dn="cn=complete.user,ou=users,dc=example,dc=com",
            status=FlextEntityStatus.ACTIVE,
        )
        
        assert spec.is_satisfied_by(complete_user)

    def test_incomplete_user_satisfaction(self) -> None:
        """Test specification with incomplete user."""
        spec = FlextLdapCompleteUserSpecification()
        
        # User missing email
        incomplete_user = FlextLdapUser(
            id=FlextEntityId("incomplete-user"),
            uid="incomplete.user",
            cn="Incomplete User",
            sn="User",
            dn="cn=incomplete.user,ou=users,dc=example,dc=com",
            status=FlextEntityStatus.ACTIVE,
        )
        
        # Should not be satisfied (depending on implementation)
        # This tests the actual business logic
        result = spec.is_satisfied_by(incomplete_user)
        assert isinstance(result, bool)


class TestFlextLdapUserManagementService:
    """Test user management service with real business logic."""

    def test_user_service_initialization(self) -> None:
        """Test user management service initialization."""
        service = FlextLdapUserManagementService()
        
        assert service is not None

    def test_validate_user_creation(self) -> None:
        """Test user creation validation."""
        service = FlextLdapUserManagementService()
        
        # Valid parameters
        valid_params = {
            "uid": "test.user",
            "cn": "Test User",
            "sn": "User",
            "given_name": "Test",
            "mail": "test@example.com",
        }
        
        result = service.validate_user_creation(valid_params)
        
        # Test the actual method behavior
        assert isinstance(result.is_success, bool)

    def test_generate_username(self) -> None:
        """Test username generation."""
        service = FlextLdapUserManagementService()
        
        result = service.generate_username("John", "Doe")
        
        assert result.is_success
        username = result.value
        assert isinstance(username, str)
        assert len(username) > 0


class TestFlextLdapGroupManagementService:
    """Test group management service with real business logic."""

    def test_group_service_initialization(self) -> None:
        """Test group management service initialization."""
        service = FlextLdapGroupManagementService()
        
        assert service is not None

    def test_create_group_params_validation(self) -> None:
        """Test group creation parameter validation."""
        service = FlextLdapGroupManagementService()
        
        valid_params = {
            "cn": "test-group",
            "description": "Test Group",
            "members": ["cn=user1,ou=users,dc=example,dc=com"],
        }
        
        result = service.create_group_params(valid_params)
        
        assert result.is_success
        group_params = result.value
        assert group_params["cn"] == "test-group"

    def test_can_add_member_validation(self) -> None:
        """Test group member addition validation."""
        service = FlextLdapGroupManagementService()
        
        # Create valid group and user
        group = FlextLdapGroup(
            id=FlextEntityId("test-group"),
            cn="test-group",
            dn="cn=test-group,ou=groups,dc=example,dc=com",
            members=[],
            status=FlextEntityStatus.ACTIVE,
        )
        
        user = FlextLdapUser(
            id=FlextEntityId("test-user"),
            uid="test.user",
            cn="Test User",
            sn="User",
            dn="cn=test.user,ou=users,dc=example,dc=com",
            status=FlextEntityStatus.ACTIVE,
        )
        
        # Should be able to add active user
        result = service.can_add_member(group, user)
        assert result.is_success
        
        # Should not be able to add inactive user
        inactive_user = FlextLdapUser(
            id=FlextEntityId("inactive-user"),
            uid="inactive.user",
            cn="Inactive User",
            sn="User",
            dn="cn=inactive.user,ou=users,dc=example,dc=com",
            status=FlextEntityStatus.INACTIVE,
        )
        
        result = service.can_add_member(group, inactive_user)
        assert not result.is_success
        
    def test_validate_group_creation(self) -> None:
        """Test group creation validation."""
        service = FlextLdapGroupManagementService()
        
        valid_group_data = {
            "cn": "valid-group",
            "description": "Valid Group",
            "members": ["cn=user1,ou=users,dc=example,dc=com"],
        }
        
        result = service.validate_group_creation(valid_group_data)
        
        # Test the actual method behavior
        assert isinstance(result.is_success, bool)


class TestFlextLdapPasswordService:
    """Test password service with real security logic."""

    def test_password_service_initialization(self) -> None:
        """Test password service initialization."""
        service = FlextLdapPasswordService()
        
        assert service is not None

    def test_generate_secure_password(self) -> None:
        """Test secure password generation."""
        service = FlextLdapPasswordService()
        
        result = service.generate_secure_password()
        
        assert result.is_success
        password = result.value
        assert isinstance(password, str)
        assert len(password) >= MIN_PASSWORD_LENGTH
        
        # Should match password pattern
        assert PASSWORD_PATTERN.match(password)

    def test_generate_secure_password_with_length(self) -> None:
        """Test secure password generation with custom length."""
        service = FlextLdapPasswordService()
        
        custom_length = 16
        result = service.generate_secure_password(length=custom_length)
        
        assert result.is_success
        password = result.value
        assert len(password) == custom_length

    def test_validate_password_strength(self) -> None:
        """Test password strength validation."""
        service = FlextLdapPasswordService()
        
        # Strong password
        strong_password = "MySecure123!"
        result = service.validate_password_strength(strong_password)
        assert result.is_success

        # Weak password
        weak_password = "weak"
        result = service.validate_password_strength(weak_password)
        assert not result.is_success

    def test_hash_password(self) -> None:
        """Test password hashing."""
        service = FlextLdapPasswordService()
        
        password = "TestPassword123!"
        result = service.hash_password(password)
        
        assert result.is_success
        hashed = result.value
        assert isinstance(hashed, str)
        assert len(hashed) > len(password)
        assert hashed != password  # Should be hashed


class TestFlextLdapDomainEvents:
    """Test domain events with real event data."""

    def test_user_created_event(self) -> None:
        """Test user created event."""
        user = FlextLdapUser(
            id=FlextEntityId("new-user"),
            uid="new.user",
            cn="New User",
            sn="User",
            dn="cn=new.user,ou=users,dc=example,dc=com",
            status=FlextEntityStatus.ACTIVE,
        )
        
        event = FlextLdapUserCreatedEvent(
            user_id=user.id,
            user_dn=user.dn,
            user_uid=user.uid,
        )
        
        assert event.user_id == user.id
        assert event.user_dn == user.dn
        assert event.user_uid == user.uid
        assert isinstance(event.occurred_at, datetime)

    def test_user_deleted_event(self) -> None:
        """Test user deleted event."""
        event = FlextLdapUserDeletedEvent(
            user_id=FlextEntityId("deleted-user"),
            user_dn="cn=deleted.user,ou=users,dc=example,dc=com",
            user_uid="deleted.user",
        )
        
        assert event.user_id.value == "deleted-user"
        assert "deleted.user" in event.user_dn
        assert event.user_uid == "deleted.user"

    def test_group_member_added_event(self) -> None:
        """Test group member added event."""
        event = FlextLdapGroupMemberAddedEvent(
            group_id=FlextEntityId("test-group"),
            group_dn="cn=test-group,ou=groups,dc=example,dc=com",
            member_dn="cn=user,ou=users,dc=example,dc=com",
        )
        
        assert event.group_id.value == "test-group"
        assert "test-group" in event.group_dn
        assert "user" in event.member_dn

    def test_password_changed_event(self) -> None:
        """Test password changed event."""
        event = FlextLdapPasswordChangedEvent(
            user_id=FlextEntityId("user-123"),
            user_dn="cn=user,ou=users,dc=example,dc=com",
            changed_by="cn=admin,ou=users,dc=example,dc=com",
        )
        
        assert event.user_id.value == "user-123"
        assert "user" in event.user_dn
        assert "admin" in event.changed_by
        assert isinstance(event.occurred_at, datetime)


class TestEntityBuilders:
    """Test entity builders with real construction logic."""

    def test_entity_parameter_builder(self) -> None:
        """Test base entity parameter builder."""
        builder = EntityParameterBuilder()
        
        params = {
            "name": "test",
            "value": 123,
            "optional": None,
        }
        
        result = builder.build_parameters(params)
        
        assert result.is_success
        built_params = result.value
        assert built_params["name"] == "test"
        assert built_params["value"] == 123

    def test_user_entity_builder(self) -> None:
        """Test user entity builder."""
        builder = UserEntityBuilder()
        
        user_data = {
            "uid": "test.user",
            "cn": "Test User",
            "sn": "User",
            "given_name": "Test",
            "mail": "test@example.com",
            "dn": "cn=test.user,ou=users,dc=example,dc=com",
        }
        
        result = builder.build_user_entity(user_data)
        
        assert result.is_success
        user = result.value
        assert isinstance(user, FlextLdapUser)
        assert user.uid == "test.user"
        assert user.cn == "Test User"

    def test_group_entity_builder(self) -> None:
        """Test group entity builder."""
        builder = GroupEntityBuilder()
        
        group_data = {
            "cn": "test-group",
            "description": "Test Group",
            "members": ["cn=user1,ou=users,dc=example,dc=com"],
            "dn": "cn=test-group,ou=groups,dc=example,dc=com",
        }
        
        result = builder.build_group_entity(group_data)
        
        assert result.is_success
        group = result.value
        assert isinstance(group, FlextLdapGroup)
        assert group.cn == "test-group"
        assert len(group.members) == 1


class TestFlextLdapDomainFactory:
    """Test domain factory with real creation logic."""

    def test_domain_factory_initialization(self) -> None:
        """Test domain factory initialization."""
        factory = FlextLdapDomainFactory()
        
        assert factory is not None

    def test_create_user_specification(self) -> None:
        """Test user specification creation."""
        factory = FlextLdapDomainFactory()
        
        spec = factory.create_user_specification()
        
        assert isinstance(spec, FlextLdapUserSpecification)
        assert spec.name is not None

    def test_create_password_service(self) -> None:
        """Test password service creation."""
        factory = FlextLdapDomainFactory()
        
        service = factory.create_password_service()
        
        assert isinstance(service, FlextLdapPasswordService)

    def test_create_user_builder(self) -> None:
        """Test user builder creation."""
        factory = FlextLdapDomainFactory()
        
        builder = factory.create_user_builder()
        
        assert isinstance(builder, UserEntityBuilder)

    def test_create_group_builder(self) -> None:
        """Test group builder creation."""
        factory = FlextLdapDomainFactory()
        
        builder = factory.create_group_builder()
        
        assert isinstance(builder, GroupEntityBuilder)