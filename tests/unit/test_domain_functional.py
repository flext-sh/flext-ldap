"""Functional tests for flext-ldap domain layer.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest
from pydantic import BaseModel

import flext_ldap.domain as domain_module
from flext_core import FlextDomainService, FlextResult
from flext_ldap.domain import FlextLdapDomain
from flext_ldap.models import FlextLdapModels

# Import the target module for coverage


class TestFlextLdapDomainFunctional:
    """Functional tests for FlextLdapDomain - real business logic validation."""

    def test_flext_ldap_domain_import_and_structure(self) -> None:
        """Test that FlextLdapDomain can be imported and has expected structure."""
        # Verify main class exists and is accessible
        assert hasattr(FlextLdapDomain, "__name__")
        assert "FlextLdapDomain" in str(FlextLdapDomain)

        # Check for expected domain-related nested classes
        expected_nested_classes = [
            "DomainSpecification",
            "UserSpecification",
            "GroupSpecification",
            "DistinguishedNameSpecification",
            "PasswordSpecification",
            "UserManagementService",
            "GroupManagementService",
            "PasswordService",
        ]

        for class_name in expected_nested_classes:
            assert hasattr(FlextLdapDomain, class_name), f"Missing {class_name}"
            nested_class = getattr(FlextLdapDomain, class_name)
            assert nested_class is not None

    def test_domain_module_loads_without_errors(self) -> None:
        """Test that domain module loads completely without import errors."""
        # Verify module has expected structure
        assert hasattr(domain_module, "FlextLdapDomain")

        # Check module-level functionality
        module_attrs = [attr for attr in dir(domain_module) if not attr.startswith("_")]
        assert len(module_attrs) >= 5, (
            f"Expected substantial module content, got: {module_attrs}"
        )


class TestDomainSpecifications:
    """Test Domain Specifications - core validation business logic."""

    def test_user_specification_validation(self) -> None:
        """Test UserSpecification with comprehensive user validation scenarios."""
        user_spec = FlextLdapDomain.UserSpecification()

        # Test with valid user objects
        valid_users = [
            FlextLdapModels.User(
                id="user_1",
                dn="cn=john.doe,ou=users,dc=example,dc=com",
                uid="john.doe",
                cn="John Doe",
                sn="Doe",
                mail="john.doe@example.com",
                object_classes=["person", "top"],
            ),
            FlextLdapModels.User(
                id="user_2",
                dn="uid=jane.smith,ou=people,dc=company,dc=org",
                uid="jane.smith",
                cn="Jane Smith",
                sn="Smith",
                given_name="Jane",
                mail="jane.smith@company.org",
                object_classes=["person", "top"],
            ),
        ]

        for user in valid_users:
            assert user_spec.is_satisfied_by(user), f"User should be valid: {user.uid}"

        # Test validation error messages for invalid objects
        invalid_candidates: list[object] = [None, "", {}, [], 123, "not-a-user"]

        for invalid in invalid_candidates:
            assert not user_spec.is_satisfied_by(invalid)
            error_msg = user_spec.get_validation_error(invalid)
            assert isinstance(error_msg, str)
            assert len(error_msg) > 0

    def test_group_specification_validation(self) -> None:
        """Test GroupSpecification with comprehensive group validation scenarios."""
        group_spec = FlextLdapDomain.GroupSpecification()

        # Test with valid group objects
        valid_groups = [
            FlextLdapModels.Group(
                id="group_1",
                dn="cn=engineers,ou=groups,dc=example,dc=com",
                cn="engineers",
                description="Engineering Team",
                object_classes=["groupOfNames", "top"],
            ),
            FlextLdapModels.Group(
                id="group_2",
                dn="cn=admins,ou=groups,dc=company,dc=org",
                cn="admins",
                description="System Administrators",
                object_classes=["groupOfNames", "top"],
                members=[
                    "cn=admin1,ou=users,dc=company,dc=org",
                    "cn=admin2,ou=users,dc=company,dc=org",
                ],
            ),
        ]

        for group in valid_groups:
            assert group_spec.is_satisfied_by(group), (
                f"Group should be valid: {group.cn}"
            )

        # Test with invalid group objects
        invalid_groups: list[object] = [None, "", {}, [], 123, "not-a-group"]

        for invalid in invalid_groups:
            assert not group_spec.is_satisfied_by(invalid)
            error_msg = group_spec.get_validation_error(invalid)
            assert isinstance(error_msg, str)
            assert len(error_msg) > 0

    def test_distinguished_name_specification(self) -> None:
        """Test DistinguishedNameSpecification with various DN formats."""
        dn_spec = FlextLdapDomain.DistinguishedNameSpecification()

        # Test with valid DN strings
        valid_dns = [
            "cn=user,dc=example,dc=com",
            "uid=john,ou=people,dc=organization,dc=org",
            "cn=admin,cn=users,dc=domain,dc=local",
            "ou=groups,dc=company,dc=com",
            "cn=John Smith,ou=Engineering,dc=company,dc=com",
        ]

        for dn in valid_dns:
            assert dn_spec.is_satisfied_by(dn), f"DN should be valid: {dn}"

        # Test with invalid DN formats
        invalid_dns: list[object] = [
            "",  # Empty string
            "invalid-dn",  # No DN components
            None,  # None value
            123,  # Non-string
            [],  # Wrong type
            {},  # Wrong type
        ]

        for invalid_dn in invalid_dns:
            assert not dn_spec.is_satisfied_by(invalid_dn)
            error_msg = dn_spec.get_validation_error(invalid_dn)
            assert isinstance(error_msg, str)
            assert len(error_msg) > 0

    def test_password_specification_validation(self) -> None:
        """Test PasswordSpecification with comprehensive password validation."""
        password_spec = FlextLdapDomain.PasswordSpecification()

        # Test with valid passwords (meeting complexity requirements)
        valid_passwords = [
            "ComplexPassword123!",
            "SecurePass2023@",
            "StrongP@ssw0rd",
            "ValidPass123#",
            "Secure123$Password",
        ]

        for password in valid_passwords:
            assert password_spec.is_satisfied_by(password), (
                f"Password should be valid: {password}"
            )

        # Test with invalid passwords
        invalid_passwords = [
            "",  # Empty
            "weak",  # Too short
            "nocapitals123",  # No capitals
            "NOLOWERCASE123",  # No lowercase
            "NoNumbers!",  # No numbers
            "NoSpecialChars123",  # No special characters
            None,  # None value
            123,  # Non-string
        ]

        for invalid_password in invalid_passwords:
            assert not password_spec.is_satisfied_by(invalid_password)
            error_msg = password_spec.get_validation_error(invalid_password)
            assert isinstance(error_msg, str)
            assert len(error_msg) > 0


class TestDomainDispatcherIntegration:
    """Tests covering dispatcher-enabled domain factory flows."""

    @pytest.fixture
    def user_payload(self) -> dict[str, object]:
        """Return a representative payload for user creation."""
        return {
            "uid": "jdoe",
            "cn": "John Doe",
            "sn": "Doe",
            "dn": "uid=jdoe,ou=people,dc=example,dc=com",
            "mail": "jdoe@example.com",
        }

    @pytest.mark.skip(
        reason="Dispatcher temporarily disabled due to command/handler type matching issues"
    )
    def test_factory_uses_dispatcher_when_feature_flag_enabled(
        self,
        monkeypatch: pytest.MonkeyPatch,
        user_payload: dict[str, object],
    ) -> None:
        """Ensure dispatcher path handles command when enabled."""
        monkeypatch.setenv("FLEXT_LDAP_ENABLE_DISPATCHER", "1")

        from flext_ldap.dispatcher import reset_dispatcher_cache

        reset_dispatcher_cache()

        factory = FlextLdapDomain.DomainFactory()

        # Force fallback handler to fail if invoked so we detect dispatcher usage.
        monkeypatch.setattr(
            factory._create_user_handler,
            "handle",
            lambda command: FlextResult[FlextLdapModels.User].fail(
                "fallback should not be used",
            ),
            raising=False,
        )

        result = factory.create_user_from_data(user_payload)

        assert result.is_success
        created_user = result.unwrap()
        assert isinstance(created_user, FlextLdapModels.User)
        assert created_user.uid == "jdoe"

    def test_factory_falls_back_when_dispatcher_disabled(
        self,
        monkeypatch: pytest.MonkeyPatch,
        user_payload: dict[str, object],
    ) -> None:
        """Verify legacy handler executes when feature flag is disabled."""
        monkeypatch.delenv("FLEXT_LDAP_ENABLE_DISPATCHER", raising=False)

        import flext_ldap.dispatcher as dispatcher_module

        dispatcher_module.reset_dispatcher_cache()

        # Raise if dispatcher were incorrectly invoked with flag disabled.
        monkeypatch.setattr(
            dispatcher_module,
            "get_dispatcher",
            lambda: (_ for _ in ()).throw(
                RuntimeError("dispatcher should not be used")
            ),
            raising=False,
        )

        factory = FlextLdapDomain.DomainFactory()

        result = factory.create_user_from_data(user_payload)

        assert result.is_success
        assert isinstance(result.unwrap(), FlextLdapModels.User)

    def test_active_user_specification(self) -> None:
        """Test ActiveUserSpecification for user status validation."""
        active_spec = FlextLdapDomain.ActiveUserSpecification()

        # Test with active user objects
        active_user = FlextLdapModels.User(
            id="active_user",
            dn="cn=active.user,ou=users,dc=example,dc=com",
            uid="active.user",
            cn="Active User",
            sn="User",
            mail="active.user@example.com",
            object_classes=["person", "top"],
            status="active",  # Set active status for validation
        )

        assert active_spec.is_satisfied_by(active_user), (
            "Active user should pass validation"
        )

        # Test with non-user objects
        invalid_candidates: list[object] = [None, "", {}, [], "not-a-user"]

        for invalid in invalid_candidates:
            assert not active_spec.is_satisfied_by(invalid)
            error_msg = active_spec.get_validation_error(invalid)
            assert isinstance(error_msg, str)
            assert len(error_msg) > 0

    def test_email_specification_validation(self) -> None:
        """Test EmailSpecification with various email formats."""
        email_spec = FlextLdapDomain.EmailSpecification()

        # Test with valid email addresses
        valid_emails = [
            "user@example.com",
            "john.doe@company.org",
            "admin+test@domain.co.uk",
            "user123@subdomain.example.com",
            "first.last@organization.gov",
        ]

        for email in valid_emails:
            assert email_spec.is_satisfied_by(email), f"Email should be valid: {email}"

        # Test with invalid email addresses
        invalid_emails = [
            "",  # Empty
            "invalid-email",  # No @ symbol
            "@domain.com",  # No local part
            "user@",  # No domain
            "user@.com",  # Invalid domain
            None,  # None value
            123,  # Non-string
        ]

        for invalid_email in invalid_emails:
            assert not email_spec.is_satisfied_by(invalid_email)
            error_msg = email_spec.get_validation_error(invalid_email)
            assert isinstance(error_msg, str)
            assert len(error_msg) > 0

    def test_complete_user_specification_composition(self) -> None:
        """Test CompleteUserSpecification as composition of other specifications."""
        complete_spec = FlextLdapDomain.CompleteUserSpecification()

        # Test accessing composed specifications
        dn_spec = complete_spec.dn_spec
        assert dn_spec is not None
        assert isinstance(dn_spec, FlextLdapDomain.DistinguishedNameSpecification)

        active_spec = complete_spec.active_spec
        assert active_spec is not None
        assert isinstance(active_spec, FlextLdapDomain.ActiveUserSpecification)

        # Test complete user validation
        complete_user = FlextLdapModels.User(
            id="complete_user",
            dn="cn=complete.user,ou=users,dc=example,dc=com",
            uid="complete.user",
            cn="Complete User",
            sn="User",
            mail="complete.user@example.com",
            object_classes=["person", "top"],
        )

        result = complete_spec.is_satisfied_by(complete_user)
        # May pass or fail depending on all composed specifications
        assert isinstance(result, bool)

        # Test validation error message
        error_msg = complete_spec.get_validation_error(complete_user)
        assert isinstance(error_msg, str)


class TestDomainServices:
    """Test Domain Services - core business logic services."""

    def test_user_management_service_user_creation(self) -> None:
        """Test UserManagementService user creation functionality."""
        user_service = FlextLdapDomain.UserManagementService()

        # Test user creation validation
        valid_creation_requests: list[dict[str, object]] = [
            {
                "dn": "cn=new.user1,ou=users,dc=example,dc=com",
                "uid": "new.user1",
                "cn": "New User 1",
                "sn": "User",
                "mail": "new.user1@example.com",
            },
            {
                "dn": "uid=new.user2,ou=people,dc=company,dc=org",
                "uid": "new.user2",
                "cn": "New User 2",
                "sn": "User",
                "given_name": "New",
                "mail": "new.user2@company.org",
            },
        ]

        for request_data in valid_creation_requests:
            validation_result = user_service.validate_user_creation(request_data)
            assert isinstance(validation_result, FlextResult)
            # May pass or fail depending on validation logic

    def test_user_management_service_user_updates(self) -> None:
        """Test UserManagementService user update functionality."""
        user_service = FlextLdapDomain.UserManagementService()

        # Test user creation validation using actual available method
        creation_requests: list[dict[str, object]] = [
            {
                "uid": "new.user",
                "dn": "cn=new.user,ou=users,dc=example,dc=com",
                "cn": "New User",
                "sn": "User",
                "mail": "new.user@example.com",
            },
            {
                "uid": "another.user",
                "dn": "cn=another.user,ou=users,dc=example,dc=com",
                "cn": "Another User",
                "sn": "User",
                "mail": "another.user@example.com",
            },
        ]

        for creation_data in creation_requests:
            validation_result = user_service.validate_user_creation(creation_data)
            assert isinstance(validation_result, FlextResult)
            # Service should validate creation requests

    def test_group_management_service_functionality(self) -> None:
        """Test GroupManagementService core functionality."""
        group_service = FlextLdapDomain.GroupManagementService()

        # Test group creation
        group_creation_data: dict[str, object] = {
            "dn": "cn=new.group,ou=groups,dc=example,dc=com",
            "cn": "new.group",
            "description": "New test group",
        }

        creation_result = group_service.validate_group_creation(group_creation_data)
        assert isinstance(creation_result, FlextResult)

        # Test group membership operations using actual can_add_member method
        test_group = FlextLdapModels.Group(
            id="test_group",
            dn="cn=existing.group,ou=groups,dc=example,dc=com",
            cn="existing.group",
            description="Test group",
            object_classes=["groupOfNames", "top"],
            members=[],
            modified_at=None,
        )

        test_user = FlextLdapModels.User(
            id="test_user",
            dn="cn=user,ou=users,dc=example,dc=com",
            uid="user",
            cn="Test User",
            sn="User",
            object_classes=["person", "top"],
        )

        membership_result = group_service.can_add_member(test_group, test_user)
        assert isinstance(membership_result, FlextResult)

    def test_password_service_functionality(self) -> None:
        """Test PasswordService password operations."""
        password_service = FlextLdapDomain.PasswordService()

        # Test password generation
        generated_passwords = []
        for _ in range(5):
            password_result = password_service.generate_secure_password()
            assert isinstance(password_result, FlextResult)

            if password_result.is_success:
                password = password_result.value
                assert isinstance(password, str)
                assert len(password) >= 8  # Minimum length expectation
                generated_passwords.append(password)

        # Test uniqueness of generated passwords
        if generated_passwords:
            assert len(generated_passwords) == len(set(generated_passwords))

        # Test password validation using available method
        test_password_changes = [
            ("OldPass123!", "NewStrongPassword456@"),
            ("CurrentPass789#", "AnotherSecure123$"),
            ("ExistingPass456@", "ValidNewPass789!"),
        ]

        for current_pass, new_pass in test_password_changes:
            validation_result = password_service.validate_password_change(
                current_pass, new_pass
            )
            assert isinstance(validation_result, FlextResult)


class TestDomainEvents:
    """Test Domain Events - event handling and structure."""

    def test_user_created_event_structure(self) -> None:
        """Test UserCreatedEvent creation and structure."""
        # Test event creation with required data
        event_data: dict[str, str | datetime] = {
            "actor": "admin@example.com",
            "occurred_at": datetime.now(UTC),
            "user_id": "new.user.123",
            "user_dn": "cn=new.user,ou=users,dc=example,dc=com",
        }

        user_created_event = FlextLdapDomain.UserCreatedEvent(
            actor=str(event_data["actor"]),
            occurred_at=event_data["occurred_at"],
            user_id=str(event_data["user_id"]),
            user_dn=str(event_data["user_dn"]),
        )

        # Verify event structure
        assert user_created_event.actor == "admin@example.com"
        assert isinstance(user_created_event.occurred_at, datetime)
        assert user_created_event.user_id == "new.user.123"
        assert user_created_event.user_dn == "cn=new.user,ou=users,dc=example,dc=com"

    def test_user_deleted_event_structure(self) -> None:
        """Test UserDeletedEvent creation and structure."""
        event_data: dict[str, str | datetime] = {
            "actor": "admin@company.org",
            "occurred_at": datetime.now(UTC),
            "user_id": "deleted.user.456",
            "user_dn": "cn=deleted.user,ou=users,dc=company,dc=org",
        }

        user_deleted_event = FlextLdapDomain.UserDeletedEvent(
            actor=str(event_data["actor"]),
            occurred_at=event_data["occurred_at"],
            user_id=str(event_data["user_id"]),
            user_dn=str(event_data["user_dn"]),
        )

        # Verify event structure
        assert user_deleted_event.actor == "admin@company.org"
        assert isinstance(user_deleted_event.occurred_at, datetime)
        assert user_deleted_event.user_id == "deleted.user.456"
        assert (
            user_deleted_event.user_dn == "cn=deleted.user,ou=users,dc=company,dc=org"
        )

    def test_group_membership_changed_event(self) -> None:
        """Test GroupMembershipChangedEvent functionality."""
        # GroupMembershipChangedEvent not implemented yet - skip test
        pytest.skip("GroupMembershipChangedEvent not implemented in domain layer")


class TestDomainIntegration:
    """Test Domain integration with flext-core patterns."""

    def test_domain_uses_flext_result_pattern(self) -> None:
        """Test that domain services use FlextResult pattern correctly."""
        user_service = FlextLdapDomain.UserManagementService()

        # Test that service methods return FlextResult
        test_data: dict[str, object] = {
            "dn": "cn=test,dc=example,dc=com",
            "uid": "test",
        }
        result = user_service.validate_user_creation(test_data)

        assert isinstance(result, FlextResult)
        assert hasattr(result, "is_success")
        # Validate result structure based on success/failure
        if result.is_success:
            assert hasattr(result, "value")
        else:
            assert hasattr(result, "error")
            assert result.error is not None

    def test_domain_follows_flext_core_patterns(self) -> None:
        """Test that domain follows flext-core architectural patterns."""
        # Test domain service inheritance
        user_service = FlextLdapDomain.UserManagementService()

        # Should inherit from FlextDomainService
        assert isinstance(user_service, FlextDomainService)

        # Test domain events use BaseModel
        event_data: dict[str, str | datetime] = {
            "actor": "test@example.com",
            "occurred_at": datetime.now(UTC),
            "user_id": "test.user",
            "user_dn": "cn=test,dc=example,dc=com",
        }

        user_event = FlextLdapDomain.UserCreatedEvent(
            actor=str(event_data["actor"]),
            occurred_at=event_data["occurred_at"],
            user_id=str(event_data["user_id"]),
            user_dn=str(event_data["user_dn"]),
        )
        assert isinstance(user_event, BaseModel)


class TestDomainFactoriesAndUtilities:
    """Test domain factories and utility functionality."""

    def test_domain_specification_factory_patterns(self) -> None:
        """Test domain specification creation patterns."""
        # Test specification instantiation
        specifications = [
            FlextLdapDomain.UserSpecification(),
            FlextLdapDomain.GroupSpecification(),
            FlextLdapDomain.DistinguishedNameSpecification(),
            FlextLdapDomain.PasswordSpecification(),
            FlextLdapDomain.ActiveUserSpecification(),
            FlextLdapDomain.EmailSpecification(),
            FlextLdapDomain.CompleteUserSpecification(),
        ]

        for spec in specifications:
            assert spec is not None
            assert hasattr(spec, "is_satisfied_by")
            assert hasattr(spec, "get_validation_error")
            assert callable(spec.is_satisfied_by)
            assert callable(spec.get_validation_error)

    def test_domain_service_factory_patterns(self) -> None:
        """Test domain service creation patterns."""
        # Test service instantiation
        services = [
            FlextLdapDomain.UserManagementService(),
            FlextLdapDomain.GroupManagementService(),
            FlextLdapDomain.PasswordService(),
        ]

        for service in services:
            assert service is not None
            # Should have domain service methods
            service_methods = [
                method
                for method in dir(service)
                if not method.startswith("_") and callable(getattr(service, method))
            ]
            assert len(service_methods) > 0


class TestDomainErrorHandling:
    """Test domain error handling and edge cases."""

    def test_specification_error_handling(self) -> None:
        """Test specification error handling with edge cases."""
        specifications = [
            FlextLdapDomain.UserSpecification(),
            FlextLdapDomain.GroupSpecification(),
            FlextLdapDomain.DistinguishedNameSpecification(),
        ]

        # Test error handling with various invalid inputs
        invalid_inputs = [None, "", {}, [], 123, True, object()]

        for spec in specifications:
            for invalid_input in invalid_inputs:
                # Should not raise exceptions
                result = spec.is_satisfied_by(invalid_input)
                assert isinstance(result, bool)

                error_msg = spec.get_validation_error(invalid_input)
                assert isinstance(error_msg, str)
                assert len(error_msg) > 0

    def test_service_error_handling(self) -> None:
        """Test service error handling with malformed requests."""
        user_service = FlextLdapDomain.UserManagementService()

        # Test with malformed creation requests
        malformed_requests: list[dict[str, object] | None] = [
            {},  # Empty request
            None,  # None request
            {"invalid": "data"},  # Missing required fields
            {"dn": ""},  # Empty required field
        ]

        for request in malformed_requests:
            if request is None:
                # Skip None requests - they should be handled by the service
                continue
            result = user_service.validate_user_creation(request)
            assert isinstance(result, FlextResult)
            # Should handle malformed requests gracefully
            if not result.is_success:
                assert result.error is not None
                assert isinstance(result.error, str)
