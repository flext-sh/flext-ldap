"""REAL coverage tests for FLEXT-LDAP domain layer.

Tests ALL domain specifications and services with REAL functionality validation.
NO MOCKS - tests execute actual business logic and validation rules.
"""

from __future__ import annotations

from typing import Never

from flext_core import FlextEntityId, FlextEntityStatus

from flext_ldap.domain import (
    FlextLdapActiveUserSpecification,
    FlextLdapDistinguishedNameSpecification,
    FlextLdapEmailSpecification,
    FlextLdapGroupManagementService,
    FlextLdapGroupSpecification,
    FlextLdapPasswordService,
    FlextLdapPasswordSpecification,
    FlextLdapUserManagementService,
    FlextLdapUserSpecification,
)
from flext_ldap.models import FlextLdapGroup, FlextLdapUser


class TestFlextLdapUserSpecificationRealValidation:
    """Test FlextLdapUserSpecification with REAL validation logic execution."""

    def test_user_specification_validates_valid_user_real(self) -> None:
        """Test user specification validates valid user - executes REAL validation."""
        spec = FlextLdapUserSpecification()

        valid_user = FlextLdapUser(
            id=FlextEntityId("test-user"),
            dn="cn=validuser,ou=users,dc=example,dc=com",
            cn="Valid User",
            sn="User",
            uid="valid.user",
            object_classes=["person", "top", "inetOrgPerson"],
            status=FlextEntityStatus.ACTIVE,
        )

        # Execute REAL validation logic
        result = spec.is_satisfied_by(valid_user)
        assert result is True

    def test_user_specification_rejects_invalid_user_real(self) -> None:
        """Test user specification rejects invalid user - executes REAL validation."""
        spec = FlextLdapUserSpecification()

        # User missing required object classes
        invalid_user = FlextLdapUser(
            id=FlextEntityId("test-user"),
            dn="cn=invaliduser,ou=users,dc=example,dc=com",
            cn="Invalid User",
            sn="User",
            uid="invalid.user",
            object_classes=["customClass"],  # Missing person, top
            status=FlextEntityStatus.ACTIVE,
        )

        # Execute REAL validation logic
        result = spec.is_satisfied_by(invalid_user)
        assert result is False

    def test_user_specification_rejects_missing_attributes_real(self) -> None:
        """Test user specification rejects users with missing attributes."""
        spec = FlextLdapUserSpecification()

        # Test object without required attributes
        invalid_object = object()
        result = spec.is_satisfied_by(invalid_object)
        assert result is False

    def test_user_specification_validation_error_messages_real(self) -> None:
        """Test user specification provides detailed error messages."""
        spec = FlextLdapUserSpecification()

        # Test error message for object without uid
        class MockObjectNoUID:
            pass

        error_msg = spec.get_validation_error(MockObjectNoUID())
        assert "must have a valid UID" in error_msg

        # Test error message for object without dn
        class MockObjectNoDN:
            uid = "test"

        error_msg = spec.get_validation_error(MockObjectNoDN())
        assert "must have a valid DN" in error_msg


class TestFlextLdapGroupSpecificationRealValidation:
    """Test FlextLdapGroupSpecification with REAL validation logic execution."""

    def test_group_specification_validates_valid_group_real(self) -> None:
        """Test group specification validates valid group - executes REAL validation."""
        spec = FlextLdapGroupSpecification()

        valid_group = FlextLdapGroup(
            id=FlextEntityId("test-group"),
            dn="cn=validgroup,ou=groups,dc=example,dc=com",
            cn="Valid Group",
            object_classes=["groupOfNames", "top"],
            status=FlextEntityStatus.ACTIVE,
        )

        # Execute REAL validation logic
        result = spec.is_satisfied_by(valid_group)
        assert result is True

    def test_group_specification_rejects_invalid_group_real(self) -> None:
        """Test group specification rejects invalid group - executes REAL validation."""
        spec = FlextLdapGroupSpecification()

        # Group missing required object classes
        invalid_group = FlextLdapGroup(
            id=FlextEntityId("test-group"),
            dn="cn=invalidgroup,ou=groups,dc=example,dc=com",
            cn="Invalid Group",
            object_classes=["customClass"],  # Missing groupOfNames, top
            status=FlextEntityStatus.ACTIVE,
        )

        # Execute REAL validation logic
        result = spec.is_satisfied_by(invalid_group)
        assert result is False

    def test_group_specification_validation_error_messages_real(self) -> None:
        """Test group specification provides detailed error messages."""
        spec = FlextLdapGroupSpecification()

        # Test error message for object without cn
        class MockObjectNoCN:
            pass

        error_msg = spec.get_validation_error(MockObjectNoCN())
        assert "must have a Common Name" in error_msg


class TestFlextLdapDistinguishedNameSpecificationRealValidation:
    """Test DN specification with REAL regex validation execution."""

    def test_dn_specification_validates_valid_dns_real(self) -> None:
        """Test DN specification validates valid DNs - executes REAL regex matching."""
        spec = FlextLdapDistinguishedNameSpecification()

        valid_dns = [
            "cn=user,ou=users,dc=example,dc=com",
            "uid=test.user,ou=people,dc=company,dc=org",
            "cn=Test User,ou=groups,dc=test,dc=local",
        ]

        for dn in valid_dns:
            # Execute REAL regex validation
            result = spec.is_satisfied_by(dn)
            assert result is True, f"Valid DN should pass validation: {dn}"

    def test_dn_specification_rejects_invalid_dns_real(self) -> None:
        """Test DN specification rejects invalid DNs - executes REAL regex matching."""
        spec = FlextLdapDistinguishedNameSpecification()

        invalid_dns = [
            "",  # Empty string
            "invalid-dn-format",  # No equals
            "=invalid,dc=com",  # Starts with equals
            "cn=",  # Empty value
        ]

        for dn in invalid_dns:
            # Execute REAL regex validation
            result = spec.is_satisfied_by(dn)
            assert result is False, f"Invalid DN should fail validation: {dn}"

    def test_dn_specification_rejects_non_string_real(self) -> None:
        """Test DN specification rejects non-string candidates."""
        spec = FlextLdapDistinguishedNameSpecification()

        non_strings = [123, None, [], {}]

        for candidate in non_strings:
            result = spec.is_satisfied_by(candidate)
            assert result is False

    def test_dn_specification_validation_error_messages_real(self) -> None:
        """Test DN specification provides detailed error messages."""
        spec = FlextLdapDistinguishedNameSpecification()

        # Test error for non-string
        error_msg = spec.get_validation_error(123)
        assert "must be a string" in error_msg

        # Test error for empty string
        error_msg = spec.get_validation_error("")
        assert "cannot be empty" in error_msg

        # Test error for invalid format
        error_msg = spec.get_validation_error("invalid-format")
        assert "Invalid DN format" in error_msg


class TestFlextLdapPasswordSpecificationRealValidation:
    """Test password specification with REAL password validation execution."""

    def test_password_specification_validates_strong_passwords_real(self) -> None:
        """Test password specification validates strong passwords - executes REAL validation."""
        spec = FlextLdapPasswordSpecification()

        strong_passwords = [
            "StrongPass123!",
            "AnotherGood1@",
            "Complex2024#",
        ]

        for password in strong_passwords:
            # Execute REAL password validation
            result = spec.is_satisfied_by(password)
            assert result is True, f"Strong password should pass: {password}"

    def test_password_specification_rejects_weak_passwords_real(self) -> None:
        """Test password specification rejects weak passwords - executes REAL validation."""
        spec = FlextLdapPasswordSpecification()

        weak_passwords = [
            "short",  # Too short
            "nouppercase123!",  # No uppercase
            "NOLOWERCASE123!",  # No lowercase
            "NoNumbers!",  # No numbers
            "a" * 200,  # Too long
        ]

        for password in weak_passwords:
            # Execute REAL password validation
            result = spec.is_satisfied_by(password)
            assert result is False, f"Weak password should fail: {password}"

    def test_password_specification_rejects_non_string_real(self) -> None:
        """Test password specification rejects non-string candidates."""
        spec = FlextLdapPasswordSpecification()

        non_strings = [123, None, [], {}]

        for candidate in non_strings:
            result = spec.is_satisfied_by(candidate)
            assert result is False

    def test_password_specification_validation_error_messages_real(self) -> None:
        """Test password specification provides detailed error messages."""
        spec = FlextLdapPasswordSpecification()

        # Test error for non-string
        error_msg = spec.get_validation_error(123)
        assert "must be a string" in error_msg

        # Test error for too short
        error_msg = spec.get_validation_error("short")
        assert "at least" in error_msg
        assert "characters" in error_msg

        # Test error for too long
        long_password = "a" * 200
        error_msg = spec.get_validation_error(long_password)
        assert "cannot exceed" in error_msg


class TestFlextLdapActiveUserSpecificationRealValidation:
    """Test active user specification with REAL status validation execution."""

    def test_active_user_specification_validates_active_user_real(self) -> None:
        """Test active user specification validates active user - executes REAL validation."""
        spec = FlextLdapActiveUserSpecification()

        active_user = FlextLdapUser(
            id=FlextEntityId("test-user"),
            dn="cn=activeuser,ou=users,dc=example,dc=com",
            cn="Active User",
            sn="User",
            uid="active.user",
            status=FlextEntityStatus.ACTIVE,
        )

        # Execute REAL status validation
        result = spec.is_satisfied_by(active_user)
        assert result is True

    def test_active_user_specification_rejects_inactive_user_real(self) -> None:
        """Test active user specification rejects inactive user - executes REAL validation."""
        spec = FlextLdapActiveUserSpecification()

        inactive_user = FlextLdapUser(
            id=FlextEntityId("test-user"),
            dn="cn=inactiveuser,ou=users,dc=example,dc=com",
            cn="Inactive User",
            sn="User",
            uid="inactive.user",
            status=FlextEntityStatus.INACTIVE,
        )

        # Execute REAL status validation
        result = spec.is_satisfied_by(inactive_user)
        assert result is False

    def test_active_user_specification_rejects_object_without_status_real(self) -> None:
        """Test active user specification rejects object without status."""
        spec = FlextLdapActiveUserSpecification()

        object_without_status = object()
        result = spec.is_satisfied_by(object_without_status)
        assert result is False


class TestFlextLdapEmailSpecificationRealValidation:
    """Test email specification with REAL email validation execution."""

    def test_email_specification_validates_valid_emails_real(self) -> None:
        """Test email specification validates valid emails - executes REAL regex validation."""
        spec = FlextLdapEmailSpecification()

        valid_emails = [
            "user@example.com",
            "test.user@company.org",
            "admin+test@domain.co.uk",
        ]

        for email in valid_emails:
            # Execute REAL email validation
            result = spec.is_satisfied_by(email)
            assert result is True, f"Valid email should pass: {email}"

    def test_email_specification_rejects_invalid_emails_real(self) -> None:
        """Test email specification rejects invalid emails - executes REAL regex validation."""
        spec = FlextLdapEmailSpecification()

        invalid_emails = [
            "invalid-email",  # No @
            "@domain.com",  # No local part
            "user@",  # No domain
            "user@domain",  # No TLD
            "",  # Empty string
        ]

        for email in invalid_emails:
            # Execute REAL email validation
            result = spec.is_satisfied_by(email)
            assert result is False, f"Invalid email should fail: {email}"


class TestFlextLdapUserManagementServiceRealLogic:
    """Test user management service with REAL business logic execution."""

    def test_user_management_service_validates_user_creation_real(self) -> None:
        """Test user management service validates user creation - executes REAL validation chain."""
        service = FlextLdapUserManagementService()

        valid_user_data = {
            "uid": "test.user",
            "cn": "Test User",
            "sn": "User",
            "dn": "cn=Test User,ou=users,dc=example,dc=com",
            "mail": "test@example.com",
            "password": "StrongPass123!",
        }

        # Execute REAL validation chain
        result = service.validate_user_creation(valid_user_data)
        assert result.is_success, (
            f"Valid user data should pass validation: {result.error}"
        )

    def test_user_management_service_rejects_invalid_user_creation_real(self) -> None:
        """Test user management service rejects invalid user creation - executes REAL validation."""
        service = FlextLdapUserManagementService()

        # Test missing required field
        invalid_user_data = {
            "cn": "Test User",
            "sn": "User",
            # Missing uid and dn
        }

        # Execute REAL validation chain
        result = service.validate_user_creation(invalid_user_data)
        assert not result.is_success
        assert "Required field missing" in (result.error or "")

    def test_user_management_service_validates_email_field_real(self) -> None:
        """Test user management service validates email field - executes REAL email validation."""
        service = FlextLdapUserManagementService()

        user_data_invalid_email = {
            "uid": "test.user",
            "cn": "Test User",
            "sn": "User",
            "dn": "cn=Test User,ou=users,dc=example,dc=com",
            "mail": "invalid-email-format",  # Invalid email
        }

        # Execute REAL validation chain including email validation
        result = service.validate_user_creation(user_data_invalid_email)
        assert not result.is_success

    def test_user_management_service_validates_password_field_real(self) -> None:
        """Test user management service validates password field - executes REAL password validation."""
        service = FlextLdapUserManagementService()

        user_data_weak_password = {
            "uid": "test.user",
            "cn": "Test User",
            "sn": "User",
            "dn": "cn=Test User,ou=users,dc=example,dc=com",
            "password": "weak",  # Too weak
        }

        # Execute REAL validation chain including password validation
        result = service.validate_user_creation(user_data_weak_password)
        assert not result.is_success

    def test_user_management_service_validates_dn_field_real(self) -> None:
        """Test user management service validates DN field - executes REAL DN validation."""
        service = FlextLdapUserManagementService()

        user_data_invalid_dn = {
            "uid": "test.user",
            "cn": "Test User",
            "sn": "User",
            "dn": "invalid-dn-format",  # Invalid DN
        }

        # Execute REAL validation chain including DN validation
        result = service.validate_user_creation(user_data_invalid_dn)
        assert not result.is_success

    def test_user_management_service_handles_exceptions_real(self) -> None:
        """Test user management service handles exceptions - executes REAL error handling."""
        service = FlextLdapUserManagementService()

        # Test with data that could trigger exception handling
        # This should execute exception handling paths
        result = service.validate_user_creation({})  # Empty data
        assert not result.is_success

    def test_user_management_service_validates_all_field_combinations_real(
        self,
    ) -> None:
        """Test user management service with all field combinations - executes REAL comprehensive validation."""
        service = FlextLdapUserManagementService()

        # Test with comprehensive user data
        comprehensive_user_data = {
            "uid": "comprehensive.user",
            "cn": "Comprehensive User",
            "sn": "User",
            "dn": "cn=Comprehensive User,ou=users,dc=example,dc=com",
            "mail": "comprehensive@example.com",
            "password": "VerySecurePass123!",
            "givenName": "Comprehensive",
            "displayName": "Comprehensive User",
            "description": "A comprehensive test user",
        }

        # Execute REAL comprehensive validation
        result = service.validate_user_creation(comprehensive_user_data)
        assert result.is_success, f"Comprehensive user should be valid: {result.error}"

    def test_user_management_service_validation_chain_order_real(self) -> None:
        """Test user management service validation chain order - executes REAL chain validation."""
        service = FlextLdapUserManagementService()

        # Test validation chain with user missing multiple fields
        incomplete_user_data = {
            "uid": "",  # Invalid UID
            "cn": "",  # Invalid CN
            # Missing sn and dn completely
        }

        # Execute REAL validation chain - should fail on first validation
        result = service.validate_user_creation(incomplete_user_data)
        assert not result.is_success
        # Should fail on required fields validation first
        assert "Required field missing" in (result.error or "")


class TestFlextLdapPasswordServiceRealGeneration:
    """Test password service with REAL password generation and validation."""

    def test_password_service_generates_secure_passwords_real(self) -> None:
        """Test password service generates secure passwords - executes REAL generation logic."""
        service = FlextLdapPasswordService()

        # Execute REAL password generation
        result = service.generate_secure_password()
        assert result.is_success, f"Password generation should succeed: {result.error}"

        password = result.value
        assert isinstance(password, str)
        assert len(password) >= 8  # Minimum length

        # Verify generated password meets complexity requirements
        password_spec = FlextLdapPasswordSpecification()
        is_valid = password_spec.is_satisfied_by(password)
        assert is_valid, f"Generated password should meet requirements: {password}"

    def test_password_service_validates_length_parameters_real(self) -> None:
        """Test password service validates length parameters - executes REAL validation logic."""
        service = FlextLdapPasswordService()

        # Test with too short length
        result = service.generate_secure_password(length=4)
        assert not result.is_success
        assert "at least" in (result.error or "")

        # Test with too long length
        result = service.generate_secure_password(length=200)
        assert not result.is_success
        assert "cannot exceed" in (result.error or "")

        # Test with valid length
        result = service.generate_secure_password(length=16)
        assert result.is_success
        assert len(result.value) == 16

    def test_password_service_handles_generation_exceptions_real(self) -> None:
        """Test password service handles generation exceptions - executes REAL error handling."""
        service = FlextLdapPasswordService()

        # Override the password generation to force an exception
        def failing_password_gen(length) -> Never:
            msg = "Simulated generation failure"
            raise ValueError(msg)

        original_method = service._generate_password_with_retries
        service._generate_password_with_retries = failing_password_gen

        try:
            # Execute REAL exception handling logic
            result = service.generate_secure_password()

            # Should fail gracefully
            assert not result.is_success
            assert "Password generation error" in (result.error or "")
        finally:
            # Restore original method
            service._generate_password_with_retries = original_method

    def test_password_service_validates_password_change_real(self) -> None:
        """Test password service validates password change - executes REAL validation logic."""
        service = FlextLdapPasswordService()

        # Test valid password change
        valid_result = service.validate_password_change(
            "OldPass123!", "NewStrongPass123!"
        )
        assert valid_result.is_success

        # Test invalid password change (same passwords)
        invalid_result = service.validate_password_change(
            "SamePass123!", "SamePass123!"
        )
        assert not invalid_result.is_success
        assert "must be different" in (invalid_result.error or "")

    def test_password_service_validates_password_strength_real(self) -> None:
        """Test password service validates password strength - executes REAL strength validation."""
        service = FlextLdapPasswordService()

        # Test weak new password
        weak_result = service.validate_password_change("OldPass123!", "weak")
        assert not weak_result.is_success

    def test_password_service_generates_multiple_different_passwords_real(self) -> None:
        """Test password service generates different passwords - executes REAL randomization."""
        service = FlextLdapPasswordService()

        passwords = set()
        for _ in range(5):
            result = service.generate_secure_password()
            assert result.is_success
            passwords.add(result.value)

        # All generated passwords should be different (very high probability)
        assert len(passwords) == 5, "Generated passwords should be unique"


class TestFlextLdapGroupManagementServiceRealLogic:
    """Test group management service with REAL business logic execution."""

    def test_group_management_service_validates_group_creation_real(self) -> None:
        """Test group management service validates group creation - executes REAL validation."""
        service = FlextLdapGroupManagementService()

        valid_group_data = {
            "cn": "Test Group",
            "dn": "cn=Test Group,ou=groups,dc=example,dc=com",
            "description": "Test group for validation",
        }

        # Execute REAL group validation
        result = service.validate_group_creation(valid_group_data)
        assert result.is_success, (
            f"Valid group data should pass validation: {result.error}"
        )

    def test_group_management_service_rejects_invalid_group_creation_real(self) -> None:
        """Test group management service rejects invalid group creation - executes REAL validation."""
        service = FlextLdapGroupManagementService()

        # Test missing required field
        invalid_group_data = {
            "description": "Missing cn and dn",
        }

        # Execute REAL group validation
        result = service.validate_group_creation(invalid_group_data)
        assert not result.is_success
        assert "Required field missing" in (result.error or "")

    def test_group_management_service_validates_group_dn_real(self) -> None:
        """Test group management service validates group DN - executes REAL DN validation."""
        service = FlextLdapGroupManagementService()

        group_data_invalid_dn = {
            "cn": "Test Group",
            "dn": "invalid-dn-format",  # Invalid DN
        }

        # Execute REAL validation including DN validation
        result = service.validate_group_creation(group_data_invalid_dn)
        assert not result.is_success

    def test_group_management_service_validates_member_addition_real(self) -> None:
        """Test group management service validates member addition - executes REAL validation."""
        service = FlextLdapGroupManagementService()

        # Create valid group
        valid_group = FlextLdapGroup(
            id=FlextEntityId("test-group"),
            dn="cn=testgroup,ou=groups,dc=example,dc=com",
            cn="Test Group",
            object_classes=["groupOfNames", "top"],
            status=FlextEntityStatus.ACTIVE,
            members=[],
        )

        # Create valid user
        valid_user = FlextLdapUser(
            id=FlextEntityId("test-user"),
            dn="cn=testuser,ou=users,dc=example,dc=com",
            cn="Test User",
            sn="User",
            uid="test.user",
            object_classes=["person", "top", "inetOrgPerson"],
            status=FlextEntityStatus.ACTIVE,
        )

        # Execute REAL member validation
        result = service.can_add_member(valid_group, valid_user)
        assert result.is_success, f"Valid member addition should pass: {result.error}"
        assert result.value is True

    def test_group_management_service_rejects_duplicate_member_real(self) -> None:
        """Test group management service rejects duplicate member - executes REAL validation."""
        service = FlextLdapGroupManagementService()

        # Create user
        user = FlextLdapUser(
            id=FlextEntityId("test-user"),
            dn="cn=testuser,ou=users,dc=example,dc=com",
            cn="Test User",
            sn="User",
            uid="test.user",
            object_classes=["person", "top", "inetOrgPerson"],
            status=FlextEntityStatus.ACTIVE,
        )

        # Create group with user already as member
        group = FlextLdapGroup(
            id=FlextEntityId("test-group"),
            dn="cn=testgroup,ou=groups,dc=example,dc=com",
            cn="Test Group",
            object_classes=["groupOfNames", "top"],
            status=FlextEntityStatus.ACTIVE,
            members=[user.dn],  # User already member
        )

        # Execute REAL validation - should reject duplicate
        result = service.can_add_member(group, user)
        assert not result.is_success
        assert "already a member" in (result.error or "")

    def test_group_management_service_rejects_inactive_user_real(self) -> None:
        """Test group management service rejects inactive user - executes REAL validation."""
        service = FlextLdapGroupManagementService()

        # Create valid group
        valid_group = FlextLdapGroup(
            id=FlextEntityId("test-group"),
            dn="cn=testgroup,ou=groups,dc=example,dc=com",
            cn="Test Group",
            object_classes=["groupOfNames", "top"],
            status=FlextEntityStatus.ACTIVE,
            members=[],
        )

        # Create inactive user
        inactive_user = FlextLdapUser(
            id=FlextEntityId("test-user"),
            dn="cn=inactiveuser,ou=users,dc=example,dc=com",
            cn="Inactive User",
            sn="User",
            uid="inactive.user",
            object_classes=["person", "top", "inetOrgPerson"],
            status=FlextEntityStatus.INACTIVE,  # Inactive status
        )

        # Execute REAL validation - should reject inactive user
        result = service.can_add_member(valid_group, inactive_user)
        assert not result.is_success
        assert "active users" in (result.error or "")

    def test_group_management_service_handles_exceptions_real(self) -> None:
        """Test group management service handles exceptions - executes REAL error handling."""
        service = FlextLdapGroupManagementService()

        # Test with invalid group data to trigger exception handling
        # This should execute exception handling paths
        result = service.validate_group_creation({})  # Empty data
        assert not result.is_success

    def test_group_management_service_validates_complex_scenarios_real(self) -> None:
        """Test group management service with complex scenarios - executes REAL complex validation."""
        service = FlextLdapGroupManagementService()

        # Test nested validation scenarios
        complex_group_data = {
            "cn": "Complex Group",
            "dn": "cn=complex,ou=groups,dc=example,dc=com",
            "description": "A complex test group with multiple validation points",
            "members": [
                "cn=user1,ou=users,dc=example,dc=com",
                "cn=user2,ou=users,dc=example,dc=com",
            ],
        }

        # Execute REAL complex validation
        result = service.validate_group_creation(complex_group_data)
        assert result.is_success, f"Complex group should be valid: {result.error}"

    def test_group_management_service_member_validation_edge_cases_real(self) -> None:
        """Test group member validation edge cases - executes REAL edge case handling."""
        service = FlextLdapGroupManagementService()

        # Create group with edge case members
        group = FlextLdapGroup(
            id=FlextEntityId("edge-group"),
            dn="cn=edgegroup,ou=groups,dc=example,dc=com",
            cn="Edge Group",
            object_classes=["groupOfNames", "top"],
            status=FlextEntityStatus.ACTIVE,
            members=["cn=existing,ou=users,dc=example,dc=com"],  # Already has a member
        )

        # Create user with edge case attributes
        user = FlextLdapUser(
            id=FlextEntityId("edge-user"),
            dn="cn=existing,ou=users,dc=example,dc=com",  # Same DN as existing member
            cn="Edge User",
            sn="User",
            uid="edge.user",
            object_classes=["person", "top", "inetOrgPerson"],
            status=FlextEntityStatus.ACTIVE,
        )

        # Execute REAL edge case validation
        result = service.can_add_member(group, user)
        assert not result.is_success  # Should reject duplicate member
        assert "already a member" in (result.error or "")
