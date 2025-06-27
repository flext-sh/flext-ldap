"""Tests for LDAP Password Modify Extended Operation Implementation.

This module provides comprehensive test coverage for the Password Modify extended
operation implementation including password validation, ASN.1 encoding/decoding,
and security management with enterprise-grade validation.

Test Coverage:
    - PasswordValidationError: Password validation exception handling
    - ModifyPasswordResult: Result processing and password information
    - ModifyPasswordExtension: Extended operation implementation
    - PasswordChangeBuilder: Fluent interface for password operations
    - ASN.1 encoding/decoding for password modify requests
    - Self-service and REDACTED_LDAP_BIND_PASSWORDistrative password operations

Security Testing:
    - Password validation and strength requirements
    - User identity validation and DN format checking
    - ASN.1 encoding security and input sanitization
    - Administrative vs self-service operation validation
    - Password generation request handling and security

Integration Testing:
    - RFC 3062 compliance validation
    - Extension request/response encoding/decoding
    - Password policy integration and validation
    - Error handling and exception management
    - Builder pattern functionality and validation
"""

from __future__ import annotations

import pytest

from ldap_core_shared.extensions.base import (
    ExtensionDecodingError,
    ExtensionOIDs,
)
from ldap_core_shared.extensions.modify_password import (
    ModifyPasswordExtension,
    ModifyPasswordResult,
    PasswordChangeBuilder,
    PasswordValidationError,
    change_password,
    generate_password,
    reset_password,
)
from ldap_core_shared.utils.constants import BER_CONTEXT_TAG_0, BER_SEQUENCE_TAG


class TestPasswordValidationError:
    """Test cases for PasswordValidationError."""

    def test_error_creation(self) -> None:
        """Test password validation error creation."""
        error = PasswordValidationError("Password too weak")
        assert str(error) == "Password too weak"
        assert isinstance(error, Exception)

    def test_error_inheritance(self) -> None:
        """Test error inheritance hierarchy."""
        error = PasswordValidationError("Test error")
        assert isinstance(error, Exception)


class TestModifyPasswordResult:
    """Test cases for ModifyPasswordResult."""

    def test_result_creation_default(self) -> None:
        """Test creating result with default values."""
        result = ModifyPasswordResult(result_code=0)

        assert result.result_code == 0
        assert result.generated_password is None
        assert result.password_changed is False
        assert result.old_password_required is False
        assert result.policy_violations == []

    def test_result_creation_with_generated_password(self) -> None:
        """Test creating result with generated password."""
        result = ModifyPasswordResult(
            result_code=0,
            generated_password="temp123!@#",
            password_changed=True,
        )

        assert result.result_code == 0
        assert result.generated_password == "temp123!@#"
        assert result.password_changed is True

    def test_result_creation_with_policy_violations(self) -> None:
        """Test creating result with policy violations."""
        violations = ["Password too short", "Must contain special characters"]
        result = ModifyPasswordResult(
            result_code=1,
            password_changed=False,
            policy_violations=violations,
        )

        assert result.result_code == 1
        assert result.password_changed is False
        assert result.policy_violations == violations

    def test_has_generated_password_method(self) -> None:
        """Test has_generated_password method."""
        # Without generated password
        result1 = ModifyPasswordResult(result_code=0)
        assert result1.has_generated_password() is False

        # With generated password
        result2 = ModifyPasswordResult(
            result_code=0,
            generated_password="generated123",
        )
        assert result2.has_generated_password() is True

        # With empty string (should be False)
        result3 = ModifyPasswordResult(
            result_code=0,
            generated_password="",
        )
        assert result3.has_generated_password() is False

    def test_is_policy_violation_method(self) -> None:
        """Test is_policy_violation method."""
        # No violations
        result1 = ModifyPasswordResult(result_code=0)
        assert result1.is_policy_violation() is False

        # Empty violations list
        result2 = ModifyPasswordResult(
            result_code=0,
            policy_violations=[],
        )
        assert result2.is_policy_violation() is False

        # With violations
        result3 = ModifyPasswordResult(
            result_code=1,
            policy_violations=["Password too weak"],
        )
        assert result3.is_policy_violation() is True

    def test_get_policy_summary_method(self) -> None:
        """Test get_policy_summary method."""
        # No violations
        result1 = ModifyPasswordResult(result_code=0)
        assert result1.get_policy_summary() == "No policy violations"

        # Single violation
        result2 = ModifyPasswordResult(
            result_code=1,
            policy_violations=["Password too short"],
        )
        assert result2.get_policy_summary() == "Policy violations: Password too short"

        # Multiple violations
        result3 = ModifyPasswordResult(
            result_code=1,
            policy_violations=["Password too short", "Must contain numbers"],
        )
        expected = "Policy violations: Password too short, Must contain numbers"
        assert result3.get_policy_summary() == expected

    def test_str_representation_success(self) -> None:
        """Test string representation for successful result."""
        result = ModifyPasswordResult(
            result_code=0,
            password_changed=True,
        )

        str_repr = str(result)
        assert str_repr == "Password modified successfully"

    def test_str_representation_with_generated_password(self) -> None:
        """Test string representation with generated password."""
        result = ModifyPasswordResult(
            result_code=0,
            generated_password="temp123456",
            password_changed=True,
        )

        str_repr = str(result)
        assert str_repr == "Password modified (generated: tem...)"

    def test_str_representation_failure(self) -> None:
        """Test string representation for failed result."""
        result = ModifyPasswordResult(
            result_code=1,
            error_message="Password policy violation",
            password_changed=False,
        )

        str_repr = str(result)
        assert "Password modify failed" in str_repr
        assert "Password policy violation" in str_repr


class TestModifyPasswordExtension:
    """Test cases for ModifyPasswordExtension."""

    def test_extension_initialization_default(self) -> None:
        """Test extension initialization with default values."""
        extension = ModifyPasswordExtension()

        assert extension.request_name == ExtensionOIDs.MODIFY_PASSWORD
        assert extension.user_identity is None
        assert extension.old_password is None
        assert extension.new_password is None

    def test_extension_initialization_self_service(self) -> None:
        """Test extension initialization for self-service change."""
        extension = ModifyPasswordExtension(
            old_password="current123",
            new_password="new456",
        )

        assert extension.user_identity is None
        assert extension.old_password == "current123"
        assert extension.new_password == "new456"

    def test_extension_initialization_REDACTED_LDAP_BIND_PASSWORD_reset(self) -> None:
        """Test extension initialization for REDACTED_LDAP_BIND_PASSWORD reset."""
        extension = ModifyPasswordExtension(
            user_identity="uid=jdoe,ou=people,dc=example,dc=com",
            new_password="reset123",
        )

        assert extension.user_identity == "uid=jdoe,ou=people,dc=example,dc=com"
        assert extension.old_password is None
        assert extension.new_password == "reset123"

    def test_user_identity_validation_valid_dn(self) -> None:
        """Test user identity validation with valid DN."""
        extension = ModifyPasswordExtension(
            user_identity="cn=John Doe,ou=users,dc=example,dc=com",
        )
        assert extension.user_identity == "cn=John Doe,ou=users,dc=example,dc=com"

    def test_user_identity_validation_empty_string(self) -> None:
        """Test user identity validation with empty string."""
        extension = ModifyPasswordExtension(user_identity="")
        assert extension.user_identity is None

    def test_user_identity_validation_whitespace(self) -> None:
        """Test user identity validation with whitespace."""
        extension = ModifyPasswordExtension(user_identity="   ")
        assert extension.user_identity is None

    def test_user_identity_validation_invalid_dn(self) -> None:
        """Test user identity validation with invalid DN."""
        with pytest.raises(
            PasswordValidationError, match="User identity must be a valid DN"
        ):
            ModifyPasswordExtension(user_identity="invalid_dn_format")

    def test_old_password_validation_empty_string(self) -> None:
        """Test old password validation with empty string."""
        with pytest.raises(
            PasswordValidationError, match="Old password cannot be empty string"
        ):
            ModifyPasswordExtension(old_password="")

    def test_old_password_validation_none(self) -> None:
        """Test old password validation with None."""
        extension = ModifyPasswordExtension(old_password=None)
        assert extension.old_password is None

    def test_new_password_validation_empty_string(self) -> None:
        """Test new password validation with empty string."""
        with pytest.raises(
            PasswordValidationError, match="New password cannot be empty string"
        ):
            ModifyPasswordExtension(new_password="")

    def test_new_password_validation_none(self) -> None:
        """Test new password validation with None."""
        extension = ModifyPasswordExtension(new_password=None)
        assert extension.new_password is None

    def test_encode_request_value_empty(self) -> None:
        """Test encoding request value with no parameters."""
        extension = ModifyPasswordExtension()

        encoded = extension.encode_request_value()
        assert encoded == b""

    def test_encode_request_value_self_service(self) -> None:
        """Test encoding request value for self-service change."""
        extension = ModifyPasswordExtension(
            old_password="old123",
            new_password="new456",
        )

        encoded = extension.encode_request_value()
        assert len(encoded) > 0
        assert encoded.startswith(bytes([BER_SEQUENCE_TAG]))

    def test_encode_request_value_REDACTED_LDAP_BIND_PASSWORD_reset(self) -> None:
        """Test encoding request value for REDACTED_LDAP_BIND_PASSWORD reset."""
        extension = ModifyPasswordExtension(
            user_identity="uid=test,dc=example,dc=com",
            new_password="reset123",
        )

        encoded = extension.encode_request_value()
        assert len(encoded) > 0
        assert encoded.startswith(bytes([BER_SEQUENCE_TAG]))

    def test_encode_request_value_with_all_fields(self) -> None:
        """Test encoding request value with all fields."""
        extension = ModifyPasswordExtension(
            user_identity="uid=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com",
            old_password="REDACTED_LDAP_BIND_PASSWORD123",
            new_password="newREDACTED_LDAP_BIND_PASSWORD456",
        )

        encoded = extension.encode_request_value()
        assert len(encoded) > 0
        assert encoded.startswith(bytes([BER_SEQUENCE_TAG]))

    def test_encode_request_value_unicode(self) -> None:
        """Test encoding request value with Unicode characters."""
        extension = ModifyPasswordExtension(
            user_identity="cn=José García,dc=example,dc=com",
            old_password="contraseña123",
            new_password="nuevaContraseña456",
        )

        encoded = extension.encode_request_value()
        assert len(encoded) > 0
        assert encoded.startswith(bytes([BER_SEQUENCE_TAG]))

    def test_decode_response_value_no_data(self) -> None:
        """Test decoding response value with no data."""
        result = ModifyPasswordExtension.decode_response_value(None, None)

        assert isinstance(result, ModifyPasswordResult)
        assert result.result_code == 0
        assert result.generated_password is None
        assert result.password_changed is True

    def test_decode_response_value_empty_sequence(self) -> None:
        """Test decoding response value with empty sequence."""
        # Empty SEQUENCE
        response_data = b"\x30\x00"
        result = ModifyPasswordExtension.decode_response_value(None, response_data)

        assert isinstance(result, ModifyPasswordResult)
        assert result.generated_password is None

    def test_decode_response_value_with_generated_password(self) -> None:
        """Test decoding response value with generated password."""
        # Manually create ASN.1 response with generated password
        password = "generated123"
        password_bytes = password.encode("utf-8")

        # Context tag [0] + length + password
        content = bytes([BER_CONTEXT_TAG_0, len(password_bytes)]) + password_bytes
        response_data = bytes([BER_SEQUENCE_TAG, len(content)]) + content

        result = ModifyPasswordExtension.decode_response_value(None, response_data)

        assert isinstance(result, ModifyPasswordResult)
        assert result.generated_password == password
        assert result.password_changed is True

    def test_decode_response_value_invalid_data(self) -> None:
        """Test decoding response value with invalid data."""
        invalid_data = b"\xff\xfe\xfd"  # Invalid ASN.1

        with pytest.raises(
            ExtensionDecodingError, match="Failed to decode password modify response"
        ):
            ModifyPasswordExtension.decode_response_value(None, invalid_data)

    def test_self_service_change_class_method(self) -> None:
        """Test self_service_change class method."""
        extension = ModifyPasswordExtension.self_service_change("old123", "new456")

        assert extension.user_identity is None
        assert extension.old_password == "old123"
        assert extension.new_password == "new456"
        assert extension.is_self_service() is True

    def test_REDACTED_LDAP_BIND_PASSWORD_reset_class_method(self) -> None:
        """Test REDACTED_LDAP_BIND_PASSWORD_reset class method."""
        user_dn = "uid=test,ou=people,dc=example,dc=com"
        extension = ModifyPasswordExtension.REDACTED_LDAP_BIND_PASSWORD_reset(user_dn, "reset123")

        assert extension.user_identity == user_dn
        assert extension.old_password is None
        assert extension.new_password == "reset123"
        assert extension.is_REDACTED_LDAP_BIND_PASSWORD_operation() is True

    def test_generate_password_class_method(self) -> None:
        """Test generate_password class method."""
        user_dn = "uid=test,ou=people,dc=example,dc=com"
        extension = ModifyPasswordExtension.generate_password(user_dn)

        assert extension.user_identity == user_dn
        assert extension.old_password is None
        assert extension.new_password is None
        assert extension.is_password_generation() is True

    def test_self_service_generate_class_method(self) -> None:
        """Test self_service_generate class method."""
        extension = ModifyPasswordExtension.self_service_generate()

        assert extension.user_identity is None
        assert extension.old_password is None
        assert extension.new_password is None
        assert extension.is_self_service() is True
        assert extension.is_password_generation() is True

    def test_is_self_service_method(self) -> None:
        """Test is_self_service method."""
        # Self-service (no user identity)
        extension1 = ModifyPasswordExtension()
        assert extension1.is_self_service() is True

        # Admin operation (with user identity)
        extension2 = ModifyPasswordExtension(user_identity="uid=test,dc=example,dc=com")
        assert extension2.is_self_service() is False

    def test_is_REDACTED_LDAP_BIND_PASSWORD_operation_method(self) -> None:
        """Test is_REDACTED_LDAP_BIND_PASSWORD_operation method."""
        # Self-service (no user identity)
        extension1 = ModifyPasswordExtension()
        assert extension1.is_REDACTED_LDAP_BIND_PASSWORD_operation() is False

        # Admin operation (with user identity)
        extension2 = ModifyPasswordExtension(user_identity="uid=test,dc=example,dc=com")
        assert extension2.is_REDACTED_LDAP_BIND_PASSWORD_operation() is True

    def test_is_password_generation_method(self) -> None:
        """Test is_password_generation method."""
        # With new password
        extension1 = ModifyPasswordExtension(new_password="test123")
        assert extension1.is_password_generation() is False

        # Without new password (generation)
        extension2 = ModifyPasswordExtension(new_password=None)
        assert extension2.is_password_generation() is True

    def test_requires_old_password_method(self) -> None:
        """Test requires_old_password method."""
        # Self-service change (requires old password)
        extension1 = ModifyPasswordExtension(new_password="new123")
        assert extension1.requires_old_password() is True

        # Self-service generation (may not require old password)
        extension2 = ModifyPasswordExtension(new_password=None)
        assert extension2.requires_old_password() is False

        # Admin operation (doesn't require old password)
        extension3 = ModifyPasswordExtension(
            user_identity="uid=test,dc=example,dc=com",
            new_password="new123",
        )
        assert extension3.requires_old_password() is False

    def test_str_representation_self_service_change(self) -> None:
        """Test string representation for self-service change."""
        extension = ModifyPasswordExtension(
            old_password="old123",
            new_password="new456",
        )

        str_repr = str(extension)
        assert str_repr == "ModifyPassword(self-service, change)"

    def test_str_representation_self_service_generate(self) -> None:
        """Test string representation for self-service generation."""
        extension = ModifyPasswordExtension(new_password=None)

        str_repr = str(extension)
        assert str_repr == "ModifyPassword(self-service, generate)"

    def test_str_representation_REDACTED_LDAP_BIND_PASSWORD_reset(self) -> None:
        """Test string representation for REDACTED_LDAP_BIND_PASSWORD reset."""
        user_dn = "uid=test,dc=example,dc=com"
        extension = ModifyPasswordExtension(
            user_identity=user_dn,
            new_password="reset123",
        )

        str_repr = str(extension)
        assert str_repr == f"ModifyPassword(REDACTED_LDAP_BIND_PASSWORD, reset for {user_dn})"

    def test_str_representation_REDACTED_LDAP_BIND_PASSWORD_generate(self) -> None:
        """Test string representation for REDACTED_LDAP_BIND_PASSWORD generation."""
        user_dn = "uid=test,dc=example,dc=com"
        extension = ModifyPasswordExtension(
            user_identity=user_dn,
            new_password=None,
        )

        str_repr = str(extension)
        assert str_repr == f"ModifyPassword(REDACTED_LDAP_BIND_PASSWORD, generate for {user_dn})"

    def test_oid_validation(self) -> None:
        """Test that the correct OID is used."""
        extension = ModifyPasswordExtension()

        # MODIFY_PASSWORD OID should be the standard RFC 3062 OID
        assert extension.request_name == "1.3.6.1.4.1.4203.1.11.1"

    def test_asn1_encoding_helpers(self) -> None:
        """Test ASN.1 encoding helper methods."""
        # Test octet string encoding
        value = b"test"
        encoded = ModifyPasswordExtension._encode_octet_string(value)
        assert encoded == b"\x04\x04test"

        # Test sequence encoding
        content = b"content"
        encoded = ModifyPasswordExtension._encode_sequence(content)
        assert encoded == b"\x30\x07content"

        # Test context tag encoding
        content = b"tagged"
        encoded = ModifyPasswordExtension._encode_context_tag(1, content)
        assert encoded == b"\x81\x06tagged"

    def test_asn1_decoding_helpers(self) -> None:
        """Test ASN.1 decoding helper methods."""
        # Test sequence decoding
        sequence_data = b"\x30\x04test"
        content = ModifyPasswordExtension._decode_sequence(sequence_data)
        assert content == b"test"

        # Test invalid sequence
        with pytest.raises(ValueError, match="Not a SEQUENCE"):
            ModifyPasswordExtension._decode_sequence(b"\x04\x04test")

        # Test context tag decoding
        tagged_data = b"\x81\x04test"
        content, pos = ModifyPasswordExtension._decode_context_tag(tagged_data, 0)
        assert content == b"test"
        assert pos == 6


class TestPasswordChangeBuilder:
    """Test cases for PasswordChangeBuilder."""

    def test_builder_initialization(self) -> None:
        """Test builder initialization."""
        builder = PasswordChangeBuilder()

        assert builder._user_identity is None
        assert builder._old_password is None
        assert builder._new_password is None

    def test_builder_for_user(self) -> None:
        """Test builder for_user method."""
        builder = PasswordChangeBuilder()
        user_dn = "uid=test,ou=people,dc=example,dc=com"

        result = builder.for_user(user_dn)

        assert result is builder  # Should return self for chaining
        assert builder._user_identity == user_dn

    def test_builder_for_current_user(self) -> None:
        """Test builder for_current_user method."""
        builder = PasswordChangeBuilder()
        builder._user_identity = "some_user"  # Set initial value

        result = builder.for_current_user()

        assert result is builder  # Should return self for chaining
        assert builder._user_identity is None

    def test_builder_with_old_password(self) -> None:
        """Test builder with_old_password method."""
        builder = PasswordChangeBuilder()

        result = builder.with_old_password("old123")

        assert result is builder  # Should return self for chaining
        assert builder._old_password == "old123"

    def test_builder_with_new_password(self) -> None:
        """Test builder with_new_password method."""
        builder = PasswordChangeBuilder()

        result = builder.with_new_password("new456")

        assert result is builder  # Should return self for chaining
        assert builder._new_password == "new456"

    def test_builder_generate_new_password(self) -> None:
        """Test builder generate_new_password method."""
        builder = PasswordChangeBuilder()
        builder._new_password = "some_password"  # Set initial value

        result = builder.generate_new_password()

        assert result is builder  # Should return self for chaining
        assert builder._new_password is None

    def test_builder_build_self_service(self) -> None:
        """Test builder build method for self-service."""
        builder = PasswordChangeBuilder()
        extension = (
            builder.for_current_user()
            .with_old_password("old123")
            .with_new_password("new456")
            .build()
        )

        assert isinstance(extension, ModifyPasswordExtension)
        assert extension.user_identity is None
        assert extension.old_password == "old123"
        assert extension.new_password == "new456"

    def test_builder_build_REDACTED_LDAP_BIND_PASSWORD_reset(self) -> None:
        """Test builder build method for REDACTED_LDAP_BIND_PASSWORD reset."""
        builder = PasswordChangeBuilder()
        user_dn = "uid=test,ou=people,dc=example,dc=com"
        extension = builder.for_user(user_dn).with_new_password("reset123").build()

        assert isinstance(extension, ModifyPasswordExtension)
        assert extension.user_identity == user_dn
        assert extension.old_password is None
        assert extension.new_password == "reset123"

    def test_builder_build_password_generation(self) -> None:
        """Test builder build method for password generation."""
        builder = PasswordChangeBuilder()
        user_dn = "uid=test,ou=people,dc=example,dc=com"
        extension = builder.for_user(user_dn).generate_new_password().build()

        assert isinstance(extension, ModifyPasswordExtension)
        assert extension.user_identity == user_dn
        assert extension.old_password is None
        assert extension.new_password is None

    def test_builder_chaining(self) -> None:
        """Test builder method chaining."""
        builder = PasswordChangeBuilder()

        # All methods should return the same builder instance
        result = (
            builder.for_user("uid=test,dc=example,dc=com")
            .with_old_password("old123")
            .with_new_password("new456")
        )

        assert result is builder

    def test_builder_build_with_validation_error(self) -> None:
        """Test builder build with validation error."""
        builder = PasswordChangeBuilder()

        # This should trigger validation error for invalid DN
        with pytest.raises(PasswordValidationError):
            builder.for_user("invalid_dn").build()


class TestConvenienceFunctions:
    """Test cases for convenience functions."""

    def test_change_password_function(self) -> None:
        """Test change_password convenience function."""
        extension = change_password("old123", "new456")

        assert isinstance(extension, ModifyPasswordExtension)
        assert extension.user_identity is None
        assert extension.old_password == "old123"
        assert extension.new_password == "new456"

    def test_reset_password_function(self) -> None:
        """Test reset_password convenience function."""
        user_dn = "uid=test,ou=people,dc=example,dc=com"
        extension = reset_password(user_dn, "reset123")

        assert isinstance(extension, ModifyPasswordExtension)
        assert extension.user_identity == user_dn
        assert extension.old_password is None
        assert extension.new_password == "reset123"

    def test_generate_password_function(self) -> None:
        """Test generate_password convenience function."""
        user_dn = "uid=test,ou=people,dc=example,dc=com"
        extension = generate_password(user_dn)

        assert isinstance(extension, ModifyPasswordExtension)
        assert extension.user_identity == user_dn
        assert extension.old_password is None
        assert extension.new_password is None


class TestIntegrationScenarios:
    """Integration test scenarios."""

    def test_rfc_3062_compliance(self) -> None:
        """Test RFC 3062 compliance scenarios."""
        # Test case 1: Self-service password change
        extension1 = ModifyPasswordExtension.self_service_change("old123", "new456")

        assert extension1.request_name == ExtensionOIDs.MODIFY_PASSWORD
        assert extension1.is_self_service() is True
        assert extension1.requires_old_password() is True

        # Test case 2: Administrative password reset
        extension2 = ModifyPasswordExtension.REDACTED_LDAP_BIND_PASSWORD_reset(
            "uid=test,dc=example,dc=com",
            "reset123",
        )

        assert extension2.is_REDACTED_LDAP_BIND_PASSWORD_operation() is True
        assert extension2.requires_old_password() is False

        # Test case 3: Server-generated password
        extension3 = ModifyPasswordExtension.generate_password(
            "uid=test,dc=example,dc=com"
        )

        assert extension3.is_password_generation() is True

    def test_extension_request_response_cycle(self) -> None:
        """Test complete extension request/response cycle."""
        # 1. Create extension for password change
        extension = ModifyPasswordExtension.self_service_change("old123", "new456")

        # 2. Encode request
        request_value = extension.encode_request_value()
        assert len(request_value) > 0

        # 3. Simulate server response with generated password
        password = "server_generated_123"
        password_bytes = password.encode("utf-8")
        content = bytes([BER_CONTEXT_TAG_0, len(password_bytes)]) + password_bytes
        response_data = bytes([BER_SEQUENCE_TAG, len(content)]) + content

        # 4. Decode response
        result = ModifyPasswordExtension.decode_response_value(None, response_data)

        # 5. Verify result
        assert isinstance(result, ModifyPasswordResult)
        assert result.generated_password == password
        assert result.password_changed is True

    def test_multiple_operation_types(self) -> None:
        """Test multiple operation types."""
        operations = [
            ("self_service", ModifyPasswordExtension.self_service_change("old", "new")),
            (
                "REDACTED_LDAP_BIND_PASSWORD_reset",
                ModifyPasswordExtension.REDACTED_LDAP_BIND_PASSWORD_reset(
                    "uid=test,dc=example,dc=com", "reset"
                ),
            ),
            (
                "generate",
                ModifyPasswordExtension.generate_password("uid=test,dc=example,dc=com"),
            ),
            ("self_generate", ModifyPasswordExtension.self_service_generate()),
        ]

        for _name, extension in operations:
            assert isinstance(extension, ModifyPasswordExtension)
            assert extension.request_name == ExtensionOIDs.MODIFY_PASSWORD

            # All should be able to encode request
            encoded = extension.encode_request_value()
            assert isinstance(encoded, bytes)

    def test_error_handling_scenarios(self) -> None:
        """Test various error handling scenarios."""
        # Test encoding error (shouldn't happen with valid data)
        extension = ModifyPasswordExtension(
            user_identity="uid=test,dc=example,dc=com",
            new_password="test123",
        )

        # Should encode successfully
        encoded = extension.encode_request_value()
        assert len(encoded) > 0

        # Test decoding error
        with pytest.raises(ExtensionDecodingError):
            ModifyPasswordExtension.decode_response_value(None, b"\xff\xfe")


class TestSecurityValidation:
    """Security-focused test cases."""

    def test_password_validation_security(self) -> None:
        """Test password validation security."""
        # Test empty password rejection
        with pytest.raises(PasswordValidationError):
            ModifyPasswordExtension(old_password="")

        with pytest.raises(PasswordValidationError):
            ModifyPasswordExtension(new_password="")

        # None values should be allowed
        extension = ModifyPasswordExtension(
            old_password=None,
            new_password=None,
        )
        assert extension.old_password is None
        assert extension.new_password is None

    def test_user_identity_security_validation(self) -> None:
        """Test user identity security validation."""
        # Valid DN formats
        valid_dns = [
            "uid=test,ou=people,dc=example,dc=com",
            "cn=John Doe,ou=users,dc=company,dc=org",
            "mail=user@domain.com,dc=example,dc=com",
        ]

        for dn in valid_dns:
            extension = ModifyPasswordExtension(user_identity=dn)
            assert extension.user_identity == dn

        # Invalid DN formats
        invalid_dns = [
            "not_a_dn",
            "no_equals_sign",
            "123456",
        ]

        for dn in invalid_dns:
            with pytest.raises(PasswordValidationError):
                ModifyPasswordExtension(user_identity=dn)

    def test_asn1_encoding_security(self) -> None:
        """Test ASN.1 encoding security."""
        # Test with various special characters
        special_chars = [
            "password\x00with\x00nulls",
            "password\r\nwith\r\nnewlines",
            "password\x1b[31mwith\x1b[0mansi",
            "password\xffwith\xfehigh\xfdbytes",
        ]

        for password in special_chars:
            extension = ModifyPasswordExtension(new_password=password)

            # Should encode without crashing
            encoded = extension.encode_request_value()
            assert isinstance(encoded, bytes)
            assert len(encoded) > 0

    def test_unicode_password_handling(self) -> None:
        """Test Unicode password handling."""
        unicode_passwords = [
            "contraseña123",  # Spanish
            "пароль123",  # Russian
            "密码123",  # Chinese
            "パスワード123",  # Japanese
        ]

        for password in unicode_passwords:
            extension = ModifyPasswordExtension(
                old_password=password,
                new_password=password + "_new",
            )

            # Should encode and handle Unicode properly
            encoded = extension.encode_request_value()
            assert isinstance(encoded, bytes)
            assert len(encoded) > 0

    def test_generated_password_security(self) -> None:
        """Test generated password security handling."""
        # Simulate various generated passwords
        generated_passwords = [
            "simple123",
            "Complex!@#$%^&*()_+",
            "Unicode密码123",
            "Very" + "Long" * 20 + "Password",
        ]

        for password in generated_passwords:
            password_bytes = password.encode("utf-8")
            content = bytes([BER_CONTEXT_TAG_0, len(password_bytes)]) + password_bytes
            response_data = bytes([BER_SEQUENCE_TAG, len(content)]) + content

            result = ModifyPasswordExtension.decode_response_value(None, response_data)
            assert result.generated_password == password


class TestPerformanceValidation:
    """Performance-focused test cases."""

    def test_extension_creation_performance(self) -> None:
        """Test extension creation performance."""
        import time

        start_time = time.time()

        # Create many extension objects
        for i in range(1000):
            ModifyPasswordExtension(
                user_identity=f"uid=user{i},dc=example,dc=com",
                old_password=f"old{i}",
                new_password=f"new{i}",
            )

        creation_time = time.time() - start_time

        # Should create quickly
        assert creation_time < 1.0  # Less than 1 second for 1000 extensions

    def test_encoding_performance(self) -> None:
        """Test ASN.1 encoding performance."""
        import time

        extension = ModifyPasswordExtension(
            user_identity="uid=test,ou=people,dc=example,dc=com",
            old_password="current_password",
            new_password="new_password",
        )

        start_time = time.time()

        # Encode many times
        for _ in range(1000):
            extension.encode_request_value()

        encoding_time = time.time() - start_time

        # Should encode quickly
        assert encoding_time < 1.0  # Less than 1 second for 1000 encodings

    def test_decoding_performance(self) -> None:
        """Test ASN.1 decoding performance."""
        import time

        # Prepare response data
        password = "generated_password_123"
        password_bytes = password.encode("utf-8")
        content = bytes([BER_CONTEXT_TAG_0, len(password_bytes)]) + password_bytes
        response_data = bytes([BER_SEQUENCE_TAG, len(content)]) + content

        start_time = time.time()

        # Decode many times
        for _ in range(1000):
            ModifyPasswordExtension.decode_response_value(None, response_data)

        decoding_time = time.time() - start_time

        # Should decode quickly
        assert decoding_time < 1.0  # Less than 1 second for 1000 decodings


class TestErrorHandling:
    """Error handling test cases."""

    def test_validation_error_handling(self) -> None:
        """Test validation error handling."""
        # Test various validation scenarios
        validation_errors = [
            ("empty_old_password", {"old_password": ""}),
            ("empty_new_password", {"new_password": ""}),
            ("invalid_dn", {"user_identity": "invalid"}),
        ]

        for _error_name, kwargs in validation_errors:
            with pytest.raises(PasswordValidationError):
                ModifyPasswordExtension(**kwargs)

    def test_encoding_error_resilience(self) -> None:
        """Test encoding error resilience."""
        # Create extension with valid data
        extension = ModifyPasswordExtension(new_password="test123")

        # Should encode successfully
        encoded = extension.encode_request_value()
        assert isinstance(encoded, bytes)

    def test_decoding_error_handling(self) -> None:
        """Test decoding error handling."""
        # Test various malformed response data
        malformed_data = [
            b"\xff\xfe\xfd",  # Invalid ASN.1
            b"\x30\xff",  # Invalid length
            b"\x30\x02\xff\xfe",  # Invalid content
        ]

        for data in malformed_data:
            with pytest.raises(ExtensionDecodingError):
                ModifyPasswordExtension.decode_response_value(None, data)

    def test_builder_error_handling(self) -> None:
        """Test builder error handling."""
        # Builder should pass through validation errors
        builder = PasswordChangeBuilder()

        with pytest.raises(PasswordValidationError):
            builder.for_user("invalid_dn").build()


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
