"""Tests for SASL Authentication Exceptions.

This module provides comprehensive test coverage for the SASL exception
hierarchy including authentication, mechanism, security, callback, and
challenge errors with security-aware validation.

Test Coverage:
    - SASLError: Base exception for all SASL errors
    - SASLAuthenticationError: Authentication process failures
    - SASLInvalidMechanismError: Mechanism selection errors
    - SASLSecurityError: Security layer violations
    - SASLCallbackError: Callback handler failures
    - SASLChallengeError: Challenge-response processing errors
    - SASLMechanismError: Mechanism-specific errors
    - Convenience functions for common error scenarios

Security Testing:
    - Sensitive information detection and filtering
    - Security-aware error reporting
    - Context validation and sanitization
    - Error hierarchy and inheritance validation

Integration Testing:
    - LDAP authentication error integration
    - Error context preservation and accessibility
    - Type safety and proper error handling
"""

from __future__ import annotations

import pytest

from ldap_core_shared.exceptions.auth import AuthenticationError
from ldap_core_shared.protocols.sasl.exceptions import (
    SASLAuthenticationError,
    SASLCallbackError,
    SASLChallengeError,
    SASLError,
    SASLInvalidMechanismError,
    SASLMechanismError,
    SASLSecurityError,
    sasl_authentication_failed,
    sasl_callback_failed,
    sasl_mechanism_not_available,
)


class TestSASLError:
    """Test cases for SASLError base exception."""

    def test_basic_sasl_error_creation(self) -> None:
        """Test basic SASL error creation."""
        error = SASLError("Test SASL error")
        assert str(error) == "Test SASL error"
        assert error.mechanism is None
        assert error.challenge_step is None
        assert error.server_message is None

    def test_sasl_error_with_mechanism(self) -> None:
        """Test SASL error creation with mechanism."""
        error = SASLError(
            "Authentication failed",
            mechanism="DIGEST-MD5",
        )
        assert str(error) == "Authentication failed"
        assert error.mechanism == "DIGEST-MD5"
        assert "mechanism" in error.context
        assert error.context["mechanism"] == "DIGEST-MD5"

    def test_sasl_error_with_challenge_step(self) -> None:
        """Test SASL error creation with challenge step."""
        error = SASLError(
            "Challenge processing failed",
            mechanism="DIGEST-MD5",
            challenge_step=2,
        )
        assert error.challenge_step == 2
        assert error.context["challenge_step"] == 2

    def test_sasl_error_with_error_code(self) -> None:
        """Test SASL error creation with error code."""
        error = SASLError(
            "Authentication failed",
            error_code="invalid-credentials",
        )
        assert error.error_code == "invalid-credentials"

    def test_sasl_error_with_context(self) -> None:
        """Test SASL error creation with custom context."""
        custom_context = {"custom_field": "custom_value"}
        error = SASLError(
            "Test error",
            context=custom_context,
            mechanism="PLAIN",
        )
        assert error.context["custom_field"] == "custom_value"
        assert error.context["mechanism"] == "PLAIN"

    def test_sasl_error_with_original_error(self) -> None:
        """Test SASL error creation with original exception."""
        original = ValueError("Original error")
        error = SASLError(
            "SASL wrapper error",
            original_error=original,
        )
        assert error.original_error is original

    def test_sasl_error_inheritance(self) -> None:
        """Test SASL error inheritance from AuthenticationError."""
        error = SASLError("Test error")
        assert isinstance(error, AuthenticationError)
        assert isinstance(error, Exception)

    def test_sensitive_info_detection_password(self) -> None:
        """Test sensitive information detection for password-related content."""
        assert SASLError._contains_sensitive_info("password123") is True
        assert SASLError._contains_sensitive_info("Invalid password") is True
        assert SASLError._contains_sensitive_info("PASSWORD_ERROR") is True

    def test_sensitive_info_detection_credentials(self) -> None:
        """Test sensitive information detection for credential-related content."""
        assert SASLError._contains_sensitive_info("credential error") is True
        assert SASLError._contains_sensitive_info("CREDENTIAL_FAILED") is True
        assert SASLError._contains_sensitive_info("Invalid credentials") is True

    def test_sensitive_info_detection_tokens(self) -> None:
        """Test sensitive information detection for token-related content."""
        assert SASLError._contains_sensitive_info("token expired") is True
        assert SASLError._contains_sensitive_info("SECRET_KEY_ERROR") is True
        assert SASLError._contains_sensitive_info("digest mismatch") is True

    def test_sensitive_info_detection_safe_content(self) -> None:
        """Test sensitive information detection for safe content."""
        assert SASLError._contains_sensitive_info("connection timeout") is False
        assert SASLError._contains_sensitive_info("invalid mechanism") is False
        assert SASLError._contains_sensitive_info("server unavailable") is False

    def test_server_message_filtering(self) -> None:
        """Test server message filtering for sensitive content."""
        # Safe server message should be included
        error = SASLError(
            "Test error",
            server_message="Connection timeout",
        )
        assert error.server_message == "Connection timeout"
        assert "server_message" in error.context

        # Sensitive server message should be filtered
        error = SASLError(
            "Test error",
            server_message="Invalid password provided",
        )
        assert error.server_message == "Invalid password provided"
        assert "server_message" not in error.context


class TestSASLAuthenticationError:
    """Test cases for SASLAuthenticationError."""

    def test_basic_authentication_error(self) -> None:
        """Test basic authentication error creation."""
        error = SASLAuthenticationError()
        assert str(error) == "SASL authentication failed"
        assert isinstance(error, SASLError)
        assert error.auth_failure_reason is None

    def test_authentication_error_with_reason(self) -> None:
        """Test authentication error with failure reason."""
        error = SASLAuthenticationError(
            "Login failed",
            auth_failure_reason="Invalid credentials",
        )
        assert str(error) == "Login failed"
        assert error.auth_failure_reason == "Invalid credentials"
        assert error.context["auth_failure_reason"] == "Invalid credentials"

    def test_authentication_error_with_mechanism(self) -> None:
        """Test authentication error with mechanism."""
        error = SASLAuthenticationError(
            mechanism="PLAIN",
            error_code="auth-failed",
        )
        assert error.mechanism == "PLAIN"
        assert error.error_code == "auth-failed"

    def test_authentication_error_kwargs_handling(self) -> None:
        """Test authentication error kwargs type casting."""
        error = SASLAuthenticationError(
            "Test error",
            mechanism="DIGEST-MD5",
            challenge_step=1,
            server_message="Auth failed",
            error_code="invalid-response",
            context={"extra": "data"},
            auth_failure_reason="Bad password",
        )

        assert error.mechanism == "DIGEST-MD5"
        assert error.challenge_step == 1
        assert error.server_message == "Auth failed"
        assert error.error_code == "invalid-response"
        assert error.context["extra"] == "data"
        assert error.auth_failure_reason == "Bad password"


class TestSASLInvalidMechanismError:
    """Test cases for SASLInvalidMechanismError."""

    def test_basic_mechanism_error(self) -> None:
        """Test basic mechanism error creation."""
        error = SASLInvalidMechanismError()
        assert str(error) == "Invalid SASL mechanism"
        assert isinstance(error, SASLError)
        assert error.requested_mechanism is None
        assert error.available_mechanisms is None

    def test_mechanism_error_with_requested(self) -> None:
        """Test mechanism error with requested mechanism."""
        error = SASLInvalidMechanismError(
            "Mechanism not supported",
            requested_mechanism="GSSAPI",
        )
        assert str(error) == "Mechanism not supported"
        assert error.requested_mechanism == "GSSAPI"
        assert error.mechanism == "GSSAPI"  # Should be set from requested
        assert error.context["requested_mechanism"] == "GSSAPI"

    def test_mechanism_error_with_available(self) -> None:
        """Test mechanism error with available mechanisms."""
        available = ["PLAIN", "DIGEST-MD5", "CRAM-MD5"]
        error = SASLInvalidMechanismError(
            "Unsupported mechanism",
            requested_mechanism="GSSAPI",
            available_mechanisms=available,
        )
        assert error.available_mechanisms == available
        assert error.context["available_mechanisms"] == available

    def test_mechanism_error_kwargs_handling(self) -> None:
        """Test mechanism error kwargs type casting."""
        error = SASLInvalidMechanismError(
            "Test error",
            requested_mechanism="SCRAM-SHA-1",
            available_mechanisms=["PLAIN"],
            challenge_step=0,
            server_message="Mechanism not available",
            error_code="unsupported-mechanism",
        )

        assert error.requested_mechanism == "SCRAM-SHA-1"
        assert error.available_mechanisms == ["PLAIN"]
        assert error.challenge_step == 0
        assert error.server_message == "Mechanism not available"
        assert error.error_code == "unsupported-mechanism"


class TestSASLSecurityError:
    """Test cases for SASLSecurityError."""

    def test_basic_security_error(self) -> None:
        """Test basic security error creation."""
        error = SASLSecurityError()
        assert str(error) == "SASL security error"
        assert isinstance(error, SASLError)
        assert error.security_layer is None
        assert error.qop_requested is None
        assert error.qop_available is None

    def test_security_error_with_layer(self) -> None:
        """Test security error with security layer."""
        error = SASLSecurityError(
            "Security layer failed",
            security_layer="auth-conf",
        )
        assert str(error) == "Security layer failed"
        assert error.security_layer == "auth-conf"
        assert error.context["security_layer"] == "auth-conf"

    def test_security_error_with_qop(self) -> None:
        """Test security error with quality of protection."""
        error = SASLSecurityError(
            "QOP negotiation failed",
            qop_requested="auth-conf",
            qop_available=["auth", "auth-int"],
        )
        assert error.qop_requested == "auth-conf"
        assert error.qop_available == ["auth", "auth-int"]
        assert error.context["qop_requested"] == "auth-conf"
        assert error.context["qop_available"] == ["auth", "auth-int"]

    def test_security_error_kwargs_handling(self) -> None:
        """Test security error kwargs type casting."""
        error = SASLSecurityError(
            "Test error",
            mechanism="DIGEST-MD5",
            security_layer="auth-int",
            qop_requested="auth-conf",
            qop_available=["auth"],
            error_code="qop-not-supported",
        )

        assert error.mechanism == "DIGEST-MD5"
        assert error.security_layer == "auth-int"
        assert error.qop_requested == "auth-conf"
        assert error.qop_available == ["auth"]
        assert error.error_code == "qop-not-supported"


class TestSASLCallbackError:
    """Test cases for SASLCallbackError."""

    def test_basic_callback_error(self) -> None:
        """Test basic callback error creation."""
        error = SASLCallbackError()
        assert str(error) == "SASL callback error"
        assert isinstance(error, SASLError)
        assert error.callback_type is None
        assert error.callback_prompt is None

    def test_callback_error_with_type(self) -> None:
        """Test callback error with callback type."""
        error = SASLCallbackError(
            "Username callback failed",
            callback_type="NameCallback",
        )
        assert str(error) == "Username callback failed"
        assert error.callback_type == "NameCallback"
        assert error.context["callback_type"] == "NameCallback"

    def test_callback_error_with_safe_prompt(self) -> None:
        """Test callback error with safe prompt text."""
        error = SASLCallbackError(
            "Prompt failed",
            callback_type="TextInputCallback",
            callback_prompt="Enter username:",
        )
        assert error.callback_prompt == "Enter username:"
        assert error.context["callback_prompt"] == "Enter username:"

    def test_callback_error_with_sensitive_prompt(self) -> None:
        """Test callback error with sensitive prompt text."""
        error = SASLCallbackError(
            "Prompt failed",
            callback_type="PasswordCallback",
            callback_prompt="Enter password for user:",
        )
        assert error.callback_prompt == "Enter password for user:"
        # Should be filtered out due to sensitive content
        assert "callback_prompt" not in error.context

    def test_callback_error_kwargs_handling(self) -> None:
        """Test callback error kwargs type casting."""
        error = SASLCallbackError(
            "Test error",
            callback_type="RealmCallback",
            callback_prompt="Select realm:",
            mechanism="DIGEST-MD5",
            error_code="callback-failed",
        )

        assert error.callback_type == "RealmCallback"
        assert error.callback_prompt == "Select realm:"
        assert error.mechanism == "DIGEST-MD5"
        assert error.error_code == "callback-failed"


class TestSASLChallengeError:
    """Test cases for SASLChallengeError."""

    def test_basic_challenge_error(self) -> None:
        """Test basic challenge error creation."""
        error = SASLChallengeError()
        assert str(error) == "SASL challenge processing error"
        assert isinstance(error, SASLError)
        assert error.challenge_malformed is False
        assert error.response_invalid is False

    def test_challenge_error_malformed(self) -> None:
        """Test challenge error with malformed challenge."""
        error = SASLChallengeError(
            "Invalid challenge format",
            challenge_malformed=True,
        )
        assert str(error) == "Invalid challenge format"
        assert error.challenge_malformed is True
        assert error.context["challenge_malformed"] is True

    def test_challenge_error_invalid_response(self) -> None:
        """Test challenge error with invalid response."""
        error = SASLChallengeError(
            "Response validation failed",
            response_invalid=True,
        )
        assert str(error) == "Response validation failed"
        assert error.response_invalid is True
        assert error.context["response_invalid"] is True

    def test_challenge_error_both_flags(self) -> None:
        """Test challenge error with both error flags."""
        error = SASLChallengeError(
            "Challenge and response errors",
            challenge_malformed=True,
            response_invalid=True,
        )
        assert error.challenge_malformed is True
        assert error.response_invalid is True
        assert error.context["challenge_malformed"] is True
        assert error.context["response_invalid"] is True

    def test_challenge_error_kwargs_handling(self) -> None:
        """Test challenge error kwargs type casting."""
        error = SASLChallengeError(
            "Test error",
            mechanism="DIGEST-MD5",
            challenge_step=2,
            challenge_malformed=True,
            error_code="malformed-challenge",
        )

        assert error.mechanism == "DIGEST-MD5"
        assert error.challenge_step == 2
        assert error.challenge_malformed is True
        assert error.error_code == "malformed-challenge"


class TestSASLMechanismError:
    """Test cases for SASLMechanismError."""

    def test_basic_mechanism_error(self) -> None:
        """Test basic mechanism error creation."""
        error = SASLMechanismError()
        assert str(error) == "SASL mechanism error"
        assert isinstance(error, SASLError)
        assert error.mechanism_error is None
        assert error.mechanism_detail is None

    def test_mechanism_error_with_code(self) -> None:
        """Test mechanism error with error code."""
        error = SASLMechanismError(
            "GSSAPI ticket expired",
            mechanism_error="ticket-expired",
        )
        assert str(error) == "GSSAPI ticket expired"
        assert error.mechanism_error == "ticket-expired"
        assert error.context["mechanism_error"] == "ticket-expired"

    def test_mechanism_error_with_detail(self) -> None:
        """Test mechanism error with detail information."""
        detail = {"krb5_error": 68, "krb5_text": "KDC_ERR_CLIENT_REVOKED"}
        error = SASLMechanismError(
            "Kerberos error",
            mechanism="GSSAPI",
            mechanism_error="krb5-error",
            mechanism_detail=detail,
        )
        assert error.mechanism_detail == detail
        assert error.context["mechanism_detail"] == detail

    def test_mechanism_error_kwargs_handling(self) -> None:
        """Test mechanism error kwargs type casting."""
        error = SASLMechanismError(
            "Test error",
            mechanism="SCRAM-SHA-256",
            mechanism_error="iteration-count-mismatch",
            mechanism_detail={"expected": 4096, "received": 1024},
            error_code="mechanism-specific-error",
        )

        assert error.mechanism == "SCRAM-SHA-256"
        assert error.mechanism_error == "iteration-count-mismatch"
        assert error.mechanism_detail["expected"] == 4096
        assert error.error_code == "mechanism-specific-error"


class TestConvenienceFunctions:
    """Test cases for convenience error creation functions."""

    def test_sasl_authentication_failed(self) -> None:
        """Test sasl_authentication_failed convenience function."""
        error = sasl_authentication_failed(
            "PLAIN",
            "Invalid username or password",
        )

        assert isinstance(error, SASLAuthenticationError)
        assert str(error) == "SASL PLAIN authentication failed: Invalid username or password"
        assert error.mechanism == "PLAIN"
        assert error.auth_failure_reason == "Invalid username or password"

    def test_sasl_authentication_failed_with_kwargs(self) -> None:
        """Test sasl_authentication_failed with additional kwargs."""
        error = sasl_authentication_failed(
            "DIGEST-MD5",
            "Digest mismatch",
            challenge_step=3,
            error_code="invalid-digest",
        )

        assert error.mechanism == "DIGEST-MD5"
        assert error.auth_failure_reason == "Digest mismatch"
        assert error.challenge_step == 3
        assert error.error_code == "invalid-digest"

    def test_sasl_mechanism_not_available(self) -> None:
        """Test sasl_mechanism_not_available convenience function."""
        available = ["PLAIN", "DIGEST-MD5"]
        error = sasl_mechanism_not_available(
            "GSSAPI",
            available,
        )

        assert isinstance(error, SASLInvalidMechanismError)
        assert str(error) == "SASL mechanism 'GSSAPI' not available"
        assert error.requested_mechanism == "GSSAPI"
        assert error.available_mechanisms == available

    def test_sasl_mechanism_not_available_with_kwargs(self) -> None:
        """Test sasl_mechanism_not_available with additional kwargs."""
        error = sasl_mechanism_not_available(
            "SCRAM-SHA-512",
            ["PLAIN"],
            error_code="unsupported",
            server_message="Mechanism not supported",
        )

        assert error.requested_mechanism == "SCRAM-SHA-512"
        assert error.available_mechanisms == ["PLAIN"]
        assert error.error_code == "unsupported"
        assert error.server_message == "Mechanism not supported"

    def test_sasl_callback_failed(self) -> None:
        """Test sasl_callback_failed convenience function."""
        error = sasl_callback_failed(
            "PasswordCallback",
            "Password not provided",
        )

        assert isinstance(error, SASLCallbackError)
        assert str(error) == "SASL PasswordCallback callback failed: Password not provided"
        assert error.callback_type == "PasswordCallback"

    def test_sasl_callback_failed_with_kwargs(self) -> None:
        """Test sasl_callback_failed with various kwargs types."""
        error = sasl_callback_failed(
            "RealmCallback",
            "Realm selection failed",
            mechanism="DIGEST-MD5",
            challenge_step=1,
            server_message="Select realm",
            error_code="callback-timeout",
            context={"timeout": 30},
            original_error=TimeoutError("Callback timeout"),
        )

        assert error.callback_type == "RealmCallback"
        assert error.mechanism == "DIGEST-MD5"
        assert error.challenge_step == 1
        assert error.server_message == "Select realm"
        assert error.error_code == "callback-timeout"
        assert error.context["timeout"] == 30
        assert isinstance(error.original_error, TimeoutError)

    def test_sasl_callback_failed_kwargs_type_safety(self) -> None:
        """Test sasl_callback_failed kwargs type casting safety."""
        # Test with wrong types that should be filtered out
        error = sasl_callback_failed(
            "NameCallback",
            "Name not provided",
            mechanism=123,  # Wrong type - should be filtered
            challenge_step="not_int",  # Wrong type - should be filtered
            server_message=None,  # Wrong type - should be filtered
            error_code=["not_string"],  # Wrong type - should be filtered
            context="not_dict",  # Wrong type - should be filtered
            original_error="not_exception",  # Wrong type - should be filtered
        )

        assert error.callback_type == "NameCallback"
        assert error.mechanism is None
        assert error.challenge_step is None
        assert error.server_message is None
        assert error.error_code is None
        assert error.context is None
        assert error.original_error is None


class TestErrorHierarchy:
    """Test cases for error hierarchy and inheritance."""

    def test_all_errors_inherit_from_sasl_error(self) -> None:
        """Test that all SASL errors inherit from SASLError."""
        error_classes = [
            SASLAuthenticationError,
            SASLInvalidMechanismError,
            SASLSecurityError,
            SASLCallbackError,
            SASLChallengeError,
            SASLMechanismError,
        ]

        for error_class in error_classes:
            error = error_class()
            assert isinstance(error, SASLError)
            assert isinstance(error, AuthenticationError)
            assert isinstance(error, Exception)

    def test_error_context_inheritance(self) -> None:
        """Test that error context is properly inherited."""
        error = SASLAuthenticationError(
            "Test error",
            mechanism="PLAIN",
            auth_failure_reason="Bad password",
        )

        # Should have both base SASL context and specific context
        assert "mechanism" in error.context
        assert "auth_failure_reason" in error.context
        assert error.auth_method == "SASL"  # From AuthenticationError

    def test_error_str_representation(self) -> None:
        """Test string representation of errors."""
        errors = [
            SASLError("Base SASL error"),
            SASLAuthenticationError("Auth failed"),
            SASLInvalidMechanismError("Invalid mechanism"),
            SASLSecurityError("Security failure"),
            SASLCallbackError("Callback failed"),
            SASLChallengeError("Challenge failed"),
            SASLMechanismError("Mechanism error"),
        ]

        for error in errors:
            str_repr = str(error)
            assert isinstance(str_repr, str)
            assert len(str_repr) > 0


class TestSecurityValidation:
    """Security-focused test cases."""

    def test_sensitive_data_filtering(self) -> None:
        """Test filtering of sensitive data from context."""
        sensitive_messages = [
            "password123",
            "user password is invalid",
            "credential failure",
            "token abc123",
            "secret key mismatch",
            "digest verification failed",
            "nonce reuse detected",
            "response contains hash",
        ]

        for message in sensitive_messages:
            error = SASLError(
                "Test error",
                server_message=message,
            )
            # Server message should be stored but not in context
            assert error.server_message == message
            assert "server_message" not in error.context

    def test_safe_data_preservation(self) -> None:
        """Test preservation of safe data in context."""
        safe_messages = [
            "connection timeout",
            "invalid mechanism",
            "server unavailable",
            "protocol version mismatch",
            "network error",
            "malformed request",
        ]

        for message in safe_messages:
            error = SASLError(
                "Test error",
                server_message=message,
            )
            assert error.server_message == message
            assert "server_message" in error.context
            assert error.context["server_message"] == message

    def test_context_sanitization(self) -> None:
        """Test context sanitization for security."""
        error = SASLCallbackError(
            "Callback failed",
            callback_prompt="Enter password:",
            callback_type="PasswordCallback",
        )

        # Callback type should be preserved (not sensitive)
        assert "callback_type" in error.context
        # Prompt should be filtered (contains sensitive keyword)
        assert "callback_prompt" not in error.context

    def test_error_information_consistency(self) -> None:
        """Test consistency between error attributes and context."""
        error = SASLAuthenticationError(
            "Auth failed",
            mechanism="DIGEST-MD5",
            auth_failure_reason="Invalid credentials",
            challenge_step=2,
        )

        # Check attribute-context consistency
        assert error.mechanism == error.context["mechanism"]
        assert error.auth_failure_reason == error.context["auth_failure_reason"]
        assert error.challenge_step == error.context["challenge_step"]


class TestEdgeCases:
    """Edge case test scenarios."""

    def test_empty_mechanism_list(self) -> None:
        """Test handling of empty available mechanisms list."""
        error = SASLInvalidMechanismError(
            "No mechanisms available",
            requested_mechanism="PLAIN",
            available_mechanisms=[],
        )
        assert error.available_mechanisms == []
        assert error.context["available_mechanisms"] == []

    def test_none_values_handling(self) -> None:
        """Test handling of None values in parameters."""
        error = SASLError(
            "Test error",
            mechanism=None,
            challenge_step=None,
            server_message=None,
            error_code=None,
            context=None,
        )

        assert error.mechanism is None
        assert error.challenge_step is None
        assert error.server_message is None
        assert error.error_code is None
        assert isinstance(error.context, dict)

    def test_large_context_data(self) -> None:
        """Test handling of large context data."""
        large_context = {f"key_{i}": f"value_{i}" for i in range(1000)}
        error = SASLError(
            "Test error",
            context=large_context,
        )

        assert len(error.context) >= 1000
        assert all(f"key_{i}" in error.context for i in range(10))

    def test_unicode_error_messages(self) -> None:
        """Test handling of Unicode error messages."""
        unicode_message = "认证失败 - Authentication failed 🔒"
        error = SASLAuthenticationError(
            unicode_message,
            mechanism="PLAIN",
        )

        assert str(error) == unicode_message
        assert error.mechanism == "PLAIN"

    def test_mechanism_case_sensitivity(self) -> None:
        """Test mechanism name case sensitivity."""
        mechanisms = ["plain", "PLAIN", "Plain", "digest-md5", "DIGEST-MD5"]

        for mechanism in mechanisms:
            error = SASLError("Test", mechanism=mechanism)
            assert error.mechanism == mechanism
            assert error.context["mechanism"] == mechanism


class TestTypeValidation:
    """Type validation test cases."""

    def test_string_parameter_validation(self) -> None:
        """Test string parameter type validation."""
        error = SASLError(
            "Test error",
            mechanism="PLAIN",
            error_code="auth-failed",
            server_message="Server error",
        )

        assert isinstance(error.mechanism, str)
        assert isinstance(error.error_code, str)
        assert isinstance(error.server_message, str)

    def test_integer_parameter_validation(self) -> None:
        """Test integer parameter type validation."""
        error = SASLError(
            "Test error",
            challenge_step=5,
        )

        assert isinstance(error.challenge_step, int)
        assert error.challenge_step == 5

    def test_list_parameter_validation(self) -> None:
        """Test list parameter type validation."""
        mechanisms = ["PLAIN", "DIGEST-MD5", "SCRAM-SHA-1"]
        error = SASLInvalidMechanismError(
            "Test error",
            available_mechanisms=mechanisms,
        )

        assert isinstance(error.available_mechanisms, list)
        assert error.available_mechanisms == mechanisms

    def test_dict_parameter_validation(self) -> None:
        """Test dict parameter type validation."""
        context = {"extra": "data", "nested": {"key": "value"}}
        error = SASLError(
            "Test error",
            context=context,
        )

        assert isinstance(error.context, dict)
        assert error.context["extra"] == "data"
        assert error.context["nested"]["key"] == "value"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
