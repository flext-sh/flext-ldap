"""Test coverage for FlextLdapValidations missing lines.

This module provides surgical test coverage for specific uncovered lines
in validations.py to achieve 100% coverage.
"""

from flext_ldap.validations import FlextLdapValidations


class TestFlextLdapValidationsCoverage:
    """Test class for covering missing validation lines."""

    def test_validate_dn_with_whitespace_only(self) -> None:
        """Test validate_dn with whitespace-only string (covers line 25)."""
        # This should trigger the empty check on line 25
        result = FlextLdapValidations.validate_dn("   ")  # Only whitespace
        assert result.is_failure
        assert result.error is not None
        assert "cannot be empty" in result.error

    def test_validate_email_with_flext_models_error(self) -> None:
        """Test validate_email when FlextModels.EmailAddress.create fails (covers line 61)."""
        # This should trigger the error message formatting on line 61
        result = FlextLdapValidations.validate_email("invalid-email-format")
        assert result.is_failure
        assert result.error is not None
        assert "Email validation failed:" in result.error

    def test_validate_password_too_short(self) -> None:
        """Test validate_password with password too short (covers line 74)."""
        # This should trigger the min length check on line 74
        result = FlextLdapValidations.validate_password("ab")  # Only 2 chars
        assert result.is_failure
        assert result.error is not None
        assert "must be at least" in result.error

    def test_validate_password_too_long(self) -> None:
        """Test validate_password with password too long (covers line 79)."""
        # This should trigger the max length check on line 79
        long_password = "a" * 200  # Very long password
        result = FlextLdapValidations.validate_password(long_password)
        assert result.is_failure
        assert result.error is not None
        assert "must be no more than" in result.error
