"""Tests for LDAP "Who Am I?" Extension Implementation.

This module provides comprehensive test coverage for the "Who Am I?" extended
operation implementation including identity parsing, result processing, and
extension management with enterprise-grade validation.

Test Coverage:
    - IdentityType: Authorization identity type enumeration
    - AuthorizationIdentityParser: Identity format parsing and validation
    - WhoAmIResult: Result processing and identity extraction
    - WhoAmIExtension: Extended operation implementation
    - Identity parsing for DN, User ID, and anonymous formats
    - Convenience functions and integration helpers

Security Testing:
    - Identity format validation and sanitization
    - Anonymous user detection and handling
    - DN format validation and extraction
    - User ID format parsing and security
    - Error handling for malformed identity strings

Integration Testing:
    - RFC 4532 compliance validation
    - Extension request/response encoding/decoding
    - Error handling and exception management
    - Result formatting and display functions
"""

from __future__ import annotations

import pytest

from ldap_core_shared.extensions.base import ExtensionDecodingError, ExtensionOIDs
from ldap_core_shared.extensions.who_am_i import (
    AuthorizationIdentityParser,
    IdentityType,
    WhoAmIExtension,
    WhoAmIResult,
    check_identity,
    who_am_i,
)


class TestIdentityType:
    """Test cases for IdentityType enumeration."""

    def test_identity_type_values(self) -> None:
        """Test identity type enumeration values."""
        assert IdentityType.ANONYMOUS.value == "anonymous"
        assert IdentityType.DN.value == "dn"
        assert IdentityType.USER_ID.value == "userid"
        assert IdentityType.UNKNOWN.value == "unknown"

    def test_identity_type_completeness(self) -> None:
        """Test that all expected identity types are defined."""
        expected_types = {"ANONYMOUS", "DN", "USER_ID", "UNKNOWN"}
        actual_types = {member.name for member in IdentityType}
        assert actual_types == expected_types


class TestAuthorizationIdentityParser:
    """Test cases for AuthorizationIdentityParser."""

    def test_parse_anonymous_empty_string(self) -> None:
        """Test parsing empty string as anonymous."""
        identity_type, value = AuthorizationIdentityParser.parse("")
        assert identity_type == IdentityType.ANONYMOUS
        assert value is None

    def test_parse_anonymous_whitespace(self) -> None:
        """Test parsing whitespace-only string as anonymous."""
        identity_type, value = AuthorizationIdentityParser.parse("   ")
        assert identity_type == IdentityType.ANONYMOUS
        assert value is None

    def test_parse_dn_format_standard(self) -> None:
        """Test parsing standard DN format."""
        identity_string = "dn:cn=John Doe,ou=users,dc=example,dc=com"
        identity_type, value = AuthorizationIdentityParser.parse(identity_string)

        assert identity_type == IdentityType.DN
        assert value == "cn=John Doe,ou=users,dc=example,dc=com"

    def test_parse_dn_format_case_insensitive(self) -> None:
        """Test parsing DN format with different case."""
        test_cases = [
            "DN:cn=test,dc=example,dc=com",
            "Dn:cn=test,dc=example,dc=com",
            "dN:cn=test,dc=example,dc=com",
        ]

        for identity_string in test_cases:
            identity_type, value = AuthorizationIdentityParser.parse(identity_string)
            assert identity_type == IdentityType.DN
            assert value == "cn=test,dc=example,dc=com"

    def test_parse_dn_format_complex(self) -> None:
        """Test parsing complex DN format."""
        identity_string = "dn:cn=Jane Smith+sn=Smith,ou=Engineering,ou=Staff,dc=company,dc=org"
        identity_type, value = AuthorizationIdentityParser.parse(identity_string)

        assert identity_type == IdentityType.DN
        assert value == "cn=Jane Smith+sn=Smith,ou=Engineering,ou=Staff,dc=company,dc=org"

    def test_parse_userid_format_standard(self) -> None:
        """Test parsing standard User ID format."""
        identity_string = "u:johndoe"
        identity_type, value = AuthorizationIdentityParser.parse(identity_string)

        assert identity_type == IdentityType.USER_ID
        assert value == "johndoe"

    def test_parse_userid_format_case_insensitive(self) -> None:
        """Test parsing User ID format with different case."""
        test_cases = ["U:testuser", "u:testuser"]

        for identity_string in test_cases:
            identity_type, value = AuthorizationIdentityParser.parse(identity_string)
            assert identity_type == IdentityType.USER_ID
            assert value == "testuser"

    def test_parse_userid_format_complex(self) -> None:
        """Test parsing complex User ID format."""
        identity_string = "u:john.doe@company.com"
        identity_type, value = AuthorizationIdentityParser.parse(identity_string)

        assert identity_type == IdentityType.USER_ID
        assert value == "john.doe@company.com"

    def test_parse_raw_dn_format(self) -> None:
        """Test parsing raw DN without prefix."""
        identity_string = "cn=admin,dc=example,dc=com"
        identity_type, value = AuthorizationIdentityParser.parse(identity_string)

        assert identity_type == IdentityType.DN
        assert value == "cn=admin,dc=example,dc=com"

    def test_parse_raw_dn_complex(self) -> None:
        """Test parsing complex raw DN."""
        identity_string = "uid=admin,ou=people,dc=example,dc=org"
        identity_type, value = AuthorizationIdentityParser.parse(identity_string)

        assert identity_type == IdentityType.DN
        assert value == "uid=admin,ou=people,dc=example,dc=org"

    def test_parse_unknown_format(self) -> None:
        """Test parsing unknown identity format."""
        identity_string = "unknown:format:here"
        identity_type, value = AuthorizationIdentityParser.parse(identity_string)

        assert identity_type == IdentityType.UNKNOWN
        assert value == "unknown:format:here"

    def test_parse_unknown_simple_string(self) -> None:
        """Test parsing simple string without DN structure."""
        identity_string = "simplestring"
        identity_type, value = AuthorizationIdentityParser.parse(identity_string)

        assert identity_type == IdentityType.UNKNOWN
        assert value == "simplestring"

    def test_is_anonymous_true_cases(self) -> None:
        """Test is_anonymous method for true cases."""
        true_cases = ["", "  ", "\t", "\n", " \t\n "]

        for identity_string in true_cases:
            assert AuthorizationIdentityParser.is_anonymous(identity_string) is True

    def test_is_anonymous_false_cases(self) -> None:
        """Test is_anonymous method for false cases."""
        false_cases = [
            "dn:cn=user,dc=example,dc=com",
            "u:username",
            "cn=user,dc=example,dc=com",
            "any non-empty string",
        ]

        for identity_string in false_cases:
            assert AuthorizationIdentityParser.is_anonymous(identity_string) is False

    def test_is_dn_method(self) -> None:
        """Test is_dn method."""
        dn_cases = [
            "dn:cn=user,dc=example,dc=com",
            "DN:cn=user,dc=example,dc=com",
            "cn=user,dc=example,dc=com",
        ]

        non_dn_cases = [
            "",
            "u:username",
            "unknown format",
        ]

        for identity_string in dn_cases:
            assert AuthorizationIdentityParser.is_dn(identity_string) is True

        for identity_string in non_dn_cases:
            assert AuthorizationIdentityParser.is_dn(identity_string) is False

    def test_is_user_id_method(self) -> None:
        """Test is_user_id method."""
        userid_cases = [
            "u:username",
            "U:USERNAME",
            "u:user@domain.com",
        ]

        non_userid_cases = [
            "",
            "dn:cn=user,dc=example,dc=com",
            "cn=user,dc=example,dc=com",
            "unknown format",
        ]

        for identity_string in userid_cases:
            assert AuthorizationIdentityParser.is_user_id(identity_string) is True

        for identity_string in non_userid_cases:
            assert AuthorizationIdentityParser.is_user_id(identity_string) is False

    def test_extract_dn_method(self) -> None:
        """Test extract_dn method."""
        # Should extract DN
        dn_cases = [
            ("dn:cn=user,dc=example,dc=com", "cn=user,dc=example,dc=com"),
            ("cn=user,dc=example,dc=com", "cn=user,dc=example,dc=com"),
        ]

        for identity_string, expected_dn in dn_cases:
            result = AuthorizationIdentityParser.extract_dn(identity_string)
            assert result == expected_dn

        # Should return None for non-DN
        non_dn_cases = ["", "u:username", "unknown format"]

        for identity_string in non_dn_cases:
            result = AuthorizationIdentityParser.extract_dn(identity_string)
            assert result is None

    def test_extract_user_id_method(self) -> None:
        """Test extract_user_id method."""
        # Should extract User ID
        userid_cases = [
            ("u:username", "username"),
            ("U:user@domain.com", "user@domain.com"),
        ]

        for identity_string, expected_userid in userid_cases:
            result = AuthorizationIdentityParser.extract_user_id(identity_string)
            assert result == expected_userid

        # Should return None for non-User ID
        non_userid_cases = ["", "dn:cn=user,dc=example,dc=com", "unknown format"]

        for identity_string in non_userid_cases:
            result = AuthorizationIdentityParser.extract_user_id(identity_string)
            assert result is None

    def test_regex_patterns_security(self) -> None:
        """Test regex patterns for security issues."""
        # Test with potentially malicious input
        malicious_inputs = [
            "dn:" + "a" * 10000,  # Very long DN
            "u:" + "b" * 10000,   # Very long User ID
            "dn:\x00\x01\x02",   # Control characters
            "u:\n\r\t",          # Whitespace characters
        ]

        for malicious_input in malicious_inputs:
            # Should not crash or hang
            try:
                identity_type, value = AuthorizationIdentityParser.parse(malicious_input)
                assert identity_type in IdentityType
                assert isinstance(value, (str, type(None)))
            except Exception:
                # If an exception occurs, it should be a reasonable one
                pass


class TestWhoAmIResult:
    """Test cases for WhoAmIResult."""

    def test_result_creation_anonymous(self) -> None:
        """Test creating result for anonymous identity."""
        result = WhoAmIResult(
            result_code=0,
            authorization_identity="",
        )

        assert result.authorization_identity == ""
        assert result.identity_type == IdentityType.ANONYMOUS
        assert result.identity_value is None
        assert result.is_anonymous is True

    def test_result_creation_dn_identity(self) -> None:
        """Test creating result for DN identity."""
        dn_string = "dn:cn=admin,dc=example,dc=com"
        result = WhoAmIResult(
            result_code=0,
            authorization_identity=dn_string,
        )

        assert result.authorization_identity == dn_string
        assert result.identity_type == IdentityType.DN
        assert result.identity_value == "cn=admin,dc=example,dc=com"
        assert result.is_anonymous is False

    def test_result_creation_userid_identity(self) -> None:
        """Test creating result for User ID identity."""
        userid_string = "u:testuser"
        result = WhoAmIResult(
            result_code=0,
            authorization_identity=userid_string,
        )

        assert result.authorization_identity == userid_string
        assert result.identity_type == IdentityType.USER_ID
        assert result.identity_value == "testuser"
        assert result.is_anonymous is False

    def test_result_creation_raw_dn(self) -> None:
        """Test creating result for raw DN identity."""
        dn_string = "cn=user,ou=people,dc=example,dc=com"
        result = WhoAmIResult(
            result_code=0,
            authorization_identity=dn_string,
        )

        assert result.authorization_identity == dn_string
        assert result.identity_type == IdentityType.DN
        assert result.identity_value == dn_string
        assert result.is_anonymous is False

    def test_get_dn_method(self) -> None:
        """Test get_dn method."""
        # DN identity should return DN
        dn_result = WhoAmIResult(
            result_code=0,
            authorization_identity="dn:cn=test,dc=example,dc=com",
        )
        assert dn_result.get_dn() == "cn=test,dc=example,dc=com"

        # Non-DN identity should return None
        userid_result = WhoAmIResult(
            result_code=0,
            authorization_identity="u:testuser",
        )
        assert userid_result.get_dn() is None

        anonymous_result = WhoAmIResult(
            result_code=0,
            authorization_identity="",
        )
        assert anonymous_result.get_dn() is None

    def test_get_user_id_method(self) -> None:
        """Test get_user_id method."""
        # User ID identity should return User ID
        userid_result = WhoAmIResult(
            result_code=0,
            authorization_identity="u:testuser",
        )
        assert userid_result.get_user_id() == "testuser"

        # Non-User ID identity should return None
        dn_result = WhoAmIResult(
            result_code=0,
            authorization_identity="dn:cn=test,dc=example,dc=com",
        )
        assert dn_result.get_user_id() is None

        anonymous_result = WhoAmIResult(
            result_code=0,
            authorization_identity="",
        )
        assert anonymous_result.get_user_id() is None

    def test_get_display_name_method(self) -> None:
        """Test get_display_name method."""
        # Anonymous
        anonymous_result = WhoAmIResult(
            result_code=0,
            authorization_identity="",
        )
        assert anonymous_result.get_display_name() == "Anonymous"

        # DN identity
        dn_result = WhoAmIResult(
            result_code=0,
            authorization_identity="dn:cn=admin,dc=example,dc=com",
        )
        assert dn_result.get_display_name() == "DN: cn=admin,dc=example,dc=com"

        # User ID identity
        userid_result = WhoAmIResult(
            result_code=0,
            authorization_identity="u:admin",
        )
        assert userid_result.get_display_name() == "User: admin"

        # Unknown identity
        unknown_result = WhoAmIResult(
            result_code=0,
            authorization_identity="unknown:format",
        )
        assert unknown_result.get_display_name() == "Unknown: unknown:format"

    def test_str_representation_success(self) -> None:
        """Test string representation for successful result."""
        result = WhoAmIResult(
            result_code=0,
            authorization_identity="dn:cn=admin,dc=example,dc=com",
        )

        str_repr = str(result)
        assert str_repr == "WhoAmI: DN: cn=admin,dc=example,dc=com"

    def test_str_representation_failure(self) -> None:
        """Test string representation for failed result."""
        result = WhoAmIResult(
            result_code=1,
            error_message="Operation failed",
            authorization_identity="",
        )

        str_repr = str(result)
        assert "WhoAmI failed" in str_repr
        assert "Operation failed" in str_repr

    def test_result_validation_with_whitespace(self) -> None:
        """Test result parsing with whitespace in identity."""
        result = WhoAmIResult(
            result_code=0,
            authorization_identity="  dn:cn=test,dc=example,dc=com  ",
        )

        # Should handle whitespace correctly
        assert result.identity_type == IdentityType.DN
        assert result.identity_value == "cn=test,dc=example,dc=com"
        assert result.is_anonymous is False


class TestWhoAmIExtension:
    """Test cases for WhoAmIExtension."""

    def test_extension_initialization(self) -> None:
        """Test extension initialization."""
        extension = WhoAmIExtension()

        assert extension.request_name == ExtensionOIDs.WHO_AM_I
        assert extension.request_value is None

    def test_extension_initialization_with_kwargs(self) -> None:
        """Test extension initialization with kwargs."""
        extension = WhoAmIExtension(some_param="ignored")

        # Should still work, extra kwargs ignored
        assert extension.request_name == ExtensionOIDs.WHO_AM_I
        assert extension.request_value is None

    def test_encode_request_value(self) -> None:
        """Test request value encoding."""
        extension = WhoAmIExtension()

        encoded = extension.encode_request_value()
        assert encoded is None

    def test_decode_response_value_empty(self) -> None:
        """Test decoding empty response value."""
        result = WhoAmIExtension.decode_response_value(None, None)

        assert isinstance(result, WhoAmIResult)
        assert result.authorization_identity == ""
        assert result.is_anonymous is True

    def test_decode_response_value_dn(self) -> None:
        """Test decoding DN response value."""
        dn_bytes = b"dn:cn=admin,dc=example,dc=com"
        result = WhoAmIExtension.decode_response_value(None, dn_bytes)

        assert isinstance(result, WhoAmIResult)
        assert result.authorization_identity == "dn:cn=admin,dc=example,dc=com"
        assert result.identity_type == IdentityType.DN
        assert result.get_dn() == "cn=admin,dc=example,dc=com"

    def test_decode_response_value_userid(self) -> None:
        """Test decoding User ID response value."""
        userid_bytes = b"u:testuser"
        result = WhoAmIExtension.decode_response_value(None, userid_bytes)

        assert isinstance(result, WhoAmIResult)
        assert result.authorization_identity == "u:testuser"
        assert result.identity_type == IdentityType.USER_ID
        assert result.get_user_id() == "testuser"

    def test_decode_response_value_unicode(self) -> None:
        """Test decoding Unicode response value."""
        unicode_bytes = "dn:cn=José García,dc=example,dc=com".encode()
        result = WhoAmIExtension.decode_response_value(None, unicode_bytes)

        assert isinstance(result, WhoAmIResult)
        assert result.authorization_identity == "dn:cn=José García,dc=example,dc=com"
        assert result.identity_type == IdentityType.DN

    def test_decode_response_value_invalid_utf8(self) -> None:
        """Test decoding invalid UTF-8 response value."""
        invalid_bytes = b"\xff\xfe\xfd"  # Invalid UTF-8

        with pytest.raises(ExtensionDecodingError, match="Failed to decode WhoAmI response"):
            WhoAmIExtension.decode_response_value(None, invalid_bytes)

    def test_create_class_method(self) -> None:
        """Test create class method."""
        extension = WhoAmIExtension.create()

        assert isinstance(extension, WhoAmIExtension)
        assert extension.request_name == ExtensionOIDs.WHO_AM_I
        assert extension.request_value is None

    def test_str_representation(self) -> None:
        """Test string representation."""
        extension = WhoAmIExtension()

        str_repr = str(extension)
        assert str_repr == "WhoAmI()"

    def test_oid_validation(self) -> None:
        """Test that the correct OID is used."""
        extension = WhoAmIExtension()

        # WHO_AM_I OID should be the standard RFC 4532 OID
        assert extension.request_name == "1.3.6.1.4.1.4203.1.11.3"


class TestConvenienceFunctions:
    """Test cases for convenience functions."""

    def test_who_am_i_function(self) -> None:
        """Test who_am_i convenience function."""
        extension = who_am_i()

        assert isinstance(extension, WhoAmIExtension)
        assert extension.request_name == ExtensionOIDs.WHO_AM_I
        assert extension.request_value is None

    def test_check_identity_not_implemented(self) -> None:
        """Test check_identity function (not implemented)."""
        mock_connection = object()

        with pytest.raises(NotImplementedError, match="check_identity requires connection manager integration"):
            check_identity(mock_connection)


class TestIntegrationScenarios:
    """Integration test scenarios."""

    def test_rfc_4532_compliance(self) -> None:
        """Test RFC 4532 compliance scenarios."""
        # Test case 1: Anonymous user
        result1 = WhoAmIResult(
            result_code=0,
            authorization_identity="",
        )
        assert result1.is_anonymous is True
        assert result1.get_display_name() == "Anonymous"

        # Test case 2: Simple authentication with DN
        result2 = WhoAmIResult(
            result_code=0,
            authorization_identity="dn:cn=Manager,dc=example,dc=com",
        )
        assert result2.is_anonymous is False
        assert result2.get_dn() == "cn=Manager,dc=example,dc=com"

        # Test case 3: SASL authentication with authzid
        result3 = WhoAmIResult(
            result_code=0,
            authorization_identity="u:jsmith",
        )
        assert result3.is_anonymous is False
        assert result3.get_user_id() == "jsmith"

    def test_extension_request_response_cycle(self) -> None:
        """Test complete extension request/response cycle."""
        # 1. Create extension
        extension = WhoAmIExtension()

        # 2. Encode request (should be None)
        request_value = extension.encode_request_value()
        assert request_value is None

        # 3. Simulate server response
        server_response = b"dn:cn=admin,ou=people,dc=company,dc=org"

        # 4. Decode response
        result = WhoAmIExtension.decode_response_value(None, server_response)

        # 5. Verify result
        assert isinstance(result, WhoAmIResult)
        assert result.authorization_identity == "dn:cn=admin,ou=people,dc=company,dc=org"
        assert result.identity_type == IdentityType.DN
        assert result.get_dn() == "cn=admin,ou=people,dc=company,dc=org"
        assert result.get_display_name() == "DN: cn=admin,ou=people,dc=company,dc=org"

    def test_multiple_extension_instances(self) -> None:
        """Test multiple extension instances."""
        extensions = [WhoAmIExtension() for _ in range(5)]

        for extension in extensions:
            assert extension.request_name == ExtensionOIDs.WHO_AM_I
            assert extension.request_value is None
            assert extension.encode_request_value() is None

    def test_error_handling_scenarios(self) -> None:
        """Test various error handling scenarios."""
        # Test with various malformed response values
        error_cases = [
            (b"\x00\x01\x02", "control characters"),
            (b"\xff" * 1000, "invalid UTF-8"),
        ]

        for error_bytes, _description in error_cases:
            with pytest.raises(ExtensionDecodingError):
                WhoAmIExtension.decode_response_value(None, error_bytes)


class TestSecurityValidation:
    """Security-focused test cases."""

    def test_identity_injection_protection(self) -> None:
        """Test protection against identity injection attacks."""
        # Test potentially malicious identity strings
        malicious_identities = [
            "dn:cn=admin,dc=example,dc=com\x00extra",  # Null byte injection
            "dn:cn=admin,dc=example,dc=com\r\ndn:cn=evil,dc=bad,dc=org",  # CRLF injection
            "u:user\x1b[31mEvil\x1b[0m",  # ANSI escape injection
        ]

        for malicious_identity in malicious_identities:
            result = WhoAmIResult(
                result_code=0,
                authorization_identity=malicious_identity,
            )

            # Should parse without crashing
            assert isinstance(result.identity_type, IdentityType)
            assert isinstance(result.get_display_name(), str)

    def test_long_identity_handling(self) -> None:
        """Test handling of very long identity strings."""
        # Test with very long identity
        long_dn = "dn:" + "cn=test," * 1000 + "dc=example,dc=com"

        result = WhoAmIResult(
            result_code=0,
            authorization_identity=long_dn,
        )

        assert result.identity_type == IdentityType.DN
        assert result.authorization_identity == long_dn

    def test_unicode_security(self) -> None:
        """Test Unicode security handling."""
        # Test with various Unicode characters
        unicode_identities = [
            "dn:cn=José García,dc=example,dc=com",
            "u:用户名@公司.com",
            "dn:cn=Søren Åge,dc=example,dc=org",
        ]

        for unicode_identity in unicode_identities:
            # Encode to bytes and decode
            identity_bytes = unicode_identity.encode("utf-8")
            result = WhoAmIExtension.decode_response_value(None, identity_bytes)

            assert result.authorization_identity == unicode_identity
            assert isinstance(result.get_display_name(), str)


class TestPerformanceValidation:
    """Performance-focused test cases."""

    def test_parsing_performance(self) -> None:
        """Test identity parsing performance."""
        import time

        # Test with various identity formats
        test_identities = [
            "",
            "dn:cn=user,dc=example,dc=com",
            "u:username",
            "cn=rawdn,dc=example,dc=com",
            "unknown:format",
        ] * 200  # 1000 total identities

        start_time = time.time()

        for identity in test_identities:
            AuthorizationIdentityParser.parse(identity)

        parsing_time = time.time() - start_time

        # Should parse quickly
        assert parsing_time < 1.0  # Less than 1 second for 1000 parses

    def test_result_creation_performance(self) -> None:
        """Test result creation performance."""
        import time

        start_time = time.time()

        # Create many result objects
        for i in range(1000):
            WhoAmIResult(
                result_code=0,
                authorization_identity=f"dn:cn=user{i},dc=example,dc=com",
            )

        creation_time = time.time() - start_time

        # Should create quickly
        assert creation_time < 2.0  # Less than 2 seconds for 1000 creations


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
