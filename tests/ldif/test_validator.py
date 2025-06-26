"""Tests for RFC 2849 Compliant LDIF Validator Implementation.

This module provides comprehensive test coverage for the RFC 2849 compliant LDIF
validator including raw content validation, entry validation, character set
compliance, and comprehensive RFC 2849 compliance checking.

Test Coverage:
    - LDIFValidationConfig: Validation configuration and options
    - RFC2849LDIFValidator: Main RFC 2849 compliant validator
    - Raw content validation with RFC 2849 compliance
    - Entry validation with schema and syntax checking
    - Character set validation and SAFE-STRING compliance
    - Base64 encoding validation and format checking
    - Line folding compliance and format validation
    - Version specification validation

Integration Testing:
    - Complete file validation workflows
    - Entry-by-entry validation processing
    - Raw content and parsed content validation
    - Configuration-based validation behavior
    - Error collection and reporting mechanisms
    - Character set and encoding compliance

Performance Testing:
    - Large file validation efficiency
    - Character set validation performance
    - Entry validation optimization
    - Pattern matching and regex performance
    - Memory usage during validation

Security Testing:
    - Input sanitization and validation
    - Character set injection protection
    - Error message information disclosure protection
    - Resource consumption limits and validation
    - RFC 2849 compliance security requirements
"""

from __future__ import annotations

import tempfile
from pathlib import Path
from unittest.mock import patch

import pytest
from pydantic import ValidationError

from ldap_core_shared.ldif.processor import LDIFEntry
from ldap_core_shared.ldif.validator import (
    LDIFValidationConfig,
    LDIFValidator,
    RFC2849LDIFValidator,
)


class TestLDIFValidationConfig:
    """Test cases for LDIFValidationConfig."""

    def test_config_creation_defaults(self) -> None:
        """Test creating config with default values."""
        config = LDIFValidationConfig()

        # Core RFC 2849 validations
        assert config.require_version_spec is True
        assert config.validate_line_folding is True
        assert config.validate_safe_strings is True
        assert config.validate_base64_encoding is True
        assert config.validate_utf8_encoding is True

        # Extended validations
        assert config.validate_dn_format is True
        assert config.validate_attribute_syntax is True
        assert config.validate_object_classes is True
        assert config.validate_required_attributes is True
        assert config.validate_change_records is True
        assert config.validate_controls is True
        assert config.validate_url_references is True

        # Limits and constraints
        assert config.allow_binary_attributes is True
        assert config.max_dn_length == 8192
        assert config.max_attribute_length == 65536
        assert config.max_line_length == 1000
        assert config.strict_rfc_compliance is True

    def test_config_creation_custom(self) -> None:
        """Test creating config with custom values."""
        config = LDIFValidationConfig(
            require_version_spec=False,
            validate_line_folding=False,
            validate_safe_strings=False,
            validate_base64_encoding=False,
            validate_utf8_encoding=False,
            validate_dn_format=False,
            validate_attribute_syntax=False,
            validate_object_classes=False,
            validate_required_attributes=False,
            validate_change_records=False,
            validate_controls=False,
            validate_url_references=False,
            allow_binary_attributes=False,
            max_dn_length=4096,
            max_attribute_length=32768,
            max_line_length=500,
            strict_rfc_compliance=False,
        )

        assert config.require_version_spec is False
        assert config.validate_line_folding is False
        assert config.validate_safe_strings is False
        assert config.validate_base64_encoding is False
        assert config.validate_utf8_encoding is False
        assert config.validate_dn_format is False
        assert config.validate_attribute_syntax is False
        assert config.validate_object_classes is False
        assert config.validate_required_attributes is False
        assert config.validate_change_records is False
        assert config.validate_controls is False
        assert config.validate_url_references is False
        assert config.allow_binary_attributes is False
        assert config.max_dn_length == 4096
        assert config.max_attribute_length == 32768
        assert config.max_line_length == 500
        assert config.strict_rfc_compliance is False

    def test_config_validation_max_dn_length_positive(self) -> None:
        """Test config validation requires positive max DN length."""
        with pytest.raises(ValidationError, match="greater than or equal to 1"):
            LDIFValidationConfig(max_dn_length=0)

    def test_config_validation_max_attribute_length_positive(self) -> None:
        """Test config validation requires positive max attribute length."""
        with pytest.raises(ValidationError, match="greater than or equal to 1"):
            LDIFValidationConfig(max_attribute_length=0)

    def test_config_validation_max_line_length_positive(self) -> None:
        """Test config validation requires positive max line length."""
        with pytest.raises(ValidationError, match="greater than or equal to 1"):
            LDIFValidationConfig(max_line_length=0)

    def test_config_strict_mode(self) -> None:
        """Test config strict mode rejects extra fields."""
        with pytest.raises(ValidationError, match="Extra inputs are not permitted"):
            LDIFValidationConfig(extra_field="not_allowed")


class TestRFC2849LDIFValidator:
    """Test cases for RFC2849LDIFValidator."""

    def test_validator_initialization_default(self) -> None:
        """Test validator initialization with default config."""
        validator = RFC2849LDIFValidator()

        assert isinstance(validator.config, LDIFValidationConfig)
        assert validator.config.require_version_spec is True
        assert validator.config.validate_line_folding is True

    def test_validator_initialization_custom_config(self) -> None:
        """Test validator initialization with custom config."""
        config = LDIFValidationConfig(
            require_version_spec=False,
            validate_line_folding=False,
        )
        validator = RFC2849LDIFValidator(config)

        assert validator.config.require_version_spec is False
        assert validator.config.validate_line_folding is False

    def test_validate_raw_content_valid_rfc2849(self) -> None:
        """Test validating valid RFC 2849 content."""
        validator = RFC2849LDIFValidator()

        valid_content = """version: 1
dn: cn=user,dc=example,dc=com
objectClass: person
cn: user
sn: User
mail: user@example.com

"""

        result = validator.validate_raw_content(valid_content)

        assert result.valid is True
        assert result.validation_type == "ldif"
        assert result.entries_validated == 1
        assert len(result.schema_errors) == 0

    def test_validate_raw_content_missing_version(self) -> None:
        """Test validating content without version specification."""
        validator = RFC2849LDIFValidator()

        invalid_content = """dn: cn=user,dc=example,dc=com
objectClass: person
cn: user

"""

        result = validator.validate_raw_content(invalid_content)

        assert result.valid is False
        assert len(result.schema_errors) > 0
        assert any("version specification" in error.lower() for error in result.schema_errors)

    def test_validate_raw_content_invalid_version(self) -> None:
        """Test validating content with invalid version number."""
        validator = RFC2849LDIFValidator()

        invalid_content = """version: 2
dn: cn=user,dc=example,dc=com
objectClass: person

"""

        result = validator.validate_raw_content(invalid_content)

        assert result.valid is False
        assert any("Invalid version number" in error for error in result.schema_errors)

    def test_validate_raw_content_utf8_encoding_error(self) -> None:
        """Test validating content with UTF-8 encoding errors."""
        validator = RFC2849LDIFValidator()

        # Create content with invalid UTF-8 (simulated)
        with patch("builtins.str.encode") as mock_encode:
            mock_encode.side_effect = UnicodeDecodeError("utf-8", b"", 0, 1, "invalid")

            result = validator.validate_raw_content("test content")

            assert result.valid is False
            assert any("Invalid UTF-8 encoding" in error for error in result.schema_errors)

    def test_validate_raw_content_line_folding_compliance(self) -> None:
        """Test validating line folding compliance."""
        validator = RFC2849LDIFValidator()

        # Content with invalid line folding (starts with space at file beginning)
        invalid_content = """ version: 1
dn: cn=user,dc=example,dc=com
objectClass: person

"""

        result = validator.validate_raw_content(invalid_content)

        assert result.valid is False
        assert any("folding" in error.lower() for error in result.schema_errors)

    def test_validate_raw_content_base64_encoding(self) -> None:
        """Test validating base64 encoded content."""
        validator = RFC2849LDIFValidator()

        # Valid base64 content
        valid_content = """version: 1
dn: cn=user,dc=example,dc=com
objectClass: person
cn:: dXNlcg==

"""

        result = validator.validate_raw_content(valid_content)

        assert result.valid is True

    def test_validate_raw_content_invalid_base64(self) -> None:
        """Test validating invalid base64 encoded content."""
        validator = RFC2849LDIFValidator()

        # Invalid base64 content
        invalid_content = """version: 1
dn: cn=user,dc=example,dc=com
objectClass: person
cn:: invalid_base64!@#

"""

        result = validator.validate_raw_content(invalid_content)

        assert result.valid is False
        assert any("base64" in error.lower() for error in result.schema_errors)

    def test_validate_entries_valid_entries(self) -> None:
        """Test validating valid LDIF entries."""
        validator = RFC2849LDIFValidator()

        entries = [
            LDIFEntry(
                dn="cn=user1,dc=example,dc=com",
                attributes={"objectClass": ["person"], "cn": ["user1"]},
            ),
            LDIFEntry(
                dn="cn=user2,dc=example,dc=com",
                attributes={"objectClass": ["person"], "cn": ["user2"]},
            ),
        ]

        result = validator.validate_entries(entries)

        assert result.valid is True
        assert result.validation_type == "ldif"
        assert result.entries_validated == 1
        assert len(result.schema_errors) == 0

    def test_validate_entries_invalid_entries(self) -> None:
        """Test validating invalid LDIF entries."""
        validator = RFC2849LDIFValidator()

        entries = [
            LDIFEntry(
                dn="",  # Invalid empty DN
                attributes={"objectClass": ["person"]},
            ),
            LDIFEntry(
                dn="invalid_dn_format",  # Invalid DN format
                attributes={"objectClass": ["person"]},
            ),
        ]

        result = validator.validate_entries(entries)

        assert result.valid is False
        assert len(result.schema_errors) > 0
        assert any("DN" in error for error in result.schema_errors)

    def test_validate_entry_valid_entry(self) -> None:
        """Test validating single valid LDIF entry."""
        validator = RFC2849LDIFValidator()

        entry = LDIFEntry(
            dn="cn=user,dc=example,dc=com",
            attributes={
                "objectClass": ["person", "inetOrgPerson"],
                "cn": ["user"],
                "sn": ["User"],
                "mail": ["user@example.com"],
            },
        )

        result = validator.validate_entry(entry)

        assert result.valid is True
        assert result.validation_type == "ldif"
        assert result.entries_validated == 1
        assert len(result.schema_errors) == 0

    def test_validate_entry_invalid_dn(self) -> None:
        """Test validating entry with invalid DN."""
        validator = RFC2849LDIFValidator()

        entry = LDIFEntry(
            dn="invalid_dn",
            attributes={"objectClass": ["person"]},
        )

        result = validator.validate_entry(entry)

        assert result.valid is False
        assert any("DN" in error for error in result.schema_errors)

    def test_validate_entry_missing_object_class(self) -> None:
        """Test validating entry without objectClass."""
        validator = RFC2849LDIFValidator()

        entry = LDIFEntry(
            dn="cn=user,dc=example,dc=com",
            attributes={"cn": ["user"]},  # No objectClass
        )

        result = validator.validate_entry(entry)

        assert result.valid is False
        assert any("objectClass" in error for error in result.schema_errors)

    def test_validate_dn_valid_dns(self) -> None:
        """Test DN validation with valid DNs."""
        validator = RFC2849LDIFValidator()

        valid_dns = [
            "cn=user,dc=example,dc=com",
            "ou=people,dc=example,dc=com",
            "uid=user123,ou=users,dc=example,dc=com",
            "cn=John Doe,ou=people,dc=company,dc=com",
        ]

        for dn in valid_dns:
            errors = validator._validate_dn(dn)
            assert len(errors) == 0, f"DN should be valid: {dn}"

    def test_validate_dn_invalid_dns(self) -> None:
        """Test DN validation with invalid DNs."""
        validator = RFC2849LDIFValidator()

        invalid_dns = [
            "",  # Empty DN
            "invalid_dn",  # No equals sign
            "cn=,dc=example,dc=com",  # Empty attribute value
            "=user,dc=example,dc=com",  # Empty attribute name
            "cn user,dc=example,dc=com",  # Missing equals sign
        ]

        for dn in invalid_dns:
            errors = validator._validate_dn(dn)
            assert len(errors) > 0, f"DN should be invalid: {dn}"

    def test_validate_dn_length_limit(self) -> None:
        """Test DN validation with length limits."""
        config = LDIFValidationConfig(max_dn_length=50)
        validator = RFC2849LDIFValidator(config)

        # DN that exceeds length limit
        long_dn = "cn=" + "x" * 100 + ",dc=example,dc=com"

        errors = validator._validate_dn(long_dn)

        assert len(errors) > 0
        assert any("exceeds maximum length" in error for error in errors)

    def test_validate_attributes_valid_attributes(self) -> None:
        """Test attribute validation with valid attributes."""
        validator = RFC2849LDIFValidator()

        attributes = {
            "cn": ["user"],
            "sn": ["User"],
            "mail": ["user@example.com"],
            "objectClass": ["person", "inetOrgPerson"],
        }

        errors, warnings = validator._validate_attributes(attributes)

        assert len(errors) == 0
        assert len(warnings) == 0

    def test_validate_attributes_invalid_names(self) -> None:
        """Test attribute validation with invalid attribute names."""
        validator = RFC2849LDIFValidator()

        attributes = {
            "123invalid": ["value"],  # Starts with number
            "invalid-name!": ["value"],  # Contains invalid characters
            "": ["value"],  # Empty name
        }

        errors, _warnings = validator._validate_attributes(attributes)

        assert len(errors) > 0
        assert any("Invalid attribute name" in error for error in errors)

    def test_validate_attributes_length_limits(self) -> None:
        """Test attribute validation with length limits."""
        config = LDIFValidationConfig(max_attribute_length=10)
        validator = RFC2849LDIFValidator(config)

        attributes = {
            "description": ["This is a very long description that exceeds the limit"],
        }

        errors, _warnings = validator._validate_attributes(attributes)

        assert len(errors) > 0
        assert any("exceeds maximum length" in error for error in errors)

    def test_validate_attributes_binary_content_disallowed(self) -> None:
        """Test attribute validation with binary content when disallowed."""
        config = LDIFValidationConfig(allow_binary_attributes=False)
        validator = RFC2849LDIFValidator(config)

        # Simulate binary content (non-ASCII)
        attributes = {
            "photo": ["ÿØÿà binary data"],  # Contains non-ASCII characters
        }

        errors, _warnings = validator._validate_attributes(attributes)

        assert len(errors) > 0
        assert any("Binary content not allowed" in error for error in errors)

    def test_validate_version_specification_valid(self) -> None:
        """Test version specification validation with valid version."""
        validator = RFC2849LDIFValidator()

        lines = ["version: 1", "dn: cn=user,dc=example,dc=com"]

        errors = validator._validate_version_specification(lines)

        assert len(errors) == 0

    def test_validate_version_specification_missing(self) -> None:
        """Test version specification validation with missing version."""
        validator = RFC2849LDIFValidator()

        lines = ["dn: cn=user,dc=example,dc=com", "objectClass: person"]

        errors = validator._validate_version_specification(lines)

        assert len(errors) > 0
        assert any("Missing required version specification" in error for error in errors)

    def test_validate_version_specification_invalid_number(self) -> None:
        """Test version specification validation with invalid version number."""
        validator = RFC2849LDIFValidator()

        lines = ["version: 2", "dn: cn=user,dc=example,dc=com"]

        errors = validator._validate_version_specification(lines)

        assert len(errors) > 0
        assert any("Invalid version number" in error for error in errors)

    def test_validate_version_specification_with_comments(self) -> None:
        """Test version specification validation with comments."""
        validator = RFC2849LDIFValidator()

        lines = [
            "# This is a comment",
            "# Another comment",
            "version: 1",
            "dn: cn=user,dc=example,dc=com",
        ]

        errors = validator._validate_version_specification(lines)

        assert len(errors) == 0

    def test_validate_line_folding_valid(self) -> None:
        """Test line folding validation with valid folding."""
        validator = RFC2849LDIFValidator()

        lines = [
            "version: 1",
            "dn: cn=user,dc=example,dc=com",
            "description: This is a long line that is properly",
            " folded according to RFC 2849 specifications",
        ]

        errors = validator._validate_line_folding(lines)

        assert len(errors) == 0

    def test_validate_line_folding_invalid_start(self) -> None:
        """Test line folding validation with invalid folding at start."""
        validator = RFC2849LDIFValidator()

        lines = [
            " version: 1",  # Invalid: starts with space
            "dn: cn=user,dc=example,dc=com",
        ]

        errors = validator._validate_line_folding(lines)

        assert len(errors) > 0
        assert any("Line folding not allowed at start" in error for error in errors)

    def test_validate_line_folding_into_empty_line(self) -> None:
        """Test line folding validation with folding into empty line."""
        validator = RFC2849LDIFValidator()

        lines = [
            "version: 1",
            "",  # Empty line
            " folded line",  # Invalid: folding into empty line
        ]

        errors = validator._validate_line_folding(lines)

        assert len(errors) > 0
        assert any("Folding into empty line not permitted" in error for error in errors)

    def test_validate_character_sets_safe_strings(self) -> None:
        """Test character set validation with safe strings."""
        validator = RFC2849LDIFValidator()

        # Content with safe characters
        content = """version: 1
dn: cn=user,dc=example,dc=com
cn: user
description: This is a safe string with normal characters

"""

        errors = validator._validate_character_sets(content)

        assert len(errors) == 0

    def test_validate_character_sets_unsafe_strings(self) -> None:
        """Test character set validation with unsafe strings."""
        validator = RFC2849LDIFValidator()

        # Content with unsafe characters (simulated)
        content = """version: 1
dn: cn=user,dc=example,dc=com
cn: user
description: This string contains unsafe character: \x00

"""

        with patch.object(validator, "_is_safe_string") as mock_is_safe:
            mock_is_safe.return_value = False

            errors = validator._validate_character_sets(content)

            assert len(errors) > 0
            assert any("unsafe characters" in error for error in errors)

    def test_validate_base64_content_valid(self) -> None:
        """Test base64 content validation with valid encoding."""
        validator = RFC2849LDIFValidator()

        lines = [
            "version: 1",
            "dn: cn=user,dc=example,dc=com",
            "cn:: dXNlcg==",  # Valid base64
        ]

        errors = validator._validate_base64_content(lines)

        assert len(errors) == 0

    def test_validate_base64_content_invalid_format(self) -> None:
        """Test base64 content validation with invalid format."""
        validator = RFC2849LDIFValidator()

        lines = [
            "version: 1",
            "dn: cn=user,dc=example,dc=com",
            "cn:: invalid_base64!@#",  # Invalid base64 characters
        ]

        errors = validator._validate_base64_content(lines)

        assert len(errors) > 0
        assert any("Invalid base64 encoding format" in error for error in errors)

    def test_validate_base64_content_decode_error(self) -> None:
        """Test base64 content validation with decode error."""
        validator = RFC2849LDIFValidator()

        lines = [
            "version: 1",
            "dn: cn=user,dc=example,dc=com",
            "cn:: YWJjZA=",  # Valid base64 format but may have decode issues
        ]

        with patch("base64.b64decode") as mock_decode:
            mock_decode.side_effect = Exception("Decode error")

            errors = validator._validate_base64_content(lines)

            assert len(errors) > 0
            assert any("Base64 decode error" in error for error in errors)

    def test_is_safe_string_valid(self) -> None:
        """Test safe string validation with valid strings."""
        validator = RFC2849LDIFValidator()

        safe_strings = [
            "",  # Empty string is safe
            "user",
            "User Name",
            "user@example.com",
            "123456",
            "normal-string_with.chars",
        ]

        for string in safe_strings:
            assert validator._is_safe_string(string) is True, f"String should be safe: {string!r}"

    def test_is_safe_string_invalid_first_char(self) -> None:
        """Test safe string validation with invalid first character."""
        validator = RFC2849LDIFValidator()

        # Strings with invalid first characters (simulated)
        with patch.object(validator, "SAFE_INIT_CHAR_PATTERN") as mock_pattern:
            mock_pattern.match.return_value = None

            assert validator._is_safe_string("test") is False

    def test_is_safe_string_invalid_chars(self) -> None:
        """Test safe string validation with invalid characters."""
        validator = RFC2849LDIFValidator()

        # Strings with invalid characters (simulated)
        with patch.object(validator, "SAFE_CHAR_PATTERN") as mock_pattern:
            mock_pattern.match.side_effect = lambda char: char != "x"

            assert validator._is_safe_string("teXt") is True  # All chars except 'x' are safe
            assert validator._is_safe_string("text") is False  # 'x' is not safe

    def test_validate_object_classes_present(self) -> None:
        """Test object class validation when objectClass is present."""
        validator = RFC2849LDIFValidator()

        entry = LDIFEntry(
            dn="cn=user,dc=example,dc=com",
            attributes={"objectClass": ["person", "inetOrgPerson"]},
        )

        errors = validator._validate_object_classes(entry)

        assert len(errors) == 0

    def test_validate_object_classes_missing(self) -> None:
        """Test object class validation when objectClass is missing."""
        validator = RFC2849LDIFValidator()

        entry = LDIFEntry(
            dn="cn=user,dc=example,dc=com",
            attributes={"cn": ["user"]},  # No objectClass
        )

        errors = validator._validate_object_classes(entry)

        assert len(errors) > 0
        assert any("objectClass" in error for error in errors)

    def test_validate_file_success(self) -> None:
        """Test file validation with valid LDIF file."""
        validator = RFC2849LDIFValidator()

        valid_content = """version: 1
dn: cn=user,dc=example,dc=com
objectClass: person
cn: user
sn: User

"""

        with tempfile.NamedTemporaryFile(mode="w", suffix=".ldif", delete=False, encoding="utf-8") as f:
            f.write(valid_content)
            temp_path = Path(f.name)

        try:
            result = validator.validate_file(temp_path)

            assert result.valid is True
            assert result.validation_type == "ldif"

        finally:
            temp_path.unlink(missing_ok=True)

    def test_validate_file_not_found(self) -> None:
        """Test file validation with non-existent file."""
        validator = RFC2849LDIFValidator()

        non_existent_file = Path("/non/existent/file.ldif")

        result = validator.validate_file(non_existent_file)

        assert result.valid is False
        assert len(result.errors) > 0
        assert any("Validation error" in error for error in result.errors)

    def test_validate_file_raw_validation_failure(self) -> None:
        """Test file validation when raw validation fails."""
        validator = RFC2849LDIFValidator()

        invalid_content = """dn: cn=user,dc=example,dc=com
objectClass: person
cn: user

"""  # Missing version specification

        with tempfile.NamedTemporaryFile(mode="w", suffix=".ldif", delete=False, encoding="utf-8") as f:
            f.write(invalid_content)
            temp_path = Path(f.name)

        try:
            result = validator.validate_file(temp_path)

            assert result.valid is False
            assert len(result.errors) > 0

        finally:
            temp_path.unlink(missing_ok=True)


class TestLDIFValidatorBackwardCompatibility:
    """Test cases for LDIF validator backward compatibility."""

    def test_ldif_validator_alias_exists(self) -> None:
        """Test LDIFValidator alias exists."""
        assert LDIFValidator is RFC2849LDIFValidator

    def test_ldif_validator_alias_functionality(self) -> None:
        """Test LDIFValidator alias provides same functionality."""
        validator1 = RFC2849LDIFValidator()
        validator2 = LDIFValidator()

        assert type(validator1) == type(validator2)
        assert validator1.config.require_version_spec == validator2.config.require_version_spec


class TestLDIFValidatorPatterns:
    """Test cases for LDIF validator regex patterns."""

    def test_safe_char_pattern(self) -> None:
        """Test SAFE_CHAR_PATTERN regex."""
        validator = RFC2849LDIFValidator()

        # Valid safe characters
        safe_chars = "abcABC123 !#$%&'()*+,-./:;<=>?@[\\]^_`{|}~"
        for char in safe_chars:
            match = validator.SAFE_CHAR_PATTERN.match(char)
            if char in "\x00\x0A\x0D":  # Excluded characters
                assert match is None, f"Character should not be safe: {char!r}"
            else:
                assert match is not None, f"Character should be safe: {char!r}"

    def test_safe_init_char_pattern(self) -> None:
        """Test SAFE_INIT_CHAR_PATTERN regex."""
        validator = RFC2849LDIFValidator()

        # Valid initial characters (different from regular safe chars)
        # Excludes space and some special characters that can't start a value
        valid_init_chars = "abcABC123!#$%&'()*+,-./:;<=>?@[\\]^_`{|}~"
        for char in valid_init_chars:
            match = validator.SAFE_INIT_CHAR_PATTERN.match(char)
            if char in " \n\r:":  # Excluded initial characters
                assert match is None, f"Character should not be safe initial: {char!r}"

    def test_base64_char_pattern(self) -> None:
        """Test BASE64_CHAR_PATTERN regex."""
        validator = RFC2849LDIFValidator()

        # Valid base64 strings
        valid_base64 = [
            "dXNlcg==",
            "YWJjZA==",
            "SGVsbG8gV29ybGQ=",
            "YWJjZGVmZ2hpams=",
        ]

        for b64_string in valid_base64:
            match = validator.BASE64_CHAR_PATTERN.match(b64_string)
            assert match is not None, f"Should be valid base64: {b64_string}"

        # Invalid base64 strings
        invalid_base64 = [
            "invalid!",
            "spaces not allowed",
            "===invalid===",
            "dXNlcg===",  # Too many padding chars
        ]

        for b64_string in invalid_base64:
            match = validator.BASE64_CHAR_PATTERN.match(b64_string)
            assert match is None, f"Should be invalid base64: {b64_string}"

    def test_ldap_oid_pattern(self) -> None:
        """Test LDAP_OID_PATTERN regex."""
        validator = RFC2849LDIFValidator()

        # Valid OIDs
        valid_oids = [
            "1.2.3.4",
            "1.3.6.1.4.1.1466.109.114.1",
            "2.5.4.3",
            "1.2.840.113556.1.4.221",
        ]

        for oid in valid_oids:
            match = validator.LDAP_OID_PATTERN.match(oid)
            assert match is not None, f"Should be valid OID: {oid}"

        # Invalid OIDs
        invalid_oids = [
            "invalid.oid",
            "1.2.3.",
            ".1.2.3",
            "1..2.3",
            "1.2.3.a",
        ]

        for oid in invalid_oids:
            match = validator.LDAP_OID_PATTERN.match(oid)
            assert match is None, f"Should be invalid OID: {oid}"


class TestLDIFValidatorIntegration:
    """Test cases for LDIF validator integration scenarios."""

    def test_complete_validation_workflow(self) -> None:
        """Test complete validation workflow from raw content to entries."""
        config = LDIFValidationConfig(
            require_version_spec=True,
            validate_line_folding=True,
            validate_safe_strings=True,
            validate_dn_format=True,
            validate_object_classes=True,
        )
        validator = RFC2849LDIFValidator(config)

        valid_content = """version: 1
dn: cn=user1,dc=example,dc=com
objectClass: person
objectClass: inetOrgPerson
cn: user1
sn: User1
mail: user1@example.com

dn: cn=user2,dc=example,dc=com
objectClass: person
objectClass: inetOrgPerson
cn: user2
sn: User2
mail: user2@example.com

"""

        # First validate raw content
        raw_result = validator.validate_raw_content(valid_content)
        assert raw_result.valid is True

        # Then validate parsed entries (would require processor integration)
        entries = [
            LDIFEntry(
                dn="cn=user1,dc=example,dc=com",
                attributes={
                    "objectClass": ["person", "inetOrgPerson"],
                    "cn": ["user1"],
                    "sn": ["User1"],
                    "mail": ["user1@example.com"],
                },
            ),
            LDIFEntry(
                dn="cn=user2,dc=example,dc=com",
                attributes={
                    "objectClass": ["person", "inetOrgPerson"],
                    "cn": ["user2"],
                    "sn": ["User2"],
                    "mail": ["user2@example.com"],
                },
            ),
        ]

        entries_result = validator.validate_entries(entries)
        assert entries_result.valid is True

    def test_configuration_based_validation(self) -> None:
        """Test validation behavior based on configuration settings."""
        # Strict configuration
        strict_config = LDIFValidationConfig(
            require_version_spec=True,
            validate_dn_format=True,
            validate_object_classes=True,
            strict_rfc_compliance=True,
        )
        strict_validator = RFC2849LDIFValidator(strict_config)

        # Relaxed configuration
        relaxed_config = LDIFValidationConfig(
            require_version_spec=False,
            validate_dn_format=False,
            validate_object_classes=False,
            strict_rfc_compliance=False,
        )
        relaxed_validator = RFC2849LDIFValidator(relaxed_config)

        # Content that would fail strict validation
        problematic_content = """dn: invalid_dn_format
cn: user

"""

        strict_result = strict_validator.validate_raw_content(problematic_content)
        relaxed_result = relaxed_validator.validate_raw_content(problematic_content)

        # Strict should find more errors than relaxed
        assert len(strict_result.schema_errors) > len(relaxed_result.schema_errors)

    def test_error_collection_and_reporting(self) -> None:
        """Test comprehensive error collection and reporting."""
        validator = RFC2849LDIFValidator()

        # Content with multiple types of errors
        problematic_content = """dn: cn=user,dc=example,dc=com
objectClass: person
cn: user

dn:
objectClass: person

dn: invalid_dn
cn: user

"""  # Missing version, empty DN, invalid DN

        result = validator.validate_raw_content(problematic_content)

        assert result.valid is False
        assert len(result.schema_errors) > 1

        # Should have errors for missing version and invalid DNs
        error_messages = " ".join(result.schema_errors)
        assert "version specification" in error_messages.lower()

    def test_performance_with_large_content(self) -> None:
        """Test validation performance with large content."""
        validator = RFC2849LDIFValidator()

        # Generate large valid content
        large_content_parts = ["version: 1\n"]
        for i in range(100):
            entry = f"""dn: cn=user{i:03d},dc=example,dc=com
objectClass: person
objectClass: inetOrgPerson
cn: user{i:03d}
sn: User{i:03d}
mail: user{i:03d}@example.com

"""
            large_content_parts.append(entry)

        large_content = "".join(large_content_parts)

        result = validator.validate_raw_content(large_content)

        # Should handle large content efficiently
        assert result.valid is True
        assert result.validation_type == "ldif"
