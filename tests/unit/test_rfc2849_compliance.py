"""RFC 2849 Compliance Test Suite - Comprehensive LDIF Format Validation.

This test suite validates complete RFC 2849 compliance for the LDIF processor,
covering all formal syntax requirements, examples from the RFC, and edge cases.

Test Coverage:
    - Version specification handling
    - Line folding and continuation
    - Base64 encoding/decoding
    - SAFE-STRING validation
    - Change record processing (add, delete, modify, modrdn)
    - Control specification parsing
    - URL reference support
    - Comment handling
    - UTF-8 validation
    - Error handling for malformed LDIF

All test cases are based on RFC 2849 examples and formal syntax definitions.
"""

from __future__ import annotations

import base64
import tempfile
from pathlib import Path
from unittest.mock import patch

import pytest

from ldap_core_shared.ldif.processor import (
    LDIFEntry,
    RFC2849LDIFProcessor,
)
from ldap_core_shared.ldif.validator import (
    RFC2849LDIFValidator,
)


class TestRFC2849VersionSpecification:
    """Test RFC 2849 version specification handling."""

    def test_valid_version_specification(self) -> None:
        """Test parsing LDIF with valid version: 1 specification."""
        processor = RFC2849LDIFProcessor()

        ldif_content = """version: 1
dn: cn=test,dc=example,dc=com
cn: test
objectClass: person
"""

        result = processor.parse_string(ldif_content)

        assert result.success is True
        assert processor._stats["version_found"] is True
        assert len(result.data) == 1
        assert result.data[0].dn == "cn=test,dc=example,dc=com"

    def test_missing_version_specification(self) -> None:
        """Test LDIF without version specification (should still parse but warn)."""
        processor = RFC2849LDIFProcessor()

        ldif_content = """dn: cn=test,dc=example,dc=com
cn: test
objectClass: person
"""

        result = processor.parse_string(ldif_content)

        assert result.success is True
        assert processor._stats["version_found"] is False
        assert len(result.data) == 1

    def test_invalid_version_number(self) -> None:
        """Test LDIF with invalid version number."""
        validator = RFC2849LDIFValidator()

        ldif_content = """version: 2
dn: cn=test,dc=example,dc=com
cn: test
"""

        result = validator.validate_raw_content(ldif_content)

        assert result.is_valid is False
        assert any("Invalid version number: 2" in error for error in result.errors)


class TestRFC2849LineFolding:
    """Test RFC 2849 line folding and continuation handling."""

    def test_line_folding_basic(self) -> None:
        """Test basic line folding with space continuation."""
        processor = RFC2849LDIFProcessor()

        # RFC 2849 Example 2 - folded description
        ldif_content = """version: 1
dn: cn=Barbara Jensen, ou=Product Development, dc=airius, dc=com
objectclass: top
objectclass: person
cn: Barbara Jensen
description: Babs is a big sailing fan, and travels extensively in sea
 rch of perfect sailing conditions.
"""

        result = processor.parse_string(ldif_content)

        assert result.success is True
        assert len(result.data) == 1

        entry = result.data[0]
        description = entry.get_attribute_values("description")[0]
        assert "search of perfect sailing conditions" in description
        assert processor._stats["lines_folded"] > 0

    def test_multiple_line_folding(self) -> None:
        """Test multiple consecutive line folding."""
        processor = RFC2849LDIFProcessor()

        ldif_content = """version: 1
dn: cn=test,dc=example,dc=com
description: This is a very long description that spans
 multiple lines and demonstrates the line folding
 capability of RFC 2849 compliant LDIF processors
 and ensures proper handling of continuation lines.
"""

        result = processor.parse_string(ldif_content)

        assert result.success is True
        entry = result.data[0]
        description = entry.get_attribute_values("description")[0]

        expected = ("This is a very long description that spans"
                   "multiple lines and demonstrates the line folding"
                   "capability of RFC 2849 compliant LDIF processors"
                   "and ensures proper handling of continuation lines.")
        assert description == expected

    def test_invalid_line_folding_empty_previous_line(self) -> None:
        """Test invalid line folding into empty line."""
        validator = RFC2849LDIFValidator()

        ldif_content = """version: 1
dn: cn=test,dc=example,dc=com

 invalid continuation after empty line
"""

        result = validator.validate_raw_content(ldif_content)

        assert result.is_valid is False
        assert any("Folding into empty line not permitted" in error for error in result.errors)


class TestRFC2849Base64Encoding:
    """Test RFC 2849 base64 encoding and decoding."""

    def test_base64_encoded_dn(self) -> None:
        """Test parsing base64 encoded DN."""
        processor = RFC2849LDIFProcessor()

        # Base64 encode a DN with non-ASCII characters
        dn_utf8 = "cn=山田太郎,dc=example,dc=com"
        dn_base64 = base64.b64encode(dn_utf8.encode("utf-8")).decode("ascii")

        ldif_content = f"""version: 1
dn:: {dn_base64}
cn: 山田太郎
objectClass: person
"""

        result = processor.parse_string(ldif_content)

        assert result.success is True
        assert len(result.data) == 1
        assert result.data[0].dn == dn_utf8
        assert processor._stats["base64_decoded"] > 0

    def test_base64_encoded_attribute_value(self) -> None:
        """Test RFC 2849 Example 3 - base64 encoded attribute value."""
        processor = RFC2849LDIFProcessor()

        # RFC 2849 Example 3
        ldif_content = """version: 1
dn: cn=Gern Jensen, ou=Product Testing, dc=airius, dc=com
objectclass: top
objectclass: person
cn: Gern Jensen
description:: V2hhdCBhIGNhcmVmdWwgcmVhZGVyIHlvdSBhcmUhICBUaGlzIHZhbHVl
 IGlzIGJhc2UtNjQtZW5jb2RlZCBiZWNhdXNlIGl0IGhhcyBhIGNvbnRyb2wgY2hhcmFjdG
 VyIGluIGl0IChhIENSKS4NICBCeSB0aGUgd2F5LCB5b3Ugc2hvdWxkIHJlYWxseSBnZXQg
 b3V0IG1vcmUu
"""

        result = processor.parse_string(ldif_content)

        assert result.success is True
        entry = result.data[0]

        # The base64 value should decode to include control characters
        description = entry.get_attribute_values("description")[0]
        assert "What a careful reader you are!" in description
        assert "\r" in description  # Contains CR control character

    def test_invalid_base64_encoding(self) -> None:
        """Test invalid base64 encoding handling."""
        validator = RFC2849LDIFValidator()

        ldif_content = """version: 1
dn: cn=test,dc=example,dc=com
description:: InvalidBase64Characters!@#$
"""

        result = validator.validate_raw_content(ldif_content)

        assert result.is_valid is False
        assert any("Base64 decode error" in error for error in result.errors)


class TestRFC2849SafeStringValidation:
    """Test RFC 2849 SAFE-STRING character set validation."""

    def test_safe_string_valid_characters(self) -> None:
        """Test valid SAFE-STRING characters."""
        processor = RFC2849LDIFProcessor()

        ldif_content = """version: 1
dn: cn=test,dc=example,dc=com
cn: test123-value_with.safe@characters
objectClass: person
"""

        result = processor.parse_string(ldif_content)

        assert result.success is True
        assert len(result.data) == 1

    def test_unsafe_string_requires_base64(self) -> None:
        """Test that unsafe strings should be base64 encoded."""
        validator = RFC2849LDIFValidator()

        # String with control characters (should be base64 encoded)
        ldif_content = """version: 1
dn: cn=test,dc=example,dc=com
description: This contains a control character \\x01 here
"""

        result = validator.validate_raw_content(ldif_content)

        # Should warn that unsafe characters should be base64 encoded
        assert any("unsafe characters" in error.lower() for error in result.errors)

    def test_safe_init_char_validation(self) -> None:
        """Test SAFE-INIT-CHAR validation for first character."""
        processor = RFC2849LDIFProcessor()

        # Test string starting with valid SAFE-INIT-CHAR
        ldif_content = """version: 1
dn: cn=test,dc=example,dc=com
cn: validStart
objectClass: person
"""

        result = processor.parse_string(ldif_content)
        assert result.success is True


class TestRFC2849ChangeRecords:
    """Test RFC 2849 change record processing."""

    def test_add_change_record(self) -> None:
        """Test add change record processing."""
        processor = RFC2849LDIFProcessor()

        ldif_content = """version: 1
dn: cn=newuser,dc=example,dc=com
changetype: add
objectClass: person
objectClass: inetOrgPerson
cn: newuser
sn: User
mail: newuser@example.com
"""

        result = processor.parse_string(ldif_content)

        assert result.success is True
        assert len(result.data) == 1

        entry = result.data[0]
        assert entry.change_record is not None
        assert entry.change_record.changetype == "add"
        assert "objectClass" in entry.change_record.attributes
        assert processor._stats["change_records"] == 1

    def test_delete_change_record(self) -> None:
        """Test delete change record processing."""
        processor = RFC2849LDIFProcessor()

        ldif_content = """version: 1
dn: cn=olduser,dc=example,dc=com
changetype: delete
"""

        result = processor.parse_string(ldif_content)

        assert result.success is True
        entry = result.data[0]
        assert entry.change_record is not None
        assert entry.change_record.changetype == "delete"

    def test_modify_change_record(self) -> None:
        """Test modify change record processing."""
        processor = RFC2849LDIFProcessor()

        ldif_content = """version: 1
dn: cn=user,dc=example,dc=com
changetype: modify
add: mail
mail: user@example.com
-
replace: telephoneNumber
telephoneNumber: +1-555-1234
-
delete: description
-
"""

        result = processor.parse_string(ldif_content)

        assert result.success is True
        entry = result.data[0]
        assert entry.change_record is not None
        assert entry.change_record.changetype == "modify"
        assert len(entry.change_record.modifications) == 3

        # Verify modification operations
        mods = entry.change_record.modifications
        assert mods[0]["operation"] == "add"
        assert mods[0]["attribute"] == "mail"
        assert mods[1]["operation"] == "replace"
        assert mods[2]["operation"] == "delete"

    def test_modrdn_change_record(self) -> None:
        """Test modrdn change record processing."""
        processor = RFC2849LDIFProcessor()

        ldif_content = """version: 1
dn: cn=oldname,dc=example,dc=com
changetype: modrdn
newrdn: cn=newname
deleteoldrdn: 1
newsuperior: ou=people,dc=example,dc=com
"""

        result = processor.parse_string(ldif_content)

        assert result.success is True
        entry = result.data[0]
        assert entry.change_record is not None
        assert entry.change_record.changetype == "modrdn"
        assert entry.change_record.new_rdn == "cn=newname"
        assert entry.change_record.delete_old_rdn is True
        assert entry.change_record.new_superior == "ou=people,dc=example,dc=com"


class TestRFC2849ControlSpecifications:
    """Test RFC 2849 control specification parsing."""

    def test_control_specification_basic(self) -> None:
        """Test basic control specification parsing."""
        processor = RFC2849LDIFProcessor()

        ldif_content = """version: 1
dn: cn=test,dc=example,dc=com
control: 2.16.840.1.113730.3.4.2 true
changetype: add
objectClass: person
cn: test
"""

        result = processor.parse_string(ldif_content)

        assert result.success is True
        entry = result.data[0]
        assert len(entry.controls) == 1

        control = entry.controls[0]
        assert control.control_type == "2.16.840.1.113730.3.4.2"
        assert control.criticality is True
        assert processor._stats["controls_processed"] == 1

    def test_control_with_value(self) -> None:
        """Test control specification with control value."""
        processor = RFC2849LDIFProcessor()

        ldif_content = """version: 1
dn: cn=test,dc=example,dc=com
control: 1.2.840.113556.1.4.319 false :MTAw
changetype: add
objectClass: person
cn: test
"""

        result = processor.parse_string(ldif_content)

        assert result.success is True
        entry = result.data[0]
        control = entry.controls[0]
        assert control.control_type == "1.2.840.113556.1.4.319"
        assert control.criticality is False
        assert control.control_value == "MTAw"

    def test_invalid_control_oid(self) -> None:
        """Test invalid control OID handling."""
        validator = RFC2849LDIFValidator()

        # Create an entry with invalid control for validation
        from ldap_core_shared.ldif.processor import LDIFControl

        invalid_control = LDIFControl(
            control_type="invalid.oid.format",
            criticality=False,
        )

        entry = LDIFEntry(
            dn="cn=test,dc=example,dc=com",
            controls=[invalid_control],
        )

        result = validator.validate_entry(entry)

        assert result.is_valid is False
        assert any("Invalid control OID format" in error for error in result.errors)


class TestRFC2849URLReferences:
    """Test RFC 2849 URL reference support."""

    def test_file_url_reference(self) -> None:
        """Test file:// URL reference handling."""
        processor = RFC2849LDIFProcessor()

        # Create a temporary file with content
        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".txt", encoding="utf-8") as f:
            f.write("This is content from a file URL reference")
            temp_file_path = f.name

        try:
            ldif_content = f"""version: 1
dn: cn=test,dc=example,dc=com
description:< file://{temp_file_path}
objectClass: person
cn: test
"""

            result = processor.parse_string(ldif_content)

            assert result.success is True
            entry = result.data[0]
            description = entry.get_attribute_values("description")[0]
            assert "This is content from a file URL reference" in description
            assert processor._stats["url_references"] == 1

        finally:
            Path(temp_file_path).unlink()

    @patch("urllib.request.urlopen")
    def test_http_url_reference(self, mock_urlopen) -> None:
        """Test HTTP URL reference handling."""
        # Mock HTTP response
        mock_response = mock_urlopen.return_value.__enter__.return_value
        mock_response.read.return_value = b"HTTP content"

        processor = RFC2849LDIFProcessor()

        ldif_content = """version: 1
dn: cn=test,dc=example,dc=com
description:< http://example.com/description.txt
objectClass: person
"""

        result = processor.parse_string(ldif_content)

        assert result.success is True
        entry = result.data[0]
        description = entry.get_attribute_values("description")[0]
        assert description == "HTTP content"


class TestRFC2849CommentHandling:
    """Test RFC 2849 comment line handling."""

    def test_comment_lines_ignored(self) -> None:
        """Test that comment lines are properly ignored."""
        processor = RFC2849LDIFProcessor()

        ldif_content = """# This is a comment at the beginning
version: 1
# Another comment in the middle
dn: cn=test,dc=example,dc=com
# Comment before attribute
cn: test
# Comment after attribute
objectClass: person
# Final comment
"""

        result = processor.parse_string(ldif_content)

        assert result.success is True
        assert len(result.data) == 1
        assert processor._stats["comments_skipped"] == 5

        entry = result.data[0]
        assert entry.dn == "cn=test,dc=example,dc=com"
        assert "test" in entry.get_attribute_values("cn")

    def test_comment_with_hash_in_middle(self) -> None:
        """Test that only lines starting with # are treated as comments."""
        processor = RFC2849LDIFProcessor()

        ldif_content = """version: 1
dn: cn=test,dc=example,dc=com
description: This contains a # character but is not a comment
objectClass: person
"""

        result = processor.parse_string(ldif_content)

        assert result.success is True
        entry = result.data[0]
        description = entry.get_attribute_values("description")[0]
        assert "This contains a # character" in description


class TestRFC2849UTF8Validation:
    """Test RFC 2849 UTF-8 encoding validation."""

    def test_valid_utf8_content(self) -> None:
        """Test valid UTF-8 content processing."""
        processor = RFC2849LDIFProcessor()

        ldif_content = """version: 1
dn: cn=山田太郎,dc=example,dc=com
cn: 山田太郎
givenName: 太郎
sn: 山田
objectClass: person
"""

        result = processor.parse_string(ldif_content)

        assert result.success is True
        entry = result.data[0]
        assert "山田太郎" in entry.get_attribute_values("cn")

    def test_utf8_validation_in_validator(self) -> None:
        """Test UTF-8 validation in the validator."""
        validator = RFC2849LDIFValidator()

        # Valid UTF-8 content
        valid_content = "version: 1\ndn: cn=test,dc=example,dc=com\ncn: 测试"
        result = validator.validate_raw_content(valid_content)

        assert result.is_valid is True


class TestRFC2849Examples:
    """Test all examples from RFC 2849."""

    def test_rfc2849_example1(self) -> None:
        """Test RFC 2849 Example 1 - simple LDAP file with two entries."""
        processor = RFC2849LDIFProcessor()

        # RFC 2849 Example 1
        ldif_content = """version: 1
dn: cn=Barbara Jensen, ou=Product Development, dc=airius, dc=com
objectclass: top
objectclass: person
objectclass: organizationalPerson
cn: Barbara Jensen
cn: Barbara J Jensen
cn: Babs Jensen
sn: Jensen
uid: bjensen
telephonenumber: +1 408 555 1212
description: A big sailing fan.

dn: cn=Bjorn Jensen, ou=Accounting, dc=airius, dc=com
objectclass: top
objectclass: person
objectclass: organizationalPerson
cn: Bjorn Jensen
sn: Jensen
telephonenumber: +1 408 555 1212
"""

        result = processor.parse_string(ldif_content)

        assert result.success is True
        assert len(result.data) == 2

        # Verify first entry
        barbara = result.data[0]
        assert barbara.dn == "cn=Barbara Jensen, ou=Product Development, dc=airius, dc=com"
        assert "Barbara Jensen" in barbara.get_attribute_values("cn")
        assert "A big sailing fan." in barbara.get_attribute_values("description")

        # Verify second entry
        bjorn = result.data[1]
        assert bjorn.dn == "cn=Bjorn Jensen, ou=Accounting, dc=airius, dc=com"
        assert "Bjorn Jensen" in bjorn.get_attribute_values("cn")

    def test_rfc2849_example4_utf8_with_language_tags(self) -> None:
        """Test RFC 2849 Example 4 - UTF-8 encoded attributes with language tags."""
        processor = RFC2849LDIFProcessor()

        # RFC 2849 Example 4 (simplified)
        ldif_content = """version: 1
dn:: b3U95Za25qWt6YOoLG89QWlyaXVz
objectclass: top
objectclass: organizationalUnit
ou:: 5Za25qWt6YOo
ou;lang-ja:: 5Za25qWt6YOo
"""

        result = processor.parse_string(ldif_content)

        assert result.success is True
        assert len(result.data) == 1

        entry = result.data[0]
        # DN should be decoded from base64
        assert "Airius" in entry.dn
        # Attributes should be decoded
        assert len(entry.get_attribute_values("ou")) > 0


class TestRFC2849ErrorHandling:
    """Test RFC 2849 compliant error handling."""

    def test_malformed_dn_specification(self) -> None:
        """Test error handling for malformed DN specification."""
        processor = RFC2849LDIFProcessor()

        ldif_content = """version: 1
notadn: cn=test,dc=example,dc=com
cn: test
"""

        result = processor.parse_string(ldif_content)

        assert result.success is False
        assert "Expected DN specification" in result.error_message

    def test_malformed_attribute_specification(self) -> None:
        """Test error handling for malformed attribute specification."""
        processor = RFC2849LDIFProcessor()

        ldif_content = """version: 1
dn: cn=test,dc=example,dc=com
malformed_attribute_no_colon test
"""

        result = processor.parse_string(ldif_content)

        assert result.success is False
        assert "Invalid attribute" in result.error_message

    def test_invalid_changetype(self) -> None:
        """Test error handling for invalid changetype."""
        processor = RFC2849LDIFProcessor()

        ldif_content = """version: 1
dn: cn=test,dc=example,dc=com
changetype: invalid
"""

        result = processor.parse_string(ldif_content)

        assert result.success is False
        assert "Invalid changetype" in result.error_message


class TestRFC2849Integration:
    """Integration tests for RFC 2849 compliance."""

    def test_comprehensive_ldif_processing(self) -> None:
        """Test comprehensive LDIF processing with all RFC 2849 features."""
        processor = RFC2849LDIFProcessor()

        # Complex LDIF with multiple RFC 2849 features
        ldif_content = """version: 1
# This is a comprehensive test of RFC 2849 features

# Basic entry
dn: cn=John Doe,ou=people,dc=example,dc=com
objectClass: person
objectClass: inetOrgPerson
cn: John Doe
sn: Doe
givenName: John
mail: john.doe@example.com

# Entry with line folding
dn: cn=Jane Smith,ou=people,dc=example,dc=com
objectClass: person
description: This is a very long description that demonstrates
 the line folding capability of RFC 2849 compliant LDIF
 processors and ensures proper handling.
cn: Jane Smith

# Entry with base64 encoded values
dn: cn=測試用戶,ou=people,dc=example,dc=com
objectClass: person
cn:: 5ris6Kqm55So5oi2
description:: VGhpcyBpcyBhIGJhc2U2NCBlbmNvZGVkIGRlc2NyaXB0aW9u

# Change record example
dn: cn=user.to.modify,ou=people,dc=example,dc=com
changetype: modify
add: telephoneNumber
telephoneNumber: +1-555-1234
-
replace: mail
mail: new.email@example.com
-
"""

        result = processor.parse_string(ldif_content)

        assert result.success is True
        assert len(result.data) == 4

        # Verify statistics
        assert processor._stats["version_found"] is True
        assert processor._stats["comments_skipped"] > 0
        assert processor._stats["lines_folded"] > 0
        assert processor._stats["base64_decoded"] > 0
        assert processor._stats["change_records"] == 1

    def test_validator_integration(self) -> None:
        """Test validator integration with processor."""
        validator = RFC2849LDIFValidator()

        # Create a temporary LDIF file
        ldif_content = """version: 1
dn: cn=test,dc=example,dc=com
objectClass: person
cn: test
"""

        with tempfile.NamedTemporaryFile(mode="w", suffix=".ldif", delete=False, encoding="utf-8") as f:
            f.write(ldif_content)
            f.flush()

            result = validator.validate_file(f.name)

        Path(f.name).unlink()

        assert result.is_valid is True
        assert result.error_count == 0


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--cov=ldap_core_shared.ldif"])
