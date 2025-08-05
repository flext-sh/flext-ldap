"""Tests for LDAP Infrastructure Data Type Converter.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

import pytest

from flext_ldap.ldap_infrastructure import FlextLdapConverter, FlextLdapDataType


# FBT smell elimination constants - SOLID DRY Principle
class TestBooleanValue:
    """Test boolean value constants - eliminates FBT003 positional booleans."""

    TRUE = True
    FALSE = False


class TestFlextLdapDataType:
    """Test suite for FlextLdapDataType enum."""

    def test_all_types_defined(self) -> None:
        """Test that all expected LDAP data types are defined."""
        expected_types = {
            "string",
            "integer",
            "boolean",
            "binary",
            "datetime",
            "dn",
            "email",
            "phone",
            "uuid",
        }

        actual_types = {t.value for t in FlextLdapDataType}
        assert actual_types == expected_types


class TestFlextLdapConverter:
    """Test suite for FlextLdapConverter class."""

    @pytest.fixture
    def converter(self) -> FlextLdapConverter:
        """FlextLdapConverter instance."""
        return FlextLdapConverter()

    def test_detect_type_email(self, converter: FlextLdapConverter) -> None:
        """Test email type detection."""
        result = converter.detect_type("user@example.com")
        assert result == FlextLdapDataType.EMAIL

    def test_detect_type_phone(self, converter: FlextLdapConverter) -> None:
        """Test phone number type detection."""
        result = converter.detect_type("+1-555-123-4567")
        assert result == FlextLdapDataType.PHONE

    def test_detect_type_uuid(self, converter: FlextLdapConverter) -> None:
        """Test UUID type detection."""
        test_uuid = uuid.uuid4()
        result = converter.detect_type(test_uuid)
        assert result == FlextLdapDataType.UUID

    def test_detect_type_dn(self, converter: FlextLdapConverter) -> None:
        """Test DN type detection."""
        result = converter.detect_type("cn=user,ou=people,dc=example,dc=com")
        assert result == FlextLdapDataType.DN

    def test_detect_type_datetime(self, converter: FlextLdapConverter) -> None:
        """Test datetime type detection."""
        test_dt = datetime.now(UTC)
        result = converter.detect_type(test_dt)
        assert result == FlextLdapDataType.DATETIME

    def test_detect_type_boolean(self, converter: FlextLdapConverter) -> None:
        """Test boolean type detection."""
        assert converter.detect_type(TestBooleanValue.TRUE) == FlextLdapDataType.BOOLEAN
        assert converter.detect_type("true") == FlextLdapDataType.BOOLEAN
        assert converter.detect_type("yes") == FlextLdapDataType.BOOLEAN

    def test_detect_type_integer(self, converter: FlextLdapConverter) -> None:
        """Test integer type detection."""
        assert converter.detect_type(123) == FlextLdapDataType.INTEGER

    def test_detect_type_binary(self, converter: FlextLdapConverter) -> None:
        """Test binary type detection."""
        result = converter.detect_type(b"binary_data")
        assert result == FlextLdapDataType.BINARY

    def test_detect_type_string_default(self, converter: FlextLdapConverter) -> None:
        """Test default string type detection."""
        result = converter.detect_type("just a regular string")
        assert result == FlextLdapDataType.STRING

    def test_detect_type_none(self, converter: FlextLdapConverter) -> None:
        """Test None value type detection."""
        result = converter.detect_type(None)
        assert result == FlextLdapDataType.STRING  # Default fallback

    def test_to_ldap_boolean(self, converter: FlextLdapConverter) -> None:
        """Test boolean to LDAP conversion."""
        assert converter.to_ldap(TestBooleanValue.TRUE) == "TRUE"
        assert converter.to_ldap(TestBooleanValue.FALSE) == "FALSE"

    def test_to_ldap_datetime(self, converter: FlextLdapConverter) -> None:
        """Test datetime to LDAP conversion."""
        dt = datetime(2025, 1, 15, 10, 30, 0, tzinfo=UTC)
        result = converter.to_ldap(dt)
        assert result == "20250115103000Z"

    def test_to_ldap_uuid(self, converter: FlextLdapConverter) -> None:
        """Test UUID to LDAP conversion."""
        test_uuid = uuid.uuid4()
        result = converter.to_ldap(test_uuid)
        assert result == str(test_uuid)

    def test_to_ldap_integer(self, converter: FlextLdapConverter) -> None:
        """Test integer to LDAP conversion."""
        assert converter.to_ldap(123) == "123"

    def test_to_ldap_list(self, converter: FlextLdapConverter) -> None:
        """Test list to LDAP conversion."""
        result = converter.to_ldap([1, 2, 3])
        assert result == ["1", "2", "3"]

    def test_to_ldap_string(self, converter: FlextLdapConverter) -> None:
        """Test string to LDAP conversion."""
        assert converter.to_ldap("test") == "test"

    def test_to_ldap_none(self, converter: FlextLdapConverter) -> None:
        """Test None to LDAP conversion."""
        assert converter.to_ldap(None) is None

    def test_from_ldap_boolean(self, converter: FlextLdapConverter) -> None:
        """Test LDAP to boolean conversion."""
        assert converter.from_ldap("TRUE", FlextLdapDataType.BOOLEAN) is True
        assert converter.from_ldap("FALSE", FlextLdapDataType.BOOLEAN) is False
        assert converter.from_ldap("true", FlextLdapDataType.BOOLEAN) is True
        assert converter.from_ldap("yes", FlextLdapDataType.BOOLEAN) is True
        assert converter.from_ldap("1", FlextLdapDataType.BOOLEAN) is True

    def test_from_ldap_integer(self, converter: FlextLdapConverter) -> None:
        """Test LDAP to integer conversion."""
        result = converter.from_ldap("123", FlextLdapDataType.INTEGER)
        assert result == 123
        assert isinstance(result, int)

    def test_from_ldap_datetime(self, converter: FlextLdapConverter) -> None:
        """Test LDAP to datetime conversion."""
        result = converter.from_ldap("20250115103000Z", FlextLdapDataType.DATETIME)
        assert isinstance(result, datetime)
        assert result.tzinfo == UTC

    def test_from_ldap_uuid(self, converter: FlextLdapConverter) -> None:
        """Test LDAP to UUID conversion."""
        test_uuid_str = str(uuid.uuid4())
        result = converter.from_ldap(test_uuid_str, FlextLdapDataType.UUID)
        assert isinstance(result, uuid.UUID)
        assert str(result) == test_uuid_str

    def test_from_ldap_bytes(self, converter: FlextLdapConverter) -> None:
        """Test LDAP bytes conversion."""
        result = converter.from_ldap(b"test", FlextLdapDataType.BINARY)
        assert result == "test"

    def test_from_ldap_list(self, converter: FlextLdapConverter) -> None:
        """Test LDAP list conversion."""
        result = converter.from_ldap(["1", "2", "3"], FlextLdapDataType.INTEGER)
        assert result == [1, 2, 3]

    def test_from_ldap_string_default(self, converter: FlextLdapConverter) -> None:
        """Test LDAP string conversion with no target type."""
        result = converter.from_ldap("test string")
        assert result == "test string"

    def test_from_ldap_none(self, converter: FlextLdapConverter) -> None:
        """Test LDAP None conversion."""
        assert converter.from_ldap(None) is None

    def test_from_ldap_auto_detect(self, converter: FlextLdapConverter) -> None:
        """Test LDAP conversion with auto-detection."""
        # Should auto-detect as email
        result = converter.from_ldap("user@example.com")
        assert result == "user@example.com"

    def test_caching_functionality(self, converter: FlextLdapConverter) -> None:
        """Test that caching works correctly."""
        # Type detection caching
        test_email = "user@example.com"
        result1 = converter.detect_type(test_email)
        result2 = converter.detect_type(test_email)
        assert result1 == result2 == FlextLdapDataType.EMAIL

        # Conversion caching
        conv1 = converter.to_ldap(123)
        conv2 = converter.to_ldap(123)
        assert conv1 == conv2 == "123"

    def test_error_handling(self, converter: FlextLdapConverter) -> None:
        """Test error handling in conversions."""
        # Invalid datetime should fallback to string
        result = converter.from_ldap("invalid-date", FlextLdapDataType.DATETIME)
        assert isinstance(result, str)

        # Invalid UUID should fallback to string
        result = converter.from_ldap("invalid-uuid", FlextLdapDataType.UUID)
        assert isinstance(result, str)

    def test_string_type_detection_patterns(
        self, converter: FlextLdapConverter
    ) -> None:
        """Test specific string pattern detection."""
        # Email patterns
        assert (
            converter._detect_string_type("user@domain.com") == FlextLdapDataType.EMAIL
        )

        # Phone patterns
        assert converter._detect_string_type("+1234567890") == FlextLdapDataType.PHONE

        # DN patterns
        assert (
            converter._detect_string_type("cn=test,dc=example,dc=com")
            == FlextLdapDataType.DN
        )

        # Boolean patterns
        assert converter._detect_string_type("true") == FlextLdapDataType.BOOLEAN
        assert converter._detect_string_type("false") == FlextLdapDataType.BOOLEAN
        assert converter._detect_string_type("yes") == FlextLdapDataType.BOOLEAN
        assert converter._detect_string_type("no") == FlextLdapDataType.BOOLEAN

        # Default string
        assert converter._detect_string_type("random text") == FlextLdapDataType.STRING
