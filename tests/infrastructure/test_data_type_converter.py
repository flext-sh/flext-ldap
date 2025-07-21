"""Tests for Data Type Converter Infrastructure.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import uuid
from datetime import datetime

import pytest

from flext_ldap.infrastructure.data_type_converter import (
    ConversionError,
    ConversionResult,
    DataTypeConverter,
    LDAPDataType,
)


class TestLDAPDataType:
    """Test suite for LDAPDataType enum."""

    def test_all_types_defined(self) -> None:
        """Test that all expected LDAP data types are defined."""
        expected_types = {
            "string",
            "integer",
            "boolean",
            "binary",
            "datetime",
            "uuid",
            "dn",
            "email",
            "phone",
            "url",
            "ip_address",
            "mac_address",
            "certificate",
            "password",
            "unknown",
        }

        actual_types = {t.value for t in LDAPDataType}
        assert actual_types == expected_types


class TestConversionResult:
    """Test suite for ConversionResult class."""

    def test_conversion_result_initialization(self) -> None:
        """Test ConversionResult initialization."""
        result = ConversionResult(
            value="test",
            source_type=LDAPDataType.STRING,
            target_type=str,
            is_valid=True,
            warnings=["warning"],
            metadata={"key": "value"},
        )

        assert result.value == "test"
        assert result.source_type == LDAPDataType.STRING
        assert result.target_type is str
        assert result.is_valid is True
        assert result.warnings == ["warning"]
        assert result.metadata == {"key": "value"}

    def test_conversion_result_to_dict(self) -> None:
        """Test ConversionResult to_dict conversion."""
        result = ConversionResult(
            value=42,
            source_type=LDAPDataType.INTEGER,
            target_type=int,
            is_valid=True,
            warnings=["test warning"],
            metadata={"source": "ldap"},
        )

        result_dict = result.to_dict()

        assert result_dict["value"] == 42
        assert result_dict["source_type"] == "integer"
        assert result_dict["target_type"] == "int"
        assert result_dict["is_valid"] is True
        assert result_dict["warnings"] == ["test warning"]
        assert result_dict["metadata"] == {"source": "ldap"}


class TestConversionError:
    """Test suite for ConversionError class."""

    def test_conversion_error_initialization(self) -> None:
        """Test ConversionError initialization."""
        error = ConversionError(
            "Test error",
            source_value="invalid",
            target_type="int",
        )

        assert str(error) == "Test error"
        assert error.source_value == "invalid"
        assert error.target_type == "int"


class TestDataTypeConverter:
    """Test suite for DataTypeConverter class."""

    @pytest.fixture
    def converter(self) -> DataTypeConverter:
        """DataTypeConverter instance."""
        return DataTypeConverter()

    @pytest.mark.asyncio
    async def test_detect_type_email(self, converter: DataTypeConverter) -> None:
        """Test email type detection."""
        result = await converter.detect_type("user@example.com")

        assert result.is_success
        assert result.data is not None
        assert result.data == LDAPDataType.EMAIL

    @pytest.mark.asyncio
    async def test_detect_type_phone(self, converter: DataTypeConverter) -> None:
        """Test phone number type detection."""
        result = await converter.detect_type("+1-555-123-4567")

        assert result.is_success
        assert result.data is not None
        assert result.data == LDAPDataType.PHONE

    @pytest.mark.asyncio
    async def test_detect_type_url(self, converter: DataTypeConverter) -> None:
        """Test URL type detection."""
        result = await converter.detect_type("https://example.com")

        assert result.is_success
        assert result.data is not None
        assert result.data == LDAPDataType.URL

    @pytest.mark.asyncio
    async def test_detect_type_ip_address(self, converter: DataTypeConverter) -> None:
        """Test IP address type detection."""
        result = await converter.detect_type("192.168.1.1")

        assert result.is_success
        assert result.data is not None
        assert result.data == LDAPDataType.IP_ADDRESS

    @pytest.mark.asyncio
    async def test_detect_type_mac_address(self, converter: DataTypeConverter) -> None:
        """Test MAC address type detection."""
        result = await converter.detect_type("AA:BB:CC:DD:EE:FF")

        assert result.is_success
        assert result.data is not None
        assert result.data == LDAPDataType.MAC_ADDRESS

    @pytest.mark.asyncio
    async def test_detect_type_uuid(self, converter: DataTypeConverter) -> None:
        """Test UUID type detection."""
        test_uuid = str(uuid.uuid4())
        result = await converter.detect_type(test_uuid)

        assert result.is_success
        assert result.data is not None
        assert result.data == LDAPDataType.UUID

    @pytest.mark.asyncio
    async def test_detect_type_dn(self, converter: DataTypeConverter) -> None:
        """Test DN type detection."""
        result = await converter.detect_type("cn=user,ou=people,dc=example,dc=com")

        assert result.is_success
        assert result.data is not None
        assert result.data == LDAPDataType.DN

    @pytest.mark.asyncio
    async def test_detect_type_datetime(self, converter: DataTypeConverter) -> None:
        """Test datetime type detection."""
        result = await converter.detect_type("2025-01-15T10:30:00Z")

        assert result.is_success
        assert result.data is not None
        assert result.data == LDAPDataType.DATE_TIME

    @pytest.mark.asyncio
    async def test_detect_type_boolean(self, converter: DataTypeConverter) -> None:
        """Test boolean type detection."""
        result = await converter.detect_type("true")

        assert result.is_success
        assert result.data is not None
        assert result.data == LDAPDataType.BOOLEAN

    @pytest.mark.asyncio
    async def test_detect_type_integer(self, converter: DataTypeConverter) -> None:
        """Test integer type detection."""
        result = await converter.detect_type("12345")

        assert result.is_success
        assert result.data is not None
        assert result.data == LDAPDataType.INTEGER

    @pytest.mark.asyncio
    async def test_detect_type_string_default(
        self,
        converter: DataTypeConverter,
    ) -> None:
        """Test default string type detection."""
        result = await converter.detect_type("just a regular string")

        assert result.is_success
        assert result.data is not None
        assert result.data == LDAPDataType.STRING

    @pytest.mark.asyncio
    async def test_detect_type_none(self, converter: DataTypeConverter) -> None:
        """Test None value type detection."""
        result = await converter.detect_type(None)

        assert result.is_success
        assert result.data is not None
        assert result.data == LDAPDataType.UNKNOWN

    @pytest.mark.asyncio
    async def test_detect_type_empty_string(self, converter: DataTypeConverter) -> None:
        """Test empty string type detection."""
        result = await converter.detect_type("")

        assert result.is_success
        assert result.data is not None
        assert result.data == LDAPDataType.STRING

    @pytest.mark.asyncio
    async def test_convert_value_string_to_string(
        self,
        converter: DataTypeConverter,
    ) -> None:
        """Test string to string conversion."""
        result = await converter.convert_value("test", str, LDAPDataType.STRING)

        assert result.is_success
        assert result.data is not None
        assert result.data.value == "test"
        assert result.data.is_valid is True
        assert result.data.source_type == LDAPDataType.STRING
        assert result.data.target_type is str

    @pytest.mark.asyncio
    async def test_convert_value_integer_to_int(
        self,
        converter: DataTypeConverter,
    ) -> None:
        """Test integer string to int conversion."""
        result = await converter.convert_value("123", int, LDAPDataType.INTEGER)

        assert result.is_success
        assert result.data is not None
        assert result.data.value == 123
        assert result.data.is_valid is True

    @pytest.mark.asyncio
    async def test_convert_value_boolean_to_bool(
        self,
        converter: DataTypeConverter,
    ) -> None:
        """Test boolean string to bool conversion."""
        # Test true values
        for true_val in ["true", "yes", "1", "on"]:
            result = await converter.convert_value(true_val, bool, LDAPDataType.BOOLEAN)
            assert result.is_success
            assert result.data is not None
            assert result.data.value is True
            assert result.data.is_valid is True

        # Test false values
        for false_val in ["false", "no", "0", "off"]:
            result = await converter.convert_value(
                false_val,
                bool,
                LDAPDataType.BOOLEAN,
            )
            assert result.is_success
            assert result.data is not None
            assert result.data.value is False
            assert result.data.is_valid is True

    @pytest.mark.asyncio
    async def test_convert_value_datetime_to_datetime(
        self,
        converter: DataTypeConverter,
    ) -> None:
        """Test datetime string to datetime conversion."""
        result = await converter.convert_value(
            "2025-01-15T10:30:00Z",
            datetime,
            LDAPDataType.DATE_TIME,
        )

        assert result.is_success
        assert result.data is not None
        assert isinstance(result.data.value, datetime)
        assert result.data.is_valid is True

    @pytest.mark.asyncio
    async def test_convert_value_uuid_to_uuid(
        self,
        converter: DataTypeConverter,
    ) -> None:
        """Test UUID string to UUID conversion."""
        test_uuid = str(uuid.uuid4())
        result = await converter.convert_value(test_uuid, uuid.UUID, LDAPDataType.UUID)

        assert result.is_success
        assert result.data is not None
        assert isinstance(result.data.value, uuid.UUID)
        assert str(result.data.value) == test_uuid
        assert result.data.is_valid is True

    @pytest.mark.asyncio
    async def test_convert_value_email_normalization(
        self,
        converter: DataTypeConverter,
    ) -> None:
        """Test email normalization."""
        result = await converter.convert_value(
            "  USER@EXAMPLE.COM  ",
            str,
            LDAPDataType.EMAIL,
        )

        assert result.is_success
        assert result.data is not None
        assert result.data.value == "user@example.com"
        assert result.data.is_valid is True

    @pytest.mark.asyncio
    async def test_convert_value_phone_normalization(
        self,
        converter: DataTypeConverter,
    ) -> None:
        """Test phone number normalization."""
        result = await converter.convert_value(
            "+1-(555) 123-4567",
            str,
            LDAPDataType.PHONE,
        )

        assert result.is_success
        assert result.data is not None
        assert result.data.value == "+15551234567"
        assert result.data.is_valid is True

    @pytest.mark.asyncio
    async def test_convert_value_ip_normalization(
        self,
        converter: DataTypeConverter,
    ) -> None:
        """Test IP address normalization."""
        result = await converter.convert_value(
            "192.168.1.1",
            str,
            LDAPDataType.IP_ADDRESS,
        )

        assert result.is_success
        assert result.data is not None
        assert result.data.value == "192.168.1.1"
        assert result.data.is_valid is True

    @pytest.mark.asyncio
    async def test_convert_value_mac_normalization(
        self,
        converter: DataTypeConverter,
    ) -> None:
        """Test MAC address normalization."""
        result = await converter.convert_value(
            "aa-bb-cc-dd-ee-ff",
            str,
            LDAPDataType.MAC_ADDRESS,
        )

        assert result.is_success
        assert result.data is not None
        assert result.data.value == "AA:BB:CC:DD:EE:FF"
        assert result.data.is_valid is True

    @pytest.mark.asyncio
    async def test_convert_value_invalid_conversion(
        self,
        converter: DataTypeConverter,
    ) -> None:
        """Test invalid conversion handling."""
        result = await converter.convert_value(
            "not_a_number",
            int,
            LDAPDataType.INTEGER,
        )

        assert result.is_success
        assert result.data is not None
        assert result.data.is_valid is False
        assert len(result.data.warnings) > 0

    @pytest.mark.asyncio
    async def test_convert_value_auto_detect_type(
        self,
        converter: DataTypeConverter,
    ) -> None:
        """Test conversion with auto-detected source type."""
        result = await converter.convert_value("user@example.com", str)

        assert result.is_success
        assert result.data is not None
        assert result.data.source_type == LDAPDataType.EMAIL
        assert result.data.value == "user@example.com"

    @pytest.mark.asyncio
    async def test_convert_value_generic_conversion(
        self,
        converter: DataTypeConverter,
    ) -> None:
        """Test generic conversion fallback."""
        result = await converter.convert_value("123.45", float, LDAPDataType.STRING)

        assert result.is_success
        assert result.data is not None
        assert result.data.value == 123.45
        assert result.data.is_valid is True
        assert "Used generic conversion" in result.data.warnings

    @pytest.mark.asyncio
    async def test_convert_batch_success(self, converter: DataTypeConverter) -> None:
        """Test successful batch conversion."""
        values = ["123", "456", "789"]
        result = await converter.convert_batch(values, int, LDAPDataType.INTEGER)

        assert result.is_success
        assert result.data is not None
        assert len(result.data) == 3
        assert all(result.data[i].is_valid for i in range(len(result.data)))
        assert [result.data[i].value for i in range(len(result.data))] == [
            123,
            456,
            789,
        ]

    @pytest.mark.asyncio
    async def test_convert_batch_mixed_results(
        self,
        converter: DataTypeConverter,
    ) -> None:
        """Test batch conversion with mixed success/failure."""
        values = ["123", "not_a_number", "456"]
        result = await converter.convert_batch(values, int, LDAPDataType.INTEGER)

        assert result.is_success
        assert result.data is not None
        assert len(result.data) == 3
        assert all(result.data[i].is_valid for i in range(len(result.data)))
        assert [result.data[i].value for i in range(len(result.data))] == [
            123,
            456,
            789,
        ]

    @pytest.mark.asyncio
    async def test_validate_type_compatibility_direct(
        self,
        converter: DataTypeConverter,
    ) -> None:
        """Test direct type compatibility validation."""
        result = await converter.validate_type_compatibility(LDAPDataType.STRING, str)

        assert result.is_success
        assert result.data is not None
        assert result.data is True

    @pytest.mark.asyncio
    async def test_validate_type_compatibility_compatible(
        self,
        converter: DataTypeConverter,
    ) -> None:
        """Test compatible type validation."""
        result = await converter.validate_type_compatibility(LDAPDataType.INTEGER, int)

        assert result.is_success
        assert result.data is not None
        assert result.data is True

    @pytest.mark.asyncio
    async def test_validate_type_compatibility_incompatible(
        self,
        converter: DataTypeConverter,
    ) -> None:
        """Test incompatible type validation."""
        result = await converter.validate_type_compatibility(
            LDAPDataType.EMAIL,
            datetime,
        )

        assert result.is_success
        assert result.data is not None
        assert result.data is False

    def test_type_detectors(self, converter: DataTypeConverter) -> None:
        """Test individual type detector methods."""
        # Email
        assert converter._is_email("user@example.com") is True
        assert converter._is_email("invalid-email") is False

        # Phone
        assert converter._is_phone("+1-555-123-4567") is True
        assert converter._is_phone("not-a-phone") is False

        # URL
        assert converter._is_url("https://example.com") is True
        assert converter._is_url("not-a-url") is False

        # IP Address
        assert converter._is_ip_address("192.168.1.1") is True
        assert converter._is_ip_address("999.999.999.999") is False

        # MAC Address
        assert converter._is_mac_address("AA:BB:CC:DD:EE:FF") is True
        assert converter._is_mac_address("not-a-mac") is False

        # UUID
        test_uuid = str(uuid.uuid4())
        assert converter._is_uuid(test_uuid) is True
        assert converter._is_uuid("not-a-uuid") is False

        # DN
        assert converter._is_dn("cn=user,dc=example,dc=com") is True
        assert converter._is_dn("not-a-dn") is False

        # Boolean
        assert converter._is_boolean("true") is True
        assert converter._is_boolean("invalid") is False

        # Integer
        assert converter._is_integer("123") is True
        assert converter._is_integer("not-a-number") is False

    def test_type_converters(self, converter: DataTypeConverter) -> None:
        """Test individual type converter methods."""
        # String conversion
        assert converter._convert_to_string(123) == "123"

        # Integer conversion
        assert converter._convert_to_int("123") == 123
        with pytest.raises(ConversionError):
            converter._convert_to_int("not-a-number")

        # Boolean conversion
        assert converter._convert_to_bool("true") is True
        assert converter._convert_to_bool("false") is False
        with pytest.raises(ConversionError):
            converter._convert_to_bool("invalid")

        # UUID conversion
        test_uuid_str = str(uuid.uuid4())
        converted_uuid = converter._convert_to_uuid(test_uuid_str)
        assert isinstance(converted_uuid, uuid.UUID)
        assert str(converted_uuid) == test_uuid_str

    def test_get_supported_types(self, converter: DataTypeConverter) -> None:
        """Test getting supported types."""
        supported_types = converter.get_supported_types()

        assert isinstance(supported_types, list)
        assert LDAPDataType.STRING in supported_types
        assert LDAPDataType.INTEGER in supported_types
        assert len(supported_types) > 0

    def test_get_supported_conversions(self, converter: DataTypeConverter) -> None:
        """Test getting supported conversions mapping."""
        conversions = converter.get_supported_conversions()

        assert isinstance(conversions, dict)
        assert LDAPDataType.STRING in conversions
        assert str in conversions[LDAPDataType.STRING]

    def test_bytes_conversion(self, converter: DataTypeConverter) -> None:
        """Test bytes conversion methods."""
        # String to bytes
        result = converter._convert_to_bytes("hello")
        assert isinstance(result, bytes)
        assert result == b"hello"

        # Bytes to bytes
        original_bytes = b"test"
        result = converter._convert_to_bytes(original_bytes)
        assert result == original_bytes

    def test_datetime_conversion_formats(self, converter: DataTypeConverter) -> None:
        """Test datetime conversion with different formats."""
        # ISO format
        dt1 = converter._convert_to_datetime("2025-01-15T10:30:00Z")
        assert isinstance(dt1, datetime)

        # Standard format
        dt2 = converter._convert_to_datetime("2025-01-15 10:30:00")
        assert isinstance(dt2, datetime)

        # LDAP GeneralizedTime
        dt3 = converter._convert_to_datetime("20250115103000Z")
        assert isinstance(dt3, datetime)

        # Invalid format
        with pytest.raises(ConversionError):
            converter._convert_to_datetime("invalid-date")
