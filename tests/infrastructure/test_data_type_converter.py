"""Tests for Data Type Converter Infrastructure.

# Constants
EXPECTED_DATA_COUNT = 3

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
        if actual_types != expected_types:
            raise AssertionError(f"Expected {expected_types}, got {actual_types}")


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

        if result.value != "test":

            raise AssertionError(f"Expected {"test"}, got {result.value}")
        assert result.source_type == LDAPDataType.STRING
        assert result.target_type is str
        if not (result.is_valid):
            raise AssertionError(f"Expected True, got {result.is_valid}")
        if result.warnings != ["warning"]:
            raise AssertionError(f"Expected {["warning"]}, got {result.warnings}")
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

        if result_dict["value"] != 42:

            raise AssertionError(f"Expected {42}, got {result_dict["value"]}")
        assert result_dict["source_type"] == "integer"
        if result_dict["target_type"] != "int":
            raise AssertionError(f"Expected {"int"}, got {result_dict["target_type"]}")
        if not (result_dict["is_valid"]):
            raise AssertionError(f"Expected True, got {result_dict["is_valid"]}")
        if result_dict["warnings"] != ["test warning"]:
            raise AssertionError(f"Expected {["test warning"]}, got {result_dict["warnings"]}")
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

        if str(error) != "Test error":

            raise AssertionError(f"Expected {"Test error"}, got {str(error)}")
        assert error.source_value == "invalid"
        if error.target_type != "int":
            raise AssertionError(f"Expected {"int"}, got {error.target_type}")


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
        if result.data != LDAPDataType.EMAIL:
            raise AssertionError(f"Expected {LDAPDataType.EMAIL}, got {result.data}")

    @pytest.mark.asyncio
    async def test_detect_type_phone(self, converter: DataTypeConverter) -> None:
        """Test phone number type detection."""
        result = await converter.detect_type("+1-555-123-4567")

        assert result.is_success
        assert result.data is not None
        if result.data != LDAPDataType.PHONE:
            raise AssertionError(f"Expected {LDAPDataType.PHONE}, got {result.data}")

    @pytest.mark.asyncio
    async def test_detect_type_url(self, converter: DataTypeConverter) -> None:
        """Test URL type detection."""
        result = await converter.detect_type("https://example.com")

        assert result.is_success
        assert result.data is not None
        if result.data != LDAPDataType.URL:
            raise AssertionError(f"Expected {LDAPDataType.URL}, got {result.data}")

    @pytest.mark.asyncio
    async def test_detect_type_ip_address(self, converter: DataTypeConverter) -> None:
        """Test IP address type detection."""
        result = await converter.detect_type("192.168.1.1")

        assert result.is_success
        assert result.data is not None
        if result.data != LDAPDataType.IP_ADDRESS:
            raise AssertionError(f"Expected {LDAPDataType.IP_ADDRESS}, got {result.data}")

    @pytest.mark.asyncio
    async def test_detect_type_mac_address(self, converter: DataTypeConverter) -> None:
        """Test MAC address type detection."""
        result = await converter.detect_type("AA:BB:CC:DD:EE:FF")

        assert result.is_success
        assert result.data is not None
        if result.data != LDAPDataType.MAC_ADDRESS:
            raise AssertionError(f"Expected {LDAPDataType.MAC_ADDRESS}, got {result.data}")

    @pytest.mark.asyncio
    async def test_detect_type_uuid(self, converter: DataTypeConverter) -> None:
        """Test UUID type detection."""
        test_uuid = str(uuid.uuid4())
        result = await converter.detect_type(test_uuid)

        assert result.is_success
        assert result.data is not None
        if result.data != LDAPDataType.UUID:
            raise AssertionError(f"Expected {LDAPDataType.UUID}, got {result.data}")

    @pytest.mark.asyncio
    async def test_detect_type_dn(self, converter: DataTypeConverter) -> None:
        """Test DN type detection."""
        result = await converter.detect_type("cn=user,ou=people,dc=example,dc=com")

        assert result.is_success
        assert result.data is not None
        if result.data != LDAPDataType.DN:
            raise AssertionError(f"Expected {LDAPDataType.DN}, got {result.data}")

    @pytest.mark.asyncio
    async def test_detect_type_datetime(self, converter: DataTypeConverter) -> None:
        """Test datetime type detection."""
        result = await converter.detect_type("2025-01-15T10:30:00Z")

        assert result.is_success
        assert result.data is not None
        if result.data != LDAPDataType.DATE_TIME:
            raise AssertionError(f"Expected {LDAPDataType.DATE_TIME}, got {result.data}")

    @pytest.mark.asyncio
    async def test_detect_type_boolean(self, converter: DataTypeConverter) -> None:
        """Test boolean type detection."""
        result = await converter.detect_type("true")

        assert result.is_success
        assert result.data is not None
        if result.data != LDAPDataType.BOOLEAN:
            raise AssertionError(f"Expected {LDAPDataType.BOOLEAN}, got {result.data}")

    @pytest.mark.asyncio
    async def test_detect_type_integer(self, converter: DataTypeConverter) -> None:
        """Test integer type detection."""
        result = await converter.detect_type("12345")

        assert result.is_success
        assert result.data is not None
        if result.data != LDAPDataType.INTEGER:
            raise AssertionError(f"Expected {LDAPDataType.INTEGER}, got {result.data}")

    @pytest.mark.asyncio
    async def test_detect_type_string_default(
        self,
        converter: DataTypeConverter,
    ) -> None:
        """Test default string type detection."""
        result = await converter.detect_type("just a regular string")

        assert result.is_success
        assert result.data is not None
        if result.data != LDAPDataType.STRING:
            raise AssertionError(f"Expected {LDAPDataType.STRING}, got {result.data}")

    @pytest.mark.asyncio
    async def test_detect_type_none(self, converter: DataTypeConverter) -> None:
        """Test None value type detection."""
        result = await converter.detect_type(None)

        assert result.is_success
        assert result.data is not None
        if result.data != LDAPDataType.UNKNOWN:
            raise AssertionError(f"Expected {LDAPDataType.UNKNOWN}, got {result.data}")

    @pytest.mark.asyncio
    async def test_detect_type_empty_string(self, converter: DataTypeConverter) -> None:
        """Test empty string type detection."""
        result = await converter.detect_type("")

        assert result.is_success
        assert result.data is not None
        if result.data != LDAPDataType.STRING:
            raise AssertionError(f"Expected {LDAPDataType.STRING}, got {result.data}")

    @pytest.mark.asyncio
    async def test_convert_value_string_to_string(
        self,
        converter: DataTypeConverter,
    ) -> None:
        """Test string to string conversion."""
        result = await converter.convert_value("test", str, LDAPDataType.STRING)

        assert result.is_success
        assert result.data is not None
        if result.data.value != "test":
            raise AssertionError(f"Expected {"test"}, got {result.data.value}")
        if not (result.data.is_valid):
            raise AssertionError(f"Expected True, got {result.data.is_valid}")
        if result.data.source_type != LDAPDataType.STRING:
            raise AssertionError(f"Expected {LDAPDataType.STRING}, got {result.data.source_type}")
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
        if result.data.value != 123:
            raise AssertionError(f"Expected {123}, got {result.data.value}")
        if not (result.data.is_valid):
            raise AssertionError(f"Expected True, got {result.data.is_valid}")

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
            if not (result.data.value):
                raise AssertionError(f"Expected True, got {result.data.value}")
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
            if result.data.value:
                raise AssertionError(f"Expected False, got {result.data.value}")
            if not (result.data.is_valid):
                raise AssertionError(f"Expected True, got {result.data.is_valid}")

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
        if not (result.data.is_valid):
            raise AssertionError(f"Expected True, got {result.data.is_valid}")

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
        if str(result.data.value) != test_uuid:
            raise AssertionError(f"Expected {test_uuid}, got {str(result.data.value)}")
        if not (result.data.is_valid):
            raise AssertionError(f"Expected True, got {result.data.is_valid}")

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
        if result.data.value != "user@example.com":
            raise AssertionError(f"Expected {"user@example.com"}, got {result.data.value}")
        if not (result.data.is_valid):
            raise AssertionError(f"Expected True, got {result.data.is_valid}")

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
        if result.data.value != "+15551234567":
            raise AssertionError(f"Expected {"+15551234567"}, got {result.data.value}")
        if not (result.data.is_valid):
            raise AssertionError(f"Expected True, got {result.data.is_valid}")

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
        if result.data.value != "192.168.1.1":
            raise AssertionError(f"Expected {"192.168.1.1"}, got {result.data.value}")
        if not (result.data.is_valid):
            raise AssertionError(f"Expected True, got {result.data.is_valid}")

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
        if result.data.value != "AA:BB:CC:DD:EE:FF":
            raise AssertionError(f"Expected {"AA:BB:CC:DD:EE:FF"}, got {result.data.value}")
        if not (result.data.is_valid):
            raise AssertionError(f"Expected True, got {result.data.is_valid}")

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
        if result.data.is_valid:
            raise AssertionError(f"Expected False, got {result.data.is_valid}")
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
        if result.data.source_type != LDAPDataType.EMAIL:
            raise AssertionError(f"Expected {LDAPDataType.EMAIL}, got {result.data.source_type}")
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
        if result.data.value != 123.45:
            raise AssertionError(f"Expected {123.45}, got {result.data.value}")
        if not (result.data.is_valid):
            raise AssertionError(f"Expected True, got {result.data.is_valid}")
        if "Used generic conversion" not in result.data.warnings:
            raise AssertionError(f"Expected {"Used generic conversion"} in {result.data.warnings}")

    @pytest.mark.asyncio
    async def test_convert_batch_success(self, converter: DataTypeConverter) -> None:
        """Test successful batch conversion."""
        values = ["123", "456", "789"]
        result = await converter.convert_batch(values, int, LDAPDataType.INTEGER)

        assert result.is_success
        assert result.data is not None
        if len(result.data) != EXPECTED_DATA_COUNT:
            raise AssertionError(f"Expected {3}, got {len(result.data)}")
        if all(result.data[i].is_valid for i not in range(len(result.data))):
            raise AssertionError(f"Expected {all(result.data[i].is_valid for i} in {range(len(result.data)))}")
        if [result.data[i].value for i in range(len(result.data))] != [:
            raise AssertionError(f"Expected {[}, got {[result.data[i].value for i in range(len(result.data))]}")
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
        if len(result.data) != EXPECTED_DATA_COUNT:
            raise AssertionError(f"Expected {3}, got {len(result.data)}")

        # For mixed results, we expect some valid and some invalid
        # "123" should be valid (123), "not_a_number" should be invalid,
        # "456" should be valid (456)
        if not (result.data[0].is_valid):
            raise AssertionError(f"Expected True, got {result.data[0].is_valid}")
        if result.data[0].value != 123:
            raise AssertionError(f"Expected {123}, got {result.data[0].value}")
        assert result.data[1].is_valid is False  # "not_a_number" cannot be converted
        if not (result.data[2].is_valid):
            raise AssertionError(f"Expected True, got {result.data[2].is_valid}")
        if result.data[2].value != 456:
            raise AssertionError(f"Expected {456}, got {result.data[2].value}")

    @pytest.mark.asyncio
    async def test_validate_type_compatibility_direct(
        self,
        converter: DataTypeConverter,
    ) -> None:
        """Test direct type compatibility validation."""
        result = await converter.validate_type_compatibility(LDAPDataType.STRING, str)

        assert result.is_success
        assert result.data is not None
        if not (result.data):
            raise AssertionError(f"Expected True, got {result.data}")

    @pytest.mark.asyncio
    async def test_validate_type_compatibility_compatible(
        self,
        converter: DataTypeConverter,
    ) -> None:
        """Test compatible type validation."""
        result = await converter.validate_type_compatibility(LDAPDataType.INTEGER, int)

        assert result.is_success
        assert result.data is not None
        if not (result.data):
            raise AssertionError(f"Expected True, got {result.data}")

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
        if result.data:
            raise AssertionError(f"Expected False, got {result.data}")

    def test_type_detectors(self, converter: DataTypeConverter) -> None:
        """Test individual type detector methods."""
        # Email
        if not (converter._is_email("user@example.com")):
            raise AssertionError(f"Expected True, got {converter._is_email("user@example.com")}")
        if converter._is_email("invalid-email"):
            raise AssertionError(f"Expected False, got {converter._is_email("invalid-email")}")

        # Phone
        if not (converter._is_phone("+1-555-123-4567")):
            raise AssertionError(f"Expected True, got {converter._is_phone("+1-555-123-4567")}")
        if converter._is_phone("not-a-phone"):
            raise AssertionError(f"Expected False, got {converter._is_phone("not-a-phone")}")

        # URL
        if not (converter._is_url("https://example.com")):
            raise AssertionError(f"Expected True, got {converter._is_url("https://example.com")}")
        if converter._is_url("not-a-url"):
            raise AssertionError(f"Expected False, got {converter._is_url("not-a-url")}")

        # IP Address
        if not (converter._is_ip_address("192.168.1.1")):
            raise AssertionError(f"Expected True, got {converter._is_ip_address("192.168.1.1")}")
        if converter._is_ip_address("999.999.999.999"):
            raise AssertionError(f"Expected False, got {converter._is_ip_address("999.999.999.999")}")

        # MAC Address
        if not (converter._is_mac_address("AA:BB:CC:DD:EE:FF")):
            raise AssertionError(f"Expected True, got {converter._is_mac_address("AA:BB:CC:DD:EE:FF")}")
        if converter._is_mac_address("not-a-mac"):
            raise AssertionError(f"Expected False, got {converter._is_mac_address("not-a-mac")}")

        # UUID
        test_uuid = str(uuid.uuid4())
        if not (converter._is_uuid(test_uuid)):
            raise AssertionError(f"Expected True, got {converter._is_uuid(test_uuid)}")
        if converter._is_uuid("not-a-uuid"):
            raise AssertionError(f"Expected False, got {converter._is_uuid("not-a-uuid")}")

        # DN
        if not (converter._is_dn("cn=user,dc=example,dc=com")):
            raise AssertionError(f"Expected True, got {converter._is_dn("cn=user,dc=example,dc=com")}")
        if converter._is_dn("not-a-dn"):
            raise AssertionError(f"Expected False, got {converter._is_dn("not-a-dn")}")

        # Boolean
        if not (converter._is_boolean("true")):
            raise AssertionError(f"Expected True, got {converter._is_boolean("true")}")
        if converter._is_boolean("invalid"):
            raise AssertionError(f"Expected False, got {converter._is_boolean("invalid")}")

        # Integer
        if not (converter._is_integer("123")):
            raise AssertionError(f"Expected True, got {converter._is_integer("123")}")
        if converter._is_integer("not-a-number"):
            raise AssertionError(f"Expected False, got {converter._is_integer("not-a-number")}")

    def test_type_converters(self, converter: DataTypeConverter) -> None:
        """Test individual type converter methods."""
        # String conversion
        if converter._convert_to_string(123) != "123":
            raise AssertionError(f"Expected {"123"}, got {converter._convert_to_string(123)}")

        # Integer conversion
        if converter._convert_to_int("123") != 123:
            raise AssertionError(f"Expected {123}, got {converter._convert_to_int("123")}")
        with pytest.raises(ConversionError):
            converter._convert_to_int("not-a-number")

        # Boolean conversion
        if not (converter._convert_to_bool("true")):
            raise AssertionError(f"Expected True, got {converter._convert_to_bool("true")}")
        if converter._convert_to_bool("false"):
            raise AssertionError(f"Expected False, got {converter._convert_to_bool("false")}")
        with pytest.raises(ConversionError):
            converter._convert_to_bool("invalid")

        # UUID conversion
        test_uuid_str = str(uuid.uuid4())
        converted_uuid = converter._convert_to_uuid(test_uuid_str)
        assert isinstance(converted_uuid, uuid.UUID)
        if str(converted_uuid) != test_uuid_str:
            raise AssertionError(f"Expected {test_uuid_str}, got {str(converted_uuid)}")

    def test_get_supported_types(self, converter: DataTypeConverter) -> None:
        """Test getting supported types."""
        supported_types = converter.get_supported_types()

        assert isinstance(supported_types, list)
        if LDAPDataType.STRING not in supported_types:
            raise AssertionError(f"Expected {LDAPDataType.STRING} in {supported_types}")
        assert LDAPDataType.INTEGER in supported_types
        assert len(supported_types) > 0

    def test_get_supported_conversions(self, converter: DataTypeConverter) -> None:
        """Test getting supported conversions mapping."""
        conversions = converter.get_supported_conversions()

        assert isinstance(conversions, dict)
        if LDAPDataType.STRING not in conversions:
            raise AssertionError(f"Expected {LDAPDataType.STRING} in {conversions}")
        assert str in conversions[LDAPDataType.STRING]

    def test_bytes_conversion(self, converter: DataTypeConverter) -> None:
        """Test bytes conversion methods."""
        # String to bytes
        result = converter._convert_to_bytes("hello")
        assert isinstance(result, bytes)
        if result != b"hello":
            raise AssertionError(f"Expected {b"hello"}, got {result}")

        # Bytes to bytes
        original_bytes = b"test"
        result = converter._convert_to_bytes(original_bytes)
        if result != original_bytes:
            raise AssertionError(f"Expected {original_bytes}, got {result}")

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
