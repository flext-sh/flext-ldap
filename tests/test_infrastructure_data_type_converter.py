"""Tests for LDAP data type converter infrastructure in FLEXT-LDAP."""

import uuid
from datetime import datetime
from unittest.mock import MagicMock, patch

import pytest

from flext_ldap.infrastructure.data_type_converter import (
    FlextLdapConversionError,
    FlextLdapConversionResult,
    FlextLdapDataType,
    FlextLdapDataTypeConverter,
)


class TestFlextLdapDataType:
    """Test LDAP data type enumeration."""

    def test_data_type_values(self) -> None:
        """Test all data type enum values."""
        assert FlextLdapDataType.STRING.value == "string"
        assert FlextLdapDataType.INTEGER.value == "integer"
        assert FlextLdapDataType.BOOLEAN.value == "boolean"
        assert FlextLdapDataType.BINARY.value == "binary"
        assert FlextLdapDataType.DATE_TIME.value == "datetime"
        assert FlextLdapDataType.UUID.value == "uuid"
        assert FlextLdapDataType.DN.value == "dn"
        assert FlextLdapDataType.EMAIL.value == "email"
        assert FlextLdapDataType.PHONE.value == "phone"
        assert FlextLdapDataType.URL.value == "url"
        assert FlextLdapDataType.IP_ADDRESS.value == "ip_address"
        assert FlextLdapDataType.MAC_ADDRESS.value == "mac_address"
        assert FlextLdapDataType.CERTIFICATE.value == "certificate"
        assert FlextLdapDataType.PASSWORD.value == "password"
        assert FlextLdapDataType.UNKNOWN.value == "unknown"


class TestFlextLdapConversionError:
    """Test LDAP conversion error."""

    def test_conversion_error_basic(self) -> None:
        """Test basic conversion error creation."""
        error = FlextLdapConversionError("Test error")
        assert str(error) == "Test error"
        assert error.source_value is None
        assert error.target_type == ""

    def test_conversion_error_with_details(self) -> None:
        """Test conversion error with details."""
        error = FlextLdapConversionError(
            "Conversion failed",
            source_value="invalid_value",
            target_type="int",
        )
        assert str(error) == "Conversion failed"
        assert error.source_value == "invalid_value"
        assert error.target_type == "int"


class TestFlextLdapConversionResult:
    """Test LDAP conversion result."""

    def test_conversion_result_basic(self) -> None:
        """Test basic conversion result creation."""
        result = FlextLdapConversionResult(
            value="test",
            source_type=FlextLdapDataType.STRING,
            target_type=str,
        )
        assert result.value == "test"
        assert result.source_type == FlextLdapDataType.STRING
        assert result.target_type is str
        assert result.is_valid is True
        assert result.warnings == []
        assert result.metadata == {}

    def test_conversion_result_with_warnings(self) -> None:
        """Test conversion result with warnings."""
        warnings = ["Warning 1", "Warning 2"]
        metadata = {"key": "value"}

        result = FlextLdapConversionResult(
            value=42,
            source_type=FlextLdapDataType.INTEGER,
            target_type=int,
            is_valid=False,
            warnings=warnings,
            metadata=metadata,
        )

        assert result.value == 42
        assert result.is_valid is False
        assert result.warnings == warnings
        assert result.metadata == metadata

    def test_to_dict(self) -> None:
        """Test conversion result to dictionary."""
        result = FlextLdapConversionResult(
            value="test@example.com",
            source_type=FlextLdapDataType.EMAIL,
            target_type=str,
            warnings=["validation warning"],
            metadata={"domain": "example.com"},
        )

        result_dict = result.to_dict()

        assert result_dict["value"] == "test@example.com"
        assert result_dict["source_type"] == "email"
        assert result_dict["target_type"] == "str"
        assert result_dict["is_valid"] is True
        assert result_dict["warnings"] == ["validation warning"]
        assert result_dict["metadata"] == {"domain": "example.com"}


class TestFlextLdapDataTypeConverter:
    """Test LDAP data type converter."""

    @pytest.fixture
    def converter(self) -> FlextLdapDataTypeConverter:
        """Create data type converter instance."""
        return FlextLdapDataTypeConverter()

    def test_initialization(self, converter: FlextLdapDataTypeConverter) -> None:
        """Test converter initialization."""
        assert converter._type_detectors is not None
        assert converter._converters is not None
        assert len(converter._type_detectors) > 0
        assert len(converter._converters) > 0

    async def test_detect_type_none(
        self, converter: FlextLdapDataTypeConverter,
    ) -> None:
        """Test detect type for None value."""
        result = await converter.detect_type(None)

        assert result.success is True
        assert result.data == FlextLdapDataType.UNKNOWN

    async def test_detect_type_empty_string(
        self, converter: FlextLdapDataTypeConverter,
    ) -> None:
        """Test detect type for empty string."""
        result = await converter.detect_type("")

        assert result.success is True
        assert result.data == FlextLdapDataType.STRING

    async def test_detect_type_email(
        self, converter: FlextLdapDataTypeConverter,
    ) -> None:
        """Test detect type for email."""
        result = await converter.detect_type("test@example.com")

        assert result.success is True
        assert result.data == FlextLdapDataType.EMAIL

    async def test_detect_type_phone(
        self, converter: FlextLdapDataTypeConverter,
    ) -> None:
        """Test detect type for phone number."""
        result = await converter.detect_type("+1-234-567-8900")

        assert result.success is True
        assert result.data == FlextLdapDataType.PHONE

    async def test_detect_type_url(self, converter: FlextLdapDataTypeConverter) -> None:
        """Test detect type for URL."""
        result = await converter.detect_type("https://example.com")

        assert result.success is True
        assert result.data == FlextLdapDataType.URL

    async def test_detect_type_uuid(
        self, converter: FlextLdapDataTypeConverter,
    ) -> None:
        """Test detect type for UUID."""
        test_uuid = str(uuid.uuid4())
        result = await converter.detect_type(test_uuid)

        assert result.success is True
        assert result.data == FlextLdapDataType.UUID

    async def test_detect_type_boolean(
        self, converter: FlextLdapDataTypeConverter,
    ) -> None:
        """Test detect type for boolean values."""
        for bool_value in ["true", "false", "TRUE", "FALSE", "yes", "no"]:
            result = await converter.detect_type(bool_value)
            assert result.success is True
            assert result.data == FlextLdapDataType.BOOLEAN

    async def test_detect_type_integer(
        self, converter: FlextLdapDataTypeConverter,
    ) -> None:
        """Test detect type for integer."""
        result = await converter.detect_type("12345")

        assert result.success is True
        assert result.data == FlextLdapDataType.INTEGER

    async def test_detect_type_exception(
        self, converter: FlextLdapDataTypeConverter,
    ) -> None:
        """Test detect type with exception."""
        # Mock the type detectors dict items() method to raise exception
        mock_detectors = MagicMock()
        mock_detectors.items.side_effect = Exception("Detectors iteration failed")
        with patch.object(converter, "_type_detectors", mock_detectors):
            result = await converter.detect_type("test@example.com")

            assert result.success is False
            assert result.error is not None
            assert "Failed to detect data type" in result.error

    async def test_convert_value_string(
        self, converter: FlextLdapDataTypeConverter,
    ) -> None:
        """Test convert value to string."""
        result = await converter.convert_value(
            "test_value",
            str,
            FlextLdapDataType.STRING,
        )

        assert result.success is True
        assert isinstance(result.data, FlextLdapConversionResult)
        assert result.data.value == "test_value"
        assert result.data.target_type is str

    async def test_convert_value_integer(
        self, converter: FlextLdapDataTypeConverter,
    ) -> None:
        """Test convert value to integer."""
        result = await converter.convert_value(
            "123",
            int,
            FlextLdapDataType.INTEGER,
        )

        assert result.success is True
        assert isinstance(result.data, FlextLdapConversionResult)
        assert result.data.value == 123
        assert result.data.target_type is int

    async def test_convert_value_boolean(
        self, converter: FlextLdapDataTypeConverter,
    ) -> None:
        """Test convert value to boolean."""
        result = await converter.convert_value(
            "true",
            bool,
            FlextLdapDataType.BOOLEAN,
        )

        assert result.success is True
        assert isinstance(result.data, FlextLdapConversionResult)
        assert result.data.value is True
        assert result.data.target_type is bool

    async def test_convert_value_uuid(
        self, converter: FlextLdapDataTypeConverter,
    ) -> None:
        """Test convert value to UUID."""
        test_uuid = str(uuid.uuid4())
        result = await converter.convert_value(
            test_uuid,
            uuid.UUID,
            FlextLdapDataType.UUID,
        )

        assert result.success is True
        assert isinstance(result.data, FlextLdapConversionResult)
        assert isinstance(result.data.value, uuid.UUID)
        assert str(result.data.value) == test_uuid

    async def test_convert_value_unsupported_conversion(
        self, converter: FlextLdapDataTypeConverter,
    ) -> None:
        """Test convert value with unsupported conversion."""
        result = await converter.convert_value(
            "test",
            dict,  # Unsupported target type
            FlextLdapDataType.STRING,
        )

        assert result.success is True
        assert result.data is not None
        assert result.data.is_valid is False
        assert "Generic conversion failed" in result.data.warnings[0]

    async def test_convert_value_exception(
        self, converter: FlextLdapDataTypeConverter,
    ) -> None:
        """Test convert value with exception."""
        # Mock detect_type to raise an exception
        with patch.object(
            converter, "detect_type", side_effect=Exception("Detection failed"),
        ):
            result = await converter.convert_value(
                "123",
                int,
            )

            assert result.success is False
            assert result.error is not None
            assert "Value conversion failed" in result.error

    async def test_convert_batch_success(
        self, converter: FlextLdapDataTypeConverter,
    ) -> None:
        """Test batch conversion success."""
        values = ["test@example.com", "123", "true"]

        result = await converter.convert_batch(values, str)

        assert result.success is True
        assert result.data is not None
        assert len(result.data) == 3
        assert all(isinstance(r, FlextLdapConversionResult) for r in result.data)

    async def test_convert_batch_empty(
        self, converter: FlextLdapDataTypeConverter,
    ) -> None:
        """Test batch conversion with empty list."""
        result = await converter.convert_batch([], str)

        assert result.success is True
        assert result.data == []

    async def test_convert_batch_exception(
        self, converter: FlextLdapDataTypeConverter,
    ) -> None:
        """Test batch conversion with exception."""
        values = ["test"]

        result = await converter.convert_batch(values, dict)  # Invalid conversion

        assert result.success is True
        assert result.data is not None
        assert len(result.data) == 1
        assert result.data[0].is_valid is False
        assert "Generic conversion failed" in result.data[0].warnings[0]

    async def test_validate_type_compatibility_success(
        self, converter: FlextLdapDataTypeConverter,
    ) -> None:
        """Test validate type compatibility success."""
        result = await converter.validate_type_compatibility(
            FlextLdapDataType.STRING,
            str,
        )

        assert result.success is True
        assert result.data is True

    async def test_validate_type_compatibility_failure(
        self, converter: FlextLdapDataTypeConverter,
    ) -> None:
        """Test validate type compatibility failure."""
        result = await converter.validate_type_compatibility(
            FlextLdapDataType.STRING,
            dict,  # Unsupported
        )

        assert result.success is True
        assert result.data is False

    def test_get_supported_types(self, converter: FlextLdapDataTypeConverter) -> None:
        """Test get supported types."""
        types = converter.get_supported_types()

        assert isinstance(types, list)
        assert len(types) > 0
        assert all(isinstance(t, FlextLdapDataType) for t in types)

    def test_get_supported_conversions(
        self, converter: FlextLdapDataTypeConverter,
    ) -> None:
        """Test get supported conversions."""
        conversions = converter.get_supported_conversions()

        assert isinstance(conversions, dict)
        assert len(conversions) > 0
        assert all(isinstance(k, FlextLdapDataType) for k in conversions)

    # Test private detector methods
    def test_is_email(self, converter: FlextLdapDataTypeConverter) -> None:
        """Test email detection."""
        assert converter._is_email("test@example.com") is True
        assert converter._is_email("invalid-email") is False

    def test_is_phone(self, converter: FlextLdapDataTypeConverter) -> None:
        """Test phone detection."""
        assert converter._is_phone("+1-234-567-8900") is True
        assert converter._is_phone("123-456-7890") is True
        assert converter._is_phone("invalid-phone") is False

    def test_is_url(self, converter: FlextLdapDataTypeConverter) -> None:
        """Test URL detection."""
        assert converter._is_url("https://example.com") is True
        assert converter._is_url("http://test.org") is True
        assert converter._is_url("invalid-url") is False

    def test_is_ip_address(self, converter: FlextLdapDataTypeConverter) -> None:
        """Test IP address detection."""
        assert converter._is_ip_address("192.168.1.1") is True
        assert converter._is_ip_address("2001:db8::1") is True
        assert converter._is_ip_address("invalid-ip") is False

    def test_is_mac_address(self, converter: FlextLdapDataTypeConverter) -> None:
        """Test MAC address detection."""
        assert converter._is_mac_address("AA:BB:CC:DD:EE:FF") is True
        assert converter._is_mac_address("invalid-mac") is False

    def test_is_uuid(self, converter: FlextLdapDataTypeConverter) -> None:
        """Test UUID detection."""
        test_uuid = str(uuid.uuid4())
        assert converter._is_uuid(test_uuid) is True
        assert converter._is_uuid("invalid-uuid") is False

    def test_is_dn(self, converter: FlextLdapDataTypeConverter) -> None:
        """Test DN detection."""
        assert converter._is_dn("cn=test,dc=example,dc=org") is True
        assert converter._is_dn("invalid-dn") is False

    def test_is_datetime(self, converter: FlextLdapDataTypeConverter) -> None:
        """Test datetime detection."""
        assert converter._is_datetime("2023-01-01T12:00:00Z") is True
        assert converter._is_datetime("20230101120000Z") is True
        assert converter._is_datetime("invalid-datetime") is False

    def test_is_binary(self, converter: FlextLdapDataTypeConverter) -> None:
        """Test binary detection."""
        import base64

        # Create binary data with actual binary content (non-UTF8)
        binary_content = bytes(range(256))  # All possible byte values
        binary_data = base64.b64encode(binary_content).decode("ascii")
        assert converter._is_binary(binary_data) is True
        assert converter._is_binary("invalid-binary") is False

    def test_is_boolean(self, converter: FlextLdapDataTypeConverter) -> None:
        """Test boolean detection."""
        assert converter._is_boolean("true") is True
        assert converter._is_boolean("false") is True
        assert converter._is_boolean("TRUE") is True
        assert converter._is_boolean("FALSE") is True
        assert converter._is_boolean("invalid-boolean") is False

    def test_is_integer(self, converter: FlextLdapDataTypeConverter) -> None:
        """Test integer detection."""
        assert converter._is_integer("123") is True
        assert converter._is_integer("-456") is True
        assert converter._is_integer("invalid-integer") is False

    # Test private converter methods
    def test_convert_to_string(self, converter: FlextLdapDataTypeConverter) -> None:
        """Test convert to string."""
        assert converter._convert_to_string(123) == "123"
        assert converter._convert_to_string("test") == "test"

    def test_convert_to_int(self, converter: FlextLdapDataTypeConverter) -> None:
        """Test convert to int."""
        assert converter._convert_to_int("123") == 123
        assert converter._convert_to_int(456) == 456

    def test_convert_to_int_invalid(
        self, converter: FlextLdapDataTypeConverter,
    ) -> None:
        """Test convert to int with invalid value."""
        with pytest.raises(FlextLdapConversionError):
            converter._convert_to_int("invalid")

    def test_convert_to_bool(self, converter: FlextLdapDataTypeConverter) -> None:
        """Test convert to bool."""
        assert converter._convert_to_bool("true") is True
        assert converter._convert_to_bool("false") is False
        assert converter._convert_to_bool("1") is True
        assert converter._convert_to_bool("0") is False

    def test_convert_to_bytes(self, converter: FlextLdapDataTypeConverter) -> None:
        """Test convert to bytes."""
        import base64

        test_data = b"test data"
        encoded = base64.b64encode(test_data).decode("ascii")
        result = converter._convert_to_bytes(encoded)
        assert result == test_data

    def test_convert_to_bytes_invalid(
        self, converter: FlextLdapDataTypeConverter,
    ) -> None:
        """Test convert to bytes with invalid value."""
        # Invalid base64 gets encoded as UTF-8 fallback
        result = converter._convert_to_bytes("invalid-base64!")
        assert result == b"invalid-base64!"

    def test_convert_to_datetime(self, converter: FlextLdapDataTypeConverter) -> None:
        """Test convert to datetime."""
        # Test ISO format
        result = converter._convert_to_datetime("2023-01-01T12:00:00Z")
        assert isinstance(result, datetime)
        assert result.year == 2023

        # Test LDAP format
        result = converter._convert_to_datetime("20230101120000Z")
        assert isinstance(result, datetime)
        assert result.year == 2023

    def test_convert_to_datetime_invalid(
        self, converter: FlextLdapDataTypeConverter,
    ) -> None:
        """Test convert to datetime with invalid value."""
        with pytest.raises(FlextLdapConversionError):
            converter._convert_to_datetime("invalid-datetime")

    def test_convert_to_uuid(self, converter: FlextLdapDataTypeConverter) -> None:
        """Test convert to UUID."""
        test_uuid = str(uuid.uuid4())
        result = converter._convert_to_uuid(test_uuid)
        assert isinstance(result, uuid.UUID)
        assert str(result) == test_uuid

    def test_convert_to_uuid_invalid(
        self, converter: FlextLdapDataTypeConverter,
    ) -> None:
        """Test convert to UUID with invalid value."""
        with pytest.raises(FlextLdapConversionError):
            converter._convert_to_uuid("invalid-uuid")

    def test_convert_email_to_string(
        self, converter: FlextLdapDataTypeConverter,
    ) -> None:
        """Test convert email to string."""
        result = converter._convert_email_to_string("test@example.com")
        assert result == "test@example.com"

    def test_convert_phone_to_string(
        self, converter: FlextLdapDataTypeConverter,
    ) -> None:
        """Test convert phone to string."""
        result = converter._convert_phone_to_string("+1-234-567-8900")
        assert result == "+12345678900"

    def test_convert_url_to_string(self, converter: FlextLdapDataTypeConverter) -> None:
        """Test convert URL to string."""
        result = converter._convert_url_to_string("https://example.com")
        assert result == "https://example.com"

    def test_convert_ip_to_string(self, converter: FlextLdapDataTypeConverter) -> None:
        """Test convert IP to string."""
        result = converter._convert_ip_to_string("192.168.1.1")
        assert result == "192.168.1.1"

    def test_convert_mac_to_string(self, converter: FlextLdapDataTypeConverter) -> None:
        """Test convert MAC to string."""
        result = converter._convert_mac_to_string("AA:BB:CC:DD:EE:FF")
        assert result == "AA:BB:CC:DD:EE:FF"

    def test_convert_dn_to_string(self, converter: FlextLdapDataTypeConverter) -> None:
        """Test convert DN to string."""
        result = converter._convert_dn_to_string("cn=test,dc=example,dc=org")
        assert result == "cn=test,dc=example,dc=org"

    def test_convert_cert_to_bytes(self, converter: FlextLdapDataTypeConverter) -> None:
        """Test convert certificate to bytes."""
        import base64

        cert_data = b"certificate data"
        encoded = base64.b64encode(cert_data).decode("ascii")
        result = converter._convert_cert_to_bytes(encoded)
        assert result == cert_data

    def test_convert_cert_to_bytes_invalid(
        self, converter: FlextLdapDataTypeConverter,
    ) -> None:
        """Test convert certificate to bytes with invalid value."""
        # Invalid cert gets encoded as UTF-8 fallback
        result = converter._convert_cert_to_bytes("invalid-cert!")
        assert result == b"invalid-cert!"

        # TypeError is raised for non-string/bytes input
        with pytest.raises(TypeError):
            converter._convert_cert_to_bytes(123)
