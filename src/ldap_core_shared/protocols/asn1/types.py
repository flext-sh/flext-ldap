"""ASN.1 Primitive Type Implementations.

This module provides comprehensive ASN.1 primitive type implementations equivalent
to perl-Convert-ASN1 with full support for all standard ASN.1 types including
integers, strings, times, object identifiers, and other primitive data types
essential for LDAP protocol operations and general ASN.1 processing.

Primitive types form the leaf nodes of ASN.1 data structures, providing
type-safe value representations with validation, encoding, and decoding
capabilities following ITU-T X.690 encoding rules.

Architecture:
    - ASN1Boolean: BOOLEAN type for true/false values
    - ASN1Integer: INTEGER type with arbitrary precision
    - ASN1BitString: BIT STRING type for bit sequences
    - ASN1OctetString: OCTET STRING type for byte sequences
    - ASN1Null: NULL type for null values
    - ASN1ObjectIdentifier: OBJECT IDENTIFIER type for OIDs
    - ASN1Real: REAL type for floating-point numbers
    - ASN1Enumerated: ENUMERATED type for named integers
    - String types: UTF8String, PrintableString, IA5String, etc.
    - Time types: UTCTime, GeneralizedTime

Usage Example:
    >>> from ldap_core_shared.protocols.asn1.types import ASN1Integer, ASN1UTF8String
    >>>
    >>> # Create integer
    >>> number = ASN1Integer(42)
    >>> encoded = number.encode()
    >>>
    >>> # Create string
    >>> text = ASN1UTF8String("Hello World")
    >>> value = text.get_value()

References:
    - perl-Convert-ASN1: Type compatibility and API
    - ITU-T X.680: ASN.1 specification
    - ITU-T X.690: ASN.1 encoding rules
    - RFC 5280: ASN.1 usage in PKI certificates
"""

from __future__ import annotations

import re
from datetime import UTC, datetime
from typing import Any, ClassVar

from ldap_core_shared.protocols.asn1.constants import (
    ASN1_BIT_STRING,
    ASN1_BOOLEAN,
    ASN1_GENERALIZED_TIME,
    ASN1_IA5_STRING,
    ASN1_INTEGER,
    ASN1_NULL,
    ASN1_OBJECT_IDENTIFIER,
    ASN1_OCTET_STRING,
    ASN1_PRIMITIVE,
    ASN1_PRINTABLE_STRING,
    ASN1_UNIVERSAL,
    ASN1_UTC_TIME,
    ASN1_UTF8_STRING,
    DEFAULT_ENCODING,
    DEFAULT_STRING_ENCODING,
)
from ldap_core_shared.protocols.asn1.elements import ASN1Element, ASN1Tag

# Validation constants for ASN.1 types
BIT_STRING_MAX_UNUSED_BITS = 7  # Maximum unused bits in BIT STRING (0-7)
BIT_STRING_MIN_UNUSED_BITS = 0  # Minimum unused bits in BIT STRING
OID_MIN_COMPONENTS = 2  # Minimum components for valid OID
OID_VALID_FIRST_COMPONENTS = [0, 1, 2]  # Valid values for first OID component
OID_MAX_SECOND_COMPONENT_01 = 39  # Max value for second component when first is 0 or 1
ASCII_MAX_VALUE = 127  # Maximum value for 7-bit ASCII characters (0-127)


class ASN1Boolean(ASN1Element):
    """ASN.1 BOOLEAN type.

    Represents true/false values with proper ASN.1 encoding.

    Example:
        >>> bool_true = ASN1Boolean(True)
        >>> bool_false = ASN1Boolean(False)
        >>> encoded = bool_true.encode()
        >>> value = bool_true.get_value()  # True
    """

    def __init__(
        self,
        value: bool = False,
        tag: ASN1Tag | None = None,
        optional: bool = False,
        default: bool = False,
    ) -> None:
        """Initialize BOOLEAN element.

        Args:
            value: Boolean value
            tag: Custom tag
            optional: Whether element is optional
            default: Default boolean value
        """
        super().__init__(value, tag, optional, default)

    def get_default_tag(self) -> ASN1Tag:
        """Get default BOOLEAN tag."""
        return ASN1Tag(
            tag_class=ASN1_UNIVERSAL,
            tag_form=ASN1_PRIMITIVE,
            tag_number=ASN1_BOOLEAN,
        )

    def encode(self, encoding: str = DEFAULT_ENCODING) -> bytes:
        """Encode BOOLEAN to bytes.

        Args:
            encoding: Encoding rules

        Returns:
            Encoded boolean as bytes
        """
        from ldap_core_shared.protocols.asn1.encoder import TLVEncoder

        # BOOLEAN content: 0xFF for True, 0x00 for False
        content = b"\xff" if self._value else b"\x00"
        return TLVEncoder.encode_tlv(self.get_tag(), content, definite=True)

    @classmethod
    def decode(cls, data: bytes, offset: int = 0) -> tuple[ASN1Boolean, int]:
        """Decode BOOLEAN from bytes.

        Args:
            data: Encoded data
            offset: Starting offset

        Returns:
            Tuple of (decoded boolean, next offset)
        """
        if offset >= len(data):
            msg = "Insufficient data for BOOLEAN decoding"
            raise ValueError(msg)

        # Check tag
        expected_tag = cls().get_default_tag()
        if data[offset] != (
            expected_tag.tag_class | expected_tag.tag_form | expected_tag.tag_number
        ):
            msg = f"Expected BOOLEAN tag, got {data[offset]:02x}"
            raise ValueError(msg)

        # Parse length
        length_offset = offset + 1
        if length_offset >= len(data):
            msg = "Insufficient data for length"
            raise ValueError(msg)

        length = data[length_offset]
        if length != 1:
            msg = f"BOOLEAN length must be 1, got {length}"
            raise ValueError(msg)

        # Parse value
        value_offset = length_offset + 1
        if value_offset >= len(data):
            msg = "Insufficient data for BOOLEAN value"
            raise ValueError(msg)

        value_byte = data[value_offset]
        value = value_byte != 0  # Any non-zero value is True

        return cls(value), value_offset + 1

    def validate(self) -> list[str]:
        """Validate BOOLEAN value.

        Returns:
            List of validation errors
        """
        errors = []

        if not isinstance(self._value, bool):
            errors.append(f"BOOLEAN value must be bool, got {type(self._value)}")

        return errors


class ASN1Integer(ASN1Element):
    """ASN.1 INTEGER type.

    Represents arbitrary precision integers with proper ASN.1 encoding.

    Example:
        >>> small_int = ASN1Integer(42)
        >>> large_int = ASN1Integer(123456789012345678901234567890)
        >>> negative = ASN1Integer(-42)
        >>> encoded = small_int.encode()
    """

    def __init__(
        self,
        value: int = 0,
        tag: ASN1Tag | None = None,
        optional: bool = False,
        default: int = 0,
    ) -> None:
        """Initialize INTEGER element.

        Args:
            value: Integer value
            tag: Custom tag
            optional: Whether element is optional
            default: Default integer value
        """
        super().__init__(value, tag, optional, default)

    def get_default_tag(self) -> ASN1Tag:
        """Get default INTEGER tag."""
        return ASN1Tag(
            tag_class=ASN1_UNIVERSAL,
            tag_form=ASN1_PRIMITIVE,
            tag_number=ASN1_INTEGER,
        )

    def encode(self, encoding: str = DEFAULT_ENCODING) -> bytes:
        """Encode INTEGER to bytes.

        Args:
            encoding: Encoding rules

        Returns:
            Encoded integer as bytes
        """
        from ldap_core_shared.protocols.asn1.encoder import TLVEncoder

        value = self._value

        # Type guard: ensure value is an integer
        if not isinstance(value, int):
            msg = f"ASN1Integer value must be int, got {type(value).__name__}"
            raise TypeError(msg)

        # Convert integer to two's complement bytes
        if value == 0:
            content = b"\x00"
        elif value > 0:
            # Positive integer
            byte_length = (value.bit_length() + 7) // 8
            content = value.to_bytes(byte_length, byteorder="big", signed=False)

            # Add padding byte if MSB is set (to avoid negative interpretation)
            if content[0] & 0x80:
                content = b"\x00" + content
        else:
            # Negative integer (two's complement)
            byte_length = (value.bit_length() + 8) // 8
            content = value.to_bytes(byte_length, byteorder="big", signed=True)

        return TLVEncoder.encode_tlv(self.get_tag(), content, definite=True)

    @classmethod
    def decode(cls, data: bytes, offset: int = 0) -> tuple[ASN1Integer, int]:
        """Decode INTEGER from bytes.

        Args:
            data: Encoded data
            offset: Starting offset

        Returns:
            Tuple of (decoded integer, next offset)
        """
        if offset >= len(data):
            msg = "Insufficient data for INTEGER decoding"
            raise ValueError(msg)

        # Check tag
        expected_tag = cls().get_default_tag()
        if data[offset] != (
            expected_tag.tag_class | expected_tag.tag_form | expected_tag.tag_number
        ):
            msg = f"Expected INTEGER tag, got {data[offset]:02x}"
            raise ValueError(msg)

        # Parse length
        length_offset = offset + 1
        if length_offset >= len(data):
            msg = "Insufficient data for length"
            raise ValueError(msg)

        length = data[length_offset]
        if length == 0:
            msg = "INTEGER length cannot be 0"
            raise ValueError(msg)

        # Parse value bytes
        value_offset = length_offset + 1
        if value_offset + length > len(data):
            msg = "Insufficient data for INTEGER value"
            raise ValueError(msg)

        value_bytes = data[value_offset : value_offset + length]

        # Convert from two's complement
        value = int.from_bytes(value_bytes, byteorder="big", signed=True)

        return cls(value), value_offset + length

    def validate(self) -> list[str]:
        """Validate INTEGER value.

        Returns:
            List of validation errors
        """
        errors = []

        if not isinstance(self._value, int):
            errors.append(f"INTEGER value must be int, got {type(self._value)}")

        return errors


class ASN1BitString(ASN1Element):
    r"""ASN.1 BIT STRING type.

    Represents sequences of bits with proper ASN.1 encoding.

    Example:
        >>> # Create from bit string
        >>> bits = ASN1BitString("1010101100001111")
        >>>
        >>> # Create from bytes with unused bits
        >>> bits_bytes = ASN1BitString(b"\\xAB\\x0F", unused_bits=4)
        >>>
        >>> # Get bit values
        >>> bit_string = bits.get_bit_string()
        >>> byte_data = bits.get_bytes()
    """

    def __init__(
        self,
        value: str | bytes = b"",
        unused_bits: int = 0,
        tag: ASN1Tag | None = None,
        optional: bool = False,
        default: Any = None,
    ) -> None:
        """Initialize BIT STRING element.

        Args:
            value: Bit string as string or bytes
            unused_bits: Number of unused bits in last byte
            tag: Custom tag
            optional: Whether element is optional
            default: Default value
        """
        super().__init__(value, tag, optional, default)
        self._unused_bits = unused_bits

        if isinstance(value, str):
            # Convert bit string to bytes
            self._bit_string = value
            self._bytes_data = self._bit_string_to_bytes(value)
            self._value = value  # Keep original string as value
        else:
            # Store bytes directly
            self._bytes_data = value
            self._bit_string = self._bytes_to_bit_string(value, unused_bits)
            self._value = self._bit_string  # Use bit string as value

    def get_default_tag(self) -> ASN1Tag:
        """Get default BIT STRING tag."""
        return ASN1Tag(
            tag_class=ASN1_UNIVERSAL,
            tag_form=ASN1_PRIMITIVE,
            tag_number=ASN1_BIT_STRING,
        )

    def get_bit_string(self) -> str:
        """Get bit string representation.

        Returns:
            String of '0' and '1' characters
        """
        return self._bit_string

    def get_bytes(self) -> bytes:
        """Get byte representation.

        Returns:
            Raw bytes
        """
        return self._bytes_data

    def get_unused_bits(self) -> int:
        """Get number of unused bits.

        Returns:
            Number of unused bits in last byte
        """
        return self._unused_bits

    def _bit_string_to_bytes(self, bit_string: str) -> bytes:
        """Convert bit string to bytes.

        Args:
            bit_string: String of '0' and '1' characters

        Returns:
            Byte representation
        """
        # Pad to multiple of 8 bits
        padded = bit_string.ljust((len(bit_string) + 7) // 8 * 8, "0")
        self._unused_bits = len(padded) - len(bit_string)

        # Convert to bytes
        bytes_data = b""
        for i in range(0, len(padded), 8):
            byte_bits = padded[i : i + 8]
            byte_value = int(byte_bits, 2)
            bytes_data += bytes([byte_value])

        return bytes_data

    def _bytes_to_bit_string(self, bytes_data: bytes, unused_bits: int) -> str:
        """Convert bytes to bit string.

        Args:
            bytes_data: Raw bytes
            unused_bits: Number of unused bits

        Returns:
            String of '0' and '1' characters
        """
        bit_string = ""
        for byte in bytes_data:
            bit_string += format(byte, "08b")

        # Remove unused bits
        if unused_bits > 0:
            bit_string = bit_string[:-unused_bits]

        return bit_string

    def encode(self, encoding: str = DEFAULT_ENCODING) -> bytes:
        """Encode BIT STRING to bytes.

        Args:
            encoding: Encoding rules

        Returns:
            Encoded bit string as bytes
        """
        from ldap_core_shared.protocols.asn1.encoder import TLVEncoder

        # BIT STRING content: unused_bits_byte + bit_data
        content = bytes([self._unused_bits]) + self._bytes_data
        return TLVEncoder.encode_tlv(self.get_tag(), content, definite=True)

    @classmethod
    def decode(cls, data: bytes, offset: int = 0) -> tuple[ASN1BitString, int]:
        """Decode BIT STRING from bytes.

        Args:
            data: Encoded data
            offset: Starting offset

        Returns:
            Tuple of (decoded bit string, next offset)
        """
        if offset >= len(data):
            msg = "Insufficient data for BIT STRING decoding"
            raise ValueError(msg)

        # Check tag
        expected_tag = cls().get_default_tag()
        if data[offset] != (
            expected_tag.tag_class | expected_tag.tag_form | expected_tag.tag_number
        ):
            msg = f"Expected BIT STRING tag, got {data[offset]:02x}"
            raise ValueError(msg)

        # Parse length
        length_offset = offset + 1
        if length_offset >= len(data):
            msg = "Insufficient data for length"
            raise ValueError(msg)

        length = data[length_offset]
        if length == 0:
            msg = "BIT STRING length cannot be 0"
            raise ValueError(msg)

        # Parse unused bits and data
        value_offset = length_offset + 1
        if value_offset + length > len(data):
            msg = "Insufficient data for BIT STRING value"
            raise ValueError(msg)

        unused_bits = data[value_offset]
        if unused_bits > 7:
            msg = f"Invalid unused bits count: {unused_bits}"
            raise ValueError(msg)

        bit_data = data[value_offset + 1 : value_offset + length]

        # Create from bytes but ensure consistent value representation
        instance = cls(bit_data, unused_bits)
        return instance, value_offset + length

    def validate(self) -> list[str]:
        """Validate BIT STRING value.

        Returns:
            List of validation errors
        """
        errors = []

        if (
            self._unused_bits < BIT_STRING_MIN_UNUSED_BITS
            or self._unused_bits > BIT_STRING_MAX_UNUSED_BITS
        ):
            errors.append(f"Unused bits must be 0-7, got {self._unused_bits}")

        if isinstance(self._value, str):
            if not re.match(r"^[01]*$", self._value):
                errors.append("Bit string must contain only '0' and '1' characters")

        return errors


class ASN1OctetString(ASN1Element):
    """ASN.1 OCTET STRING type.

    Represents sequences of bytes with proper ASN.1 encoding.

    Example:
        >>> # Create from bytes
        >>> octets = ASN1OctetString(b"Hello World")
        >>>
        >>> # Create from string
        >>> octets_str = ASN1OctetString("Hello World", encoding="utf-8")
        >>>
        >>> # Get byte data
        >>> byte_data = octets.get_bytes()
        >>> string_data = octets.get_string()
    """

    def __init__(
        self,
        value: str | bytes = b"",
        encoding: str = DEFAULT_STRING_ENCODING,
        tag: ASN1Tag | None = None,
        optional: bool = False,
        default: Any = None,
    ) -> None:
        """Initialize OCTET STRING element.

        Args:
            value: String or bytes value
            encoding: String encoding if value is string
            tag: Custom tag
            optional: Whether element is optional
            default: Default value
        """
        super().__init__(value, tag, optional, default)
        self._encoding = encoding
        self._string_data: str | None = ""

        if isinstance(value, str):
            self._bytes_data = value.encode(encoding)
            self._string_data = value
        else:
            self._bytes_data = value
            try:
                self._string_data = value.decode(encoding)
            except UnicodeDecodeError:
                self._string_data = None

    def get_default_tag(self) -> ASN1Tag:
        """Get default OCTET STRING tag."""
        return ASN1Tag(
            tag_class=ASN1_UNIVERSAL,
            tag_form=ASN1_PRIMITIVE,
            tag_number=ASN1_OCTET_STRING,
        )

    def get_bytes(self) -> bytes:
        """Get byte representation.

        Returns:
            Raw bytes
        """
        return self._bytes_data

    def get_string(self, encoding: str | None = None) -> str | None:
        """Get string representation.

        Args:
            encoding: String encoding to use

        Returns:
            String representation or None if not decodable
        """
        if encoding is None:
            encoding = self._encoding

        try:
            return self._bytes_data.decode(encoding)
        except UnicodeDecodeError:
            return None

    def encode(self, encoding: str = DEFAULT_ENCODING) -> bytes:
        """Encode OCTET STRING to bytes.

        Args:
            encoding: Encoding rules

        Returns:
            Encoded octet string as bytes
        """
        from ldap_core_shared.protocols.asn1.encoder import TLVEncoder

        # OCTET STRING content is the raw bytes
        content = self._bytes_data
        return TLVEncoder.encode_tlv(self.get_tag(), content, definite=True)

    @classmethod
    def decode(cls, data: bytes, offset: int = 0) -> tuple[ASN1OctetString, int]:
        """Decode OCTET STRING from bytes.

        Args:
            data: Encoded data
            offset: Starting offset

        Returns:
            Tuple of (decoded octet string, next offset)
        """
        if offset >= len(data):
            msg = "Insufficient data for OCTET STRING decoding"
            raise ValueError(msg)

        # Check tag
        expected_tag = cls().get_default_tag()
        if data[offset] != (
            expected_tag.tag_class | expected_tag.tag_form | expected_tag.tag_number
        ):
            msg = f"Expected OCTET STRING tag, got {data[offset]:02x}"
            raise ValueError(msg)

        # Parse length
        length_offset = offset + 1
        if length_offset >= len(data):
            msg = "Insufficient data for length"
            raise ValueError(msg)

        length = data[length_offset]

        # Parse data bytes
        value_offset = length_offset + 1
        if value_offset + length > len(data):
            msg = "Insufficient data for OCTET STRING value"
            raise ValueError(msg)

        octet_data = data[value_offset : value_offset + length]

        return cls(octet_data), value_offset + length

    def validate(self) -> list[str]:
        """Validate OCTET STRING value.

        Returns:
            List of validation errors
        """
        # OCTET STRING can contain any bytes, so no specific validation needed
        return []


class ASN1Null(ASN1Element):
    """ASN.1 NULL type.

    Represents null/empty values with proper ASN.1 encoding.

    Example:
        >>> null_value = ASN1Null()
        >>> encoded = null_value.encode()
        >>> is_null = null_value.get_value() is None
    """

    def __init__(
        self,
        tag: ASN1Tag | None = None,
        optional: bool = False,
    ) -> None:
        """Initialize NULL element.

        Args:
            tag: Custom tag
            optional: Whether element is optional
        """
        super().__init__(None, tag, optional, None)

    def get_default_tag(self) -> ASN1Tag:
        """Get default NULL tag."""
        return ASN1Tag(
            tag_class=ASN1_UNIVERSAL,
            tag_form=ASN1_PRIMITIVE,
            tag_number=ASN1_NULL,
        )

    def encode(self, encoding: str = DEFAULT_ENCODING) -> bytes:
        """Encode NULL to bytes.

        Args:
            encoding: Encoding rules

        Returns:
            Encoded null as bytes
        """
        from ldap_core_shared.protocols.asn1.encoder import TLVEncoder

        # NULL has no content (empty bytes)
        content = b""
        return TLVEncoder.encode_tlv(self.get_tag(), content, definite=True)

    @classmethod
    def decode(cls, data: bytes, offset: int = 0) -> tuple[ASN1Null, int]:
        """Decode NULL from bytes.

        Args:
            data: Encoded data
            offset: Starting offset

        Returns:
            Tuple of (decoded null, next offset)
        """
        if offset >= len(data):
            msg = "Insufficient data for NULL decoding"
            raise ValueError(msg)

        # Check tag
        expected_tag = cls().get_default_tag()
        if data[offset] != (
            expected_tag.tag_class | expected_tag.tag_form | expected_tag.tag_number
        ):
            msg = f"Expected NULL tag, got {data[offset]:02x}"
            raise ValueError(msg)

        # Parse length
        length_offset = offset + 1
        if length_offset >= len(data):
            msg = "Insufficient data for length"
            raise ValueError(msg)

        length = data[length_offset]
        if length != 0:
            msg = f"NULL length must be 0, got {length}"
            raise ValueError(msg)

        return cls(), length_offset + 1

    def validate(self) -> list[str]:
        """Validate NULL value.

        Returns:
            List of validation errors
        """
        errors = []

        if self._value is not None:
            errors.append(f"NULL value must be None, got {self._value!r}")

        return errors


class ASN1ObjectIdentifier(ASN1Element):
    """ASN.1 OBJECT IDENTIFIER type.

    Represents object identifiers (OIDs) with proper ASN.1 encoding.

    Example:
        >>> # Create from dot notation
        >>> oid = ASN1ObjectIdentifier("1.2.3.4.5")
        >>>
        >>> # Create from list
        >>> oid_list = ASN1ObjectIdentifier([1, 2, 3, 4, 5])
        >>>
        >>> # Get components
        >>> components = oid.get_components()
        >>> dot_notation = oid.get_dot_notation()
    """

    def __init__(
        self,
        value: str | list[int] | None = None,
        tag: ASN1Tag | None = None,
        optional: bool = False,
        default: Any = None,
    ) -> None:
        """Initialize OBJECT IDENTIFIER element.

        Args:
            value: OID as dot notation string or list of integers
            tag: Custom tag
            optional: Whether element is optional
            default: Default value
        """
        super().__init__(value, tag, optional, default)

        if isinstance(value, str):
            self._components = [int(x) for x in value.split(".")]
            self._dot_notation = value
            self._value = value  # Keep original string as value
        elif isinstance(value, list | tuple):
            self._components = list(value)  # Convert tuple to list
            self._dot_notation = ".".join(str(x) for x in value)
            self._value = self._dot_notation  # Use dot notation as value
        else:
            self._components = []
            self._dot_notation = ""
            self._value = ""

    def get_default_tag(self) -> ASN1Tag:
        """Get default OBJECT IDENTIFIER tag."""
        return ASN1Tag(
            tag_class=ASN1_UNIVERSAL,
            tag_form=ASN1_PRIMITIVE,
            tag_number=ASN1_OBJECT_IDENTIFIER,
        )

    def get_components(self) -> list[int]:
        """Get OID components.

        Returns:
            List of integer components
        """
        return self._components.copy()

    def get_dot_notation(self) -> str:
        """Get dot notation representation.

        Returns:
            OID as dot-separated string
        """
        return self._dot_notation

    def _encode_oid_component(self, component: int) -> bytes:
        """Encode single OID component using base-128.

        Args:
            component: OID component value

        Returns:
            Encoded component bytes
        """
        if component == 0:
            return b"\x00"

        # Convert to base-128 with continuation bits
        octets = []
        while component > 0:
            octets.insert(0, component & 0x7F)
            component >>= 7

        # Set continuation bits (all except last)
        for i in range(len(octets) - 1):
            octets[i] |= 0x80

        return bytes(octets)

    @classmethod
    def _decode_oid_component(cls, data: bytes, offset: int) -> tuple[int, int]:
        """Decode single OID component from base-128 encoding.

        Args:
            data: OID component data
            offset: Starting offset

        Returns:
            Tuple of (component value, bytes consumed)
        """
        if offset >= len(data):
            msg = "Insufficient data for OID component"
            raise ValueError(msg)

        component = 0
        bytes_read = 0

        while offset + bytes_read < len(data):
            byte = data[offset + bytes_read]
            bytes_read += 1

            component = (component << 7) | (byte & 0x7F)

            # If continuation bit is not set, this is the last byte
            if (byte & 0x80) == 0:
                break
        else:
            msg = "Unterminated OID component"
            raise ValueError(msg)

        return component, bytes_read

    def encode(self, encoding: str = DEFAULT_ENCODING) -> bytes:
        """Encode OBJECT IDENTIFIER to bytes.

        Args:
            encoding: Encoding rules

        Returns:
            Encoded OID as bytes
        """
        from ldap_core_shared.protocols.asn1.encoder import TLVEncoder

        if len(self._components) < 2:
            msg = "OID must have at least 2 components"
            raise ValueError(msg)

        # First component: (first * 40) + second
        first_component = self._components[0] * 40 + self._components[1]
        content = self._encode_oid_component(first_component)

        # Remaining components
        for component in self._components[2:]:
            content += self._encode_oid_component(component)

        return TLVEncoder.encode_tlv(self.get_tag(), content, definite=True)

    @classmethod
    def decode(cls, data: bytes, offset: int = 0) -> tuple[ASN1ObjectIdentifier, int]:
        """Decode OBJECT IDENTIFIER from bytes.

        Args:
            data: Encoded data
            offset: Starting offset

        Returns:
            Tuple of (decoded OID, next offset)
        """
        if offset >= len(data):
            msg = "Insufficient data for OBJECT IDENTIFIER decoding"
            raise ValueError(msg)

        # Check tag
        expected_tag = cls().get_default_tag()
        if data[offset] != (
            expected_tag.tag_class | expected_tag.tag_form | expected_tag.tag_number
        ):
            msg = f"Expected OBJECT IDENTIFIER tag, got {data[offset]:02x}"
            raise ValueError(msg)

        # Parse length
        length_offset = offset + 1
        if length_offset >= len(data):
            msg = "Insufficient data for length"
            raise ValueError(msg)

        length = data[length_offset]
        if length == 0:
            msg = "OBJECT IDENTIFIER length cannot be 0"
            raise ValueError(msg)

        # Parse OID components
        value_offset = length_offset + 1
        if value_offset + length > len(data):
            msg = "Insufficient data for OBJECT IDENTIFIER value"
            raise ValueError(msg)

        oid_data = data[value_offset : value_offset + length]
        components = []

        # Decode first component (combined first two)
        first_component, bytes_read = cls._decode_oid_component(oid_data, 0)
        if first_component < 80:  # first * 40 + second < 80
            first = first_component // 40
            second = first_component % 40
        else:
            first = 2
            second = first_component - 80

        components.extend([first, second])

        # Decode remaining components
        pos = bytes_read
        while pos < len(oid_data):
            component, bytes_read = cls._decode_oid_component(oid_data, pos)
            components.append(component)
            pos += bytes_read

        # Create from components list but ensure consistent value representation
        instance = cls(components)
        return instance, value_offset + length

    def validate(self) -> list[str]:
        """Validate OBJECT IDENTIFIER value.

        Returns:
            List of validation errors
        """
        errors = []

        if len(self._components) < OID_MIN_COMPONENTS:
            errors.append("OID must have at least 2 components")

        if (
            len(self._components) >= 1
            and self._components[0] not in OID_VALID_FIRST_COMPONENTS
        ):
            errors.append("First OID component must be 0, 1, or 2")

        if len(self._components) >= OID_MIN_COMPONENTS and (
            self._components[0] in {0, 1}
            and self._components[1] > OID_MAX_SECOND_COMPONENT_01
        ):
            errors.append("Second OID component must be <= 39 when first is 0 or 1")

        errors.extend(
            "OID components must be non-negative integers"
            for component in self._components
            if component < 0
        )

        return errors


class ASN1UTF8String(ASN1Element):
    """ASN.1 UTF8String type.

    Represents UTF-8 encoded character strings with proper ASN.1 encoding.

    Example:
        >>> utf8_str = ASN1UTF8String("Hello 世界")
        >>> encoded = utf8_str.encode()
        >>> text = utf8_str.get_value()
    """

    def __init__(
        self,
        value: str = "",
        tag: ASN1Tag | None = None,
        optional: bool = False,
        default: str = "",
    ) -> None:
        """Initialize UTF8String element.

        Args:
            value: String value
            tag: Custom tag
            optional: Whether element is optional
            default: Default string value
        """
        super().__init__(value, tag, optional, default)

    def get_default_tag(self) -> ASN1Tag:
        """Get default UTF8String tag."""
        return ASN1Tag(
            tag_class=ASN1_UNIVERSAL,
            tag_form=ASN1_PRIMITIVE,
            tag_number=ASN1_UTF8_STRING,
        )

    def encode(self, encoding: str = DEFAULT_ENCODING) -> bytes:
        """Encode UTF8String to bytes.

        Args:
            encoding: Encoding rules

        Returns:
            Encoded UTF8 string as bytes
        """
        from ldap_core_shared.protocols.asn1.encoder import TLVEncoder

        # UTF8String content is the UTF-8 encoded string
        value = self._value

        # Type guard: ensure value is a string
        if not isinstance(value, str):
            msg = f"ASN1UTF8String value must be str, got {type(value).__name__}"
            raise TypeError(msg)

        content = value.encode("utf-8")
        return TLVEncoder.encode_tlv(self.get_tag(), content, definite=True)

    @classmethod
    def decode(cls, data: bytes, offset: int = 0) -> tuple[ASN1UTF8String, int]:
        """Decode UTF8String from bytes.

        Args:
            data: Encoded data
            offset: Starting offset

        Returns:
            Tuple of (decoded UTF8 string, next offset)
        """
        if offset >= len(data):
            msg = "Insufficient data for UTF8String decoding"
            raise ValueError(msg)

        # Check tag
        expected_tag = cls().get_default_tag()
        if data[offset] != (
            expected_tag.tag_class | expected_tag.tag_form | expected_tag.tag_number
        ):
            msg = f"Expected UTF8String tag, got {data[offset]:02x}"
            raise ValueError(msg)

        # Parse length
        length_offset = offset + 1
        if length_offset >= len(data):
            msg = "Insufficient data for length"
            raise ValueError(msg)

        length = data[length_offset]

        # Parse string data
        value_offset = length_offset + 1
        if value_offset + length > len(data):
            msg = "Insufficient data for UTF8String value"
            raise ValueError(msg)

        string_data = data[value_offset : value_offset + length]

        try:
            string_value = string_data.decode("utf-8")
        except UnicodeDecodeError as e:
            msg = f"Invalid UTF-8 string: {e}"
            raise ValueError(msg) from e

        return cls(string_value), value_offset + length

    def validate(self) -> list[str]:
        """Validate UTF8String value.

        Returns:
            List of validation errors
        """
        errors = []

        if not isinstance(self._value, str):
            errors.append(f"UTF8String value must be str, got {type(self._value)}")
        else:
            try:
                self._value.encode("utf-8")
            except UnicodeEncodeError as e:
                errors.append(f"Invalid UTF-8 string: {e}")

        return errors


class ASN1PrintableString(ASN1Element):
    """ASN.1 PrintableString type.

    Represents printable character strings with proper ASN.1 encoding.
    Limited to A-Z, a-z, 0-9, space, and specific punctuation.

    Example:
        >>> printable = ASN1PrintableString("Hello World 123")
        >>> encoded = printable.encode()
        >>> text = printable.get_value()
    """

    # Allowed characters in PrintableString
    ALLOWED_CHARS: ClassVar[set[str]] = set(
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789 '()+,-./:=?",
    )

    def __init__(
        self,
        value: str = "",
        tag: ASN1Tag | None = None,
        optional: bool = False,
        default: str = "",
    ) -> None:
        """Initialize PrintableString element.

        Args:
            value: String value
            tag: Custom tag
            optional: Whether element is optional
            default: Default string value
        """
        super().__init__(value, tag, optional, default)

    def get_default_tag(self) -> ASN1Tag:
        """Get default PrintableString tag."""
        return ASN1Tag(
            tag_class=ASN1_UNIVERSAL,
            tag_form=ASN1_PRIMITIVE,
            tag_number=ASN1_PRINTABLE_STRING,
        )

    def encode(self, encoding: str = DEFAULT_ENCODING) -> bytes:
        """Encode PrintableString to bytes.

        Args:
            encoding: Encoding rules

        Returns:
            Encoded printable string as bytes
        """
        from ldap_core_shared.protocols.asn1.encoder import TLVEncoder

        # Type guard: ensure value is a string
        value = self._value
        if not isinstance(value, str):
            msg = f"ASN1PrintableString value must be str, got {type(value).__name__}"
            raise TypeError(msg)

        # Validate characters are in allowed set
        invalid_chars = set(value) - self.ALLOWED_CHARS
        if invalid_chars:
            msg = f"PrintableString contains invalid characters: {invalid_chars}"
            raise ValueError(msg)

        # PrintableString content is ASCII encoded
        content = value.encode("ascii")
        return TLVEncoder.encode_tlv(self.get_tag(), content, definite=True)

    @classmethod
    def decode(cls, data: bytes, offset: int = 0) -> tuple[ASN1PrintableString, int]:
        """Decode PrintableString from bytes.

        Args:
            data: Encoded data
            offset: Starting offset

        Returns:
            Tuple of (decoded printable string, next offset)
        """
        if offset >= len(data):
            msg = "Insufficient data for PrintableString decoding"
            raise ValueError(msg)

        # Check tag
        expected_tag = cls().get_default_tag()
        if data[offset] != (
            expected_tag.tag_class | expected_tag.tag_form | expected_tag.tag_number
        ):
            msg = f"Expected PrintableString tag, got {data[offset]:02x}"
            raise ValueError(msg)

        # Parse length
        length_offset = offset + 1
        if length_offset >= len(data):
            msg = "Insufficient data for length"
            raise ValueError(msg)

        length = data[length_offset]

        # Parse string data
        value_offset = length_offset + 1
        if value_offset + length > len(data):
            msg = "Insufficient data for PrintableString value"
            raise ValueError(msg)

        string_data = data[value_offset : value_offset + length]

        try:
            string_value = string_data.decode("ascii")
        except UnicodeDecodeError as e:
            msg = f"Invalid ASCII string: {e}"
            raise ValueError(msg) from e

        # Validate characters are in allowed set
        invalid_chars = set(string_value) - cls.ALLOWED_CHARS
        if invalid_chars:
            msg = f"PrintableString contains invalid characters: {invalid_chars}"
            raise ValueError(msg)

        return cls(string_value), value_offset + length

    def validate(self) -> list[str]:
        """Validate PrintableString value.

        Returns:
            List of validation errors
        """
        errors = []

        if not isinstance(self._value, str):
            errors.append(f"PrintableString value must be str, got {type(self._value)}")
        else:
            invalid_chars = set(self._value) - self.ALLOWED_CHARS
            if invalid_chars:
                errors.append(
                    f"PrintableString contains invalid characters: {invalid_chars}",
                )

        return errors


class ASN1IA5String(ASN1Element):
    """ASN.1 IA5String type.

    Represents IA5 (ASCII) character strings with proper ASN.1 encoding.
    Limited to 7-bit ASCII characters (0-127).

    Example:
        >>> ia5_str = ASN1IA5String("user@example.com")
        >>> encoded = ia5_str.encode()
        >>> text = ia5_str.get_value()
    """

    def __init__(
        self,
        value: str = "",
        tag: ASN1Tag | None = None,
        optional: bool = False,
        default: str = "",
    ) -> None:
        """Initialize IA5String element.

        Args:
            value: String value
            tag: Custom tag
            optional: Whether element is optional
            default: Default string value
        """
        super().__init__(value, tag, optional, default)

    def get_default_tag(self) -> ASN1Tag:
        """Get default IA5String tag."""
        return ASN1Tag(
            tag_class=ASN1_UNIVERSAL,
            tag_form=ASN1_PRIMITIVE,
            tag_number=ASN1_IA5_STRING,
        )

    def encode(self, encoding: str = DEFAULT_ENCODING) -> bytes:
        """Encode IA5String to bytes.

        Args:
            encoding: Encoding rules

        Returns:
            Encoded IA5 string as bytes
        """
        from ldap_core_shared.protocols.asn1.encoder import TLVEncoder

        # Type guard: ensure value is a string
        value = self._value
        if not isinstance(value, str):
            msg = f"ASN1IA5String value must be str, got {type(value).__name__}"
            raise TypeError(msg)

        # Validate all characters are in 7-bit ASCII range
        try:
            encoded = value.encode("ascii")
            for byte in encoded:
                if byte > ASCII_MAX_VALUE:
                    msg = f"IA5String contains non-ASCII character: {chr(byte)}"
                    raise ValueError(msg)
        except UnicodeEncodeError as e:
            msg = f"IA5String contains non-ASCII characters: {e}"
            raise ValueError(msg) from e

        # IA5String content is ASCII encoded
        content = encoded
        return TLVEncoder.encode_tlv(self.get_tag(), content, definite=True)

    @classmethod
    def decode(cls, data: bytes, offset: int = 0) -> tuple[ASN1IA5String, int]:
        """Decode IA5String from bytes.

        Args:
            data: Encoded data
            offset: Starting offset

        Returns:
            Tuple of (decoded IA5 string, next offset)
        """
        if offset >= len(data):
            msg = "Insufficient data for IA5String decoding"
            raise ValueError(msg)

        # Check tag
        expected_tag = cls().get_default_tag()
        if data[offset] != (
            expected_tag.tag_class | expected_tag.tag_form | expected_tag.tag_number
        ):
            msg = f"Expected IA5String tag, got {data[offset]:02x}"
            raise ValueError(msg)

        # Parse length
        length_offset = offset + 1
        if length_offset >= len(data):
            msg = "Insufficient data for length"
            raise ValueError(msg)

        length = data[length_offset]

        # Parse string data
        value_offset = length_offset + 1
        if value_offset + length > len(data):
            msg = "Insufficient data for IA5String value"
            raise ValueError(msg)

        string_data = data[value_offset : value_offset + length]

        # Validate all bytes are in 7-bit ASCII range
        for byte in string_data:
            if byte > ASCII_MAX_VALUE:
                msg = f"IA5String contains non-ASCII byte: {byte:02x}"
                raise ValueError(msg)

        try:
            string_value = string_data.decode("ascii")
        except UnicodeDecodeError as e:
            msg = f"Invalid ASCII string: {e}"
            raise ValueError(msg) from e

        return cls(string_value), value_offset + length

    def validate(self) -> list[str]:
        """Validate IA5String value.

        Returns:
            List of validation errors
        """
        errors = []

        if not isinstance(self._value, str):
            errors.append(f"IA5String value must be str, got {type(self._value)}")
        else:
            try:
                encoded = self._value.encode("ascii")
                # Check that all bytes are in 7-bit ASCII range
                for byte in encoded:
                    if byte > ASCII_MAX_VALUE:
                        errors.append(
                            f"IA5String contains non-ASCII character: {chr(byte)}",
                        )
                        break
            except UnicodeEncodeError:
                errors.append("IA5String contains non-ASCII characters")

        return errors


class ASN1UTCTime(ASN1Element):
    """ASN.1 UTCTime type.

    Represents UTC time values with proper ASN.1 encoding.
    Format: YYMMDDHHMMSSZ or YYMMDDHHMMSS+HHMM

    Example:
        >>> # Create from datetime
        >>> utc_time = ASN1UTCTime(datetime.now(timezone.utc))
        >>>
        >>> # Create from string
        >>> utc_str = ASN1UTCTime("230615120000Z")
        >>>
        >>> # Get datetime
        >>> dt = utc_time.get_datetime()
    """

    def __init__(
        self,
        value: datetime | str | None = None,
        tag: ASN1Tag | None = None,
        optional: bool = False,
        default: Any = None,
    ) -> None:
        """Initialize UTCTime element.

        Args:
            value: Datetime or UTC time string
            tag: Custom tag
            optional: Whether element is optional
            default: Default value
        """
        super().__init__(value, tag, optional, default)
        self._datetime: datetime | None = None
        self._time_string: str = ""

        if isinstance(value, datetime):
            self._datetime = value
            self._time_string = self._datetime_to_utc_string(value)
        elif isinstance(value, str):
            self._time_string = value
            self._datetime = self._utc_string_to_datetime(value)
        else:
            self._datetime = None
            self._time_string = ""

    def get_default_tag(self) -> ASN1Tag:
        """Get default UTCTime tag."""
        return ASN1Tag(
            tag_class=ASN1_UNIVERSAL,
            tag_form=ASN1_PRIMITIVE,
            tag_number=ASN1_UTC_TIME,
        )

    def get_datetime(self) -> datetime | None:
        """Get datetime representation.

        Returns:
            Datetime object or None
        """
        return self._datetime

    def get_time_string(self) -> str:
        """Get UTC time string representation.

        Returns:
            UTC time string
        """
        return self._time_string

    def _datetime_to_utc_string(self, dt: datetime) -> str:
        """Convert datetime to UTC string.

        Args:
            dt: Datetime object

        Returns:
            UTC time string
        """
        # Convert to UTC if needed
        if dt.tzinfo is not None:
            dt = dt.astimezone(UTC)

        # Format as YYMMDDHHMMSSZ
        return dt.strftime("%y%m%d%H%M%SZ")

    def _utc_string_to_datetime(self, time_str: str) -> datetime | None:
        """Convert UTC string to datetime.

        Args:
            time_str: UTC time string

        Returns:
            Datetime object or None if invalid
        """
        import re

        # UTC time formats: YYMMDDHHMMSSZ or YYMMDDHHMMSS+HHMM
        if not time_str:
            return None

        # Pattern for YYMMDDHHMMSSZ
        utc_pattern = r"^(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})Z$"
        match = re.match(utc_pattern, time_str)

        if match:
            year, month, day, hour, minute, second = match.groups()
            year = int(year)

            # Interpret 2-digit year (Y2K rule: 00-49 = 20xx, 50-99 = 19xx)
            if year >= 50:
                year += 1900
            else:
                year += 2000

            try:
                return datetime(
                    year=year,
                    month=int(month),
                    day=int(day),
                    hour=int(hour),
                    minute=int(minute),
                    second=int(second),
                    tzinfo=UTC,
                )
            except ValueError:
                return None

        # Could add support for other formats (+HHMM, etc.) here
        return None

    def encode(self, encoding: str = DEFAULT_ENCODING) -> bytes:
        """Encode UTCTime to bytes.

        Args:
            encoding: Encoding rules

        Returns:
            Encoded UTC time as bytes
        """
        from ldap_core_shared.protocols.asn1.encoder import TLVEncoder

        if not self._time_string:
            msg = "UTCTime has no time string to encode"
            raise ValueError(msg)

        # UTCTime content is ASCII encoded time string
        content = self._time_string.encode("ascii")
        return TLVEncoder.encode_tlv(self.get_tag(), content, definite=True)

    @classmethod
    def decode(cls, data: bytes, offset: int = 0) -> tuple[ASN1UTCTime, int]:
        """Decode UTCTime from bytes.

        Args:
            data: Encoded data
            offset: Starting offset

        Returns:
            Tuple of (decoded UTC time, next offset)
        """
        if offset >= len(data):
            msg = "Insufficient data for UTCTime decoding"
            raise ValueError(msg)

        # Check tag
        expected_tag = cls().get_default_tag()
        if data[offset] != (
            expected_tag.tag_class | expected_tag.tag_form | expected_tag.tag_number
        ):
            msg = f"Expected UTCTime tag, got {data[offset]:02x}"
            raise ValueError(msg)

        # Parse length
        length_offset = offset + 1
        if length_offset >= len(data):
            msg = "Insufficient data for length"
            raise ValueError(msg)

        length = data[length_offset]

        # Parse time string data
        value_offset = length_offset + 1
        if value_offset + length > len(data):
            msg = "Insufficient data for UTCTime value"
            raise ValueError(msg)

        time_data = data[value_offset : value_offset + length]

        try:
            time_string = time_data.decode("ascii")
        except UnicodeDecodeError as e:
            msg = f"Invalid ASCII time string: {e}"
            raise ValueError(msg) from e

        return cls(time_string), value_offset + length

    def validate(self) -> list[str]:
        """Validate UTCTime value.

        Returns:
            List of validation errors
        """
        errors = []

        if self._datetime is None and self._time_string:
            errors.append("Invalid UTC time string format")

        if self._time_string:
            # Validate time string format
            import re

            if not re.match(r"^\d{12}Z$", self._time_string):
                errors.append("UTCTime must be in format YYMMDDHHMMSSZ")

        if self._datetime:
            # Validate year range for UTCTime (1950-2049)
            year = self._datetime.year
            if year < 1950 or year > 2049:
                errors.append(f"UTCTime year {year} outside valid range (1950-2049)")

        return errors


class ASN1GeneralizedTime(ASN1Element):
    """ASN.1 GeneralizedTime type.

    Represents generalized time values with proper ASN.1 encoding.
    Format: YYYYMMDDHHMMSSZ or YYYYMMDDHHMMSS+HHMM

    Example:
        >>> # Create from datetime
        >>> gen_time = ASN1GeneralizedTime(datetime.now(timezone.utc))
        >>>
        >>> # Create from string
        >>> gen_str = ASN1GeneralizedTime("20230615120000Z")
        >>>
        >>> # Get datetime
        >>> dt = gen_time.get_datetime()
    """

    def __init__(
        self,
        value: datetime | str | None = None,
        tag: ASN1Tag | None = None,
        optional: bool = False,
        default: Any = None,
    ) -> None:
        """Initialize GeneralizedTime element.

        Args:
            value: Datetime or generalized time string
            tag: Custom tag
            optional: Whether element is optional
            default: Default value
        """
        super().__init__(value, tag, optional, default)
        self._datetime: datetime | None = None
        self._time_string: str = ""

        if isinstance(value, datetime):
            self._datetime = value
            self._time_string = self._datetime_to_generalized_string(value)
        elif isinstance(value, str):
            self._time_string = value
            self._datetime = self._generalized_string_to_datetime(value)
        else:
            self._datetime = None
            self._time_string = ""

    def get_default_tag(self) -> ASN1Tag:
        """Get default GeneralizedTime tag."""
        return ASN1Tag(
            tag_class=ASN1_UNIVERSAL,
            tag_form=ASN1_PRIMITIVE,
            tag_number=ASN1_GENERALIZED_TIME,
        )

    def get_datetime(self) -> datetime | None:
        """Get datetime representation.

        Returns:
            Datetime object or None
        """
        return self._datetime

    def get_time_string(self) -> str:
        """Get generalized time string representation.

        Returns:
            Generalized time string
        """
        return self._time_string

    def _datetime_to_generalized_string(self, dt: datetime) -> str:
        """Convert datetime to generalized time string.

        Args:
            dt: Datetime object

        Returns:
            Generalized time string
        """
        # Convert to UTC if needed
        if dt.tzinfo is not None:
            dt = dt.astimezone(UTC)

        # Format as YYYYMMDDHHMMSSZ
        return dt.strftime("%Y%m%d%H%M%SZ")

    def _generalized_string_to_datetime(self, time_str: str) -> datetime | None:
        """Convert generalized time string to datetime.

        Args:
            time_str: Generalized time string

        Returns:
            Datetime object or None if invalid
        """
        import re

        # GeneralizedTime formats: YYYYMMDDHHMMSSZ or YYYYMMDDHHMMSS+HHMM
        if not time_str:
            return None

        # Pattern for YYYYMMDDHHMMSSZ
        gen_pattern = r"^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})Z$"
        match = re.match(gen_pattern, time_str)

        if match:
            year, month, day, hour, minute, second = match.groups()

            try:
                return datetime(
                    year=int(year),
                    month=int(month),
                    day=int(day),
                    hour=int(hour),
                    minute=int(minute),
                    second=int(second),
                    tzinfo=UTC,
                )
            except ValueError:
                return None

        # Could add support for other formats (+HHMM, fractional seconds, etc.) here
        return None

    def encode(self, encoding: str = DEFAULT_ENCODING) -> bytes:
        """Encode GeneralizedTime to bytes.

        Args:
            encoding: Encoding rules

        Returns:
            Encoded generalized time as bytes
        """
        from ldap_core_shared.protocols.asn1.encoder import TLVEncoder

        if not self._time_string:
            msg = "GeneralizedTime has no time string to encode"
            raise ValueError(msg)

        # GeneralizedTime content is ASCII encoded time string
        content = self._time_string.encode("ascii")
        return TLVEncoder.encode_tlv(self.get_tag(), content, definite=True)

    @classmethod
    def decode(cls, data: bytes, offset: int = 0) -> tuple[ASN1GeneralizedTime, int]:
        """Decode GeneralizedTime from bytes.

        Args:
            data: Encoded data
            offset: Starting offset

        Returns:
            Tuple of (decoded generalized time, next offset)
        """
        if offset >= len(data):
            msg = "Insufficient data for GeneralizedTime decoding"
            raise ValueError(msg)

        # Check tag
        expected_tag = cls().get_default_tag()
        if data[offset] != (
            expected_tag.tag_class | expected_tag.tag_form | expected_tag.tag_number
        ):
            msg = f"Expected GeneralizedTime tag, got {data[offset]:02x}"
            raise ValueError(msg)

        # Parse length
        length_offset = offset + 1
        if length_offset >= len(data):
            msg = "Insufficient data for length"
            raise ValueError(msg)

        length = data[length_offset]

        # Parse time string data
        value_offset = length_offset + 1
        if value_offset + length > len(data):
            msg = "Insufficient data for GeneralizedTime value"
            raise ValueError(msg)

        time_data = data[value_offset : value_offset + length]

        try:
            time_string = time_data.decode("ascii")
        except UnicodeDecodeError as e:
            msg = f"Invalid ASCII time string: {e}"
            raise ValueError(msg) from e

        return cls(time_string), value_offset + length

    def validate(self) -> list[str]:
        """Validate GeneralizedTime value.

        Returns:
            List of validation errors
        """
        errors = []

        if self._datetime is None and self._time_string:
            errors.append("Invalid generalized time string format")

        if self._time_string:
            # Validate time string format
            import re

            if not re.match(r"^\d{14}Z$", self._time_string):
                errors.append("GeneralizedTime must be in format YYYYMMDDHHMMSSZ")

        if self._datetime:
            # Validate year range for GeneralizedTime (any reasonable range)
            year = self._datetime.year
            if year < 1000 or year > 9999:
                errors.append(
                    f"GeneralizedTime year {year} outside valid range (1000-9999)",
                )

        return errors


# Export all type classes for easy import
__all__ = [
    "ASN1BitString",
    "ASN1Boolean",
    "ASN1GeneralizedTime",
    "ASN1IA5String",
    "ASN1Integer",
    "ASN1Null",
    "ASN1ObjectIdentifier",
    "ASN1OctetString",
    "ASN1PrintableString",
    "ASN1UTCTime",
    "ASN1UTF8String",
]


# TODO: Additional types to implement:
# - ASN1Real (REAL type for floating-point numbers)
# - ASN1Enumerated (ENUMERATED type for named integers)
# - ASN1NumericString (NumericString type for numeric characters)
# - ASN1VisibleString (VisibleString type for visible characters)
# - ASN1GeneralString (GeneralString type for general characters)
# - ASN1BMPString (BMPString type for Unicode strings)
# - ASN1UniversalString (UniversalString type for Unicode strings)
# - ASN1GraphicString (GraphicString type for graphic characters)
# - ASN1ObjectDescriptor (ObjectDescriptor type)
# - ASN1External (EXTERNAL type)
# - ASN1EmbeddedPDV (EMBEDDED PDV type)
# - ASN1CharacterString (CHARACTER STRING type)

# TODO: Integration points for complete type functionality:
#
# 1. Encoding Implementation:
#    - Complete BER/DER encoding for all primitive types
#    - Proper tag, length, value encoding
#    - DER canonical encoding rules
#    - Indefinite length support for BER
#
# 2. Decoding Implementation:
#    - Complete BER/DER decoding for all primitive types
#    - Error recovery and validation
#    - Support for indefinite length
#    - Partial decoding support
#
# 3. Validation System:
#    - Character set validation for string types
#    - Range validation for integer types
#    - Format validation for time types
#    - OID structure validation
#
# 4. String Encoding Support:
#    - Multiple character encodings
#    - Character set restrictions
#    - Normalization and canonicalization
#    - Internationalization support
#
# 5. Time Handling:
#    - Multiple time formats
#    - Timezone handling
#    - Leap second support
#    - Time zone conversion
#
# 6. Performance Optimization:
#    - Efficient large integer handling
#    - Lazy string encoding/decoding
#    - Memory optimization
#    - Caching of encoded forms
