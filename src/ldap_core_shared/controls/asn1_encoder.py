"""ASN.1 BER Encoder/Decoder for LDAP Controls.

This module provides comprehensive ASN.1 Basic Encoding Rules (BER) encoding
and decoding functionality for LDAP controls, ensuring full RFC compliance
across all control implementations.

RFC References:
    - RFC 4511: Lightweight Directory Access Protocol (LDAP): The Protocol
    - X.690: Information technology – ASN.1 encoding rules
    - RFC 2696: LDAP Control Extension for Simple Paged Results Manipulation
    - RFC 2891: LDAP Control Extension for Server Side Sorting

Architecture:
    - ASN1Encoder: Comprehensive BER encoding functionality
    - ASN1Decoder: Comprehensive BER decoding functionality
    - ASN1ValidationError: Validation and encoding error handling
    - Type-specific encoders for all ASN.1 types used in LDAP controls

This replaces the simple BER encoding helpers scattered across control
implementations with a centralized, RFC-compliant solution.
"""

from __future__ import annotations

from ldap_core_shared.exceptions.base import LDAPError

# ASN.1 BER constants
MAX_CONTEXT_TAG_NUMBER = 7  # Context tags are limited to 0-7
BER_SHORT_FORM_THRESHOLD = 0x80  # Values below this use short form length encoding
MAX_LONG_FORM_OCTETS = 126  # Maximum octets in long form length encoding
MAX_LENGTH_BYTES = 4  # Maximum length bytes supported for decoding


class ASN1Error(LDAPError):
    """Base ASN.1 encoding/decoding error."""


class ASN1EncodingError(ASN1Error):
    """ASN.1 encoding error."""


class ASN1DecodingError(ASN1Error):
    """ASN.1 decoding error."""


class ASN1ValidationError(ASN1Error):
    """ASN.1 validation error."""


# ASN.1 Universal Tags (from X.690)
class ASN1Tags:
    """ASN.1 Universal Tag definitions."""

    # Primitive types
    BOOLEAN = 0x01
    INTEGER = 0x02
    BIT_STRING = 0x03
    OCTET_STRING = 0x04
    NULL = 0x05
    OBJECT_IDENTIFIER = 0x06
    ENUMERATED = 0x0A
    UTF8_STRING = 0x0C

    # Constructed types
    SEQUENCE = 0x30
    SET = 0x31

    # Context-specific tags (0x80 + tag number)
    CONTEXT_0 = 0x80
    CONTEXT_1 = 0x81
    CONTEXT_2 = 0x82
    CONTEXT_3 = 0x83
    CONTEXT_4 = 0x84
    CONTEXT_5 = 0x85
    CONTEXT_6 = 0x86
    CONTEXT_7 = 0x87


class ASN1Encoder:
    """RFC-compliant ASN.1 BER encoder for LDAP controls."""

    @staticmethod
    def encode_boolean(value: bool) -> bytes:
        """Encode boolean value as ASN.1 BOOLEAN.

        Args:
            value: Boolean value to encode

        Returns:
            BER-encoded BOOLEAN

        Raises:
            ASN1EncodingError: If encoding fails

        """
        try:
            content = b"\xff" if value else b"\x00"
            return ASN1Encoder._encode_tlv(ASN1Tags.BOOLEAN, content)
        except Exception as e:
            msg = f"Failed to encode boolean: {e}"
            raise ASN1EncodingError(msg) from e

    @staticmethod
    def encode_integer(value: int) -> bytes:
        """Encode integer value as ASN.1 INTEGER.

        Args:
            value: Integer value to encode (can be negative)

        Returns:
            BER-encoded INTEGER

        Raises:
            ASN1EncodingError: If encoding fails

        """
        try:
            if value == 0:
                content = b"\x00"
            elif value > 0:
                # Positive integer
                byte_length = (value.bit_length() + 7) // 8
                content = value.to_bytes(byte_length, "big", signed=False)
                # Add padding byte if MSB is set to avoid negative interpretation
                if content[0] & 0x80:
                    content = b"\x00" + content
            else:
                # Negative integer (two's complement)
                byte_length = (value.bit_length() + 8) // 8
                content = value.to_bytes(byte_length, "big", signed=True)

            return ASN1Encoder._encode_tlv(ASN1Tags.INTEGER, content)
        except Exception as e:
            msg = f"Failed to encode integer: {e}"
            raise ASN1EncodingError(msg) from e

    @staticmethod
    def encode_enumerated(value: int) -> bytes:
        """Encode enumerated value as ASN.1 ENUMERATED.

        Args:
            value: Enumerated value to encode

        Returns:
            BER-encoded ENUMERATED

        Raises:
            ASN1EncodingError: If encoding fails

        """
        try:
            if value < 0:
                msg = "ENUMERATED values must be non-negative"
                raise ASN1ValidationError(msg)

            if value == 0:
                content = b"\x00"
            else:
                byte_length = (value.bit_length() + 7) // 8
                content = value.to_bytes(byte_length, "big")
                # Add padding byte if MSB is set
                if content[0] & 0x80:
                    content = b"\x00" + content

            return ASN1Encoder._encode_tlv(ASN1Tags.ENUMERATED, content)
        except Exception as e:
            msg = f"Failed to encode enumerated: {e}"
            raise ASN1EncodingError(msg) from e

    @staticmethod
    def encode_octet_string(value: bytes) -> bytes:
        """Encode bytes as ASN.1 OCTET STRING.

        Args:
            value: Bytes to encode

        Returns:
            BER-encoded OCTET STRING

        Raises:
            ASN1EncodingError: If encoding fails

        """
        try:
            return ASN1Encoder._encode_tlv(ASN1Tags.OCTET_STRING, value)
        except Exception as e:
            msg = f"Failed to encode octet string: {e}"
            raise ASN1EncodingError(msg) from e

    @staticmethod
    def encode_utf8_string(value: str) -> bytes:
        """Encode string as ASN.1 UTF8String.

        Args:
            value: String to encode

        Returns:
            BER-encoded UTF8String

        Raises:
            ASN1EncodingError: If encoding fails

        """
        try:
            content = value.encode("utf-8")
            return ASN1Encoder._encode_tlv(ASN1Tags.UTF8_STRING, content)
        except Exception as e:
            msg = f"Failed to encode UTF8 string: {e}"
            raise ASN1EncodingError(msg) from e

    @staticmethod
    def encode_null() -> bytes:
        """Encode ASN.1 NULL value.

        Returns:
            BER-encoded NULL

        """
        return ASN1Encoder._encode_tlv(ASN1Tags.NULL, b"")

    @staticmethod
    def encode_sequence(content: bytes) -> bytes:
        """Encode content as ASN.1 SEQUENCE.

        Args:
            content: Content to wrap in SEQUENCE

        Returns:
            BER-encoded SEQUENCE

        Raises:
            ASN1EncodingError: If encoding fails

        """
        try:
            return ASN1Encoder._encode_tlv(ASN1Tags.SEQUENCE, content)
        except Exception as e:
            msg = f"Failed to encode sequence: {e}"
            raise ASN1EncodingError(msg) from e

    @staticmethod
    def encode_set(content: bytes) -> bytes:
        """Encode content as ASN.1 SET.

        Args:
            content: Content to wrap in SET

        Returns:
            BER-encoded SET

        Raises:
            ASN1EncodingError: If encoding fails

        """
        try:
            return ASN1Encoder._encode_tlv(ASN1Tags.SET, content)
        except Exception as e:
            msg = f"Failed to encode set: {e}"
            raise ASN1EncodingError(msg) from e

    @staticmethod
    def encode_context_tag(
        tag_number: int,
        content: bytes,
        constructed: bool = False,
    ) -> bytes:
        """Encode content with context-specific tag.

        Args:
            tag_number: Context tag number (0-7)
            content: Content to tag
            constructed: Whether the tag is constructed (default: primitive)

        Returns:
            BER-encoded context-tagged content

        Raises:
            ASN1EncodingError: If encoding fails

        """
        try:
            if not 0 <= tag_number <= MAX_CONTEXT_TAG_NUMBER:
                msg = f"Context tag number must be 0-7, got {tag_number}"
                raise ASN1ValidationError(msg)

            tag = 0x80 | tag_number  # Context-specific, primitive
            if constructed:
                tag |= 0x20  # Set constructed bit

            return ASN1Encoder._encode_tlv(tag, content)
        except Exception as e:
            msg = f"Failed to encode context tag: {e}"
            raise ASN1EncodingError(msg) from e

    @staticmethod
    def _encode_tlv(tag: int, content: bytes) -> bytes:
        """Encode tag-length-value triplet.

        Args:
            tag: ASN.1 tag byte
            content: Content bytes

        Returns:
            BER-encoded TLV

        Raises:
            ASN1EncodingError: If encoding fails

        """
        try:
            tag_bytes = bytes([tag])
            length_bytes = ASN1Encoder._encode_length(len(content))
            return tag_bytes + length_bytes + content
        except Exception as e:
            msg = f"Failed to encode TLV: {e}"
            raise ASN1EncodingError(msg) from e

    @staticmethod
    def _encode_length(length: int) -> bytes:
        """Encode length using BER rules.

        Args:
            length: Length to encode

        Returns:
            BER-encoded length

        Raises:
            ASN1EncodingError: If encoding fails

        """
        try:
            if length < 0:
                msg = "Length cannot be negative"
                raise ASN1ValidationError(msg)

            if length < BER_SHORT_FORM_THRESHOLD:
                # Short form: length fits in 7 bits
                return bytes([length])
            # Long form: first byte has bit 7 set and indicates number of length bytes
            length_bytes: list[int] = []
            temp_length = length
            while temp_length > 0:
                length_bytes.insert(0, temp_length & 0xFF)
                temp_length >>= 8

            if len(length_bytes) > MAX_LONG_FORM_OCTETS:
                msg = "Length too long for BER encoding"
                raise ASN1ValidationError(msg)

            return bytes([0x80 | len(length_bytes)]) + bytes(length_bytes)
        except Exception as e:
            msg = f"Failed to encode length: {e}"
            raise ASN1EncodingError(msg) from e


class ASN1Decoder:
    """RFC-compliant ASN.1 BER decoder for LDAP controls."""

    @staticmethod
    def decode_boolean(data: bytes, offset: int = 0) -> tuple[bool, int]:
        """Decode ASN.1 BOOLEAN.

        Args:
            data: BER-encoded data
            offset: Starting offset in data

        Returns:
            Tuple of (boolean_value, new_offset)

        Raises:
            ASN1DecodingError: If decoding fails

        """
        try:
            tag, length, content, new_offset = ASN1Decoder._decode_tlv(data, offset)

            if tag != ASN1Tags.BOOLEAN:
                msg = f"Expected BOOLEAN tag, got {tag:02x}"
                raise ASN1DecodingError(msg)

            if length != 1:
                msg = f"BOOLEAN must have length 1, got {length}"
                raise ASN1DecodingError(msg)

            return content[0] != 0, new_offset
        except Exception as e:
            msg = f"Failed to decode boolean: {e}"
            raise ASN1DecodingError(msg) from e

    @staticmethod
    def decode_integer(data: bytes, offset: int = 0) -> tuple[int, int]:
        """Decode ASN.1 INTEGER.

        Args:
            data: BER-encoded data
            offset: Starting offset in data

        Returns:
            Tuple of (integer_value, new_offset)

        Raises:
            ASN1DecodingError: If decoding fails

        """
        try:
            tag, length, content, new_offset = ASN1Decoder._decode_tlv(data, offset)

            if tag != ASN1Tags.INTEGER:
                msg = f"Expected INTEGER tag, got {tag:02x}"
                raise ASN1DecodingError(msg)

            if length == 0:
                msg = "INTEGER cannot have zero length"
                raise ASN1DecodingError(msg)

            # Convert bytes to integer (signed)
            value = int.from_bytes(content, "big", signed=True)
            return value, new_offset
        except Exception as e:
            msg = f"Failed to decode integer: {e}"
            raise ASN1DecodingError(msg) from e

    @staticmethod
    def decode_enumerated(data: bytes, offset: int = 0) -> tuple[int, int]:
        """Decode ASN.1 ENUMERATED.

        Args:
            data: BER-encoded data
            offset: Starting offset in data

        Returns:
            Tuple of (enumerated_value, new_offset)

        Raises:
            ASN1DecodingError: If decoding fails

        """
        try:
            tag, length, content, new_offset = ASN1Decoder._decode_tlv(data, offset)

            if tag != ASN1Tags.ENUMERATED:
                msg = f"Expected ENUMERATED tag, got {tag:02x}"
                raise ASN1DecodingError(msg)

            if length == 0:
                msg = "ENUMERATED cannot have zero length"
                raise ASN1DecodingError(msg)

            # Convert bytes to integer (unsigned for enumerated)
            value = int.from_bytes(content, "big", signed=False)
            return value, new_offset
        except Exception as e:
            msg = f"Failed to decode enumerated: {e}"
            raise ASN1DecodingError(msg) from e

    @staticmethod
    def decode_octet_string(data: bytes, offset: int = 0) -> tuple[bytes, int]:
        """Decode ASN.1 OCTET STRING.

        Args:
            data: BER-encoded data
            offset: Starting offset in data

        Returns:
            Tuple of (octet_string_value, new_offset)

        Raises:
            ASN1DecodingError: If decoding fails

        """
        try:
            tag, _length, content, new_offset = ASN1Decoder._decode_tlv(data, offset)

            if tag != ASN1Tags.OCTET_STRING:
                msg = f"Expected OCTET STRING tag, got {tag:02x}"
                raise ASN1DecodingError(msg)

            return content, new_offset
        except Exception as e:
            msg = f"Failed to decode octet string: {e}"
            raise ASN1DecodingError(msg) from e

    @staticmethod
    def decode_utf8_string(data: bytes, offset: int = 0) -> tuple[str, int]:
        """Decode ASN.1 UTF8String.

        Args:
            data: BER-encoded data
            offset: Starting offset in data

        Returns:
            Tuple of (string_value, new_offset)

        Raises:
            ASN1DecodingError: If decoding fails

        """
        try:
            tag, _length, content, new_offset = ASN1Decoder._decode_tlv(data, offset)

            if tag != ASN1Tags.UTF8_STRING:
                msg = f"Expected UTF8String tag, got {tag:02x}"
                raise ASN1DecodingError(msg)

            try:
                string_value = content.decode("utf-8")
            except UnicodeDecodeError as e:
                msg = f"Invalid UTF-8 encoding: {e}"
                raise ASN1DecodingError(msg) from e

            return string_value, new_offset
        except Exception as e:
            msg = f"Failed to decode UTF8 string: {e}"
            raise ASN1DecodingError(msg) from e

    @staticmethod
    def decode_sequence(data: bytes, offset: int = 0) -> tuple[bytes, int]:
        """Decode ASN.1 SEQUENCE and return content.

        Args:
            data: BER-encoded data
            offset: Starting offset in data

        Returns:
            Tuple of (sequence_content, new_offset)

        Raises:
            ASN1DecodingError: If decoding fails

        """
        try:
            tag, _length, content, new_offset = ASN1Decoder._decode_tlv(data, offset)

            if tag != ASN1Tags.SEQUENCE:
                msg = f"Expected SEQUENCE tag, got {tag:02x}"
                raise ASN1DecodingError(msg)

            return content, new_offset
        except Exception as e:
            msg = f"Failed to decode sequence: {e}"
            raise ASN1DecodingError(msg) from e

    @staticmethod
    def decode_context_tag(
        data: bytes,
        offset: int,
        expected_tag: int,
    ) -> tuple[bytes, int]:
        """Decode context-specific tag.

        Args:
            data: BER-encoded data
            offset: Starting offset in data
            expected_tag: Expected context tag number (0-7)

        Returns:
            Tuple of (tag_content, new_offset)

        Raises:
            ASN1DecodingError: If decoding fails

        """
        try:
            tag, _length, content, new_offset = ASN1Decoder._decode_tlv(data, offset)

            expected_tag_byte = 0x80 | expected_tag
            if tag != expected_tag_byte and tag != (expected_tag_byte | 0x20):
                msg = f"Expected context tag {expected_tag}, got {tag:02x}"
                raise ASN1DecodingError(msg)

            return content, new_offset
        except Exception as e:
            msg = f"Failed to decode context tag: {e}"
            raise ASN1DecodingError(msg) from e

    @staticmethod
    def _decode_tlv(data: bytes, offset: int) -> tuple[int, int, bytes, int]:
        """Decode tag-length-value triplet.

        Args:
            data: BER-encoded data
            offset: Starting offset

        Returns:
            Tuple of (tag, length, content, new_offset)

        Raises:
            ASN1DecodingError: If decoding fails

        """
        try:
            if offset >= len(data):
                msg = "Unexpected end of data"
                raise ASN1DecodingError(msg)

            # Decode tag
            tag = data[offset]
            offset += 1

            # Decode length
            length, offset = ASN1Decoder._decode_length(data, offset)

            # Extract content
            if offset + length > len(data):
                msg = "Content extends beyond data"
                raise ASN1DecodingError(msg)

            content = data[offset : offset + length]
            offset += length

            return tag, length, content, offset
        except Exception as e:
            msg = f"Failed to decode TLV: {e}"
            raise ASN1DecodingError(msg) from e

    @staticmethod
    def _decode_length(data: bytes, offset: int) -> tuple[int, int]:
        """Decode length using BER rules.

        Args:
            data: BER-encoded data
            offset: Starting offset

        Returns:
            Tuple of (length, new_offset)

        Raises:
            ASN1DecodingError: If decoding fails

        """
        try:
            if offset >= len(data):
                msg = "Unexpected end of data while reading length"
                raise ASN1DecodingError(msg)

            first_byte = data[offset]
            offset += 1

            if first_byte & 0x80 == 0:
                # Short form: length is in the first byte
                return first_byte, offset
            # Long form: first byte indicates number of length bytes
            num_length_bytes = first_byte & 0x7F

            if num_length_bytes == 0:
                msg = "Indefinite length not supported"
                raise ASN1DecodingError(msg)

            if num_length_bytes > MAX_LENGTH_BYTES:
                msg = "Length too long"
                raise ASN1DecodingError(msg)

            if offset + num_length_bytes > len(data):
                msg = "Unexpected end of data while reading length bytes"
                raise ASN1DecodingError(msg)

            length = 0
            for i in range(num_length_bytes):
                length = (length << 8) | data[offset + i]

            offset += num_length_bytes
            return length, offset
        except Exception as e:
            msg = f"Failed to decode length: {e}"
            raise ASN1DecodingError(msg) from e

    @staticmethod
    def peek_tag(data: bytes, offset: int = 0) -> int:
        """Peek at the next tag without consuming data.

        Args:
            data: BER-encoded data
            offset: Starting offset

        Returns:
            Tag byte

        Raises:
            ASN1DecodingError: If no tag available

        """
        if offset >= len(data):
            msg = "No tag available at offset"
            raise ASN1DecodingError(msg)
        return data[offset]

    @staticmethod
    def has_more_data(data: bytes, offset: int) -> bool:
        """Check if more data is available for decoding.

        Args:
            data: BER-encoded data
            offset: Current offset

        Returns:
            True if more data is available

        """
        return offset < len(data)


# Convenience functions for common encoding patterns
def encode_sequence_of(*elements: bytes) -> bytes:
    """Encode multiple elements as a SEQUENCE.

    Args:
        *elements: ASN.1 encoded elements to include in sequence

    Returns:
        BER-encoded SEQUENCE containing all elements

    """
    content = b"".join(elements)
    return ASN1Encoder.encode_sequence(content)


def encode_attribute_list(attributes: list[str]) -> bytes:
    """Encode list of attribute names as SEQUENCE OF UTF8String.

    Args:
        attributes: List of attribute names

    Returns:
        BER-encoded SEQUENCE OF UTF8String

    """
    elements = [ASN1Encoder.encode_utf8_string(attr) for attr in attributes]
    return encode_sequence_of(*elements)


def decode_attribute_list(data: bytes, offset: int = 0) -> tuple[list[str], int]:
    """Decode SEQUENCE OF UTF8String to attribute list.

    Args:
        data: BER-encoded data
        offset: Starting offset

    Returns:
        Tuple of (attribute_list, new_offset)

    """
    sequence_content, new_offset = ASN1Decoder.decode_sequence(data, offset)

    attributes = []
    seq_offset = 0

    while ASN1Decoder.has_more_data(sequence_content, seq_offset):
        attr_name, seq_offset = ASN1Decoder.decode_utf8_string(
            sequence_content,
            seq_offset,
        )
        attributes.append(attr_name)

    return attributes, new_offset
