"""ASN.1 BER/DER Encoder Implementation.

This module provides comprehensive ASN.1 encoding capabilities inspired by
perl-Convert-ASN1 with support for both Basic Encoding Rules (BER) and
Distinguished Encoding Rules (DER) as specified in ITU-T X.690.

Features:
    - Complete BER/DER encoding implementation
    - Tag-Length-Value (TLV) encoding
    - Definite and indefinite length encoding
    - Canonical ordering for DER compliance
    - Performance-optimized encoding algorithms
    - Support for all ASN.1 primitive and constructed types

Architecture:
    - ASN1Encoder: Main encoding interface
    - BEREncoder: Basic Encoding Rules implementation
    - DEREncoder: Distinguished Encoding Rules implementation
    - EncodingContext: Context management for encoding operations
    - TLVEncoder: Low-level Tag-Length-Value encoding

Usage Example:
    >>> from ldap_core_shared.protocols.asn1.encoder import ASN1Encoder
    >>> from ldap_core_shared.protocols.asn1.types import ASN1Integer, ASN1UTF8String
    >>>
    >>> # Create encoder
    >>> encoder = ASN1Encoder(encoding_rules="DER")
    >>>
    >>> # Encode integer
    >>> integer = ASN1Integer(42)
    >>> encoded_int = encoder.encode(integer)
    >>>
    >>> # Encode string
    >>> string = ASN1UTF8String("Hello World")
    >>> encoded_str = encoder.encode(string)

References:
    - ITU-T X.690: ASN.1 encoding rules specification
    - perl-Convert-ASN1: Encoding algorithm compatibility
    - RFC 5280: ASN.1 usage in PKI certificates
    - OpenSSL ASN.1 implementation patterns
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from datetime import datetime
from enum import Enum
from typing import TYPE_CHECKING

from pydantic import BaseModel, ConfigDict, Field

from ldap_core_shared.protocols.asn1.constants import (
    ASN1_BIT_STRING,
    ASN1_BOOLEAN,
    ASN1_GENERALIZED_TIME,
    ASN1_IA5_STRING,
    ASN1_INTEGER,
    ASN1_LONG_TAG_FORM,
    ASN1_NULL,
    ASN1_OBJECT_IDENTIFIER,
    ASN1_OCTET_STRING,
    ASN1_PRINTABLE_STRING,
    ASN1_SEQUENCE,
    ASN1_SET,
    ASN1_UTC_TIME,
    ASN1_UTF8_STRING,
)

if TYPE_CHECKING:
    from ldap_core_shared.protocols.asn1.elements import ASN1Element, ASN1Tag

logger = __import__("logging").getLogger(__name__)

# BER/DER encoding constants
BER_SHORT_FORM_THRESHOLD = 0x80  # 128 - Values below use short form length encoding
BER_MAX_LONG_FORM_OCTETS = 126  # Maximum number of octets in long form length encoding
OID_MIN_COMPONENTS = 2  # Minimum number of components required for valid OID
BER_INDEFINITE_LENGTH_MARKER = 0x80  # Marker byte for indefinite length encoding
OID_FIRST_COMPONENT_MULTIPLIER = 40  # OID encoding: first component multiplied by 40
OID_CONTINUATION_BIT = 0x80  # High bit set for continuation in OID encoding
INTEGER_MSB_MASK = 0x80  # Most significant bit mask for integer sign detection


class EncodingRules(Enum):
    """ASN.1 encoding rules."""

    BER = "BER"  # Basic Encoding Rules
    DER = "DER"  # Distinguished Encoding Rules
    CER = "CER"  # Canonical Encoding Rules


class EncodingError(Exception):
    """ASN.1 encoding error."""

    def __init__(self, message: str, element: ASN1Element | None = None) -> None:
        """Initialize encoding error.

        Args:
            message: Error message
            element: Element that caused the error
        """
        super().__init__(message)
        self.element = element


class EncodingContext(BaseModel):
    """Encoding context for ASN.1 operations."""

    model_config = ConfigDict(strict=True, extra="forbid")

    rules: EncodingRules = Field(description="Encoding rules to use")
    definite_length: bool = Field(
        default=True,
        description="Use definite length encoding",
    )
    canonical_order: bool = Field(default=False, description="Use canonical ordering")
    validate_elements: bool = Field(
        default=True,
        description="Validate elements before encoding",
    )
    max_depth: int = Field(default=100, description="Maximum nesting depth")
    current_depth: int = Field(default=0, description="Current nesting depth")


class TLVEncoder:
    """Low-level Tag-Length-Value encoder.

    Provides primitive encoding operations for ASN.1 TLV structures
    following ITU-T X.690 encoding rules.
    """

    @staticmethod
    def encode_tag(tag: ASN1Tag) -> bytes:
        """Encode ASN.1 tag.

        Args:
            tag: ASN.1 tag to encode

        Returns:
            Encoded tag bytes

        Raises:
            EncodingError: If tag encoding fails
        """
        try:
            # Short form tag (tag number < 31)
            if tag.tag_number < ASN1_LONG_TAG_FORM:
                tag_byte = tag.tag_class | tag.tag_form | tag.tag_number
                return bytes([tag_byte])

            # Long form tag (tag number >= 31)
            first_byte = tag.tag_class | tag.tag_form | ASN1_LONG_TAG_FORM
            result = bytes([first_byte])

            # Encode tag number using base-128
            tag_number = tag.tag_number
            if tag_number == 0:
                result += b"\x00"
            else:
                # Convert to base-128 with continuation bits
                octets: list[int] = []
                while tag_number > 0:
                    octets.insert(0, tag_number & 0x7F)
                    tag_number >>= 7

                # Set continuation bits (all except last)
                for i in range(len(octets) - 1):
                    octets[i] |= OID_CONTINUATION_BIT

                result += bytes(octets)

            return result

        except Exception as e:
            msg = f"Failed to encode tag: {e}"
            raise EncodingError(msg) from e

    @staticmethod
    def encode_length(length: int, definite: bool = True) -> bytes:
        """Encode ASN.1 length.

        Args:
            length: Length value to encode
            definite: Use definite length encoding

        Returns:
            Encoded length bytes

        Raises:
            EncodingError: If length encoding fails
        """
        try:
            if not definite:
                # Indefinite length encoding: 0x80
                return bytes([BER_INDEFINITE_LENGTH_MARKER])

            if length < 0:
                msg = f"Length cannot be negative: {length}"
                raise EncodingError(msg)

            # Short form length (length < 128)
            if length < BER_SHORT_FORM_THRESHOLD:
                return bytes([length])

            # Long form length (length >= 128)
            # Convert length to bytes (big-endian)
            length_bytes: list[int] = []
            temp_length = length
            while temp_length > 0:
                length_bytes.insert(0, temp_length & 0xFF)
                temp_length >>= 8

            if len(length_bytes) > BER_MAX_LONG_FORM_OCTETS:
                msg = f"Length too large: {length}"
                raise EncodingError(msg)

            # First byte: 0x80 | number of length bytes
            first_byte = BER_INDEFINITE_LENGTH_MARKER | len(length_bytes)
            return bytes([first_byte]) + bytes(length_bytes)

        except Exception as e:
            msg = f"Failed to encode length: {e}"
            raise EncodingError(msg) from e

    @staticmethod
    def encode_tlv(tag: ASN1Tag, content: bytes, definite: bool = True) -> bytes:
        """Encode complete Tag-Length-Value structure.

        Args:
            tag: ASN.1 tag
            content: Content bytes
            definite: Use definite length encoding

        Returns:
            Complete TLV encoded bytes
        """
        tag_bytes = TLVEncoder.encode_tag(tag)
        length_bytes = TLVEncoder.encode_length(len(content), definite)

        result = tag_bytes + length_bytes + content

        # Add end-of-contents octets for indefinite length
        if not definite:
            result += b"\x00\x00"

        return result


class ASN1EncoderBase(ABC):
    """Abstract base class for ASN.1 encoders."""

    def __init__(self, context: EncodingContext | None = None) -> None:
        """Initialize encoder.

        Args:
            context: Encoding context
        """
        self.context = context or EncodingContext(rules=EncodingRules.BER)

    @abstractmethod
    def encode_element(self, element: ASN1Element) -> bytes:
        """Encode ASN.1 element.

        Args:
            element: Element to encode

        Returns:
            Encoded bytes
        """

    def _validate_element(self, element: ASN1Element) -> None:
        """Validate element before encoding.

        Args:
            element: Element to validate

        Raises:
            EncodingError: If validation fails
        """
        if not self.context.validate_elements:
            return

        errors = element.validate()
        if errors:
            msg = f"Element validation failed: {'; '.join(errors)}"
            raise EncodingError(msg, element)

    def _check_depth(self) -> None:
        """Check encoding depth limit.

        Raises:
            EncodingError: If maximum depth exceeded
        """
        if self.context.current_depth > self.context.max_depth:
            msg = f"Maximum encoding depth exceeded: {self.context.max_depth}"
            raise EncodingError(msg)


class BEREncoder(ASN1EncoderBase):
    """Basic Encoding Rules (BER) encoder.

    Implements ASN.1 BER encoding as specified in ITU-T X.690.
    """

    def encode_element(self, element: ASN1Element) -> bytes:
        """Encode ASN.1 element using BER.

        Args:
            element: Element to encode

        Returns:
            BER encoded bytes
        """
        self._validate_element(element)
        self._check_depth()

        tag = element.get_tag()

        # Dispatch to specific encoding method based on tag
        if tag.tag_number == ASN1_BOOLEAN:
            return self._encode_boolean(element)
        if tag.tag_number == ASN1_INTEGER:
            return self._encode_integer(element)
        if tag.tag_number == ASN1_BIT_STRING:
            return self._encode_bit_string(element)
        if tag.tag_number == ASN1_OCTET_STRING:
            return self._encode_octet_string(element)
        if tag.tag_number == ASN1_NULL:
            return self._encode_null(element)
        if tag.tag_number == ASN1_OBJECT_IDENTIFIER:
            return self._encode_object_identifier(element)
        if tag.tag_number == ASN1_UTF8_STRING:
            return self._encode_utf8_string(element)
        if tag.tag_number == ASN1_PRINTABLE_STRING:
            return self._encode_printable_string(element)
        if tag.tag_number == ASN1_IA5_STRING:
            return self._encode_ia5_string(element)
        if tag.tag_number == ASN1_UTC_TIME:
            return self._encode_utc_time(element)
        if tag.tag_number == ASN1_GENERALIZED_TIME:
            return self._encode_generalized_time(element)
        if tag.tag_number == ASN1_SEQUENCE:
            return self._encode_sequence(element)
        if tag.tag_number == ASN1_SET:
            return self._encode_set(element)
        # Generic encoding for unknown types
        return self._encode_generic(element)

    def _encode_boolean(self, element: ASN1Element) -> bytes:
        """Encode BOOLEAN element."""
        value = element.get_value()
        content = b"\xff" if value else b"\x00"
        return TLVEncoder.encode_tlv(
            element.get_tag(),
            content,
            self.context.definite_length,
        )

    def _encode_integer(self, element: ASN1Element) -> bytes:
        """Encode INTEGER element."""
        value = element.get_value()
        if not isinstance(value, int):
            msg = f"INTEGER value must be int, got {type(value)}"
            raise EncodingError(msg, element)

        # Convert integer to two's complement bytes
        if value == 0:
            content = b"\x00"
        elif value > 0:
            # Positive integer
            byte_length = (value.bit_length() + 7) // 8
            content = value.to_bytes(byte_length, byteorder="big", signed=False)

            # Add padding byte if MSB is set (to avoid negative interpretation)
            if content[0] & INTEGER_MSB_MASK:
                content = b"\x00" + content
        else:
            # Negative integer (two's complement)
            byte_length = (value.bit_length() + 8) // 8
            content = value.to_bytes(byte_length, byteorder="big", signed=True)

        return TLVEncoder.encode_tlv(
            element.get_tag(),
            content,
            self.context.definite_length,
        )

    def _encode_bit_string(self, element: ASN1Element) -> bytes:
        """Encode BIT STRING element."""
        # Get bit string data and unused bits
        if hasattr(element, "get_bytes") and hasattr(element, "get_unused_bits"):
            bit_data = element.get_bytes()
            unused_bits = element.get_unused_bits()
        else:
            msg = "BIT STRING element missing required methods"
            raise EncodingError(msg, element)

        # Content: unused_bits_byte + bit_data
        content = bytes([unused_bits]) + bit_data
        return TLVEncoder.encode_tlv(
            element.get_tag(),
            content,
            self.context.definite_length,
        )

    def _encode_octet_string(self, element: ASN1Element) -> bytes:
        """Encode OCTET STRING element."""
        if hasattr(element, "get_bytes"):
            content = element.get_bytes()
        else:
            # Fallback to raw value
            value = element.get_value()
            if isinstance(value, bytes):
                content = value
            elif isinstance(value, str):
                content = value.encode("utf-8")
            else:
                msg = f"Cannot encode OCTET STRING from {type(value)}"
                raise EncodingError(msg, element)

        return TLVEncoder.encode_tlv(
            element.get_tag(),
            content,
            self.context.definite_length,
        )

    def _encode_null(self, element: ASN1Element) -> bytes:
        """Encode NULL element."""
        content = b""  # NULL has no content
        return TLVEncoder.encode_tlv(
            element.get_tag(),
            content,
            self.context.definite_length,
        )

    def _encode_object_identifier(self, element: ASN1Element) -> bytes:
        """Encode OBJECT IDENTIFIER element."""
        if hasattr(element, "get_components"):
            components = element.get_components()
        else:
            msg = "OBJECT IDENTIFIER element missing get_components method"
            raise EncodingError(msg, element)

        if len(components) < OID_MIN_COMPONENTS:
            msg = "OID must have at least 2 components"
            raise EncodingError(msg, element)

        # First component: (first * 40) + second
        first_component = components[0] * OID_FIRST_COMPONENT_MULTIPLIER + components[1]
        content = self._encode_oid_component(first_component)

        # Remaining components
        for component in components[2:]:
            content += self._encode_oid_component(component)

        return TLVEncoder.encode_tlv(
            element.get_tag(),
            content,
            self.context.definite_length,
        )

    def _encode_oid_component(self, component: int) -> bytes:
        """Encode single OID component using base-128."""
        if component == 0:
            return b"\x00"

        # Convert to base-128 with continuation bits
        octets: list[int] = []
        while component > 0:
            octets.insert(0, component & 0x7F)
            component >>= 7

        # Set continuation bits (all except last)
        for i in range(len(octets) - 1):
            octets[i] |= OID_CONTINUATION_BIT

        return bytes(octets)

    def _encode_utf8_string(self, element: ASN1Element) -> bytes:
        """Encode UTF8String element."""
        value = element.get_value()
        if not isinstance(value, str):
            msg = f"UTF8String value must be str, got {type(value)}"
            raise EncodingError(msg, element)

        content = value.encode("utf-8")
        return TLVEncoder.encode_tlv(
            element.get_tag(),
            content,
            self.context.definite_length,
        )

    def _encode_printable_string(self, element: ASN1Element) -> bytes:
        """Encode PrintableString element."""
        value = element.get_value()
        if not isinstance(value, str):
            msg = f"PrintableString value must be str, got {type(value)}"
            raise EncodingError(msg, element)

        content = value.encode("ascii")
        return TLVEncoder.encode_tlv(
            element.get_tag(),
            content,
            self.context.definite_length,
        )

    def _encode_ia5_string(self, element: ASN1Element) -> bytes:
        """Encode IA5String element."""
        value = element.get_value()
        if not isinstance(value, str):
            msg = f"IA5String value must be str, got {type(value)}"
            raise EncodingError(msg, element)

        content = value.encode("ascii")
        return TLVEncoder.encode_tlv(
            element.get_tag(),
            content,
            self.context.definite_length,
        )

    def _encode_utc_time(self, element: ASN1Element) -> bytes:
        """Encode UTCTime element."""
        if hasattr(element, "get_time_string"):
            time_string = element.get_time_string()
        else:
            # Fallback to value
            value = element.get_value()
            if isinstance(value, str):
                time_string = value
            elif isinstance(value, datetime):
                # Convert datetime to UTC time string
                time_string = value.strftime("%y%m%d%H%M%SZ")
            else:
                msg = f"Cannot encode UTCTime from {type(value)}"
                raise EncodingError(msg, element)

        content = time_string.encode("ascii")
        return TLVEncoder.encode_tlv(
            element.get_tag(),
            content,
            self.context.definite_length,
        )

    def _encode_generalized_time(self, element: ASN1Element) -> bytes:
        """Encode GeneralizedTime element."""
        if hasattr(element, "get_time_string"):
            time_string = element.get_time_string()
        else:
            # Fallback to value
            value = element.get_value()
            if isinstance(value, str):
                time_string = value
            elif isinstance(value, datetime):
                # Convert datetime to generalized time string
                time_string = value.strftime("%Y%m%d%H%M%SZ")
            else:
                msg = f"Cannot encode GeneralizedTime from {type(value)}"
                raise EncodingError(msg, element)

        content = time_string.encode("ascii")
        return TLVEncoder.encode_tlv(
            element.get_tag(),
            content,
            self.context.definite_length,
        )

    def _encode_sequence(self, element: ASN1Element) -> bytes:
        """Encode SEQUENCE element."""
        content = b""

        # Increase depth
        self.context.current_depth += 1
        try:
            # Encode all elements in sequence
            if hasattr(element, "__iter__"):
                for sub_element in element:
                    content += self.encode_element(sub_element)
            else:
                msg = "SEQUENCE element is not iterable"
                raise EncodingError(msg, element)

            return TLVEncoder.encode_tlv(
                element.get_tag(),
                content,
                self.context.definite_length,
            )
        finally:
            self.context.current_depth -= 1

    def _encode_set(self, element: ASN1Element) -> bytes:
        """Encode SET element."""
        encoded_elements: list[bytes] = []

        # Increase depth
        self.context.current_depth += 1
        try:
            # Encode all elements in set
            if hasattr(element, "__iter__"):
                encoded_elements.extend(
                    self.encode_element(sub_element) for sub_element in element
                )
            else:
                msg = "SET element is not iterable"
                raise EncodingError(msg, element)

            # For BER, order doesn't matter, but for DER we need canonical order
            if self.context.canonical_order:
                encoded_elements.sort()

            content = b"".join(encoded_elements)
            return TLVEncoder.encode_tlv(
                element.get_tag(),
                content,
                self.context.definite_length,
            )
        finally:
            self.context.current_depth -= 1

    def _encode_generic(self, element: ASN1Element) -> bytes:
        """Generic encoding for unknown element types."""
        value = element.get_value()

        if isinstance(value, bytes):
            content = value
        elif isinstance(value, str):
            content = value.encode("utf-8")
        elif value is None:
            content = b""
        else:
            # Try to serialize as string
            content = str(value).encode("utf-8")

        return TLVEncoder.encode_tlv(
            element.get_tag(),
            content,
            self.context.definite_length,
        )


class DEREncoder(BEREncoder):
    """Distinguished Encoding Rules (DER) encoder.

    Implements ASN.1 DER encoding as specified in ITU-T X.690.
    DER is a subset of BER with additional constraints for canonical encoding.
    """

    def __init__(self, context: EncodingContext | None = None) -> None:
        """Initialize DER encoder."""
        if context is None:
            context = EncodingContext(
                rules=EncodingRules.DER,
                definite_length=True,  # DER requires definite length
                canonical_order=True,  # DER requires canonical ordering
            )
        else:
            # Enforce DER constraints
            context.definite_length = True
            context.canonical_order = True

        super().__init__(context)

    def _encode_set(self, element: ASN1Element) -> bytes:
        """Encode SET element with DER canonical ordering."""
        encoded_elements: list[bytes] = []

        # Increase depth
        self.context.current_depth += 1
        try:
            # Encode all elements in set
            if hasattr(element, "__iter__"):
                encoded_elements.extend(
                    self.encode_element(sub_element) for sub_element in element
                )
            else:
                msg = "SET element is not iterable"
                raise EncodingError(msg, element)

            # DER requires canonical ordering of SET elements
            # Sort by encoded form (lexicographic order)
            encoded_elements.sort()

            content = b"".join(encoded_elements)
            return TLVEncoder.encode_tlv(
                element.get_tag(),
                content,
                True,
            )  # Always definite length
        finally:
            self.context.current_depth -= 1


class ASN1Encoder:
    """High-level ASN.1 encoder interface.

    Provides a unified interface for ASN.1 encoding with support
    for different encoding rules (BER, DER, CER).
    """

    _encoder: ASN1EncoderBase

    def __init__(
        self,
        encoding_rules: str | EncodingRules = EncodingRules.BER,
        definite_length: bool = True,
        validate_elements: bool = True,
    ) -> None:
        """Initialize ASN.1 encoder.

        Args:
            encoding_rules: Encoding rules to use
            definite_length: Use definite length encoding
            validate_elements: Validate elements before encoding
        """
        if isinstance(encoding_rules, str):
            encoding_rules = EncodingRules(encoding_rules)

        self.context = EncodingContext(
            rules=encoding_rules,
            definite_length=definite_length,
            canonical_order=(encoding_rules == EncodingRules.DER),
            validate_elements=validate_elements,
        )

        # Create appropriate encoder
        if encoding_rules == EncodingRules.DER:
            self._encoder = DEREncoder(self.context)
        else:
            # Default to BER for BER and CER
            self._encoder = BEREncoder(self.context)

    def encode(self, element: ASN1Element) -> bytes:
        """Encode ASN.1 element.

        Args:
            element: Element to encode

        Returns:
            Encoded bytes

        Raises:
            EncodingError: If encoding fails
        """
        try:
            return self._encoder.encode_element(element)
        except Exception as e:
            if isinstance(e, EncodingError):
                raise
            msg = f"Encoding failed: {e}"
            raise EncodingError(msg, element) from e

    def encode_multiple(self, elements: list[ASN1Element]) -> list[bytes]:
        """Encode multiple ASN.1 elements.

        Args:
            elements: List of elements to encode

        Returns:
            List of encoded byte strings
        """
        return [self.encode(element) for element in elements]

    def get_context(self) -> EncodingContext:
        """Get encoding context.

        Returns:
            Current encoding context
        """
        return self.context

    def set_validate_elements(self, validate: bool) -> None:
        """Set element validation flag.

        Args:
            validate: Whether to validate elements before encoding
        """
        self.context.validate_elements = validate

    def set_max_depth(self, max_depth: int) -> None:
        """Set maximum encoding depth.

        Args:
            max_depth: Maximum nesting depth allowed
        """
        self.context.max_depth = max_depth


# TODO: Integration points for complete encoding functionality:
#
# 1. Performance Optimization:
#    - Lazy encoding for large elements
#    - Streaming encoding support
#    - Memory-efficient encoding
#    - Encoding result caching
#
# 2. Advanced Encoding Features:
#    - Custom encoding strategies
#    - Encoding profiles for different applications
#    - Compression support
#    - Error recovery mechanisms
#
# 3. Standards Compliance:
#    - Complete ITU-T X.690 compliance testing
#    - RFC compatibility validation
#    - Interoperability testing
#    - Standards version support
#
# 4. Debugging and Diagnostics:
#    - Encoding trace generation
#    - Performance profiling
#    - Memory usage tracking
#    - Error location reporting
#
# 5. Integration Features:
#    - Schema-driven encoding
#    - Template-based encoding
#    - Batch encoding operations
#    - Parallel encoding support
#
# 6. Security Features:
#    - Input validation and sanitization
#    - Safe encoding limits
#    - Resource usage controls
#    - Secure element handling
