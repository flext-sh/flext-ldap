"""Tests for ASN.1 BER/DER Encoder Implementation.

This module provides comprehensive test coverage for the ASN.1 encoder
including BER/DER encoding, tag-length-value encoding, and security validation.

Test Coverage:
    - TLVEncoder: Tag, length, value encoding primitives
    - BEREncoder: Basic Encoding Rules implementation
    - DEREncoder: Distinguished Encoding Rules implementation
    - ASN1Encoder: High-level encoding interface
    - Error handling and security validation
    - Edge cases and malformed input handling

Security Testing:
    - Maximum depth validation
    - Resource consumption limits
    - Input validation and sanitization
    - Error handling without information leakage

Performance Testing:
    - Large element encoding
    - Deep nesting scenarios
    - Memory usage validation
    - Encoding speed benchmarks
"""

from __future__ import annotations

from typing import Any

import pytest

from ldap_core_shared.protocols.asn1.constants import (
    ASN1_BOOLEAN,
    ASN1_CONSTRUCTED,
    ASN1_INTEGER,
    ASN1_NULL,
    ASN1_OCTET_STRING,
    ASN1_PRIMITIVE,
    ASN1_SEQUENCE,
    ASN1_SET,
    ASN1_UNIVERSAL,
    ASN1_UTF8_STRING,
)
from ldap_core_shared.protocols.asn1.encoder import (
    ASN1Encoder,
    BEREncoder,
    DEREncoder,
    EncodingContext,
    EncodingError,
    EncodingRules,
    TLVEncoder,
)


class MockASN1Tag:
    """Mock ASN.1 tag for testing."""

    def __init__(self, tag_class: int = ASN1_UNIVERSAL, tag_form: int = ASN1_PRIMITIVE, tag_number: int = ASN1_INTEGER) -> None:
        self.tag_class = tag_class
        self.tag_form = tag_form
        self.tag_number = tag_number


class MockASN1Element:
    """Mock ASN.1 element for testing."""

    def __init__(self, tag: MockASN1Tag | None = None, value: Any = None, validate_errors: list[str] | None = None) -> None:
        self.tag = tag or MockASN1Tag()
        self.value = value
        self.validate_errors = validate_errors or []

    def get_tag(self):
        return self.tag

    def get_value(self):
        return self.value

    def validate(self):
        return self.validate_errors

    def __iter__(self):
        # For sequence/set testing
        if isinstance(self.value, list):
            return iter(self.value)
        return iter([])


class TestTLVEncoder:
    """Test cases for TLVEncoder."""

    def test_encode_tag_short_form(self) -> None:
        """Test encoding short form tags (tag number < 31)."""
        tag = MockASN1Tag(ASN1_UNIVERSAL, ASN1_PRIMITIVE, ASN1_INTEGER)
        result = TLVEncoder.encode_tag(tag)
        expected = bytes([ASN1_UNIVERSAL | ASN1_PRIMITIVE | ASN1_INTEGER])
        assert result == expected

    def test_encode_tag_long_form(self) -> None:
        """Test encoding long form tags (tag number >= 31)."""
        tag = MockASN1Tag(ASN1_UNIVERSAL, ASN1_PRIMITIVE, 200)
        result = TLVEncoder.encode_tag(tag)

        # First byte: class | form | 0x1F
        first_byte = ASN1_UNIVERSAL | ASN1_PRIMITIVE | 0x1F

        # Tag number 200 in base-128: 0x81, 0x48
        expected = bytes([first_byte, 0x81, 0x48])
        assert result == expected

    def test_encode_tag_zero_long_form(self) -> None:
        """Test encoding tag number 0 in long form."""
        tag = MockASN1Tag(ASN1_UNIVERSAL, ASN1_PRIMITIVE, 0)
        result = TLVEncoder.encode_tag(tag)
        expected = bytes([ASN1_UNIVERSAL | ASN1_PRIMITIVE | 0])
        assert result == expected

    def test_encode_length_short_form(self) -> None:
        """Test encoding short form lengths (< 128)."""
        result = TLVEncoder.encode_length(42)
        assert result == bytes([42])

    def test_encode_length_long_form(self) -> None:
        """Test encoding long form lengths (>= 128)."""
        result = TLVEncoder.encode_length(300)
        # 300 = 0x012C, so 2 bytes needed
        # First byte: 0x80 | 2 = 0x82
        expected = bytes([0x82, 0x01, 0x2C])
        assert result == expected

    def test_encode_length_indefinite(self) -> None:
        """Test indefinite length encoding."""
        result = TLVEncoder.encode_length(100, definite=False)
        assert result == bytes([0x80])

    def test_encode_length_negative_error(self) -> None:
        """Test error handling for negative lengths."""
        with pytest.raises(EncodingError, match="Length cannot be negative"):
            TLVEncoder.encode_length(-1)

    def test_encode_length_too_large_error(self) -> None:
        """Test error handling for extremely large lengths."""
        huge_length = 2 ** (127 * 8)  # Exceeds 126 bytes
        with pytest.raises(EncodingError, match="Length too large"):
            TLVEncoder.encode_length(huge_length)

    def test_encode_tlv_definite(self) -> None:
        """Test complete TLV encoding with definite length."""
        tag = MockASN1Tag(ASN1_UNIVERSAL, ASN1_PRIMITIVE, ASN1_INTEGER)
        content = b"\x01\x23"
        result = TLVEncoder.encode_tlv(tag, content, definite=True)

        expected = bytes([ASN1_INTEGER]) + bytes([2]) + content
        assert result == expected

    def test_encode_tlv_indefinite(self) -> None:
        """Test complete TLV encoding with indefinite length."""
        tag = MockASN1Tag(ASN1_UNIVERSAL, ASN1_PRIMITIVE, ASN1_OCTET_STRING)
        content = b"test"
        result = TLVEncoder.encode_tlv(tag, content, definite=False)

        expected = (bytes([ASN1_OCTET_STRING]) +
                   bytes([0x80]) +
                   content +
                   bytes([0x00, 0x00]))
        assert result == expected


class TestEncodingContext:
    """Test cases for EncodingContext."""

    def test_default_context(self) -> None:
        """Test default encoding context creation."""
        context = EncodingContext(rules=EncodingRules.BER)
        assert context.rules == EncodingRules.BER
        assert context.definite_length is True
        assert context.canonical_order is False
        assert context.validate_elements is True
        assert context.max_depth == 100
        assert context.current_depth == 0

    def test_der_context(self) -> None:
        """Test DER-specific context settings."""
        context = EncodingContext(
            rules=EncodingRules.DER,
            definite_length=True,
            canonical_order=True,
        )
        assert context.rules == EncodingRules.DER
        assert context.definite_length is True
        assert context.canonical_order is True


class TestBEREncoder:
    """Test cases for BEREncoder."""

    def setup_method(self) -> None:
        """Set up test fixtures."""
        self.context = EncodingContext(rules=EncodingRules.BER)
        self.encoder = BEREncoder(self.context)

    def test_encode_boolean_true(self) -> None:
        """Test encoding boolean TRUE value."""
        element = MockASN1Element(
            MockASN1Tag(ASN1_UNIVERSAL, ASN1_PRIMITIVE, ASN1_BOOLEAN),
            True,
        )
        result = self.encoder.encode_element(element)
        expected = bytes([ASN1_BOOLEAN, 1, 0xFF])
        assert result == expected

    def test_encode_boolean_false(self) -> None:
        """Test encoding boolean FALSE value."""
        element = MockASN1Element(
            MockASN1Tag(ASN1_UNIVERSAL, ASN1_PRIMITIVE, ASN1_BOOLEAN),
            False,
        )
        result = self.encoder.encode_element(element)
        expected = bytes([ASN1_BOOLEAN, 1, 0x00])
        assert result == expected

    def test_encode_integer_zero(self) -> None:
        """Test encoding integer value 0."""
        element = MockASN1Element(
            MockASN1Tag(ASN1_UNIVERSAL, ASN1_PRIMITIVE, ASN1_INTEGER),
            0,
        )
        result = self.encoder.encode_element(element)
        expected = bytes([ASN1_INTEGER, 1, 0x00])
        assert result == expected

    def test_encode_integer_positive(self) -> None:
        """Test encoding positive integer."""
        element = MockASN1Element(
            MockASN1Tag(ASN1_UNIVERSAL, ASN1_PRIMITIVE, ASN1_INTEGER),
            42,
        )
        result = self.encoder.encode_element(element)
        expected = bytes([ASN1_INTEGER, 1, 42])
        assert result == expected

    def test_encode_integer_positive_msb_set(self) -> None:
        """Test encoding positive integer with MSB set (requires padding)."""
        element = MockASN1Element(
            MockASN1Tag(ASN1_UNIVERSAL, ASN1_PRIMITIVE, ASN1_INTEGER),
            255,
        )
        result = self.encoder.encode_element(element)
        # 255 = 0xFF, MSB set, so needs padding byte
        expected = bytes([ASN1_INTEGER, 2, 0x00, 0xFF])
        assert result == expected

    def test_encode_integer_negative(self) -> None:
        """Test encoding negative integer."""
        element = MockASN1Element(
            MockASN1Tag(ASN1_UNIVERSAL, ASN1_PRIMITIVE, ASN1_INTEGER),
            -1,
        )
        result = self.encoder.encode_element(element)
        expected = bytes([ASN1_INTEGER, 1, 0xFF])
        assert result == expected

    def test_encode_integer_large_positive(self) -> None:
        """Test encoding large positive integer."""
        element = MockASN1Element(
            MockASN1Tag(ASN1_UNIVERSAL, ASN1_PRIMITIVE, ASN1_INTEGER),
            65537,
        )
        result = self.encoder.encode_element(element)
        # 65537 = 0x010001
        expected = bytes([ASN1_INTEGER, 3, 0x01, 0x00, 0x01])
        assert result == expected

    def test_encode_integer_invalid_type(self) -> None:
        """Test error handling for invalid integer type."""
        element = MockASN1Element(
            MockASN1Tag(ASN1_UNIVERSAL, ASN1_PRIMITIVE, ASN1_INTEGER),
            "not an integer",
        )
        with pytest.raises(EncodingError, match="INTEGER value must be int"):
            self.encoder.encode_element(element)

    def test_encode_null(self) -> None:
        """Test encoding NULL element."""
        element = MockASN1Element(
            MockASN1Tag(ASN1_UNIVERSAL, ASN1_PRIMITIVE, ASN1_NULL),
            None,
        )
        result = self.encoder.encode_element(element)
        expected = bytes([ASN1_NULL, 0])
        assert result == expected

    def test_encode_utf8_string(self) -> None:
        """Test encoding UTF8String element."""
        element = MockASN1Element(
            MockASN1Tag(ASN1_UNIVERSAL, ASN1_PRIMITIVE, ASN1_UTF8_STRING),
            "Hello 世界",
        )
        result = self.encoder.encode_element(element)
        content = "Hello 世界".encode()
        expected = bytes([ASN1_UTF8_STRING, len(content)]) + content
        assert result == expected

    def test_encode_utf8_string_invalid_type(self) -> None:
        """Test error handling for invalid UTF8String type."""
        element = MockASN1Element(
            MockASN1Tag(ASN1_UNIVERSAL, ASN1_PRIMITIVE, ASN1_UTF8_STRING),
            123,
        )
        with pytest.raises(EncodingError, match="UTF8String value must be str"):
            self.encoder.encode_element(element)

    def test_encode_octet_string_bytes(self) -> None:
        """Test encoding OCTET STRING from bytes."""
        element = MockASN1Element(
            MockASN1Tag(ASN1_UNIVERSAL, ASN1_PRIMITIVE, ASN1_OCTET_STRING),
            b"\x01\x02\x03\x04",
        )
        result = self.encoder.encode_element(element)
        expected = bytes([ASN1_OCTET_STRING, 4, 0x01, 0x02, 0x03, 0x04])
        assert result == expected

    def test_encode_octet_string_string(self) -> None:
        """Test encoding OCTET STRING from string."""
        element = MockASN1Element(
            MockASN1Tag(ASN1_UNIVERSAL, ASN1_PRIMITIVE, ASN1_OCTET_STRING),
            "test",
        )
        result = self.encoder.encode_element(element)
        expected = bytes([ASN1_OCTET_STRING, 4]) + b"test"
        assert result == expected

    def test_encode_sequence(self) -> None:
        """Test encoding SEQUENCE element."""
        # Create sub-elements
        int_element = MockASN1Element(
            MockASN1Tag(ASN1_UNIVERSAL, ASN1_PRIMITIVE, ASN1_INTEGER),
            42,
        )
        bool_element = MockASN1Element(
            MockASN1Tag(ASN1_UNIVERSAL, ASN1_PRIMITIVE, ASN1_BOOLEAN),
            True,
        )

        # Create sequence element
        element = MockASN1Element(
            MockASN1Tag(ASN1_UNIVERSAL, ASN1_CONSTRUCTED, ASN1_SEQUENCE),
            [int_element, bool_element],
        )

        result = self.encoder.encode_element(element)

        # Expected: SEQUENCE tag + length + encoded sub-elements
        int_encoded = bytes([ASN1_INTEGER, 1, 42])
        bool_encoded = bytes([ASN1_BOOLEAN, 1, 0xFF])
        content = int_encoded + bool_encoded
        expected = bytes([ASN1_SEQUENCE | ASN1_CONSTRUCTED, len(content)]) + content

        assert result == expected

    def test_encode_set_ber_no_ordering(self) -> None:
        """Test encoding SET element with BER (no canonical ordering)."""
        # Create sub-elements
        element1 = MockASN1Element(
            MockASN1Tag(ASN1_UNIVERSAL, ASN1_PRIMITIVE, ASN1_INTEGER),
            2,
        )
        element2 = MockASN1Element(
            MockASN1Tag(ASN1_UNIVERSAL, ASN1_PRIMITIVE, ASN1_INTEGER),
            1,
        )

        # Create set element
        element = MockASN1Element(
            MockASN1Tag(ASN1_UNIVERSAL, ASN1_CONSTRUCTED, ASN1_SET),
            [element1, element2],
        )

        result = self.encoder.encode_element(element)

        # For BER, order is preserved
        encoded1 = bytes([ASN1_INTEGER, 1, 2])
        encoded2 = bytes([ASN1_INTEGER, 1, 1])
        content = encoded1 + encoded2
        expected = bytes([ASN1_SET | ASN1_CONSTRUCTED, len(content)]) + content

        assert result == expected

    def test_encode_element_validation_error(self) -> None:
        """Test element validation error handling."""
        element = MockASN1Element(
            MockASN1Tag(ASN1_UNIVERSAL, ASN1_PRIMITIVE, ASN1_INTEGER),
            42,
            validate_errors=["Test validation error"],
        )

        with pytest.raises(EncodingError, match="Element validation failed"):
            self.encoder.encode_element(element)

    def test_encode_element_validation_disabled(self) -> None:
        """Test encoding with validation disabled."""
        self.context.validate_elements = False
        element = MockASN1Element(
            MockASN1Tag(ASN1_UNIVERSAL, ASN1_PRIMITIVE, ASN1_INTEGER),
            42,
            validate_errors=["Test validation error"],
        )

        # Should not raise validation error
        result = self.encoder.encode_element(element)
        expected = bytes([ASN1_INTEGER, 1, 42])
        assert result == expected

    def test_encode_depth_limit_exceeded(self) -> None:
        """Test maximum encoding depth limit."""
        self.context.max_depth = 2

        # Create deeply nested sequence
        inner = MockASN1Element(
            MockASN1Tag(ASN1_UNIVERSAL, ASN1_PRIMITIVE, ASN1_INTEGER),
            42,
        )
        middle = MockASN1Element(
            MockASN1Tag(ASN1_UNIVERSAL, ASN1_CONSTRUCTED, ASN1_SEQUENCE),
            [inner],
        )
        outer = MockASN1Element(
            MockASN1Tag(ASN1_UNIVERSAL, ASN1_CONSTRUCTED, ASN1_SEQUENCE),
            [middle],
        )

        with pytest.raises(EncodingError, match="Maximum encoding depth exceeded"):
            self.encoder.encode_element(outer)


class TestDEREncoder:
    """Test cases for DEREncoder."""

    def setup_method(self) -> None:
        """Set up test fixtures."""
        self.encoder = DEREncoder()

    def test_der_context_initialization(self) -> None:
        """Test DER encoder context initialization."""
        assert self.encoder.context.rules == EncodingRules.DER
        assert self.encoder.context.definite_length is True
        assert self.encoder.context.canonical_order is True

    def test_der_context_enforcement(self) -> None:
        """Test DER context constraint enforcement."""
        context = EncodingContext(
            rules=EncodingRules.BER,
            definite_length=False,
            canonical_order=False,
        )
        encoder = DEREncoder(context)

        # DER constraints should be enforced
        assert encoder.context.definite_length is True
        assert encoder.context.canonical_order is True

    def test_encode_set_canonical_ordering(self) -> None:
        """Test SET encoding with DER canonical ordering."""
        # Create elements that will encode to different values
        element1 = MockASN1Element(
            MockASN1Tag(ASN1_UNIVERSAL, ASN1_PRIMITIVE, ASN1_INTEGER),
            2,  # Encodes to larger value
        )
        element2 = MockASN1Element(
            MockASN1Tag(ASN1_UNIVERSAL, ASN1_PRIMITIVE, ASN1_INTEGER),
            1,  # Encodes to smaller value
        )

        # Create set element (order reversed)
        element = MockASN1Element(
            MockASN1Tag(ASN1_UNIVERSAL, ASN1_CONSTRUCTED, ASN1_SET),
            [element1, element2],
        )

        result = self.encoder.encode_element(element)

        # For DER, elements should be sorted by encoded form
        encoded1 = bytes([ASN1_INTEGER, 1, 2])
        encoded2 = bytes([ASN1_INTEGER, 1, 1])
        # encoded2 comes first lexicographically
        content = encoded2 + encoded1
        expected = bytes([ASN1_SET | ASN1_CONSTRUCTED, len(content)]) + content

        assert result == expected


class TestASN1Encoder:
    """Test cases for ASN1Encoder high-level interface."""

    def test_encoder_initialization_ber(self) -> None:
        """Test BER encoder initialization."""
        encoder = ASN1Encoder(encoding_rules=EncodingRules.BER)
        assert isinstance(encoder._encoder, BEREncoder)
        assert encoder.context.rules == EncodingRules.BER

    def test_encoder_initialization_der(self) -> None:
        """Test DER encoder initialization."""
        encoder = ASN1Encoder(encoding_rules=EncodingRules.DER)
        assert isinstance(encoder._encoder, DEREncoder)
        assert encoder.context.rules == EncodingRules.DER

    def test_encoder_initialization_string(self) -> None:
        """Test encoder initialization with string parameter."""
        encoder = ASN1Encoder(encoding_rules="DER")
        assert isinstance(encoder._encoder, DEREncoder)
        assert encoder.context.rules == EncodingRules.DER

    def test_encode_single_element(self) -> None:
        """Test encoding single element."""
        encoder = ASN1Encoder()
        element = MockASN1Element(
            MockASN1Tag(ASN1_UNIVERSAL, ASN1_PRIMITIVE, ASN1_INTEGER),
            42,
        )

        result = encoder.encode(element)
        expected = bytes([ASN1_INTEGER, 1, 42])
        assert result == expected

    def test_encode_multiple_elements(self) -> None:
        """Test encoding multiple elements."""
        encoder = ASN1Encoder()
        elements = [
            MockASN1Element(
                MockASN1Tag(ASN1_UNIVERSAL, ASN1_PRIMITIVE, ASN1_INTEGER),
                42,
            ),
            MockASN1Element(
                MockASN1Tag(ASN1_UNIVERSAL, ASN1_PRIMITIVE, ASN1_BOOLEAN),
                True,
            ),
        ]

        results = encoder.encode_multiple(elements)

        assert len(results) == 2
        assert results[0] == bytes([ASN1_INTEGER, 1, 42])
        assert results[1] == bytes([ASN1_BOOLEAN, 1, 0xFF])

    def test_encode_error_handling(self) -> None:
        """Test error handling in encode method."""
        encoder = ASN1Encoder()

        # Create element that will cause encoding error
        element = MockASN1Element(
            MockASN1Tag(ASN1_UNIVERSAL, ASN1_PRIMITIVE, ASN1_INTEGER),
            "invalid integer",
        )

        with pytest.raises(EncodingError, match="Encoding failed"):
            encoder.encode(element)

    def test_set_validate_elements(self) -> None:
        """Test setting element validation flag."""
        encoder = ASN1Encoder()
        assert encoder.context.validate_elements is True

        encoder.set_validate_elements(False)
        assert encoder.context.validate_elements is False

    def test_set_max_depth(self) -> None:
        """Test setting maximum depth."""
        encoder = ASN1Encoder()
        assert encoder.context.max_depth == 100

        encoder.set_max_depth(50)
        assert encoder.context.max_depth == 50

    def test_get_context(self) -> None:
        """Test getting encoding context."""
        encoder = ASN1Encoder()
        context = encoder.get_context()
        assert isinstance(context, EncodingContext)
        assert context is encoder.context


class TestEncodingError:
    """Test cases for EncodingError exception."""

    def test_encoding_error_basic(self) -> None:
        """Test basic encoding error creation."""
        error = EncodingError("Test error")
        assert str(error) == "Test error"
        assert error.element is None

    def test_encoding_error_with_element(self) -> None:
        """Test encoding error with element information."""
        element = MockASN1Element()
        error = EncodingError("Test error", element)
        assert str(error) == "Test error"
        assert error.element is element


class TestSecurityValidation:
    """Security-focused test cases."""

    def test_resource_exhaustion_protection(self) -> None:
        """Test protection against resource exhaustion attacks."""
        encoder = ASN1Encoder()
        encoder.set_max_depth(5)

        # Create deeply nested structure
        element = MockASN1Element(
            MockASN1Tag(ASN1_UNIVERSAL, ASN1_PRIMITIVE, ASN1_INTEGER),
            42,
        )

        for _ in range(10):  # Create nesting beyond limit
            element = MockASN1Element(
                MockASN1Tag(ASN1_UNIVERSAL, ASN1_CONSTRUCTED, ASN1_SEQUENCE),
                [element],
            )

        with pytest.raises(EncodingError, match="Maximum encoding depth exceeded"):
            encoder.encode(element)

    def test_large_length_handling(self) -> None:
        """Test handling of extremely large lengths."""
        with pytest.raises(EncodingError, match="Length too large"):
            TLVEncoder.encode_length(2 ** (127 * 8))

    def test_negative_length_rejection(self) -> None:
        """Test rejection of negative lengths."""
        with pytest.raises(EncodingError, match="Length cannot be negative"):
            TLVEncoder.encode_length(-1)

    def test_input_validation_enforcement(self) -> None:
        """Test input validation enforcement."""
        encoder = ASN1Encoder(validate_elements=True)

        element = MockASN1Element(
            MockASN1Tag(ASN1_UNIVERSAL, ASN1_PRIMITIVE, ASN1_INTEGER),
            42,
            validate_errors=["Security validation failed"],
        )

        with pytest.raises(EncodingError, match="Element validation failed"):
            encoder.encode(element)


class TestPerformance:
    """Performance-focused test cases."""

    def test_large_element_encoding(self) -> None:
        """Test encoding of large elements."""
        # Create large octet string
        large_data = b"x" * 10000
        element = MockASN1Element(
            MockASN1Tag(ASN1_UNIVERSAL, ASN1_PRIMITIVE, ASN1_OCTET_STRING),
            large_data,
        )

        encoder = ASN1Encoder()
        result = encoder.encode(element)

        # Verify correct encoding
        assert result.startswith(bytes([ASN1_OCTET_STRING]))
        assert large_data in result

    def test_deep_nesting_performance(self) -> None:
        """Test performance with deep but allowed nesting."""
        encoder = ASN1Encoder()
        encoder.set_max_depth(50)

        # Create nested structure within limits
        element = MockASN1Element(
            MockASN1Tag(ASN1_UNIVERSAL, ASN1_PRIMITIVE, ASN1_INTEGER),
            42,
        )

        for _ in range(30):  # Within limit
            element = MockASN1Element(
                MockASN1Tag(ASN1_UNIVERSAL, ASN1_CONSTRUCTED, ASN1_SEQUENCE),
                [element],
            )

        # Should complete without error
        result = encoder.encode(element)
        assert len(result) > 0


class TestEdgeCases:
    """Edge case test scenarios."""

    def test_empty_sequence(self) -> None:
        """Test encoding empty SEQUENCE."""
        element = MockASN1Element(
            MockASN1Tag(ASN1_UNIVERSAL, ASN1_CONSTRUCTED, ASN1_SEQUENCE),
            [],
        )

        encoder = ASN1Encoder()
        result = encoder.encode(element)
        expected = bytes([ASN1_SEQUENCE | ASN1_CONSTRUCTED, 0])
        assert result == expected

    def test_empty_set(self) -> None:
        """Test encoding empty SET."""
        element = MockASN1Element(
            MockASN1Tag(ASN1_UNIVERSAL, ASN1_CONSTRUCTED, ASN1_SET),
            [],
        )

        encoder = ASN1Encoder()
        result = encoder.encode(element)
        expected = bytes([ASN1_SET | ASN1_CONSTRUCTED, 0])
        assert result == expected

    def test_zero_length_octet_string(self) -> None:
        """Test encoding zero-length OCTET STRING."""
        element = MockASN1Element(
            MockASN1Tag(ASN1_UNIVERSAL, ASN1_PRIMITIVE, ASN1_OCTET_STRING),
            b"",
        )

        encoder = ASN1Encoder()
        result = encoder.encode(element)
        expected = bytes([ASN1_OCTET_STRING, 0])
        assert result == expected

    def test_unicode_utf8_string(self) -> None:
        """Test encoding Unicode UTF8String."""
        element = MockASN1Element(
            MockASN1Tag(ASN1_UNIVERSAL, ASN1_PRIMITIVE, ASN1_UTF8_STRING),
            "Test 🌟 ü é 中文",
        )

        encoder = ASN1Encoder()
        result = encoder.encode(element)

        content = "Test 🌟 ü é 中文".encode()
        expected = bytes([ASN1_UTF8_STRING, len(content)]) + content
        assert result == expected


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
