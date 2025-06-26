"""ASN.1 Constants and Type Definitions.

This module provides comprehensive ASN.1 constants equivalent to perl-Convert-ASN1
with all standard ASN.1 type tags, class identifiers, and encoding constants
used for BER/DER encoding and decoding operations.

These constants follow ITU-T X.690 specification for ASN.1 encoding rules
and provide compatibility with perl-Convert-ASN1 constant definitions.

Architecture:
    - Type Tags: Universal ASN.1 type identifiers
    - Class Tags: ASN.1 tag class identifiers (Universal, Application, etc.)
    - Form Tags: Primitive vs Constructed encoding forms
    - Length Encoding: Constants for length field encoding
    - Utility Constants: Common values for ASN.1 processing

Usage Example:
    >>> from ldap_core_shared.protocols.asn1.constants import *
    >>>
    >>> # Check ASN.1 type
    >>> if tag == ASN1_INTEGER:
    ...     print("Integer type detected")
    >>>
    >>> # Combine tag class and type
    >>> context_tag = ASN1_CONTEXT | ASN1_CONSTRUCTED | 0x01
    >>>
    >>> # Check for long form length
    >>> if length_byte & ASN1_LONG_LENGTH:
    ...     print("Long form length encoding")

References:
    - perl-Convert-ASN1: Constants compatibility
    - ITU-T X.690: ASN.1 encoding rules specification
    - RFC 5280: ASN.1 usage in PKI certificates
    - LDAP Protocol: ASN.1 constants for LDAP operations
"""

from __future__ import annotations

# =============================================================================
# UNIVERSAL TYPE TAGS (ITU-T X.690)
# =============================================================================

# Basic Universal Types
ASN1_BOOLEAN = 0x01           # BOOLEAN
ASN1_INTEGER = 0x02           # INTEGER
ASN1_BIT_STRING = 0x03        # BIT STRING
ASN1_OCTET_STRING = 0x04      # OCTET STRING
ASN1_NULL = 0x05              # NULL
ASN1_OBJECT_IDENTIFIER = 0x06  # OBJECT IDENTIFIER
ASN1_OBJECT_DESCRIPTOR = 0x07  # ObjectDescriptor
ASN1_EXTERNAL = 0x08          # EXTERNAL
ASN1_REAL = 0x09              # REAL
ASN1_ENUMERATED = 0x0A        # ENUMERATED
ASN1_EMBEDDED_PDV = 0x0B      # EMBEDDED PDV
ASN1_UTF8_STRING = 0x0C       # UTF8String
ASN1_RELATIVE_OID = 0x0D      # RELATIVE-OID

# Constructed Universal Types
ASN1_SEQUENCE = 0x10          # SEQUENCE, SEQUENCE OF
ASN1_SET = 0x11               # SET, SET OF

# Character String Types
ASN1_NUMERIC_STRING = 0x12    # NumericString
ASN1_PRINTABLE_STRING = 0x13  # PrintableString
ASN1_T61_STRING = 0x14        # T61String, TeletexString
ASN1_VIDEOTEX_STRING = 0x15   # VideotexString
ASN1_IA5_STRING = 0x16        # IA5String
ASN1_UTC_TIME = 0x17          # UTCTime
ASN1_GENERALIZED_TIME = 0x18  # GeneralizedTime
ASN1_GRAPHIC_STRING = 0x19    # GraphicString
ASN1_VISIBLE_STRING = 0x1A    # VisibleString, ISO646String
ASN1_GENERAL_STRING = 0x1B    # GeneralString
ASN1_UNIVERSAL_STRING = 0x1C  # UniversalString
ASN1_CHARACTER_STRING = 0x1D  # CHARACTER STRING
ASN1_BMP_STRING = 0x1E        # BMPString

# =============================================================================
# TAG CLASS IDENTIFIERS
# =============================================================================

ASN1_UNIVERSAL = 0x00         # Universal class
ASN1_APPLICATION = 0x40       # Application class
ASN1_CONTEXT = 0x80           # Context-specific class
ASN1_PRIVATE = 0xC0           # Private class

# Class mask for extracting tag class
ASN1_CLASS_MASK = 0xC0

# =============================================================================
# CONSTRUCTED/PRIMITIVE FORM
# =============================================================================

ASN1_PRIMITIVE = 0x00         # Primitive encoding
ASN1_CONSTRUCTED = 0x20       # Constructed encoding

# Form mask for extracting constructed bit
ASN1_FORM_MASK = 0x20

# =============================================================================
# LENGTH ENCODING CONSTANTS
# =============================================================================

ASN1_LONG_LENGTH = 0x80       # Long form length indicator
ASN1_INDEFINITE_LENGTH = 0x80  # Indefinite length (constructed only)
ASN1_LENGTH_MASK = 0x7F       # Length value mask

# Maximum values for different length encodings
ASN1_SHORT_LENGTH_MAX = 127   # Maximum short form length
ASN1_LONG_LENGTH_MAX = 0x7F   # Maximum number of length octets

# =============================================================================
# TAG NUMBER CONSTANTS
# =============================================================================

ASN1_TAG_NUMBER_MASK = 0x1F   # Tag number mask for short form
ASN1_LONG_TAG_FORM = 0x1F     # Long form tag indicator
ASN1_TAG_CONTINUATION = 0x80  # Tag continuation bit
ASN1_TAG_VALUE_MASK = 0x7F    # Tag value mask for long form

# =============================================================================
# ENCODING MODE CONSTANTS
# =============================================================================

# Encoding rules
ENCODING_BER = "BER"          # Basic Encoding Rules
ENCODING_DER = "DER"          # Distinguished Encoding Rules
ENCODING_CER = "CER"          # Canonical Encoding Rules
ENCODING_PER = "PER"          # Packed Encoding Rules
ENCODING_XER = "XER"          # XML Encoding Rules

# Default encoding
DEFAULT_ENCODING = ENCODING_BER

# =============================================================================
# TAGGING DEFAULTS
# =============================================================================

# Tagging modes
TAGGING_EXPLICIT = "EXPLICIT"  # Explicit tagging
TAGGING_IMPLICIT = "IMPLICIT"  # Implicit tagging

# Default tagging (for backward compatibility with perl-Convert-ASN1)
DEFAULT_TAGGING = TAGGING_IMPLICIT

# =============================================================================
# REAL NUMBER ENCODING FORMATS
# =============================================================================

# Real encoding formats
REAL_BINARY = "binary"        # Binary encoding
REAL_DECIMAL_NR1 = "nr1"      # Decimal NR1 form
REAL_DECIMAL_NR2 = "nr2"      # Decimal NR2 form
REAL_DECIMAL_NR3 = "nr3"      # Decimal NR3 form

# Default real encoding
DEFAULT_REAL_ENCODING = REAL_BINARY

# =============================================================================
# TIME ENCODING FORMATS
# =============================================================================

# Time encoding modes
TIME_UTC = "utctime"          # Encode as UTC without zone
TIME_WITH_ZONE = "withzone"   # Encode with timezone
TIME_LOCAL = "local"          # Encode as local time

# Default time encoding
DEFAULT_TIME_ENCODING = TIME_WITH_ZONE

# =============================================================================
# STRING ENCODING CONSTANTS
# =============================================================================

# Character set encodings for string types
CHARSET_ASCII = "ascii"
CHARSET_UTF8 = "utf-8"
CHARSET_UTF16 = "utf-16"
CHARSET_UTF32 = "utf-32"
CHARSET_LATIN1 = "latin-1"

# Default string encoding
DEFAULT_STRING_ENCODING = CHARSET_UTF8

# =============================================================================
# ERROR CODES AND CONSTANTS
# =============================================================================

# Parse error types
ERROR_INVALID_TAG = "invalid_tag"
ERROR_INVALID_LENGTH = "invalid_length"
ERROR_INVALID_VALUE = "invalid_value"
ERROR_TRUNCATED_DATA = "truncated_data"
ERROR_SCHEMA_VIOLATION = "schema_violation"
ERROR_ENCODING_ERROR = "encoding_error"
ERROR_DECODING_ERROR = "decoding_error"

# =============================================================================
# COMPATIBILITY ALIASES (perl-Convert-ASN1 style)
# =============================================================================

# perl-Convert-ASN1 compatible constant names
ASN_BOOLEAN = ASN1_BOOLEAN
ASN_INTEGER = ASN1_INTEGER
ASN_BIT_STR = ASN1_BIT_STRING
ASN_OCTET_STR = ASN1_OCTET_STRING
ASN_NULL = ASN1_NULL
ASN_OBJECT_ID = ASN1_OBJECT_IDENTIFIER
ASN_REAL = ASN1_REAL
ASN_ENUMERATED = ASN1_ENUMERATED
ASN_SEQUENCE = ASN1_SEQUENCE
ASN_SET = ASN1_SET
ASN_PRINT_STR = ASN1_PRINTABLE_STRING
ASN_IA5_STR = ASN1_IA5_STRING
ASN_UTC_TIME = ASN1_UTC_TIME
ASN_GENERAL_TIME = ASN1_GENERALIZED_TIME
ASN_RELATIVE_OID = ASN1_RELATIVE_OID

# Class constants
ASN_UNIVERSAL = ASN1_UNIVERSAL
ASN_APPLICATION = ASN1_APPLICATION
ASN_CONTEXT = ASN1_CONTEXT
ASN_PRIVATE = ASN1_PRIVATE

# Form constants
ASN_PRIMITIVE = ASN1_PRIMITIVE
ASN_CONSTRUCTOR = ASN1_CONSTRUCTED  # Note: perl-Convert-ASN1 uses CONSTRUCTOR

# Length constants
ASN_LONG_LEN = ASN1_LONG_LENGTH
ASN_EXTENSION_ID = ASN1_LONG_TAG_FORM
ASN_BIT = ASN1_TAG_CONTINUATION

# =============================================================================
# LDAP-SPECIFIC ASN.1 CONSTANTS
# =============================================================================

# LDAP message types (Application class)
LDAP_BIND_REQUEST = ASN1_APPLICATION | ASN1_CONSTRUCTED | 0x00
LDAP_BIND_RESPONSE = ASN1_APPLICATION | ASN1_CONSTRUCTED | 0x01
LDAP_UNBIND_REQUEST = ASN1_APPLICATION | ASN1_PRIMITIVE | 0x02
LDAP_SEARCH_REQUEST = ASN1_APPLICATION | ASN1_CONSTRUCTED | 0x03
LDAP_SEARCH_RESULT_ENTRY = ASN1_APPLICATION | ASN1_CONSTRUCTED | 0x04
LDAP_SEARCH_RESULT_DONE = ASN1_APPLICATION | ASN1_CONSTRUCTED | 0x05
LDAP_MODIFY_REQUEST = ASN1_APPLICATION | ASN1_CONSTRUCTED | 0x06
LDAP_MODIFY_RESPONSE = ASN1_APPLICATION | ASN1_CONSTRUCTED | 0x07
LDAP_ADD_REQUEST = ASN1_APPLICATION | ASN1_CONSTRUCTED | 0x08
LDAP_ADD_RESPONSE = ASN1_APPLICATION | ASN1_CONSTRUCTED | 0x09
LDAP_DELETE_REQUEST = ASN1_APPLICATION | ASN1_PRIMITIVE | 0x0A
LDAP_DELETE_RESPONSE = ASN1_APPLICATION | ASN1_CONSTRUCTED | 0x0B
LDAP_MODIFY_DN_REQUEST = ASN1_APPLICATION | ASN1_CONSTRUCTED | 0x0C
LDAP_MODIFY_DN_RESPONSE = ASN1_APPLICATION | ASN1_CONSTRUCTED | 0x0D
LDAP_COMPARE_REQUEST = ASN1_APPLICATION | ASN1_CONSTRUCTED | 0x0E
LDAP_COMPARE_RESPONSE = ASN1_APPLICATION | ASN1_CONSTRUCTED | 0x0F
LDAP_ABANDON_REQUEST = ASN1_APPLICATION | ASN1_PRIMITIVE | 0x10
LDAP_SEARCH_RESULT_REFERENCE = ASN1_APPLICATION | ASN1_CONSTRUCTED | 0x13
LDAP_EXTENDED_REQUEST = ASN1_APPLICATION | ASN1_CONSTRUCTED | 0x17
LDAP_EXTENDED_RESPONSE = ASN1_APPLICATION | ASN1_CONSTRUCTED | 0x18
LDAP_INTERMEDIATE_RESPONSE = ASN1_APPLICATION | ASN1_CONSTRUCTED | 0x19

# LDAP filter types (Context class)
LDAP_FILTER_AND = ASN1_CONTEXT | ASN1_CONSTRUCTED | 0x00
LDAP_FILTER_OR = ASN1_CONTEXT | ASN1_CONSTRUCTED | 0x01
LDAP_FILTER_NOT = ASN1_CONTEXT | ASN1_CONSTRUCTED | 0x02
LDAP_FILTER_EQUALITY = ASN1_CONTEXT | ASN1_CONSTRUCTED | 0x03
LDAP_FILTER_SUBSTRINGS = ASN1_CONTEXT | ASN1_CONSTRUCTED | 0x04
LDAP_FILTER_GREATER_OR_EQUAL = ASN1_CONTEXT | ASN1_CONSTRUCTED | 0x05
LDAP_FILTER_LESS_OR_EQUAL = ASN1_CONTEXT | ASN1_CONSTRUCTED | 0x06
LDAP_FILTER_PRESENT = ASN1_CONTEXT | ASN1_PRIMITIVE | 0x07
LDAP_FILTER_APPROXIMATE = ASN1_CONTEXT | ASN1_CONSTRUCTED | 0x08
LDAP_FILTER_EXTENSIBLE = ASN1_CONTEXT | ASN1_CONSTRUCTED | 0x09

# =============================================================================
# UTILITY FUNCTIONS
# =============================================================================


def get_tag_class(tag: int) -> int:
    """Extract tag class from tag byte.

    Args:
        tag: ASN.1 tag byte

    Returns:
        Tag class (UNIVERSAL, APPLICATION, CONTEXT, PRIVATE)
    """
    return tag & ASN1_CLASS_MASK


def get_tag_form(tag: int) -> int:
    """Extract tag form from tag byte.

    Args:
        tag: ASN.1 tag byte

    Returns:
        Tag form (PRIMITIVE, CONSTRUCTED)
    """
    return tag & ASN1_FORM_MASK


def get_tag_number(tag: int) -> int:
    """Extract tag number from tag byte.

    Args:
        tag: ASN.1 tag byte

    Returns:
        Tag number (for short form only)
    """
    return tag & ASN1_TAG_NUMBER_MASK


def is_constructed(tag: int) -> bool:
    """Check if tag represents constructed encoding.

    Args:
        tag: ASN.1 tag byte

    Returns:
        True if tag is constructed
    """
    return bool(tag & ASN1_CONSTRUCTED)


def is_primitive(tag: int) -> bool:
    """Check if tag represents primitive encoding.

    Args:
        tag: ASN.1 tag byte

    Returns:
        True if tag is primitive
    """
    return not is_constructed(tag)


def is_universal(tag: int) -> bool:
    """Check if tag is universal class.

    Args:
        tag: ASN.1 tag byte

    Returns:
        True if tag is universal class
    """
    return get_tag_class(tag) == ASN1_UNIVERSAL


def is_application(tag: int) -> bool:
    """Check if tag is application class.

    Args:
        tag: ASN.1 tag byte

    Returns:
        True if tag is application class
    """
    return get_tag_class(tag) == ASN1_APPLICATION


def is_context(tag: int) -> bool:
    """Check if tag is context-specific class.

    Args:
        tag: ASN.1 tag byte

    Returns:
        True if tag is context-specific class
    """
    return get_tag_class(tag) == ASN1_CONTEXT


def is_private(tag: int) -> bool:
    """Check if tag is private class.

    Args:
        tag: ASN.1 tag byte

    Returns:
        True if tag is private class
    """
    return get_tag_class(tag) == ASN1_PRIVATE


def make_tag(tag_class: int, form: int, number: int) -> int:
    """Construct ASN.1 tag from components.

    Args:
        tag_class: Tag class (UNIVERSAL, APPLICATION, etc.)
        form: Tag form (PRIMITIVE, CONSTRUCTED)
        number: Tag number

    Returns:
        Complete ASN.1 tag byte

    Raises:
        ValueError: If tag number too large for short form
    """
    if number >= ASN1_LONG_TAG_FORM:
        msg = f"Tag number {number} requires long form encoding"
        raise ValueError(msg)

    return tag_class | form | number


# =============================================================================
# CONSTANT VALIDATION
# =============================================================================

def validate_constants() -> None:
    """Validate ASN.1 constant definitions for consistency."""
    # Verify tag class values don't overlap
    assert ASN1_UNIVERSAL != ASN1_APPLICATION
    assert ASN1_APPLICATION != ASN1_CONTEXT
    assert ASN1_CONTEXT != ASN1_PRIVATE

    # Verify form values are distinct
    assert ASN1_PRIMITIVE != ASN1_CONSTRUCTED

    # Universal tag validation constants
    ASN1_UNIVERSAL_TAG_MIN = 0
    ASN1_UNIVERSAL_TAG_MAX = 0x1E  # 30 in decimal - maximum universal tag value

    # Verify universal type tags are in valid range
    assert ASN1_UNIVERSAL_TAG_MIN <= ASN1_BOOLEAN <= ASN1_UNIVERSAL_TAG_MAX
    assert ASN1_UNIVERSAL_TAG_MIN <= ASN1_SEQUENCE <= ASN1_UNIVERSAL_TAG_MAX

    # Verify compatibility aliases match
    assert ASN_BOOLEAN == ASN1_BOOLEAN
    assert ASN_SEQUENCE == ASN1_SEQUENCE


# Run validation on import
validate_constants()


# Export all constants for star import
__all__ = [
    "ASN1_APPLICATION",
    "ASN1_BIT_STRING",
    # Universal type tags
    "ASN1_BOOLEAN",
    "ASN1_CONSTRUCTED",
    "ASN1_CONTEXT",
    "ASN1_ENUMERATED",
    "ASN1_GENERALIZED_TIME",
    "ASN1_IA5_STRING",
    "ASN1_INDEFINITE_LENGTH",
    "ASN1_INTEGER",
    # Length constants
    "ASN1_LONG_LENGTH",
    "ASN1_NULL",
    "ASN1_NUMERIC_STRING",
    "ASN1_OBJECT_IDENTIFIER",
    "ASN1_OCTET_STRING",
    # Tag forms
    "ASN1_PRIMITIVE",
    "ASN1_PRINTABLE_STRING",
    "ASN1_PRIVATE",
    "ASN1_REAL",
    "ASN1_RELATIVE_OID",
    "ASN1_SEQUENCE",
    "ASN1_SET",
    # Tag classes
    "ASN1_UNIVERSAL",
    "ASN1_UTC_TIME",
    "ASN1_UTF8_STRING",
    "ASN1_VISIBLE_STRING",
    "ASN_APPLICATION",
    "ASN_BIT",
    "ASN_BIT_STR",
    # Compatibility aliases
    "ASN_BOOLEAN",
    "ASN_CONSTRUCTOR",
    "ASN_CONTEXT",
    "ASN_ENUMERATED",
    "ASN_EXTENSION_ID",
    "ASN_GENERAL_TIME",
    "ASN_IA5_STR",
    "ASN_INTEGER",
    "ASN_LONG_LEN",
    "ASN_NULL",
    "ASN_OBJECT_ID",
    "ASN_OCTET_STR",
    "ASN_PRIMITIVE",
    "ASN_PRINT_STR",
    "ASN_PRIVATE",
    "ASN_REAL",
    "ASN_RELATIVE_OID",
    "ASN_SEQUENCE",
    "ASN_SET",
    "ASN_UNIVERSAL",
    "ASN_UTC_TIME",
    "DEFAULT_ENCODING",
    "DEFAULT_TAGGING",
    # Encoding constants
    "ENCODING_BER",
    "ENCODING_DER",
    # LDAP constants
    "LDAP_BIND_REQUEST",
    "LDAP_BIND_RESPONSE",
    "LDAP_FILTER_AND",
    "LDAP_FILTER_OR",
    "LDAP_SEARCH_REQUEST",
    "LDAP_SEARCH_RESULT_ENTRY",
    "TAGGING_EXPLICIT",
    "TAGGING_IMPLICIT",
    # Utility functions
    "get_tag_class",
    "get_tag_form",
    "get_tag_number",
    "is_application",
    "is_constructed",
    "is_context",
    "is_primitive",
    "is_private",
    "is_universal",
    "make_tag",
    "validate_constants",
]
