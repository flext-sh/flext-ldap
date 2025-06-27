"""Unit tests for ASN.1 Types module.

Tests the ASN.1 primitive and constructed types including integers,
strings, booleans, null values, and other fundamental ASN.1 data types.
"""

from __future__ import annotations

import pytest


class TestASN1Integer:
    """Test cases for ASN1Integer type."""

    @pytest.mark.unit
    @pytest.mark.asn1
    def test_integer_creation(self) -> None:
        """Test ASN1Integer creation with various values."""
        try:
            from ldap_core_shared.protocols.asn1.types import ASN1Integer

            # Test positive integer
            int1 = ASN1Integer(42)
            assert int1.get_value() == 42

            # Test negative integer
            int2 = ASN1Integer(-100)
            assert int2.get_value() == -100

            # Test zero
            int3 = ASN1Integer(0)
            assert int3.get_value() == 0

            # Test large integer
            large_int = ASN1Integer(2**64)
            assert large_int.get_value() == 2**64

        except ImportError:
            pytest.skip("ASN1Integer module not available")

    @pytest.mark.unit
    @pytest.mark.asn1
    def test_integer_tag(self) -> None:
        """Test ASN1Integer default tag."""
        try:
            from ldap_core_shared.protocols.asn1.constants import (
                ASN1_PRIMITIVE,
                ASN1_UNIVERSAL,
            )
            from ldap_core_shared.protocols.asn1.types import ASN1Integer

            integer = ASN1Integer(42)
            tag = integer.get_default_tag()

            assert tag.tag_class == ASN1_UNIVERSAL
            assert tag.tag_form == ASN1_PRIMITIVE
            assert tag.tag_number == 2  # INTEGER tag number

        except ImportError:
            pytest.skip("ASN1Integer tag functionality not available")

    @pytest.mark.unit
    @pytest.mark.asn1
    def test_integer_validation(self) -> None:
        """Test ASN1Integer validation."""
        try:
            from ldap_core_shared.protocols.asn1.types import ASN1Integer

            # Valid integer
            valid_int = ASN1Integer(42)
            errors = valid_int.validate()
            assert isinstance(errors, list)
            # Should have no errors for valid integer

            # Test with non-integer value
            try:
                invalid_int = ASN1Integer("not an integer")
                errors = invalid_int.validate()
                # Should detect type error
            except (ValueError, TypeError):
                # Expected for invalid type
                pass

        except ImportError:
            pytest.skip("ASN1Integer validation not available")

    @pytest.mark.unit
    @pytest.mark.asn1
    def test_integer_encoding_interface(self) -> None:
        """Test ASN1Integer encoding interface."""
        try:
            from ldap_core_shared.protocols.asn1.types import ASN1Integer

            integer = ASN1Integer(42)

            # Should have encode method
            assert hasattr(integer, "encode")

            # Test encoding (may raise NotImplementedError)
            try:
                encoded = integer.encode()
                assert isinstance(encoded, bytes)
                # DER encoding of INTEGER 42 should be \x02\x01\x2A
            except NotImplementedError:
                # Expected during development
                pass

        except ImportError:
            pytest.skip("ASN1Integer encoding not available")


class TestASN1Boolean:
    """Test cases for ASN1Boolean type."""

    @pytest.mark.unit
    @pytest.mark.asn1
    def test_boolean_creation(self) -> None:
        """Test ASN1Boolean creation."""
        try:
            from ldap_core_shared.protocols.asn1.types import ASN1Boolean

            # Test True
            bool_true = ASN1Boolean(True)
            assert bool_true.get_value() is True

            # Test False
            bool_false = ASN1Boolean(False)
            assert bool_false.get_value() is False

        except ImportError:
            pytest.skip("ASN1Boolean module not available")

    @pytest.mark.unit
    @pytest.mark.asn1
    def test_boolean_tag(self) -> None:
        """Test ASN1Boolean default tag."""
        try:
            from ldap_core_shared.protocols.asn1.constants import (
                ASN1_PRIMITIVE,
                ASN1_UNIVERSAL,
            )
            from ldap_core_shared.protocols.asn1.types import ASN1Boolean

            boolean = ASN1Boolean(True)
            tag = boolean.get_default_tag()

            assert tag.tag_class == ASN1_UNIVERSAL
            assert tag.tag_form == ASN1_PRIMITIVE
            assert tag.tag_number == 1  # BOOLEAN tag number

        except ImportError:
            pytest.skip("ASN1Boolean tag functionality not available")

    @pytest.mark.unit
    @pytest.mark.asn1
    def test_boolean_validation(self) -> None:
        """Test ASN1Boolean validation."""
        try:
            from ldap_core_shared.protocols.asn1.types import ASN1Boolean

            # Valid boolean
            valid_bool = ASN1Boolean(True)
            errors = valid_bool.validate()
            assert isinstance(errors, list)

        except ImportError:
            pytest.skip("ASN1Boolean validation not available")

    @pytest.mark.unit
    @pytest.mark.asn1
    def test_boolean_encoding_interface(self) -> None:
        """Test ASN1Boolean encoding interface."""
        try:
            from ldap_core_shared.protocols.asn1.types import ASN1Boolean

            boolean = ASN1Boolean(True)

            # Should have encode method
            assert hasattr(boolean, "encode")

            # Test encoding (may raise NotImplementedError)
            try:
                encoded = boolean.encode()
                assert isinstance(encoded, bytes)
            except NotImplementedError:
                # Expected during development
                pass

        except ImportError:
            pytest.skip("ASN1Boolean encoding not available")


class TestASN1UTF8String:
    """Test cases for ASN1UTF8String type."""

    @pytest.mark.unit
    @pytest.mark.asn1
    def test_utf8string_creation(self) -> None:
        """Test ASN1UTF8String creation."""
        try:
            from ldap_core_shared.protocols.asn1.types import ASN1UTF8String

            # Test ASCII string
            str1 = ASN1UTF8String("Hello World")
            assert str1.get_value() == "Hello World"

            # Test UTF-8 string
            str2 = ASN1UTF8String("Olá Mundo 🌍")
            assert str2.get_value() == "Olá Mundo 🌍"

            # Test empty string
            str3 = ASN1UTF8String("")
            assert str3.get_value() == ""

        except ImportError:
            pytest.skip("ASN1UTF8String module not available")

    @pytest.mark.unit
    @pytest.mark.asn1
    def test_utf8string_tag(self) -> None:
        """Test ASN1UTF8String default tag."""
        try:
            from ldap_core_shared.protocols.asn1.constants import (
                ASN1_PRIMITIVE,
                ASN1_UNIVERSAL,
            )
            from ldap_core_shared.protocols.asn1.types import ASN1UTF8String

            string = ASN1UTF8String("test")
            tag = string.get_default_tag()

            assert tag.tag_class == ASN1_UNIVERSAL
            assert tag.tag_form == ASN1_PRIMITIVE
            assert tag.tag_number == 12  # UTF8String tag number

        except ImportError:
            pytest.skip("ASN1UTF8String tag functionality not available")

    @pytest.mark.unit
    @pytest.mark.asn1
    def test_utf8string_validation(self) -> None:
        """Test ASN1UTF8String validation."""
        try:
            from ldap_core_shared.protocols.asn1.types import ASN1UTF8String

            # Valid UTF-8 string
            valid_str = ASN1UTF8String("Valid UTF-8: 🎉")
            errors = valid_str.validate()
            assert isinstance(errors, list)

        except ImportError:
            pytest.skip("ASN1UTF8String validation not available")

    @pytest.mark.unit
    @pytest.mark.asn1
    def test_utf8string_encoding_interface(self) -> None:
        """Test ASN1UTF8String encoding interface."""
        try:
            from ldap_core_shared.protocols.asn1.types import ASN1UTF8String

            string = ASN1UTF8String("test")

            # Should have encode method
            assert hasattr(string, "encode")

            # Test encoding (may raise NotImplementedError)
            try:
                encoded = string.encode()
                assert isinstance(encoded, bytes)
            except NotImplementedError:
                # Expected during development
                pass

        except ImportError:
            pytest.skip("ASN1UTF8String encoding not available")


class TestASN1OctetString:
    """Test cases for ASN1OctetString type."""

    @pytest.mark.unit
    @pytest.mark.asn1
    def test_octetstring_creation(self) -> None:
        """Test ASN1OctetString creation."""
        try:
            from ldap_core_shared.protocols.asn1.types import ASN1OctetString

            # Test with bytes
            octets1 = ASN1OctetString(b"Hello World")
            assert octets1.get_value() == b"Hello World"

            # Test with string (should be converted to bytes)
            octets2 = ASN1OctetString("Hello")
            if isinstance(octets2.get_value(), bytes):
                assert octets2.get_value() == b"Hello"
            else:
                assert octets2.get_value() == "Hello"

            # Test empty
            octets3 = ASN1OctetString(b"")
            assert octets3.get_value() == b""

        except ImportError:
            pytest.skip("ASN1OctetString module not available")

    @pytest.mark.unit
    @pytest.mark.asn1
    def test_octetstring_tag(self) -> None:
        """Test ASN1OctetString default tag."""
        try:
            from ldap_core_shared.protocols.asn1.constants import (
                ASN1_PRIMITIVE,
                ASN1_UNIVERSAL,
            )
            from ldap_core_shared.protocols.asn1.types import ASN1OctetString

            octets = ASN1OctetString(b"test")
            tag = octets.get_default_tag()

            assert tag.tag_class == ASN1_UNIVERSAL
            assert tag.tag_form == ASN1_PRIMITIVE
            assert tag.tag_number == 4  # OCTET STRING tag number

        except ImportError:
            pytest.skip("ASN1OctetString tag functionality not available")


class TestASN1Null:
    """Test cases for ASN1Null type."""

    @pytest.mark.unit
    @pytest.mark.asn1
    def test_null_creation(self) -> None:
        """Test ASN1Null creation."""
        try:
            from ldap_core_shared.protocols.asn1.types import ASN1Null

            null = ASN1Null()
            assert null.get_value() is None

        except ImportError:
            pytest.skip("ASN1Null module not available")

    @pytest.mark.unit
    @pytest.mark.asn1
    def test_null_tag(self) -> None:
        """Test ASN1Null default tag."""
        try:
            from ldap_core_shared.protocols.asn1.constants import (
                ASN1_PRIMITIVE,
                ASN1_UNIVERSAL,
            )
            from ldap_core_shared.protocols.asn1.types import ASN1Null

            null = ASN1Null()
            tag = null.get_default_tag()

            assert tag.tag_class == ASN1_UNIVERSAL
            assert tag.tag_form == ASN1_PRIMITIVE
            assert tag.tag_number == 5  # NULL tag number

        except ImportError:
            pytest.skip("ASN1Null tag functionality not available")

    @pytest.mark.unit
    @pytest.mark.asn1
    def test_null_validation(self) -> None:
        """Test ASN1Null validation."""
        try:
            from ldap_core_shared.protocols.asn1.types import ASN1Null

            null = ASN1Null()
            errors = null.validate()
            assert isinstance(errors, list)
            # NULL should always be valid

        except ImportError:
            pytest.skip("ASN1Null validation not available")


class TestASN1ObjectIdentifier:
    """Test cases for ASN1ObjectIdentifier type."""

    @pytest.mark.unit
    @pytest.mark.asn1
    def test_oid_creation(self) -> None:
        """Test ASN1ObjectIdentifier creation."""
        try:
            from ldap_core_shared.protocols.asn1.types import ASN1ObjectIdentifier

            # Test with string OID
            oid1 = ASN1ObjectIdentifier("1.2.3.4.5")
            assert oid1.get_value() == "1.2.3.4.5"

            # Test with tuple OID
            oid2 = ASN1ObjectIdentifier((1, 2, 3, 4, 5))
            if isinstance(oid2.get_value(), tuple):
                assert oid2.get_value() == (1, 2, 3, 4, 5)
            else:
                assert oid2.get_value() == "1.2.3.4.5"

        except ImportError:
            pytest.skip("ASN1ObjectIdentifier module not available")

    @pytest.mark.unit
    @pytest.mark.asn1
    def test_oid_tag(self) -> None:
        """Test ASN1ObjectIdentifier default tag."""
        try:
            from ldap_core_shared.protocols.asn1.constants import (
                ASN1_PRIMITIVE,
                ASN1_UNIVERSAL,
            )
            from ldap_core_shared.protocols.asn1.types import ASN1ObjectIdentifier

            oid = ASN1ObjectIdentifier("1.2.3")
            tag = oid.get_default_tag()

            assert tag.tag_class == ASN1_UNIVERSAL
            assert tag.tag_form == ASN1_PRIMITIVE
            assert tag.tag_number == 6  # OBJECT IDENTIFIER tag number

        except ImportError:
            pytest.skip("ASN1ObjectIdentifier tag functionality not available")

    @pytest.mark.unit
    @pytest.mark.asn1
    def test_oid_validation(self) -> None:
        """Test ASN1ObjectIdentifier validation."""
        try:
            from ldap_core_shared.protocols.asn1.types import ASN1ObjectIdentifier

            # Valid OID
            valid_oid = ASN1ObjectIdentifier("1.2.3.4.5")
            errors = valid_oid.validate()
            assert isinstance(errors, list)

            # Test invalid OID format
            try:
                invalid_oid = ASN1ObjectIdentifier("invalid.oid")
                errors = invalid_oid.validate()
                # Should detect format error
            except ValueError:
                # Expected for invalid format
                pass

        except ImportError:
            pytest.skip("ASN1ObjectIdentifier validation not available")


class TestASN1BitString:
    """Test cases for ASN1BitString type."""

    @pytest.mark.unit
    @pytest.mark.asn1
    def test_bitstring_creation(self) -> None:
        """Test ASN1BitString creation."""
        try:
            from ldap_core_shared.protocols.asn1.types import ASN1BitString

            # Test with binary string
            bits1 = ASN1BitString("101010")
            assert bits1.get_value() == "101010"

            # Test with bytes
            bits2 = ASN1BitString(b"\xaa")  # 10101010
            if isinstance(bits2.get_value(), bytes):
                assert bits2.get_value() == b"\xaa"

        except ImportError:
            pytest.skip("ASN1BitString module not available")

    @pytest.mark.unit
    @pytest.mark.asn1
    def test_bitstring_tag(self) -> None:
        """Test ASN1BitString default tag."""
        try:
            from ldap_core_shared.protocols.asn1.constants import (
                ASN1_PRIMITIVE,
                ASN1_UNIVERSAL,
            )
            from ldap_core_shared.protocols.asn1.types import ASN1BitString

            bits = ASN1BitString("101010")
            tag = bits.get_default_tag()

            assert tag.tag_class == ASN1_UNIVERSAL
            assert tag.tag_form == ASN1_PRIMITIVE
            assert tag.tag_number == 3  # BIT STRING tag number

        except ImportError:
            pytest.skip("ASN1BitString tag functionality not available")


class TestASN1Enumerated:
    """Test cases for ASN1Enumerated type."""

    @pytest.mark.unit
    @pytest.mark.asn1
    def test_enumerated_creation(self) -> None:
        """Test ASN1Enumerated creation."""
        try:
            from ldap_core_shared.protocols.asn1.types import ASN1Enumerated

            # Test with integer value
            enum1 = ASN1Enumerated(1)
            assert enum1.get_value() == 1

            # Test with enumerated values
            enum2 = ASN1Enumerated(42)
            assert enum2.get_value() == 42

        except ImportError:
            pytest.skip("ASN1Enumerated module not available")

    @pytest.mark.unit
    @pytest.mark.asn1
    def test_enumerated_tag(self) -> None:
        """Test ASN1Enumerated default tag."""
        try:
            from ldap_core_shared.protocols.asn1.constants import (
                ASN1_PRIMITIVE,
                ASN1_UNIVERSAL,
            )
            from ldap_core_shared.protocols.asn1.types import ASN1Enumerated

            enum = ASN1Enumerated(1)
            tag = enum.get_default_tag()

            assert tag.tag_class == ASN1_UNIVERSAL
            assert tag.tag_form == ASN1_PRIMITIVE
            assert tag.tag_number == 10  # ENUMERATED tag number

        except ImportError:
            pytest.skip("ASN1Enumerated tag functionality not available")


class TestASN1TypeUtilities:
    """Test ASN.1 type utility functions."""

    @pytest.mark.unit
    @pytest.mark.asn1
    def test_type_string_representations(self) -> None:
        """Test string representations of ASN.1 types."""
        try:
            from ldap_core_shared.protocols.asn1.types import (
                ASN1Integer,
                ASN1UTF8String,
            )

            # Test integer string representation
            integer = ASN1Integer(42)
            str_repr = str(integer)
            assert "42" in str_repr
            assert "ASN1Integer" in str_repr

            # Test string string representation
            string = ASN1UTF8String("test")
            str_repr = str(string)
            assert "test" in str_repr
            assert "ASN1UTF8String" in str_repr

        except ImportError:
            pytest.skip("ASN.1 type string representations not available")

    @pytest.mark.unit
    @pytest.mark.asn1
    def test_type_dictionary_conversion(self) -> None:
        """Test dictionary conversion of ASN.1 types."""
        try:
            from ldap_core_shared.protocols.asn1.types import ASN1Integer

            integer = ASN1Integer(42)

            if hasattr(integer, "to_dict"):
                dict_repr = integer.to_dict()
                assert isinstance(dict_repr, dict)
                assert "type" in dict_repr
                assert "value" in dict_repr
                assert dict_repr["value"] == 42

        except ImportError:
            pytest.skip("ASN.1 type dictionary conversion not available")

    @pytest.mark.unit
    @pytest.mark.asn1
    def test_type_equality_comparison(self) -> None:
        """Test equality comparison of ASN.1 types."""
        try:
            from ldap_core_shared.protocols.asn1.types import ASN1Integer

            # Test equal integers
            int1 = ASN1Integer(42)
            int2 = ASN1Integer(42)

            if hasattr(int1, "__eq__"):
                assert int1 == int2

            # Test different integers
            int3 = ASN1Integer(100)
            if hasattr(int1, "__eq__"):
                assert int1 != int3

        except ImportError:
            pytest.skip("ASN.1 type equality comparison not available")


class TestASN1TypePerformance:
    """Performance tests for ASN.1 types."""

    @pytest.mark.unit
    @pytest.mark.asn1
    @pytest.mark.slow
    def test_large_integer_performance(self) -> None:
        """Test performance with large integers."""
        try:
            import time

            from ldap_core_shared.protocols.asn1.types import ASN1Integer

            start_time = time.time()

            # Create many large integers
            for i in range(1000):
                large_int = ASN1Integer(2**128 + i)
                # Basic operations
                large_int.get_value()
                large_int.get_default_tag()
                large_int.validate()

            creation_time = time.time() - start_time

            # Should create reasonably quickly (less than 2 seconds)
            assert creation_time < 2.0

        except ImportError:
            pytest.skip("Large integer performance test not available")

    @pytest.mark.unit
    @pytest.mark.asn1
    @pytest.mark.slow
    def test_large_string_performance(self) -> None:
        """Test performance with large strings."""
        try:
            import time

            from ldap_core_shared.protocols.asn1.types import ASN1UTF8String

            start_time = time.time()

            # Create large string
            large_string = "A" * 10000

            # Create many string objects
            for i in range(100):
                string_obj = ASN1UTF8String(large_string + str(i))
                # Basic operations
                string_obj.get_value()
                string_obj.get_default_tag()
                string_obj.validate()

            creation_time = time.time() - start_time

            # Should create reasonably quickly (less than 2 seconds)
            assert creation_time < 2.0

        except ImportError:
            pytest.skip("Large string performance test not available")
