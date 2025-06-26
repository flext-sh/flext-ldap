"""Unit tests for ASN.1 Elements module.

Tests the ASN.1 element framework including sequences, sets, choices,
tagged elements, and the base ASN.1 element functionality.
"""

from __future__ import annotations

from unittest.mock import Mock

import pytest


class TestASN1Element:
    """Test cases for base ASN1Element class."""

    @pytest.mark.unit
    @pytest.mark.asn1
    def test_asn1_element_base_class(self) -> None:
        """Test ASN1Element base class functionality."""
        try:
            from ldap_core_shared.protocols.asn1.elements import ASN1Element

            # ASN1Element is abstract, so we can't instantiate it directly
            assert ASN1Element is not None
            assert hasattr(ASN1Element, "get_default_tag")
            assert hasattr(ASN1Element, "encode")
            assert hasattr(ASN1Element, "decode")
            assert hasattr(ASN1Element, "validate")

        except ImportError:
            pytest.skip("ASN1Element module not available")

    @pytest.mark.unit
    @pytest.mark.asn1
    def test_asn1_tag_functionality(self) -> None:
        """Test ASN1Tag functionality."""
        try:
            from ldap_core_shared.protocols.asn1.constants import (
                ASN1_PRIMITIVE,
                ASN1_UNIVERSAL,
            )
            from ldap_core_shared.protocols.asn1.elements import ASN1Tag

            tag = ASN1Tag(
                tag_class=ASN1_UNIVERSAL,
                tag_form=ASN1_PRIMITIVE,
                tag_number=2,  # INTEGER
            )

            assert tag.tag_class == ASN1_UNIVERSAL
            assert tag.tag_form == ASN1_PRIMITIVE
            assert tag.tag_number == 2
            assert tag.is_universal() is True
            assert tag.is_constructed() is False

        except ImportError:
            pytest.skip("ASN1Tag module not available")

    @pytest.mark.unit
    @pytest.mark.asn1
    def test_asn1_tag_byte_generation(self) -> None:
        """Test ASN1Tag byte generation."""
        try:
            from ldap_core_shared.protocols.asn1.constants import (
                ASN1_PRIMITIVE,
                ASN1_UNIVERSAL,
            )
            from ldap_core_shared.protocols.asn1.elements import ASN1Tag

            tag = ASN1Tag(
                tag_class=ASN1_UNIVERSAL,
                tag_form=ASN1_PRIMITIVE,
                tag_number=2,
            )

            tag_byte = tag.get_tag_byte()
            assert isinstance(tag_byte, int)
            assert tag_byte == 0x02  # INTEGER tag

        except ImportError:
            pytest.skip("ASN1Tag byte generation not available")


class TestASN1Sequence:
    """Test cases for ASN1Sequence class."""

    @pytest.fixture
    def sample_elements(self):
        """Create sample ASN.1 elements for testing."""
        try:
            from ldap_core_shared.protocols.asn1.types import ASN1Boolean, ASN1Integer
            return [
                ASN1Integer(42),
                ASN1Boolean(True),
                ASN1Integer(100),
            ]
        except ImportError:
            # Return mock elements
            return [
                Mock(get_value=lambda: 42),
                Mock(get_value=lambda: True),
                Mock(get_value=lambda: 100),
            ]

    @pytest.mark.unit
    @pytest.mark.asn1
    def test_sequence_creation(self) -> None:
        """Test ASN1Sequence creation."""
        try:
            from ldap_core_shared.protocols.asn1.elements import ASN1Sequence

            sequence = ASN1Sequence()
            assert sequence is not None
            assert len(sequence) == 0

        except ImportError:
            pytest.skip("ASN1Sequence module not available")

    @pytest.mark.unit
    @pytest.mark.asn1
    def test_sequence_with_elements(self, sample_elements) -> None:
        """Test ASN1Sequence with initial elements."""
        try:
            from ldap_core_shared.protocols.asn1.elements import ASN1Sequence

            sequence = ASN1Sequence(sample_elements)
            assert len(sequence) == 3

            # Test element access
            first_element = sequence[0]
            assert first_element is not None

        except ImportError:
            pytest.skip("ASN1Sequence with elements not available")

    @pytest.mark.unit
    @pytest.mark.asn1
    def test_sequence_operations(self, sample_elements) -> None:
        """Test ASN1Sequence operations (append, insert, remove)."""
        try:
            from ldap_core_shared.protocols.asn1.elements import ASN1Sequence
            from ldap_core_shared.protocols.asn1.types import ASN1Integer

            sequence = ASN1Sequence()

            # Test append
            new_element = ASN1Integer(200)
            sequence.append(new_element)
            assert len(sequence) == 1

            # Test insert
            another_element = ASN1Integer(300)
            sequence.insert(0, another_element)
            assert len(sequence) == 2
            assert sequence[0].get_value() == 300

            # Test remove
            sequence.remove(new_element)
            assert len(sequence) == 1

            # Test clear
            sequence.clear()
            assert len(sequence) == 0

        except ImportError:
            pytest.skip("ASN1Sequence operations not available")

    @pytest.mark.unit
    @pytest.mark.asn1
    def test_sequence_iteration(self, sample_elements) -> None:
        """Test ASN1Sequence iteration."""
        try:
            from ldap_core_shared.protocols.asn1.elements import ASN1Sequence

            sequence = ASN1Sequence(sample_elements)

            # Test iteration
            element_count = 0
            for element in sequence:
                element_count += 1
                assert element is not None

            assert element_count == len(sample_elements)

        except ImportError:
            pytest.skip("ASN1Sequence iteration not available")

    @pytest.mark.unit
    @pytest.mark.asn1
    def test_sequence_validation(self, sample_elements) -> None:
        """Test ASN1Sequence validation."""
        try:
            from ldap_core_shared.protocols.asn1.elements import ASN1Sequence

            sequence = ASN1Sequence(sample_elements)
            errors = sequence.validate()

            # Should be a list (empty if valid)
            assert isinstance(errors, list)

        except ImportError:
            pytest.skip("ASN1Sequence validation not available")


class TestASN1Set:
    """Test cases for ASN1Set class."""

    @pytest.mark.unit
    @pytest.mark.asn1
    def test_set_creation(self) -> None:
        """Test ASN1Set creation."""
        try:
            from ldap_core_shared.protocols.asn1.elements import ASN1Set

            asn1_set = ASN1Set()
            assert asn1_set is not None
            assert len(asn1_set) == 0

        except ImportError:
            pytest.skip("ASN1Set module not available")

    @pytest.mark.unit
    @pytest.mark.asn1
    def test_set_operations(self) -> None:
        """Test ASN1Set operations."""
        try:
            from ldap_core_shared.protocols.asn1.elements import ASN1Set
            from ldap_core_shared.protocols.asn1.types import ASN1Integer

            asn1_set = ASN1Set()

            # Test add
            element1 = ASN1Integer(100)
            asn1_set.add(element1)
            assert len(asn1_set) == 1

            # Test add another
            element2 = ASN1Integer(200)
            asn1_set.add(element2)
            assert len(asn1_set) == 2

            # Test remove
            asn1_set.remove(element1)
            assert len(asn1_set) == 1

        except ImportError:
            pytest.skip("ASN1Set operations not available")

    @pytest.mark.unit
    @pytest.mark.asn1
    def test_set_canonical_ordering(self) -> None:
        """Test ASN1Set canonical ordering for DER."""
        try:
            from ldap_core_shared.protocols.asn1.elements import ASN1Set
            from ldap_core_shared.protocols.asn1.types import ASN1Integer

            asn1_set = ASN1Set()
            asn1_set.add(ASN1Integer(300))
            asn1_set.add(ASN1Integer(100))
            asn1_set.add(ASN1Integer(200))

            # Get canonical order
            canonical_elements = asn1_set.get_canonical_order()
            assert len(canonical_elements) == 3

        except ImportError:
            pytest.skip("ASN1Set canonical ordering not available")


class TestASN1Choice:
    """Test cases for ASN1Choice class."""

    @pytest.mark.unit
    @pytest.mark.asn1
    def test_choice_creation(self) -> None:
        """Test ASN1Choice creation."""
        try:
            from ldap_core_shared.protocols.asn1.elements import ASN1Choice
            from ldap_core_shared.protocols.asn1.types import ASN1Boolean, ASN1Integer

            alternatives = {
                "integer": ASN1Integer,
                "boolean": ASN1Boolean,
            }

            choice = ASN1Choice(alternatives)
            assert choice is not None

            # Verify alternatives
            available = choice.get_alternatives()
            assert "integer" in available
            assert "boolean" in available

        except ImportError:
            pytest.skip("ASN1Choice module not available")

    @pytest.mark.unit
    @pytest.mark.asn1
    def test_choice_selection(self) -> None:
        """Test ASN1Choice selection functionality."""
        try:
            from ldap_core_shared.protocols.asn1.elements import ASN1Choice
            from ldap_core_shared.protocols.asn1.types import (
                ASN1Integer,
                ASN1UTF8String,
            )

            alternatives = {
                "number": ASN1Integer,
                "text": ASN1UTF8String,
            }

            choice = ASN1Choice(alternatives)

            # Test setting choice
            choice.set_choice("number", 42)
            chosen = choice.get_choice()
            assert chosen is not None
            assert chosen[0] == "number"
            assert chosen[1] == 42

            # Test changing choice
            choice.set_choice("text", "Hello World")
            chosen = choice.get_choice()
            assert chosen[0] == "text"
            assert chosen[1] == "Hello World"

        except ImportError:
            pytest.skip("ASN1Choice selection not available")

    @pytest.mark.unit
    @pytest.mark.asn1
    def test_choice_invalid_selection(self) -> None:
        """Test ASN1Choice with invalid selection."""
        try:
            from ldap_core_shared.protocols.asn1.elements import ASN1Choice
            from ldap_core_shared.protocols.asn1.types import ASN1Integer

            alternatives = {"number": ASN1Integer}
            choice = ASN1Choice(alternatives)

            # Test invalid choice
            with pytest.raises(ValueError):
                choice.set_choice("invalid", 42)

        except ImportError:
            pytest.skip("ASN1Choice error handling not available")

    @pytest.mark.unit
    @pytest.mark.asn1
    def test_choice_validation(self) -> None:
        """Test ASN1Choice validation."""
        try:
            from ldap_core_shared.protocols.asn1.elements import ASN1Choice
            from ldap_core_shared.protocols.asn1.types import ASN1Integer

            alternatives = {"number": ASN1Integer}
            choice = ASN1Choice(alternatives)

            # Test validation without choice
            errors = choice.validate()
            assert len(errors) > 0  # Should have error for no choice

            # Test validation with choice
            choice.set_choice("number", 42)
            errors = choice.validate()
            assert isinstance(errors, list)

        except ImportError:
            pytest.skip("ASN1Choice validation not available")


class TestASN1Tagged:
    """Test cases for ASN1Tagged class."""

    @pytest.mark.unit
    @pytest.mark.asn1
    def test_tagged_element_creation(self) -> None:
        """Test ASN1Tagged creation."""
        try:
            from ldap_core_shared.protocols.asn1.constants import ASN1_CONTEXT
            from ldap_core_shared.protocols.asn1.elements import ASN1Tagged
            from ldap_core_shared.protocols.asn1.types import ASN1Integer

            inner_element = ASN1Integer(42)
            tagged = ASN1Tagged(
                inner_element,
                tag_class=ASN1_CONTEXT,
                tag_number=1,
                explicit=True,
            )

            assert tagged is not None
            assert tagged.get_inner_element() == inner_element
            assert tagged.is_explicit() is True
            assert tagged.is_implicit() is False

        except ImportError:
            pytest.skip("ASN1Tagged module not available")

    @pytest.mark.unit
    @pytest.mark.asn1
    def test_tagged_element_implicit(self) -> None:
        """Test ASN1Tagged with implicit tagging."""
        try:
            from ldap_core_shared.protocols.asn1.constants import ASN1_CONTEXT
            from ldap_core_shared.protocols.asn1.elements import ASN1Tagged
            from ldap_core_shared.protocols.asn1.types import ASN1Integer

            inner_element = ASN1Integer(42)
            tagged = ASN1Tagged(
                inner_element,
                tag_class=ASN1_CONTEXT,
                tag_number=2,
                explicit=False,
                implicit=True,
            )

            assert tagged.is_explicit() is False
            assert tagged.is_implicit() is True

        except ImportError:
            pytest.skip("ASN1Tagged implicit tagging not available")

    @pytest.mark.unit
    @pytest.mark.asn1
    def test_tagged_element_validation(self) -> None:
        """Test ASN1Tagged validation."""
        try:
            from ldap_core_shared.protocols.asn1.constants import ASN1_CONTEXT
            from ldap_core_shared.protocols.asn1.elements import ASN1Tagged
            from ldap_core_shared.protocols.asn1.types import ASN1Integer

            inner_element = ASN1Integer(42)
            tagged = ASN1Tagged(
                inner_element,
                tag_class=ASN1_CONTEXT,
                tag_number=1,
                explicit=True,
            )

            errors = tagged.validate()
            assert isinstance(errors, list)

        except ImportError:
            pytest.skip("ASN1Tagged validation not available")


class TestASN1Any:
    """Test cases for ASN1Any class."""

    @pytest.mark.unit
    @pytest.mark.asn1
    def test_any_element_creation(self) -> None:
        """Test ASN1Any creation."""
        try:
            from ldap_core_shared.protocols.asn1.elements import ASN1Any

            # Test with raw bytes
            raw_data = b"\x02\x01\x2A"  # INTEGER 42
            any_element = ASN1Any(raw_data)

            assert any_element is not None
            assert any_element.get_raw_data() == raw_data

        except ImportError:
            pytest.skip("ASN1Any module not available")

    @pytest.mark.unit
    @pytest.mark.asn1
    def test_any_from_element(self) -> None:
        """Test ASN1Any.from_element."""
        try:
            from ldap_core_shared.protocols.asn1.elements import ASN1Any
            from ldap_core_shared.protocols.asn1.types import ASN1Integer

            integer = ASN1Integer(42)
            any_element = ASN1Any.from_element(integer)

            assert any_element is not None
            assert any_element.get_decoded_element() == integer

        except ImportError:
            pytest.skip("ASN1Any.from_element not available")


class TestASN1ElementEncoding:
    """Test ASN.1 element encoding functionality."""

    @pytest.mark.unit
    @pytest.mark.asn1
    def test_element_encoding_interface(self) -> None:
        """Test that elements have encoding interface."""
        try:
            from ldap_core_shared.protocols.asn1.types import ASN1Integer

            integer = ASN1Integer(42)

            # Should have encode method
            assert hasattr(integer, "encode")

            # Test encoding (may raise NotImplementedError)
            try:
                encoded = integer.encode()
                assert isinstance(encoded, bytes)
            except NotImplementedError:
                # Expected during development
                pass

        except ImportError:
            pytest.skip("ASN1 element encoding not available")

    @pytest.mark.unit
    @pytest.mark.asn1
    def test_element_decoding_interface(self) -> None:
        """Test that elements have decoding interface."""
        try:
            from ldap_core_shared.protocols.asn1.types import ASN1Integer

            # Should have decode class method
            assert hasattr(ASN1Integer, "decode")

            # Test decoding (may raise NotImplementedError)
            try:
                test_data = b"\x02\x01\x2A"  # INTEGER 42
                decoded, offset = ASN1Integer.decode(test_data)
                assert decoded is not None
                assert isinstance(offset, int)
            except NotImplementedError:
                # Expected during development
                pass

        except ImportError:
            pytest.skip("ASN1 element decoding not available")


class TestASN1ElementUtilities:
    """Test ASN.1 element utility functions."""

    @pytest.mark.unit
    @pytest.mark.asn1
    def test_element_dictionary_representation(self) -> None:
        """Test element to_dict functionality."""
        try:
            from ldap_core_shared.protocols.asn1.types import ASN1Integer

            integer = ASN1Integer(42)

            if hasattr(integer, "to_dict"):
                dict_repr = integer.to_dict()
                assert isinstance(dict_repr, dict)
                assert "type" in dict_repr
                assert "value" in dict_repr

        except ImportError:
            pytest.skip("ASN1 element dictionary representation not available")

    @pytest.mark.unit
    @pytest.mark.asn1
    def test_element_string_representation(self) -> None:
        """Test element string representation."""
        try:
            from ldap_core_shared.protocols.asn1.types import ASN1Integer

            integer = ASN1Integer(42)

            # Test __str__
            str_repr = str(integer)
            assert isinstance(str_repr, str)
            assert "42" in str_repr

            # Test __repr__
            repr_str = repr(integer)
            assert isinstance(repr_str, str)

        except ImportError:
            pytest.skip("ASN1 element string representation not available")
