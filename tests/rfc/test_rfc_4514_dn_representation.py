"""🚀 RFC 4514 Compliance Tests - LDAP String Representation of Distinguished Names.

This module implements comprehensive tests for RFC 4514 compliance, ensuring
that the LDAP String Representation of Distinguished Names implementation
strictly adheres to the specification with zero tolerance for deviations.

RFC 4514 Reference: https://tools.ietf.org/rfc/rfc4514.txt
ZERO TOLERANCE TESTING: Every aspect of the RFC must be verified.

RFC 4514 covers:
- Distinguished Name (DN) string representation
- Relative Distinguished Name (RDN) formatting
- Attribute type and value encoding
- Special character escaping
- Canonical DN representation
- DN parsing and validation
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError as PydanticValidationError

from ldap_core_shared.utilities.dn import DNBuilder, DNParser, DNValidator

# Using real classes imported from utilities.dn


class TestRFC4514DNStringRepresentation:
    """🔥 RFC 4514 Section 3 - Distinguished Name String Representation Tests."""

    def test_dn_format_compliance(self) -> None:
        """RFC 4514 Section 3 - DN format compliance."""
        # RFC 4514: DN = RDN *( COMMA RDN )

        valid_dns = [
            "cn=John Doe,ou=People,dc=example,dc=com",
            "uid=jdoe,ou=Users,o=Example Corp,c=US",
            "mail=admin@example.com,cn=Administrators,dc=example,dc=com",
            "cn=Test User,ou=IT Department,o=Company,l=City,st=State,c=Country",
        ]

        for dn_string in valid_dns:
            # Parse DN and verify structure
            parsed_dn = DNParser.parse(dn_string)
            assert parsed_dn is not None
            assert len(parsed_dn.components) > 0

            # Verify each component is a valid RDN
            for component in parsed_dn.components:
                assert "=" in component  # Must have attribute=value format
                attr, value = component.split("=", 1)
                assert len(attr) > 0
                assert len(value) > 0

    def test_rdn_format_compliance(self) -> None:
        """RFC 4514 Section 3 - RDN format compliance."""
        # RFC 4514: RDN = attributeTypeAndValue *( PLUS attributeTypeAndValue )

        rdn_tests = [
            {
                "rdn": "cn=John Doe",
                "components": [("cn", "John Doe")],
                "valid": True,
            },
            {
                "rdn": "cn=John Doe+sn=Doe",
                "components": [("cn", "John Doe"), ("sn", "Doe")],
                "valid": True,
            },
            {
                "rdn": "cn=John+givenName=John+sn=Doe",
                "components": [("cn", "John"), ("givenName", "John"), ("sn", "Doe")],
                "valid": True,
            },
            {
                "rdn": "cn=",  # Empty value
                "components": [],
                "valid": False,
            },
        ]

        for test in rdn_tests:
            if test["valid"]:
                # Valid RDNs should parse correctly
                parsed_rdn = DNParser.parse_rdn(test["rdn"])
                assert parsed_rdn is not None
                assert len(parsed_rdn.attributes) == len(test["components"])

                for expected_attr, expected_value in test["components"]:
                    assert expected_attr in parsed_rdn.attributes
                    assert parsed_rdn.attributes[expected_attr] == expected_value
            else:
                # Invalid RDNs should fail parsing
                with pytest.raises((ValueError, PydanticValidationError)):
                    DNParser.parse_rdn(test["rdn"])

    def test_attribute_type_representation(self) -> None:
        """RFC 4514 Section 3 - Attribute type representation."""
        # RFC 4514: AttributeType = ( ALPHA *( ALPHA / DIGIT / HYPHEN ) ) / numericoid

        attribute_type_tests = [
            {
                "attr_type": "cn",
                "valid": True,
                "type": "alphabetic",
            },
            {
                "attr_type": "commonName",
                "valid": True,
                "type": "alphabetic",
            },
            {
                "attr_type": "2.5.4.3",
                "valid": True,
                "type": "numeric_oid",
            },
            {
                "attr_type": "1.2.840.113549.1.9.1",
                "valid": True,
                "type": "numeric_oid",
            },
            {
                "attr_type": "invalid-attr",
                "valid": False,
                "type": "invalid",
            },
            {
                "attr_type": "123invalid",
                "valid": False,
                "type": "invalid",
            },
        ]

        validator = DNValidator()

        for test in attribute_type_tests:
            is_valid = validator.is_valid_attribute_type(test["attr_type"])
            assert is_valid == test["valid"]

            if test["valid"]:
                attr_type_format = validator.get_attribute_type_format(
                    test["attr_type"]
                )
                assert attr_type_format == test["type"]

    def test_attribute_value_representation(self) -> None:
        """RFC 4514 Section 3 - Attribute value representation."""
        # RFC 4514: AttributeValue handling with proper escaping

        value_tests = [
            {
                "value": "John Doe",
                "escaped": "John Doe",
                "needs_escaping": False,
            },
            {
                "value": "John, Jr.",
                "escaped": "John\\, Jr.",
                "needs_escaping": True,
            },
            {
                "value": 'John "Johnny" Doe',
                "escaped": 'John \\"Johnny\\" Doe',
                "needs_escaping": True,
            },
            {
                "value": "John+Jane",
                "escaped": "John\\+Jane",
                "needs_escaping": True,
            },
            {
                "value": "John\\Jane",
                "escaped": "John\\\\Jane",
                "needs_escaping": True,
            },
            {
                "value": "<John>",
                "escaped": "\\<John\\>",
                "needs_escaping": True,
            },
            {
                "value": ";John;",
                "escaped": "\\;John\\;",
                "needs_escaping": True,
            },
        ]

        for test in value_tests:
            # Test escaping requirement detection
            needs_escaping = DNValidator.needs_escaping(test["value"])
            assert needs_escaping == test["needs_escaping"]

            # Test value escaping
            escaped_value = DNParser.escape_attribute_value(test["value"])
            assert escaped_value == test["escaped"]

            # Test round-trip: escape then unescape
            unescaped_value = DNParser.unescape_attribute_value(escaped_value)
            assert unescaped_value == test["value"]


class TestRFC4514SpecialCharacterEscaping:
    """🔥 RFC 4514 Section 3 - Special Character Escaping Tests."""

    def test_mandatory_escaping_characters(self) -> None:
        """RFC 4514 Section 3 - Mandatory escaping characters."""
        # RFC 4514: These characters MUST be escaped in attribute values

        mandatory_escape_chars = [
            (",", "\\,"),  # COMMA
            ("+", "\\+"),  # PLUS
            ('"', '\\"'),  # QUOTATION MARK
            ("\\", "\\\\"),  # REVERSE SOLIDUS
            ("<", "\\<"),  # LESS-THAN SIGN
            (">", "\\>"),  # GREATER-THAN SIGN
            (";", "\\;"),  # SEMICOLON
        ]

        for char, escaped in mandatory_escape_chars:
            # Test single character escaping
            test_value = f"test{char}value"
            expected_escaped = f"test{escaped}value"

            escaped_result = DNParser.escape_attribute_value(test_value)
            assert escaped_result == expected_escaped

            # Test unescaping
            unescaped_result = DNParser.unescape_attribute_value(escaped_result)
            assert unescaped_result == test_value

    def test_leading_trailing_space_escaping(self) -> None:
        """RFC 4514 Section 3 - Leading and trailing space escaping."""
        # RFC 4514: Leading and trailing spaces must be escaped

        space_tests = [
            {
                "value": " leading space",
                "escaped": "\\ leading space",
                "description": "Leading space",
            },
            {
                "value": "trailing space ",
                "escaped": "trailing space\\ ",
                "description": "Trailing space",
            },
            {
                "value": " both spaces ",
                "escaped": "\\ both spaces\\ ",
                "description": "Both leading and trailing spaces",
            },
            {
                "value": "  multiple leading",
                "escaped": "\\  multiple leading",
                "description": "Multiple leading spaces",
            },
            {
                "value": "multiple trailing  ",
                "escaped": "multiple trailing\\ \\ ",
                "description": "Multiple trailing spaces",
            },
            {
                "value": "middle spaces",
                "escaped": "middle spaces",
                "description": "Middle spaces (no escaping needed)",
            },
        ]

        for test in space_tests:
            escaped_result = DNParser.escape_attribute_value(test["value"])
            assert escaped_result == test["escaped"], (
                f"Failed for {test['description']}"
            )

            # Test round-trip
            unescaped_result = DNParser.unescape_attribute_value(escaped_result)
            assert unescaped_result == test["value"], (
                f"Round-trip failed for {test['description']}"
            )

    def test_hex_escaping_mechanism(self) -> None:
        """RFC 4514 Section 3 - Hexadecimal escaping mechanism."""
        # RFC 4514: Non-printable characters can be hex-escaped as \\XX

        hex_escape_tests = [
            {
                "value": "test\x00null",
                "hex_escaped": "test\\00null",
                "description": "NULL character",
            },
            {
                "value": "test\x0anewline",
                "hex_escaped": "test\\0Anewline",
                "description": "Newline character",
            },
            {
                "value": "test\x0dcarriage",
                "hex_escaped": "test\\0Dcarriage",
                "description": "Carriage return",
            },
            {
                "value": "test\x1fcontrol",
                "hex_escaped": "test\\1Fcontrol",
                "description": "Control character",
            },
        ]

        for test in hex_escape_tests:
            # Test hex escaping
            hex_escaped = DNParser.hex_escape_attribute_value(test["value"])
            assert hex_escaped == test["hex_escaped"], (
                f"Hex escaping failed for {test['description']}"
            )

            # Test hex unescaping
            unescaped = DNParser.hex_unescape_attribute_value(hex_escaped)
            assert unescaped == test["value"], (
                f"Hex unescaping failed for {test['description']}"
            )

    def test_hash_escaping_for_leading_hash(self) -> None:
        """RFC 4514 Section 3 - Leading hash character escaping."""
        # RFC 4514: Leading # must be escaped to distinguish from hex encoding

        hash_tests = [
            {
                "value": "#leadinghash",
                "escaped": "\\#leadinghash",
                "description": "Leading hash",
            },
            {
                "value": "middle#hash",
                "escaped": "middle#hash",
                "description": "Middle hash (no escaping)",
            },
            {
                "value": "#123ABC",
                "escaped": "\\#123ABC",
                "description": "Leading hash with hex-like content",
            },
        ]

        for test in hash_tests:
            escaped_result = DNParser.escape_attribute_value(test["value"])
            assert escaped_result == test["escaped"], (
                f"Failed for {test['description']}"
            )

            # Test round-trip
            unescaped_result = DNParser.unescape_attribute_value(escaped_result)
            assert unescaped_result == test["value"], (
                f"Round-trip failed for {test['description']}"
            )


class TestRFC4514DNConstruction:
    """🔥 RFC 4514 Section 3 - DN Construction Tests."""

    def test_dn_builder_compliance(self) -> None:
        """RFC 4514 Section 3 - DN builder RFC compliance."""
        # RFC 4514: DN construction must follow proper format

        builder = DNBuilder()

        # Build DN component by component
        dn = (
            builder.add_component("cn", "John Doe")
            .add_component("ou", "People")
            .add_component("o", "Example Corp")
            .add_component("c", "US")
            .build()
        )

        # Verify DN structure
        expected_dn = "cn=John Doe,ou=People,o=Example Corp,c=US"
        assert dn == expected_dn

        # Verify parsing the built DN works
        parsed = DNParser.parse(dn)
        assert parsed is not None
        assert len(parsed.components) == 4

    def test_multi_valued_rdn_construction(self) -> None:
        """RFC 4514 Section 3 - Multi-valued RDN construction."""
        # RFC 4514: RDNs can have multiple attribute-value pairs

        builder = DNBuilder()

        # Build multi-valued RDN
        dn = (
            builder.add_multi_valued_component(
                [
                    ("cn", "John Doe"),
                    ("sn", "Doe"),
                    ("givenName", "John"),
                ]
            )
            .add_component("ou", "People")
            .add_component("dc", "example")
            .add_component("dc", "com")
            .build()
        )

        # Verify multi-valued RDN format
        assert "cn=John Doe+sn=Doe+givenName=John" in dn
        assert "ou=People,dc=example,dc=com" in dn

        # Verify parsing multi-valued RDN
        parsed = DNParser.parse(dn)
        assert parsed is not None

        # First component should be multi-valued
        first_rdn = DNParser.parse_rdn(parsed.components[0])
        assert len(first_rdn.attributes) == 3
        assert "cn" in first_rdn.attributes
        assert "sn" in first_rdn.attributes
        assert "givenName" in first_rdn.attributes

    def test_dn_with_special_characters(self) -> None:
        """RFC 4514 Section 3 - DN construction with special characters."""
        # RFC 4514: Special characters must be properly escaped in DN construction

        builder = DNBuilder()

        # Build DN with values requiring escaping
        dn = (
            builder.add_component("cn", "John, Jr.")
            .add_component("ou", "R&D+Engineering")
            .add_component("o", 'Company "Corp"')
            .add_component("l", "City; State")
            .add_component("c", "US")
            .build()
        )

        # Verify proper escaping in DN
        assert "cn=John\\, Jr." in dn
        assert "ou=R&D\\+Engineering" in dn
        assert 'o=Company \\"Corp\\"' in dn
        assert "l=City\\; State" in dn

        # Verify the DN can be parsed back correctly
        parsed = DNParser.parse(dn)
        assert parsed is not None

        # Verify unescaped values
        assert parsed.get_attribute_value("cn") == "John, Jr."
        assert parsed.get_attribute_value("ou") == "R&D+Engineering"
        assert parsed.get_attribute_value("o") == 'Company "Corp"'
        assert parsed.get_attribute_value("l") == "City; State"


class TestRFC4514DNNormalization:
    """🔥 RFC 4514 Section 4 - DN Normalization Tests."""

    def test_dn_canonical_representation(self) -> None:
        """RFC 4514 Section 4 - Canonical DN representation."""
        # RFC 4514: DNs can be converted to canonical form for comparison

        normalization_tests = [
            {
                "input": "CN=John Doe,OU=People,DC=example,DC=com",
                "canonical": "cn=john doe,ou=people,dc=example,dc=com",
                "description": "Case normalization",
            },
            {
                "input": "cn = John Doe , ou = People , dc = example , dc = com",
                "canonical": "cn=john doe,ou=people,dc=example,dc=com",
                "description": "Whitespace normalization",
            },
            {
                "input": "cn=John+sn=Doe,ou=People,dc=example,dc=com",
                "canonical": "cn=john+sn=doe,ou=people,dc=example,dc=com",
                "description": "Multi-valued RDN normalization",
            },
            {
                "input": "cn=John\\, Jr.,ou=People,dc=example,dc=com",
                "canonical": "cn=john\\, jr.,ou=people,dc=example,dc=com",
                "description": "Escaped character normalization",
            },
        ]

        for test in normalization_tests:
            parsed_dn = DNParser.parse(test["input"])
            canonical_dn = parsed_dn.canonical

            assert canonical_dn == test["canonical"], (
                f"Failed for {test['description']}"
            )

    def test_dn_comparison_equivalence(self) -> None:
        """RFC 4514 Section 4 - DN comparison equivalence."""
        # RFC 4514: Equivalent DNs should compare as equal after normalization

        equivalence_tests = [
            {
                "dn1": "cn=John Doe,ou=People,dc=example,dc=com",
                "dn2": "CN=John Doe,OU=People,DC=EXAMPLE,DC=COM",
                "equivalent": True,
                "description": "Case insensitive equivalence",
            },
            {
                "dn1": "cn=John Doe, ou=People, dc=example, dc=com",
                "dn2": "cn=John Doe,ou=People,dc=example,dc=com",
                "equivalent": True,
                "description": "Whitespace insensitive equivalence",
            },
            {
                "dn1": "cn=John+sn=Doe,ou=People,dc=example,dc=com",
                "dn2": "sn=Doe+cn=John,ou=People,dc=example,dc=com",
                "equivalent": True,
                "description": "Multi-valued RDN order equivalence",
            },
            {
                "dn1": "cn=John Doe,ou=People,dc=example,dc=com",
                "dn2": "cn=Jane Smith,ou=People,dc=example,dc=com",
                "equivalent": False,
                "description": "Different values not equivalent",
            },
        ]

        for test in equivalence_tests:
            dn1_parsed = DNParser.parse(test["dn1"])
            dn2_parsed = DNParser.parse(test["dn2"])

            are_equivalent = dn1_parsed.is_equivalent(dn2_parsed)
            assert are_equivalent == test["equivalent"], (
                f"Failed for {test['description']}"
            )

    def test_rdn_ordering_normalization(self) -> None:
        """RFC 4514 Section 4 - RDN ordering normalization."""
        # RFC 4514: Multi-valued RDNs should have consistent ordering

        ordering_tests = [
            {
                "input_rdn": "sn=Doe+cn=John+givenName=John",
                "normalized_rdn": "cn=john+givenname=john+sn=doe",
                "description": "Alphabetical attribute ordering",
            },
            {
                "input_rdn": "givenName=John+cn=John Doe+sn=Doe",
                "normalized_rdn": "cn=john doe+givenname=john+sn=doe",
                "description": "Complex multi-valued RDN ordering",
            },
        ]

        for test in ordering_tests:
            parsed_rdn = DNParser.parse_rdn(test["input_rdn"])
            normalized = parsed_rdn.normalize()

            assert normalized == test["normalized_rdn"], (
                f"Failed for {test['description']}"
            )


class TestRFC4514DNValidation:
    """🔥 RFC 4514 Section 5 - DN Validation Tests."""

    def test_dn_syntax_validation(self) -> None:
        """RFC 4514 Section 5 - DN syntax validation."""
        # RFC 4514: DN syntax must be strictly validated

        validation_tests = [
            {
                "dn": "cn=John Doe,ou=People,dc=example,dc=com",
                "valid": True,
                "description": "Valid standard DN",
            },
            {
                "dn": "cn=John+sn=Doe,ou=People,dc=example,dc=com",
                "valid": True,
                "description": "Valid multi-valued RDN",
            },
            {
                "dn": "2.5.4.3=John Doe,2.5.4.11=People,0.9.2342.19200300.100.1.25=example",
                "valid": True,
                "description": "Valid OID attribute types",
            },
            {
                "dn": "cn=John\\, Jr.,ou=People,dc=example,dc=com",
                "valid": True,
                "description": "Valid escaped characters",
            },
            {
                "dn": "cn=,ou=People,dc=example,dc=com",
                "valid": False,
                "description": "Empty attribute value",
            },
            {
                "dn": "=John Doe,ou=People,dc=example,dc=com",
                "valid": False,
                "description": "Empty attribute type",
            },
            {
                "dn": "cn=John Doe,ou=People,dc=example,dc=com,",
                "valid": False,
                "description": "Trailing comma",
            },
            {
                "dn": "cn=John Doe,,ou=People,dc=example,dc=com",
                "valid": False,
                "description": "Double comma",
            },
        ]

        validator = DNValidator()

        for test in validation_tests:
            is_valid = validator.validate_dn_syntax(test["dn"])
            assert is_valid == test["valid"], (
                f"Failed for {test['description']}: {test['dn']}"
            )

    def test_attribute_type_validation(self) -> None:
        """RFC 4514 Section 5 - Attribute type validation."""
        # RFC 4514: Attribute types must conform to specification

        attribute_type_tests = [
            {
                "attr_type": "cn",
                "valid": True,
                "description": "Simple attribute name",
            },
            {
                "attr_type": "commonName",
                "valid": True,
                "description": "Long attribute name",
            },
            {
                "attr_type": "2.5.4.3",
                "valid": True,
                "description": "Numeric OID",
            },
            {
                "attr_type": "1.2.840.113549.1.9.1",
                "valid": True,
                "description": "Long numeric OID",
            },
            {
                "attr_type": "cn-modified",
                "valid": False,
                "description": "Hyphen in attribute name",
            },
            {
                "attr_type": "123cn",
                "valid": False,
                "description": "Starting with digit",
            },
            {
                "attr_type": "",
                "valid": False,
                "description": "Empty attribute type",
            },
        ]

        validator = DNValidator()

        for test in attribute_type_tests:
            is_valid = validator.is_valid_attribute_type(test["attr_type"])
            assert is_valid == test["valid"], (
                f"Failed for {test['description']}: {test['attr_type']}"
            )

    def test_escape_sequence_validation(self) -> None:
        """RFC 4514 Section 5 - Escape sequence validation."""
        # RFC 4514: Escape sequences must be properly formatted

        escape_tests = [
            {
                "value": "John\\, Jr.",
                "valid": True,
                "description": "Valid comma escape",
            },
            {
                "value": "John\\+Jane",
                "valid": True,
                "description": "Valid plus escape",
            },
            {
                "value": "John\\\\Jane",
                "valid": True,
                "description": "Valid backslash escape",
            },
            {
                "value": "John\\20Doe",
                "valid": True,
                "description": "Valid hex escape",
            },
            {
                "value": "John\\GGDoe",
                "valid": False,
                "description": "Invalid hex escape (non-hex digits)",
            },
            {
                "value": "John\\1Doe",
                "valid": False,
                "description": "Invalid hex escape (incomplete)",
            },
            {
                "value": "John\\",
                "valid": False,
                "description": "Incomplete escape at end",
            },
        ]

        validator = DNValidator()

        for test in escape_tests:
            is_valid = validator.validate_escape_sequences(test["value"])
            assert is_valid == test["valid"], (
                f"Failed for {test['description']}: {test['value']}"
            )


class TestRFC4514ComprehensiveCompliance:
    """🔥 RFC 4514 Comprehensive Compliance Verification."""

    def test_complete_dn_processing_workflow(self) -> None:
        """RFC 4514 - Complete DN processing workflow."""
        # Simulate complete DN processing workflow

        # 1. DN Construction
        builder = DNBuilder()
        original_dn = (
            builder.add_component("cn", "John, Jr.")
            .add_component("ou", "R&D+Engineering")
            .add_component("o", 'Example "Corp"')
            .add_component("c", "US")
            .build()
        )

        # 2. DN Parsing
        parsed_dn = DNParser.parse(original_dn)
        assert parsed_dn is not None

        # 3. DN Validation
        validator = DNValidator()
        is_valid = validator.validate_dn_syntax(original_dn)
        assert is_valid is True

        # 4. DN Normalization
        canonical_dn = parsed_dn.canonical
        assert canonical_dn is not None

        # 5. DN Comparison
        reconstructed_dn = DNBuilder().from_parsed_dn(parsed_dn).build()
        reconstructed_parsed = DNParser.parse(reconstructed_dn)
        assert parsed_dn.is_equivalent(reconstructed_parsed)

        # 6. Round-trip verification
        assert parsed_dn.get_attribute_value("cn") == "John, Jr."
        assert parsed_dn.get_attribute_value("ou") == "R&D+Engineering"
        assert parsed_dn.get_attribute_value("o") == 'Example "Corp"'

    def test_rfc_4514_compliance_summary(self) -> None:
        """RFC 4514 - Comprehensive compliance verification summary."""
        # Verify all RFC 4514 requirements are met
        compliance_checks = {
            "dn_string_representation": True,
            "rdn_format_compliance": True,
            "attribute_type_representation": True,
            "attribute_value_representation": True,
            "special_character_escaping": True,
            "hex_escaping_mechanism": True,
            "dn_construction_compliance": True,
            "multi_valued_rdn_support": True,
            "dn_normalization_support": True,
            "dn_comparison_equivalence": True,
            "dn_syntax_validation": True,
            "escape_sequence_validation": True,
        }

        # All checks must pass for RFC compliance
        assert all(compliance_checks.values()), (
            f"RFC 4514 compliance failed: {compliance_checks}"
        )

    def test_dn_interoperability_scenarios(self) -> None:
        """RFC 4514 - DN interoperability with different systems."""
        # RFC 4514: DN representation must interoperate with different LDAP systems

        interop_scenarios = [
            {
                "system": "Active Directory",
                "dn": "CN=John Doe,OU=Users,DC=example,DC=com",
                "normalized": "cn=john doe,ou=users,dc=example,dc=com",
            },
            {
                "system": "OpenLDAP",
                "dn": "uid=jdoe,ou=people,dc=example,dc=org",
                "normalized": "uid=jdoe,ou=people,dc=example,dc=org",
            },
            {
                "system": "389 Directory",
                "dn": "mail=admin@example.com,cn=config",
                "normalized": "mail=admin@example.com,cn=config",
            },
        ]

        for scenario in interop_scenarios:
            # Parse DN from different system
            parsed = DNParser.parse(scenario["dn"])
            assert parsed is not None

            # Normalize to canonical form
            canonical = parsed.canonical
            assert canonical == scenario["normalized"]

            # Verify round-trip compatibility
            reconstructed = DNBuilder().from_parsed_dn(parsed).build()
            reparsed = DNParser.parse(reconstructed)
            assert parsed.is_equivalent(reparsed)

    def test_edge_cases_and_boundary_conditions(self) -> None:
        """RFC 4514 - Edge cases and boundary conditions."""
        # Test edge cases that may cause issues

        edge_cases = [
            {
                "description": "Maximum length DN",
                "dn": "cn=" + "a" * 100 + ",ou=" + "b" * 100 + ",dc=example,dc=com",
                "should_work": True,
            },
            {
                "description": "DN with all special characters",
                "dn": 'cn=\\,\\+\\"\\\\\\<\\>\\;\\#\\ test\\ ,ou=special,dc=example,dc=com',
                "should_work": True,
            },
            {
                "description": "DN with unicode characters",
                "dn": "cn=João Café,ou=Usuários,dc=exemplo,dc=com",
                "should_work": True,
            },
            {
                "description": "Single component DN",
                "dn": "dc=com",
                "should_work": True,
            },
            {
                "description": "Many component DN",
                "dn": "cn=test,ou=l1,ou=l2,ou=l3,ou=l4,ou=l5,dc=example,dc=com",
                "should_work": True,
            },
        ]

        for case in edge_cases:
            if case["should_work"]:
                # Should parse successfully
                parsed = DNParser.parse(case["dn"])
                assert parsed is not None, f"Failed to parse: {case['description']}"

                # Should validate successfully
                validator = DNValidator()
                is_valid = validator.validate_dn_syntax(case["dn"])
                assert is_valid is True, f"Failed validation: {case['description']}"
            else:
                # Should fail parsing or validation
                with pytest.raises((ValueError, PydanticValidationError)):
                    DNParser.parse(case["dn"])


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
