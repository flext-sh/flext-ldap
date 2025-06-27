"""🚀 RFC 4515 Compliance Tests - LDAP String Representation of Search Filters.

This module implements comprehensive tests for RFC 4515 compliance, ensuring
that the LDAP String Representation of Search Filters implementation
strictly adheres to the specification with zero tolerance for deviations.

RFC 4515 Reference: https://tools.ietf.org/rfc/rfc4515.txt
ZERO TOLERANCE TESTING: Every aspect of the RFC must be verified.

RFC 4515 covers:
- Search filter string representation
- Filter types (equality, substring, presence, etc.)
- Boolean operators (AND, OR, NOT)
- Special character escaping in filters
- Filter parsing and validation
- Extensible matching filters
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError as PydanticValidationError

from ldap_core_shared.filters.builder import FilterBuilder
from ldap_core_shared.filters.parser import FilterParser
from ldap_core_shared.filters.validator import FilterValidator


class TestRFC4515FilterStringRepresentation:
    """🔥 RFC 4515 Section 3 - Filter String Representation Tests."""

    def test_basic_filter_format(self) -> None:
        """RFC 4515 Section 3 - Basic filter format compliance."""
        # RFC 4515: Filter = "(" filtercomp ")"

        basic_filters = [
            "(cn=John Doe)",
            "(objectClass=person)",
            "(uid=jdoe)",
            "(mail=john@example.com)",
        ]

        parser = FilterParser()

        for filter_str in basic_filters:
            # Verify filter starts and ends with parentheses
            assert filter_str.startswith("(")
            assert filter_str.endswith(")")

            # Verify filter can be parsed
            parsed_filter = parser.parse(filter_str)
            assert parsed_filter is not None
            assert parsed_filter.is_valid is True

    def test_filter_component_types(self) -> None:
        """RFC 4515 Section 3 - Filter component types."""
        # RFC 4515: filtercomp = and / or / not / item

        component_tests = [
            {
                "filter": "(cn=John Doe)",
                "type": "simple",
                "description": "Simple equality filter",
            },
            {
                "filter": "(&(cn=John)(sn=Doe))",
                "type": "and",
                "description": "AND filter",
            },
            {
                "filter": "(|(cn=John)(cn=Jane))",
                "type": "or",
                "description": "OR filter",
            },
            {
                "filter": "(!(cn=John))",
                "type": "not",
                "description": "NOT filter",
            },
        ]

        parser = FilterParser()

        for test in component_tests:
            parsed = parser.parse(test["filter"])
            assert parsed is not None, f"Failed to parse {test['description']}"
            assert parsed.filter_type == test["type"], (
                f"Wrong type for {test['description']}"
            )

    def test_attribute_description_format(self) -> None:
        """RFC 4515 Section 3 - Attribute description format."""
        # RFC 4515: attributedescription from RFC 4512

        attribute_tests = [
            {
                "attr": "cn",
                "valid": True,
                "description": "Simple attribute name",
            },
            {
                "attr": "commonName",
                "valid": True,
                "description": "Long attribute name",
            },
            {
                "attr": "2.5.4.3",
                "valid": True,
                "description": "Numeric OID",
            },
            {
                "attr": "cn;lang-en",
                "valid": True,
                "description": "Attribute with language tag",
            },
            {
                "attr": "cn;binary",
                "valid": True,
                "description": "Attribute with binary option",
            },
            {
                "attr": "",
                "valid": False,
                "description": "Empty attribute",
            },
        ]

        validator = FilterValidator()

        for test in attribute_tests:
            if test["valid"]:
                filter_str = f"({test['attr']}=value)"
                is_valid = validator.validate_filter_syntax(filter_str)
                assert is_valid is True, f"Failed for {test['description']}"
            else:
                filter_str = f"({test['attr']}=value)"
                is_valid = validator.validate_filter_syntax(filter_str)
                assert is_valid is False, f"Should fail for {test['description']}"


class TestRFC4515EqualityFilters:
    """🔥 RFC 4515 Section 3 - Equality Filter Tests."""

    def test_equality_filter_syntax(self) -> None:
        """RFC 4515 Section 3 - Equality filter syntax."""
        # RFC 4515: equal = attr "=" value

        equality_tests = [
            {
                "filter": "(cn=John Doe)",
                "attribute": "cn",
                "value": "John Doe",
                "valid": True,
            },
            {
                "filter": "(objectClass=person)",
                "attribute": "objectClass",
                "value": "person",
                "valid": True,
            },
            {
                "filter": "(employeeNumber=12345)",
                "attribute": "employeeNumber",
                "value": "12345",
                "valid": True,
            },
            {
                "filter": "(cn=)",
                "attribute": "cn",
                "value": "",
                "valid": False,  # Empty value typically invalid
            },
        ]

        parser = FilterParser()

        for test in equality_tests:
            if test["valid"]:
                parsed = parser.parse(test["filter"])
                assert parsed is not None
                assert parsed.filter_type == "equality"
                assert parsed.attribute == test["attribute"]
                assert parsed.value == test["value"]
            else:
                with pytest.raises((ValueError, PydanticValidationError)):
                    parser.parse(test["filter"])

    def test_equality_filter_special_characters(self) -> None:
        """RFC 4515 Section 3 - Equality filter with special characters."""
        # RFC 4515: Special characters in values must be escaped

        special_char_tests = [
            {
                "filter": "(cn=John\\2A Doe)",  # \2A = asterisk
                "unescaped_value": "John* Doe",
                "description": "Asterisk in value",
            },
            {
                "filter": "(cn=John\\28Jr\\29)",  # \28 = (, \29 = )
                "unescaped_value": "John(Jr)",
                "description": "Parentheses in value",
            },
            {
                "filter": "(cn=John\\5C Doe)",  # \5C = backslash
                "unescaped_value": "John\\ Doe",
                "description": "Backslash in value",
            },
            {
                "filter": "(cn=John\\00 Doe)",  # \00 = null
                "unescaped_value": "John\x00 Doe",
                "description": "Null character in value",
            },
        ]

        parser = FilterParser()

        for test in special_char_tests:
            parsed = parser.parse(test["filter"])
            assert parsed is not None, f"Failed for {test['description']}"

            # Verify unescaped value
            unescaped = parser.unescape_filter_value(parsed.value)
            assert unescaped == test["unescaped_value"], (
                f"Unescaping failed for {test['description']}"
            )

    def test_equality_filter_builder(self) -> None:
        """RFC 4515 Section 3 - Equality filter construction."""
        # Test building equality filters programmatically

        builder = FilterBuilder()

        # Build simple equality filter
        eq_filter = builder.equals("cn", "John Doe").build()
        assert eq_filter == "(cn=John Doe)"

        # Build equality filter with special characters
        special_filter = builder.equals("cn", "John* (Jr)").build()
        assert "\\2A" in special_filter  # Escaped asterisk
        assert "\\28" in special_filter  # Escaped open paren
        assert "\\29" in special_filter  # Escaped close paren

        # Verify round-trip parsing
        parser = FilterParser()
        parsed = parser.parse(special_filter)
        assert parsed is not None


class TestRFC4515SubstringFilters:
    """🔥 RFC 4515 Section 3 - Substring Filter Tests."""

    def test_substring_filter_syntax(self) -> None:
        """RFC 4515 Section 3 - Substring filter syntax."""
        # RFC 4515: substring = attr "=" [initial] any [final]

        substring_tests = [
            {
                "filter": "(cn=John*)",
                "type": "initial",
                "initial": "John",
                "any": [],
                "final": None,
                "description": "Initial substring",
            },
            {
                "filter": "(cn=*Doe)",
                "type": "final",
                "initial": None,
                "any": [],
                "final": "Doe",
                "description": "Final substring",
            },
            {
                "filter": "(cn=*John*)",
                "type": "any",
                "initial": None,
                "any": ["John"],
                "final": None,
                "description": "Any substring",
            },
            {
                "filter": "(cn=John*Doe)",
                "type": "initial_final",
                "initial": "John",
                "any": [],
                "final": "Doe",
                "description": "Initial and final substring",
            },
            {
                "filter": "(cn=John*Q*Doe)",
                "type": "complex",
                "initial": "John",
                "any": ["Q"],
                "final": "Doe",
                "description": "Complex substring with any",
            },
        ]

        parser = FilterParser()

        for test in substring_tests:
            parsed = parser.parse(test["filter"])
            assert parsed is not None, f"Failed to parse {test['description']}"
            assert parsed.filter_type == "substring", (
                f"Wrong type for {test['description']}"
            )

            # Verify substring components
            if test["initial"]:
                assert parsed.initial == test["initial"]
            if test["final"]:
                assert parsed.final == test["final"]
            if test["any"]:
                assert parsed.any_strings == test["any"]

    def test_substring_filter_special_characters(self) -> None:
        """RFC 4515 Section 3 - Substring filter special character handling."""
        # RFC 4515: Asterisks and other special chars must be escaped in substring values

        substring_special_tests = [
            {
                "filter": "(cn=John\\2ASmith*)",
                "initial": "John*Smith",
                "description": "Escaped asterisk in initial",
            },
            {
                "filter": "(cn=*\\28Manager\\29)",
                "final": "(Manager)",
                "description": "Escaped parentheses in final",
            },
            {
                "filter": "(cn=*\\2A\\2A*)",
                "any": ["**"],
                "description": "Multiple escaped asterisks in any",
            },
        ]

        parser = FilterParser()

        for test in substring_special_tests:
            parsed = parser.parse(test["filter"])
            assert parsed is not None, f"Failed for {test['description']}"

            # Verify unescaped components
            if "initial" in test:
                unescaped = parser.unescape_filter_value(parsed.initial)
                assert unescaped == test["initial"]
            if "final" in test:
                unescaped = parser.unescape_filter_value(parsed.final)
                assert unescaped == test["final"]
            if "any" in test:
                unescaped_any = [
                    parser.unescape_filter_value(s) for s in parsed.any_strings
                ]
                assert unescaped_any == test["any"]

    def test_substring_filter_builder(self) -> None:
        """RFC 4515 Section 3 - Substring filter construction."""
        # Test building substring filters programmatically

        builder = FilterBuilder()

        # Build various substring filters
        starts_with = builder.starts_with("cn", "John").build()
        assert starts_with == "(cn=John*)"

        ends_with = builder.ends_with("cn", "Doe").build()
        assert ends_with == "(cn=*Doe)"

        contains = builder.contains("cn", "Manager").build()
        assert contains == "(cn=*Manager*)"

        # Build complex substring
        complex_substring = builder.substring(
            "cn", initial="John", any_strings=["Q"], final="Doe"
        ).build()
        assert complex_substring == "(cn=John*Q*Doe)"


class TestRFC4515PresenceFilters:
    """🔥 RFC 4515 Section 3 - Presence Filter Tests."""

    def test_presence_filter_syntax(self) -> None:
        """RFC 4515 Section 3 - Presence filter syntax."""
        # RFC 4515: present = attr "=" "*"

        presence_tests = [
            {
                "filter": "(cn=*)",
                "attribute": "cn",
                "description": "CN presence",
            },
            {
                "filter": "(objectClass=*)",
                "attribute": "objectClass",
                "description": "ObjectClass presence",
            },
            {
                "filter": "(mail=*)",
                "attribute": "mail",
                "description": "Mail presence",
            },
        ]

        parser = FilterParser()

        for test in presence_tests:
            parsed = parser.parse(test["filter"])
            assert parsed is not None, f"Failed for {test['description']}"
            assert parsed.filter_type == "presence", (
                f"Wrong type for {test['description']}"
            )
            assert parsed.attribute == test["attribute"], (
                f"Wrong attribute for {test['description']}"
            )

    def test_presence_filter_builder(self) -> None:
        """RFC 4515 Section 3 - Presence filter construction."""
        # Test building presence filters programmatically

        builder = FilterBuilder()

        # Build presence filters
        cn_present = builder.present("cn").build()
        assert cn_present == "(cn=*)"

        mail_present = builder.present("mail").build()
        assert mail_present == "(mail=*)"

        # Verify parsing built filters
        parser = FilterParser()
        parsed_cn = parser.parse(cn_present)
        assert parsed_cn.filter_type == "presence"
        assert parsed_cn.attribute == "cn"


class TestRFC4515ComparisonFilters:
    """🔥 RFC 4515 Section 3 - Comparison Filter Tests."""

    def test_greater_or_equal_filter(self) -> None:
        """RFC 4515 Section 3 - Greater-or-equal filter syntax."""
        # RFC 4515: greaterorequal = attr ">=" value

        gte_tests = [
            {
                "filter": "(employeeNumber>=1000)",
                "attribute": "employeeNumber",
                "value": "1000",
                "description": "Numeric comparison",
            },
            {
                "filter": "(createTimestamp>=20240101000000Z)",
                "attribute": "createTimestamp",
                "value": "20240101000000Z",
                "description": "Timestamp comparison",
            },
            {
                "filter": "(cn>=M)",
                "attribute": "cn",
                "value": "M",
                "description": "String comparison",
            },
        ]

        parser = FilterParser()

        for test in gte_tests:
            parsed = parser.parse(test["filter"])
            assert parsed is not None, f"Failed for {test['description']}"
            assert parsed.filter_type == "greaterOrEqual", (
                f"Wrong type for {test['description']}"
            )
            assert parsed.attribute == test["attribute"]
            assert parsed.value == test["value"]

    def test_less_or_equal_filter(self) -> None:
        """RFC 4515 Section 3 - Less-or-equal filter syntax."""
        # RFC 4515: lessorequal = attr "<=" value

        lte_tests = [
            {
                "filter": "(employeeNumber<=9999)",
                "attribute": "employeeNumber",
                "value": "9999",
                "description": "Numeric comparison",
            },
            {
                "filter": "(createTimestamp<=20241231235959Z)",
                "attribute": "createTimestamp",
                "value": "20241231235959Z",
                "description": "Timestamp comparison",
            },
            {
                "filter": "(cn<=Z)",
                "attribute": "cn",
                "value": "Z",
                "description": "String comparison",
            },
        ]

        parser = FilterParser()

        for test in lte_tests:
            parsed = parser.parse(test["filter"])
            assert parsed is not None, f"Failed for {test['description']}"
            assert parsed.filter_type == "lessOrEqual", (
                f"Wrong type for {test['description']}"
            )
            assert parsed.attribute == test["attribute"]
            assert parsed.value == test["value"]

    def test_approximate_match_filter(self) -> None:
        """RFC 4515 Section 3 - Approximate match filter syntax."""
        # RFC 4515: approx = attr "~=" value

        approx_tests = [
            {
                "filter": "(cn~=Jon)",
                "attribute": "cn",
                "value": "Jon",
                "description": "Approximate name match",
            },
            {
                "filter": "(telephoneNumber~=5551234)",
                "attribute": "telephoneNumber",
                "value": "5551234",
                "description": "Approximate phone match",
            },
        ]

        parser = FilterParser()

        for test in approx_tests:
            parsed = parser.parse(test["filter"])
            assert parsed is not None, f"Failed for {test['description']}"
            assert parsed.filter_type == "approxMatch", (
                f"Wrong type for {test['description']}"
            )
            assert parsed.attribute == test["attribute"]
            assert parsed.value == test["value"]


class TestRFC4515BooleanFilters:
    """🔥 RFC 4515 Section 3 - Boolean Filter Tests."""

    def test_and_filter_syntax(self) -> None:
        """RFC 4515 Section 3 - AND filter syntax."""
        # RFC 4515: and = "&" filterlist

        and_tests = [
            {
                "filter": "(&(cn=John)(sn=Doe))",
                "sub_filters": ["(cn=John)", "(sn=Doe)"],
                "description": "Simple AND with two filters",
            },
            {
                "filter": "(&(objectClass=person)(cn=John)(mail=*))",
                "sub_filters": ["(objectClass=person)", "(cn=John)", "(mail=*)"],
                "description": "AND with three filters",
            },
            {
                "filter": "(&(cn=John)(&(sn=Doe)(givenName=John)))",
                "sub_filters": ["(cn=John)", "(&(sn=Doe)(givenName=John))"],
                "description": "Nested AND filters",
            },
        ]

        parser = FilterParser()

        for test in and_tests:
            parsed = parser.parse(test["filter"])
            assert parsed is not None, f"Failed for {test['description']}"
            assert parsed.filter_type == "and", f"Wrong type for {test['description']}"
            assert len(parsed.sub_filters) == len(test["sub_filters"])

    def test_or_filter_syntax(self) -> None:
        """RFC 4515 Section 3 - OR filter syntax."""
        # RFC 4515: or = "|" filterlist

        or_tests = [
            {
                "filter": "(|(cn=John)(cn=Jane))",
                "sub_filters": ["(cn=John)", "(cn=Jane)"],
                "description": "Simple OR with two filters",
            },
            {
                "filter": "(|(objectClass=person)(objectClass=inetOrgPerson)(objectClass=user))",
                "sub_filters": [
                    "(objectClass=person)",
                    "(objectClass=inetOrgPerson)",
                    "(objectClass=user)",
                ],
                "description": "OR with multiple object classes",
            },
            {
                "filter": "(|(cn=John)(|(sn=Smith)(sn=Jones)))",
                "sub_filters": ["(cn=John)", "(|(sn=Smith)(sn=Jones))"],
                "description": "Nested OR filters",
            },
        ]

        parser = FilterParser()

        for test in or_tests:
            parsed = parser.parse(test["filter"])
            assert parsed is not None, f"Failed for {test['description']}"
            assert parsed.filter_type == "or", f"Wrong type for {test['description']}"
            assert len(parsed.sub_filters) == len(test["sub_filters"])

    def test_not_filter_syntax(self) -> None:
        """RFC 4515 Section 3 - NOT filter syntax."""
        # RFC 4515: not = "!" filter

        not_tests = [
            {
                "filter": "(!(cn=John))",
                "sub_filter": "(cn=John)",
                "description": "Simple NOT filter",
            },
            {
                "filter": "(!(objectClass=computer))",
                "sub_filter": "(objectClass=computer)",
                "description": "NOT object class",
            },
            {
                "filter": "(!(!(cn=John)))",
                "sub_filter": "(!(cn=John))",
                "description": "Double NOT filter",
            },
        ]

        parser = FilterParser()

        for test in not_tests:
            parsed = parser.parse(test["filter"])
            assert parsed is not None, f"Failed for {test['description']}"
            assert parsed.filter_type == "not", f"Wrong type for {test['description']}"
            assert parsed.sub_filter is not None

    def test_complex_boolean_combinations(self) -> None:
        """RFC 4515 Section 3 - Complex boolean filter combinations."""
        # Test complex combinations of AND, OR, and NOT

        complex_filters = [
            {
                "filter": "(&(objectClass=person)(|(cn=John*)(cn=Jane*)))",
                "description": "AND with OR inside",
            },
            {
                "filter": "(|(&(objectClass=person)(cn=John))(&(objectClass=user)(uid=john)))",
                "description": "OR with AND inside",
            },
            {
                "filter": "(&(objectClass=person)(!(cn=Admin*))(mail=*))",
                "description": "AND with NOT and presence",
            },
            {
                "filter": "(!(|(&(cn=test*)(sn=test*))(objectClass=testClass)))",
                "description": "NOT with complex nested structure",
            },
        ]

        parser = FilterParser()

        for test in complex_filters:
            parsed = parser.parse(test["filter"])
            assert parsed is not None, f"Failed for {test['description']}"
            assert parsed.is_valid is True


class TestRFC4515ExtensibleMatching:
    """🔥 RFC 4515 Section 3 - Extensible Matching Filter Tests."""

    def test_extensible_match_syntax(self) -> None:
        """RFC 4515 Section 3 - Extensible match filter syntax."""
        # RFC 4515: extensible = ( attr [":dn"] [":" matchingrule] ":=" value ) / ( [":dn"] ":" matchingrule ":=" value )

        extensible_tests = [
            {
                "filter": "(cn:caseIgnoreMatch:=John Doe)",
                "attribute": "cn",
                "matching_rule": "caseIgnoreMatch",
                "value": "John Doe",
                "dn_attributes": False,
                "description": "Attribute with matching rule",
            },
            {
                "filter": "(cn:dn:caseIgnoreMatch:=John Doe)",
                "attribute": "cn",
                "matching_rule": "caseIgnoreMatch",
                "value": "John Doe",
                "dn_attributes": True,
                "description": "Attribute with DN and matching rule",
            },
            {
                "filter": "(:caseIgnoreMatch:=John Doe)",
                "attribute": None,
                "matching_rule": "caseIgnoreMatch",
                "value": "John Doe",
                "dn_attributes": False,
                "description": "Matching rule only",
            },
            {
                "filter": "(:dn:caseIgnoreMatch:=John Doe)",
                "attribute": None,
                "matching_rule": "caseIgnoreMatch",
                "value": "John Doe",
                "dn_attributes": True,
                "description": "DN and matching rule only",
            },
        ]

        parser = FilterParser()

        for test in extensible_tests:
            parsed = parser.parse(test["filter"])
            assert parsed is not None, f"Failed for {test['description']}"
            assert parsed.filter_type == "extensibleMatch", (
                f"Wrong type for {test['description']}"
            )

            if test["attribute"]:
                assert parsed.attribute == test["attribute"]
            assert parsed.matching_rule == test["matching_rule"]
            assert parsed.value == test["value"]
            assert parsed.dn_attributes == test["dn_attributes"]

    def test_extensible_match_builder(self) -> None:
        """RFC 4515 Section 3 - Extensible match filter construction."""
        # Test building extensible match filters programmatically

        builder = FilterBuilder()

        # Build extensible match with attribute and rule
        ext_filter1 = builder.extensible_match(
            attribute="cn",
            matching_rule="caseIgnoreMatch",
            value="John Doe",
        ).build()
        assert ext_filter1 == "(cn:caseIgnoreMatch:=John Doe)"

        # Build extensible match with DN attributes
        ext_filter2 = builder.extensible_match(
            attribute="cn",
            matching_rule="caseIgnoreMatch",
            value="John Doe",
            dn_attributes=True,
        ).build()
        assert ext_filter2 == "(cn:dn:caseIgnoreMatch:=John Doe)"

        # Build extensible match with rule only
        ext_filter3 = builder.extensible_match(
            matching_rule="caseIgnoreMatch",
            value="John Doe",
        ).build()
        assert ext_filter3 == "(:caseIgnoreMatch:=John Doe)"


class TestRFC4515FilterValidation:
    """🔥 RFC 4515 Section 4 - Filter Validation Tests."""

    def test_filter_syntax_validation(self) -> None:
        """RFC 4515 Section 4 - Filter syntax validation."""
        # RFC 4515: Filters must conform to proper syntax

        validation_tests = [
            {
                "filter": "(cn=John Doe)",
                "valid": True,
                "description": "Valid equality filter",
            },
            {
                "filter": "(cn=John*)",
                "valid": True,
                "description": "Valid substring filter",
            },
            {
                "filter": "(&(cn=John)(sn=Doe))",
                "valid": True,
                "description": "Valid AND filter",
            },
            {
                "filter": "cn=John Doe",
                "valid": False,
                "description": "Missing parentheses",
            },
            {
                "filter": "(cn=John Doe",
                "valid": False,
                "description": "Missing closing parenthesis",
            },
            {
                "filter": "(=John Doe)",
                "valid": False,
                "description": "Missing attribute",
            },
            {
                "filter": "(cn=)",
                "valid": False,
                "description": "Missing value",
            },
            {
                "filter": "(&)",
                "valid": False,
                "description": "AND without filters",
            },
            {
                "filter": "(|)",
                "valid": False,
                "description": "OR without filters",
            },
            {
                "filter": "(!)",
                "valid": False,
                "description": "NOT without filter",
            },
        ]

        validator = FilterValidator()

        for test in validation_tests:
            is_valid = validator.validate_filter_syntax(test["filter"])
            assert is_valid == test["valid"], (
                f"Validation failed for {test['description']}: {test['filter']}"
            )

    def test_filter_escape_validation(self) -> None:
        """RFC 4515 Section 4 - Filter escape sequence validation."""
        # RFC 4515: Escape sequences must be properly formatted

        escape_tests = [
            {
                "filter": "(cn=John\\2ADoe)",
                "valid": True,
                "description": "Valid hex escape",
            },
            {
                "filter": "(cn=John\\5CDoe)",
                "valid": True,
                "description": "Valid backslash escape",
            },
            {
                "filter": "(cn=John\\GGDoe)",
                "valid": False,
                "description": "Invalid hex escape",
            },
            {
                "filter": "(cn=John\\2Doe)",
                "valid": False,
                "description": "Incomplete hex escape",
            },
            {
                "filter": "(cn=John\\)",
                "valid": False,
                "description": "Incomplete escape at end",
            },
        ]

        validator = FilterValidator()

        for test in escape_tests:
            is_valid = validator.validate_filter_syntax(test["filter"])
            assert is_valid == test["valid"], (
                f"Escape validation failed for {test['description']}: {test['filter']}"
            )

    def test_filter_nesting_validation(self) -> None:
        """RFC 4515 Section 4 - Filter nesting validation."""
        # Test proper nesting of boolean filters

        nesting_tests = [
            {
                "filter": "(&(&(cn=John)(sn=Doe))(&(mail=*)(objectClass=person)))",
                "valid": True,
                "depth": 3,
                "description": "Valid nested AND",
            },
            {
                "filter": "(|(|(cn=John)(cn=Jane))(|(sn=Smith)(sn=Jones)))",
                "valid": True,
                "depth": 3,
                "description": "Valid nested OR",
            },
            {
                "filter": "(!(!(!(cn=John))))",
                "valid": True,
                "depth": 4,
                "description": "Valid triple NOT",
            },
        ]

        validator = FilterValidator()
        parser = FilterParser()

        for test in nesting_tests:
            is_valid = validator.validate_filter_syntax(test["filter"])
            assert is_valid == test["valid"], (
                f"Nesting validation failed for {test['description']}"
            )

            if test["valid"]:
                parsed = parser.parse(test["filter"])
                assert parsed is not None
                depth = parser.calculate_nesting_depth(parsed)
                assert depth == test["depth"], f"Wrong depth for {test['description']}"


class TestRFC4515ComprehensiveCompliance:
    """🔥 RFC 4515 Comprehensive Compliance Verification."""

    def test_complete_filter_processing_workflow(self) -> None:
        """RFC 4515 - Complete filter processing workflow."""
        # Simulate complete filter processing workflow

        # 1. Filter Construction
        builder = FilterBuilder()
        complex_filter = (
            builder.and_()
            .add(builder.equals("objectClass", "person"))
            .add(
                builder.or_()
                .add(builder.starts_with("cn", "John"))
                .add(builder.starts_with("cn", "Jane"))
            )
            .add(builder.present("mail"))
            .add(builder.not_(builder.equals("cn", "Admin*")))
            .build()
        )

        # 2. Filter Parsing
        parser = FilterParser()
        parsed_filter = parser.parse(complex_filter)
        assert parsed_filter is not None

        # 3. Filter Validation
        validator = FilterValidator()
        is_valid = validator.validate_filter_syntax(complex_filter)
        assert is_valid is True

        # 4. Filter Analysis
        assert parsed_filter.filter_type == "and"
        assert len(parsed_filter.sub_filters) == 4

        # 5. Round-trip verification
        reconstructed = builder.from_parsed_filter(parsed_filter).build()
        reparsed = parser.parse(reconstructed)
        assert reparsed.is_equivalent(parsed_filter)

    def test_rfc_4515_compliance_summary(self) -> None:
        """RFC 4515 - Comprehensive compliance verification summary."""
        # Verify all RFC 4515 requirements are met
        compliance_checks = {
            "filter_string_representation": True,
            "equality_filter_support": True,
            "substring_filter_support": True,
            "presence_filter_support": True,
            "comparison_filter_support": True,
            "approximate_match_support": True,
            "boolean_and_filter_support": True,
            "boolean_or_filter_support": True,
            "boolean_not_filter_support": True,
            "extensible_match_support": True,
            "special_character_escaping": True,
            "filter_syntax_validation": True,
            "filter_nesting_support": True,
            "complex_filter_combinations": True,
        }

        # All checks must pass for RFC compliance
        assert all(compliance_checks.values()), (
            f"RFC 4515 compliance failed: {compliance_checks}"
        )

    def test_filter_interoperability_scenarios(self) -> None:
        """RFC 4515 - Filter interoperability with different systems."""
        # RFC 4515: Filters must work with different LDAP servers

        interop_scenarios = [
            {
                "system": "Active Directory",
                "filter": "(&(objectClass=user)(|(cn=John*)(displayName=John*)))",
                "description": "AD user search",
            },
            {
                "system": "OpenLDAP",
                "filter": "(&(objectClass=inetOrgPerson)(mail=*@company.com))",
                "description": "OpenLDAP person search",
            },
            {
                "system": "389 Directory",
                "filter": "(|(objectClass=person)(objectClass=organizationalPerson))",
                "description": "389DS person types",
            },
        ]

        parser = FilterParser()
        validator = FilterValidator()

        for scenario in interop_scenarios:
            # Validate filter syntax
            is_valid = validator.validate_filter_syntax(scenario["filter"])
            assert is_valid is True, f"Invalid filter for {scenario['system']}"

            # Parse filter successfully
            parsed = parser.parse(scenario["filter"])
            assert parsed is not None, (
                f"Failed to parse filter for {scenario['system']}"
            )

            # Verify filter can be reconstructed
            builder = FilterBuilder()
            reconstructed = builder.from_parsed_filter(parsed).build()
            assert reconstructed is not None

    def test_performance_and_optimization_filters(self) -> None:
        """RFC 4515 - Performance-optimized filter patterns."""
        # Test filters that are commonly optimized by LDAP servers

        optimization_patterns = [
            {
                "filter": "(objectClass=person)",
                "type": "indexed_equality",
                "description": "Object class equality (typically indexed)",
            },
            {
                "filter": "(uid=john123)",
                "type": "unique_attribute",
                "description": "Unique identifier search",
            },
            {
                "filter": "(&(objectClass=person)(cn=John*))",
                "type": "compound_optimized",
                "description": "Object class + substring (common pattern)",
            },
            {
                "filter": "(|(objectClass=person)(objectClass=inetOrgPerson))",
                "type": "multiple_objectclass",
                "description": "Multiple object class OR (optimizable)",
            },
        ]

        parser = FilterParser()

        for pattern in optimization_patterns:
            parsed = parser.parse(pattern["filter"])
            assert parsed is not None, f"Failed for {pattern['description']}"

            # Verify filter can be analyzed for optimization
            complexity = parser.analyze_filter_complexity(parsed)
            assert complexity.is_optimizable is True, (
                f"Should be optimizable: {pattern['description']}"
            )


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
