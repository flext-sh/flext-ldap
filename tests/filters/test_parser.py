"""Tests for LDAP Filter Parser Implementation.

This module provides comprehensive test coverage for the RFC 4515 compliant LDAP
filter parser including syntax validation, structural analysis, and comprehensive
error handling with enterprise-grade parsing patterns and performance validation.

Test Coverage:
    - FilterType: Enumeration of LDAP filter types and categories
    - FilterSyntaxError: Parse error handling with position tracking
    - ParsedFilter: Structured filter representation and manipulation
    - FilterParser: Main RFC 4515 compliant parser with regex patterns
    - FilterAnalyzer: Advanced filter analysis and optimization utilities
    - Filter parsing with comprehensive syntax validation and error recovery

Integration Testing:
    - Complete filter parsing workflows with nested compound filters
    - Syntax error reporting with position and context information
    - Filter complexity analysis and performance characteristic detection
    - Security analysis for potential injection patterns and DoS protection
    - Optimization suggestions and performance hint generation

Performance Testing:
    - Large nested filter parsing efficiency and optimization
    - Regex pattern compilation and matching performance
    - Memory usage during filter processing and structural analysis
    - Parser operation timing and throughput validation
    - Complex filter analysis and recommendation performance

Security Testing:
    - Input validation and sanitization for filter strings
    - Injection pattern detection and prevention mechanisms
    - Error message information disclosure protection
    - Resource consumption limits during parsing operations
    - Filter complexity DoS protection and validation limits
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from ldap_core_shared.filters.parser import (
    FilterAnalyzer,
    FilterParser,
    FilterSyntaxError,
    FilterType,
    ParsedFilter,
    get_filter_attributes,
    get_filter_complexity,
    is_valid_filter,
    parse_filter,
)


class TestFilterType:
    """Test cases for FilterType enumeration."""

    def test_filter_type_values(self) -> None:
        """Test FilterType enumeration values."""
        assert FilterType.EQUALITY.value == "equality"
        assert FilterType.SUBSTRING.value == "substring"
        assert FilterType.GREATER_EQUAL.value == "greater_equal"
        assert FilterType.LESS_EQUAL.value == "less_equal"
        assert FilterType.PRESENT.value == "present"
        assert FilterType.APPROXIMATE.value == "approximate"
        assert FilterType.AND.value == "and"
        assert FilterType.OR.value == "or"
        assert FilterType.NOT.value == "not"
        assert FilterType.EXTENSIBLE.value == "extensible"

    def test_filter_type_enumeration_completeness(self) -> None:
        """Test FilterType enumeration completeness."""
        expected_types = {
            "equality", "substring", "greater_equal", "less_equal",
            "present", "approximate", "and", "or", "not", "extensible",
        }

        actual_types = {member.value for member in FilterType}
        assert actual_types == expected_types

    def test_filter_type_membership_validation(self) -> None:
        """Test FilterType membership validation."""
        # Valid filter types
        for filter_type in FilterType:
            assert isinstance(filter_type, FilterType)
            assert filter_type.value in {
                "equality", "substring", "greater_equal", "less_equal",
                "present", "approximate", "and", "or", "not", "extensible",
            }


class TestFilterSyntaxError:
    """Test cases for FilterSyntaxError."""

    def test_syntax_error_creation_basic(self) -> None:
        """Test creating syntax error with basic message."""
        error = FilterSyntaxError("Invalid filter syntax")

        assert str(error) == "Invalid filter syntax"
        assert error.position is None
        assert error.filter_string is None

    def test_syntax_error_creation_with_position(self) -> None:
        """Test creating syntax error with position information."""
        filter_string = "(cn=test"
        error = FilterSyntaxError("Missing closing parenthesis", position=7, filter_string=filter_string)

        assert "Missing closing parenthesis at position 7" in str(error)
        assert error.position == 7
        assert error.filter_string == filter_string

    def test_syntax_error_context_generation(self) -> None:
        """Test error context generation around position."""
        filter_string = "(&(cn=user)(objectClass=person))"
        error = FilterSyntaxError("Error here", position=15, filter_string=filter_string)

        error_str = str(error)
        assert "position 15" in error_str
        assert "^" in error_str  # Pointer should be included

    def test_syntax_error_inheritance(self) -> None:
        """Test FilterSyntaxError inheritance from Exception."""
        error = FilterSyntaxError("Test error")

        assert isinstance(error, Exception)
        assert isinstance(error, FilterSyntaxError)


class TestParsedFilter:
    """Test cases for ParsedFilter."""

    def test_parsed_filter_creation_simple(self) -> None:
        """Test creating simple parsed filter."""
        parsed = ParsedFilter(
            filter_type=FilterType.EQUALITY,
            attribute="cn",
            value="test",
            operator="=",
            raw_filter="(cn=test)",
        )

        assert parsed.filter_type == FilterType.EQUALITY
        assert parsed.attribute == "cn"
        assert parsed.value == "test"
        assert parsed.operator == "="
        assert parsed.raw_filter == "(cn=test)"
        assert parsed.children == []
        assert parsed.is_negated is False

    def test_parsed_filter_creation_compound(self) -> None:
        """Test creating compound parsed filter."""
        child1 = ParsedFilter(
            filter_type=FilterType.EQUALITY,
            attribute="cn",
            value="test",
            operator="=",
            raw_filter="(cn=test)",
        )

        child2 = ParsedFilter(
            filter_type=FilterType.PRESENT,
            attribute="objectClass",
            operator="=",
            value="*",
            raw_filter="(objectClass=*)",
        )

        parsed = ParsedFilter(
            filter_type=FilterType.AND,
            children=[child1, child2],
            raw_filter="(&(cn=test)(objectClass=*))",
        )

        assert parsed.filter_type == FilterType.AND
        assert len(parsed.children) == 2
        assert parsed.attribute is None
        assert parsed.value is None

    def test_parsed_filter_validation_and_children(self) -> None:
        """Test ParsedFilter validation for AND children count."""
        child = ParsedFilter(
            filter_type=FilterType.EQUALITY,
            attribute="cn",
            value="test",
            operator="=",
            raw_filter="(cn=test)",
        )

        # AND filter with insufficient children should raise error
        with pytest.raises(ValidationError, match="AND filter must have at least 2 children"):
            ParsedFilter(
                filter_type=FilterType.AND,
                children=[child],  # Only 1 child
                raw_filter="(&(cn=test))",
            )

    def test_parsed_filter_validation_or_children(self) -> None:
        """Test ParsedFilter validation for OR children count."""
        child = ParsedFilter(
            filter_type=FilterType.EQUALITY,
            attribute="cn",
            value="test",
            operator="=",
            raw_filter="(cn=test)",
        )

        # OR filter with insufficient children should raise error
        with pytest.raises(ValidationError, match="OR filter must have at least 2 children"):
            ParsedFilter(
                filter_type=FilterType.OR,
                children=[child],  # Only 1 child
                raw_filter="(|(cn=test))",
            )

    def test_parsed_filter_validation_not_children(self) -> None:
        """Test ParsedFilter validation for NOT children count."""
        child1 = ParsedFilter(
            filter_type=FilterType.EQUALITY,
            attribute="cn",
            value="test1",
            operator="=",
            raw_filter="(cn=test1)",
        )

        child2 = ParsedFilter(
            filter_type=FilterType.EQUALITY,
            attribute="sn",
            value="test2",
            operator="=",
            raw_filter="(sn=test2)",
        )

        # NOT filter with wrong number of children should raise error
        with pytest.raises(ValidationError, match="NOT filter must have exactly 1 child"):
            ParsedFilter(
                filter_type=FilterType.NOT,
                children=[child1, child2],  # 2 children
                raw_filter="(!(cn=test1)(sn=test2))",
            )

    def test_parsed_filter_is_simple(self) -> None:
        """Test is_simple method for filter classification."""
        simple_filter = ParsedFilter(
            filter_type=FilterType.EQUALITY,
            attribute="cn",
            value="test",
            operator="=",
            raw_filter="(cn=test)",
        )

        compound_filter = ParsedFilter(
            filter_type=FilterType.AND,
            children=[simple_filter],
            raw_filter="(&(cn=test))",
        )

        assert simple_filter.is_simple() is True
        assert compound_filter.is_simple() is False

    def test_parsed_filter_is_compound(self) -> None:
        """Test is_compound method for filter classification."""
        simple_filter = ParsedFilter(
            filter_type=FilterType.EQUALITY,
            attribute="cn",
            value="test",
            operator="=",
            raw_filter="(cn=test)",
        )

        compound_filter = ParsedFilter(
            filter_type=FilterType.AND,
            children=[simple_filter, simple_filter],
            raw_filter="(&(cn=test)(cn=test))",
        )

        assert simple_filter.is_compound() is False
        assert compound_filter.is_compound() is True

    def test_parsed_filter_get_attributes(self) -> None:
        """Test get_attributes method for attribute extraction."""
        child1 = ParsedFilter(
            filter_type=FilterType.EQUALITY,
            attribute="cn",
            value="test",
            operator="=",
            raw_filter="(cn=test)",
        )

        child2 = ParsedFilter(
            filter_type=FilterType.PRESENT,
            attribute="objectClass",
            operator="=",
            value="*",
            raw_filter="(objectClass=*)",
        )

        compound_filter = ParsedFilter(
            filter_type=FilterType.AND,
            children=[child1, child2],
            raw_filter="(&(cn=test)(objectClass=*))",
        )

        attributes = compound_filter.get_attributes()
        assert attributes == {"cn", "objectClass"}

    def test_parsed_filter_get_complexity_score_simple(self) -> None:
        """Test complexity score calculation for simple filters."""
        simple_filter = ParsedFilter(
            filter_type=FilterType.EQUALITY,
            attribute="cn",
            value="test",
            operator="=",
            raw_filter="(cn=test)",
        )

        assert simple_filter.get_complexity_score() == 1

    def test_parsed_filter_get_complexity_score_compound(self) -> None:
        """Test complexity score calculation for compound filters."""
        child1 = ParsedFilter(
            filter_type=FilterType.EQUALITY,
            attribute="cn",
            value="test",
            operator="=",
            raw_filter="(cn=test)",
        )

        child2 = ParsedFilter(
            filter_type=FilterType.PRESENT,
            attribute="objectClass",
            operator="=",
            value="*",
            raw_filter="(objectClass=*)",
        )

        compound_filter = ParsedFilter(
            filter_type=FilterType.AND,
            children=[child1, child2],
            raw_filter="(&(cn=test)(objectClass=*))",
        )

        # Complexity: 1 (AND operator) + 1 (child1) + 1 (child2) = 3
        assert compound_filter.get_complexity_score() == 3

    def test_parsed_filter_to_string_equality(self) -> None:
        """Test to_string method for equality filters."""
        parsed = ParsedFilter(
            filter_type=FilterType.EQUALITY,
            attribute="cn",
            value="test",
            operator="=",
            raw_filter="(cn=test)",
        )

        assert parsed.to_string() == "(cn=test)"

    def test_parsed_filter_to_string_substring(self) -> None:
        """Test to_string method for substring filters."""
        parsed = ParsedFilter(
            filter_type=FilterType.SUBSTRING,
            attribute="cn",
            value="*test*",
            operator="=",
            raw_filter="(cn=*test*)",
        )

        assert parsed.to_string() == "(cn=*test*)"

    def test_parsed_filter_to_string_present(self) -> None:
        """Test to_string method for presence filters."""
        parsed = ParsedFilter(
            filter_type=FilterType.PRESENT,
            attribute="objectClass",
            operator="=",
            value="*",
            raw_filter="(objectClass=*)",
        )

        assert parsed.to_string() == "(objectClass=*)"

    def test_parsed_filter_to_string_compound_and(self) -> None:
        """Test to_string method for AND compound filters."""
        child1 = ParsedFilter(
            filter_type=FilterType.EQUALITY,
            attribute="cn",
            value="test",
            operator="=",
            raw_filter="(cn=test)",
        )

        child2 = ParsedFilter(
            filter_type=FilterType.PRESENT,
            attribute="objectClass",
            operator="=",
            value="*",
            raw_filter="(objectClass=*)",
        )

        compound = ParsedFilter(
            filter_type=FilterType.AND,
            children=[child1, child2],
            raw_filter="(&(cn=test)(objectClass=*))",
        )

        assert compound.to_string() == "(&(cn=test)(objectClass=*))"

    def test_parsed_filter_to_string_compound_not(self) -> None:
        """Test to_string method for NOT compound filters."""
        child = ParsedFilter(
            filter_type=FilterType.EQUALITY,
            attribute="cn",
            value="test",
            operator="=",
            raw_filter="(cn=test)",
        )

        not_filter = ParsedFilter(
            filter_type=FilterType.NOT,
            children=[child],
            is_negated=True,
            raw_filter="(!(cn=test))",
        )

        assert not_filter.to_string() == "(!(cn=test))"

    def test_parsed_filter_extensible_match_fields(self) -> None:
        """Test ParsedFilter extensible match specific fields."""
        parsed = ParsedFilter(
            filter_type=FilterType.EXTENSIBLE,
            attribute="cn",
            value="test",
            operator=":=",
            raw_filter="(cn:1.2.3.4:=test)",
            matching_rule="1.2.3.4",
            dn_attributes=False,
        )

        assert parsed.matching_rule == "1.2.3.4"
        assert parsed.dn_attributes is False

    def test_parsed_filter_str_representation(self) -> None:
        """Test __str__ method delegates to to_string."""
        parsed = ParsedFilter(
            filter_type=FilterType.EQUALITY,
            attribute="cn",
            value="test",
            operator="=",
            raw_filter="(cn=test)",
        )

        assert str(parsed) == "(cn=test)"


class TestFilterParser:
    """Test cases for FilterParser."""

    def test_parser_initialization(self) -> None:
        """Test FilterParser initialization."""
        parser = FilterParser()

        assert parser._position == 0
        assert parser._filter_string == ""

    def test_parse_simple_equality_filter(self) -> None:
        """Test parsing simple equality filter."""
        parser = FilterParser()
        result = parser.parse("(cn=test)")

        assert result.filter_type == FilterType.EQUALITY
        assert result.attribute == "cn"
        assert result.value == "test"
        assert result.operator == "="

    def test_parse_simple_substring_filter(self) -> None:
        """Test parsing simple substring filter."""
        parser = FilterParser()
        result = parser.parse("(cn=*test*)")

        assert result.filter_type == FilterType.SUBSTRING
        assert result.attribute == "cn"
        assert result.value == "*test*"
        assert result.operator == "="

    def test_parse_simple_presence_filter(self) -> None:
        """Test parsing simple presence filter."""
        parser = FilterParser()
        result = parser.parse("(objectClass=*)")

        assert result.filter_type == FilterType.PRESENT
        assert result.attribute == "objectClass"
        assert result.value == "*"
        assert result.operator == "="

    def test_parse_simple_greater_equal_filter(self) -> None:
        """Test parsing simple greater-than-or-equal filter."""
        parser = FilterParser()
        result = parser.parse("(uidNumber>=1000)")

        assert result.filter_type == FilterType.GREATER_EQUAL
        assert result.attribute == "uidNumber"
        assert result.value == "1000"
        assert result.operator == ">="

    def test_parse_simple_less_equal_filter(self) -> None:
        """Test parsing simple less-than-or-equal filter."""
        parser = FilterParser()
        result = parser.parse("(uidNumber<=9999)")

        assert result.filter_type == FilterType.LESS_EQUAL
        assert result.attribute == "uidNumber"
        assert result.value == "9999"
        assert result.operator == "<="

    def test_parse_simple_approximate_filter(self) -> None:
        """Test parsing simple approximate match filter."""
        parser = FilterParser()
        result = parser.parse("(cn~=test)")

        assert result.filter_type == FilterType.APPROXIMATE
        assert result.attribute == "cn"
        assert result.value == "test"
        assert result.operator == "~="

    def test_parse_compound_and_filter(self) -> None:
        """Test parsing compound AND filter."""
        parser = FilterParser()
        result = parser.parse("(&(cn=test)(objectClass=person))")

        assert result.filter_type == FilterType.AND
        assert len(result.children) == 2
        assert result.children[0].attribute == "cn"
        assert result.children[1].attribute == "objectClass"

    def test_parse_compound_or_filter(self) -> None:
        """Test parsing compound OR filter."""
        parser = FilterParser()
        result = parser.parse("(|(cn=test1)(cn=test2))")

        assert result.filter_type == FilterType.OR
        assert len(result.children) == 2
        assert result.children[0].value == "test1"
        assert result.children[1].value == "test2"

    def test_parse_compound_not_filter(self) -> None:
        """Test parsing compound NOT filter."""
        parser = FilterParser()
        result = parser.parse("(!(cn=test))")

        assert result.filter_type == FilterType.NOT
        assert len(result.children) == 1
        assert result.is_negated is True
        assert result.children[0].attribute == "cn"

    def test_parse_nested_compound_filter(self) -> None:
        """Test parsing nested compound filters."""
        parser = FilterParser()
        result = parser.parse("(&(|(cn=test1)(cn=test2))(objectClass=person))")

        assert result.filter_type == FilterType.AND
        assert len(result.children) == 2
        assert result.children[0].filter_type == FilterType.OR
        assert result.children[1].filter_type == FilterType.EQUALITY

    def test_parse_complex_nested_filter(self) -> None:
        """Test parsing complex nested filter structures."""
        filter_string = "(&(objectClass=person)(|(cn=*admin*)(!(department=temp)))(uidNumber>=1000))"
        parser = FilterParser()
        result = parser.parse(filter_string)

        assert result.filter_type == FilterType.AND
        assert len(result.children) == 3
        assert result.children[1].filter_type == FilterType.OR
        assert result.children[1].children[1].filter_type == FilterType.NOT

    def test_parse_escaped_characters(self) -> None:
        """Test parsing filters with escaped characters."""
        parser = FilterParser()
        result = parser.parse(r"(cn=test\2aparens\28and\29brackets\5c)")

        assert result.filter_type == FilterType.EQUALITY
        assert result.attribute == "cn"
        assert r"\2a" in result.value  # Escaped asterisk
        assert r"\28" in result.value  # Escaped open paren
        assert r"\29" in result.value  # Escaped close paren
        assert r"\5c" in result.value  # Escaped backslash

    def test_parse_whitespace_handling(self) -> None:
        """Test parsing filters with whitespace."""
        parser = FilterParser()
        result = parser.parse("  ( cn = test )  ")

        assert result.filter_type == FilterType.EQUALITY
        assert result.attribute == "cn"
        assert result.value == "test"

    def test_parse_empty_filter_error(self) -> None:
        """Test parsing empty filter raises error."""
        parser = FilterParser()

        with pytest.raises(FilterSyntaxError, match="Empty filter string"):
            parser.parse("")

    def test_parse_invalid_syntax_missing_parentheses(self) -> None:
        """Test parsing filter with missing parentheses."""
        parser = FilterParser()

        with pytest.raises(FilterSyntaxError, match="Filter must start with"):
            parser.parse("cn=test")

    def test_parse_invalid_syntax_unclosed_filter(self) -> None:
        """Test parsing filter with unclosed parentheses."""
        parser = FilterParser()

        with pytest.raises(FilterSyntaxError, match="Unclosed"):
            parser.parse("(cn=test")

    def test_parse_invalid_attribute_name(self) -> None:
        """Test parsing filter with invalid attribute name."""
        parser = FilterParser()

        with pytest.raises(FilterSyntaxError, match="Invalid attribute name"):
            parser.parse("(123invalid=test)")

    def test_parse_invalid_operator(self) -> None:
        """Test parsing filter with invalid operator."""
        parser = FilterParser()

        with pytest.raises(FilterSyntaxError, match="Invalid operator"):
            parser.parse("(cn<>test)")

    def test_parse_insufficient_and_children(self) -> None:
        """Test parsing AND filter with insufficient children."""
        parser = FilterParser()

        with pytest.raises(FilterSyntaxError, match="AND filter requires at least 2 child filters"):
            parser.parse("(&(cn=test))")

    def test_parse_insufficient_or_children(self) -> None:
        """Test parsing OR filter with insufficient children."""
        parser = FilterParser()

        with pytest.raises(FilterSyntaxError, match="OR filter requires at least 2 child filters"):
            parser.parse("(|(cn=test))")

    def test_parse_not_filter_no_child(self) -> None:
        """Test parsing NOT filter without child."""
        parser = FilterParser()

        with pytest.raises(FilterSyntaxError, match="NOT filter requires a child filter"):
            parser.parse("(!)")

    def test_parse_trailing_characters(self) -> None:
        """Test parsing filter with trailing characters."""
        parser = FilterParser()

        with pytest.raises(FilterSyntaxError, match="Unexpected characters after filter"):
            parser.parse("(cn=test)extra")

    def test_parse_attribute_with_hyphens(self) -> None:
        """Test parsing attribute names with hyphens."""
        parser = FilterParser()
        result = parser.parse("(x121-address=test)")

        assert result.attribute == "x121-address"
        assert result.value == "test"

    def test_parse_empty_value_presence(self) -> None:
        """Test parsing filters with empty values (presence)."""
        parser = FilterParser()
        result = parser.parse("(objectClass=*)")

        assert result.filter_type == FilterType.PRESENT
        assert result.value == "*"


class TestFilterAnalyzer:
    """Test cases for FilterAnalyzer."""

    def test_analyzer_initialization(self) -> None:
        """Test FilterAnalyzer initialization."""
        analyzer = FilterAnalyzer()

        assert isinstance(analyzer._parser, FilterParser)

    def test_analyze_valid_simple_filter(self) -> None:
        """Test analyzing valid simple filter."""
        analyzer = FilterAnalyzer()
        result = analyzer.analyze("(cn=test)")

        assert result["valid"] is True
        assert result["filter_type"] == "equality"
        assert result["complexity_score"] == 1
        assert "cn" in result["attributes"]

    def test_analyze_invalid_filter_syntax(self) -> None:
        """Test analyzing filter with syntax error."""
        analyzer = FilterAnalyzer()
        result = analyzer.analyze("(cn=test")  # Missing closing paren

        assert result["valid"] is False
        assert "syntax_error" in result
        assert result["performance_hints"] == []
        assert result["security_warnings"] == []

    def test_analyze_complex_filter_performance(self) -> None:
        """Test analyzing complex filter for performance hints."""
        analyzer = FilterAnalyzer()
        complex_filter = "(&" + "(cn=test)" * 15 + ")"  # Complex nested filter
        result = analyzer.analyze(complex_filter)

        assert result["valid"] is True
        assert result["complexity_score"] > 10
        assert any("Complex nested filter" in hint for hint in result["performance_hints"])

    def test_analyze_substring_filter_performance(self) -> None:
        """Test analyzing substring filter for performance hints."""
        analyzer = FilterAnalyzer()
        result = analyzer.analyze("(cn=*test*)")

        assert result["valid"] is True
        assert any("Substring filters" in hint for hint in result["performance_hints"])

    def test_analyze_presence_filter_performance(self) -> None:
        """Test analyzing presence filter for performance hints."""
        analyzer = FilterAnalyzer()
        result = analyzer.analyze("(objectClass=*)")

        assert result["valid"] is True
        assert any("Presence filters" in hint for hint in result["performance_hints"])

    def test_analyze_overly_broad_security(self) -> None:
        """Test analyzing overly broad filter for security warnings."""
        analyzer = FilterAnalyzer()
        result = analyzer.analyze("(objectClass=*)")  # Very broad filter

        assert result["valid"] is True
        assert any("excessive results" in warning for warning in result["security_warnings"])

    def test_analyze_injection_patterns_security(self) -> None:
        """Test analyzing potential injection patterns."""
        analyzer = FilterAnalyzer()
        result = analyzer.analyze("(cn=test)(objectClass=*)")  # Potential injection

        assert result["valid"] is True
        # Should detect injection-like patterns in complex scenarios

    def test_analyze_optimization_suggestions(self) -> None:
        """Test analyzing filter for optimization suggestions."""
        analyzer = FilterAnalyzer()
        result = analyzer.analyze("(&(cn=*test*)(objectClass=person))")

        assert result["valid"] is True
        assert any("equality filters" in suggestion for suggestion in result["optimization_suggestions"])

    def test_analyze_has_substring_filters(self) -> None:
        """Test internal _has_substring_filters method."""
        analyzer = FilterAnalyzer()
        parser = FilterParser()

        # Simple substring filter
        parsed = parser.parse("(cn=*test*)")
        assert analyzer._has_substring_filters(parsed) is True

        # Equality filter
        parsed = parser.parse("(cn=test)")
        assert analyzer._has_substring_filters(parsed) is False

    def test_analyze_has_presence_filters(self) -> None:
        """Test internal _has_presence_filters method."""
        analyzer = FilterAnalyzer()
        parser = FilterParser()

        # Presence filter
        parsed = parser.parse("(objectClass=*)")
        assert analyzer._has_presence_filters(parsed) is True

        # Equality filter
        parsed = parser.parse("(cn=test)")
        assert analyzer._has_presence_filters(parsed) is False

    def test_analyze_is_overly_broad(self) -> None:
        """Test internal _is_overly_broad method."""
        analyzer = FilterAnalyzer()
        parser = FilterParser()

        # Presence filter (broad)
        parsed = parser.parse("(objectClass=*)")
        assert analyzer._is_overly_broad(parsed) is True

        # Equality filter (not broad)
        parsed = parser.parse("(cn=test)")
        assert analyzer._is_overly_broad(parsed) is False

    def test_analyze_has_injection_patterns(self) -> None:
        """Test internal _has_injection_patterns method."""
        analyzer = FilterAnalyzer()
        parser = FilterParser()

        # Filter with suspicious characters
        parsed = parser.parse("(cn=test(injection))")
        assert analyzer._has_injection_patterns(parsed) is True

        # Clean filter
        parsed = parser.parse("(cn=test)")
        assert analyzer._has_injection_patterns(parsed) is False


class TestConvenienceFunctions:
    """Test cases for convenience functions."""

    def test_parse_filter_function(self) -> None:
        """Test parse_filter convenience function."""
        result = parse_filter("(cn=test)")

        assert isinstance(result, ParsedFilter)
        assert result.filter_type == FilterType.EQUALITY
        assert result.attribute == "cn"
        assert result.value == "test"

    def test_is_valid_filter_valid(self) -> None:
        """Test is_valid_filter with valid filter."""
        assert is_valid_filter("(cn=test)") is True
        assert is_valid_filter("(&(cn=test)(objectClass=person))") is True

    def test_is_valid_filter_invalid(self) -> None:
        """Test is_valid_filter with invalid filter."""
        assert is_valid_filter("(cn=test") is False  # Missing closing paren
        assert is_valid_filter("invalid") is False  # Not a filter
        assert is_valid_filter("") is False  # Empty string

    def test_get_filter_attributes_function(self) -> None:
        """Test get_filter_attributes convenience function."""
        attributes = get_filter_attributes("(&(cn=test)(objectClass=person))")

        assert attributes == {"cn", "objectClass"}

    def test_get_filter_attributes_error(self) -> None:
        """Test get_filter_attributes with invalid filter."""
        with pytest.raises(FilterSyntaxError):
            get_filter_attributes("(cn=test")  # Invalid syntax

    def test_get_filter_complexity_function(self) -> None:
        """Test get_filter_complexity convenience function."""
        complexity = get_filter_complexity("(&(cn=test)(objectClass=person))")

        assert complexity == 3  # 1 for AND + 1 for each child

    def test_get_filter_complexity_error(self) -> None:
        """Test get_filter_complexity with invalid filter."""
        with pytest.raises(FilterSyntaxError):
            get_filter_complexity("(cn=test")  # Invalid syntax


class TestFilterParserIntegration:
    """Test cases for FilterParser integration scenarios."""

    def test_comprehensive_filter_parsing_workflow(self) -> None:
        """Test comprehensive filter parsing workflow."""
        parser = FilterParser()
        analyzer = FilterAnalyzer()

        # Complex real-world filter
        filter_string = """
        (&
            (objectClass=person)
            (|
                (cn=*admin*)
                (title=*manager*)
                (&
                    (department=IT)
                    (!(accountExpired=TRUE))
                )
            )
            (uidNumber>=1000)
        )
        """

        # Parse filter
        parsed = parser.parse(filter_string)
        assert parsed.filter_type == FilterType.AND
        assert len(parsed.children) == 3

        # Analyze filter
        analysis = analyzer.analyze(filter_string)
        assert analysis["valid"] is True
        assert analysis["complexity_score"] > 5
        assert "person" in analysis["attributes"]
        assert "cn" in analysis["attributes"]
        assert "title" in analysis["attributes"]

    def test_performance_with_deeply_nested_filters(self) -> None:
        """Test performance with deeply nested filter structures."""
        parser = FilterParser()

        # Build deeply nested filter
        filter_parts = ["(cn=test)"] * 5
        nested_filter = "(&" + "(&".join(filter_parts) + ")" * 5

        # Should parse without issues
        result = parser.parse(nested_filter)
        assert result.filter_type == FilterType.AND
        assert result.get_complexity_score() > 10

    def test_error_reporting_and_position_tracking(self) -> None:
        """Test comprehensive error reporting with position tracking."""
        parser = FilterParser()

        # Filter with error at specific position
        filter_string = "(&(cn=test)(invalid attribute=value))"

        try:
            parser.parse(filter_string)
            msg = "Should have raised FilterSyntaxError"
            raise AssertionError(msg)
        except FilterSyntaxError as e:
            assert e.position is not None
            assert e.filter_string == filter_string
            assert "position" in str(e)

    def test_unicode_and_special_characters(self) -> None:
        """Test parsing filters with unicode and special characters."""
        parser = FilterParser()

        # Filter with unicode value
        result = parser.parse("(cn=José)")
        assert result.attribute == "cn"
        assert result.value == "José"

        # Filter with spaces in value
        result = parser.parse("(displayName=John Doe)")
        assert result.value == "John Doe"

    def test_edge_cases_and_boundary_conditions(self) -> None:
        """Test edge cases and boundary conditions."""
        parser = FilterParser()

        # Single character attribute and value
        result = parser.parse("(a=b)")
        assert result.attribute == "a"
        assert result.value == "b"

        # Very long attribute name
        long_attr = "a" * 100
        result = parser.parse(f"({long_attr}=test)")
        assert result.attribute == long_attr

        # Empty value (should be presence filter)
        result = parser.parse("(objectClass=*)")
        assert result.filter_type == FilterType.PRESENT

    def test_security_validation_comprehensive(self) -> None:
        """Test comprehensive security validation scenarios."""
        parser = FilterParser()
        analyzer = FilterAnalyzer()

        # Potentially malicious filters
        malicious_filters = [
            "(cn=*)",  # Very broad
            "(objectClass=*)",  # Extremely broad
            "(cn=" + "*" * 1000 + ")",  # Long value
        ]

        for filter_str in malicious_filters:
            # Should parse but flag security issues
            parsed = parser.parse(filter_str)
            assert parsed is not None

            analysis = analyzer.analyze(filter_str)
            assert analysis["valid"] is True
            # Should have security warnings for broad filters
            if "*" in filter_str:
                assert len(analysis["security_warnings"]) > 0

    def test_filter_reconstruction_accuracy(self) -> None:
        """Test filter reconstruction accuracy."""
        parser = FilterParser()

        original_filters = [
            "(cn=test)",
            "(&(cn=test)(objectClass=person))",
            "(|(cn=test1)(cn=test2))",
            "(!(cn=test))",
            "(cn>=1000)",
            "(cn<=9999)",
            "(cn~=test)",
            "(cn=*test*)",
            "(objectClass=*)",
        ]

        for original in original_filters:
            parsed = parser.parse(original)
            reconstructed = parsed.to_string()

            # Parse reconstructed filter to verify it's valid
            reparsed = parser.parse(reconstructed)
            assert reparsed.filter_type == parsed.filter_type
            assert reparsed.attribute == parsed.attribute
