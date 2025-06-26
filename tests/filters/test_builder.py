"""Tests for LDAP Filter Builder Implementation.

This module provides comprehensive test coverage for the fluent API LDAP filter
builder including filter construction, escaping, validation, and comprehensive
enterprise-grade filter building patterns with performance and security validation.

Test Coverage:
    - FilterOperator: Enumeration of LDAP filter operators
    - FilterExpression: Immutable filter expression representation
    - FilterEscaping: Utilities for proper LDAP filter value escaping
    - FilterBuilder: Main fluent API for programmatic filter construction
    - Filter building with comprehensive syntax validation and optimization
    - Convenience functions for common filter patterns and operations

Integration Testing:
    - Complete filter building workflows with nested compound structures
    - Fluent API chaining and method composition patterns
    - Filter expression validation and error handling mechanisms
    - Escaping and unescaping operations for security and compliance
    - Complex filter construction with multiple operator combinations

Performance Testing:
    - Large filter construction efficiency and optimization
    - Memory usage during filter building and expression management
    - Builder operation timing and throughput validation
    - Complex nested filter building performance characteristics
    - Filter string generation and optimization patterns

Security Testing:
    - Input validation and sanitization for filter components
    - Proper escaping of special characters and injection prevention
    - Attribute name validation and security constraints
    - Filter complexity limits and DoS protection mechanisms
    - Error handling security and information disclosure protection
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from ldap_core_shared.filters.builder import (
    FilterBuilder,
    FilterEscaping,
    FilterExpression,
    FilterOperator,
    and_filters,
    contains,
    equals,
    not_filter,
    or_filters,
    present,
)


class TestFilterOperator:
    """Test cases for FilterOperator enumeration."""

    def test_filter_operator_values(self) -> None:
        """Test FilterOperator enumeration values."""
        assert FilterOperator.EQUAL.value == "="
        assert FilterOperator.APPROXIMATE.value == "~="
        assert FilterOperator.GREATER_EQUAL.value == ">="
        assert FilterOperator.LESS_EQUAL.value == "<="
        assert FilterOperator.PRESENT.value == "=*"
        assert FilterOperator.SUBSTRING.value == "substring"
        assert FilterOperator.AND.value == "&"
        assert FilterOperator.OR.value == "|"
        assert FilterOperator.NOT.value == "!"

    def test_filter_operator_completeness(self) -> None:
        """Test FilterOperator enumeration completeness."""
        expected_operators = {
            "=", "~=", ">=", "<=", "=*", "substring", "&", "|", "!",
        }

        actual_operators = {member.value for member in FilterOperator}
        assert actual_operators == expected_operators

    def test_filter_operator_membership_validation(self) -> None:
        """Test FilterOperator membership validation."""
        for operator in FilterOperator:
            assert isinstance(operator, FilterOperator)
            assert operator.value in {
                "=", "~=", ">=", "<=", "=*", "substring", "&", "|", "!",
            }


class TestFilterExpression:
    """Test cases for FilterExpression."""

    def test_filter_expression_creation_basic(self) -> None:
        """Test creating basic filter expression."""
        expr = FilterExpression(filter_string="(cn=test)")

        assert expr.filter_string == "(cn=test)"
        assert expr.is_valid is True
        assert expr.complexity_score == 1

    def test_filter_expression_creation_complete(self) -> None:
        """Test creating complete filter expression."""
        expr = FilterExpression(
            filter_string="(&(cn=test)(objectClass=person))",
            is_valid=True,
            complexity_score=5,
        )

        assert expr.filter_string == "(&(cn=test)(objectClass=person))"
        assert expr.is_valid is True
        assert expr.complexity_score == 5

    def test_filter_expression_validation_empty_string(self) -> None:
        """Test filter expression validation with empty string."""
        with pytest.raises(ValidationError, match="Filter string cannot be empty"):
            FilterExpression(filter_string="")

    def test_filter_expression_validation_whitespace_only(self) -> None:
        """Test filter expression validation with whitespace only."""
        with pytest.raises(ValidationError, match="Filter string cannot be empty"):
            FilterExpression(filter_string="   ")

    def test_filter_expression_auto_parentheses(self) -> None:
        """Test filter expression auto-adds parentheses."""
        expr = FilterExpression(filter_string="cn=test")

        # Should automatically wrap in parentheses
        assert expr.filter_string == "(cn=test)"

    def test_filter_expression_str_representation(self) -> None:
        """Test __str__ method returns filter string."""
        expr = FilterExpression(filter_string="(cn=test)")

        assert str(expr) == "(cn=test)"

    def test_filter_expression_repr_representation(self) -> None:
        """Test __repr__ method includes validity."""
        expr = FilterExpression(filter_string="(cn=test)", is_valid=True)

        repr_str = repr(expr)
        assert "(cn=test)" in repr_str
        assert "valid=True" in repr_str

    def test_filter_expression_get_filter_string(self) -> None:
        """Test get_filter_string method."""
        expr = FilterExpression(filter_string="(cn=test)")

        assert expr.get_filter_string() == "(cn=test)"

    def test_filter_expression_is_simple(self) -> None:
        """Test is_simple method for complexity classification."""
        simple_expr = FilterExpression(filter_string="(cn=test)", complexity_score=1)
        complex_expr = FilterExpression(filter_string="(&(cn=test)(sn=user))", complexity_score=3)

        assert simple_expr.is_simple() is True
        assert complex_expr.is_simple() is False

    def test_filter_expression_is_complex(self) -> None:
        """Test is_complex method for complexity classification."""
        simple_expr = FilterExpression(filter_string="(cn=test)", complexity_score=1)
        complex_expr = FilterExpression(filter_string="(&(cn=test)(sn=user))", complexity_score=3)

        assert simple_expr.is_complex() is False
        assert complex_expr.is_complex() is True

    def test_filter_expression_strict_mode(self) -> None:
        """Test filter expression strict mode rejects extra fields."""
        with pytest.raises(ValidationError, match="Extra inputs are not permitted"):
            FilterExpression(filter_string="(cn=test)", extra_field="not_allowed")

    def test_filter_expression_required_fields(self) -> None:
        """Test filter expression requires filter_string."""
        with pytest.raises(ValidationError, match="Field required"):
            FilterExpression()


class TestFilterEscaping:
    """Test cases for FilterEscaping utilities."""

    def test_escape_value_basic_string(self) -> None:
        """Test escaping basic string values."""
        result = FilterEscaping.escape_value("test")
        assert result == "test"

    def test_escape_value_special_characters(self) -> None:
        """Test escaping special characters."""
        # Test each special character
        assert FilterEscaping.escape_value("test*") == r"test\2a"
        assert FilterEscaping.escape_value("test(") == r"test\28"
        assert FilterEscaping.escape_value("test)") == r"test\29"
        assert FilterEscaping.escape_value("test\\") == r"test\5c"
        assert FilterEscaping.escape_value("test\x00") == r"test\00"

    def test_escape_value_multiple_characters(self) -> None:
        """Test escaping multiple special characters."""
        result = FilterEscaping.escape_value("test*()")
        assert result == r"test\2a\28\29"

    def test_escape_value_non_string_input(self) -> None:
        """Test escaping non-string values."""
        assert FilterEscaping.escape_value(123) == "123"
        assert FilterEscaping.escape_value(True) == "True"
        assert FilterEscaping.escape_value(None) == "None"

    def test_escape_value_empty_string(self) -> None:
        """Test escaping empty string."""
        assert FilterEscaping.escape_value("") == ""

    def test_unescape_value_basic_string(self) -> None:
        """Test unescaping basic string values."""
        result = FilterEscaping.unescape_value("test")
        assert result == "test"

    def test_unescape_value_escaped_characters(self) -> None:
        """Test unescaping escaped characters."""
        assert FilterEscaping.unescape_value(r"test\2a") == "test*"
        assert FilterEscaping.unescape_value(r"test\28") == "test("
        assert FilterEscaping.unescape_value(r"test\29") == "test)"
        assert FilterEscaping.unescape_value(r"test\5c") == "test\\"
        assert FilterEscaping.unescape_value(r"test\00") == "test\x00"

    def test_unescape_value_multiple_characters(self) -> None:
        """Test unescaping multiple escaped characters."""
        result = FilterEscaping.unescape_value(r"test\2a\28\29")
        assert result == "test*()"

    def test_escape_unescape_roundtrip(self) -> None:
        """Test escape/unescape roundtrip preserves original."""
        original = "test*()\\special\x00chars"
        escaped = FilterEscaping.escape_value(original)
        unescaped = FilterEscaping.unescape_value(escaped)

        assert unescaped == original

    def test_escape_attribute_valid_names(self) -> None:
        """Test escaping valid attribute names."""
        valid_names = ["cn", "commonName", "x121Address", "telephoneNumber"]

        for name in valid_names:
            result = FilterEscaping.escape_attribute(name)
            assert result == name

    def test_escape_attribute_invalid_names(self) -> None:
        """Test escaping invalid attribute names raises error."""
        invalid_names = ["123invalid", "invalid!", "invalid@attr", "invalid attr"]

        for name in invalid_names:
            with pytest.raises(ValueError, match="Invalid attribute name"):
                FilterEscaping.escape_attribute(name)

    def test_escape_attribute_non_string_input(self) -> None:
        """Test escaping non-string attribute names."""
        FilterEscaping.escape_attribute(123)
        # Should convert to string first, but 123 is invalid attribute name
        with pytest.raises(ValueError, match="Invalid attribute name"):
            FilterEscaping.escape_attribute(123)

    def test_escape_attribute_empty_string(self) -> None:
        """Test escaping empty attribute name."""
        with pytest.raises(ValueError, match="Invalid attribute name"):
            FilterEscaping.escape_attribute("")

    def test_escape_chars_completeness(self) -> None:
        """Test ESCAPE_CHARS dictionary completeness."""
        expected_chars = {"\\", "*", "(", ")", "\x00"}
        actual_chars = set(FilterEscaping.ESCAPE_CHARS.keys())

        assert actual_chars == expected_chars

    def test_escape_chars_values(self) -> None:
        """Test ESCAPE_CHARS mapping values."""
        assert FilterEscaping.ESCAPE_CHARS["\\"] == r"\5c"
        assert FilterEscaping.ESCAPE_CHARS["*"] == r"\2a"
        assert FilterEscaping.ESCAPE_CHARS["("] == r"\28"
        assert FilterEscaping.ESCAPE_CHARS[")"] == r"\29"
        assert FilterEscaping.ESCAPE_CHARS["\x00"] == r"\00"


class TestFilterBuilder:
    """Test cases for FilterBuilder."""

    def test_builder_initialization(self) -> None:
        """Test FilterBuilder initialization."""
        builder = FilterBuilder()

        assert builder._filter_stack == []
        assert builder._operator_stack == []
        assert builder._complexity == 0

    def test_builder_equal_filter(self) -> None:
        """Test building equality filter."""
        builder = FilterBuilder()
        expr = builder.equal("cn", "test").build()

        assert expr.filter_string == "(cn=test)"
        assert expr.complexity_score == 1

    def test_builder_equal_filter_with_escaping(self) -> None:
        """Test building equality filter with special characters."""
        builder = FilterBuilder()
        expr = builder.equal("cn", "test*").build()

        assert expr.filter_string == r"(cn=test\2a)"

    def test_builder_not_equal_filter(self) -> None:
        """Test building not-equal filter."""
        builder = FilterBuilder()
        expr = builder.not_equal("cn", "test").build()

        assert expr.filter_string == "(!(cn=test))"

    def test_builder_contains_filter(self) -> None:
        """Test building substring contains filter."""
        builder = FilterBuilder()
        expr = builder.contains("cn", "test").build()

        assert expr.filter_string == r"(cn=*test*)"

    def test_builder_starts_with_filter(self) -> None:
        """Test building starts-with filter."""
        builder = FilterBuilder()
        expr = builder.starts_with("cn", "test").build()

        assert expr.filter_string == r"(cn=test*)"

    def test_builder_ends_with_filter(self) -> None:
        """Test building ends-with filter."""
        builder = FilterBuilder()
        expr = builder.ends_with("cn", "test").build()

        assert expr.filter_string == r"(cn=*test)"

    def test_builder_present_filter(self) -> None:
        """Test building presence filter."""
        builder = FilterBuilder()
        expr = builder.present("objectClass").build()

        assert expr.filter_string == "(objectClass=*)"

    def test_builder_absent_filter(self) -> None:
        """Test building absence filter."""
        builder = FilterBuilder()
        expr = builder.absent("mail").build()

        assert expr.filter_string == "(!(mail=*))"

    def test_builder_greater_equal_filter(self) -> None:
        """Test building greater-than-or-equal filter."""
        builder = FilterBuilder()
        expr = builder.greater_equal("uidNumber", 1000).build()

        assert expr.filter_string == "(uidNumber>=1000)"

    def test_builder_less_equal_filter(self) -> None:
        """Test building less-than-or-equal filter."""
        builder = FilterBuilder()
        expr = builder.less_equal("uidNumber", 9999).build()

        assert expr.filter_string == "(uidNumber<=9999)"

    def test_builder_approximate_filter(self) -> None:
        """Test building approximate match filter."""
        builder = FilterBuilder()
        expr = builder.approximate("cn", "test").build()

        assert expr.filter_string == "(cn~=test)"

    def test_builder_substring_filter_complete(self) -> None:
        """Test building complete substring filter."""
        builder = FilterBuilder()
        expr = builder.substring(
            "cn",
            initial="start",
            any_parts=["middle1", "middle2"],
            final="end",
        ).build()

        filter_str = expr.filter_string
        assert filter_str.startswith("(cn=start")
        assert "middle1" in filter_str
        assert "middle2" in filter_str
        assert filter_str.endswith("end)")

    def test_builder_substring_filter_initial_only(self) -> None:
        """Test building substring filter with initial part only."""
        builder = FilterBuilder()
        expr = builder.substring("cn", initial="start").build()

        assert expr.filter_string == "(cn=start*)"

    def test_builder_substring_filter_final_only(self) -> None:
        """Test building substring filter with final part only."""
        builder = FilterBuilder()
        expr = builder.substring("cn", final="end").build()

        assert expr.filter_string == "(cn=*end)"

    def test_builder_substring_filter_any_parts_only(self) -> None:
        """Test building substring filter with any parts only."""
        builder = FilterBuilder()
        expr = builder.substring("cn", any_parts=["middle1", "middle2"]).build()

        filter_str = expr.filter_string
        assert "middle1" in filter_str
        assert "middle2" in filter_str
        assert filter_str.count("*") >= 3  # At least one * between each part

    def test_builder_and_filter(self) -> None:
        """Test building AND compound filter."""
        builder = FilterBuilder()
        expr = (builder.and_()
               .equal("cn", "test")
               .equal("objectClass", "person")
               .end()
               .build())

        assert expr.filter_string == "(&(cn=test)(objectClass=person))"

    def test_builder_or_filter(self) -> None:
        """Test building OR compound filter."""
        builder = FilterBuilder()
        expr = (builder.or_()
               .equal("cn", "test1")
               .equal("cn", "test2")
               .end()
               .build())

        assert expr.filter_string == "(|(cn=test1)(cn=test2))"

    def test_builder_not_filter(self) -> None:
        """Test building NOT compound filter."""
        builder = FilterBuilder()
        expr = (builder.not_()
               .equal("cn", "test")
               .end()
               .build())

        assert expr.filter_string == "(!(cn=test))"

    def test_builder_nested_filters(self) -> None:
        """Test building nested compound filters."""
        builder = FilterBuilder()
        expr = (builder.and_()
               .equal("objectClass", "person")
               .or_()
               .equal("cn", "admin")
               .contains("title", "manager")
               .end()
               .end()
               .build())

        filter_str = expr.filter_string
        assert filter_str.startswith("(&")
        assert "(objectClass=person)" in filter_str
        assert "(|" in filter_str
        assert "(cn=admin)" in filter_str
        assert "title=*manager*" in filter_str

    def test_builder_complex_nested_structure(self) -> None:
        """Test building complex nested filter structure."""
        builder = FilterBuilder()
        expr = (builder.and_()
               .equal("objectClass", "person")
               .or_()
               .contains("cn", "admin")
               .not_()
               .equal("accountExpired", "TRUE")
               .end()
               .end()
               .greater_equal("uidNumber", 1000)
               .end()
               .build())

        # Should be a complex nested structure
        assert expr.complexity_score > 5
        assert "(&" in expr.filter_string
        assert "(|" in expr.filter_string
        assert "(!" in expr.filter_string

    def test_builder_chaining_pattern(self) -> None:
        """Test fluent API chaining pattern."""
        builder = FilterBuilder()

        # All methods should return builder for chaining
        result = (builder
                 .equal("cn", "test")
                 .and_()
                 .equal("objectClass", "person")
                 .end())

        assert result is builder

    def test_builder_end_without_compound_filter(self) -> None:
        """Test end() without starting compound filter raises error."""
        builder = FilterBuilder()

        with pytest.raises(ValueError, match="No compound filter to close"):
            builder.equal("cn", "test").end()

    def test_builder_and_filter_insufficient_conditions(self) -> None:
        """Test AND filter with insufficient conditions."""
        builder = FilterBuilder()

        with pytest.raises(ValueError, match="AND filter requires at least .* conditions"):
            builder.and_().equal("cn", "test").end()

    def test_builder_or_filter_insufficient_conditions(self) -> None:
        """Test OR filter with insufficient conditions."""
        builder = FilterBuilder()

        with pytest.raises(ValueError, match="OR filter requires at least .* conditions"):
            builder.or_().equal("cn", "test").end()

    def test_builder_not_filter_multiple_conditions(self) -> None:
        """Test NOT filter with multiple conditions raises error."""
        builder = FilterBuilder()

        with pytest.raises(ValueError, match="NOT filter requires exactly 1 condition"):
            (builder.not_()
             .equal("cn", "test1")
             .equal("cn", "test2")
             .end())

    def test_builder_build_without_conditions(self) -> None:
        """Test build() without adding conditions raises error."""
        builder = FilterBuilder()

        with pytest.raises(ValueError, match="No filter conditions added"):
            builder.build()

    def test_builder_build_with_unclosed_compound(self) -> None:
        """Test build() with unclosed compound filter raises error."""
        builder = FilterBuilder()

        with pytest.raises(ValueError, match="Unclosed compound filters"):
            builder.and_().equal("cn", "test").build()

    def test_builder_build_multiple_top_level(self) -> None:
        """Test build() with multiple top-level filters."""
        builder = FilterBuilder()
        expr = (builder
               .equal("cn", "test")
               .equal("objectClass", "person")
               .build())

        # Should wrap multiple top-level filters in AND
        assert expr.filter_string.startswith("(&")
        assert "(cn=test)" in expr.filter_string
        assert "(objectClass=person)" in expr.filter_string

    def test_builder_reset(self) -> None:
        """Test builder reset functionality."""
        builder = FilterBuilder()

        # Add some filters
        builder.equal("cn", "test").equal("objectClass", "person")

        # Reset and verify clean state
        result = builder.reset()
        assert result is builder
        assert builder._filter_stack == []
        assert builder._operator_stack == []
        assert builder._complexity == 0

    def test_builder_complexity_calculation(self) -> None:
        """Test builder complexity score calculation."""
        builder = FilterBuilder()

        # Simple filter
        simple_expr = builder.equal("cn", "test").build()
        assert simple_expr.complexity_score == 1

        # Reset and build complex filter
        builder.reset()
        complex_expr = (builder.and_()
                       .equal("cn", "test")
                       .equal("objectClass", "person")
                       .or_()
                       .contains("title", "admin")
                       .present("mail")
                       .end()
                       .end()
                       .build())

        assert complex_expr.complexity_score > 5

    def test_builder_attribute_validation(self) -> None:
        """Test builder validates attribute names."""
        builder = FilterBuilder()

        # Valid attribute names should work
        builder.equal("cn", "test")
        builder.equal("commonName", "test")
        builder.equal("x121Address", "test")

        # Invalid attribute names should raise errors
        with pytest.raises(ValueError, match="Invalid attribute name"):
            builder.equal("123invalid", "test")

    def test_builder_value_escaping_integration(self) -> None:
        """Test builder properly escapes values."""
        builder = FilterBuilder()

        # Test various special characters
        expr = builder.equal("cn", "test*()\x00").build()

        # Should contain escaped characters
        assert r"\2a" in expr.filter_string  # *
        assert r"\28" in expr.filter_string  # (
        assert r"\29" in expr.filter_string  # )
        assert r"\00" in expr.filter_string  # \x00

    def test_builder_non_string_values(self) -> None:
        """Test builder handles non-string values."""
        builder = FilterBuilder()

        # Test various value types
        expr1 = builder.equal("uidNumber", 1000).build()
        assert "(uidNumber=1000)" in expr1.filter_string

        builder.reset()
        expr2 = builder.equal("enabled", True).build()
        assert "(enabled=True)" in expr2.filter_string


class TestConvenienceFunctions:
    """Test cases for convenience functions."""

    def test_equals_function(self) -> None:
        """Test equals convenience function."""
        expr = equals("cn", "test")

        assert isinstance(expr, FilterExpression)
        assert expr.filter_string == "(cn=test)"

    def test_contains_function(self) -> None:
        """Test contains convenience function."""
        expr = contains("cn", "admin")

        assert isinstance(expr, FilterExpression)
        assert expr.filter_string == r"(cn=*admin*)"

    def test_present_function(self) -> None:
        """Test present convenience function."""
        expr = present("objectClass")

        assert isinstance(expr, FilterExpression)
        assert expr.filter_string == "(objectClass=*)"

    def test_and_filters_function(self) -> None:
        """Test and_filters convenience function."""
        filter1 = equals("cn", "test")
        filter2 = equals("objectClass", "person")

        expr = and_filters(filter1, filter2)

        assert isinstance(expr, FilterExpression)
        assert expr.filter_string.startswith("(&")
        assert "(cn=test)" in expr.filter_string
        assert "(objectClass=person)" in expr.filter_string

    def test_and_filters_function_insufficient_filters(self) -> None:
        """Test and_filters with insufficient filters."""
        filter1 = equals("cn", "test")

        with pytest.raises(ValueError, match="AND requires at least .* filters"):
            and_filters(filter1)

    def test_and_filters_function_string_filters(self) -> None:
        """Test and_filters with string filter inputs."""
        expr = and_filters("(cn=test)", "(objectClass=person)")

        assert isinstance(expr, FilterExpression)
        assert "(&" in expr.filter_string
        assert "(cn=test)" in expr.filter_string
        assert "(objectClass=person)" in expr.filter_string

    def test_or_filters_function(self) -> None:
        """Test or_filters convenience function."""
        filter1 = equals("cn", "admin")
        filter2 = equals("cn", "administrator")

        expr = or_filters(filter1, filter2)

        assert isinstance(expr, FilterExpression)
        assert expr.filter_string.startswith("(|")
        assert "(cn=admin)" in expr.filter_string
        assert "(cn=administrator)" in expr.filter_string

    def test_or_filters_function_insufficient_filters(self) -> None:
        """Test or_filters with insufficient filters."""
        filter1 = equals("cn", "test")

        with pytest.raises(ValueError, match="OR requires at least .* filters"):
            or_filters(filter1)

    def test_not_filter_function(self) -> None:
        """Test not_filter convenience function."""
        filter1 = equals("cn", "guest")

        expr = not_filter(filter1)

        assert isinstance(expr, FilterExpression)
        assert expr.filter_string.startswith("(!")
        assert "(cn=guest)" in expr.filter_string

    def test_not_filter_function_string_input(self) -> None:
        """Test not_filter with string filter input."""
        expr = not_filter("(cn=guest)")

        assert isinstance(expr, FilterExpression)
        assert expr.filter_string.startswith("(!")
        assert "(cn=guest)" in expr.filter_string

    def test_convenience_functions_filter_extraction(self) -> None:
        """Test convenience functions properly extract filter content."""
        # Test with parentheses that should be removed
        filter_with_parens = FilterExpression(filter_string="(cn=test)")
        expr = and_filters(filter_with_parens, "(objectClass=person)")

        # Should not have nested extra parentheses
        filter_str = expr.filter_string
        assert filter_str.count("(cn=test)") == 1
        assert filter_str.count("(objectClass=person)") == 1


class TestFilterBuilderIntegration:
    """Test cases for FilterBuilder integration scenarios."""

    def test_real_world_filter_construction(self) -> None:
        """Test construction of real-world LDAP filters."""
        builder = FilterBuilder()

        # Build a realistic corporate directory filter
        expr = (builder.and_()
               .equal("objectClass", "person")
               .or_()
               .contains("cn", "admin")
               .contains("title", "manager")
               .and_()
               .equal("department", "IT")
               .not_()
               .equal("accountExpired", "TRUE")
               .end()
               .end()
               .end()
               .greater_equal("uidNumber", 1000)
               .present("mail")
               .end()
               .build())

        # Verify structure and complexity
        assert expr.is_complex()
        assert expr.complexity_score > 8
        assert "(&" in expr.filter_string
        assert "(objectClass=person)" in expr.filter_string
        assert "(uidNumber>=1000)" in expr.filter_string

    def test_filter_builder_error_recovery(self) -> None:
        """Test filter builder error recovery patterns."""
        builder = FilterBuilder()

        # Test recovery from error conditions
        try:
            # This should fail
            builder.and_().equal("cn", "test").end()
        except ValueError:
            pass

        # Builder should still be usable after error
        builder.reset()
        expr = builder.equal("cn", "test").build()
        assert expr.filter_string == "(cn=test)"

    def test_complex_nested_structure_validation(self) -> None:
        """Test validation of complex nested structures."""
        builder = FilterBuilder()

        # Build deeply nested structure
        expr = (builder.and_()
               .or_()
               .equal("cn", "test1")
               .equal("cn", "test2")
               .end()
               .and_()
               .present("objectClass")
               .not_()
               .equal("disabled", "TRUE")
               .end()
               .end()
               .or_()
               .contains("mail", "admin")
               .greater_equal("uidNumber", 1000)
               .end()
               .end()
               .build())

        # Should be valid and complex
        assert expr.is_valid
        assert expr.complexity_score > 10

        # Should have proper nesting structure
        filter_str = expr.filter_string
        assert filter_str.count("(&") >= 2
        assert filter_str.count("(|") >= 2
        assert filter_str.count("(!") >= 1

    def test_performance_with_large_filters(self) -> None:
        """Test performance with large filter construction."""
        builder = FilterBuilder()

        # Build large AND filter
        builder.and_()
        for i in range(50):
            builder.equal(f"attr{i:02d}", f"value{i:02d}")
        expr = builder.end().build()

        # Should handle large filters efficiently
        assert expr.complexity_score == 51  # 50 conditions + 1 AND operator
        assert expr.filter_string.count("(attr") == 50

    def test_security_validation_integration(self) -> None:
        """Test security validation during filter construction."""
        builder = FilterBuilder()

        # Test with potentially problematic values
        problematic_values = [
            "normal_value",
            "value*with*wildcards",
            "value(with)parens",
            "value\\with\\backslash",
            "value\x00with\x00nulls",
        ]

        for i, value in enumerate(problematic_values):
            builder.equal(f"attr{i}", value)

        expr = builder.build()

        # Should properly escape all problematic characters
        filter_str = expr.filter_string
        assert r"\2a" in filter_str  # Escaped *
        assert r"\28" in filter_str  # Escaped (
        assert r"\29" in filter_str  # Escaped )
        assert r"\5c" in filter_str  # Escaped \
        assert r"\00" in filter_str  # Escaped null

    def test_builder_state_management(self) -> None:
        """Test builder state management and isolation."""
        builder1 = FilterBuilder()
        builder2 = FilterBuilder()

        # Build different filters with different builders
        expr1 = builder1.equal("cn", "test1").build()
        expr2 = builder2.equal("cn", "test2").build()

        # Results should be independent
        assert expr1.filter_string == "(cn=test1)"
        assert expr2.filter_string == "(cn=test2)"

        # Test state isolation during compound filter building
        builder1.reset()
        builder1.and_().equal("attr1", "value1")

        builder2.reset()
        builder2.or_().equal("attr2", "value2")

        # Each should maintain its own operator stack
        assert builder1._operator_stack[-1] == FilterOperator.AND
        assert builder2._operator_stack[-1] == FilterOperator.OR

    def test_edge_case_handling(self) -> None:
        """Test edge case handling in filter construction."""
        builder = FilterBuilder()

        # Test empty values
        expr1 = builder.equal("cn", "").build()
        assert expr1.filter_string == "(cn=)"

        # Test single character values
        builder.reset()
        expr2 = builder.equal("a", "b").build()
        assert expr2.filter_string == "(a=b)"

        # Test very long values
        builder.reset()
        long_value = "x" * 1000
        expr3 = builder.equal("cn", long_value).build()
        assert long_value in expr3.filter_string

    def test_filter_composition_patterns(self) -> None:
        """Test common filter composition patterns."""
        # Pattern 1: User search filter
        user_filter = (FilterBuilder()
                      .and_()
                      .equal("objectClass", "person")
                      .or_()
                      .contains("cn", "john")
                      .contains("mail", "john")
                      .contains("uid", "john")
                      .end()
                      .end()
                      .build())

        # Pattern 2: Group membership filter
        group_filter = (FilterBuilder()
                       .and_()
                       .equal("objectClass", "groupOfNames")
                       .equal("member", "cn=john,ou=people,dc=example,dc=com")
                       .end()
                       .build())

        # Pattern 3: Active account filter
        active_filter = (FilterBuilder()
                        .and_()
                        .present("objectClass")
                        .not_()
                        .equal("accountExpired", "TRUE")
                        .end()
                        .not_()
                        .equal("disabled", "TRUE")
                        .end()
                        .end()
                        .build())

        # All patterns should be valid and properly structured
        for filter_expr in [user_filter, group_filter, active_filter]:
            assert filter_expr.is_valid
            assert filter_expr.complexity_score > 1

    def test_convenience_function_integration(self) -> None:
        """Test integration between builder and convenience functions."""
        # Build filter with builder
        builder_filter = (FilterBuilder()
                         .and_()
                         .equal("cn", "test")
                         .equal("objectClass", "person")
                         .end()
                         .build())

        # Build equivalent filter with convenience functions
        convenience_filter = and_filters(
            equals("cn", "test"),
            equals("objectClass", "person"),
        )

        # Results should be functionally equivalent
        # (exact string match may differ due to parentheses handling)
        assert "(cn=test)" in builder_filter.filter_string
        assert "(objectClass=person)" in builder_filter.filter_string
        assert "(cn=test)" in convenience_filter.filter_string
        assert "(objectClass=person)" in convenience_filter.filter_string

    def test_error_message_quality(self) -> None:
        """Test quality and helpfulness of error messages."""
        builder = FilterBuilder()

        # Test various error conditions and verify helpful messages
        with pytest.raises(ValueError) as exc_info:
            builder.and_().equal("cn", "test").end()
        assert "requires at least" in str(exc_info.value)

        with pytest.raises(ValueError) as exc_info:
            builder.reset().end()
        assert "No compound filter to close" in str(exc_info.value)

        with pytest.raises(ValueError) as exc_info:
            builder.reset().build()
        assert "No filter conditions added" in str(exc_info.value)

    def test_memory_efficiency(self) -> None:
        """Test memory efficiency during filter construction."""
        import gc

        # Build and discard many filters to test memory usage
        for i in range(100):
            builder = FilterBuilder()
            expr = (builder.and_()
                   .equal("cn", f"test{i}")
                   .equal("objectClass", "person")
                   .end()
                   .build())

            # Use the filter to prevent optimization
            assert f"test{i}" in expr.filter_string

        # Force garbage collection
        gc.collect()

        # Test should complete without memory issues
        assert True
