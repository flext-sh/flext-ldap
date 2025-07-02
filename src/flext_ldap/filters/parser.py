"""LDAP Filter Parser Implementation.

This module provides comprehensive LDAP filter parsing functionality following
RFC 4515 specification with enhanced error handling and structural analysis.
Based on perl-ldap Net::LDAP::Filter parsing capabilities.

The FilterParser enables decomposition of LDAP filter strings into structured
representations for analysis, validation, and programmatic manipulation.

Architecture:
    - FilterParser: Main parser class for filter string analysis
    - ParsedFilter: Structured representation of parsed filters
    - FilterToken: Individual filter components and operators
    - FilterSyntaxError: Parse error handling and reporting

Usage Example:
    >>> from flext_ldap.filters.parser import FilterParser
    >>>
    >>> # Parse simple filter
    >>> parser = FilterParser()
    >>> parsed = parser.parse("(cn=John Doe)")
    >>> print(parsed.filter_type)  # 'equality'
    >>> print(parsed.attribute)  # 'cn'
    >>> print(parsed.value)  # 'John Doe'
    >>>
    >>> # Parse complex nested filter
    >>> complex_filter = "(&(objectClass=person)(|(cn=*REDACTED_LDAP_BIND_PASSWORD*)(mail=*@example.com))"
    >>> parsed = parser.parse(complex_filter)
    >>> print(parsed.filter_type)  # 'and'
    >>> print(len(parsed.children)  # 2

References:
    - perl-ldap: lib/Net/LDAP/Filter.pm
    - RFC 4515: LDAP String Representation of Search Filters
    - RFC 4511: LDAP Protocol Specification
"""

from __future__ import annotations

import re
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field, validator

# Constants for filter validation
MIN_COMPOUND_FILTER_CHILDREN = 2  # Minimum children for AND/OR filters
EXACT_NOT_FILTER_CHILDREN = 1  # Exact children for NOT filters
COMPLEXITY_PERFORMANCE_THRESHOLD = (
    10  # Complexity score threshold for performance warnings
)


class FilterType(Enum):
    """LDAP filter types."""

    EQUALITY = "equality"
    SUBSTRING = "substring"
    GREATER_EQUAL = "greater_equal"
    LESS_EQUAL = "less_equal"
    PRESENT = "present"
    APPROXIMATE = "approximate"
    AND = "and"
    OR = "or"
    NOT = "not"
    EXTENSIBLE = "extensible"


class FilterSyntaxError(Exception):
    """Exception raised for filter syntax errors."""

    def __init__(
        self,
        message: str,
        position: int | None = None,
        filter_string: str | None = None,
    ) -> None:
        """Initialize syntax error with context.

        Args:
            message: Error description
            position: Character position where error occurred
            filter_string: Original filter string that failed parsing
        """
        self.position = position
        self.filter_string = filter_string

        if position is not None and filter_string:
            context = self._get_error_context(filter_string, position)
            full_message = f"{message} at position {position}: {context}"
        else:
            full_message = message

        super().__init__(full_message)

    def _get_error_context(self, filter_string: str, position: int) -> str:
        """Get context around error position."""
        start = max(0, position - 10)
        end = min(len(filter_string), position + 10)

        context = filter_string[start:end]
        pointer_pos = position - start
        pointer = " " * pointer_pos + "^"

        return f"\n{context}\n{pointer}"


class ParsedFilter(BaseModel):
    """Structured representation of parsed LDAP filter.

    This class represents the parsed structure of an LDAP filter,
    providing easy access to filter components and enabling
    programmatic manipulation.

    Attributes:
        filter_type: Type of filter (equality, and, or, etc.)
        attribute: Attribute name for simple filters
        value: Filter value for simple filters
        operator: Comparison operator for simple filters
        children: Child filters for compound filters
        is_negated: Whether filter is negated
        raw_filter: Original filter string

    Note:
        For compound filters (and, or, not), the children attribute
        contains the nested filter components.
    """

    filter_type: FilterType = Field(description="Type of LDAP filter")

    attribute: str | None = Field(
        default=None,
        description="Attribute name for simple filters",
    )

    value: str | None = Field(
        default=None,
        description="Filter value for simple filters",
    )

    operator: str | None = Field(
        default=None,
        description="Comparison operator (=, >=, <=, ~=)",
    )

    children: list[ParsedFilter] = Field(
        default_factory=list,
        description="Child filters for compound filters",
    )

    is_negated: bool = Field(default=False, description="Whether filter is negated")

    raw_filter: str = Field(description="Original filter string")

    # Extensible match components
    matching_rule: str | None = Field(
        default=None,
        description="Matching rule OID for extensible matches",
    )

    dn_attributes: bool = Field(
        default=False,
        description="Whether extensible match includes DN attributes",
    )

    @validator("children")
    def validate_children(self, v: list[Any], values: dict[str, Any]) -> list[Any]:
        """Validate children based on filter type."""
        filter_type = values.get("filter_type")

        if filter_type == FilterType.AND and len(v) < MIN_COMPOUND_FILTER_CHILDREN:
            msg = "AND filter must have at least 2 children"
            raise ValueError(msg)

        if filter_type == FilterType.OR and len(v) < MIN_COMPOUND_FILTER_CHILDREN:
            msg = "OR filter must have at least 2 children"
            raise ValueError(msg)

        if filter_type == FilterType.NOT and len(v) != EXACT_NOT_FILTER_CHILDREN:
            msg = "NOT filter must have exactly 1 child"
            raise ValueError(msg)

        return v

    def is_simple(self) -> bool:
        """Check if this is a simple (non-compound) filter."""
        return self.filter_type not in {FilterType.AND, FilterType.OR, FilterType.NOT}

    def is_compound(self) -> bool:
        """Check if this is a compound filter."""
        return self.filter_type in {FilterType.AND, FilterType.OR, FilterType.NOT}

    def get_attributes(self) -> set[str]:
        """Get all attributes referenced in this filter and its children.

        Returns:
            Set of attribute names used in the filter
        """
        attributes = set()

        if self.attribute:
            attributes.add(self.attribute)

        for child in self.children:
            attributes.update(child.get_attributes())

        return attributes

    def get_complexity_score(self) -> int:
        """Calculate complexity score for the filter.

        Returns:
            Complexity score (1 for simple filters, higher for compound)
        """
        if self.is_simple():
            return 1

        # Compound filters: sum of children + 1 for the operator
        return 1 + sum(child.get_complexity_score() for child in self.children)

    def to_string(self) -> str:
        """Convert parsed filter back to string representation.

        Returns:
            LDAP filter string
        """
        if self.filter_type == FilterType.EQUALITY:
            return f"({self.attribute}={self.value})"

        if self.filter_type == FilterType.SUBSTRING:
            return f"({self.attribute}={self.value})"

        if self.filter_type == FilterType.GREATER_EQUAL:
            return f"({self.attribute}>={self.value})"

        if self.filter_type == FilterType.LESS_EQUAL:
            return f"({self.attribute}<={self.value})"

        if self.filter_type == FilterType.PRESENT:
            return f"({self.attribute}=*)"

        if self.filter_type == FilterType.APPROXIMATE:
            return f"({self.attribute}~={self.value})"

        if self.filter_type == FilterType.AND:
            children_str = "".join(child.to_string() for child in self.children)
            return f"(&{children_str})"

        if self.filter_type == FilterType.OR:
            children_str = "".join(child.to_string() for child in self.children)
            return f"(|{children_str})"

        if self.filter_type == FilterType.NOT:
            child_str = self.children[0].to_string() if self.children else ""
            return f"(!{child_str})"

        # Default fallback
        return self.raw_filter

    def __str__(self) -> str:
        """String representation of parsed filter."""
        return self.to_string()


class FilterParser:
    """Parser for LDAP filter strings.

    This class provides comprehensive parsing of LDAP filter strings
    according to RFC 4515 specification. It handles all standard
    filter types including compound filters with proper nesting.

    Example:
        >>> parser = FilterParser()
        >>> parsed = parser.parse("(&(cn=john)(mail=*@example.com)")
        >>> print(parsed.filter_type)  # FilterType.AND
        >>> print(len(parsed.children)  # 2
    """

    # Regular expressions for filter components
    _ATTRIBUTE_PATTERN = re.compile(r"[a-zA-Z][a-zA-Z0-9\-]*")
    _ESCAPED_CHAR_PATTERN = re.compile(r"\\[0-9a-fA-F]{2}")

    def __init__(self) -> None:
        """Initialize filter parser."""
        self._position = 0
        self._filter_string = ""

    def parse(self, filter_string: str) -> ParsedFilter:
        """Parse LDAP filter string into structured representation.

        Args:
            filter_string: LDAP filter string to parse

        Returns:
            ParsedFilter with structured representation

        Raises:
            FilterSyntaxError: If filter syntax is invalid
        """
        if not filter_string or not filter_string.strip():
            msg = "Empty filter string"
            raise FilterSyntaxError(msg)

        self._filter_string = filter_string.strip()
        self._position = 0

        try:
            parsed = self._parse_filter()

            # Check for trailing characters
            if self._position < len(self._filter_string):
                msg = "Unexpected characters after filter"
                raise FilterSyntaxError(msg, self._position, self._filter_string)

            return parsed

        except FilterSyntaxError:
            raise
        except Exception as e:
            msg = f"Parse error: {e}"
            raise FilterSyntaxError(msg, self._position, self._filter_string) from e

    def _parse_filter(self) -> ParsedFilter:
        """Parse a single filter component."""
        self._skip_whitespace()

        if not self._has_more():
            msg = "Unexpected end of filter"
            raise FilterSyntaxError(msg, self._position, self._filter_string)

        if self._current_char() != "(":
            msg = "Filter must start with '('"
            raise FilterSyntaxError(msg, self._position, self._filter_string)

        self._advance()  # Skip opening parenthesis
        self._skip_whitespace()

        if not self._has_more():
            msg = "Unexpected end after '('"
            raise FilterSyntaxError(msg, self._position, self._filter_string)

        # Check for compound filter operators
        current = self._current_char()

        if current == "&":
            return self._parse_and_filter()
        if current == "|":
            return self._parse_or_filter()
        if current == "!":
            return self._parse_not_filter()
        return self._parse_simple_filter()

    def _parse_and_filter(self) -> ParsedFilter:
        """Parse AND compound filter."""
        self._advance()  # Skip '&'
        self._skip_whitespace()

        children = []
        while self._has_more() and self._current_char() != ")":
            child = self._parse_filter()
            children.append(child)
            self._skip_whitespace()

        if not self._has_more():
            msg = "Unclosed AND filter"
            raise FilterSyntaxError(msg, self._position, self._filter_string)

        self._advance()  # Skip closing parenthesis

        if len(children) < MIN_COMPOUND_FILTER_CHILDREN:
            msg = "AND filter requires at least 2 child filters"
            raise FilterSyntaxError(msg, self._position, self._filter_string)

        return ParsedFilter(
            filter_type=FilterType.AND,
            children=children,
            raw_filter=self._filter_string,
        )

    def _parse_or_filter(self) -> ParsedFilter:
        """Parse OR compound filter."""
        self._advance()  # Skip '|'
        self._skip_whitespace()

        children = []
        while self._has_more() and self._current_char() != ")":
            child = self._parse_filter()
            children.append(child)
            self._skip_whitespace()

        if not self._has_more():
            msg = "Unclosed OR filter"
            raise FilterSyntaxError(msg, self._position, self._filter_string)

        self._advance()  # Skip closing parenthesis

        if len(children) < MIN_COMPOUND_FILTER_CHILDREN:
            msg = "OR filter requires at least 2 child filters"
            raise FilterSyntaxError(msg, self._position, self._filter_string)

        return ParsedFilter(
            filter_type=FilterType.OR,
            children=children,
            raw_filter=self._filter_string,
        )

    def _parse_not_filter(self) -> ParsedFilter:
        """Parse NOT compound filter."""
        self._advance()  # Skip '!'
        self._skip_whitespace()

        if not self._has_more() or self._current_char() == ")":
            msg = "NOT filter requires a child filter"
            raise FilterSyntaxError(msg, self._position, self._filter_string)

        child = self._parse_filter()
        self._skip_whitespace()

        if not self._has_more():
            msg = "Unclosed NOT filter"
            raise FilterSyntaxError(msg, self._position, self._filter_string)

        self._advance()  # Skip closing parenthesis

        return ParsedFilter(
            filter_type=FilterType.NOT,
            children=[child],
            is_negated=True,
            raw_filter=self._filter_string,
        )

    def _parse_simple_filter(self) -> ParsedFilter:
        """Parse simple (non-compound) filter."""
        # Parse attribute name
        attribute = self._parse_attribute()

        if not self._has_more():
            msg = "Incomplete filter after attribute"
            raise FilterSyntaxError(msg, self._position, self._filter_string)

        # Parse operator
        operator = self._parse_operator()

        # Parse value
        value = self._parse_value()

        # Skip closing parenthesis
        if not self._has_more() or self._current_char() != ")":
            msg = "Missing closing parenthesis"
            raise FilterSyntaxError(msg, self._position, self._filter_string)

        self._advance()

        # Determine filter type based on operator and value
        filter_type = self._determine_filter_type(operator, value)

        return ParsedFilter(
            filter_type=filter_type,
            attribute=attribute,
            value=value,
            operator=operator,
            raw_filter=self._filter_string,
        )

    def _parse_attribute(self) -> str:
        """Parse attribute name."""
        start_pos = self._position

        if not self._has_more() or not self._current_char().isalpha():
            msg = "Invalid attribute name"
            raise FilterSyntaxError(msg, self._position, self._filter_string)

        # First character must be alphabetic
        self._advance()

        # Subsequent characters can be alphanumeric or hyphen
        while self._has_more() and (
            self._current_char().isalnum() or self._current_char() == "-"
        ):
            self._advance()

        attribute = self._filter_string[start_pos : self._position]

        if not attribute:
            msg = "Empty attribute name"
            raise FilterSyntaxError(msg, self._position, self._filter_string)

        return attribute

    def _parse_operator(self) -> str:
        """Parse comparison operator."""
        if not self._has_more():
            msg = "Missing operator"
            raise FilterSyntaxError(msg, self._position, self._filter_string)

        start_pos = self._position

        if self._current_char() == "~":
            self._advance()
            if self._has_more() and self._current_char() == "=":
                self._advance()
                return "~="
            msg = "Invalid operator: expected '~='"
            raise FilterSyntaxError(msg, start_pos, self._filter_string)

        if self._current_char() == ">":
            self._advance()
            if self._has_more() and self._current_char() == "=":
                self._advance()
                return ">="
            msg = "Invalid operator: expected '>='"
            raise FilterSyntaxError(msg, start_pos, self._filter_string)

        if self._current_char() == "<":
            self._advance()
            if self._has_more() and self._current_char() == "=":
                self._advance()
                return "<="
            msg = "Invalid operator: expected '<='"
            raise FilterSyntaxError(msg, start_pos, self._filter_string)

        if self._current_char() == "=":
            self._advance()
            return "="

        msg = "Invalid operator"
        raise FilterSyntaxError(msg, self._position, self._filter_string)

    def _parse_value(self) -> str:
        """Parse filter value."""
        value_chars = []

        while self._has_more() and self._current_char() != ")":
            char = self._current_char()

            if char == "\\":
                # Handle escaped characters
                if self._position + 2 < len(self._filter_string):
                    escape_seq = self._filter_string[
                        self._position : self._position + 3
                    ]
                    if self._ESCAPED_CHAR_PATTERN.match(escape_seq):
                        # Valid escape sequence
                        value_chars.append(escape_seq)
                        self._position += 3
                        continue

                # Invalid escape sequence
                msg = "Invalid escape sequence"
                raise FilterSyntaxError(msg, self._position, self._filter_string)

            value_chars.append(char)
            self._advance()

        return "".join(value_chars)

        # Value can be empty for presence filters

    def _determine_filter_type(self, operator: str, value: str) -> FilterType:
        """Determine filter type based on operator and value."""
        if operator == "=" and value == "*":
            return FilterType.PRESENT

        if operator == "=" and "*" in value:
            return FilterType.SUBSTRING

        if operator == "=":
            return FilterType.EQUALITY

        if operator == ">=":
            return FilterType.GREATER_EQUAL

        if operator == "<=":
            return FilterType.LESS_EQUAL

        if operator == "~=":
            return FilterType.APPROXIMATE

        # Default to equality
        return FilterType.EQUALITY

    def _current_char(self) -> str:
        """Get current character."""
        if self._position >= len(self._filter_string):
            return ""
        return self._filter_string[self._position]

    def _advance(self) -> None:
        """Advance position by one character."""
        self._position += 1

    def _has_more(self) -> bool:
        """Check if more characters are available."""
        return self._position < len(self._filter_string)

    def _skip_whitespace(self) -> None:
        """Skip whitespace characters."""
        while self._has_more() and self._current_char().isspace():
            self._advance()


# Convenience functions
def parse_filter(filter_string: str) -> ParsedFilter:
    """Parse LDAP filter string.

    Args:
        filter_string: LDAP filter to parse

    Returns:
        ParsedFilter with structured representation
    """
    parser = FilterParser()
    return parser.parse(filter_string)


def is_valid_filter(filter_string: str) -> bool:
    """Check if filter string is syntactically valid.

    Args:
        filter_string: LDAP filter to validate

    Returns:
        True if filter is valid, False otherwise
    """
    try:
        parse_filter(filter_string)
        return True
    except FilterSyntaxError:
        return False


def get_filter_attributes(filter_string: str) -> set[str]:
    """Extract all attributes referenced in filter.

    Args:
        filter_string: LDAP filter to analyze

    Returns:
        Set of attribute names used in the filter

    Raises:
        FilterSyntaxError: If filter syntax is invalid
    """
    parsed = parse_filter(filter_string)
    return parsed.get_attributes()


def get_filter_complexity(filter_string: str) -> int:
    """Calculate complexity score for filter.

    Args:
        filter_string: LDAP filter to analyze

    Returns:
        Complexity score (higher = more complex)

    Raises:
        FilterSyntaxError: If filter syntax is invalid
    """
    parsed = parse_filter(filter_string)
    return parsed.get_complexity_score()


class FilterAnalyzer:
    """Advanced filter analysis and optimization utilities.

    This class provides advanced analysis capabilities for LDAP filters
    including performance hints, optimization suggestions, and security
    analysis.

    Example:
        >>> analyzer = FilterAnalyzer()
        >>> analysis = analyzer.analyze("(&(objectClass=person)(cn=*REDACTED_LDAP_BIND_PASSWORD*)")
        >>> print(analysis.performance_hints)
        >>> print(analysis.security_warnings)
    """

    def __init__(self) -> None:
        """Initialize filter analyzer."""
        self._parser = FilterParser()

    def analyze(self, filter_string: str) -> dict[str, Any]:
        """Perform comprehensive filter analysis.

        Args:
            filter_string: LDAP filter to analyze

        Returns:
            Analysis results with performance and security insights
        """
        try:
            parsed = self._parser.parse(filter_string)
        except FilterSyntaxError as e:
            return {
                "valid": False,
                "syntax_error": str(e),
                "performance_hints": [],
                "security_warnings": [],
                "optimization_suggestions": [],
            }

        return {
            "valid": True,
            "filter_type": parsed.filter_type.value,
            "complexity_score": parsed.get_complexity_score(),
            "attributes": list(parsed.get_attributes()),
            "performance_hints": self._analyze_performance(parsed),
            "security_warnings": self._analyze_security(parsed),
            "optimization_suggestions": self._suggest_optimizations(parsed),
        }

    def _analyze_performance(self, parsed: ParsedFilter) -> list[str]:
        """Analyze filter for performance characteristics."""
        hints = []

        # Check for substring filters
        if self._has_substring_filters(parsed):
            hints.append(
                "Substring filters may impact performance - consider using indexed attributes",
            )

        # Check for complex nested filters
        if parsed.get_complexity_score() > COMPLEXITY_PERFORMANCE_THRESHOLD:
            hints.append(
                "Complex nested filter - consider simplification for better performance",
            )

        # Check for presence filters on non-indexed attributes
        if self._has_presence_filters(parsed):
            hints.append("Presence filters on non-indexed attributes may be slow")

        return hints

    def _analyze_security(self, parsed: ParsedFilter) -> list[str]:
        """Analyze filter for security concerns."""
        warnings = []

        # Check for overly broad filters
        if self._is_overly_broad(parsed):
            warnings.append(
                "Filter may return excessive results - consider adding more constraints",
            )

        # Check for potential injection patterns
        if self._has_injection_patterns(parsed):
            warnings.append(
                "Filter contains patterns that may indicate injection attempts",
            )

        return warnings

    def _suggest_optimizations(self, parsed: ParsedFilter) -> list[str]:
        """Suggest filter optimizations."""
        suggestions = []

        # Suggest moving equality filters first in AND clauses
        if parsed.filter_type == FilterType.AND:
            suggestions.append(
                "Consider placing equality filters before substring filters",
            )

        # Suggest using presence filters for existence checks
        if self._can_use_presence_filter(parsed):
            suggestions.append(
                "Consider using presence filter (*) for attribute existence checks",
            )

        return suggestions

    def _has_substring_filters(self, parsed: ParsedFilter) -> bool:
        """Check if filter contains substring operations."""
        if parsed.filter_type == FilterType.SUBSTRING:
            return True

        return any(self._has_substring_filters(child) for child in parsed.children)

    def _has_presence_filters(self, parsed: ParsedFilter) -> bool:
        """Check if filter contains presence operations."""
        if parsed.filter_type == FilterType.PRESENT:
            return True

        return any(self._has_presence_filters(child) for child in parsed.children)

    def _is_overly_broad(self, parsed: ParsedFilter) -> bool:
        """Check if filter is overly broad."""
        # Simple heuristic: filters with only presence or substring operations
        if parsed.filter_type in {FilterType.PRESENT, FilterType.SUBSTRING}:
            return True

        # Check for AND filters with only broad conditions
        if parsed.filter_type == FilterType.AND:
            return all(self._is_overly_broad(child) for child in parsed.children)

        return False

    def _has_injection_patterns(self, parsed: ParsedFilter) -> bool:
        """Check for potential injection patterns."""
        # This is a simplified check - real implementation would be more sophisticated
        if parsed.value and any(
            char in parsed.value for char in ["(", ")", "&", "|", "!"]
        ):
            return True

        return any(self._has_injection_patterns(child) for child in parsed.children)

    def _can_use_presence_filter(self, parsed: ParsedFilter) -> bool:
        """Check if presence filter can be used instead."""
        # Simple heuristic for demonstration
        return parsed.filter_type == FilterType.EQUALITY and parsed.value == ""


# TODO: Integration points for implementation:
#
# 1. Schema Integration:
#    - Validate attribute names against LDAP schema
#    - Check attribute syntax compatibility with operators
#    - Suggest appropriate matching rules for attributes
#
# 2. Performance Integration:
#    - Integrate with LDAP server index information
#    - Provide performance estimates for filter operations
#    - Suggest index creation for frequently used filters
#
# 3. Security Integration:
#    - Advanced injection detection and prevention
#    - Filter complexity limits to prevent DoS attacks
#    - Audit logging for suspicious filter patterns
#
# 4. Optimization Engine:
#    - Automatic filter rewriting for better performance
#    - Query plan analysis and optimization suggestions
#    - Cost-based optimization for complex filters
#
# 5. Caching System:
#    - Cache parsed filter representations
#    - Invalidate cache on schema changes
#    - Share cached parses across operations
#
# 6. Testing Framework:
#    - Comprehensive test suite for all filter types
#    - Edge case testing for malformed filters
#    - Performance testing for complex nested filters
#    - Security testing for injection attempts
