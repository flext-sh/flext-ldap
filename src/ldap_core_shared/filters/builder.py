from __future__ import annotations

"""LDAP Filter Builder Implementation.

This module provides a fluent API for building complex LDAP filters programmatically.
Based on perl-ldap Net::LDAP::Filter functionality with enhanced Python patterns
for intuitive filter construction.

The FilterBuilder enables creating complex nested filter expressions using a
chainable interface, eliminating the need to manually construct filter strings
and reducing syntax errors.

Architecture:
    - FilterBuilder: Main builder class with fluent API
    - FilterExpression: Immutable filter representation
    - FilterOperators: Standard LDAP operators and utilities
    - FilterEscaping: Proper escaping for filter values

Usage Example:
    >>> from ldap_core_shared.filters.builder import FilterBuilder
    >>> # Simple equality filter
    >>> filter_expr = FilterBuilder().equal("cn", "John Doe").build()
    >>> print(filter_expr)  # (cn=John Doe)
    >>> # Complex nested filter
    >>> complex_filter = (
    ...     FilterBuilder()
    ...     .and_()
    ...     .equal("objectClass", "person")
    ...     .not_()
    ...     .equal("accountExpired", "TRUE")
    ...     .end()
    ...     .or_()
    ...     .starts_with("mail", "REDACTED_LDAP_BIND_PASSWORD")
    ...     .contains("department", "IT")
    ...     .end()
    ...     .end()
    ...     .build()
    ... )

References:
    - perl-ldap: lib/Net/LDAP/Filter.pm
    - RFC 4515: LDAP String Representation of Search Filters
"""


import re
from enum import Enum
from typing import Any, Optional, Union

from pydantic import BaseModel, Field, validator

from ldap_core_shared.utils.constants import MIN_LOGICAL_OPERATORS


class FilterOperator(Enum):
    """LDAP filter operators."""

    EQUAL = "="
    APPROXIMATE = "~="
    GREATER_EQUAL = ">="
    LESS_EQUAL = "<="
    PRESENT = "=*"
    SUBSTRING = "substring"
    AND = "&"
    OR = "|"
    NOT = "!"


class FilterExpression(BaseModel):
    """Immutable LDAP filter expression.

    Represents a complete LDAP filter that can be converted to string format
    for use in LDAP search operations.

    Attributes:
        filter_string: The complete LDAP filter string
        is_valid: Whether the filter syntax is valid
        complexity_score: Estimated complexity of the filter

    Note:
        Filter expressions are immutable once created. Use FilterBuilder
        to construct new expressions.
    """

    filter_string: str = Field(description="Complete LDAP filter string")

    is_valid: bool = Field(default=True, description="Whether filter syntax is valid")

    complexity_score: int = Field(
        default=1, description="Estimated filter complexity (1-DEFAULT_MAX_ITEMS)",
    )

    @validator("filter_string")
    def validate_filter_string(cls, v: str) -> str:
        """Validate filter string format."""
        if not v or not v.strip():
            msg = "Filter string cannot be empty"
            raise ValueError(msg)

        # Basic syntax check - should start and end with parentheses for compound filters
        v = v.strip()
        if len(v) > 1 and not (v.startswith("(") and v.endswith(")")):
            v = f"({v})"

        return v

    def __str__(self) -> str:
        """String representation of the filter."""
        return self.filter_string

    def __repr__(self) -> str:
        """Detailed representation of the filter."""
        return f"FilterExpression('{self.filter_string}', valid={self.is_valid})"

    def get_filter_string(self) -> str:
        """Get the LDAP filter string."""
        return self.filter_string

    def is_simple(self) -> bool:
        """Check if this is a simple (non-compound) filter."""
        return self.complexity_score == 1

    def is_complex(self) -> bool:
        """Check if this is a complex (compound) filter."""
        return self.complexity_score > 1


class FilterEscaping:
    """Utilities for escaping LDAP filter values.

    LDAP filter values must escape certain characters according to RFC 4515.
    This class provides methods for proper escaping and unescaping.
    """

    # Characters that must be escaped in LDAP filter values
    ESCAPE_CHARS = {
        "\\": r"\5c",
        "*": r"\2a",
        "(": r"\28",
        ")": r"\29",
        "\x00": r"\00",
    }

    @classmethod
    def escape_value(cls, value: Any) -> str:
        """Escape special characters in filter value.

        Args:
            value: Raw value to escape

        Returns:
            Escaped value safe for use in LDAP filters
        """
        if not isinstance(value, str):
            value = str(value)

        str_value: str = value
        for char, escaped in cls.ESCAPE_CHARS.items():
            str_value = str_value.replace(char, escaped)

        return str_value

    @classmethod
    def unescape_value(cls, value: str) -> str:
        """Unescape LDAP filter value.

        Args:
            value: Escaped filter value

        Returns:
            Unescaped original value
        """
        for char, escaped in cls.ESCAPE_CHARS.items():
            value = value.replace(escaped, char)

        return value

    @classmethod
    def escape_attribute(cls, attribute: Any) -> str:
        """Escape LDAP attribute name.

        Args:
            attribute: Attribute name to escape

        Returns:
            Escaped attribute name

        Note:
            Attribute names have different escaping rules than values.
        """
        if not isinstance(attribute, str):
            attribute = str(attribute)

        str_attribute: str = attribute
        # Attribute names should only contain valid LDAP attribute characters
        if not re.match(r"^[a-zA-Z][a-zA-Z0-9\-]*$", str_attribute):
            msg = f"Invalid attribute name: {str_attribute}"
            raise ValueError(msg)

        return str_attribute


class FilterBuilder:
    """Fluent API for building LDAP filters.

    This class provides a chainable interface for constructing complex LDAP
    filter expressions. It handles proper escaping, parentheses, and syntax
    to generate valid LDAP filter strings.

    Example:
        >>> builder = FilterBuilder()
        >>> filter_expr = (
        ...     builder.and_()
        ...     .equal("objectClass", "person")
        ...     .contains("cn", "REDACTED_LDAP_BIND_PASSWORD")
        ...     .end()
        ...     .build()
        ... )
    """

    def __init__(self) -> None:
        """Initialize a new filter builder."""
        self._filter_stack: list[str] = []
        self._operator_stack: list[FilterOperator] = []
        self._complexity = 0

    def equal(self, attribute: str, value: Any) -> FilterBuilder:
        """Add equality filter condition.

        Args:
            attribute: LDAP attribute name
            value: Value to match exactly

        Returns:
            Builder instance for chaining
        """
        escaped_attr = FilterEscaping.escape_attribute(attribute)
        escaped_value = FilterEscaping.escape_value(str(value))
        filter_part = f"({escaped_attr}={escaped_value})"
        self._add_filter_part(filter_part)
        return self

    def not_equal(self, attribute: str, value: Any) -> FilterBuilder:
        """Add not-equal filter condition.

        Args:
            attribute: LDAP attribute name
            value: Value to exclude

        Returns:
            Builder instance for chaining
        """
        escaped_attr = FilterEscaping.escape_attribute(attribute)
        escaped_value = FilterEscaping.escape_value(str(value))
        filter_part = f"(!({escaped_attr}={escaped_value}))"
        self._add_filter_part(filter_part)
        return self

    def contains(self, attribute: str, value: str) -> FilterBuilder:
        """Add substring contains filter condition.

        Args:
            attribute: LDAP attribute name
            value: Substring to search for

        Returns:
            Builder instance for chaining
        """
        escaped_attr = FilterEscaping.escape_attribute(attribute)
        escaped_value = FilterEscaping.escape_value(value)
        filter_part = f"({escaped_attr}=*{escaped_value}*)"
        self._add_filter_part(filter_part)
        return self

    def starts_with(self, attribute: str, value: str) -> FilterBuilder:
        """Add starts-with filter condition.

        Args:
            attribute: LDAP attribute name
            value: Prefix to match

        Returns:
            Builder instance for chaining
        """
        escaped_attr = FilterEscaping.escape_attribute(attribute)
        escaped_value = FilterEscaping.escape_value(value)
        filter_part = f"({escaped_attr}={escaped_value}*)"
        self._add_filter_part(filter_part)
        return self

    def ends_with(self, attribute: str, value: str) -> FilterBuilder:
        """Add ends-with filter condition.

        Args:
            attribute: LDAP attribute name
            value: Suffix to match

        Returns:
            Builder instance for chaining
        """
        escaped_attr = FilterEscaping.escape_attribute(attribute)
        escaped_value = FilterEscaping.escape_value(value)
        filter_part = f"({escaped_attr}=*{escaped_value})"
        self._add_filter_part(filter_part)
        return self

    def present(self, attribute: str) -> FilterBuilder:
        """Add presence filter condition (attribute exists).

        Args:
            attribute: LDAP attribute name to check for presence

        Returns:
            Builder instance for chaining
        """
        escaped_attr = FilterEscaping.escape_attribute(attribute)
        filter_part = f"({escaped_attr}=*)"
        self._add_filter_part(filter_part)
        return self

    def absent(self, attribute: str) -> FilterBuilder:
        """Add absence filter condition (attribute does not exist).

        Args:
            attribute: LDAP attribute name to check for absence

        Returns:
            Builder instance for chaining
        """
        escaped_attr = FilterEscaping.escape_attribute(attribute)
        filter_part = f"(!({escaped_attr}=*))"
        self._add_filter_part(filter_part)
        return self

    def greater_equal(self, attribute: str, value: Any) -> FilterBuilder:
        """Add greater-than-or-equal filter condition.

        Args:
            attribute: LDAP attribute name
            value: Minimum value

        Returns:
            Builder instance for chaining
        """
        escaped_attr = FilterEscaping.escape_attribute(attribute)
        escaped_value = FilterEscaping.escape_value(str(value))
        filter_part = f"({escaped_attr}>={escaped_value})"
        self._add_filter_part(filter_part)
        return self

    def less_equal(self, attribute: str, value: Any) -> FilterBuilder:
        """Add less-than-or-equal filter condition.

        Args:
            attribute: LDAP attribute name
            value: Maximum value

        Returns:
            Builder instance for chaining
        """
        escaped_attr = FilterEscaping.escape_attribute(attribute)
        escaped_value = FilterEscaping.escape_value(str(value))
        filter_part = f"({escaped_attr}<={escaped_value})"
        self._add_filter_part(filter_part)
        return self

    def approximate(self, attribute: str, value: Any) -> FilterBuilder:
        """Add approximate match filter condition.

        Args:
            attribute: LDAP attribute name
            value: Value for approximate matching

        Returns:
            Builder instance for chaining
        """
        escaped_attr = FilterEscaping.escape_attribute(attribute)
        escaped_value = FilterEscaping.escape_value(str(value))
        filter_part = f"({escaped_attr}~={escaped_value})"
        self._add_filter_part(filter_part)
        return self

    def substring(
        self,
        attribute: str,
        initial: Optional[str] = None,
        any_parts: Optional[list[str]] = None,
        final: Optional[str] = None,
    ) -> FilterBuilder:
        """Add substring filter with precise control.

        Args:
            attribute: LDAP attribute name
            initial: Initial substring (prefix)
            any_parts: List of substring parts that can appear anywhere
            final: Final substring (suffix)

        Returns:
            Builder instance for chaining
        """
        escaped_attr = FilterEscaping.escape_attribute(attribute)

        # Build substring pattern
        parts = []

        if initial:
            parts.append(FilterEscaping.escape_value(initial))
        parts.append("*")

        if any_parts:
            for part in any_parts:
                parts.extend([FilterEscaping.escape_value(part), "*"])

        if final:
            parts.append(FilterEscaping.escape_value(final))

        # Remove trailing * if we have a final part
        if final and parts[-2] == "*":
            parts = parts[:-1]

        substring_value = "".join(parts)
        filter_part = f"({escaped_attr}={substring_value})"
        self._add_filter_part(filter_part)
        return self

    def and_(self) -> FilterBuilder:
        """Start an AND compound filter.

        Returns:
            Builder instance for chaining

        Note:
            Must be closed with end() call.
        """
        self._start_compound(FilterOperator.AND)
        return self

    def or_(self) -> FilterBuilder:
        """Start an OR compound filter.

        Returns:
            Builder instance for chaining

        Note:
            Must be closed with end() call.
        """
        self._start_compound(FilterOperator.OR)
        return self

    def not_(self) -> FilterBuilder:
        """Start a NOT compound filter.

        Returns:
            Builder instance for chaining

        Note:
            Must be closed with end() call.
        """
        self._start_compound(FilterOperator.NOT)
        return self

    def end(self) -> FilterBuilder:
        """End the current compound filter.

        Returns:
            Builder instance for chaining

        Raises:
            ValueError: If no compound filter to close
        """
        if not self._operator_stack:
            msg = "No compound filter to close"
            raise ValueError(msg)

        operator = self._operator_stack.pop()

        # Collect filters for this compound level
        compound_filters: list[str] = []
        while self._filter_stack and not self._filter_stack[-1].startswith(
            "__COMPOUND_START__",
        ):
            compound_filters.insert(0, self._filter_stack.pop())

        # Remove the compound start marker
        if self._filter_stack and self._filter_stack[-1].startswith(
            "__COMPOUND_START__",
        ):
            self._filter_stack.pop()

        # Build the compound filter
        if operator == FilterOperator.AND:
            if len(compound_filters) < MIN_LOGICAL_OPERATORS:
                msg = f"AND filter requires at least {MIN_LOGICAL_OPERATORS} conditions"
                raise ValueError(msg)
            compound_filter = f"(&{''.join(compound_filters)})"
        elif operator == FilterOperator.OR:
            if len(compound_filters) < MIN_LOGICAL_OPERATORS:
                msg = f"OR filter requires at least {MIN_LOGICAL_OPERATORS} conditions"
                raise ValueError(msg)
            compound_filter = f"(|{''.join(compound_filters)})"
        elif operator == FilterOperator.NOT:
            if len(compound_filters) != 1:
                msg = "NOT filter requires exactly 1 condition"
                raise ValueError(msg)
            compound_filter = f"(!{compound_filters[0]})"
        else:
            msg = f"Unknown compound operator: {operator}"
            raise ValueError(msg)

        self._add_filter_part(compound_filter)
        return self

    def build(self) -> FilterExpression:
        """Build the final filter expression.

        Returns:
            Immutable FilterExpression

        Raises:
            ValueError: If builder state is invalid
        """
        if self._operator_stack:
            msg = "Unclosed compound filters. Call end() to close them."
            raise ValueError(msg)

        if not self._filter_stack:
            msg = "No filter conditions added"
            raise ValueError(msg)

        if len(self._filter_stack) == 1:
            filter_string = self._filter_stack[0]
        else:
            # Multiple top-level filters - wrap in AND
            filter_string = f"(&{''.join(self._filter_stack)})"

        return FilterExpression(
            filter_string=filter_string, complexity_score=max(1, self._complexity),
        )

    def reset(self) -> FilterBuilder:
        """Reset the builder to initial state.

        Returns:
            Builder instance for chaining
        """
        self._filter_stack.clear()
        self._operator_stack.clear()
        self._complexity = 0
        return self

    def _add_filter_part(self, filter_part: str) -> None:
        """Add a filter part to the current context."""
        self._filter_stack.append(filter_part)
        self._complexity += 1

    def _start_compound(self, operator: FilterOperator) -> None:
        """Start a compound filter operation."""
        self._operator_stack.append(operator)
        self._filter_stack.append(f"__COMPOUND_START__{operator.value}")
        self._complexity += 1


# Convenience functions for common filter patterns
def equals(attribute: str, value: Any) -> FilterExpression:
    """Create simple equality filter.

    Args:
        attribute: LDAP attribute name
        value: Value to match

    Returns:
        FilterExpression for equality condition
    """
    return FilterBuilder().equal(attribute, value).build()


def contains(attribute: str, value: str) -> FilterExpression:
    """Create simple substring contains filter.

    Args:
        attribute: LDAP attribute name
        value: Substring to search for

    Returns:
        FilterExpression for contains condition
    """
    return FilterBuilder().contains(attribute, value).build()


def present(attribute: str) -> FilterExpression:
    """Create simple presence filter.

    Args:
        attribute: LDAP attribute name

    Returns:
        FilterExpression for presence condition
    """
    return FilterBuilder().present(attribute).build()


def and_filters(*filters: Union[FilterExpression, str]) -> FilterExpression:
    """Combine multiple filters with AND logic.

    Args:
        *filters: FilterExpression objects or filter strings

    Returns:
        FilterExpression combining all filters with AND
    """
    if len(filters) < MIN_LOGICAL_OPERATORS:
        msg = f"AND requires at least {MIN_LOGICAL_OPERATORS} filters"
        raise ValueError(msg)

    builder = FilterBuilder().and_()
    for filter_expr in filters:
        if isinstance(filter_expr, FilterExpression):
            # Extract the filter content (remove outer parentheses if present)
            filter_str = filter_expr.filter_string
            if filter_str.startswith("(") and filter_str.endswith(")"):
                filter_str = filter_str[1:-1]
            builder._add_filter_part(f"({filter_str})")
        else:
            builder._add_filter_part(f"({filter_expr})")

    return builder.end().build()


def or_filters(*filters: Union[FilterExpression, str]) -> FilterExpression:
    """Combine multiple filters with OR logic.

    Args:
        *filters: FilterExpression objects or filter strings

    Returns:
        FilterExpression combining all filters with OR
    """
    if len(filters) < MIN_LOGICAL_OPERATORS:
        msg = f"OR requires at least {MIN_LOGICAL_OPERATORS} filters"
        raise ValueError(msg)

    builder = FilterBuilder().or_()
    for filter_expr in filters:
        if isinstance(filter_expr, FilterExpression):
            # Extract the filter content (remove outer parentheses if present)
            filter_str = filter_expr.filter_string
            if filter_str.startswith("(") and filter_str.endswith(")"):
                filter_str = filter_str[1:-1]
            builder._add_filter_part(f"({filter_str})")
        else:
            builder._add_filter_part(f"({filter_expr})")

    return builder.end().build()


def not_filter(filter_expr: Union[FilterExpression, str]) -> FilterExpression:
    """Negate a filter with NOT logic.

    Args:
        filter_expr: FilterExpression object or filter string to negate

    Returns:
        FilterExpression negating the input filter
    """
    builder = FilterBuilder().not_()

    if isinstance(filter_expr, FilterExpression):
        filter_str = filter_expr.filter_string
        if filter_str.startswith("(") and filter_str.endswith(")"):
            filter_str = filter_str[1:-1]
        builder._add_filter_part(f"({filter_str})")
    else:
        builder._add_filter_part(f"({filter_expr})")

    return builder.end().build()

# TODO: Integration points for implementation:
#
# 1. Schema Integration:
#    - Validate attribute names against LDAP schema
#    - Type-aware value formatting (dates, numbers, etc.)
#    - Attribute syntax validation and normalization
#
# 2. Query Optimization:
#    - Filter complexity analysis and optimization suggestions
#    - Index hint generation for common filter patterns
#    - Performance impact estimation for complex filters
#
# 3. Search Integration:
#    - Seamless integration with search operations
#    - Automatic filter application in search methods
#    - Result set filtering and post-processing
#
# 4. Template System:
#    - Parameterized filter templates for common patterns
#    - Filter composition from reusable components
#    - Dynamic filter generation from search criteria
#
# 5. Security Features:
#    - Input sanitization and injection prevention
#    - Filter complexity limits to prevent DoS attacks
#    - Audit logging for complex or sensitive filters
#
# 6. Testing Framework:
#    - Unit tests for all filter operations and combinations
#    - Integration tests with real LDAP servers
#    - Performance tests for complex filter scenarios
#    - Edge case tests for special characters and encodings
