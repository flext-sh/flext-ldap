"""LDAP Filter Parsing and Manipulation Utilities.

This module provides comprehensive LDAP filter processing following RFC 4515
with perl-ldap compatibility patterns for filter parsing, validation, optimization,
and transformation of LDAP search filters.

LDAP filters provide standardized query mechanisms for directory searches,
enabling complex attribute matching, logical operations, and efficient
directory queries essential for enterprise applications.

Architecture:
    - LDAPFilter: Main filter representation and manipulation class
    - FilterParser: Parser for filter syntax and structure
    - FilterOptimizer: Filter optimization and transformation
    - FilterValidator: Filter validation and compliance checking

Usage Example:
    >>> from flext_ldap.utilities.filter import LDAPFilter
    >>>
    >>> # Parse complex filter
    >>> filter_obj = LDAPFilter("(&(objectClass=person)(|(cn=john*)(mail=*@example.com)))")
    >>>
    >>> # Validate and optimize
    >>> if filter_obj.is_valid():
    ...     optimized = filter_obj.optimize()
    ...     print(f"Optimized: {optimized}")
    >>>
    >>> # Build filter programmatically
    >>> builder = LDAPFilter.builder()
    >>> filter_obj = builder.and_([
    ...     builder.equals("objectClass", "person"),
    ...     builder.starts_with("cn", "john")
    ... ])

References:
    - perl-ldap: lib/Net/LDAP/Filter.pm
    - RFC 4515: LDAP String Representation of Search Filters
    - RFC 4511: LDAP Protocol Specification
    - LDAP filter syntax and matching rules

"""

from __future__ import annotations

import re
from enum import Enum

from pydantic import BaseModel, Field


class FilterType(Enum):
    """LDAP filter operation types."""

    AND = "and"  # (&(filter1)(filter2)...)
    OR = "or"  # (|(filter1)(filter2)...)
    NOT = "not"  # (!(filter))
    EQUALS = "equals"  # (attr=value)
    SUBSTRING = "substring"  # (attr=value*)
    GREATER_EQUAL = "greater_equal"  # (attr>=value)
    LESS_EQUAL = "less_equal"  # (attr<=value)
    PRESENT = "present"  # (attr=*)
    APPROX = "approx"  # (attr~=value)
    EXTENSIBLE = "extensible"  # (attr:dn:rule:=value)


class MatchingRule(Enum):
    """LDAP matching rules."""

    CASE_IGNORE = "caseIgnoreMatch"
    CASE_EXACT = "caseExactMatch"
    NUMERIC_STRING = "numericStringMatch"
    DISTINGUISHED_NAME = "distinguishedNameMatch"
    OBJECT_IDENTIFIER = "objectIdentifierMatch"
    BOOLEAN = "booleanMatch"
    INTEGER = "integerMatch"
    BIT_STRING = "bitStringMatch"
    OCTET_STRING = "octetStringMatch"
    GENERALIZED_TIME = "generalizedTimeMatch"


class FilterComponent(BaseModel):
    """Individual filter component representation."""

    filter_type: FilterType = Field(description="Type of filter operation")

    attribute: str | None = Field(default=None, description="Attribute name")

    value: str | None = Field(default=None, description="Filter value")

    subfilters: list[FilterComponent] = Field(
        default_factory=list,
        description="Sub-filters for logical operations",
    )

    # Extensible matching components
    matching_rule: str | None = Field(
        default=None,
        description="Matching rule OID or name",
    )

    dn_attributes: bool = Field(
        default=False,
        description="Whether to match DN attributes",
    )

    # Metadata
    negated: bool = Field(default=False, description="Whether filter is negated")

    def is_simple(self) -> bool:
        """Check if filter is a simple attribute-value assertion."""
        return self.filter_type in {
            FilterType.EQUALS,
            FilterType.SUBSTRING,
            FilterType.GREATER_EQUAL,
            FilterType.LESS_EQUAL,
            FilterType.PRESENT,
            FilterType.APPROX,
        }

    def is_logical(self) -> bool:
        """Check if filter is a logical operation."""
        return self.filter_type in {FilterType.AND, FilterType.OR, FilterType.NOT}

    def get_attributes(self) -> set[str]:
        """Get all attributes referenced in this filter component."""
        attributes = set()

        if self.attribute:
            attributes.add(self.attribute)

        for subfilter in self.subfilters:
            attributes.update(subfilter.get_attributes())

        return attributes

    def count_conditions(self) -> int:
        """Count total number of conditions in filter."""
        if self.is_simple():
            return 1

        count = 0
        for subfilter in self.subfilters:
            count += subfilter.count_conditions()

        return count


class LDAPFilter:
    """LDAP filter representation and manipulation.

    This class provides comprehensive LDAP filter processing capabilities
    following RFC 4515 standards with perl-ldap compatibility patterns
    for parsing, validation, and optimization.

    Example:
        >>> # Parse existing filter
        >>> filter_obj = LDAPFilter("(&(objectClass=person)(cn=john*))")
        >>>
        >>> # Validate filter
        >>> if filter_obj.is_valid():
        ...     print("Filter is valid")
        >>>
        >>> # Get filter attributes
        >>> attrs = filter_obj.get_attributes()
        >>> print(f"Attributes used: {attrs}")
        >>>
        >>> # Optimize filter
        >>> optimized = filter_obj.optimize()
        >>> print(f"Optimized: {optimized}")
        >>>
        >>> # Build filter programmatically
        >>> builder = LDAPFilter.builder()
        >>> new_filter = builder.and_([
        ...     builder.equals("objectClass", "person"),
        ...     builder.or_([
        ...         builder.starts_with("cn", "john"),
        ...         builder.starts_with("cn", "jane")
        ...     ])
        ... ])

    """

    # Regex patterns for filter parsing
    FILTER_PATTERN = re.compile(r"^\s*\((.+)\)\s*$")
    SIMPLE_FILTER_PATTERN = re.compile(r"^([^()]+?)([~<>=]+)(.*)$")
    EXTENSIBLE_PATTERN = re.compile(r"^([^:]*):?([^:]*):?([^:]*):?=(.*)$")

    def __init__(self, filter_string: str | None = None) -> None:
        """Initialize LDAP filter.

        Args:
            filter_string: LDAP filter string to parse (optional)

        """
        self._root_component: FilterComponent | None = None
        self._original_string = filter_string
        self._validation_errors: list[str] = []

        if filter_string:
            try:
                self._root_component = self._parse_filter(filter_string.strip())
            except Exception as e:
                self._validation_errors.append(f"Filter parsing error: {e}")

    def _parse_filter(self, filter_str: str) -> FilterComponent:
        """Parse LDAP filter string into components.

        Args:
            filter_str: Filter string to parse

        Returns:
            Parsed filter component

        """
        # Remove outer parentheses
        match = self.FILTER_PATTERN.match(filter_str)
        if not match:
            msg = f"Invalid filter format: {filter_str}"
            raise ValueError(msg)

        inner_filter = match.group(1)

        # Check for logical operators
        if inner_filter.startswith("&"):
            return self._parse_logical_filter(inner_filter[1:], FilterType.AND)
        if inner_filter.startswith("|"):
            return self._parse_logical_filter(inner_filter[1:], FilterType.OR)
        if inner_filter.startswith("!"):
            subfilter = self._parse_filter(f"({inner_filter[1:]})")
            return FilterComponent(
                filter_type=FilterType.NOT,
                subfilters=[subfilter],
            )
        return self._parse_simple_filter(inner_filter)

    def _parse_logical_filter(
        self,
        filter_str: str,
        op_type: FilterType,
    ) -> FilterComponent:
        """Parse logical filter (AND/OR).

        Args:
            filter_str: Filter string without operator prefix
            op_type: Logical operation type

        Returns:
            Parsed logical filter component

        """
        subfilters = []
        i = 0

        while i < len(filter_str):
            if filter_str[i] == "(":
                # Find matching closing parenthesis
                depth = 1
                start = i
                i += 1

                while i < len(filter_str) and depth > 0:
                    if filter_str[i] == "(":
                        depth += 1
                    elif filter_str[i] == ")":
                        depth -= 1
                    i += 1

                if depth != 0:
                    msg = "Unmatched parentheses in filter"
                    raise ValueError(msg)

                # Parse subfilter
                subfilter_str = filter_str[start:i]
                subfilter = self._parse_filter(subfilter_str)
                subfilters.append(subfilter)
            else:
                # Skip whitespace
                while i < len(filter_str) and filter_str[i].isspace():
                    i += 1
                if i < len(filter_str):
                    msg = f"Unexpected character in logical filter: {filter_str[i]}"
                    raise ValueError(msg)

        return FilterComponent(
            filter_type=op_type,
            subfilters=subfilters,
        )

    def _parse_simple_filter(self, filter_str: str) -> FilterComponent:
        """Parse simple attribute filter.

        Args:
            filter_str: Simple filter string

        Returns:
            Parsed simple filter component

        """
        # Check for extensible matching
        if ":" in filter_str and "=" in filter_str:
            ext_match = self.EXTENSIBLE_PATTERN.match(filter_str)
            if ext_match:
                attr, dn_flag, rule, value = ext_match.groups()
                return FilterComponent(
                    filter_type=FilterType.EXTENSIBLE,
                    attribute=attr or None,
                    value=value,
                    matching_rule=rule or None,
                    dn_attributes=dn_flag == "dn",
                )

        # Parse simple assertion
        match = self.SIMPLE_FILTER_PATTERN.match(filter_str)
        if not match:
            msg = f"Invalid simple filter format: {filter_str}"
            raise ValueError(msg)

        attribute, operator, value = match.groups()

        # Determine filter type based on operator and value
        if operator == "=" and value == "*":
            filter_type = FilterType.PRESENT
            value = None
        elif operator == "=" and ("*" in value):
            filter_type = FilterType.SUBSTRING
        elif operator == "=":
            filter_type = FilterType.EQUALS
        elif operator == ">=":
            filter_type = FilterType.GREATER_EQUAL
        elif operator == "<=":
            filter_type = FilterType.LESS_EQUAL
        elif operator == "~=":
            filter_type = FilterType.APPROX
        else:
            msg = f"Unknown filter operator: {operator}"
            raise ValueError(msg)

        return FilterComponent(
            filter_type=filter_type,
            attribute=attribute.strip(),
            value=value,
        )

    def to_string(self) -> str:
        """Convert filter back to string representation.

        Returns:
            LDAP filter string

        """
        if not self._root_component:
            return "(objectClass=*)"  # Default filter

        return self._component_to_string(self._root_component)

    def _component_to_string(self, component: FilterComponent) -> str:
        """Convert filter component to string.

        Args:
            component: Filter component to convert

        Returns:
            String representation of component

        """
        if component.filter_type == FilterType.AND:
            subfilter_strings = [
                self._component_to_string(sf) for sf in component.subfilters
            ]
            return f"(&{''.join(subfilter_strings)})"

        if component.filter_type == FilterType.OR:
            subfilter_strings = [
                self._component_to_string(sf) for sf in component.subfilters
            ]
            return f"(|{''.join(subfilter_strings)})"

        if component.filter_type == FilterType.NOT:
            if component.subfilters:
                subfilter_str = self._component_to_string(component.subfilters[0])
                return f"(!{subfilter_str[1:-1]})"  # Remove outer parens
            return "(!(objectClass=*))"

        if component.filter_type == FilterType.EQUALS:
            return f"({component.attribute}={component.value or ''})"

        if component.filter_type == FilterType.SUBSTRING:
            return f"({component.attribute}={component.value or ''})"

        if component.filter_type == FilterType.GREATER_EQUAL:
            return f"({component.attribute}>={component.value or ''})"

        if component.filter_type == FilterType.LESS_EQUAL:
            return f"({component.attribute}<={component.value or ''})"

        if component.filter_type == FilterType.PRESENT:
            return f"({component.attribute}=*)"

        if component.filter_type == FilterType.APPROX:
            return f"({component.attribute}~={component.value or ''})"

        # FilterType.EXTENSIBLE
        parts = []
        if component.attribute:
            parts.append(component.attribute)
        if component.dn_attributes:
            parts.append("dn")
        if component.matching_rule:
            parts.append(component.matching_rule)

        attr_part = ":".join(parts) if parts else ""
        return f"({attr_part}:={component.value or ''})"

    def is_valid(self) -> bool:
        """Check if filter is valid.

        Returns:
            True if filter is valid

        """
        return len(self._validation_errors) == 0 and self._root_component is not None

    def get_validation_errors(self) -> list[str]:
        """Get validation errors.

        Returns:
            List of validation error messages

        """
        return self._validation_errors.copy()

    def get_attributes(self) -> set[str]:
        """Get all attributes referenced in filter.

        Returns:
            Set of attribute names

        """
        if not self._root_component:
            return set()

        return self._root_component.get_attributes()

    def count_conditions(self) -> int:
        """Count total number of conditions in filter.

        Returns:
            Number of filter conditions

        """
        if not self._root_component:
            return 0

        return self._root_component.count_conditions()

    def optimize(self) -> LDAPFilter:
        """Optimize filter for better performance.

        Returns:
            Optimized filter

        """
        if not self._root_component:
            return LDAPFilter()

        optimized_component = self._optimize_component(self._root_component)

        optimized_filter = LDAPFilter()
        optimized_filter._root_component = optimized_component
        return optimized_filter

    def _optimize_component(self, component: FilterComponent) -> FilterComponent:
        """Optimize individual filter component.

        Args:
            component: Component to optimize

        Returns:
            Optimized component

        """
        # Recursively optimize subfilters
        if component.subfilters:
            optimized_subfilters = [
                self._optimize_component(sf) for sf in component.subfilters
            ]
        else:
            optimized_subfilters = []

        # Apply optimization rules
        if component.filter_type == FilterType.AND:
            # Remove redundant conditions
            unique_subfilters = []
            seen_conditions = set()

            for sf in optimized_subfilters:
                sf_str = self._component_to_string(sf)
                if sf_str not in seen_conditions:
                    unique_subfilters.append(sf)
                    seen_conditions.add(sf_str)

            # Flatten nested AND operations
            flattened_subfilters = []
            for sf in unique_subfilters:
                if sf.filter_type == FilterType.AND:
                    flattened_subfilters.extend(sf.subfilters)
                else:
                    flattened_subfilters.append(sf)

            return FilterComponent(
                filter_type=FilterType.AND,
                subfilters=flattened_subfilters,
            )

        if component.filter_type == FilterType.OR:
            # Similar optimization for OR
            unique_subfilters = []
            seen_conditions = set()

            for sf in optimized_subfilters:
                sf_str = self._component_to_string(sf)
                if sf_str not in seen_conditions:
                    unique_subfilters.append(sf)
                    seen_conditions.add(sf_str)

            # Flatten nested OR operations
            flattened_subfilters = []
            for sf in unique_subfilters:
                if sf.filter_type == FilterType.OR:
                    flattened_subfilters.extend(sf.subfilters)
                else:
                    flattened_subfilters.append(sf)

            return FilterComponent(
                filter_type=FilterType.OR,
                subfilters=flattened_subfilters,
            )

        # Return simple filter as-is with optimized subfilters
        return FilterComponent(
            filter_type=component.filter_type,
            attribute=component.attribute,
            value=component.value,
            subfilters=optimized_subfilters,
            matching_rule=component.matching_rule,
            dn_attributes=component.dn_attributes,
            negated=component.negated,
        )

    def negate(self) -> LDAPFilter:
        """Create negated version of filter.

        Returns:
            Negated filter

        """
        if not self._root_component:
            return LDAPFilter()

        negated_filter = LDAPFilter()
        negated_filter._root_component = FilterComponent(
            filter_type=FilterType.NOT,
            subfilters=[self._root_component],
        )

        return negated_filter

    def combine_and(self, other: LDAPFilter) -> LDAPFilter:
        """Combine with another filter using AND.

        Args:
            other: Other filter to combine

        Returns:
            Combined filter

        """
        if not self._root_component or not other._root_component:
            return LDAPFilter()

        combined_filter = LDAPFilter()
        combined_filter._root_component = FilterComponent(
            filter_type=FilterType.AND,
            subfilters=[self._root_component, other._root_component],
        )

        return combined_filter

    def combine_or(self, other: LDAPFilter) -> LDAPFilter:
        """Combine with another filter using OR.

        Args:
            other: Other filter to combine

        Returns:
            Combined filter

        """
        if not self._root_component or not other._root_component:
            return LDAPFilter()

        combined_filter = LDAPFilter()
        combined_filter._root_component = FilterComponent(
            filter_type=FilterType.OR,
            subfilters=[self._root_component, other._root_component],
        )

        return combined_filter

    @staticmethod
    def builder() -> FilterBuilder:
        """Create filter builder for programmatic construction.

        Returns:
            FilterBuilder instance

        """
        return FilterBuilder()

    def __str__(self) -> str:
        """String representation."""
        return self.to_string()

    def __repr__(self) -> str:
        """Detailed string representation."""
        return f"LDAPFilter('{self.to_string()}')"

    def __eq__(self, other: object) -> bool:
        """Check filter equality."""
        if not isinstance(other, LDAPFilter):
            return False
        return self.to_string() == other.to_string()

    def __hash__(self) -> int:
        """Hash for LDAPFilter."""
        return hash(self.to_string())


class FilterBuilder:
    """Builder for programmatic filter construction."""

    def equals(self, attribute: str, value: str) -> LDAPFilter:
        """Create equals filter."""
        filter_obj = LDAPFilter()
        filter_obj._root_component = FilterComponent(
            filter_type=FilterType.EQUALS,
            attribute=attribute,
            value=value,
        )
        return filter_obj

    def starts_with(self, attribute: str, prefix: str) -> LDAPFilter:
        """Create starts-with substring filter."""
        filter_obj = LDAPFilter()
        filter_obj._root_component = FilterComponent(
            filter_type=FilterType.SUBSTRING,
            attribute=attribute,
            value=f"{prefix}*",
        )
        return filter_obj

    def ends_with(self, attribute: str, suffix: str) -> LDAPFilter:
        """Create ends-with substring filter."""
        filter_obj = LDAPFilter()
        filter_obj._root_component = FilterComponent(
            filter_type=FilterType.SUBSTRING,
            attribute=attribute,
            value=f"*{suffix}",
        )
        return filter_obj

    def contains(self, attribute: str, substring: str) -> LDAPFilter:
        """Create contains substring filter."""
        filter_obj = LDAPFilter()
        filter_obj._root_component = FilterComponent(
            filter_type=FilterType.SUBSTRING,
            attribute=attribute,
            value=f"*{substring}*",
        )
        return filter_obj

    def present(self, attribute: str) -> LDAPFilter:
        """Create presence filter."""
        filter_obj = LDAPFilter()
        filter_obj._root_component = FilterComponent(
            filter_type=FilterType.PRESENT,
            attribute=attribute,
        )
        return filter_obj

    def greater_equal(self, attribute: str, value: str) -> LDAPFilter:
        """Create greater-or-equal filter."""
        filter_obj = LDAPFilter()
        filter_obj._root_component = FilterComponent(
            filter_type=FilterType.GREATER_EQUAL,
            attribute=attribute,
            value=value,
        )
        return filter_obj

    def less_equal(self, attribute: str, value: str) -> LDAPFilter:
        """Create less-or-equal filter."""
        filter_obj = LDAPFilter()
        filter_obj._root_component = FilterComponent(
            filter_type=FilterType.LESS_EQUAL,
            attribute=attribute,
            value=value,
        )
        return filter_obj

    def approx(self, attribute: str, value: str) -> LDAPFilter:
        """Create approximate match filter."""
        filter_obj = LDAPFilter()
        filter_obj._root_component = FilterComponent(
            filter_type=FilterType.APPROX,
            attribute=attribute,
            value=value,
        )
        return filter_obj

    def extensible(
        self,
        attribute: str | None,
        value: str,
        matching_rule: str | None = None,
        dn_attributes: bool = False,
    ) -> LDAPFilter:
        """Create extensible match filter."""
        filter_obj = LDAPFilter()
        filter_obj._root_component = FilterComponent(
            filter_type=FilterType.EXTENSIBLE,
            attribute=attribute,
            value=value,
            matching_rule=matching_rule,
            dn_attributes=dn_attributes,
        )
        return filter_obj

    def and_(self, filters: list[LDAPFilter]) -> LDAPFilter:
        """Create AND filter."""
        filter_obj = LDAPFilter()
        components = [f._root_component for f in filters if f._root_component]
        filter_obj._root_component = FilterComponent(
            filter_type=FilterType.AND,
            subfilters=components,
        )
        return filter_obj

    def or_(self, filters: list[LDAPFilter]) -> LDAPFilter:
        """Create OR filter."""
        filter_obj = LDAPFilter()
        components = [f._root_component for f in filters if f._root_component]
        filter_obj._root_component = FilterComponent(
            filter_type=FilterType.OR,
            subfilters=components,
        )
        return filter_obj

    def not_(self, filter_obj: LDAPFilter) -> LDAPFilter:
        """Create NOT filter."""
        negated_filter = LDAPFilter()
        if filter_obj._root_component:
            negated_filter._root_component = FilterComponent(
                filter_type=FilterType.NOT,
                subfilters=[filter_obj._root_component],
            )
        return negated_filter


class FilterParser:
    """Advanced filter parsing utilities."""

    @staticmethod
    def parse_filter_string(filter_str: str) -> LDAPFilter:
        """Parse filter string with enhanced error handling."""
        return LDAPFilter(filter_str)

    @staticmethod
    def validate_filter_syntax(filter_str: str) -> list[str]:
        """Validate filter syntax and return errors."""
        try:
            filter_obj = LDAPFilter(filter_str)
            return filter_obj.get_validation_errors()
        except Exception as e:
            return [str(e)]

    @staticmethod
    def extract_filter_attributes(filter_str: str) -> set[str]:
        """Extract all attributes from filter string."""
        try:
            filter_obj = LDAPFilter(filter_str)
            return filter_obj.get_attributes()
        except Exception:
            return set()


# Convenience functions
def parse_ldap_filter(filter_str: str) -> LDAPFilter:
    """Parse LDAP filter string.

    Args:
        filter_str: LDAP filter string

    Returns:
        Parsed LDAPFilter object

    """
    return LDAPFilter(filter_str)


def validate_filter(filter_str: str) -> bool:
    """Validate LDAP filter string.

    Args:
        filter_str: Filter string to validate

    Returns:
        True if filter is valid

    """
    try:
        filter_obj = LDAPFilter(filter_str)
        return filter_obj.is_valid()
    except Exception:
        return False


def optimize_filter(filter_str: str) -> str:
    """Optimize LDAP filter string.

    Args:
        filter_str: Filter string to optimize

    Returns:
        Optimized filter string

    """
    try:
        filter_obj = LDAPFilter(filter_str)
        if filter_obj.is_valid():
            optimized = filter_obj.optimize()
            return str(optimized)
        return filter_str
    except Exception:
        return filter_str


def combine_filters_and(filters: list[str]) -> str:
    """Combine multiple filters with AND operation.

    Args:
        filters: List of filter strings

    Returns:
        Combined filter string

    """
    if not filters:
        return "(objectClass=*)"

    if len(filters) == 1:
        return filters[0]

    builder = FilterBuilder()
    filter_objects = [LDAPFilter(f) for f in filters]
    combined = builder.and_(filter_objects)
    return str(combined)


def combine_filters_or(filters: list[str]) -> str:
    """Combine multiple filters with OR operation.

    Args:
        filters: List of filter strings

    Returns:
        Combined filter string

    """
    if not filters:
        return "(objectClass=*)"

    if len(filters) == 1:
        return filters[0]

    builder = FilterBuilder()
    filter_objects = [LDAPFilter(f) for f in filters]
    combined = builder.or_(filter_objects)
    return str(combined)


# TODO: Integration points for implementation:
#
# 1. Advanced Filter Optimization:
#    - Index-aware filter optimization
#    - Cost-based filter reordering
#    - Query plan optimization
#
# 2. Filter Validation and Security:
#    - Injection attack prevention
#    - Filter complexity limits
#    - Security policy enforcement
#
# 3. Schema Integration:
#    - Schema-aware attribute validation
#    - Matching rule integration
#    - Syntax validation for attribute types
#
# 4. Performance Optimization:
#    - Efficient filter parsing algorithms
#    - Filter caching and reuse
#    - Optimized string operations
#
# 5. Extended Filter Features:
#    - Custom matching rules support
#    - Advanced extensible matching
#    - Vendor-specific filter extensions
#
# 6. Integration with Search Operations:
#    - Direct integration with search operations
#    - Filter-based result processing
#    - Dynamic filter construction
#
# 7. Testing Requirements:
#    - Unit tests for all filter functionality
#    - Performance tests for complex filters
#    - Security tests for filter injection
#    - Compliance tests with RFC 4515
