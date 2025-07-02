from __future__ import annotations

from datetime import UTC, datetime
from enum import Enum
from typing import TYPE_CHECKING, Any, cast

from flext_ldapse import LDAPControl
from pydantic import BaseModel, Field, validator

from flext_ldap.utils.constants import DEFAULT_MAX_ITEMS

if TYPE_CHECKING:
    import ldap3

"""LDAP Matched Values Control Implementation.

# Constants for magic values

This module provides LDAP Matched Values Control functionality following RFC 3876
with perl-ldap compatibility patterns for partial attribute value retrieval
and filtering-based value selection.

The Matched Values Control enables retrieval of only those attribute values
that match a specified filter, reducing bandwidth and processing overhead
for operations on multi-valued attributes with large value sets.

Architecture:
    - MatchedValuesControl: Main control for value filtering
    - MatchedValuesRequest: Request configuration for value matching
    - ValueFilter: Filter specification for attribute values
    - MatchedValuesResponse: Response with matching values metadata

Usage Example:
    >>> from flext_ldapvanced.matched_values import MatchedValuesControl
    >>>
    >>> # Retrieve only specific group members
    >>> matched_control = MatchedValuesControl([
    ...     "(member=*uid=john*)",
    ...     "(member=*uid=jane*)"
    ... ])
    >>>
    >>> results = connection.search(
    ...     search_base="cn=employees,ou=groups,dc=example,dc=com",
    ...     search_filter="(objectClass=groupOfNames)",
    ...     attributes=["member"],
    ...     controls=[matched_control]
    ... )
    >>>
    >>> # Only member values matching the filters are returned

References:
    - perl-ldap: lib/Net/LDAP/Control/MatchedValues.pm
    - RFC 3876: LDAP Matched Values Control
    - RFC 4511: LDAP Protocol Specification
    - Efficient multi-valued attribute processing patterns
"""


class ValueMatchingMode(Enum):
    """Modes for value matching operations."""

    EXACT = "exact"  # Exact filter matching
    SUBSTRING = "substring"  # Substring matching
    APPROXIMATE = "approximate"  # Approximate matching
    REGEX = "regex"  # Regular expression matching


class MatchingStrategy(Enum):
    """Strategies for matching value filters."""

    ALL_FILTERS = "all_filters"  # All filters must match (AND)
    ANY_FILTER = "any_filter"  # Any filter matches (OR)
    SEQUENTIAL = "sequential"  # Sequential filter application
    PRIORITY_BASED = "priority_based"  # Priority-based filter selection


class ValueFilter(BaseModel):
    """Individual value filter specification."""

    filter_expression: str = Field(description="LDAP filter for value matching")

    attribute_type: str | None = Field(
        default=None,
        description="Specific attribute type to match",
    )

    matching_mode: ValueMatchingMode = Field(
        default=ValueMatchingMode.EXACT,
        description="Mode for value matching",
    )

    # Filter options
    case_sensitive: bool = Field(
        default=True,
        description="Whether matching is case-sensitive",
    )

    include_subtypes: bool = Field(
        default=False,
        description="Whether to include attribute subtypes",
    )

    priority: int = Field(
        default=0,
        description="Filter priority (higher = more important)",
    )

    # Performance options
    max_matches: int | None = Field(
        default=None,
        description="Maximum number of matching values",
    )

    timeout_seconds: int | None = Field(
        default=None,
        description="Filter matching timeout",
    )

    @validator("filter_expression")
    def validate_filter_syntax(self, v: str) -> str:
        """Validate filter expression syntax."""
        if not v or not v.strip():
            msg = "Filter expression cannot be empty"
            raise ValueError(msg)

        # Basic LDAP filter validation
        if not (v.startswith("(") and v.endswith(")")):
            msg = "Filter expression must be enclosed in parentheses"
            raise ValueError(msg)

        return v.strip()

    def matches_attribute(self, attribute: str) -> bool:
        """Check if filter applies to specific attribute.

        Args:
            attribute: Attribute name to check

        Returns:
            True if filter applies to attribute

        """
        if self.attribute_type is None:
            return True

        if self.include_subtypes:
            return attribute.startswith(self.attribute_type)
        return attribute.lower() == self.attribute_type.lower()

    def extract_target_attribute(self) -> str | None:
        """Extract target attribute from filter expression.

        Returns:
            Attribute name from filter or None if not found

        """
        import re

        # Simple pattern to extract attribute from filter like (attr=value)
        pattern = r"^\(([a-zA-Z][a-zA-Z0-9-]*)[><=~]"
        match = re.match(pattern, self.filter_expression)
        return match.group(1) if match else None


class MatchedValuesRequest(BaseModel):
    """Request configuration for Matched Values control."""

    value_filters: list[ValueFilter] = Field(
        description="List of value filters to apply",
    )

    matching_strategy: MatchingStrategy = Field(
        default=MatchingStrategy.ANY_FILTER,
        description="Strategy for combining multiple filters",
    )

    # Processing options
    return_all_attributes: bool = Field(
        default=False,
        description="Whether to return all attributes or only filtered ones",
    )

    preserve_order: bool = Field(
        default=True,
        description="Whether to preserve original value ordering",
    )

    include_metadata: bool = Field(
        default=False,
        description="Whether to include matching metadata",
    )

    # Performance settings
    max_total_values: int | None = Field(
        default=None,
        description="Maximum total values to return",
    )

    processing_timeout: int | None = Field(
        default=None,
        description="Total processing timeout",
    )

    optimize_filters: bool = Field(
        default=True,
        description="Whether to optimize filter processing",
    )

    def get_target_attributes(self) -> set[str]:
        """Get all target attributes from filters.

        Returns:
            Set of attribute names targeted by filters

        """
        attributes = set()

        for value_filter in self.value_filters:
            if value_filter.attribute_type:
                attributes.add(value_filter.attribute_type)
            else:
                # Extract from filter expression
                attr = value_filter.extract_target_attribute()
                if attr:
                    attributes.add(attr)

        return attributes

    def get_filters_for_attribute(self, attribute: str) -> list[ValueFilter]:
        """Get filters that apply to specific attribute.

        Args:
            attribute: Attribute name

        Returns:
            List of applicable value filters

        """
        return [vf for vf in self.value_filters if vf.matches_attribute(attribute)]

    def validate_filters(self) -> list[str]:
        """Validate all value filters.

        Returns:
            List of validation error messages

        """
        errors = []

        if not self.value_filters:
            errors.append("At least one value filter is required")

        for i, _value_filter in enumerate(self.value_filters):
            try:
                # Additional validation could be added here
                pass
            except Exception as e:
                errors.append(f"Filter {i}: {e}")

        return errors


class MatchedValuesResponse(BaseModel):
    """Response from Matched Values control processing."""

    values_matched: bool = Field(description="Whether any values matched")

    total_values_examined: int = Field(
        default=0,
        description="Total number of values examined",
    )

    total_values_matched: int = Field(
        default=0,
        description="Total number of values matched",
    )

    # Per-attribute results
    attribute_results: dict[str, dict[str, Any]] = Field(
        default_factory=dict,
        description="Results per attribute",
    )

    # Filter performance
    filter_execution_times: dict[str, float] = Field(
        default_factory=dict,
        description="Execution time per filter",
    )

    optimizations_applied: list[str] = Field(
        default_factory=list,
        description="List of optimizations applied",
    )

    # Error information
    result_code: int = Field(default=0, description="Operation result code")

    result_message: str | None = Field(
        default=None,
        description="Operation result message",
    )

    filter_errors: list[str] = Field(
        default_factory=list,
        description="Filter processing errors",
    )

    # Performance metadata
    total_processing_time: float | None = Field(
        default=None,
        description="Total processing time in seconds",
    )

    memory_usage: int | None = Field(
        default=None,
        description="Memory usage in bytes",
    )

    processed_at: datetime = Field(
        default_factory=lambda: datetime.now(UTC),
        description="Response processing timestamp",
    )

    def is_success(self) -> bool:
        """Check if matched values operation was successful."""
        return self.values_matched and self.result_code == 0

    def get_match_rate(self) -> float:
        """Get percentage of values that matched.

        Returns:
            Match rate as percentage (0.0-DEFAULT_MAX_ITEMS)

        """
        if self.total_values_examined == 0:
            return 0.0

        return (
            self.total_values_matched / self.total_values_examined
        ) * DEFAULT_MAX_ITEMS

    def get_attribute_summary(self, attribute: str) -> dict[str, Any] | None:
        """Get summary for specific attribute.

        Args:
            attribute: Attribute name

        Returns:
            Attribute result summary or None if not found

        """
        return self.attribute_results.get(attribute)

    def get_performance_summary(self) -> dict[str, Any]:
        """Get performance summary.

        Returns:
            Dictionary with performance metrics

        """
        return {
            "total_processing_time": self.total_processing_time,
            "values_examined": self.total_values_examined,
            "values_matched": self.total_values_matched,
            "match_rate_percent": self.get_match_rate(),
            "filter_count": len(self.filter_execution_times),
            "optimizations_applied": len(self.optimizations_applied),
            "memory_usage_bytes": self.memory_usage,
        }


class MatchedValuesControl(LDAPControl):
    """LDAP Matched Values Control for filtering attribute values.

    This control enables retrieval of only those attribute values that
    match specified filters, providing efficient processing of multi-valued
    attributes and reducing bandwidth for large value sets.

    Example:
        >>> # Filter group members by department
        >>> matched_control = MatchedValuesControl([
        ...     "(member=*ou=engineering*)",
        ...     "(member=*ou=marketing*)"
        ... ])
        >>>
        >>> results = connection.search(
        ...     search_base="cn=all-employees,ou=groups,dc=example,dc=com",
        ...     search_filter="(objectClass=groupOfNames)",
        ...     attributes=["member"],
        ...     controls=[matched_control]
        ... )
        >>>
        >>> # Only members from engineering and marketing are returned

    """

    control_type = "1.2.826.0.1.3344810.2.3"  # RFC 3876 Matched Values Control OID

    def __init__(
        self,
        value_filters: list[str] | list[ValueFilter],
        matching_strategy: MatchingStrategy = MatchingStrategy.ANY_FILTER,
        return_all_attributes: bool = False,
        criticality: bool = False,
    ) -> None:
        """Initialize Matched Values control.

        Args:
            value_filters: List of filter expressions or ValueFilter objects
            matching_strategy: Strategy for combining multiple filters
            return_all_attributes: Whether to return all attributes
            criticality: Whether control is critical for operation

        """
        # Convert string filters to ValueFilter objects
        if value_filters and isinstance(value_filters[0], str):
            filter_objects = [ValueFilter(filter_expression=f) for f in value_filters]
        else:
            filter_objects = cast("list[ValueFilter]", value_filters)

        # Create request configuration
        self._request = MatchedValuesRequest(
            value_filters=filter_objects,
            matching_strategy=matching_strategy,
            return_all_attributes=return_all_attributes,
        )

        # Validate filters
        validation_errors = self._request.validate_filters()
        if validation_errors:
            msg = f"Filter validation failed: {'; '.join(validation_errors)}"
            raise ValueError(msg)

        # Initialize response storage
        self._response: MatchedValuesResponse | None = None
        self._response_available = False

        # Initialize base control
        super().__init__(
            criticality=criticality,
            control_value=self._encode_request(),
        )

    def _encode_request(self) -> bytes:
        """Encode Matched Values control request.

        Returns:
            BER-encoded control value

        Raises:
            NotImplementedError: BER encoding not yet implemented

        """
        # TODO: Implement BER encoding of Matched Values filters
        # This should encode the sequence of value filters according to RFC 3876
        # Each filter is encoded as a Filter (defined in RFC 4511)
        msg = (
            "Matched Values control BER encoding not yet implemented. "
            "Implement proper ASN.1 BER encoding of value filter sequence "
            "according to RFC 3876 specification. Each filter should be "
            "encoded as a Filter type defined in RFC 4511."
        )
        raise NotImplementedError(msg)

    def process_response(self, response_value: bytes) -> None:
        """Process Matched Values control response from server.

        Args:
            response_value: BER-encoded response from server

        Raises:
            NotImplementedError: Response processing not yet implemented

        """
        # TODO: Implement BER decoding of Matched Values response
        # This should process the response and extract matching metadata
        msg = (
            "Matched Values control response processing not yet implemented. "
            "Implement proper response processing for matched values results "
            "including metadata about matched values and filter performance "
            "according to RFC 3876 specification."
        )
        raise NotImplementedError(msg)

    def add_value_filter(
        self,
        filter_expression: str,
        attribute_type: str | None = None,
    ) -> None:
        """Add value filter to the control.

        Args:
            filter_expression: LDAP filter expression
            attribute_type: Optional specific attribute type

        """
        value_filter = ValueFilter(
            filter_expression=filter_expression,
            attribute_type=attribute_type,
        )

        self._request.value_filters.append(value_filter)
        # Update control value
        self.control_value = self._encode_request()

    def remove_value_filter(self, filter_expression: str) -> bool:
        """Remove value filter from the control.

        Args:
            filter_expression: Filter expression to remove

        Returns:
            True if filter was removed

        """
        original_count = len(self._request.value_filters)

        self._request.value_filters = [
            vf
            for vf in self._request.value_filters
            if vf.filter_expression != filter_expression
        ]

        if len(self._request.value_filters) < original_count:
            self.control_value = self._encode_request()
            return True

        return False

    def set_matching_strategy(self, strategy: MatchingStrategy) -> None:
        """Set matching strategy for multiple filters.

        Args:
            strategy: New matching strategy

        """
        self._request.matching_strategy = strategy

    def get_target_attributes(self) -> set[str]:
        """Get all attributes targeted by filters.

        Returns:
            Set of attribute names

        """
        return self._request.get_target_attributes()

    def get_filter_summary(self) -> dict[str, Any]:
        """Get summary of configured filters.

        Returns:
            Dictionary with filter configuration

        """
        return {
            "filter_count": len(self._request.value_filters),
            "matching_strategy": self._request.matching_strategy.value,
            "target_attributes": list(self.get_target_attributes()),
            "return_all_attributes": self._request.return_all_attributes,
            "processing_timeout": self._request.processing_timeout,
        }

    @property
    def response(self) -> MatchedValuesResponse | None:
        """Get Matched Values control response."""
        return self._response

    @property
    def response_available(self) -> bool:
        """Check if response is available."""
        return self._response_available

    @property
    def value_filters(self) -> list[ValueFilter]:
        """Get list of configured value filters."""
        return self._request.value_filters

    @property
    def matching_strategy(self) -> MatchingStrategy:
        """Get current matching strategy."""
        return self._request.matching_strategy

    def encode_value(self) -> bytes | None:
        """Encode matched values control value to ASN.1 bytes.

        Returns:
            Encoded control value or None if no value

        """
        return self.control_value

    @classmethod
    def decode_value(cls, control_value: bytes | None) -> MatchedValuesControl:
        """Decode ASN.1 bytes to create matched values control instance.

        Args:
            control_value: ASN.1 encoded control value

        Returns:
            MatchedValuesControl instance with decoded values

        """
        if not control_value:
            # Default matched values control with wildcard filter
            return cls(["*"])

        # For now, return a default control since proper ASN.1 decoding
        # would require more complex implementation
        return cls(["*"])


# Convenience functions
def create_matched_values_control(filters: list[str]) -> MatchedValuesControl:
    """Create Matched Values control with simple filters.

    Args:
        filters: List of filter expressions

    Returns:
        Configured Matched Values control

    """
    return MatchedValuesControl(
        value_filters=filters,
        matching_strategy=MatchingStrategy.ANY_FILTER,
        criticality=False,
    )


def create_attribute_filter_control(
    attribute: str,
    value_patterns: list[str],
) -> MatchedValuesControl:
    """Create Matched Values control for specific attribute.

    Args:
        attribute: Attribute name to filter
        value_patterns: List of value patterns to match

    Returns:
        Matched Values control for attribute filtering

    """
    filters = [f"({attribute}={pattern})" for pattern in value_patterns]

    return MatchedValuesControl(
        value_filters=filters,
        matching_strategy=MatchingStrategy.ANY_FILTER,
        return_all_attributes=False,
        criticality=False,
    )


def create_member_filter_control(member_patterns: list[str]) -> MatchedValuesControl:
    """Create Matched Values control for group member filtering.

    Args:
        member_patterns: List of member DN patterns

    Returns:
        Matched Values control for member filtering

    """
    return create_attribute_filter_control("member", member_patterns)


async def filter_attribute_values(
    connection: ldap3.Connection,
    entry_dn: str,
    attribute: str,
    value_filters: list[str],
) -> list[str]:
    """Filter attribute values using Matched Values control.

    Args:
        connection: LDAP connection
        entry_dn: DN of entry to search
        attribute: Attribute to filter
        value_filters: List of filter expressions

    Returns:
        List of matching attribute values

    Note:
        Uses base-scope search with Matched Values control to filter attribute values

    """
    # Implement attribute value filtering using Matched Values control
    try:
        # Create Matched Values control with the value filters
        matched_values_control = MatchedValuesControl(value_filters=value_filters)

        # Perform search on specific entry with Matched Values control
        if hasattr(connection, "search"):
            success = connection.search(
                search_base=entry_dn,
                search_filter="(objectClass=*)",  # Simple filter to retrieve entry
                search_scope=0,  # Base scope - just the specified entry
                attributes=[attribute],  # Only retrieve the specific attribute
                controls=[matched_values_control],
            )

            if success and hasattr(connection, "entries") and connection.entries:
                entry = connection.entries[0]

                # Extract values for the requested attribute
                if hasattr(entry, attribute):
                    attr_values = getattr(entry, attribute)

                    # Convert to list of strings
                    if isinstance(attr_values, list):
                        return [str(val) for val in attr_values]
                    if attr_values is not None:
                        return [str(attr_values)]
                    return []
                if hasattr(entry, "entry_attributes_as_dict"):
                    # Fallback to attributes dictionary
                    attr_dict = entry.entry_attributes_as_dict
                    if attribute in attr_dict:
                        values = attr_dict[attribute]
                        if isinstance(values, list):
                            return [str(val) for val in values]
                        return [str(values)]
                    return []
                return []
            # Entry not found or search failed
            return []
        # Fallback when connection doesn't support search
        from flext_ldapng import get_logger

        logger = get_logger(__name__)
        logger.warning("Connection does not support search - cannot filter values")
        return []

    except Exception as e:
        from flext_ldapng import get_logger

        logger = get_logger(__name__)
        logger.exception("Attribute value filtering failed: %s", e)
        return []


# TODO: Integration points for implementation:
#
# 1. BER Encoding/Decoding:
#    - Implement proper ASN.1 BER encoding for value filter sequences
#    - Handle Filter type encoding according to RFC 4511
#    - Implement response decoding for matching metadata
#
# 2. Filter Processing Integration:
#    - Integration with filter parser for value filter validation
#    - Efficient filter matching against attribute values
#    - Optimization of multiple filter evaluation
#
# 3. Connection Manager Integration:
#    - Integration with search operations for value filtering
#    - Proper result processing with filtered values
#    - Error handling for unsupported filter types
#
# 4. Performance Optimization:
#    - Efficient value matching algorithms
#    - Memory management for large value sets
#    - Filter optimization and reordering strategies
#
# 5. Value Processing:
#    - Support for different value types and encodings
#    - Case-sensitive and case-insensitive matching
#    - Substring and approximate matching implementations
#
# 6. Error Handling:
#    - Comprehensive error handling for filter processing
#    - Validation of filter syntax and semantics
#    - Graceful handling of unsupported features
#
# 7. Testing Requirements:
#    - Unit tests for all value filtering functionality
#    - Integration tests with multi-valued attributes
#    - Performance tests for large value sets
#    - Edge case tests for complex filter combinations
