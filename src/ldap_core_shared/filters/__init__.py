"""LDAP Filter Operations Module.

This module provides comprehensive LDAP filter functionality following perl-ldap
Net::LDAP::Filter architecture with enterprise-grade Python enhancements.

LDAP filters are essential for directory queries, providing precise control over
search criteria and result sets. This module enables building, parsing, and
validating complex LDAP filter expressions programmatically.

Architecture:
    - FilterBuilder: Fluent API for constructing complex filters
    - FilterParser: Parse filter strings into structured representations
    - FilterValidator: Validate filter syntax and semantics
    - FilterOperators: Standard LDAP filter operators and functions

Usage Example:
    >>> from ldap_core_shared.filters import FilterBuilder
    >>> # Build complex filter using fluent API
    >>> filter_expr = (
    ...     FilterBuilder()
    ...     .and_()
    ...     .equal("objectClass", "person")
    ...     .or_()
    ...     .contains("cn", "john")
    ...     .starts_with("mail", "j")
    ...     .end()
    ...     .end()
    ...     .build()
    ... )
    >>> print(filter_expr)  # (&(objectClass=person)(|(cn=*john*)(mail=j*)))

References:
    - perl-ldap: lib/Net/LDAP/Filter.pm
    - RFC 4515: Lightweight Directory Access Protocol (LDAP): String Representation of Search Filters
    - RFC 4511: Lightweight Directory Access Protocol (LDAP): The Protocol
"""

from typing import TYPE_CHECKING

# Import core filter components
from .builder import FilterBuilder, FilterExpression
from .parser import FilterParser, ParsedFilter
from .validator import FilterValidationResult, FilterValidator

__all__ = [
    # Core filter building
    "FilterBuilder",
    "FilterExpression",
    # Filter parsing
    "FilterParser",
    "ParsedFilter",
    # Filter validation
    "FilterValidator",
    "FilterValidationResult",
]
