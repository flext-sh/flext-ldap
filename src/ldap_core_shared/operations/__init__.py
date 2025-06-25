"""Advanced LDAP Operations Module.

This module provides comprehensive advanced LDAP operations following perl-ldap
Net::LDAP patterns with enterprise-grade Python enhancements. Implements the
missing 5-8 advanced operations required to achieve 100% perl-ldap coverage.

Advanced operations enable enterprise-grade LDAP functionality including atomic
modifications, persistent search, pre/post-read controls, and high-performance
asynchronous operations.

Architecture:
    - AtomicOperations: Atomic modifications including increment operations
    - CompareOperations: Server-side attribute value comparison
    - PersistentSearch: Real-time directory change notifications
    - PrePostReadControls: Atomic read of entry state before/after modifications
    - AsyncOperations: Non-blocking LDAP operations with callbacks

Usage Example:
    >>> from ldap_core_shared.operations import AtomicOperations
    >>>
    >>> # Atomic increment without race conditions
    >>> atomic = AtomicOperations(connection)
    >>> result = await atomic.increment_attribute(
    ...     "uid=user1,ou=users,dc=example,dc=com", "loginCount", 1
    ... )
    >>> print(f"New value: {result.new_value}")
    >>>
    >>> # Compare operation for authentication
    >>> compare = CompareOperations(connection)
    >>> is_valid = await compare.compare_password(
    ...     "uid=user1,ou=users,dc=example,dc=com", "userPassword", "secret123"
    ... )

References:
    - perl-ldap: lib/Net/LDAP.pod (increment operations, lines 514-527)
    - perl-ldap: lib/Net/LDAP/Control/PersistentSearch.pm
    - perl-ldap: lib/Net/LDAP/Control/PreRead.pm and PostRead.pm
    - RFC 4525: LDAP Modify-Increment Extension
    - RFC 4511: LDAP Protocol Specification (compare operations)
"""

from typing import TYPE_CHECKING

# Import advanced operation components
from ldap_core_shared.operations.atomic import AtomicOperations, IncrementResult
from ldap_core_shared.operations.compare import CompareOperations, CompareResult

__all__ = [
    # Atomic operations
    "AtomicOperations",
    "CompareOperations",
    "CompareResult",
    "IncrementResult",
]
