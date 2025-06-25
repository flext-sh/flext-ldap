"""Core module tests package.

Test suite for ldap-core-shared core functionality including operations,
transactions, and enterprise features. Follows Zero Tolerance testing
methodology with 100% coverage and comprehensive validation.

Test Organization:
    - test_operations.py: LDAP operations testing
    - test_transaction_context.py: Transaction context testing
    - test_enterprise_transaction.py: Enterprise transaction testing
    - conftest.py: Shared fixtures and test utilities

Testing Principles:
    - Zero Tolerance: No untested code paths
    - DRY: Shared fixtures and utilities, no duplication
    - SOLID: Well-structured test classes and methods
    - Performance: Tests validate 12K+ entries/second capability

Version: 1.0.0-enterprise
"""

from __future__ import annotations

# Version info for test suite
__version__ = "1.0.0-enterprise"
__test_coverage_target__ = "100%"
__performance_validation__ = "12,000+ entries/second"
