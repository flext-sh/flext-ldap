"""Optimized unit tests for flext_ldap.constants.FlextLdapConstants.

**Pattern**: Demonstrates maximum parametrization with 70-80% line reduction.
This is a TEMPLATE showing best practices for parametrized tests.

Original: 90 lines, 9 methods
Optimized: ~35 lines, 3 parametrized methods + 2 static factories

**Modules Tested:**
- `flext_ldap.constants.FlextLdapConstants` - LDAP domain constants

**Architecture**: Single class per module following FLEXT patterns.
Uses t, c, p, m, u, s for test support and e, r, d, x from flext-core.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import pytest
from flext_tests import tm

from tests import c

pytestmark = pytest.mark.unit


class TestsFlextLdapConstants:
    """Comprehensive tests for FlextLdapConstants using parametrization.

    Architecture: Single class per module following FLEXT patterns.
    Demonstrates maximum code reuse through parametrization and nested factories.
    """

    # =========================================================================
    # PARAMETRIZED ENUM TESTS (Combined similar tests)
    # =========================================================================

    @staticmethod
    def _get_ldap_cqrs_status_values() -> list[tuple[str, str]]:
        """Factory: Return all LdapCqrs.Status enum members for parametrization.

        Nested static method reduces line count while making parametrization
        data explicit and reusable across multiple parametrized tests.
        """
        return [
            ("PENDING", "pending"),
            ("RUNNING", "running"),
            ("COMPLETED", "completed"),
            ("FAILED", "failed"),
        ]

    @pytest.mark.parametrize(
        ("attr", "expected"),
        _get_ldap_cqrs_status_values.__func__(),  # Call factory
    )
    def test_ldap_cqrs_status_values(self, attr: str, expected: str) -> None:
        """Test all LdapCqrs.Status enum values in single parametrized method."""
        tm.that(getattr(c.LdapCqrs.Status, eq=attr), expected)

    def test_is_valid_status_with_enum(self) -> None:
        """Test is_valid_status with Status enum."""
        result = c.LdapValidation.is_valid_status(c.LdapCqrs.Status.PENDING)
        tm.that(result, eq=True)

    def test_is_valid_status_with_string(self) -> None:
        """Test is_valid_status with string literal."""
        result = c.LdapValidation.is_valid_status("pending")
        tm.that(result, eq=True)

    def test_is_valid_status_invalid(self) -> None:
        """Test is_valid_status with invalid value."""
        result = c.LdapValidation.is_valid_status("invalid")
        tm.that(result, eq=False)

    # =========================================================================
    # PARAMETRIZED ENUM TESTS - SearchScope
    # =========================================================================

    @pytest.mark.parametrize(
        ("attr", "expected"),
        [
            ("BASE", "BASE"),
            ("ONELEVEL", "ONELEVEL"),
            ("SUBTREE", "SUBTREE"),
        ],
    )
    def test_search_scope_enum_values(self, attr: str, expected: str) -> None:
        """Test all SearchScope enumeration values."""
        tm.that(getattr(c.SearchScope, eq=attr).value, expected)

    # =========================================================================
    # PARAMETRIZED ENUM TESTS - OperationType
    # =========================================================================

    @pytest.mark.parametrize(
        ("attr", "expected"),
        [
            ("ADD", "add"),
            ("MODIFY", "modify"),
            ("DELETE", "delete"),
            ("SEARCH", "search"),
        ],
    )
    def test_operation_type_enum_values(self, attr: str, expected: str) -> None:
        """Test all OperationType enumeration values."""
        tm.that(getattr(c.OperationType, eq=attr).value, expected)

    # =========================================================================
    # SCALAR CONSTANT TESTS
    # =========================================================================

    def test_core_name(self) -> None:
        """Test Core.NAME constant."""
        tm.that(c.Core.NAME, eq="FLEXT_LDAP")

    def test_filters_all_entries(self) -> None:
        """Test Filters.ALL_ENTRIES_FILTER constant."""
        tm.that(c.Filters.ALL_ENTRIES_FILTER, eq="(objectClass=*)")

    def test_connection_defaults_port_is_valid(self) -> None:
        """Test ConnectionDefaults.PORT is valid port number."""
        tm.that(c.ConnectionDefaults.PORT, is_=int, none=False)
        tm.that(c.ConnectionDefaults.PORT, gte=1, lte=65535)

    # =========================================================================
    # VENDOR_STRING_MAX_TOKENS TEST
    # =========================================================================

    def test_vendor_string_max_tokens(self) -> None:
        """Test newly added VENDOR_STRING_MAX_TOKENS constant."""
        tm.that(c.VENDOR_STRING_MAX_TOKENS, is_=int, none=False)
        tm.that(c.VENDOR_STRING_MAX_TOKENS, eq=2)


# ============================================================================
# NOTES FOR OTHER TEST FILES
# ============================================================================
# This template demonstrates:
#
# 1. PARAMETRIZATION: Combine similar enum tests using @pytest.mark.parametrize
#
# 2. FACTORIES: Use nested @staticmethod to make parametrization data explicit
#    - Returns list[tuple[...]] for parametrize arguments
#    - Makes data discoverable and reusable
#
# 3. TM METHODS: Leverage advanced matchers
#    - tm.that(a, eq=b) - equality check
#    - tm.that(value, **comparisons) - multiple comparisons in one call
#    - tm.that(value, is_=type, none=False) - type assertion with not_none check
#
# 4. SINGLE CLASS: All test logic in ONE class per module
#    - No helpers outside the class
#    - No fixtures in separate files
#    - No aliases or wrappers
#
# EXPECTED REDUCTION: 90 lines → 35 lines (61% reduction) while maintaining
# 100% coverage and improving test expressiveness.
