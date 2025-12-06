"""Unit tests for flext_ldap.constants.FlextLdapConstants.

**Modules Tested:**
- `flext_ldap.constants.FlextLdapConstants` - LDAP domain constants

**Test Scope:**
- Constant values and enumerations
- Validation helpers
- Type narrowing functions
- Filter constants
- Search scope constants

All tests use real functionality without mocks, leveraging flext-core test utilities
and domain-specific helpers to reduce code duplication while maintaining 100% coverage.

Architecture: Single class per module following FLEXT patterns.
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
    Uses parametrized tests and factories for maximum code reuse and DRY principles.
    Expected reduction: 91 lines → 45 lines (51% reduction).
    """

    # =========================================================================
    # PARAMETRIZED ENUM TESTS (Combined similar tests)
    # =========================================================================

    @staticmethod
    def _get_ldap_cqrs_status_values() -> list[tuple[str, str]]:
        """Factory: Return all LdapCqrs.Status enum members for parametrization."""
        return [
            ("PENDING", "pending"),
            ("RUNNING", "running"),
            ("COMPLETED", "completed"),
            ("FAILED", "failed"),
        ]

    @pytest.mark.parametrize(
        ("attr", "expected"),
        _get_ldap_cqrs_status_values.__func__(),
    )
    def test_ldap_cqrs_status_values(self, attr: str, expected: str) -> None:
        """Test all LdapCqrs.Status enum values."""
        tm.eq(getattr(c.LdapCqrs.Status, attr), expected)

    @pytest.mark.parametrize(
        ("scope", "expected"),
        [
            ("BASE", "BASE"),
            ("ONELEVEL", "ONELEVEL"),
            ("SUBTREE", "SUBTREE"),
        ],
    )
    def test_search_scope_values(self, scope: str, expected: str) -> None:
        """Test all SearchScope enumeration values."""
        tm.eq(getattr(c.SearchScope, scope).value, expected)

    @pytest.mark.parametrize(
        ("op_type", "expected"),
        [
            ("ADD", "add"),
            ("MODIFY", "modify"),
            ("DELETE", "delete"),
            ("SEARCH", "search"),
        ],
    )
    def test_operation_type_values(self, op_type: str, expected: str) -> None:
        """Test all OperationType enumeration values."""
        tm.eq(getattr(c.OperationType, op_type), expected)

    # =========================================================================
    # SCALAR CONSTANT TESTS
    # =========================================================================

    def test_core_name(self) -> None:
        """Test Core.NAME constant."""
        tm.eq(c.Core.NAME, "FLEXT_LDAP")

    def test_filters_all_entries(self) -> None:
        """Test Filters.ALL_ENTRIES_FILTER constant."""
        tm.eq(c.Filters.ALL_ENTRIES_FILTER, "(objectClass=*)")

    # =========================================================================
    # VALIDATION METHOD TESTS (Parametrized)
    # =========================================================================

    @pytest.mark.parametrize(
        ("status", "expected"),
        [
            (c.LdapCqrs.Status.PENDING, True),
            ("pending", True),
            ("running", True),
            ("invalid", False),
        ],
    )
    def test_is_valid_status(
        self,
        status: str | object,
        expected: bool,
    ) -> None:
        """Test is_valid_status with various input types."""
        result = c.LdapValidation.is_valid_status(status)
        tm.eq(result, expected)

    # =========================================================================
    # CONNECTION DEFAULTS TESTS
    # =========================================================================

    def test_connection_defaults_port(self) -> None:
        """Test ConnectionDefaults.PORT is valid port number."""
        tm.is_type(c.ConnectionDefaults.PORT, int)
        tm.that(c.ConnectionDefaults.PORT, gte=1, lte=65535)
