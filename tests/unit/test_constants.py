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

from tests import c, u

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
        _get_ldap_cqrs_status_values(),
    )
    def test_ldap_cqrs_status_values(self, attr: str, expected: str) -> None:
        """Test all LdapCqrs.Status enum values."""
        # Map attribute names to enum values
        status_map: dict[str, c.Ldap.LdapCqrs.Status] = {
            "PENDING": c.Ldap.LdapCqrs.Status.PENDING,
            "RUNNING": c.Ldap.LdapCqrs.Status.RUNNING,
            "COMPLETED": c.Ldap.LdapCqrs.Status.COMPLETED,
            "FAILED": c.Ldap.LdapCqrs.Status.FAILED,
        }
        actual = status_map[attr]
        tm.that(actual, eq=expected)

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
        # Map scope names to enum values
        scope_map: dict[str, c.SearchScope] = {
            "BASE": c.SearchScope.BASE,
            "ONELEVEL": c.SearchScope.ONELEVEL,
            "SUBTREE": c.SearchScope.SUBTREE,
        }
        actual = scope_map[scope].value
        tm.that(actual, eq=expected)

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
        # Map operation type names to enum values
        op_type_map: dict[str, c.Ldap.OperationType] = {
            "ADD": c.Ldap.OperationType.ADD,
            "MODIFY": c.Ldap.OperationType.MODIFY,
            "DELETE": c.Ldap.OperationType.DELETE,
            "SEARCH": c.Ldap.OperationType.SEARCH,
        }
        actual = op_type_map[op_type]
        tm.that(actual, eq=expected)

    # =========================================================================
    # SCALAR CONSTANT TESTS
    # =========================================================================

    def test_core_name(self) -> None:
        """Test Core.NAME constant."""
        tm.that(c.Core.NAME, eq="FLEXT_LDAP")

    def test_filters_all_entries(self) -> None:
        """Test Filters.ALL_ENTRIES_FILTER constant."""
        tm.that(c.Filters.ALL_ENTRIES_FILTER, eq="(objectClass=*)")

    # =========================================================================
    # VALIDATION METHOD TESTS (Parametrized)
    # =========================================================================

    @pytest.mark.parametrize(
        ("status", "expected"),
        [
            (c.Ldap.LdapCqrs.Status.PENDING, True),
            ("pending", True),
            ("running", True),
            ("invalid", False),
        ],
    )
    def test_is_valid_status(
        self,
        status: str | c.Ldap.LdapCqrs.Status,
        expected: bool,
    ) -> None:
        """Test is_valid_status with various input types."""
        result = u.Ldap.Validation.is_valid_status(status)
        tm.that(result, eq=expected)

    # =========================================================================
    # CONNECTION DEFAULTS TESTS
    # =========================================================================

    def test_connection_defaults_port(self) -> None:
        """Test ConnectionDefaults.PORT is valid port number."""
        tm.that(c.ConnectionDefaults.PORT, is_=int, none=False)
        tm.that(c.ConnectionDefaults.PORT, gte=1, lte=65535)
