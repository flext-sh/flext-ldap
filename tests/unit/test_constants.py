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
from flext_tests import c, u

from tests import c, u

pytestmark = pytest.mark.unit


class TestsFlextLdapConstants:
    """Comprehensive tests for FlextLdapConstants using parametrization.

    Architecture: Single class per module following FLEXT patterns.
    Demonstrates maximum code reuse through parametrization and nested factories.
    """

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
        [
            ("PENDING", "pending"),
            ("RUNNING", "running"),
            ("COMPLETED", "completed"),
            ("FAILED", "failed"),
        ],
    )
    def test_ldap_cqrs_status_values(self, attr: str, expected: str) -> None:
        """Test all LdapCqrs.Status enum values in single parametrized method."""
        status_map: dict[str, c.Ldap.LdapCqrs.Status] = {
            "PENDING": c.Ldap.LdapCqrs.Status.PENDING,
            "RUNNING": c.Ldap.LdapCqrs.Status.RUNNING,
            "COMPLETED": c.Ldap.LdapCqrs.Status.COMPLETED,
            "FAILED": c.Ldap.LdapCqrs.Status.FAILED,
        }
        u.Tests.Matchers.that(status_map[attr].value, eq=expected)

    def test_is_valid_status_with_enum(self) -> None:
        """Test is_valid_status with Status enum."""
        result = u.Ldap.Validation.is_valid_status(c.Ldap.LdapCqrs.Status.PENDING)
        u.Tests.Matchers.that(result, eq=True)

    def test_is_valid_status_with_string(self) -> None:
        """Test is_valid_status with string literal."""
        result = u.Ldap.Validation.is_valid_status("pending")
        u.Tests.Matchers.that(result, eq=True)

    def test_is_valid_status_invalid(self) -> None:
        """Test is_valid_status with invalid value."""
        result = u.Ldap.Validation.is_valid_status("invalid")
        u.Tests.Matchers.that(result, eq=False)

    @pytest.mark.parametrize(
        ("attr", "expected"),
        [("BASE", "BASE"), ("ONELEVEL", "ONELEVEL"), ("SUBTREE", "SUBTREE")],
    )
    def test_search_scope_enum_values(self, attr: str, expected: str) -> None:
        """Test all SearchScope enumeration values."""
        scope_map: dict[str, c.Ldap.SearchScope] = {
            "BASE": c.Ldap.SearchScope.BASE,
            "ONELEVEL": c.Ldap.SearchScope.ONELEVEL,
            "SUBTREE": c.Ldap.SearchScope.SUBTREE,
        }
        u.Tests.Matchers.that(scope_map[attr].value, eq=expected)

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
        op_type_map: dict[str, c.Ldap.OperationType] = {
            "ADD": c.Ldap.OperationType.ADD,
            "MODIFY": c.Ldap.OperationType.MODIFY,
            "DELETE": c.Ldap.OperationType.DELETE,
            "SEARCH": c.Ldap.OperationType.SEARCH,
        }
        u.Tests.Matchers.that(op_type_map[attr].value, eq=expected)

    def test_core_name(self) -> None:
        """Test Core.NAME constant."""
        u.Tests.Matchers.that(c.Ldap.Core.NAME, eq="FLEXT_LDAP")

    def test_filters_all_entries(self) -> None:
        """Test Filters.ALL_ENTRIES_FILTER constant."""
        u.Tests.Matchers.that(c.Ldap.Filters.ALL_ENTRIES_FILTER, eq="(objectClass=*)")

    def test_connection_defaults_port_is_valid(self) -> None:
        """Test ConnectionDefaults.PORT is valid port number."""
        u.Tests.Matchers.that(c.Ldap.ConnectionDefaults.PORT, is_=int, none=False)
        u.Tests.Matchers.that(c.Ldap.ConnectionDefaults.PORT, gte=1, lte=65535)

    def test_vendor_string_max_tokens(self) -> None:
        """Test newly added VENDOR_STRING_MAX_TOKENS constant."""
        u.Tests.Matchers.that(
            c.Ldap.ServerTypeMappings.VENDOR_STRING_MAX_TOKENS, is_=int, none=False
        )
        u.Tests.Matchers.that(c.Ldap.ServerTypeMappings.VENDOR_STRING_MAX_TOKENS, eq=2)
