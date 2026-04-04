"""Unit tests for flext_ldap.constants.FlextLdapConstants.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import pytest
from flext_tests import tm

from tests import c, u

pytestmark = pytest.mark.unit


class TestsFlextLdapConstants:
    """Contract tests for FlextLdapConstants enum/constant values."""

    @pytest.mark.parametrize(
        ("attr", "expected"),
        c.Ldap.Tests.ConstantVerification.STATUS_SCENARIOS,
    )
    def test_ldap_cqrs_status_values(self, attr: str, expected: str) -> None:
        tm.that(getattr(c.Ldap.LdapCqrs.Status, attr).value, eq=expected)

    def test_is_valid_status_with_enum(self) -> None:
        tm.that(
            u.Ldap.Validation.is_valid_status(c.Ldap.LdapCqrs.Status.PENDING),
            eq=True,
        )

    def test_is_valid_status_with_string(self) -> None:
        tm.that(
            u.Ldap.Validation.is_valid_status(
                c.Ldap.LdapCqrs.Status.PENDING.value,
            ),
            eq=True,
        )

    def test_is_valid_status_invalid(self) -> None:
        tm.that(
            not u.Ldap.Validation.is_valid_status(
                c.Ldap.Tests.ConstantVerification.INVALID_STATUS,
            ),
            eq=True,
        )

    @pytest.mark.parametrize(
        ("attr", "expected"),
        c.Ldap.Tests.ConstantVerification.SCOPE_SCENARIOS,
    )
    def test_search_scope_enum_values(self, attr: str, expected: str) -> None:
        tm.that(getattr(c.Ldap.SearchScope, attr).value, eq=expected)

    @pytest.mark.parametrize(
        ("attr", "expected"),
        c.Ldap.Tests.ConstantVerification.OPERATION_TYPE_SCENARIOS,
    )
    def test_operation_type_enum_values(self, attr: str, expected: str) -> None:
        tm.that(getattr(c.Ldap.OperationType, attr).value, eq=expected)

    def test_core_name(self) -> None:
        tm.that(
            c.Ldap.Core.NAME,
            eq=c.Ldap.Tests.ConstantVerification.EXPECTED_CORE_NAME,
        )

    def test_filters_all_entries(self) -> None:
        tm.that(
            c.Ldap.Filters.ALL_ENTRIES_FILTER,
            eq=c.Ldap.Tests.ConstantVerification.EXPECTED_ALL_ENTRIES_FILTER,
        )

    def test_connection_defaults_port_is_valid(self) -> None:
        tm.that(c.Ldap.ConnectionDefaults.PORT, is_=int, none=False)
        tm.that(
            c.Ldap.ConnectionDefaults.PORT,
            gte=c.Ldap.Tests.Config.PORT_MIN,
            lte=c.Ldap.Tests.Config.PORT_MAX,
        )

    def test_vendor_string_max_tokens(self) -> None:
        tm.that(c.Ldap.ServerTypeMappings.VENDOR_STRING_MAX_TOKENS, is_=int, none=False)
        tm.that(
            c.Ldap.ServerTypeMappings.VENDOR_STRING_MAX_TOKENS,
            eq=c.Ldap.Tests.ConstantVerification.EXPECTED_VENDOR_STRING_MAX_TOKENS,
        )
