"""Unit tests for flext_ldap.constants.FlextLdapConstants.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import pytest

from tests import c, u

pytestmark = pytest.mark.unit


class TestsFlextLdapConstantsUnit:
    """Contract tests for FlextLdapConstants enum/constant values."""

    @pytest.mark.parametrize(
        ("attr", "expected"),
        c.Ldap.Tests.CONSTANT_STATUS_SCENARIOS,
    )
    def test_ldap_cqrs_status_values(self, attr: str, expected: str) -> None:
        pass

    def test_is_valid_status_with_enum(self) -> None:
        u.Ldap.Tests.that(
            u.Ldap.Validation.is_valid_status(c.Ldap.LdapCqrs.Status.PENDING), eq=True
        )

    def test_is_valid_status_with_string(self) -> None:
        u.Ldap.Tests.that(
            u.Ldap.Validation.is_valid_status(
                c.Ldap.LdapCqrs.Status.PENDING.value,
            ),
            eq=True,
        )

    def test_is_valid_status_invalid(self) -> None:
        u.Ldap.Tests.that(
            not u.Ldap.Validation.is_valid_status(
                c.Ldap.Tests.CONSTANT_INVALID_STATUS,
            ),
            eq=True,
        )

    @pytest.mark.parametrize(
        ("attr", "expected"),
        c.Ldap.Tests.CONSTANT_SCOPE_SCENARIOS,
    )
    def test_search_scope_enum_values(self, attr: str, expected: str) -> None:
        pass

    @pytest.mark.parametrize(
        ("attr", "expected"),
        c.Ldap.Tests.CONSTANT_OPERATION_TYPE_SCENARIOS,
    )
    def test_operation_type_enum_values(self, attr: str, expected: str) -> None:
        pass

    def test_core_name(self) -> None:
        u.Ldap.Tests.that(c.Ldap.Core.NAME, eq=c.Ldap.Tests.CONSTANT_EXPECTED_CORE_NAME)

    def test_filters_all_entries(self) -> None:
        u.Ldap.Tests.that(
            c.Ldap.Filters.ALL_ENTRIES_FILTER,
            eq=c.Ldap.Tests.CONSTANT_EXPECTED_ALL_ENTRIES_FILTER,
        )

    def test_connection_defaults_port_is_valid(self) -> None:
        u.Ldap.Tests.that(c.Ldap.ConnectionDefaults.PORT, is_=int, none=False)
        u.Ldap.Tests.that(
            c.Ldap.ConnectionDefaults.PORT,
            gte=c.Ldap.Tests.CONFIG_PORT_MIN,
            lte=c.Ldap.Tests.CONFIG_PORT_MAX,
        )

    def test_vendor_string_max_tokens(self) -> None:
        u.Ldap.Tests.that(
            c.Ldap.ServerTypeMappings.VENDOR_STRING_MAX_TOKENS, is_=int, none=False
        )
        u.Ldap.Tests.that(
            c.Ldap.ServerTypeMappings.VENDOR_STRING_MAX_TOKENS,
            eq=c.Ldap.Tests.CONSTANT_EXPECTED_VENDOR_STRING_MAX_TOKENS,
        )
