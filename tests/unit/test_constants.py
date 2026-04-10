"""Unit tests for flext_ldap.constants.FlextLdapConstants.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import pytest

from tests import c, u

pytestmark = pytest.mark.unit


class TestsFlextLdapConstants:
    """Contract tests for FlextLdapConstants enum/constant values."""

    @pytest.mark.parametrize(
        ("attr", "expected"),
        c.Ldap.Tests.ConstantVerification.STATUS_SCENARIOS,
    )
    def test_ldap_cqrs_status_values(self, attr: str, expected: str) -> None:
        pass

    def test_is_valid_status_with_enum(self) -> None:
        u.Tests.Matchers.that(
            u.Ldap.Validation.is_valid_status(c.Ldap.LdapCqrs.Status.PENDING),
            eq=True,
        )

    def test_is_valid_status_with_string(self) -> None:
        u.Tests.Matchers.that(
            u.Ldap.Validation.is_valid_status(
                c.Ldap.LdapCqrs.Status.PENDING.value,
            ),
            eq=True,
        )

    def test_is_valid_status_invalid(self) -> None:
        u.Tests.Matchers.that(
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
        pass

    @pytest.mark.parametrize(
        ("attr", "expected"),
        c.Ldap.Tests.ConstantVerification.OPERATION_TYPE_SCENARIOS,
    )
    def test_operation_type_enum_values(self, attr: str, expected: str) -> None:
        pass

    def test_core_name(self) -> None:
        u.Tests.Matchers.that(
            c.Ldap.Core.NAME,
            eq=c.Ldap.Tests.ConstantVerification.EXPECTED_CORE_NAME,
        )

    def test_filters_all_entries(self) -> None:
        u.Tests.Matchers.that(
            c.Ldap.Filters.ALL_ENTRIES_FILTER,
            eq=c.Ldap.Tests.ConstantVerification.EXPECTED_ALL_ENTRIES_FILTER,
        )

    def test_connection_defaults_port_is_valid(self) -> None:
        u.Tests.Matchers.that(c.Ldap.ConnectionDefaults.PORT, is_=int, none=False)
        u.Tests.Matchers.that(
            c.Ldap.ConnectionDefaults.PORT,
            gte=c.Ldap.Tests.Config.PORT_MIN,
            lte=c.Ldap.Tests.Config.PORT_MAX,
        )

    def test_vendor_string_max_tokens(self) -> None:
        u.Tests.Matchers.that(
            c.Ldap.ServerTypeMappings.VENDOR_STRING_MAX_TOKENS, is_=int, none=False
        )
        u.Tests.Matchers.that(
            c.Ldap.ServerTypeMappings.VENDOR_STRING_MAX_TOKENS,
            eq=c.Ldap.Tests.ConstantVerification.EXPECTED_VENDOR_STRING_MAX_TOKENS,
        )
