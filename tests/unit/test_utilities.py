"""Unit tests for flext_ldap.utilities.FlextLdapUtilities.

Architecture: Single class per module following FLEXT patterns.
Uses t, c, p, m, u, s for test support and e, r, p, d, x from flext-core.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from collections.abc import (
    Callable,
    Mapping,
)

import pytest

from tests import c, t, u

pytestmark = pytest.mark.unit


class TestsFlextLdapUtilitiesUnit:
    """Comprehensive tests for FlextLdapUtilities.

    All test data comes from c.Ldap.Tests.* — zero inline constants.
    """

    def test_to_str_simple(self) -> None:
        result = u.to_str(c.Ldap.Tests.STRING_SIMPLE)
        u.Ldap.Tests.that(result, eq=c.Ldap.Tests.STRING_SIMPLE)

    def test_to_str_list_from_list(self) -> None:
        result = u.to_str_list(list(c.Ldap.Tests.LIST_ABC))
        u.Ldap.Tests.that(result, eq=list(c.Ldap.Tests.LIST_ABC))

    def test_to_str_list_from_single(self) -> None:
        result = u.to_str_list(c.Ldap.Tests.LIST_SINGLE)
        u.Ldap.Tests.that(result, eq=[c.Ldap.Tests.LIST_SINGLE])

    def test_ldap3_value_to_strings_from_none(self) -> None:
        result = u.Ldap.ldap3_value_to_strings(None)
        u.Ldap.Tests.that(result, eq=[])

    def test_norm_str_lowercase(self) -> None:
        result = u.Ldap.norm_str(c.Ldap.Tests.STRING_SIMPLE_UPPER, case="lower")
        u.Ldap.Tests.that(result, eq=c.Ldap.Tests.STRING_SIMPLE)

    def test_norm_str_uppercase(self) -> None:
        result = u.Ldap.norm_str(c.Ldap.Tests.STRING_SIMPLE, case="upper")
        u.Ldap.Tests.that(result, eq=c.Ldap.Tests.STRING_SIMPLE_UPPER)

    def test_norm_join(self) -> None:
        result = u.Ldap.norm_join(list(c.Ldap.Tests.NORM_JOIN_INPUT), case="lower")
        u.Ldap.Tests.that(result, eq=c.Ldap.Tests.NORM_JOIN_EXPECTED)

    def test_filter_truthy(self) -> None:
        result = u.Ldap.filter_truthy(dict(c.Ldap.Tests.FILTER_TRUTHY_INPUT))
        assert isinstance(result, dict)
        u.Ldap.Tests.that(
            sorted(result.keys()), eq=list(c.Ldap.Tests.FILTER_TRUTHY_EXPECTED_KEYS)
        )

    def test_map_str(self) -> None:
        result = u.Ldap.map_str(list(c.Ldap.Tests.LIST_ABC), case="upper")
        u.Ldap.Tests.that(result, eq=list(c.Ldap.Tests.LIST_ABC_UPPER))

    def test_find_callable_with_mapping(self) -> None:
        handlers: Mapping[str, Callable[[], t.Scalar]] = {
            c.Ldap.Tests.CALLABLE_HANDLER_FOUND_KEY: lambda: "value1",
            "handler2": lambda: False,
        }
        result = u.Ldap.find_callable(handlers)
        u.Ldap.Tests.that(result, eq=c.Ldap.Tests.CALLABLE_HANDLER_FOUND_KEY)

    def test_find_callable_not_found(self) -> None:
        handlers: Mapping[str, Callable[[], t.Scalar | None]] = {
            "handler1": lambda: False,
            "handler2": lambda: None,
            "handler3": lambda: "",
        }
        result = u.Ldap.find_callable(handlers)
        u.Ldap.Tests.that(result, none=True)

    def test_dn_str_with_string(self) -> None:
        result = u.Ldap.dn_str(c.Ldap.Tests.ENTRY_DN_TEST_EXAMPLE)
        u.Ldap.Tests.that(result, eq=c.Ldap.Tests.ENTRY_DN_TEST_EXAMPLE)

    def test_dn_str_with_none(self) -> None:
        result = u.Ldap.dn_str(None)
        u.Ldap.Tests.that(result, eq=c.Ldap.UNKNOWN_CATEGORY)

    def test_dn_str_with_custom_default(self) -> None:
        result = u.Ldap.dn_str(
            None,
            default=c.Ldap.Tests.STRING_DEFAULT_CUSTOM,
        )
        u.Ldap.Tests.that(result, eq=c.Ldap.Tests.STRING_DEFAULT_CUSTOM)


__all__: list[str] = ["TestsFlextLdapUtilitiesUnit"]
