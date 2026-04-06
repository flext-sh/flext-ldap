"""Unit tests for flext_ldap.utilities.FlextLdapUtilities.

Architecture: Single class per module following FLEXT patterns.
Uses t, c, p, m, u, s for test support and e, r, d, x from flext-core.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from collections.abc import Callable, Mapping

import pytest

from tests import c, t, u

pytestmark = pytest.mark.unit


class TestsFlextLdapUtilities:
    """Comprehensive tests for FlextLdapUtilities.

    All test data comes from c.Ldap.Tests.* — zero inline constants.
    """

    def test_to_str_simple(self) -> None:
        result = u.to_str(c.Ldap.Tests.StringValues.SIMPLE)
        u.Tests.Matchers.that(result, eq=c.Ldap.Tests.StringValues.SIMPLE)

    def test_to_str_none(self) -> None:
        result = u.to_str(None)
        u.Tests.Matchers.that(result, eq=c.Ldap.Tests.StringValues.EMPTY)

    def test_to_str_with_default(self) -> None:
        result = u.to_str(None, default=c.Ldap.Tests.StringValues.DEFAULT_CUSTOM)
        u.Tests.Matchers.that(result, eq=c.Ldap.Tests.StringValues.DEFAULT_CUSTOM)

    def test_to_str_list_from_list(self) -> None:
        result = u.to_str_list(list(c.Ldap.Tests.ListValues.ABC))
        u.Tests.Matchers.that(result, eq=list(c.Ldap.Tests.ListValues.ABC))

    def test_to_str_list_from_single(self) -> None:
        result = u.to_str_list(c.Ldap.Tests.ListValues.SINGLE)
        u.Tests.Matchers.that(result, eq=[c.Ldap.Tests.ListValues.SINGLE])

    def test_to_str_list_from_none(self) -> None:
        result = u.to_str_list(None)
        u.Tests.Matchers.that(result, eq=[])

    def test_norm_str_lowercase(self) -> None:
        result = u.Ldap.norm_str(c.Ldap.Tests.StringValues.SIMPLE_UPPER, case="lower")
        u.Tests.Matchers.that(result, eq=c.Ldap.Tests.StringValues.SIMPLE)

    def test_norm_str_uppercase(self) -> None:
        result = u.Ldap.norm_str(c.Ldap.Tests.StringValues.SIMPLE, case="upper")
        u.Tests.Matchers.that(result, eq=c.Ldap.Tests.StringValues.SIMPLE_UPPER)

    def test_norm_join(self) -> None:
        result = u.Ldap.norm_join(list(c.Ldap.Tests.NormData.JOIN_INPUT), case="lower")
        u.Tests.Matchers.that(result, eq=c.Ldap.Tests.NormData.JOIN_EXPECTED)

    def test_filter_truthy(self) -> None:
        result = u.Ldap.filter_truthy(dict(c.Ldap.Tests.FilterTruthyData.INPUT))
        assert isinstance(result, dict)
        u.Tests.Matchers.that(
            sorted(result.keys()),
            eq=list(c.Ldap.Tests.FilterTruthyData.EXPECTED_KEYS),
        )

    def test_map_str(self) -> None:
        result = u.Ldap.map_str(list(c.Ldap.Tests.ListValues.ABC), case="upper")
        u.Tests.Matchers.that(result, eq=list(c.Ldap.Tests.ListValues.ABC_UPPER))

    def test_find_callable_with_mapping(self) -> None:
        handlers: Mapping[str, Callable[[], t.Scalar]] = {
            c.Ldap.Tests.CallableHandlers.FOUND_KEY: lambda: "value1",
            "handler2": lambda: False,
        }
        result = u.Ldap.find_callable(handlers)
        u.Tests.Matchers.that(result, eq=c.Ldap.Tests.CallableHandlers.FOUND_KEY)

    def test_find_callable_not_found(self) -> None:
        handlers: Mapping[str, Callable[[], t.Scalar | None]] = {
            "handler1": lambda: False,
            "handler2": lambda: None,
            "handler3": lambda: "",
        }
        result = u.Ldap.find_callable(handlers)
        u.Tests.Matchers.that(result, none=True)

    def test_dn_str_with_string(self) -> None:
        result = u.Ldap.dn_str(c.Ldap.Tests.EntryDN.TEST_EXAMPLE)
        u.Tests.Matchers.that(result, eq=c.Ldap.Tests.EntryDN.TEST_EXAMPLE)

    def test_dn_str_with_none(self) -> None:
        result = u.Ldap.dn_str(None)
        u.Tests.Matchers.that(result, eq=c.Ldap.Defaults.UNKNOWN_CATEGORY)

    def test_dn_str_with_custom_default(self) -> None:
        result = u.Ldap.dn_str(
            None,
            default=c.Ldap.Tests.StringValues.DEFAULT_CUSTOM,
        )
        u.Tests.Matchers.that(result, eq=c.Ldap.Tests.StringValues.DEFAULT_CUSTOM)


__all__ = ["TestsFlextLdapUtilities"]
