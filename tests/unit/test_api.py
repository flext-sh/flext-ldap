"""Unit tests for ldap API facade (MRO-based).

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import pytest

from flext_ldap import FlextLdapSyncCallbacks, ldap
from tests import c, m, t, u

pytestmark = [pytest.mark.unit]


class TestsFlextLdapApi:
    """Tests for ldap API facade — MRO-based, zero ceremony."""

    # --- Context Manager ---
    def test_enter_returns_self(self) -> None:
        api = ldap
        u.Ldap.Tests.that(api.__enter__(), eq=api)

    def test_with_statement(self) -> None:
        api = ldap
        with api as ctx:
            u.Ldap.Tests.that(ctx, eq=api)

    # --- MRO Method Inheritance ---
    def test_is_connected_default_false(self) -> None:
        u.Ldap.Tests.that(not ldap.is_connected, eq=True)

    # --- Callback Type Guards ---
    @pytest.mark.parametrize("case", c.Ldap.Tests.CallbackGuardCase)
    def test_is_multi_phase_callback(
        self,
        case: c.Ldap.Tests.CallbackGuardCase,
    ) -> None:
        callbacks: dict[
            c.Ldap.Tests.CallbackGuardCase, t.Ldap.ProgressCallbackUnion | None
        ] = {
            c.Ldap.Tests.CallbackGuardCase.NONE: None,
            c.Ldap.Tests.CallbackGuardCase.MULTI: u.Ldap.Tests.multi_phase_cb,
            c.Ldap.Tests.CallbackGuardCase.SINGLE: u.Ldap.Tests.single_phase_cb,
        }
        callback = callbacks[case]
        expected, _ = c.Ldap.Tests.CALLBACK_GUARD_EXPECTED[case]
        u.Ldap.Tests.that(
            FlextLdapSyncCallbacks.is_multi_phase_callback(callback), eq=expected
        )

    @pytest.mark.parametrize("case", c.Ldap.Tests.CallbackGuardCase)
    def test_is_single_phase_callback(
        self,
        case: c.Ldap.Tests.CallbackGuardCase,
    ) -> None:
        callbacks: dict[
            c.Ldap.Tests.CallbackGuardCase, t.Ldap.ProgressCallbackUnion | None
        ] = {
            c.Ldap.Tests.CallbackGuardCase.NONE: None,
            c.Ldap.Tests.CallbackGuardCase.MULTI: u.Ldap.Tests.multi_phase_cb,
            c.Ldap.Tests.CallbackGuardCase.SINGLE: u.Ldap.Tests.single_phase_cb,
        }
        callback = callbacks[case]
        _, expected = c.Ldap.Tests.CALLBACK_GUARD_EXPECTED[case]
        u.Ldap.Tests.that(
            FlextLdapSyncCallbacks.is_single_phase_callback(callback), eq=expected
        )

    def test_search_without_connection_returns_failure(self) -> None:
        search_options = m.Ldap.SearchOptions(
            base_dn=c.Ldap.Tests.RFC_DEFAULT_BASE_DN,
            filter_str=c.Ldap.Tests.RFC_DEFAULT_FILTER,
            scope=c.Ldap.SearchScope.SUBTREE.value,
        )
        u.Ldap.Tests.fail(ldap.search(search_options))

    def test_execute_without_connection_reports_not_connected(self) -> None:
        error = u.Ldap.Tests.fail(ldap.execute())
        u.Ldap.Tests.that(
            error.lower(),
            contains=str(c.Ldap.ErrorMessage.NOT_CONNECTED).lower(),
        )
