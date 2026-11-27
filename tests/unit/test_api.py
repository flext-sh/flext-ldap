"""Unit tests for ldap API facade (MRO-based).

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from collections.abc import Mapping

import pytest

from tests import FlextLdap, c, ldap, m, t, u

pytestmark = [pytest.mark.unit]


class TestsFlextLdapApi:
    """Tests for ldap API facade — MRO-based, zero ceremony."""

    # --- Context Manager contract ---
    @staticmethod
    def test_with_statement_yields_same_facade() -> None:
        """Verify with statement yields same facade."""
        with ldap as ctx:
            u.Tests.that(ctx, eq=ldap)

    @staticmethod
    def test_context_manager_exit_leaves_facade_disconnected() -> None:
        """Verify context manager exit leaves facade disconnected."""
        with ldap:
            pass
        u.Tests.that(ldap.is_connected, eq=False)

    @staticmethod
    def test_context_manager_does_not_suppress_exceptions() -> None:
        """Verify context manager does not suppress exceptions.

        Raises:
            RuntimeError: Always.

        """
        with u.Tests.raises(RuntimeError), ldap:
            raise RuntimeError(c.Tests.RFC_DEFAULT_FILTER)

    # --- Connection state invariant ---
    @staticmethod
    def test_is_connected_default_false() -> None:
        """Verify is connected default false."""
        u.Tests.that(ldap.is_connected, eq=False)

    @staticmethod
    def test_is_connected_is_idempotent_read() -> None:
        """Verify is connected is idempotent read."""
        first = ldap.is_connected
        second = ldap.is_connected
        u.Tests.that(first, eq=second)

    # --- Callback Type Guards ---
    @staticmethod
    def _callback_for_case(
        case: c.Tests.CallbackGuardCase,
    ) -> t.Ldap.ProgressCallbackUnion | None:
        """Return the callback payload for one callback-guard case."""
        callbacks: Mapping[
            c.Tests.CallbackGuardCase,
            t.Ldap.ProgressCallbackUnion | None,
        ] = {
            c.Tests.CallbackGuardCase.NONE: None,
            c.Tests.CallbackGuardCase.MULTI: u.Tests.multi_phase_cb,
            c.Tests.CallbackGuardCase.SINGLE: u.Tests.single_phase_cb,
        }
        return callbacks[case]

    @pytest.mark.parametrize("case", c.Tests.CallbackGuardCase)
    def test_is_multi_phase_callback(
        self,
        case: c.Tests.CallbackGuardCase,
    ) -> None:
        """Verify is multi phase callback."""
        callback = self._callback_for_case(case)
        expected, _ = c.Tests.CALLBACK_GUARD_EXPECTED[case]
        u.Tests.that(FlextLdap.multi_phase_callback(callback), eq=expected)

    @pytest.mark.parametrize("case", c.Tests.CallbackGuardCase)
    def test_is_single_phase_callback(
        self,
        case: c.Tests.CallbackGuardCase,
    ) -> None:
        """Verify is single phase callback."""
        callback = self._callback_for_case(case)
        _, expected = c.Tests.CALLBACK_GUARD_EXPECTED[case]
        u.Tests.that(FlextLdap.single_phase_callback(callback), eq=expected)

    @staticmethod
    def test_search_without_connection_returns_failure() -> None:
        """Verify search without connection returns failure."""
        search_options = m.Ldap.SearchOptions(
            base_dn=c.Tests.RFC_DEFAULT_BASE_DN,
            filter_str=c.Tests.RFC_DEFAULT_FILTER,
            scope=c.Ldap.SearchScope.SUBTREE.value,
        )
        u.Tests.fail(ldap.search(search_options))

    @staticmethod
    def test_execute_without_connection_reports_not_connected() -> None:
        """Verify execute without connection reports not connected."""
        error = u.Tests.fail(ldap.execute())
        u.Tests.that(
            error.lower(),
            contains=str(c.Ldap.ErrorMessage.NOT_CONNECTED).lower(),
        )
