"""Unit tests for ldap API facade (MRO-based).

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from flext_ldap import ldap
from flext_ldap.services.sync import FlextLdapSync
from tests import c, m, u

if TYPE_CHECKING:
    from tests import t

pytestmark = [pytest.mark.unit]


class TestsFlextLdapApi:
    """Tests for ldap API facade — MRO-based, zero ceremony."""

    # --- Context Manager contract ---
    @staticmethod
    def test_with_statement_yields_same_facade() -> None:
        """Verify with statement yields same facade."""
        with ldap as ctx:
            u.Ldap.Tests.that(ctx, eq=ldap)

    @staticmethod
    def test_context_manager_exit_leaves_facade_disconnected() -> None:
        """Verify context manager exit leaves facade disconnected."""
        with ldap:
            pass
        u.Ldap.Tests.that(ldap.is_connected, eq=False)

    @staticmethod
    def test_context_manager_does_not_suppress_exceptions() -> None:
        """Verify context manager does not suppress exceptions.

        Raises:
            RuntimeError: Always.
        """
        with pytest.raises(RuntimeError), ldap:
            raise RuntimeError(c.Ldap.Tests.RFC_DEFAULT_FILTER)

    # --- Connection state invariant ---
    @staticmethod
    def test_is_connected_default_false() -> None:
        """Verify is connected default false."""
        u.Ldap.Tests.that(ldap.is_connected, eq=False)

    @staticmethod
    def test_is_connected_is_idempotent_read() -> None:
        """Verify is connected is idempotent read."""
        first = ldap.is_connected
        second = ldap.is_connected
        u.Ldap.Tests.that(first, eq=second)

    # --- Callback Type Guards ---
    @staticmethod
    def _callback_for_case(
        case: c.Ldap.Tests.CallbackGuardCase,
    ) -> t.Ldap.ProgressCallbackUnion | None:
        """Return the callback payload for one callback-guard case."""
        callbacks: dict[
            c.Ldap.Tests.CallbackGuardCase,
            t.Ldap.ProgressCallbackUnion | None,
        ] = {
            c.Ldap.Tests.CallbackGuardCase.NONE: None,
            c.Ldap.Tests.CallbackGuardCase.MULTI: u.Ldap.Tests.multi_phase_cb,
            c.Ldap.Tests.CallbackGuardCase.SINGLE: u.Ldap.Tests.single_phase_cb,
        }
        return callbacks[case]

    @pytest.mark.parametrize("case", c.Ldap.Tests.CallbackGuardCase)
    def test_is_multi_phase_callback(
        self,
        case: c.Ldap.Tests.CallbackGuardCase,
    ) -> None:
        """Verify is multi phase callback."""
        callback = self._callback_for_case(case)
        expected, _ = c.Ldap.Tests.CALLBACK_GUARD_EXPECTED[case]
        u.Ldap.Tests.that(FlextLdapSync.multi_phase_callback(callback), eq=expected)

    @pytest.mark.parametrize("case", c.Ldap.Tests.CallbackGuardCase)
    def test_is_single_phase_callback(
        self,
        case: c.Ldap.Tests.CallbackGuardCase,
    ) -> None:
        """Verify is single phase callback."""
        callback = self._callback_for_case(case)
        _, expected = c.Ldap.Tests.CALLBACK_GUARD_EXPECTED[case]
        u.Ldap.Tests.that(FlextLdapSync.single_phase_callback(callback), eq=expected)

    @staticmethod
    def test_search_without_connection_returns_failure() -> None:
        """Verify search without connection returns failure."""
        search_options = m.Ldap.SearchOptions(
            base_dn=c.Ldap.Tests.RFC_DEFAULT_BASE_DN,
            filter_str=c.Ldap.Tests.RFC_DEFAULT_FILTER,
            scope=c.Ldap.SearchScope.SUBTREE.value,
        )
        u.Ldap.Tests.fail(ldap.search(search_options))

    @staticmethod
    def test_execute_without_connection_reports_not_connected() -> None:
        """Verify execute without connection reports not connected."""
        error = u.Ldap.Tests.fail(ldap.execute())
        u.Ldap.Tests.that(
            error.lower(),
            contains=str(c.Ldap.ErrorMessage.NOT_CONNECTED).lower(),
        )
