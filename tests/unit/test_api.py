"""Unit tests for ldap API facade (MRO-based).

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import inspect

import pytest

from flext_ldap import FlextLdapSettings, FlextLdapSyncCallbacks, ldap
from tests import c, m, p, t, u

pytestmark = [pytest.mark.unit]


class TestsFlextLdapApi:
    """Tests for ldap API facade — MRO-based, zero ceremony."""

    # --- Initialization ---
    def test_init_no_args(self) -> None:
        u.Ldap.Tests.that(ldap, none=False)

    def test_logger_available(self) -> None:
        u.Ldap.Tests.that(ldap.logger, none=False)

    def test_config_returns_flext_settings(self) -> None:
        assert isinstance(ldap.settings, p.Settings)

    def test_settings_are_typed_for_ldap_namespace(self) -> None:
        assert isinstance(ldap.settings, FlextLdapSettings)

    # --- Context Manager ---
    def test_enter_returns_self(self) -> None:
        api = ldap
        u.Ldap.Tests.that(api.__enter__(), eq=api)

    def test_exit_calls_disconnect(self) -> None:
        ldap.__exit__(None, None, None)

    def test_with_statement(self) -> None:
        api = ldap
        with api as ctx:
            u.Ldap.Tests.that(ctx, eq=api)

    # --- MRO Method Inheritance ---
    def test_is_connected_default_false(self) -> None:
        u.Ldap.Tests.that(not ldap.is_connected, eq=True)

    # --- Callback Type Guards ---
    @pytest.mark.parametrize(
        ("callback", "expected"),
        [
            pytest.param(None, False, id="none"),
            pytest.param(u.Ldap.Tests.multi_phase_cb, True, id="5_params_true"),
            pytest.param(u.Ldap.Tests.single_phase_cb, False, id="4_params_false"),
        ],
    )
    def test_is_multi_phase_callback(
        self,
        callback: t.Ldap.ProgressCallbackUnion,
        expected: bool,
    ) -> None:
        u.Ldap.Tests.that(
            FlextLdapSyncCallbacks.is_multi_phase_callback(callback), eq=expected
        )

    @pytest.mark.parametrize(
        ("callback", "expected"),
        [
            pytest.param(None, False, id="none"),
            pytest.param(u.Ldap.Tests.single_phase_cb, True, id="4_params_true"),
            pytest.param(u.Ldap.Tests.multi_phase_cb, False, id="5_params_false"),
        ],
    )
    def test_is_single_phase_callback(
        self,
        callback: t.Ldap.ProgressCallbackUnion,
        expected: bool,
    ) -> None:
        u.Ldap.Tests.that(
            FlextLdapSyncCallbacks.is_single_phase_callback(callback), eq=expected
        )

    def test_callback_param_count_constants(self) -> None:
        u.Ldap.Tests.that(
            len(inspect.signature(u.Ldap.Tests.multi_phase_cb).parameters),
            eq=c.Ldap.Callback.MULTI_PHASE_PARAM_COUNT,
        )
        u.Ldap.Tests.that(
            len(inspect.signature(u.Ldap.Tests.single_phase_cb).parameters),
            eq=c.Ldap.Callback.SINGLE_PHASE_PARAM_COUNT,
        )

    # --- API Methods (via MRO) ---
    @pytest.mark.parametrize(
        "method_name",
        c.Ldap.Tests.API_EXPECTED_METHODS,
    )
    def test_api_method_exists_and_callable(self, method_name: str) -> None:
        u.Ldap.Tests.that(callable(getattr(ldap, method_name)), eq=True)

    def test_disconnect_when_not_connected(self) -> None:
        ldap.disconnect()

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
            contains=str(c.Ldap.ErrorStrings.NOT_CONNECTED).lower(),
        )
