"""Unit tests for ldap API facade (MRO-based).

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import inspect
from collections.abc import Callable

import pytest
from flext_tests import tm

from flext_core import FlextSettings
from flext_ldap import FlextLdapSettings, FlextLdapSyncCallbacks, ldap
from tests import c, m, u

pytestmark = [pytest.mark.unit]


class TestsFlextLdapApi:
    """Tests for ldap API facade — MRO-based, zero ceremony."""

    @classmethod
    def _create_api(cls) -> ldap:
        return ldap()

    # --- Initialization ---

    def test_init_no_args(self) -> None:
        tm.that(self._create_api(), none=False)

    def test_logger_available(self) -> None:
        tm.that(self._create_api().logger, none=False)

    def test_config_returns_flext_settings(self) -> None:
        assert isinstance(self._create_api().config, FlextSettings)

    def test_service_config_type(self) -> None:
        assert ldap._get_service_config_type() is FlextLdapSettings

    # --- Context Manager ---

    def test_enter_returns_self(self) -> None:
        api = self._create_api()
        tm.that(api.__enter__(), eq=api)

    def test_exit_calls_disconnect(self) -> None:
        self._create_api().__exit__(None, None, None)

    def test_with_statement(self) -> None:
        api = self._create_api()
        with api as ctx:
            tm.that(ctx, eq=api)

    # --- MRO Method Inheritance ---

    def test_is_connected_default_false(self) -> None:
        tm.that(not self._create_api().is_connected, eq=True)

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
        callback: Callable[..., None] | None,
        expected: bool,
    ) -> None:
        tm.that(FlextLdapSyncCallbacks.is_multi_phase_callback(callback), eq=expected)

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
        callback: Callable[..., None] | None,
        expected: bool,
    ) -> None:
        tm.that(FlextLdapSyncCallbacks.is_single_phase_callback(callback), eq=expected)

    def test_callback_param_count_constants(self) -> None:
        tm.that(
            len(inspect.signature(u.Ldap.Tests.multi_phase_cb).parameters),
            eq=c.Ldap.Callback.MULTI_PHASE_PARAM_COUNT,
        )
        tm.that(
            len(inspect.signature(u.Ldap.Tests.single_phase_cb).parameters),
            eq=c.Ldap.Callback.SINGLE_PHASE_PARAM_COUNT,
        )

    # --- API Methods (via MRO) ---

    @pytest.mark.parametrize(
        "method_name",
        c.Ldap.Tests.Api.EXPECTED_METHODS,
    )
    def test_api_method_exists_and_callable(self, method_name: str) -> None:
        api = self._create_api()
        assert hasattr(api, method_name)
        assert callable(getattr(api, method_name))

    def test_disconnect_when_not_connected(self) -> None:
        self._create_api().disconnect()

    def test_search_without_connection_returns_failure(self) -> None:
        search_options = m.Ldap.SearchOptions(
            base_dn=c.Ldap.Tests.RFC.DEFAULT_BASE_DN,
            filter_str=c.Ldap.Tests.RFC.DEFAULT_FILTER,
            scope=c.Ldap.SearchScope.SUBTREE.value,
        )
        tm.fail(self._create_api().search(search_options))

    def test_execute_returns_result(self) -> None:
        tm.fail(self._create_api().execute())

    # --- Model Config ---

    def test_model_config(self) -> None:
        cfg = ldap.model_config
        tm.that(not cfg.get("frozen"), eq=not c.Ldap.Tests.ApiModelConfig.FROZEN)
        tm.that(cfg.get("extra"), eq=c.Ldap.Tests.ApiModelConfig.EXTRA)
        tm.that(
            cfg.get("arbitrary_types_allowed"),
            eq=c.Ldap.Tests.ApiModelConfig.ARBITRARY_TYPES_ALLOWED,
        )
