"""Unit tests for FlextLdap API facade (MRO-based).

Tests initialization, context manager, callback type guards, method signatures,
and model config. All tests use real functionality without mocks.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import inspect
from collections.abc import Callable

import pytest
from flext_core import FlextSettings
from flext_tests import tm

from flext_ldap import FlextLdapSettings, FlextLdapSyncCallbacks, ldap
from tests import c, m, p

pytestmark = [pytest.mark.unit]


def _single_phase_cb(
    _a: int,
    _b: int,
    _c: str,
    _d: p.Ldap.LdapBatchStats,
) -> None:
    """Test callback with 4 parameters (single-phase)."""


def _multi_phase_cb(
    _a: str,
    _b: int,
    _c: int,
    _d: str,
    _e: p.Ldap.LdapBatchStats,
) -> None:
    """Test callback with 5 parameters (multi-phase)."""


class TestsFlextLdapApi:
    """Tests for ldap API facade — MRO-based, zero ceremony.

    ldap() instantiates with no args. Everything via MRO:
    FlextLdap → FlextLdapSync → FlextLdapOperations → FlextLdapConnection
    """

    @classmethod
    def _create_api(cls) -> ldap:
        """Factory — MRO-based, no constructor args."""
        return ldap()

    # --- Initialization ---

    def test_init_no_args(self) -> None:
        """Test FlextLdap initializes with zero ceremony."""
        api = self._create_api()
        tm.that(api, none=False)

    def test_logger_available(self) -> None:
        """Test logger is available on API instance."""
        tm.that(self._create_api().logger, none=False)

    def test_config_returns_flext_settings(self) -> None:
        """Test config property returns FlextSettings."""
        assert isinstance(self._create_api().config, FlextSettings)

    def test_service_config_type(self) -> None:
        """Test _get_service_config_type returns FlextLdapSettings."""
        assert ldap._get_service_config_type() is FlextLdapSettings

    # --- Context Manager ---

    def test_enter_returns_self(self) -> None:
        """Test __enter__ returns self for 'with' statement."""
        api = self._create_api()
        tm.that(api.__enter__(), eq=api)

    def test_exit_calls_disconnect(self) -> None:
        """Test __exit__ invokes cleanup without error."""
        self._create_api().__exit__(None, None, None)

    def test_with_statement(self) -> None:
        """Test 'with' statement returns same API instance."""
        api = self._create_api()
        with api as ctx:
            tm.that(ctx, eq=api)

    # --- MRO Method Inheritance ---

    def test_is_connected_default_false(self) -> None:
        """Test is_connected returns False on fresh instance."""
        tm.that(not self._create_api().is_connected, eq=True)

    # --- Callback Type Guards ---

    @pytest.mark.parametrize(
        ("callback", "expected"),
        [
            pytest.param(None, False, id="none"),
            pytest.param(_multi_phase_cb, True, id="5_params_true"),
            pytest.param(_single_phase_cb, False, id="4_params_false"),
        ],
    )
    def test_is_multi_phase_callback(
        self,
        callback: Callable[..., None] | None,
        expected: bool,
    ) -> None:
        """Test is_multi_phase_callback with various param counts."""
        tm.that(
            FlextLdapSyncCallbacks.is_multi_phase_callback(callback),
            eq=expected,
        )

    @pytest.mark.parametrize(
        ("callback", "expected"),
        [
            pytest.param(None, False, id="none"),
            pytest.param(_single_phase_cb, True, id="4_params_true"),
            pytest.param(_multi_phase_cb, False, id="5_params_false"),
        ],
    )
    def test_is_single_phase_callback(
        self,
        callback: Callable[..., None] | None,
        expected: bool,
    ) -> None:
        """Test is_single_phase_callback with various param counts."""
        tm.that(
            FlextLdapSyncCallbacks.is_single_phase_callback(callback),
            eq=expected,
        )

    def test_callback_param_count_constants(self) -> None:
        """Test callback parameter count constants match expected values."""
        tm.that(len(inspect.signature(_multi_phase_cb).parameters), eq=5)
        tm.that(len(inspect.signature(_single_phase_cb).parameters), eq=4)

    # --- API Methods (via MRO) ---

    @pytest.mark.parametrize(
        "method_name",
        [
            "connect",
            "disconnect",
            "search",
            "add",
            "modify",
            "delete",
            "upsert",
            "batch_upsert",
            "sync_phase_entries",
            "sync_multiple_phases",
        ],
    )
    def test_api_method_exists_and_callable(self, method_name: str) -> None:
        """Test API facade exposes expected method as callable via MRO."""
        api = self._create_api()
        assert hasattr(api, method_name)
        assert callable(getattr(api, method_name))

    def test_disconnect_when_not_connected(self) -> None:
        """Test disconnect does not raise when not connected."""
        self._create_api().disconnect()

    def test_search_without_connection_returns_failure(self) -> None:
        """Test search returns r failure when not connected."""
        search_options = m.Ldap.SearchOptions(
            base_dn=c.Ldap.Tests.RFC.DEFAULT_BASE_DN,
            filter_str=c.Ldap.Tests.RFC.DEFAULT_FILTER,
            scope=c.Ldap.SearchScope.SUBTREE.value,
        )
        tm.fail(self._create_api().search(search_options))

    def test_execute_returns_result(self) -> None:
        """Test execute returns r (failure when not connected)."""
        tm.fail(self._create_api().execute())

    # --- Model Config ---

    def test_model_config(self) -> None:
        """Test FlextLdap model_config has expected Pydantic v2 settings."""
        cfg = ldap.model_config
        tm.that(not cfg.get("frozen"), eq=True)
        tm.that(cfg.get("extra"), eq="ignore")
        tm.that(cfg.get("arbitrary_types_allowed"), eq=True)
