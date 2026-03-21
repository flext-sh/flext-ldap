"""Unit tests for FlextLdap API facade.

Tests initialization, context manager, callback type guards, method signatures,
and model config. All tests use real functionality without mocks.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from collections.abc import Callable

import pytest
from flext_core import FlextSettings
from flext_ldif import FlextLdif

from flext_ldap import (
    MULTI_PHASE_CALLBACK_PARAM_COUNT,
    SINGLE_PHASE_CALLBACK_PARAM_COUNT,
    FlextLdap,
    FlextLdapConnection,
    FlextLdapOperations,
    FlextLdapSettings,
    FlextLdapSyncCallbacks,
)
from tests.constants import TestsFlextLdapConstants as c
from tests.models import TestsFlextLdapModels as m
from tests.protocols import TestsFlextLdapProtocols as p
from tests.utilities import TestsFlextLdapUtilities as u

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
    """Tests for FlextLdap API facade.

    Architecture: Single class per module following FLEXT patterns.
    Tests API structure and behavior without requiring LDAP connections.
    """

    @classmethod
    def _create_config(cls) -> FlextLdapSettings:
        """Factory for FlextLdapSettings."""
        return FlextLdapSettings()

    @classmethod
    def _create_connection(
        cls,
        config: FlextLdapSettings | None = None,
    ) -> FlextLdapConnection:
        """Factory for FlextLdapConnection."""
        resolved_config = config if config is not None else cls._create_config()
        return FlextLdapConnection(config=resolved_config)

    @classmethod
    def _create_api(
        cls,
        connection: FlextLdapConnection | None = None,
        ldif: FlextLdif | None = None,
    ) -> FlextLdap:
        """Factory for FlextLdap API instance."""
        conn = connection or cls._create_connection()
        return FlextLdap(
            connection=conn,
            operations=FlextLdapOperations(connection=conn),
            ldif=ldif,
        )

    # --- Initialization ---

    def test_init_with_dependencies(self) -> None:
        """Test FlextLdap initializes with all dependencies populated."""
        api = self._create_api()
        u.Tests.Matchers.that(api, none=False)
        u.Tests.Matchers.that(api._connection, none=False)
        u.Tests.Matchers.that(api._operations, none=False)
        u.Tests.Matchers.that(api._ldif, none=False)

    def test_init_default_ldif(self) -> None:
        """Test FlextLdap uses default FlextLdif when not provided."""
        u.Tests.Matchers.that(
            self._create_api(ldif=None)._ldif, is_=FlextLdif, none=False
        )

    def test_init_custom_ldif(self) -> None:
        """Test FlextLdap accepts custom FlextLdif instance."""
        custom = FlextLdif()
        u.Tests.Matchers.that(self._create_api(ldif=custom)._ldif, eq=custom)

    def test_inherits_config_from_connection(self) -> None:
        """Test API inherits config from connection."""
        config = self._create_config()
        api = self._create_api(connection=self._create_connection(config))
        assert api._config is not None

    def test_logger_available(self) -> None:
        """Test logger is available on API instance."""
        u.Tests.Matchers.that(self._create_api().logger, none=False)

    def test_config_returns_flext_settings(self) -> None:
        """Test config property returns FlextSettings."""
        assert isinstance(self._create_api().config, FlextSettings)

    def test_service_config_type(self) -> None:
        """Test _get_service_config_type returns FlextLdapSettings."""
        assert FlextLdap._get_service_config_type() is FlextLdapSettings

    # --- Context Manager ---

    def test_enter_returns_self(self) -> None:
        """Test __enter__ returns self for 'with' statement."""
        api = self._create_api()
        u.Tests.Matchers.that(api.__enter__(), eq=api)

    def test_exit_calls_disconnect(self) -> None:
        """Test __exit__ invokes cleanup without error."""
        self._create_api().__exit__(None, None, None)

    def test_with_statement(self) -> None:
        """Test 'with' statement returns same API instance."""
        api = self._create_api()
        with api as ctx:
            u.Tests.Matchers.that(ctx, eq=api)

    # --- Constants ---

    def test_callback_param_count_constants(self) -> None:
        """Test callback parameter count constants match expected values."""
        u.Tests.Matchers.that(MULTI_PHASE_CALLBACK_PARAM_COUNT, eq=5)
        u.Tests.Matchers.that(SINGLE_PHASE_CALLBACK_PARAM_COUNT, eq=4)

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
        u.Tests.Matchers.that(
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
        u.Tests.Matchers.that(
            FlextLdapSyncCallbacks.is_single_phase_callback(callback),
            eq=expected,
        )

    # --- API Methods ---

    @pytest.mark.parametrize(
        "method_name",
        [
            "connect",
            "disconnect",
            "search",
            "add",
            "modify",
            "delete",
        ],
    )
    def test_api_method_exists_and_callable(self, method_name: str) -> None:
        """Test API facade exposes expected method as callable."""
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
        u.Tests.Matchers.fail(self._create_api().search(search_options))

    def test_execute_returns_result(self) -> None:
        """Test execute returns r (failure when not connected)."""
        u.Tests.Matchers.fail(self._create_api().execute())

    # --- Model Config ---

    def test_model_config(self) -> None:
        """Test FlextLdap model_config has expected Pydantic v2 settings."""
        cfg = FlextLdap.model_config
        u.Tests.Matchers.that(cfg.get("frozen"), eq=False)
        u.Tests.Matchers.that(cfg.get("extra"), eq="forbid")
        u.Tests.Matchers.that(cfg.get("arbitrary_types_allowed"), eq=True)


__all__ = ["TestsFlextLdapApi"]
