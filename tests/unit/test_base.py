"""Unit tests for flext_ldap.base.FlextLdapServiceBase.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import override

import pytest

from flext_core import FlextSettings, r
from flext_ldap import FlextLdapServiceBase, base, s
from tests import c, m, p

pytestmark = pytest.mark.unit


class TestsFlextLdapBase:
    """Tests for FlextLdapServiceBase."""

    class _SuccessService(FlextLdapServiceBase):
        @override
        def execute(
            self,
            **_kwargs: str | float | bool | None,
        ) -> r[m.Ldap.SearchResult]:
            return r[m.Ldap.SearchResult].ok(
                m.Ldap.SearchResult(entries=[], search_options=None),
            )

    class _FailService(FlextLdapServiceBase):
        @override
        def execute(
            self,
            **_kwargs: str | float | bool | None,
        ) -> r[m.Ldap.SearchResult]:
            return r[m.Ldap.SearchResult].fail(c.Ldap.Tests.Base.FAIL_ERROR_MESSAGE)

    # ── Structure & exports ────────────────────────────────────────────

    def test_exports(self) -> None:
        assert callable(s)
        assert c.Ldap.Tests.Base.EXPORT_ALIAS in base.__all__

    def test_has_docstring(self) -> None:
        assert s.__doc__ is not None

    # ── Execute: success + failure ─────────────────────────────────────

    def test_execute_success(self) -> None:
        result = self._SuccessService().execute()
        assert result.is_success

    def test_execute_failure(self) -> None:
        result = self._FailService().execute()
        assert result.is_failure
        assert result.error == c.Ldap.Tests.Base.FAIL_ERROR_MESSAGE

    # ── Config + Logger ────────────────────────────────────────────────

    def test_config_property(self) -> None:
        svc = self._SuccessService()
        assert isinstance(svc.config, p.Settings)

    def test_config_matches_global(self) -> None:
        cfg = self._SuccessService().config
        glob = FlextSettings.get_global()
        assert cfg.app_name == glob.app_name
        assert cfg.version == glob.version

    def test_logger_property(self) -> None:
        assert self._SuccessService().logger is not None

    # ── Model config inheritance ───────────────────────────────────────

    @pytest.mark.parametrize(
        ("attr", "expected"),
        c.Ldap.Tests.ModelConfig.SERVICE_BASE_CONFIG,
        ids=[x[0] for x in c.Ldap.Tests.ModelConfig.SERVICE_BASE_CONFIG],
    )
    def test_model_config(self, attr: str, expected: str | bool) -> None:
        assert self._SuccessService.model_config.get(attr) == expected

    # ── Independence ───────────────────────────────────────────────────

    def test_multiple_services_independent(self) -> None:
        a, b = self._SuccessService(), self._FailService()
        assert a.execute().is_success
        assert b.execute().is_failure
