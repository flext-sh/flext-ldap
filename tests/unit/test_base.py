"""Unit tests for flext_ldap.base.FlextLdapService.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import pytest
from flext_core import FlextSettings

from flext_ldap import base
from tests import c, m, p, s

pytestmark = pytest.mark.unit


class TestsFlextLdapBase:
    """Tests for FlextLdapService."""

    # ── Structure & exports ────────────────────────────────────────────

    def test_exports(self) -> None:
        assert callable(s)
        assert c.Ldap.Tests.BASE_EXPORT_ALIAS in base.__all__

    def test_has_docstring(self) -> None:
        assert s.__doc__ is not None

    # ── Execute: success + failure ─────────────────────────────────────

    def test_execute_success(self) -> None:
        result = m.Ldap.Tests.SuccessService().execute()
        assert result.success

    def test_execute_failure(self) -> None:
        result = m.Ldap.Tests.FailService().execute()
        assert result.failure
        assert result.error == c.Ldap.Tests.BASE_FAIL_ERROR_MESSAGE

    # ── Config + Logger ────────────────────────────────────────────────

    def test_config_property(self) -> None:
        svc = m.Ldap.Tests.SuccessService()
        assert isinstance(svc.settings, p.Settings)

    def test_config_matches_global(self) -> None:
        cfg = m.Ldap.Tests.SuccessService().settings
        glob = FlextSettings.fetch_global()
        assert cfg.app_name == glob.app_name
        assert cfg.version == glob.version

    def test_logger_property(self) -> None:
        assert m.Ldap.Tests.SuccessService().logger is not None

    # ── Model settings inheritance ───────────────────────────────────────

    @pytest.mark.parametrize(
        ("attr", "expected"),
        c.Ldap.Tests.MODEL_CONFIG_SERVICE_BASE_CONFIG,
        ids=[x[0] for x in c.Ldap.Tests.MODEL_CONFIG_SERVICE_BASE_CONFIG],
    )
    def test_model_config(self, attr: str, expected: str | bool) -> None:
        assert m.Ldap.Tests.SuccessService.model_config.get(attr) == expected

    # ── Independence ───────────────────────────────────────────────────

    def test_multiple_services_independent(self) -> None:
        a, b = m.Ldap.Tests.SuccessService(), m.Ldap.Tests.FailService()
        assert a.execute().success
        assert b.execute().failure
