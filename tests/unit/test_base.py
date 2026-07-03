"""Unit tests for flext_ldap.base.FlextLdapService.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import pytest
from flext_tests.settings import FlextTestsSettings

from flext_core import FlextSettings
from tests.constants import c
from tests.models import m

pytestmark = pytest.mark.unit


class TestsFlextLdapBase:
    """Tests for FlextLdapService."""

    # ── Execute: success + failure ─────────────────────────────────────

    def test_execute_success(self) -> None:
        result = m.Ldap.Tests.SuccessService().execute()
        assert result.success

    def test_execute_failure(self) -> None:
        result = m.Ldap.Tests.FailService().execute()
        assert result.failure
        assert result.error == c.Ldap.Tests.BASE_FAIL_ERROR_MESSAGE

    # ── Config ─────────────────────────────────────────────────────────

    def test_settings_is_isolated_from_root(self) -> None:
        """Project settings must be isolated from root FlextSettings (rule 3).

        FlextLdapSettings inherits ``FlextSettingsBase`` and owns its own
        per-class singleton — it does NOT mix root concrete
        fields like ``app_name`` / ``version``.
        """
        cfg = m.Ldap.Tests.SuccessService().settings
        glob = FlextSettings.fetch_global()
        assert cfg is not glob
        assert isinstance(glob, FlextSettings)
        assert isinstance(cfg, FlextTestsSettings)
        assert isinstance(cfg.Tests, m.SettingsValue)

    def test_fetch_settings_exposes_full_mro_namespaces(self) -> None:
        settings = m.Ldap.Tests.SuccessService.fetch_settings()

        assert isinstance(settings.Cli, m.SettingsValue)
        assert isinstance(settings.Ldif, m.SettingsValue)
        assert isinstance(settings.Ldap, m.SettingsValue)
        assert isinstance(settings.Tests, m.SettingsValue)

    # ── Independence ───────────────────────────────────────────────────

    def test_multiple_services_independent(self) -> None:
        a, b = m.Ldap.Tests.SuccessService(), m.Ldap.Tests.FailService()
        assert a.execute().success
        assert b.execute().failure
