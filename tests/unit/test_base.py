"""Behavioral unit tests for flext_ldap.base.FlextLdapService.

Exercises only the observable public contract of the LDAP service base:
- ``execute()`` returns an ``r[T]`` whose success/failure/value/error are honored.
- ``r[T]`` combinators (map / flat_map / recover / unwrap_or) behave lawfully.
- ``settings`` / ``fetch_settings()`` expose the composed MRO namespaces.
- project settings stay isolated from the root ``FlextSettings`` singleton.
- distinct service instances resolve independently.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import pytest
from flext_tests import FlextTestsSettings

from flext_core import FlextSettings
from tests.constants import c
from tests.models import m

pytestmark = pytest.mark.unit


class TestsFlextLdapBase:
    """Behavioral contract of FlextLdapService via its test services."""

    # ── execute(): success outcome ─────────────────────────────────────

    def test_execute_success_reports_success(self) -> None:
        result = m.Ldap.Tests.SuccessService().execute()

        assert result.success
        assert not result.failure

    def test_execute_success_carries_true_value(self) -> None:
        result = m.Ldap.Tests.SuccessService().execute()

        assert result.unwrap() is True
        assert result.error is None

    # ── execute(): failure outcome ─────────────────────────────────────

    def test_execute_failure_reports_failure(self) -> None:
        result = m.Ldap.Tests.FailService().execute()

        assert result.failure
        assert not result.success

    def test_execute_failure_exposes_declared_error_message(self) -> None:
        result = m.Ldap.Tests.FailService().execute()

        assert result.error == c.Ldap.Tests.BASE_FAIL_ERROR_MESSAGE

    # ── r[T] combinator laws on the returned result ────────────────────

    def test_map_transforms_success_value_only(self) -> None:
        mapped = m.Ldap.Tests.SuccessService().execute().map(lambda ok: not ok)

        assert mapped.success
        assert mapped.unwrap() is False

    def test_map_does_not_run_on_failure(self) -> None:
        mapped = m.Ldap.Tests.FailService().execute().map(lambda ok: not ok)

        assert mapped.failure
        assert mapped.error == c.Ldap.Tests.BASE_FAIL_ERROR_MESSAGE

    def test_recover_replaces_failure_with_fallback_value(self) -> None:
        recovered = m.Ldap.Tests.FailService().execute().recover(lambda _err: True)

        assert recovered.success
        assert recovered.unwrap() is True

    @pytest.mark.parametrize(
        ("service_factory", "fallback", "expected"),
        [
            (m.Ldap.Tests.SuccessService, False, True),
            (m.Ldap.Tests.FailService, False, False),
        ],
    )
    def test_unwrap_or_returns_value_or_fallback(
        self,
        service_factory: type[m.Ldap.Tests.SuccessService | m.Ldap.Tests.FailService],
        fallback: bool,
        expected: bool,
    ) -> None:
        assert service_factory().execute().unwrap_or(fallback) is expected

    # ── settings: isolation from the root singleton ────────────────────

    def test_settings_isolated_from_root_global(self) -> None:
        cfg = m.Ldap.Tests.SuccessService().settings

        assert cfg is not glob
        assert isinstance(glob, FlextSettings)
        assert isinstance(cfg, FlextTestsSettings)

    # ── settings: composed MRO namespaces exposed publicly ─────────────

    @pytest.mark.parametrize(
        "namespace",
        ["Cli", "Ldif", "Ldap", "Tests"],
    )
    def test_fetch_settings_exposes_mro_namespace(self, namespace: str) -> None:
        settings = m.Ldap.Tests.SuccessService.fetch_settings()

        assert isinstance(getattr(settings, namespace), m.SettingsValue)

    def test_instance_settings_match_fetch_settings_singleton(self) -> None:
        instance = m.Ldap.Tests.SuccessService()

        assert instance.settings is m.Ldap.Tests.SuccessService.fetch_settings()

    # ── independence across instances ──────────────────────────────────

    def test_distinct_services_resolve_independently(self) -> None:
        ok, bad = m.Ldap.Tests.SuccessService(), m.Ldap.Tests.FailService()

        assert ok.execute().success
        assert bad.execute().failure
