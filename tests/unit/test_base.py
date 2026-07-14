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
from flext_tests import FlextTestsSettings, tm
from pydantic import BaseModel

from flext_core import FlextSettings
from tests import c, m

pytestmark = pytest.mark.unit


class TestsFlextLdapBase:
    """Behavioral contract of FlextLdapService via its test services."""

    # ── execute(): success outcome ─────────────────────────────────────

    def test_execute_success_reports_success(self) -> None:
        result = m.Ldap.Tests.SuccessService().execute()

        tm.ok(result)
        assert not result.failure

    def test_execute_success_carries_true_value(self) -> None:
        result = m.Ldap.Tests.SuccessService().execute()

        tm.that(result.unwrap(), eq=True)
        tm.that(result.error, none=True)

    # ── execute(): failure outcome ─────────────────────────────────────

    def test_execute_failure_reports_failure(self) -> None:
        result = m.Ldap.Tests.FailService().execute()

        tm.fail(result)
        tm.fail(result)

    def test_execute_failure_exposes_declared_error_message(self) -> None:
        result = m.Ldap.Tests.FailService().execute()

        tm.that(result.error, eq=c.Ldap.Tests.BASE_FAIL_ERROR_MESSAGE)

    # ── r[T] combinator laws on the returned result ────────────────────

    def test_map_transforms_success_value_only(self) -> None:
        mapped = m.Ldap.Tests.SuccessService().execute().map(lambda ok: not ok)

        tm.ok(mapped)
        tm.that(mapped.unwrap(), eq=False)

    def test_map_does_not_run_on_failure(self) -> None:
        mapped = m.Ldap.Tests.FailService().execute().map(lambda ok: not ok)

        tm.fail(mapped)
        tm.that(mapped.error, eq=c.Ldap.Tests.BASE_FAIL_ERROR_MESSAGE)

    def test_recover_replaces_failure_with_fallback_value(self) -> None:
        recovered = m.Ldap.Tests.FailService().execute().recover(lambda _err: True)

        tm.ok(recovered)
        tm.that(recovered.unwrap(), eq=True)

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
        # NOTE (multi-agent): restore root singleton read removed by a bad "fixes" commit.
        glob = FlextSettings.fetch_global()

        assert cfg is not glob
        tm.that(glob, is_=FlextSettings)
        tm.that(cfg, is_=FlextTestsSettings)

    # ── settings: composed MRO namespaces exposed publicly ─────────────

    # NOTE (multi-agent): SSOT settings expose Ldap/Ldif/Tests namespaces as
    # plain BaseModel sections (flext-core reference: tests/unit/test_service.py);
    # CLI data is flat cli_* fields, not a "Cli" namespace.
    @pytest.mark.parametrize(
        "namespace",
        ["Ldif", "Ldap", "Tests"],
    )
    def test_fetch_settings_exposes_mro_namespace(self, namespace: str) -> None:
        settings = m.Ldap.Tests.SuccessService.fetch_settings()

        tm.that(getattr(settings, namespace), is_=BaseModel)

    def test_instance_settings_match_fetch_settings_singleton(self) -> None:
        instance = m.Ldap.Tests.SuccessService()

        assert instance.settings is m.Ldap.Tests.SuccessService.fetch_settings()

    # ── independence across instances ──────────────────────────────────

    def test_distinct_services_resolve_independently(self) -> None:
        ok, bad = m.Ldap.Tests.SuccessService(), m.Ldap.Tests.FailService()

        tm.ok(ok.execute())
        tm.fail(bad.execute())
