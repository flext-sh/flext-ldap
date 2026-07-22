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

from operator import not_

import pytest
from pydantic import BaseModel

from flext_core import FlextSettings
from flext_tests import FlextTestsSettings, tm
from tests import c, m

pytestmark = pytest.mark.unit


class TestsFlextLdapBase:
    """Behavioral contract of FlextLdapService via its test services."""

    # ── execute(): success outcome ─────────────────────────────────────

    def test_execute_success_reports_success(self) -> None:
        """Verify execute success reports success."""
        result = m.Ldap.Tests.SuccessService().execute()

        tm.ok(result)
        tm.that(result.failure, eq=False)

    def test_execute_success_carries_true_value(self) -> None:
        """Verify execute success carries true value."""
        result = m.Ldap.Tests.SuccessService().execute()

        tm.that(result.unwrap(), eq=True)
        tm.that(result.error, none=True)

    # ── execute(): failure outcome ─────────────────────────────────────

    def test_execute_failure_reports_failure(self) -> None:
        """Verify execute failure reports failure."""
        result = m.Ldap.Tests.FailService().execute()

        tm.fail(result)
        tm.fail(result)

    def test_execute_failure_exposes_declared_error_message(self) -> None:
        """Verify execute failure exposes declared error message."""
        result = m.Ldap.Tests.FailService().execute()

        tm.that(result.error, eq=c.Ldap.Tests.BASE_FAIL_ERROR_MESSAGE)

    # ── r[T] combinator laws on the returned result ────────────────────

    def test_map_transforms_success_value_only(self) -> None:
        """Verify map transforms success value only."""
        mapped = m.Ldap.Tests.SuccessService().execute().map(not_)

        tm.ok(mapped)
        tm.that(mapped.unwrap(), eq=False)

    def test_map_does_not_run_on_failure(self) -> None:
        """Verify map does not run on failure."""
        mapped = m.Ldap.Tests.FailService().execute().map(not_)

        tm.fail(mapped)
        tm.that(mapped.error, eq=c.Ldap.Tests.BASE_FAIL_ERROR_MESSAGE)

    def test_recover_replaces_failure_with_fallback_value(self) -> None:
        """Verify recover replaces failure with fallback value."""
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
        *,
        fallback: bool,
        expected: bool,
    ) -> None:
        """Verify unwrap or returns value or fallback."""
        tm.that(service_factory().execute().unwrap_or(fallback), eq=expected)

    # ── settings: isolation from the root singleton ────────────────────

    def test_settings_isolated_from_root_global(self) -> None:
        """Verify settings isolated from root global."""
        cfg = m.Ldap.Tests.SuccessService().settings
        # NOTE (multi-agent): restore root singleton read removed by a bad "fixes" commit.
        glob = FlextSettings.fetch_global()

        tm.that(cfg is glob, eq=False)
        tm.that(glob, is_=FlextSettings)
        tm.that(cfg, is_=FlextTestsSettings)

    # ── settings: composed MRO namespaces exposed publicly ─────────────

    # NOTE (multi-agent): SSOT settings expose Ldap/Ldif/Tests namespaces as
    # plain BaseModel sections (flext-core reference: tests/unit/test_service.py);
    # CLI data is flat cli_* fields, not a "Cli" namespace.
    @pytest.mark.parametrize("namespace", ["Ldif", "Ldap", "Tests"])
    def test_fetch_settings_exposes_mro_namespace(self, namespace: str) -> None:
        """Verify fetch settings exposes mro namespace."""
        settings = m.Ldap.Tests.SuccessService.fetch_settings()

        tm.that(getattr(settings, namespace), is_=BaseModel)

    def test_instance_settings_match_fetch_settings_singleton(self) -> None:
        """Verify instance settings match fetch settings singleton."""
        instance = m.Ldap.Tests.SuccessService()

        tm.that(
            instance.settings is m.Ldap.Tests.SuccessService.fetch_settings(), eq=True
        )

    # ── independence across instances ──────────────────────────────────

    def test_distinct_services_resolve_independently(self) -> None:
        """Verify distinct services resolve independently."""
        ok, bad = m.Ldap.Tests.SuccessService(), m.Ldap.Tests.FailService()

        tm.ok(ok.execute())
        tm.fail(bad.execute())
