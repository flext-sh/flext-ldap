"""Unit tests for LDAP sync mixins exposed through the public facade.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from pathlib import Path

import pytest

from flext_ldap import FlextLdap, FlextLdapSync, ldap
from tests import c, m, u

pytestmark = pytest.mark.unit


class TestsFlextLdapSync:
    """Validate LDAP sync behavior without leaving the public facade pattern."""

    @staticmethod
    def _entry(dn: str) -> m.Ldif.Entry:
        return m.Ldif.Entry(
            dn=m.Ldif.DN(value=dn),
            attributes=m.Ldif.Attributes(
                attributes={},
                attribute_metadata={},
            ),
        )

    @staticmethod
    def _create_client() -> FlextLdap:
        return ldap()

    def test_sync_mixin_execute_is_placeholder(self) -> None:
        u.Tests.Matchers.fail(FlextLdapSync().execute())

    def test_sync_methods_are_available_on_public_facade(self) -> None:
        client = self._create_client()
        u.Tests.Matchers.that(callable(client.sync_phase_entries), eq=True)
        u.Tests.Matchers.that(callable(client.sync_multiple_phases), eq=True)

    def test_sync_phase_entries_missing_path_returns_failure(self) -> None:
        result = self._create_client().sync_phase_entries(
            Path(c.Ldap.Tests.SyncFacade.MISSING_LDIF_PATH),
            c.Ldap.Tests.SyncFacade.PHASE_NAME_USERS,
        )
        u.Tests.Matchers.fail(result)

    def test_sync_multiple_phases_skips_missing_files(self) -> None:
        result = self._create_client().sync_multiple_phases({
            c.Ldap.Tests.SyncFacade.PHASE_NAME_USERS: Path(
                c.Ldap.Tests.SyncFacade.MISSING_LDIF_PATH
            ),
        })
        sync_result = u.Tests.Matchers.ok(result)
        u.Tests.Matchers.that(
            sync_result.total_entries, eq=c.Ldap.Tests.SyncFacade.ZERO_COUNT
        )
        u.Tests.Matchers.that(
            sync_result.total_synced, eq=c.Ldap.Tests.SyncFacade.ZERO_COUNT
        )
        u.Tests.Matchers.that(sync_result.phase_results, empty=True)

    def test_make_phase_progress_callback_keeps_single_phase_callback(self) -> None:
        cb = u.Ldap.Tests.single_phase_cb
        config = m.Ldap.SyncPhaseConfig(progress_callback=cb)
        callback = FlextLdapSync._make_phase_progress_callback(
            c.Ldap.Tests.SyncFacade.PHASE_NAME_USERS, config
        )
        assert callback is cb


__all__ = ["TestsFlextLdapSync", "pytestmark"]
