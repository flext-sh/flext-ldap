"""Unit tests for LDAP sync mixins exposed through the public facade.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from pathlib import Path

import pytest
from flext_tests import tm

from flext_ldap import FlextLdap, FlextLdapSync, FlextLdapSyncCallbacks, ldap
from tests import m, p

pytestmark = pytest.mark.unit


def _single_phase_callback(
    _current: int,
    _total: int,
    _dn: str,
    _stats: p.Ldap.LdapBatchStats,
) -> None:
    """Callback with the single-phase signature."""


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
        tm.fail(FlextLdapSync().execute())

    def test_sync_methods_are_available_on_public_facade(self) -> None:
        client = self._create_client()
        tm.that(callable(client.sync_phase_entries), eq=True)
        tm.that(callable(client.sync_multiple_phases), eq=True)

    def test_sync_phase_entries_missing_path_returns_failure(self) -> None:
        result = self._create_client().sync_phase_entries(
            Path("/tmp/flext-ldap-sync-missing.ldif"),
            "users",
        )
        tm.fail(result)

    def test_sync_multiple_phases_skips_missing_files(self) -> None:
        result = self._create_client().sync_multiple_phases({
            "users": Path("/tmp/flext-ldap-sync-missing.ldif"),
        })
        sync_result = tm.ok(result)
        tm.that(sync_result.total_entries, eq=0)
        tm.that(sync_result.total_synced, eq=0)
        tm.that(sync_result.phase_results, empty=True)

    def test_convert_entries_to_protocol_returns_copy(self) -> None:
        entries = [self._entry("cn=test,dc=example,dc=com")]
        protocol_entries = FlextLdapSyncCallbacks.convert_entries_to_protocol(entries)
        tm.that(protocol_entries, len=1)
        assert protocol_entries is not entries

    def test_make_phase_progress_callback_keeps_single_phase_callback(self) -> None:
        config = m.Ldap.SyncPhaseConfig(progress_callback=_single_phase_callback)
        callback = FlextLdapSync._make_phase_progress_callback("users", config)
        assert callback is _single_phase_callback


__all__ = ["TestsFlextLdapSync", "pytestmark"]
