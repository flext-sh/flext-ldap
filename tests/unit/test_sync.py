"""Behavioral unit tests for LDAP sync via the public facade.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from pathlib import Path

import pytest

from flext_ldap import ldap, t
from tests import c, m, u

pytestmark = pytest.mark.unit


class TestsFlextLdapSync:
    """Assert observable sync contract through the public LDAP facade."""

    def test_execute_reports_not_connected_failure(self) -> None:
        # Arrange / Act
        result = ldap.execute()
        # Assert: placeholder mixin surfaces a failure, never a silent success
        error = u.Ldap.Tests.fail(result)
        u.Ldap.Tests.that(error, contains="Not connected")

    @pytest.mark.parametrize("phase", c.Ldap.Tests.SYNC_FACADE_MISSING_FILE_PHASES)
    def test_sync_phase_entries_missing_file_fails_with_parse_error(
        self,
        phase: str,
    ) -> None:
        # Arrange / Act
        result = ldap.sync_phase_entries(
            Path(c.Ldap.Tests.SYNC_FACADE_MISSING_LDIF_PATH),
            phase,
        )
        # Assert
        error = u.Ldap.Tests.fail(result)
        u.Ldap.Tests.that(error, contains="Failed to parse LDIF file")

    @pytest.mark.parametrize("phase", c.Ldap.Tests.SYNC_FACADE_MISSING_FILE_PHASES)
    def test_sync_multiple_phases_missing_file_fails_with_not_found(
        self,
        phase: str,
    ) -> None:
        # Arrange / Act
        result = ldap.sync_multiple_phases({
            phase: Path(c.Ldap.Tests.SYNC_FACADE_MISSING_LDIF_PATH),
        })
        # Assert
        error = u.Ldap.Tests.fail(result)
        u.Ldap.Tests.that(error, contains="not found")

    def test_sync_multiple_phases_missing_file_fails_when_stop_on_error(
        self,
        tmp_path: Path,
    ) -> None:
        # Arrange
        missing_file = tmp_path / c.Ldap.Tests.SYNC_FACADE_USERS_LDIF_FILENAME
        # Act
        result = ldap.sync_multiple_phases(
            {c.Ldap.Tests.SYNC_FACADE_PHASE_NAME_USERS: missing_file},
            settings=m.Ldap.SyncPhaseConfig(stop_on_error=True),
        )
        # Assert
        u.Ldap.Tests.fail(result)

    def test_sync_phase_entries_empty_ldif_succeeds_with_zeroed_result(
        self,
        tmp_path: Path,
    ) -> None:
        # Arrange
        ldif_file = tmp_path / c.Ldap.Tests.SYNC_FACADE_USERS_LDIF_FILENAME
        ldif_file.write_text("", encoding="utf-8")
        # Act
        summary = u.Ldap.Tests.ok(
            ldap.sync_phase_entries(
                ldif_file,
                c.Ldap.Tests.SYNC_FACADE_PHASE_NAME_USERS,
            ),
        )
        # Assert: public PhaseSyncResult contract for an empty phase
        u.Ldap.Tests.that(
            summary.phase_name,
            eq=c.Ldap.Tests.SYNC_FACADE_PHASE_NAME_USERS,
        )
        u.Ldap.Tests.that(summary.total_entries, eq=0)
        u.Ldap.Tests.that(summary.synced, eq=0)
        u.Ldap.Tests.that(summary.failed, eq=0)
        u.Ldap.Tests.that(summary.skipped, eq=0)
        u.Ldap.Tests.that(summary.success_rate, eq=100.0)

    def test_sync_multiple_phases_empty_ldif_succeeds_with_aggregate_result(
        self,
        tmp_path: Path,
    ) -> None:
        # Arrange
        ldif_file = tmp_path / c.Ldap.Tests.SYNC_FACADE_USERS_LDIF_FILENAME
        ldif_file.write_text("", encoding="utf-8")
        # Act
        aggregate = u.Ldap.Tests.ok(
            ldap.sync_multiple_phases({
                c.Ldap.Tests.SYNC_FACADE_PHASE_NAME_USERS: ldif_file,
            }),
        )
        # Assert: public MultiPhaseSyncResult contract
        u.Ldap.Tests.that(aggregate.overall_success, eq=True)
        u.Ldap.Tests.that(aggregate.total_entries, eq=0)
        u.Ldap.Tests.that(aggregate.total_synced, eq=0)
        u.Ldap.Tests.that(
            c.Ldap.Tests.SYNC_FACADE_PHASE_NAME_USERS in aggregate.phase_results,
            eq=True,
        )

    @pytest.mark.parametrize(
        "callback",
        [
            None,
            u.Ldap.Tests.single_phase_cb,
            u.Ldap.Tests.multi_phase_cb,
        ],
    )
    def test_sync_phase_entries_accepts_valid_callback_arities(
        self,
        tmp_path: Path,
        callback: t.Ldap.ProgressCallbackUnion | None,
    ) -> None:
        # Arrange: a real entry forces callback normalization + batch upsert
        ldif_file = tmp_path / c.Ldap.Tests.SYNC_FACADE_USERS_LDIF_FILENAME
        ldif_file.write_text(
            c.Ldap.Tests.SYNC_FACADE_SINGLE_ENTRY_LDIF,
            encoding="utf-8",
        )
        # Act: single- and multi-phase signatures (and no callback) are all accepted;
        # without a live server the batch stage fails rather than raising TypeError.
        result = ldap.sync_phase_entries(
            ldif_file,
            c.Ldap.Tests.SYNC_FACADE_PHASE_NAME_USERS,
            settings=m.Ldap.SyncPhaseConfig(progress_callback=callback),
        )
        # Assert
        u.Ldap.Tests.fail(result)

    def test_sync_phase_entries_rejects_invalid_callback_arity(
        self,
        tmp_path: Path,
    ) -> None:
        # Arrange
        ldif_file = tmp_path / c.Ldap.Tests.SYNC_FACADE_USERS_LDIF_FILENAME
        ldif_file.write_text(
            c.Ldap.Tests.SYNC_FACADE_SINGLE_ENTRY_LDIF,
            encoding="utf-8",
        )
        # Act / Assert: an unsupported arity is a contract violation, not a failure result
        with pytest.raises(TypeError, match="single-phase"):
            ldap.sync_phase_entries(
                ldif_file,
                c.Ldap.Tests.SYNC_FACADE_PHASE_NAME_USERS,
                settings=m.Ldap.SyncPhaseConfig(
                    progress_callback=u.Ldap.Tests.invalid_phase_cb,
                ),
            )

    def test_sync_multiple_phases_unparsable_file_fails_without_stop_on_error(
        self,
        tmp_path: Path,
    ) -> None:
        # Arrange
        bad_ldif = tmp_path / c.Ldap.Tests.SYNC_FACADE_USERS_LDIF_FILENAME
        bad_ldif.write_bytes(b"not valid ldif content\x00\xff")
        # Act
        result = ldap.sync_multiple_phases(
            {c.Ldap.Tests.SYNC_FACADE_PHASE_NAME_USERS: bad_ldif},
            settings=m.Ldap.SyncPhaseConfig(stop_on_error=False),
        )
        # Assert: aggregate reports failure honestly instead of masking the bad phase
        u.Ldap.Tests.fail(result)


__all__: list[str] = ["TestsFlextLdapSync"]
