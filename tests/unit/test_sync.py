"""Unit tests for LDAP sync mixins exposed through the public facade.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import tempfile
from pathlib import Path

import pytest

from flext_ldap import FlextLdapSync, ldap
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

    def test_sync_mixin_execute_is_placeholder(self) -> None:
        u.Ldap.Tests.fail(FlextLdapSync().execute())

    def test_sync_phase_entries_missing_path_returns_failure(self) -> None:
        result = ldap.sync_phase_entries(
            Path(c.Ldap.Tests.SYNC_FACADE_MISSING_LDIF_PATH),
            c.Ldap.Tests.SYNC_FACADE_PHASE_NAME_USERS,
        )
        u.Ldap.Tests.fail(result)

    def test_sync_multiple_phases_missing_files_fails(self) -> None:
        result = ldap.sync_multiple_phases({
            c.Ldap.Tests.SYNC_FACADE_PHASE_NAME_USERS: Path(
                c.Ldap.Tests.SYNC_FACADE_MISSING_LDIF_PATH
            ),
        })
        u.Ldap.Tests.fail(result)

    def test_sync_phase_entries_invalid_callback_signature_raises(
        self,
        tmp_path: Path,
    ) -> None:
        ldif_file = tmp_path / c.Ldap.Tests.SYNC_FACADE_USERS_LDIF_FILENAME
        ldif_file.write_text(
            c.Ldap.Tests.SYNC_FACADE_SINGLE_ENTRY_LDIF, encoding="utf-8"
        )

        with pytest.raises(TypeError):
            ldap.sync_phase_entries(
                ldif_file,
                c.Ldap.Tests.SYNC_FACADE_PHASE_NAME_USERS,
                settings=m.Ldap.SyncPhaseConfig(
                    progress_callback=u.Ldap.Tests.invalid_phase_cb,
                ),
            )

    def test_sync_phase_entries_success_with_real_connection(
        self,
        tmp_path: Path,
        connection_config: m.Ldap.ConnectionConfig,
    ) -> None:
        ldif_file = tmp_path / c.Ldap.Tests.SYNC_FACADE_USERS_LDIF_FILENAME
        ldif_file.write_text(
            c.Ldap.Tests.SYNC_FACADE_SINGLE_ENTRY_LDIF, encoding="utf-8"
        )

        u.Ldap.Tests.ensure_basic_ldap_structure()
        u.Ldap.Tests.assert_connection_success(ldap.connect(connection_config))

        phase_result = u.Ldap.Tests.ok(
            ldap.sync_phase_entries(
                ldif_file,
                c.Ldap.Tests.SYNC_FACADE_PHASE_NAME_USERS,
                settings=m.Ldap.SyncPhaseConfig(
                    progress_callback=u.Ldap.Tests.single_phase_cb,
                ),
            ),
        )
        u.Ldap.Tests.that(
            phase_result.phase_name,
            eq=c.Ldap.Tests.SYNC_FACADE_PHASE_NAME_USERS,
        )
        u.Ldap.Tests.that(phase_result.total_entries > 0, eq=True)

        search_result = u.Ldap.Tests.ok(
            ldap.search(
                m.Ldap.SearchOptions.base_scope(c.Ldap.Tests.SYNC_FACADE_TEST_USER_DN),
            ),
        )
        u.Ldap.Tests.that(search_result.total_count > 0, eq=True)
        ldap.disconnect()

    def test_sync_multiple_phases_stop_on_error_returns_failure(
        self,
        tmp_path: Path,
        connection_config: m.Ldap.ConnectionConfig,
    ) -> None:
        users_ldif = tmp_path / c.Ldap.Tests.SYNC_FACADE_USERS_LDIF_FILENAME
        users_ldif.write_text(
            c.Ldap.Tests.SYNC_FACADE_SINGLE_ENTRY_LDIF, encoding="utf-8"
        )

        u.Ldap.Tests.ensure_basic_ldap_structure()
        u.Ldap.Tests.assert_connection_success(ldap.connect(connection_config))

        result = ldap.sync_multiple_phases(
            {
                c.Ldap.Tests.SYNC_FACADE_PHASE_NAME_USERS: users_ldif,
                c.Ldap.Tests.SYNC_FACADE_PHASE_NAME_GROUPS: Path(
                    c.Ldap.Tests.SYNC_FACADE_MISSING_LDIF_PATH,
                ),
            },
            settings=m.Ldap.SyncPhaseConfig(stop_on_error=True),
        )
        error = u.Ldap.Tests.fail(result)
        u.Ldap.Tests.that(
            bool(c.Ldap.Tests.SYNC_PHASE_FAILURE_RE.search(error)), eq=True
        )
        u.Ldap.Tests.that(error, contains=c.Ldap.Tests.SYNC_FACADE_PHASE_NAME_GROUPS)
        ldap.disconnect()

    def test_sync_multiple_phases_phase_failure_returns_fail_when_not_stop_on_error(
        self,
    ) -> None:
        with tempfile.NamedTemporaryFile(suffix=".ldif", delete=False) as tmp:
            tmp.write(b"not valid ldif content\x00\xff")
            bad_ldif = Path(tmp.name)
        result = ldap.sync_multiple_phases(
            {c.Ldap.Tests.SYNC_FACADE_PHASE_NAME_USERS: bad_ldif},
            settings=m.Ldap.SyncPhaseConfig(stop_on_error=False),
        )
        u.Ldap.Tests.fail(result)


__all__: list[str] = ["TestsFlextLdapSync"]
