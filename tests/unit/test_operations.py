"""Unit tests for flext_ldap.services.operations.FlextLdapOperations.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import pytest

from flext_ldap import FlextLdapOperations
from tests import c, m, t, u

pytestmark = pytest.mark.unit


class TestsFlextLdapOperations:
    """Public behavior tests for FlextLdapOperations without test doubles."""

    @staticmethod
    def _entry(dn: str) -> m.Ldif.Entry:
        return m.Ldif.Entry(
            dn=m.Ldif.DN(value=dn),
            attributes=m.Ldif.Attributes(
                attributes={},
                attribute_metadata={},
            ),
        )

    def test_is_connected_not_connected(self) -> None:
        operations = FlextLdapOperations()
        u.Ldap.Tests.that(not operations.is_connected, eq=True)

    @pytest.mark.parametrize(
        ("error_message", "expected"),
        list(c.Ldap.Tests.OPERATIONS_ERROR_DETECTION_SCENARIOS.items()),
    )
    def test_already_exists_error_detection(
        self,
        error_message: str,
        expected: bool,
    ) -> None:
        result = FlextLdapOperations.already_exists_error(error_message)
        u.Ldap.Tests.that(result, eq=expected)

    def test_execute_method_returns_failure_when_not_connected(self) -> None:
        operations = FlextLdapOperations()
        result = operations.execute()
        u.Ldap.Tests.fail(result)

    def test_search_without_connection_returns_failure(self) -> None:
        operations = FlextLdapOperations()
        search_options = m.Ldap.SearchOptions(
            base_dn=c.Ldap.Tests.RFC_DEFAULT_BASE_DN,
            filter_str=c.Ldap.Tests.RFC_DEFAULT_FILTER,
            scope=c.Ldap.SearchScope.SUBTREE.value,
        )
        result = operations.search(search_options)
        u.Ldap.Tests.fail(result)

    def test_search_invalid_base_dn_returns_failure(self) -> None:
        operations = FlextLdapOperations()
        search_options = m.Ldap.SearchOptions(
            base_dn=c.Ldap.Tests.MODELS_INVALID_DN_FORMAT,
            filter_str=c.Ldap.ALL_ENTRIES_FILTER,
            scope=c.Ldap.SearchScope.SUBTREE.value,
        )

        error = u.Ldap.Tests.fail(operations.search(search_options))
        u.Ldap.Tests.that(error, contains="Invalid base DN")

    def test_add_without_connection_returns_failure(self) -> None:
        operations = FlextLdapOperations()
        result = operations.add(self._entry(c.Ldap.Tests.ENTRY_DN_TEST_EXAMPLE))
        u.Ldap.Tests.fail(result)

    def test_delete_without_connection_returns_failure(self) -> None:
        operations = FlextLdapOperations()
        result = operations.delete(c.Ldap.Tests.ENTRY_DN_TEST_EXAMPLE)
        u.Ldap.Tests.fail(result)

    def test_modify_without_connection_returns_failure(self) -> None:
        operations = FlextLdapOperations()
        changes: t.Ldap.OperationChanges = {
            "cn": [
                (
                    int(c.Ldap.ModifyOperation.REPLACE),
                    [c.Ldap.Tests.STRING_SIMPLE],
                )
            ]
        }

        result = operations.modify(c.Ldap.Tests.ENTRY_DN_TEST_EXAMPLE, changes)
        u.Ldap.Tests.fail(result)

    def test_batch_upsert_stop_on_error_returns_failure(self) -> None:
        operations = FlextLdapOperations()
        entries = [
            self._entry(c.Ldap.Tests.SYNC_FACADE_TEST_USER_DN),
            self._entry(c.Ldap.Tests.ENTRY_DN_TEST_EXAMPLE),
        ]

        error = u.Ldap.Tests.fail(operations.batch_upsert(entries, stop_on_error=True))
        u.Ldap.Tests.that(error, contains=c.Ldap.Tests.OPERATIONS_BATCH_STOP_FRAGMENT)

    def test_batch_upsert_all_failed_returns_failure(self) -> None:
        operations = FlextLdapOperations()
        entries = [self._entry(c.Ldap.Tests.SYNC_FACADE_TEST_USER_DN)]

        error = u.Ldap.Tests.fail(operations.batch_upsert(entries, stop_on_error=False))
        u.Ldap.Tests.that(
            error,
            contains=c.Ldap.Tests.OPERATIONS_BATCH_ALL_FAILED_FRAGMENT,
        )

    def test_batch_upsert_progress_callback_on_failure(self) -> None:
        operations = FlextLdapOperations()
        entries = [self._entry(c.Ldap.Tests.SYNC_FACADE_TEST_USER_DN)]
        observed: list[tuple[int, int, str, tuple[int, int, int]]] = []

        def progress(
            current: int,
            total: int,
            dn: str,
            stats: m.Ldap.LdapBatchStats,
        ) -> None:
            observed.append((
                current,
                total,
                dn,
                (stats.synced, stats.failed, stats.skipped),
            ))

        u.Ldap.Tests.fail(operations.batch_upsert(entries, progress_callback=progress))
        u.Ldap.Tests.that(len(observed), eq=1)
        u.Ldap.Tests.that(observed[0][0], eq=1)
        u.Ldap.Tests.that(observed[0][1], eq=1)
        u.Ldap.Tests.that(observed[0][3], eq=(0, 1, 0))
