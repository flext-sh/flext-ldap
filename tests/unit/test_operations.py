"""Unit tests for flext_ldap.services.operations.FlextLdapOperations.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import override

import pytest

from flext_ldap.services.operations import FlextLdapOperations
from flext_ldif import r
from tests import c, m, p, t, u

pytestmark = pytest.mark.unit


class TestsFlextLdapOperations:
    """Public behavior tests for FlextLdapOperations."""

    class BatchPathOperations(FlextLdapOperations):
        """Deterministic operations service for exercising public batch flow."""

        _queued_results: list[p.Result[m.Ldap.LdapOperationResult]] = u.PrivateAttr(
            default_factory=list,
        )

        def __init__(
            self,
            results: t.SequenceOf[p.Result[m.Ldap.LdapOperationResult]],
        ) -> None:
            super().__init__()
            self._queued_results = list(results)

        @override
        def upsert(
            self,
            entry: p.Ldif.Entry,
            *,
            retry_on_errors: t.StrSequence | None = None,
            max_retries: int = 1,
        ) -> p.Result[m.Ldap.LdapOperationResult]:
            _ = entry, retry_on_errors, max_retries
            if not self._queued_results:
                return r[m.Ldap.LdapOperationResult].fail(
                    "No queued upsert result",
                )
            return self._queued_results.pop(0)

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
                ),
            ],
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

    def test_batch_upsert_partial_failure_returns_failure(self) -> None:
        operations = self.BatchPathOperations((
            r[m.Ldap.LdapOperationResult].ok(
                m.Ldap.LdapOperationResult.with_operation(
                    c.Ldap.UpsertOperation.ADDED,
                ),
            ),
            r[m.Ldap.LdapOperationResult].fail("planned batch failure"),
            r[m.Ldap.LdapOperationResult].ok(
                m.Ldap.LdapOperationResult.with_operation(
                    c.Ldap.UpsertOperation.SKIPPED,
                ),
            ),
        ))
        entries = [
            self._entry(c.Ldap.Tests.SYNC_FACADE_TEST_USER_DN),
            self._entry(c.Ldap.Tests.ENTRY_DN_TEST_EXAMPLE),
            self._entry(c.Ldap.Tests.RFC_DEFAULT_BASE_DN),
        ]

        error = u.Ldap.Tests.fail(operations.batch_upsert(entries))

        u.Ldap.Tests.that(error, contains="1 entries failed")
        u.Ldap.Tests.that(error, contains="1 synced")
        u.Ldap.Tests.that(error, contains="1 skipped")

    def test_batch_upsert_unknown_operation_counts_as_failure(self) -> None:
        """An upsert that reports an unrecognized operation fails the batch.

        Exercised through the public ``batch_upsert`` contract: a successful
        upsert whose operation is neither ADDED/MODIFIED nor SKIPPED must be
        counted as failed, so the batch result is a failure reporting one
        failed and zero synced/skipped entries.
        """
        operations = self.BatchPathOperations((
            r[m.Ldap.LdapOperationResult].ok(
                m.Ldap.LdapOperationResult.with_operation(c.Ldap.Tests.STRING_SIMPLE),
            ),
        ))
        entries = [self._entry(c.Ldap.Tests.ENTRY_DN_TEST_EXAMPLE)]

        error = u.Ldap.Tests.fail(operations.batch_upsert(entries))

        u.Ldap.Tests.that(error, contains="1 entries failed")
        u.Ldap.Tests.that(error, contains="0 synced")
        u.Ldap.Tests.that(error, contains="0 skipped")

    def test_upsert_schema_modify_missing_dn_returns_failure(self) -> None:
        operations = FlextLdapOperations()
        entry = m.Ldif.Entry(
            dn=None,
            attributes=m.Ldif.Attributes(
                attributes={
                    c.Ldap.AttributeName.CHANGETYPE: [
                        c.Ldif.LdifChangeType.MODIFY.value,
                    ],
                    c.Ldif.ChangeOperation.ADD: [c.Ldap.AttributeName.COMMON_NAME],
                    c.Ldap.AttributeName.COMMON_NAME: [
                        c.Ldap.Tests.STRING_SIMPLE,
                    ],
                },
                attribute_metadata={},
            ),
        )

        error = u.Ldap.Tests.fail(operations.upsert(entry))

        u.Ldap.Tests.that(error, contains="Schema modify entry missing DN")

    @pytest.mark.parametrize(
        "case",
        [
            case
            for case in c.Ldap.Tests.EntryOperationCase
            if case is not c.Ldap.Tests.EntryOperationCase.INVALID_DN
        ],
    )
    def test_add_with_dn_variations_returns_failure_not_connected(
        self,
        case: c.Ldap.Tests.EntryOperationCase,
    ) -> None:
        """Test add operation with constructible DN formats (not connected scenario).

        INVALID_DN is excluded: an Entry cannot be constructed with an RFC 4514
        invalid DN (the DN model correctly rejects it at construction time), so
        the invalid-DN case is a model-validation concern, not an add-not-connected
        concern. ``test_invalid_dn_rejected_by_model`` covers that contract.
        """
        operations = FlextLdapOperations()
        dn = c.Ldap.Tests.ENTRY_DN_SCENARIOS[case]
        result = operations.add(self._entry(dn))
        u.Ldap.Tests.fail(result)

    def test_invalid_dn_rejected_by_model(self) -> None:
        """An RFC 4514 invalid DN is rejected at model-construction time."""
        invalid_dn = c.Ldap.Tests.ENTRY_DN_SCENARIOS[
            c.Ldap.Tests.EntryOperationCase.INVALID_DN
        ]
        with pytest.raises(c.ValidationError):
            m.Ldif.DN(value=invalid_dn)

    @pytest.mark.parametrize(
        "case",
        c.Ldap.Tests.EntryOperationCase,
    )
    def test_delete_with_dn_variations_returns_failure_not_connected(
        self,
        case: c.Ldap.Tests.EntryOperationCase,
    ) -> None:
        """Test delete operation with various DN formats (not connected scenario)."""
        operations = FlextLdapOperations()
        dn = c.Ldap.Tests.ENTRY_DN_SCENARIOS[case]
        result = operations.delete(dn)
        u.Ldap.Tests.fail(result)

    @pytest.mark.parametrize(
        "case",
        c.Ldap.Tests.SearchFilterCase,
    )
    def test_search_with_filter_variations_returns_failure_not_connected(
        self,
        case: c.Ldap.Tests.SearchFilterCase,
    ) -> None:
        """Test search operation with various filter types (not connected scenario)."""
        operations = FlextLdapOperations()
        search_filter = c.Ldap.Tests.SEARCH_FILTER_SCENARIOS_ADVANCED[case]
        search_options = m.Ldap.SearchOptions(
            base_dn=c.Ldap.Tests.RFC_DEFAULT_BASE_DN,
            filter_str=search_filter,
            scope=c.Ldap.SearchScope.SUBTREE.value,
        )
        result = operations.search(search_options)
        u.Ldap.Tests.fail(result)

    @pytest.mark.parametrize(
        "case",
        c.Ldap.Tests.SearchScopeCase,
    )
    def test_search_with_scope_variations_returns_failure_not_connected(
        self,
        case: c.Ldap.Tests.SearchScopeCase,
    ) -> None:
        """Test search operation with various scope types (not connected scenario)."""
        operations = FlextLdapOperations()
        scope_str = c.Ldap.Tests.SEARCH_SCOPE_SCENARIOS[case]
        search_options = m.Ldap.SearchOptions(
            base_dn=c.Ldap.Tests.RFC_DEFAULT_BASE_DN,
            filter_str=c.Ldap.Tests.RFC_DEFAULT_FILTER,
            scope=scope_str,
        )
        result = operations.search(search_options)
        u.Ldap.Tests.fail(result)

    @pytest.mark.parametrize(
        "case",
        c.Ldap.Tests.SearchSizeCase,
    )
    def test_search_with_size_limit_variations_returns_failure_not_connected(
        self,
        case: c.Ldap.Tests.SearchSizeCase,
    ) -> None:
        """Test search operation with various size limits (not connected scenario)."""
        operations = FlextLdapOperations()
        size_limit = c.Ldap.Tests.SEARCH_SIZE_SCENARIOS[case]
        search_options = m.Ldap.SearchOptions(
            base_dn=c.Ldap.Tests.RFC_DEFAULT_BASE_DN,
            filter_str=c.Ldap.Tests.RFC_DEFAULT_FILTER,
            scope=c.Ldap.SearchScope.SUBTREE.value,
            size_limit=size_limit,
        )
        result = operations.search(search_options)
        u.Ldap.Tests.fail(result)

    def test_batch_upsert_empty_batch_returns_success(self) -> None:
        """Test batch_upsert with empty entry list (not connected scenario)."""
        operations = FlextLdapOperations()
        entries: list[m.Ldif.Entry] = []
        result = operations.batch_upsert(entries, stop_on_error=False)
        u.Ldap.Tests.ok(result)
