"""Unit tests for flext_ldap.services.operations.FlextLdapOperations.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import pytest

from flext_ldap.services import FlextLdapOperations
from tests import c, m, p, t, u

pytestmark = pytest.mark.unit


class TestsFlextLdapOperations:
    """Public behavior tests for FlextLdapOperations."""

    @staticmethod
    def _entry(dn: str) -> p.Ldif.Entry:
        return m.Ldif.Entry(
            dn=m.Ldif.DN(value=dn),
            attributes=m.Ldif.Attributes(attributes={}, attribute_metadata={}),
            domain_events=[],
        )

    @staticmethod
    def test_is_connected_not_connected() -> None:
        """Verify is connected not connected."""
        operations = FlextLdapOperations()
        u.Ldap.Tests.that(not operations.is_connected, eq=True)

    @pytest.mark.parametrize(
        ("error_message", "expected"),
        list(c.Ldap.Tests.OPERATIONS_ERROR_DETECTION_SCENARIOS.items()),
    )
    @staticmethod
    def test_already_exists_error_detection(
        error_message: str,
        *,
        expected: bool,
    ) -> None:
        """Verify already exists error detection."""
        result = FlextLdapOperations.already_exists_error(error_message)
        u.Ldap.Tests.that(result, eq=expected)

    @staticmethod
    def test_execute_method_returns_failure_when_not_connected() -> None:
        """Verify execute method returns failure when not connected."""
        operations = FlextLdapOperations()
        result = operations.execute()
        u.Ldap.Tests.fail(result)

    @staticmethod
    def test_search_without_connection_returns_failure() -> None:
        """Verify search without connection returns failure."""
        operations = FlextLdapOperations()
        search_options = m.Ldap.SearchOptions(
            base_dn=c.Ldap.Tests.RFC_DEFAULT_BASE_DN,
            filter_str=c.Ldap.Tests.RFC_DEFAULT_FILTER,
            scope=c.Ldap.SearchScope.SUBTREE.value,
        )
        result = operations.search(search_options)
        u.Ldap.Tests.fail(result)

    @staticmethod
    def test_search_invalid_base_dn_returns_failure() -> None:
        """Verify search invalid base dn returns failure."""
        operations = FlextLdapOperations()
        search_options = m.Ldap.SearchOptions(
            base_dn=c.Ldap.Tests.MODELS_INVALID_DN_FORMAT,
            filter_str=c.Ldap.ALL_ENTRIES_FILTER,
            scope=c.Ldap.SearchScope.SUBTREE.value,
        )

        error = u.Ldap.Tests.fail(operations.search(search_options))
        u.Ldap.Tests.that(error, contains="Invalid base DN")

    def test_add_without_connection_returns_failure(self) -> None:
        """Verify add without connection returns failure."""
        operations = FlextLdapOperations()
        result = operations.add(self._entry(c.Ldap.Tests.ENTRY_DN_TEST_EXAMPLE))
        u.Ldap.Tests.fail(result)

    @staticmethod
    def test_delete_without_connection_returns_failure() -> None:
        """Verify delete without connection returns failure."""
        operations = FlextLdapOperations()
        result = operations.delete(c.Ldap.Tests.ENTRY_DN_TEST_EXAMPLE)
        u.Ldap.Tests.fail(result)

    @staticmethod
    def test_modify_without_connection_returns_failure() -> None:
        """Verify modify without connection returns failure."""
        operations = FlextLdapOperations()
        changes: t.Ldap.OperationChanges = {
            "cn": [(int(c.Ldap.ModifyOperation.REPLACE), [c.Ldap.Tests.STRING_SIMPLE])],
        }

        result = operations.modify(c.Ldap.Tests.ENTRY_DN_TEST_EXAMPLE, changes)
        u.Ldap.Tests.fail(result)

    def test_batch_upsert_stop_on_error_returns_failure(self) -> None:
        """Verify batch upsert stop on error returns failure."""
        operations = FlextLdapOperations()
        entries = [
            self._entry(c.Ldap.Tests.SYNC_FACADE_TEST_USER_DN),
            self._entry(c.Ldap.Tests.ENTRY_DN_TEST_EXAMPLE),
        ]

        expected = u.Ldap.Tests.fail(operations.upsert(entries[0]))
        error = u.Ldap.Tests.fail(operations.batch_upsert(entries, stop_on_error=True))
        u.Ldap.Tests.that(error, eq=expected)

    def test_batch_upsert_all_failed_returns_failure(self) -> None:
        """Verify batch upsert all failed returns failure."""
        operations = FlextLdapOperations()
        entries = [self._entry(c.Ldap.Tests.SYNC_FACADE_TEST_USER_DN)]

        error = u.Ldap.Tests.fail(operations.batch_upsert(entries, stop_on_error=False))
        u.Ldap.Tests.that(
            error,
            contains=c.Ldap.Tests.OPERATIONS_BATCH_ALL_FAILED_FRAGMENT,
        )

    @staticmethod
    def test_upsert_schema_modify_missing_dn_returns_failure() -> None:
        """A native modify record still requires the target DN."""
        operations = FlextLdapOperations()
        entry = m.Ldif.Entry(
            dn=None,
            changetype=c.Ldif.ChangeType.MODIFY,
            attributes=m.Ldif.Attributes(
                attributes={"cn": [c.Ldap.Tests.STRING_SIMPLE]}
            ),
            change_operations=[
                m.Ldif.ChangeOperation(
                    operation=c.Ldif.ChangeOperation.ADD,
                    attribute="cn",
                    values=[
                        m.Ldif.ChangeOperationValue(value=c.Ldap.Tests.STRING_SIMPLE)
                    ],
                )
            ],
        )
        error = u.Ldap.Tests.fail(operations.upsert(entry))
        u.Ldap.Tests.that(error, contains="Upsert entry missing DN")

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

    @staticmethod
    def test_invalid_dn_rejected_by_model() -> None:
        """An RFC 4514 invalid DN is rejected at model-construction time."""
        invalid_dn = c.Ldap.Tests.ENTRY_DN_SCENARIOS[
            c.Ldap.Tests.EntryOperationCase.INVALID_DN
        ]
        with u.Tests.raises(c.ValidationError):
            m.Ldif.DN(value=invalid_dn)

    @staticmethod
    @pytest.mark.parametrize("case", c.Ldap.Tests.EntryOperationCase)
    def test_delete_with_dn_variations_returns_failure_not_connected(
        case: c.Ldap.Tests.EntryOperationCase,
    ) -> None:
        """Test delete operation with various DN formats (not connected scenario)."""
        operations = FlextLdapOperations()
        dn = c.Ldap.Tests.ENTRY_DN_SCENARIOS[case]
        result = operations.delete(dn)
        u.Ldap.Tests.fail(result)

    @staticmethod
    @pytest.mark.parametrize("case", c.Ldap.Tests.SearchFilterCase)
    def test_search_with_filter_variations_returns_failure_not_connected(
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

    @staticmethod
    @pytest.mark.parametrize("case", c.Ldap.Tests.SearchScopeCase)
    def test_search_with_scope_variations_returns_failure_not_connected(
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

    @staticmethod
    @pytest.mark.parametrize("case", c.Ldap.Tests.SearchSizeCase)
    def test_search_with_size_limit_variations_returns_failure_not_connected(
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

    @staticmethod
    def test_batch_upsert_empty_batch_returns_success() -> None:
        """Test batch_upsert with empty entry list (not connected scenario)."""
        operations = FlextLdapOperations()
        entries: list[p.Ldif.Entry] = []
        result = operations.batch_upsert(entries, stop_on_error=False)
        u.Ldap.Tests.ok(result)
