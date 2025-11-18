"""Test helpers for flext-ldap tests - massive code deduplication.

This module provides helper methods to reduce code duplication across
all flext-ldap tests. Each method replaces common patterns used in tests.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from flext_core import FlextResult
from flext_ldif.models import FlextLdifModels

from flext_ldap import FlextLdap
from flext_ldap.models import FlextLdapModels


class FlextLdapTestHelpers:
    """Helper methods for flext-ldap tests to reduce code duplication."""

    @staticmethod
    def create_entry(
        dn: str,
        attributes: dict[str, list[str]],
    ) -> FlextLdifModels.Entry:
        """Create FlextLdifModels.Entry from DN and attributes dict.

        Replaces repetitive Entry creation code across all tests.

        Args:
            dn: Distinguished name as string
            attributes: Attributes dict with list values

        Returns:
            FlextLdifModels.Entry instance

        """
        return FlextLdifModels.Entry(
            dn=FlextLdifModels.DistinguishedName(value=dn),
            attributes=FlextLdifModels.LdifAttributes(attributes=attributes),
        )

    @staticmethod
    def create_entry_from_dict(entry_dict: dict[str, object]) -> FlextLdifModels.Entry:
        """Create FlextLdifModels.Entry from dict format.

        Replaces conversion code from test fixtures.

        Args:
            entry_dict: Dict with 'dn' and 'attributes' keys

        Returns:
            FlextLdifModels.Entry instance

        """
        dn_str = str(entry_dict.get("dn", ""))
        attrs_dict = entry_dict.get("attributes", {})
        if not isinstance(attrs_dict, dict):
            attrs_dict = {}

        return FlextLdapTestHelpers.create_entry(dn_str, attrs_dict)

    @staticmethod
    def create_search_options(
        base_dn: str,
        filter_str: str = "(objectClass=*)",
        scope: str = "SUBTREE",
        attributes: list[str] | None = None,
    ) -> FlextLdapModels.SearchOptions:
        """Create SearchOptions with common defaults.

        Replaces repetitive SearchOptions creation.

        Args:
            base_dn: Base DN for search
            filter_str: LDAP filter string
            scope: Search scope (BASE, ONELEVEL, SUBTREE)
            attributes: Attributes to retrieve

        Returns:
            FlextLdapModels.SearchOptions instance

        """
        return FlextLdapModels.SearchOptions(
            base_dn=base_dn,
            filter_str=filter_str,
            scope=scope,
            attributes=attributes,
        )

    @staticmethod
    def add_entry_with_cleanup(
        client: FlextLdap,
        entry: FlextLdifModels.Entry,
        dns_tracker: object | None = None,
    ) -> tuple[FlextLdifModels.Entry, FlextResult[FlextLdapModels.OperationResult]]:
        """Add entry with automatic cleanup and tracking (REGRA 3).

        Replaces add + cleanup pattern used in many tests.
        Tracks DN for intelligent session cleanup.

        Args:
            client: FlextLdap client instance
            entry: Entry to add
            dns_tracker: Optional DNS tracker for intelligent cleanup (REGRA 3)

        Returns:
            Tuple of (entry, result)

        """
        # Cleanup any existing entry first (pre-cleanup)
        dn_str = str(entry.dn)
        _ = client.delete(dn_str)

        # Add entry (REAL LDAP operation, NO MOCKS)
        result = client.add(entry)

        # Track DN for intelligent cleanup (REGRA 3)
        if (
            result.is_success
            and dns_tracker is not None
            and hasattr(dns_tracker, "add")
        ):
            dns_tracker.add(dn_str)  # type: ignore[attr-defined]

        return (entry, result)

    @staticmethod
    def add_entry_from_dict_with_cleanup(
        client: FlextLdap,
        entry_dict: dict[str, object],
        dns_tracker: object | None = None,
    ) -> tuple[FlextLdifModels.Entry, FlextResult[FlextLdapModels.OperationResult]]:
        """Add entry from dict with automatic cleanup and tracking (REGRA 3).

        Combines create_entry_from_dict + add_entry_with_cleanup.
        Tracks DN for intelligent session cleanup.

        Args:
            client: FlextLdap client instance
            entry_dict: Entry dict with 'dn' and 'attributes'
            dns_tracker: Optional DNS tracker for intelligent cleanup (REGRA 3)

        Returns:
            Tuple of (entry, result)

        """
        entry = FlextLdapTestHelpers.create_entry_from_dict(entry_dict)
        return FlextLdapTestHelpers.add_entry_with_cleanup(client, entry, dns_tracker)

    @staticmethod
    def delete_entry_safe(
        client: FlextLdap,
        dn: str | FlextLdifModels.DistinguishedName,
    ) -> FlextResult[FlextLdapModels.OperationResult]:
        """Delete entry safely (ignores errors if not exists).

        Replaces try/except delete patterns.

        Args:
            client: FlextLdap client instance
            dn: Distinguished name to delete

        Returns:
            FlextResult of delete operation

        """
        return client.delete(dn)

    @staticmethod
    def assert_search_success(
        result: FlextResult[FlextLdapModels.SearchResult],
        min_entries: int = 0,
    ) -> FlextLdapModels.SearchResult:
        """Assert search result is successful and return unwrapped result.

        Replaces repetitive assert + unwrap patterns.

        Args:
            result: Search result to assert
            min_entries: Minimum number of entries expected

        Returns:
            Unwrapped SearchResult

        """
        assert result.is_success, f"Search failed: {result.error}"
        search_result = result.unwrap()
        assert len(search_result.entries) >= min_entries
        assert search_result.total_count == len(search_result.entries)
        return search_result

    @staticmethod
    def assert_operation_success(
        result: FlextResult[FlextLdapModels.OperationResult],
        expected_affected: int = 1,
    ) -> FlextLdapModels.OperationResult:
        """Assert operation result is successful and return unwrapped result.

        Replaces repetitive assert + unwrap patterns for operations.

        Args:
            result: Operation result to assert
            expected_affected: Expected number of entries affected

        Returns:
            Unwrapped OperationResult

        """
        assert result.is_success, f"Operation failed: {result.error}"
        operation_result = result.unwrap()
        assert operation_result.success is True
        assert operation_result.entries_affected == expected_affected
        return operation_result

    @staticmethod
    def add_multiple_entries_from_dicts(
        client: FlextLdap,
        entry_dicts: list[dict[str, object]],
        adjust_dn: dict[str, str] | None = None,
    ) -> list[
        tuple[FlextLdifModels.Entry, FlextResult[FlextLdapModels.OperationResult]]
    ]:
        """Add multiple entries from dicts with DN adjustment.

        Replaces loops of add_entry_from_dict_with_cleanup.

        Args:
            client: FlextLdap client instance
            entry_dicts: List of entry dicts
            adjust_dn: Optional dict with 'from' and 'to' keys for DN replacement

        Returns:
            List of (entry, result) tuples

        """
        results = []
        for entry_dict in entry_dicts:
            # Adjust DN if needed
            if adjust_dn:
                dn_str = str(entry_dict.get("dn", ""))
                dn_str = dn_str.replace(adjust_dn["from"], adjust_dn["to"])
                entry_dict = {**entry_dict, "dn": dn_str}

            entry, result = FlextLdapTestHelpers.add_entry_from_dict_with_cleanup(
                client,
                entry_dict,
            )
            results.append((entry, result))
        return results

    @staticmethod
    def modify_entry_with_verification(
        client: FlextLdap,
        entry_dict: dict[str, object],
        changes: dict[str, list[tuple[str, list[str]]]],
    ) -> tuple[
        FlextLdifModels.Entry,
        FlextResult[FlextLdapModels.OperationResult],
        FlextResult[FlextLdapModels.OperationResult],
    ]:
        """Add entry, modify it, and verify changes.

        Replaces add + modify + verify patterns.

        Args:
            client: FlextLdap client instance
            entry_dict: Entry dict to add first
            changes: Modification changes

        Returns:
            Tuple of (entry, add_result, modify_result)

        """
        entry, add_result = FlextLdapTestHelpers.add_entry_from_dict_with_cleanup(
            client,
            entry_dict,
        )
        if not add_result.is_success:
            return (
                entry,
                add_result,
                FlextResult[FlextLdapModels.OperationResult].fail("Add failed"),
            )

        dn_str = str(entry.dn)
        modify_result = client.modify(dn_str, changes)
        return (entry, add_result, modify_result)

    @staticmethod
    def delete_entry_with_verification(
        client: FlextLdap,
        entry_dict: dict[str, object],
    ) -> tuple[
        FlextLdifModels.Entry,
        FlextResult[FlextLdapModels.OperationResult],
        FlextResult[FlextLdapModels.OperationResult],
    ]:
        """Add entry, delete it, and verify deletion.

        Replaces add + delete + verify patterns.

        Args:
            client: FlextLdap client instance
            entry_dict: Entry dict to add first

        Returns:
            Tuple of (entry, add_result, delete_result)

        """
        entry, add_result = FlextLdapTestHelpers.add_entry_from_dict_with_cleanup(
            client,
            entry_dict,
        )
        if not add_result.is_success:
            return (
                entry,
                add_result,
                FlextResult[FlextLdapModels.OperationResult].fail("Add failed"),
            )

        dn_str = str(entry.dn)
        delete_result = client.delete(dn_str)
        return (entry, add_result, delete_result)
