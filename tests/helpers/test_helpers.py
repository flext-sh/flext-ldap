"""Advanced test helpers for flext-ldap tests using Python 3.13 features.

This module provides comprehensive helper methods with factory patterns,
dataclasses, and generic utilities to maximize code reuse across all
flext-ldap tests. Built on flext-core patterns for consistency.

**Modules Tested:**
- FlextLdap: LDAP API facade
- FlextLdapModels: LDAP domain models
- FlextLdifModels: LDIF entry models

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

from flext_core import FlextResult, FlextRuntime
from flext_ldif.models import FlextLdifModels

from flext_ldap import FlextLdap
from flext_ldap.constants import FlextLdapConstants
from flext_ldap.models import FlextLdapModels
from tests.fixtures.typing import GenericFieldsDict

from ..fixtures.constants import TestConstants


class DnsTrackerProtocol(Protocol):
    """Protocol for DNS tracker objects."""

    def add(self, dn: str) -> None:
        """Add DN to tracker."""
        ...


# Type alias for search scope - reuse production types
SearchScopeType = FlextLdapConstants.LiteralTypes.SearchScopeLiteral

# Valid scopes for runtime validation - reuse production StrEnum
VALID_SCOPES: frozenset[str] = frozenset({
    FlextLdapConstants.SearchScope.BASE.value,
    FlextLdapConstants.SearchScope.ONELEVEL.value,
    FlextLdapConstants.SearchScope.SUBTREE.value,
})


def _validate_scope(scope: str) -> SearchScopeType:
    """Validate and return a typed search scope.

    Args:
        scope: Scope string to validate

    Returns:
        Validated scope as Literal type

    Raises:
        ValueError: If scope is not valid

    """
    if scope not in VALID_SCOPES:
        msg = f"Invalid scope: {scope}. Must be one of {VALID_SCOPES}"
        raise ValueError(msg)
    # Use FlextLdapConstants for type-safe mapping
    scope_map: dict[str, SearchScopeType] = {
        "BASE": "BASE",
        "ONELEVEL": "ONELEVEL",
        "SUBTREE": "SUBTREE",
    }
    return scope_map[scope]


@dataclass(frozen=True, slots=True)
class LdapTestDataFactory:
    """Advanced factory for LDAP test data using Python 3.13 dataclasses."""

    base_dn: str = TestConstants.DEFAULT_BASE_DN
    default_user_dn: str = TestConstants.TEST_USER_DN
    default_group_dn: str = TestConstants.TEST_GROUP_DN

    def create_entry(
        self,
        dn: str | None = None,
        **attributes: list[str],
    ) -> FlextLdifModels.Entry:
        """Factory method for creating test entries with defaults."""
        entry_dn = dn or self.default_user_dn
        default_attrs: dict[str, list[str]] = {
            "cn": ["testuser"],
            "sn": ["User"],
            "givenName": ["Test"],
            "uid": ["testuser"],
            "mail": ["testuser@flext.local"],
            "objectClass": ["inetOrgPerson", "organizationalPerson", "person", "top"],
            "userPassword": ["test123"],
        }
        default_attrs.update(attributes)
        return FlextLdifModels.Entry(
            dn=FlextLdifModels.DistinguishedName(value=entry_dn),
            attributes=FlextLdifModels.LdifAttributes(attributes=default_attrs),
        )

    def create_search_options(
        self,
        base_dn: str | None = None,
        filter_str: str = TestConstants.DEFAULT_FILTER,
        scope: str = TestConstants.DEFAULT_SCOPE,
        attributes: list[str] | None = None,
    ) -> FlextLdapModels.SearchOptions:
        """Factory method for creating search options with smart defaults."""
        validated_scope = _validate_scope(scope)
        return FlextLdapModels.SearchOptions(
            base_dn=base_dn or self.base_dn,
            filter_str=filter_str,
            scope=validated_scope,
            attributes=attributes,
        )

    def create_connection_config(
        self,
        host: str = TestConstants.DEFAULT_HOST,
        port: int = TestConstants.DEFAULT_PORT,
        bind_dn: str = TestConstants.DEFAULT_BIND_DN,
        bind_password: str = TestConstants.DEFAULT_BIND_PASSWORD,
    ) -> FlextLdapModels.ConnectionConfig:
        """Factory method for connection configurations with explicit parameters."""
        return FlextLdapModels.ConnectionConfig(
            host=host,
            port=port,
            bind_dn=bind_dn,
            bind_password=bind_password,
        )


class FlextLdapTestHelpers:
    """Advanced helper methods for flext-ldap tests with maximum code reuse."""

    # Factory instance for consistent test data generation
    factory = LdapTestDataFactory()

    @staticmethod
    def create_entry(
        dn: str,
        attributes: dict[str, list[str]],
    ) -> FlextLdifModels.Entry:
        """Create FlextLdifModels.Entry from DN and attributes dict.

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
    def create_entry_from_dict(entry_dict: GenericFieldsDict) -> FlextLdifModels.Entry:
        """Create FlextLdifModels.Entry from dict format.

        Enhanced version with better type safety and validation.

        Args:
            entry_dict: Dict with 'dn' and 'attributes' keys

        Returns:
            FlextLdifModels.Entry instance

        """
        dn_str = str(entry_dict.get("dn", ""))
        attrs_raw = entry_dict.get("attributes", {})

        # Type-safe conversion using FlextRuntime
        attributes: dict[str, list[str]] = {}
        if FlextRuntime.is_dict_like(attrs_raw):
            for key, value in attrs_raw.items():
                if FlextRuntime.is_list_like(value):
                    attributes[str(key)] = [str(item) for item in value]
                else:
                    attributes[str(key)] = [str(value)]

        return FlextLdapTestHelpers.create_entry(dn_str, attributes)

    @staticmethod
    def create_search_options(
        base_dn: str,
        filter_str: str = "(objectClass=*)",
        scope: str = FlextLdapConstants.SearchScope.SUBTREE.value,
        attributes: list[str] | None = None,
    ) -> FlextLdapModels.SearchOptions:
        """Create SearchOptions with common defaults.

        Args:
            base_dn: Base DN for search
            filter_str: LDAP filter string
            scope: Search scope (BASE, ONELEVEL, SUBTREE)
            attributes: Attributes to retrieve

        Returns:
            FlextLdapModels.SearchOptions instance

        """
        validated_scope = _validate_scope(scope)
        return FlextLdapModels.SearchOptions(
            base_dn=base_dn,
            filter_str=filter_str,
            scope=validated_scope,
            attributes=attributes,
        )

    @staticmethod
    def add_entry_with_cleanup(
        client: FlextLdap,
        entry: FlextLdifModels.Entry,
        dns_tracker: DnsTrackerProtocol | None = None,
    ) -> tuple[FlextLdifModels.Entry, FlextResult[FlextLdapModels.OperationResult]]:
        """Add entry with automatic cleanup and tracking.

        Replaces add + cleanup pattern used in many tests.
        Tracks DN for intelligent session cleanup.

        Args:
            client: FlextLdap client instance
            entry: Entry to add
            dns_tracker: Optional DNS tracker for intelligent cleanup

        Returns:
            Tuple of (entry, result)

        """
        # Cleanup any existing entry first (pre-cleanup)
        dn_str = str(entry.dn)
        _ = client.delete(dn_str)

        # Add entry (REAL LDAP operation, NO MOCKS)
        result = client.add(entry)

        # Track DN for intelligent cleanup
        if result.is_success and dns_tracker is not None:
            dns_tracker.add(dn_str)

        return (entry, result)

    @staticmethod
    def add_entry_from_dict_with_cleanup(
        client: FlextLdap,
        entry_dict: GenericFieldsDict,
        dns_tracker: DnsTrackerProtocol | None = None,
    ) -> tuple[FlextLdifModels.Entry, FlextResult[FlextLdapModels.OperationResult]]:
        """Add entry from dict with automatic cleanup and tracking.

        Combines create_entry_from_dict + add_entry_with_cleanup.
        Tracks DN for intelligent session cleanup.

        Args:
            client: FlextLdap client instance
            entry_dict: Entry dict with 'dn' and 'attributes'
            dns_tracker: Optional DNS tracker for intelligent cleanup

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
        assert search_result.total_count() == len(search_result.entries)
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
        entry_dicts: list[GenericFieldsDict],
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
        results: list[
            tuple[FlextLdifModels.Entry, FlextResult[FlextLdapModels.OperationResult]]
        ] = []
        for entry_dict_item in entry_dicts:
            # Type narrowing: verify entry_dict_item is a dict before use
            if not FlextRuntime.is_dict_like(entry_dict_item):
                msg = f"Expected dict, got {type(entry_dict_item)}"
                raise TypeError(msg)
            entry_dict: GenericFieldsDict = dict(entry_dict_item)

            # Adjust DN if needed
            if adjust_dn:
                dn_str = str(entry_dict.get("dn", ""))
                from_val = str(adjust_dn.get("from", ""))
                to_val = str(adjust_dn.get("to", ""))
                dn_str = dn_str.replace(from_val, to_val)
                entry_dict["dn"] = dn_str

            entry, result = FlextLdapTestHelpers.add_entry_from_dict_with_cleanup(
                client,
                entry_dict,
            )
            results.append((entry, result))
        return results

    @staticmethod
    def modify_entry_with_verification(
        client: FlextLdap,
        entry_dict: GenericFieldsDict,
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
        entry_dict: GenericFieldsDict,
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


__all__ = [
    "VALID_SCOPES",
    "FlextLdapTestHelpers",
    "LdapTestDataFactory",
    "SearchScopeType",
]
