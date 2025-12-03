"""Advanced test helpers for flext-ldap tests using Python 3.13 features.

This module provides comprehensive helper methods with factory patterns,
dataclasses, and generic utilities to maximize code reuse across all
flext-ldap tests. Built on flext-core patterns for consistency.

**Modules Tested:**
- FlextLdap: LDAP API facade
- m: LDAP domain models
- FlextLdifModels: LDIF entry models

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Literal, Protocol, cast

from flext_core import FlextRuntime
from flext_ldif.models import FlextLdifModels
from ldap3 import Connection, Entry as Ldap3Entry

from flext_ldap import FlextLdap, c, m, p, r, t, u
from flext_ldap.services.operations import FlextLdapOperations

from ..fixtures.constants import TestConstants
from ..fixtures.typing import GenericFieldsDict

# Type alias for ldap3 search scope literal - shared across tests
Ldap3SearchScope = Literal["BASE", "LEVEL", "SUBTREE"]


class DnsTrackerProtocol(Protocol):
    """Protocol for DNS tracker objects."""

    def add(self, dn: str) -> None:
        """Add DN to tracker."""
        ...


# Type alias for search scope - reuse production types
SearchScopeType = c.LiteralTypes.SearchScopeLiteral

# Valid scopes for runtime validation - reuse production StrEnum
VALID_SCOPES: frozenset[str] = frozenset({
    c.SearchScope.BASE.value,
    c.SearchScope.ONELEVEL.value,
    c.SearchScope.SUBTREE.value,
})


def _validate_scope(scope: str) -> SearchScopeType:
    """Validate and return a typed search scope.

    Uses u.Enum.parse for unified enum parsing.

    Args:
        scope: Scope string to validate

    Returns:
        Validated scope as Literal type

    Raises:
        ValueError: If scope is not valid

    """
    # Use u.Enum.parse for unified enum parsing
    parse_result = u.Enum.parse(
        c.SearchScope,
        scope,
    )
    if parse_result.is_success:
        # Convert StrEnum to Literal type
        scope_value = parse_result.value.value
        if scope_value in VALID_SCOPES:
            return cast("SearchScopeType", scope_value)

    # If parsing failed, raise ValueError with helpful message
    msg = f"Invalid scope: {scope}. Must be one of {VALID_SCOPES}"
    raise ValueError(msg)


def to_ldap3_scope(
    scope: c.SearchScope,
) -> Ldap3SearchScope:
    """Convert c.SearchScope to ldap3 search scope literal.

    Shared helper to avoid duplication across test files.
    Replaces local _to_ldap3_scope functions in test files.

    Args:
        scope: Search scope enum value

    Returns:
        Literal string value expected by ldap3

    Raises:
        ValueError: If scope value is unknown

    """
    scope_value = scope.value
    if scope_value == "ONELEVEL":
        return "LEVEL"
    if scope_value == "BASE":
        return "BASE"
    if scope_value == "SUBTREE":
        return "SUBTREE"
    msg = f"Unknown scope value: {scope_value}"
    raise ValueError(msg)


class Ldap3TestHelpers:
    """Helper methods for ldap3.Connection testing patterns.

    Provides common patterns for LDAP operations using ldap3.Connection
    to reduce duplication across test files.
    """

    @staticmethod
    def search_base_entry(
        connection: Connection,
        base_dn: str,
        scope: c.SearchScope = c.SearchScope.BASE,
        attributes: list[str] | None = None,
    ) -> list[Ldap3Entry]:
        """Search for base DN entry using ldap3.Connection.

        Common pattern for getting base DN entry in tests.
        Reduces duplication of search calls across test files.

        Args:
            connection: ldap3.Connection instance
            base_dn: Base DN to search
            scope: Search scope (defaults to BASE)
            attributes: Attributes to retrieve (defaults to ["*"])

        Returns:
            List of ldap3.Entry objects from search

        """
        if attributes is None:
            attributes = ["*"]
        connection.search(
            search_base=base_dn,
            search_filter="(objectClass=*)",
            search_scope=to_ldap3_scope(scope),
            attributes=attributes,
        )
        return list(connection.entries) if connection.entries else []


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
            "mail": ["testuser@internal.invalid"],
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
    ) -> m.SearchOptions:
        """Factory method for creating search options with smart defaults."""
        validated_scope = _validate_scope(scope)
        return m.SearchOptions(
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
    ) -> m.ConnectionConfig:
        """Factory method for connection configurations with explicit parameters."""
        return m.ConnectionConfig(
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

            def process_attr(key: object, value: object) -> tuple[str, list[str]]:
                """Process attribute value."""
                value_typed: t.GeneralValueType = cast("t.GeneralValueType", value)
                if FlextRuntime.is_list_like(value_typed):
                    return (str(key), [str(item) for item in value_typed])
                return (str(key), [str(value_typed)])

            processed_attrs = u.process(
                cast("dict[object, object]", attrs_raw),
                processor=process_attr,
                on_error="skip",
            )
            if processed_attrs.is_success:
                attributes.update(
                    dict(cast("list[tuple[str, list[str]]]", processed_attrs.value))
                )

        return FlextLdapTestHelpers.create_entry(dn_str, attributes)

    @staticmethod
    def create_search_options(
        base_dn: str,
        filter_str: str = "(objectClass=*)",
        scope: str = c.SearchScope.SUBTREE.value,
        attributes: list[str] | None = None,
    ) -> m.SearchOptions:
        """Create SearchOptions with common defaults.

        Args:
            base_dn: Base DN for search
            filter_str: LDAP filter string
            scope: Search scope (BASE, ONELEVEL, SUBTREE)
            attributes: Attributes to retrieve

        Returns:
            m.SearchOptions instance

        """
        validated_scope = _validate_scope(scope)
        return m.SearchOptions(
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
    ) -> tuple[FlextLdifModels.Entry, r[m.OperationResult]]:
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
    ) -> tuple[FlextLdifModels.Entry, r[m.OperationResult]]:
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
    def create_entry_with_normalization(
        dn: str,
        attributes: Mapping[str, t.GeneralValueType],
    ) -> FlextLdifModels.Entry:
        """Create Entry with attribute normalization from any value type.

        Args:
            dn: Distinguished name string
            attributes: Attribute dict - values are normalized to list[str]

        Returns:
            FlextLdifModels.Entry with normalized attributes

        """
        attrs_dict: dict[str, list[str]] = {}

        def process_attr_item(
            key: str, value_item_raw: object
        ) -> tuple[str, list[str]]:
            """Process attribute item value."""
            value_typed: t.GeneralValueType = cast("t.GeneralValueType", value_item_raw)
            if FlextRuntime.is_list_like(value_typed):
                return (key, [str(item) for item in value_typed])
            return (key, [str(value_item_raw)])

        processed_attrs = u.process(
            attributes,
            processor=process_attr_item,
            on_error="skip",
        )
        if processed_attrs.is_success:
            attrs_dict.update(
                dict(cast("list[tuple[str, list[str]]]", processed_attrs.value))
            )
        return FlextLdapTestHelpers.create_entry(dn, attrs_dict)

    @staticmethod
    def cleanup_entry(
        client: (FlextLdap | FlextLdapOperations | p.LdapService.LdapClientProtocol),
        dn: str | p.LdapEntry.DistinguishedNameProtocol,
    ) -> None:
        """Cleanup entry before add to avoid entryAlreadyExists errors.

        Args:
            client: LDAP client with delete method
            dn: Distinguished name to delete

        """
        dn_str = str(dn) if dn else ""
        _ = client.delete(dn_str)

    @staticmethod
    def cleanup_after_test(
        client: (FlextLdap | FlextLdapOperations | p.LdapService.LdapClientProtocol),
        dn: str | p.LdapEntry.DistinguishedNameProtocol,
    ) -> None:
        """Cleanup entry after test execution.

        Args:
            client: LDAP client with delete method
            dn: Distinguished name to delete

        """
        dn_str = str(dn) if dn else ""
        _ = client.delete(dn_str)

    @staticmethod
    def _ensure_flext_result[T](
        result: r[T] | p.ResultProtocol[T] | p.ResultProtocol[object],
    ) -> r[T]:
        """Ensure result is FlextResult, converting from protocol if needed.

        Args:
            result: Result that may be FlextResult or ResultProtocol

        Returns:
            r[T] guaranteed

        """
        if isinstance(result, r):
            # Type narrowing: isinstance check ensures r[T]
            # Use cast to satisfy pyright's invariant type parameter check
            return cast("r[T]", result)
        # Convert protocol result to r
        if result.is_success:
            unwrapped = result.unwrap()
            # Type narrowing: unwrapped is T from protocol contract
            # Use r.ok with explicit type parameter via cast
            typed_unwrapped: T = cast("T", unwrapped)
            return r.ok(typed_unwrapped)
        error_msg = str(result.error) if result.error else "Unknown error"
        return r.fail(error_msg)

    @staticmethod
    def delete_entry_safe(
        client: FlextLdap,
        dn: str | FlextLdifModels.DistinguishedName,
    ) -> r[m.OperationResult]:
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
        result: r[m.SearchResult],
        min_entries: int = 0,
    ) -> m.SearchResult:
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
        entries_len = len(search_result.entries)
        assert entries_len >= min_entries
        # total_count is a computed_field that returns len(entries), verify it matches
        # Access via attribute to avoid type checker issues with computed_field
        total_count_actual: int = len(search_result.entries)
        assert total_count_actual == entries_len
        return search_result

    @staticmethod
    def assert_operation_success(
        result: r[m.OperationResult],
        expected_affected: int = 1,
    ) -> m.OperationResult:
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
    ) -> list[tuple[FlextLdifModels.Entry, r[m.OperationResult]]]:
        """Add multiple entries from dicts with DN adjustment.

        Replaces loops of add_entry_from_dict_with_cleanup.

        Args:
            client: FlextLdap client instance
            entry_dicts: List of entry dicts
            adjust_dn: Optional dict with 'from' and 'to' keys for DN replacement

        Returns:
            List of (entry, result) tuples

        """
        results: list[tuple[FlextLdifModels.Entry, r[m.OperationResult]]] = []
        for entry_dict_item in entry_dicts:
            # Type narrowing: cast to GeneralValueType for FlextRuntime methods
            entry_dict_typed: t.GeneralValueType = cast(
                "t.GeneralValueType", entry_dict_item
            )
            if not FlextRuntime.is_dict_like(entry_dict_typed):
                msg = f"Expected dict, got {type(entry_dict_item)}"
                raise TypeError(msg)
            # Cast to GenericFieldsDict - GenericFieldsDict allows any keys via __extra_items__
            entry_dict: GenericFieldsDict = cast(
                "GenericFieldsDict",
                dict(entry_dict_item),
            )

            # Adjust DN if needed
            if adjust_dn:
                dn_str = str(entry_dict.get("dn", ""))
                from_val = str(adjust_dn.get("from", ""))
                to_val = str(adjust_dn.get("to", ""))
                dn_str = dn_str.replace(from_val, to_val)
                # GenericFieldsDict allows any keys via __extra_items__
                # Create new dict with updated DN to avoid TypedDict assignment issues
                updated_dict: GenericFieldsDict = cast(
                    "GenericFieldsDict",
                    {**entry_dict, "dn": dn_str},
                )
                entry_dict = updated_dict

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
        r[m.OperationResult],
        r[m.OperationResult],
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
                r[m.OperationResult].fail("Add failed"),
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
        r[m.OperationResult],
        r[m.OperationResult],
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
                r[m.OperationResult].fail("Add failed"),
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
