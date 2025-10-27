"""Custom assertions and helpers for LDAP testing.

Provides assertion helpers for validating LDAP operations, entry attributes,
and search results in integration tests.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

from ldap3 import Entry


class LdapTestAssertions:
    """Custom assertions for LDAP integration testing."""

    @staticmethod
    def assert_entry_exists(entry: Entry | None, entry_dn: str) -> None:
        """Assert that an LDAP entry exists and has correct DN.

        Args:
            entry: ldap3.Entry object or None
            entry_dn: Expected DN string

        Raises:
            AssertionError: If entry doesn't exist or DN doesn't match

        """
        assert entry is not None, f"Entry {entry_dn} does not exist"
        assert str(entry.entry_dn) == entry_dn, (
            f"Entry DN mismatch: expected {entry_dn}, got {entry.entry_dn}"
        )

    @staticmethod
    def assert_entry_has_attribute(
        entry: Entry,
        attribute_name: str,
        expected_values: list[str | bytes] | None = None,
    ) -> None:
        """Assert that an entry has an attribute with optional value check.

        Args:
            entry: ldap3.Entry object
            attribute_name: Name of attribute to check
            expected_values: Optional list of expected values

        Raises:
            AssertionError: If attribute missing or values don't match

        """
        assert attribute_name in entry.entry_attributes, (
            f"Attribute {attribute_name} not found in entry {entry.entry_dn}"
        )

        if expected_values is not None:
            actual_values = entry[attribute_name]
            assert actual_values == expected_values, (
                f"Attribute {attribute_name} mismatch in {entry.entry_dn}: "
                f"expected {expected_values}, got {actual_values}"
            )

    @staticmethod
    def assert_entry_has_object_class(entry: Entry, expected_class: str) -> None:
        """Assert that an entry has an object class.

        Args:
            entry: ldap3.Entry object
            expected_class: Expected object class name

        Raises:
            AssertionError: If object class not present

        """
        object_classes = entry.objectClass.values
        assert expected_class in object_classes, (
            f"Object class {expected_class} not found in {entry.entry_dn}. "
            f"Present: {object_classes}"
        )

    @staticmethod
    def assert_entries_count(
        entries: list[Entry], expected_count: int, context: str = ""
    ) -> None:
        """Assert the number of entries in search results.

        Args:
            entries: List of ldap3.Entry objects
            expected_count: Expected number of entries
            context: Optional context string for error message

        Raises:
            AssertionError: If entry count doesn't match

        """
        assert len(entries) == expected_count, (
            f"Entry count mismatch {context}: "
            f"expected {expected_count}, got {len(entries)}"
        )

    @staticmethod
    def assert_entries_contain_dn(entries: list[Entry], expected_dn: str) -> None:
        """Assert that search results contain a specific DN.

        Args:
            entries: List of ldap3.Entry objects
            expected_dn: Expected DN to find

        Raises:
            AssertionError: If DN not found in entries

        """
        entry_dns = [str(entry.entry_dn) for entry in entries]
        assert expected_dn in entry_dns, (
            f"DN {expected_dn} not found in search results. Found: {entry_dns}"
        )

    @staticmethod
    def assert_entry_attribute_contains(
        entry: Entry, attribute_name: str, value: str | bytes
    ) -> None:
        """Assert that an entry's attribute contains a specific value.

        Args:
            entry: ldap3.Entry object
            attribute_name: Name of attribute
            value: Value to find in attribute

        Raises:
            AssertionError: If attribute doesn't contain value

        """
        assert attribute_name in entry.entry_attributes, (
            f"Attribute {attribute_name} not found in entry {entry.entry_dn}"
        )

        attribute_values = entry[attribute_name]
        assert value in attribute_values, (
            f"Value {value} not found in attribute {attribute_name} "
            f"of entry {entry.entry_dn}. Values: {attribute_values}"
        )

    @staticmethod
    def assert_no_duplicates(entries: list[Entry]) -> None:
        """Assert that search results contain no duplicate DNs.

        Args:
            entries: List of ldap3.Entry objects

        Raises:
            AssertionError: If duplicates found

        """
        entry_dns = [str(entry.entry_dn) for entry in entries]
        unique_dns = set(entry_dns)

        assert len(entry_dns) == len(unique_dns), (
            f"Duplicate entries found in search results. "
            f"Total: {len(entry_dns)}, Unique: {len(unique_dns)}"
        )


__all__ = ["LdapTestAssertions"]
