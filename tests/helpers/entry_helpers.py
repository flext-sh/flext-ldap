"""Helper methods for creating and manipulating Entry objects in tests.

This class provides methods to reduce duplication when creating Entry objects
from dictionaries, fixtures, and other common test patterns.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from flext_core import FlextResult
from flext_ldif.models import FlextLdifModels

from flext_ldap.models import FlextLdapModels
from flext_ldap.typings import LdapClientProtocol


class EntryTestHelpers:
    """Helper methods for Entry creation and manipulation in tests."""

    @staticmethod
    def dict_to_entry(
        entry_dict: Mapping[str, object] | dict[str, object],
    ) -> FlextLdifModels.Entry:
        """Convert dictionary to FlextLdifModels.Entry.

        This is a common pattern repeated across many tests. Centralizes
        the conversion logic to reduce duplication.

        Args:
            entry_dict: Dictionary with 'dn' and 'attributes' keys

        Returns:
            FlextLdifModels.Entry created from dictionary

        Example:
            entry_dict = {
                "dn": "cn=test,dc=example,dc=com",
                "attributes": {"cn": ["test"], "objectClass": ["person"]}
            }
            entry = EntryTestHelpers.dict_to_entry(entry_dict)

        """
        dn_str = str(entry_dict.get("dn", ""))
        dn = FlextLdifModels.DistinguishedName(value=dn_str)
        attrs_dict = entry_dict.get("attributes", {})
        if isinstance(attrs_dict, dict):
            attrs = FlextLdifModels.LdifAttributes.model_validate({
                "attributes": attrs_dict,
            })
        else:
            attrs = FlextLdifModels.LdifAttributes()
        return FlextLdifModels.Entry(dn=dn, attributes=attrs)

    @staticmethod
    def cleanup_entry(
        client: LdapClientProtocol,
        dn: str | FlextLdifModels.DistinguishedName,
    ) -> None:
        """Cleanup entry before add to avoid entryAlreadyExists errors.

        This is a common pattern repeated across many tests. Performs
        a delete operation before add to ensure entry doesn't exist.

        Args:
            client: LDAP client with delete method (FlextLdap, Ldap3Adapter, etc.)
            dn: Distinguished name as string or DistinguishedName object

        Example:
            entry = EntryTestHelpers.dict_to_entry(test_user_entry)
            EntryTestHelpers.cleanup_entry(ldap_client, entry.dn)
            result = ldap_client.add(entry)

        """
        dn_str = str(dn) if dn else ""
        _ = client.delete(dn_str)  # Ignore result, just cleanup

    @staticmethod
    def verify_entry_added(
        client: LdapClientProtocol,
        dn: str | FlextLdifModels.DistinguishedName,
    ) -> bool:
        """Verify that an entry was successfully added to LDAP.

        This is a common pattern repeated across many tests. Performs
        a BASE search to verify the entry exists after add operation.

        Args:
            client: LDAP client with search method (FlextLdap, Ldap3Adapter, etc.)
            dn: Distinguished name as string or DistinguishedName object

        Returns:
            True if entry exists, False otherwise

        Example:
            result = ldap_client.add(entry)
            assert result.is_success
            assert EntryTestHelpers.verify_entry_added(ldap_client, entry.dn)

        """
        dn_str = str(dn) if dn else ""
        # All clients now use SearchOptions - unified API
        search_options = FlextLdapModels.SearchOptions(
            base_dn=dn_str,
            filter_str="(objectClass=*)",
            scope="BASE",
        )
        search_result = client.search(search_options)
        if search_result.is_success:
            unwrapped = search_result.unwrap()
            # Handle both return types: SearchResult or list[Entry]
            if isinstance(unwrapped, FlextLdapModels.SearchResult):
                entries = unwrapped.entries
            else:
                entries = unwrapped
            return len(entries) == 1
        return False

    @staticmethod
    def cleanup_after_test(
        client: LdapClientProtocol,
        dn: str | FlextLdifModels.DistinguishedName,
    ) -> None:
        """Cleanup entry after test execution.

        This is a common pattern repeated across many tests. Performs
        a delete operation after test to clean up test data. Ignores
        errors since entry may not exist.

        Args:
            client: LDAP client with delete method (FlextLdap, Ldap3Adapter, etc.)
            dn: Distinguished name as string or DistinguishedName object

        Example:
            result = ldap_client.add(entry)
            assert result.is_success
            # ... test assertions ...
            EntryTestHelpers.cleanup_after_test(ldap_client, entry.dn)

        """
        dn_str = str(dn) if dn else ""
        delete_result = client.delete(dn_str)
        # Ignore result - entry may not exist, that's OK for cleanup
        _ = delete_result

    @staticmethod
    def add_entry_from_dict(
        client: LdapClientProtocol,
        entry_dict: Mapping[str, object] | dict[str, object],
        *,
        verify: bool = True,
        cleanup_before: bool = True,
        cleanup_after: bool = True,
    ) -> tuple[FlextLdifModels.Entry, FlextResult[Any]]:
        """Complete workflow: convert dict to entry, cleanup, add, verify, cleanup.

        This method replaces the entire pattern of:
        - Converting dict to Entry
        - Cleaning up before add
        - Adding entry
        - Verifying entry was added
        - Cleaning up after test

        Args:
            client: LDAP client with add, delete, search methods
            entry_dict: Dictionary with 'dn' and 'attributes' keys
            verify: Whether to verify entry was added (default: True)
            cleanup_before: Whether to cleanup before add (default: True)
            cleanup_after: Whether to cleanup after add (default: True)

        Returns:
            Tuple of (entry, add_result)

        Example:
            entry, result = EntryTestHelpers.add_entry_from_dict(
                ldap_client, test_user_entry
            )
            assert result.is_success

        """
        # Convert dict to entry
        entry = EntryTestHelpers.dict_to_entry(entry_dict)

        # Ensure entry has DN
        if entry.dn is None:
            error_msg = "Entry must have a DN"
            raise ValueError(error_msg)

        # Cleanup before if requested
        if cleanup_before:
            # Convert DN to string to avoid type issues
            dn_str = str(entry.dn) if entry.dn else ""
            EntryTestHelpers.cleanup_entry(client, dn_str)

        # Add entry
        add_result = client.add(entry)

        # Verify if requested and add was successful
        if verify and add_result.is_success:
            dn_str = str(entry.dn) if entry.dn else ""
            assert EntryTestHelpers.verify_entry_added(client, dn_str), (
                "Entry was not found after add"
            )

        # Cleanup after if requested
        if cleanup_after:
            dn_str = str(entry.dn) if entry.dn else ""
            EntryTestHelpers.cleanup_after_test(client, dn_str)

        return entry, add_result

    @staticmethod
    def add_multiple_entries_from_dicts(
        client: LdapClientProtocol,
        entry_dicts: list[dict[str, object]],
        *,
        adjust_dn: dict[str, str] | None = None,
        cleanup_before: bool = True,
        cleanup_after: bool = True,
    ) -> list[tuple[FlextLdifModels.Entry, FlextResult[Any]]]:
        """Add multiple entries from list of dictionaries.

        This method replaces the entire pattern of:
        - Looping through entry dictionaries
        - Adjusting DNs if needed
        - Converting each dict to Entry
        - Cleaning up before each add
        - Adding each entry
        - Collecting DNs for cleanup
        - Cleaning up all entries after

        Args:
            client: LDAP client with add, delete methods
            entry_dicts: List of dictionaries with 'dn' and 'attributes' keys
            adjust_dn: Optional dict with 'from' and 'to' keys to replace in DN
            cleanup_before: Whether to cleanup before each add (default: True)
            cleanup_after: Whether to cleanup all entries after (default: True)

        Returns:
            List of tuples (entry, add_result) for each entry

        Example:
            results = EntryTestHelpers.add_multiple_entries_from_dicts(
                ldap_client,
                [user1_dict, user2_dict],
                adjust_dn={"from": "dc=example,dc=com", "to": "dc=flext,dc=local"}
            )

        """
        results: list[tuple[FlextLdifModels.Entry, FlextResult[Any]]] = []
        added_dns: list[str] = []

        for entry_dict in entry_dicts:
            # Adjust DN if requested
            if adjust_dn:
                original_dn = str(entry_dict.get("dn", ""))
                adjusted_dn = original_dn.replace(
                    adjust_dn.get("from", ""),
                    adjust_dn.get("to", ""),
                )
                entry_dict = {**entry_dict, "dn": adjusted_dn}

            # Add entry using the complete workflow (but don't cleanup after yet)
            entry, add_result = EntryTestHelpers.add_entry_from_dict(
                client,
                entry_dict,
                verify=False,  # Skip verification for speed
                cleanup_before=cleanup_before,
                cleanup_after=False,  # We'll cleanup all at once
            )

            results.append((entry, add_result))
            if entry.dn:
                added_dns.append(str(entry.dn))

        # Cleanup all entries at once if requested
        if cleanup_after:
            for dn_str in added_dns:
                EntryTestHelpers.cleanup_after_test(client, dn_str)

        return results  # type: ignore[return-value]

    @staticmethod
    def modify_entry_with_verification(
        client: LdapClientProtocol,
        entry_dict: Mapping[str, object] | dict[str, object],
        changes: dict[str, list[tuple[str, list[str]]]],
        *,
        verify_attribute: str | None = None,
        verify_value: str | None = None,
        cleanup_before: bool = True,
        cleanup_after: bool = True,
    ) -> tuple[FlextLdifModels.Entry, FlextResult[Any], FlextResult[Any]]:
        """Complete modify workflow: add entry, modify, verify, cleanup.

        This method replaces the entire pattern of:
        - Converting dict to Entry
        - Cleaning up before add
        - Adding entry
        - Modifying entry
        - Verifying modification
        - Cleaning up after test

        Args:
            client: LDAP client with add, modify, delete, search methods
            entry_dict: Dictionary with 'dn' and 'attributes' keys
            changes: Dictionary of modifications (attr -> list of (operation, values))
            verify_attribute: Optional attribute name to verify after modify
            verify_value: Optional value to check in verify_attribute
            cleanup_before: Whether to cleanup before add (default: True)
            cleanup_after: Whether to cleanup after modify (default: True)

        Returns:
            Tuple of (entry, add_result, modify_result)

        Example:
            entry, add_result, modify_result = EntryTestHelpers.modify_entry_with_verification(
                ldap_client,
                test_user_entry,
                {"mail": [(MODIFY_REPLACE, ["new@example.com"])]},
                verify_attribute="mail",
                verify_value="new@example.com"
            )

        """
        # First add the entry (without cleanup_after since we'll do it at the end)
        entry, add_result = EntryTestHelpers.add_entry_from_dict(
            client,
            entry_dict,
            verify=False,  # We'll verify after modify
            cleanup_before=cleanup_before,
            cleanup_after=False,  # We'll cleanup at the end
        )

        # Check if add_result is successful
        add_success = add_result.is_success

        if not add_success:
            # If add failed, cleanup and return
            if cleanup_after:
                dn_str = str(entry.dn) if entry.dn else ""
                EntryTestHelpers.cleanup_after_test(client, dn_str)
            return entry, add_result, add_result  # Return add_result as modify_result

        # Modify the entry
        dn_str = str(entry.dn) if entry.dn else ""
        modify_result = client.modify(dn_str, changes)

        # Verify modification if requested
        modify_success = modify_result.is_success

        if modify_success and verify_attribute and verify_value:
            # All clients now use SearchOptions - unified API
            search_options = FlextLdapModels.SearchOptions(
                base_dn=dn_str,
                filter_str="(objectClass=*)",
                scope="BASE",
            )
            search_result = client.search(search_options)
            if search_result.is_success:
                unwrapped = search_result.unwrap()
                # Handle both return types: SearchResult or list[Entry]
                if isinstance(unwrapped, FlextLdapModels.SearchResult):
                    entries = unwrapped.entries
                else:
                    entries = unwrapped
                if entries:
                    modified_entry = entries[0]
                    if (
                        modified_entry.attributes
                        and modified_entry.attributes.attributes
                    ):
                        attrs = modified_entry.attributes.attributes.get(
                            verify_attribute,
                            [],
                        )
                        assert verify_value in attrs, (
                            f"Expected {verify_value} in {verify_attribute}, got {attrs}"
                        )

        # Cleanup after if requested
        if cleanup_after:
            dn_str = str(entry.dn) if entry.dn else ""
            EntryTestHelpers.cleanup_after_test(client, dn_str)

        return entry, add_result, modify_result

    @staticmethod
    def delete_entry_with_verification(
        client: LdapClientProtocol,
        entry_dict: Mapping[str, object] | dict[str, object],
        *,
        cleanup_before: bool = True,
        verify_deletion: bool = True,
    ) -> tuple[FlextLdifModels.Entry, FlextResult[Any], FlextResult[Any]]:
        """Complete delete workflow: add entry, delete, verify deletion.

        This method replaces the entire pattern of:
        - Converting dict to Entry
        - Cleaning up before add
        - Adding entry
        - Deleting entry
        - Verifying deletion (entry doesn't exist)
        - No cleanup needed (entry already deleted)

        Args:
            client: LDAP client with add, delete, search methods
            entry_dict: Dictionary with 'dn' and 'attributes' keys
            cleanup_before: Whether to cleanup before add (default: True)
            verify_deletion: Whether to verify entry was deleted (default: True)

        Returns:
            Tuple of (entry, add_result, delete_result)

        Example:
            entry, add_result, delete_result = EntryTestHelpers.delete_entry_with_verification(
                ldap_client, test_user_entry
            )
            assert add_result.is_success
            assert delete_result.is_success

        """
        # First add the entry (without cleanup_after since we'll delete it)
        entry, add_result = EntryTestHelpers.add_entry_from_dict(
            client,
            entry_dict,
            verify=False,  # We'll verify after delete
            cleanup_before=cleanup_before,
            cleanup_after=False,  # We'll delete it, no cleanup needed
        )

        # Check if add_result is successful
        add_success = add_result.is_success

        if not add_success:
            # If add failed, return early
            return entry, add_result, add_result

        # Delete the entry
        dn_str = str(entry.dn) if entry.dn else ""
        delete_result = client.delete(dn_str)

        # Verify deletion if requested
        if verify_deletion:
            delete_success = delete_result.is_success

            if delete_success:
                # All clients now use SearchOptions - unified API
                search_options = FlextLdapModels.SearchOptions(
                    base_dn=dn_str,
                    filter_str="(objectClass=*)",
                    scope="BASE",
                )
                search_result = client.search(search_options)
                if search_result.is_success:
                    unwrapped = search_result.unwrap()
                    # Handle both return types: SearchResult or list[Entry]
                    if isinstance(unwrapped, FlextLdapModels.SearchResult):
                        entries = unwrapped.entries
                    else:
                        entries = unwrapped
                    assert len(entries) == 0, (
                        f"Entry {dn_str} still exists after deletion"
                    )

        return entry, add_result, delete_result

    @staticmethod
    def create_entry(
        dn: str,
        attributes: dict[str, list[str] | str],
    ) -> FlextLdifModels.Entry:
        """Create Entry directly from DN string and attributes dict.

        This method replaces the common pattern of creating Entry objects
        with DistinguishedName and LdifAttributes manually.

        Args:
            dn: Distinguished name as string
            attributes: Dictionary of attributes (values can be list or single value)

        Returns:
            FlextLdifModels.Entry created from parameters

        Example:
            entry = EntryTestHelpers.create_entry(
                "cn=test,dc=example,dc=com",
                {"cn": ["test"], "objectClass": ["person"]}
            )

        """
        dn_obj = FlextLdifModels.DistinguishedName(value=dn)
        # Convert single values to lists
        attrs_dict: dict[str, list[str]] = {}
        for key, value in attributes.items():
            if isinstance(value, list):
                attrs_dict[key] = value
            elif isinstance(value, (tuple, set, frozenset)):
                # Convert list-like collections to list of strings
                attrs_dict[key] = [str(item) for item in value]
            else:
                attrs_dict[key] = [str(value)]
        attrs = FlextLdifModels.LdifAttributes.model_validate({
            "attributes": attrs_dict,
        })
        return FlextLdifModels.Entry(dn=dn_obj, attributes=attrs)

    @staticmethod
    def add_and_cleanup(
        client: LdapClientProtocol,
        entry: FlextLdifModels.Entry,
        *,
        verify: bool = False,
        cleanup_after: bool = True,
    ) -> FlextResult[Any]:
        """Add entry with automatic cleanup before and after.

        Simplified version for when you already have an Entry object.

        Args:
            client: LDAP client with add, delete methods
            entry: FlextLdifModels.Entry to add
            verify: Whether to verify entry was added (default: False)
            cleanup_after: Whether to cleanup after add (default: True)

        Returns:
            Add result object

        Example:
            entry = EntryTestHelpers.create_entry("cn=test,dc=example,dc=com", {"cn": ["test"]})
            result = EntryTestHelpers.add_and_cleanup(ldap_client, entry)

        """
        # Cleanup before
        if entry.dn:
            dn_str = str(entry.dn)
            EntryTestHelpers.cleanup_entry(client, dn_str)

        # Add entry
        add_result = client.add(entry)

        # Verify if requested
        if verify and entry.dn and add_result.is_success:
            dn_str = str(entry.dn)
            assert EntryTestHelpers.verify_entry_added(client, dn_str)

        # Cleanup after if requested
        if cleanup_after and entry.dn:
            dn_str = str(entry.dn)
            EntryTestHelpers.cleanup_after_test(client, dn_str)

        return add_result
