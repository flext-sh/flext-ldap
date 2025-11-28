"""Helper methods for creating and manipulating Entry objects in tests.

This module provides methods to reduce duplication when creating Entry objects
from dictionaries, fixtures, and other common test patterns. Uses flext_tests
utilities for maximum code reuse and DRY principles.

Module: EntryTestHelpers
Scope: Entry creation, manipulation, and LDAP operation workflows for tests
Pattern: Static helper methods using flext_tests and protocols

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from collections.abc import Callable, Generator, Mapping
from contextlib import contextmanager
from typing import cast

from flext_core import FlextResult, FlextRuntime
from flext_ldif.models import FlextLdifModels
from ldap3 import Connection, Entry as Ldap3Entry, Server

from flext_ldap import FlextLdap
from flext_ldap.constants import FlextLdapConstants
from flext_ldap.models import FlextLdapModels
from flext_ldap.protocols import FlextLdapProtocols
from flext_ldap.services.operations import FlextLdapOperations
from tests.fixtures.typing import GenericFieldsDict

LdapClientType = FlextLdap | FlextLdapProtocols.LdapClient
LdapOperationsType = FlextLdap | FlextLdapOperations | FlextLdapProtocols.LdapClient


class EntryTestHelpers:
    """Helper methods for Entry creation and manipulation in tests.

    Uses flext_tests utilities and protocols for maximum code reuse.
    All methods are static for easy use in tests.
    """

    class _EntryFactory:
        """Nested class for entry creation (SRP)."""

        @staticmethod
        def _normalize_attributes(
            attributes: Mapping[str, object],
        ) -> dict[str, list[str]]:
            """Normalize attributes to dict[str, list[str]].

            Args:
                attributes: Raw attributes mapping with any value type

            Returns:
                Normalized dict with list[str] values

            """
            attrs_dict: dict[str, list[str]] = {}
            for key, value_item_raw in attributes.items():
                if FlextRuntime.is_list_like(value_item_raw):
                    attrs_dict[key] = [str(item) for item in value_item_raw]
                else:
                    attrs_dict[key] = [str(value_item_raw)]
            return attrs_dict

    @staticmethod
    def create_entry(
        dn: str,
        attributes: Mapping[str, object],
    ) -> FlextLdifModels.Entry:
        """Create Entry directly from DN string and attributes dict.

        Args:
            dn: Distinguished name string
            attributes: Attribute dict - values are normalized to list[str]

        Returns:
            FlextLdifModels.Entry with normalized attributes

        """
        dn_obj = FlextLdifModels.DistinguishedName(value=dn)
        attrs_dict = EntryTestHelpers._EntryFactory._normalize_attributes(attributes)
        attrs = FlextLdifModels.LdifAttributes.model_validate({
            "attributes": attrs_dict,
        })
        return FlextLdifModels.Entry(dn=dn_obj, attributes=attrs)

    @staticmethod
    def dict_to_entry(
        entry_dict: Mapping[str, object] | GenericFieldsDict,
    ) -> FlextLdifModels.Entry:
        """Convert dictionary to FlextLdifModels.Entry."""
        dn_str = str(entry_dict.get("dn", ""))
        attrs_raw = entry_dict.get("attributes", {})
        attrs_dict: GenericFieldsDict = cast(
            "GenericFieldsDict",
            dict(attrs_raw) if FlextRuntime.is_dict_like(attrs_raw) else {},
        )
        return EntryTestHelpers.create_entry(dn_str, attrs_dict)

    @staticmethod
    def cleanup_entry(
        client: LdapOperationsType,
        dn: str | FlextLdifModels.DistinguishedName,
    ) -> None:
        """Cleanup entry before add to avoid entryAlreadyExists errors."""
        dn_str = str(dn) if dn else ""
        _ = client.delete(dn_str)

    @staticmethod
    def verify_entry_added(
        client: LdapOperationsType,
        dn: str | FlextLdifModels.DistinguishedName,
    ) -> bool:
        """Verify that an entry was successfully added to LDAP."""
        dn_str = str(dn) if dn else ""
        search_options = FlextLdapModels.SearchOptions(
            base_dn=dn_str,
            filter_str="(objectClass=*)",
            scope=FlextLdapConstants.SearchScope.BASE,
            attributes=["*"],  # Get all attributes for validation
        )
        search_result = client.search(
            cast("FlextLdapProtocols.SearchOptionsProtocol", search_options)
        )
        if search_result.is_success:
            unwrapped = search_result.unwrap()
            return len(unwrapped.entries) == 1
        return False

    @staticmethod
    def verify_entry_data_matches(
        client: LdapOperationsType,
        expected_entry: FlextLdifModels.Entry,
    ) -> bool:
        """Verify that entry data in LDAP matches expected entry.

        Args:
            client: LDAP client with search method
            expected_entry: Expected entry data

        Returns:
            True if entry data matches, False otherwise

        """
        if not expected_entry.dn:
            return False

        dn_str = str(expected_entry.dn)
        search_options = FlextLdapModels.SearchOptions(
            base_dn=dn_str,
            filter_str="(objectClass=*)",
            scope=FlextLdapConstants.SearchScope.BASE,
            attributes=["*"],  # Get all attributes
        )
        search_result = client.search(
            cast("FlextLdapProtocols.SearchOptionsProtocol", search_options)
        )
        if not search_result.is_success:
            return False

        unwrapped = search_result.unwrap()
        if len(unwrapped.entries) != 1:
            return False

        found_entry = unwrapped.entries[0]

        # Compare DN
        if str(found_entry.dn) != str(expected_entry.dn):
            return False

        # Compare attributes
        if not found_entry.attributes or not expected_entry.attributes:
            return False

        found_attrs = (
            found_entry.attributes.attributes
            if hasattr(found_entry.attributes, "attributes")
            else dict(found_entry.attributes)
        )
        expected_attrs = (
            expected_entry.attributes.attributes
            if hasattr(expected_entry.attributes, "attributes")
            else dict(expected_entry.attributes)
        )

        # Check that all expected attributes are present with correct values
        for attr_name, expected_values in expected_attrs.items():
            if attr_name not in found_attrs:
                return False
            found_values = found_attrs[attr_name]
            if sorted(found_values) != sorted(expected_values):
                return False

        return True

    @staticmethod
    def cleanup_after_test(
        client: LdapOperationsType,
        dn: str | FlextLdifModels.DistinguishedName,
    ) -> None:
        """Cleanup entry after test execution."""
        dn_str = str(dn) if dn else ""
        _ = client.delete(dn_str)

    @staticmethod
    def add_entry_from_dict(
        client: LdapOperationsType,
        entry_dict: Mapping[str, object] | GenericFieldsDict,
        *,
        verify: bool = True,
        cleanup_before: bool = True,
        cleanup_after: bool = True,
    ) -> tuple[FlextLdifModels.Entry, FlextResult[FlextLdapModels.OperationResult]]:
        """Complete workflow: convert dict to entry, cleanup, add, verify, cleanup."""
        entry = EntryTestHelpers.dict_to_entry(entry_dict)
        if cleanup_before:
            EntryTestHelpers.cleanup_entry(client, str(entry.dn) if entry.dn else "")
        add_result = client.add(cast("FlextLdapProtocols.EntryProtocol", entry))
        if verify and add_result.is_success:
            assert EntryTestHelpers.verify_entry_added(
                client,
                str(entry.dn) if entry.dn else "",
            ), "Entry was not found after add"
        if cleanup_after:
            EntryTestHelpers.cleanup_after_test(
                client,
                str(entry.dn) if entry.dn else "",
            )
        return entry, add_result

    @staticmethod
    def add_multiple_entries_from_dicts(
        client: LdapOperationsType,
        entry_dicts: list[GenericFieldsDict],
        *,
        adjust_dn: dict[str, str] | None = None,
        cleanup_before: bool = True,
        cleanup_after: bool = True,
    ) -> list[
        tuple[FlextLdifModels.Entry, FlextResult[FlextLdapModels.OperationResult]]
    ]:
        """Add multiple entries from list of dictionaries."""
        results: list[
            tuple[FlextLdifModels.Entry, FlextResult[FlextLdapModels.OperationResult]]
        ] = []
        added_dns: list[str] = []
        for entry_dict_item in entry_dicts:
            entry_dict: GenericFieldsDict = dict(entry_dict_item)
            if adjust_dn:
                original_dn = str(entry_dict.get("dn", ""))
                adjusted_dn = original_dn.replace(
                    str(adjust_dn.get("from", "")),
                    str(adjust_dn.get("to", "")),
                )
                entry_dict["dn"] = adjusted_dn
            entry, add_result = EntryTestHelpers.add_entry_from_dict(
                client,
                entry_dict,
                verify=False,
                cleanup_before=cleanup_before,
                cleanup_after=False,
            )
            results.append((entry, add_result))
            if entry.dn:
                added_dns.append(str(entry.dn))
        if cleanup_after:
            for dn_str in added_dns:
                EntryTestHelpers.cleanup_after_test(client, dn_str)
        return results

    @staticmethod
    def modify_entry_with_verification(
        client: LdapOperationsType,
        entry_dict: Mapping[str, object] | GenericFieldsDict,
        changes: dict[str, list[tuple[str, list[str]]]],
        *,
        verify_attribute: str | None = None,
        verify_value: str | None = None,
        cleanup_before: bool = True,
        cleanup_after: bool = True,
    ) -> tuple[
        FlextLdifModels.Entry,
        FlextResult[FlextLdapModels.OperationResult],
        FlextResult[FlextLdapModels.OperationResult],
    ]:
        """Complete modify workflow: add entry, modify, verify, cleanup."""
        entry, add_result = EntryTestHelpers.add_entry_from_dict(
            client,
            entry_dict,
            verify=False,
            cleanup_before=cleanup_before,
            cleanup_after=False,
        )
        if not add_result.is_success:
            if cleanup_after:
                EntryTestHelpers.cleanup_after_test(
                    client,
                    str(entry.dn) if entry.dn else "",
                )
            return entry, add_result, add_result
        dn_str = str(entry.dn) if entry.dn else ""
        modify_result = client.modify(dn_str, changes)
        if modify_result.is_success and verify_attribute and verify_value and entry.dn:
            search_options = FlextLdapModels.SearchOptions(
                base_dn=dn_str,
                filter_str="(objectClass=*)",
                scope=FlextLdapConstants.SearchScope.BASE,
            )
            search_result = client.search(
                cast("FlextLdapProtocols.SearchOptionsProtocol", search_options)
            )
            if search_result.is_success:
                unwrapped = search_result.unwrap()
                if unwrapped.entries:
                    modified_entry = unwrapped.entries[0]
                    if modified_entry.attributes:
                        entry_attrs = (
                            modified_entry.attributes.attributes
                            if hasattr(modified_entry.attributes, "attributes")
                            else dict(modified_entry.attributes)
                        )
                        attrs = entry_attrs.get(verify_attribute, [])
                        assert verify_value in attrs, (
                            f"Expected {verify_value} in {verify_attribute}, got {attrs}"
                        )
        if cleanup_after:
            EntryTestHelpers.cleanup_after_test(client, dn_str)
        return entry, add_result, modify_result

    @staticmethod
    def delete_entry_with_verification(
        client: LdapOperationsType,
        entry_dict: Mapping[str, object] | GenericFieldsDict,
        *,
        cleanup_before: bool = True,
        verify_deletion: bool = True,
    ) -> tuple[
        FlextLdifModels.Entry,
        FlextResult[FlextLdapModels.OperationResult],
        FlextResult[FlextLdapModels.OperationResult],
    ]:
        """Complete delete workflow: add entry, delete, verify deletion."""
        entry, add_result = EntryTestHelpers.add_entry_from_dict(
            client,
            entry_dict,
            verify=False,
            cleanup_before=cleanup_before,
            cleanup_after=False,
        )
        if not add_result.is_success:
            return entry, add_result, add_result
        dn_str = str(entry.dn) if entry.dn else ""
        delete_result = client.delete(dn_str)
        if verify_deletion and delete_result.is_success:
            search_options = FlextLdapModels.SearchOptions(
                base_dn=dn_str,
                filter_str="(objectClass=*)",
                scope=FlextLdapConstants.SearchScope.BASE,
            )
            search_result = client.search(
                cast("FlextLdapProtocols.SearchOptionsProtocol", search_options)
            )
            if search_result.is_success:
                unwrapped = search_result.unwrap()
                assert len(unwrapped.entries) == 0, (
                    f"Entry {dn_str} still exists after deletion"
                )
        return entry, add_result, delete_result

    @staticmethod
    def add_and_cleanup(
        client: LdapOperationsType,
        entry: FlextLdifModels.Entry,
        *,
        verify: bool = False,
        verify_data: bool = False,
        cleanup_after: bool = True,
    ) -> FlextResult[FlextLdapModels.OperationResult]:
        """Add entry with automatic cleanup before and after.

        Args:
            client: LDAP client
            entry: Entry to add
            verify: Whether to verify entry exists after add
            verify_data: Whether to verify entry data matches expected data
            cleanup_after: Whether to cleanup after test

        """
        if entry.dn:
            dn_str = str(entry.dn)
            EntryTestHelpers.cleanup_entry(client, dn_str)
        add_result = client.add(cast("FlextLdapProtocols.EntryProtocol", entry))
        if add_result.is_success:
            if verify and entry.dn:
                assert EntryTestHelpers.verify_entry_added(client, str(entry.dn))
            if verify_data:
                assert EntryTestHelpers.verify_entry_data_matches(client, entry)
        if cleanup_after and entry.dn:
            EntryTestHelpers.cleanup_after_test(client, str(entry.dn))
        return add_result

    @staticmethod
    @contextmanager
    def ldap3_connection_from_container(
        ldap_container: GenericFieldsDict,
    ) -> Generator[tuple[Connection, Ldap3Entry | None]]:
        """Context manager for LDAP3 connection from container fixture."""
        server = Server(
            f"ldap://{ldap_container['host']}:{ldap_container['port']}",
            get_info="ALL",
        )
        connection = Connection(
            server,
            user=str(ldap_container["bind_dn"]),
            password=str(ldap_container["password"]),
            auto_bind=True,
        )
        entry: Ldap3Entry | None = None
        try:
            connection.search(
                search_base=str(ldap_container["base_dn"]),
                search_filter="(objectClass=*)",
                search_scope=FlextLdapConstants.SearchScope.BASE.value,
                attributes=["*"],
            )
            if len(connection.entries) > 0:
                entry = connection.entries[0]
            yield (connection, entry)
        finally:
            if connection.bound:
                unbind_func: Callable[[], None] = connection.unbind
                unbind_func()

    @staticmethod
    def with_ldap3_entry(
        ldap_container: GenericFieldsDict,
        modifier: Callable[[Ldap3Entry], None],
    ) -> Ldap3Entry | None:
        """Get LDAP3 entry and apply modification, returning modified entry."""
        with EntryTestHelpers.ldap3_connection_from_container(ldap_container) as (
            _,
            entry,
        ):
            if entry and hasattr(entry, "entry_attributes_as_dict"):
                modifier(entry)
                return entry
        return None

    class MetadataHelpers:
        """Helper methods for metadata assertion in tests (moved from nested class)."""

        @staticmethod
        def get_extensions(entry: FlextLdifModels.Entry) -> GenericFieldsDict:
            """Get extensions dict from entry metadata."""
            if not entry.metadata or not hasattr(entry.metadata, "extensions"):
                return {}
            extensions = entry.metadata.extensions
            return dict(extensions) if FlextRuntime.is_dict_like(extensions) else {}

        @staticmethod
        def assert_base64_tracked(entry: FlextLdifModels.Entry, attr_name: str) -> None:
            """Assert base64 attribute is tracked in metadata."""
            extensions = EntryTestHelpers.MetadataHelpers.get_extensions(entry)
            base64_attrs = extensions.get("base64_encoded_attributes")
            if base64_attrs:
                base64_list = (
                    list(base64_attrs)
                    if FlextRuntime.is_list_like(base64_attrs)
                    else [base64_attrs]
                )
                base64_strs = [str(a) for a in base64_list if a is not None]
                assert any(attr_name in a for a in base64_strs), (
                    f"Expected {attr_name} in base64_encoded_attributes"
                )

        @staticmethod
        def assert_converted_tracked(
            entry: FlextLdifModels.Entry,
            attr_name: str,
        ) -> None:
            """Assert converted attribute is tracked in metadata."""
            extensions = EntryTestHelpers.MetadataHelpers.get_extensions(entry)
            converted_attrs = extensions.get("converted_attributes")
            if converted_attrs and isinstance(converted_attrs, (list, dict, set)):
                assert attr_name in converted_attrs, (
                    f"Expected {attr_name} in converted_attributes"
                )

    @staticmethod
    def create_real_ldap3_entry(
        ldap_container: GenericFieldsDict,
        dn: str,
        attributes: GenericFieldsDict,
    ) -> Ldap3Entry | None:
        """Create real LDAP3 entry by adding to LDAP and retrieving it."""
        with EntryTestHelpers.ldap3_connection_from_container(ldap_container) as (
            connection,
            _,
        ):
            # Add entry to LDAP
            object_class_value = attributes.get("objectClass", ["top"])
            object_classes: list[str]
            if FlextRuntime.is_list_like(object_class_value):
                object_classes = [str(oc) for oc in object_class_value]
            elif isinstance(object_class_value, str):
                object_classes = [object_class_value]
            else:
                object_classes = ["top"]

            attrs_dict: GenericFieldsDict = {
                k: v for k, v in attributes.items() if k != "objectClass"
            }

            add_func: Callable[[str, list[str], GenericFieldsDict], bool] = (
                connection.add
            )
            add_success = add_func(dn, object_classes, attrs_dict)
            if not add_success:
                return None

            # Retrieve the entry
            connection.search(
                search_base=dn,
                search_filter="(objectClass=*)",
                search_scope=FlextLdapConstants.SearchScope.BASE.value,
                attributes=["*"],
            )
            if connection.entries:
                entry_raw = connection.entries[0]
                entry: Ldap3Entry | None = (
                    entry_raw if isinstance(entry_raw, Ldap3Entry) else None
                )
                if entry:
                    # Cleanup
                    delete_func: Callable[[str], bool] = connection.delete
                    delete_func(dn)
                    return entry
            return None
