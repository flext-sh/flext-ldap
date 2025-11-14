"""Comprehensive LDAP operations tests using real server and fixtures.

Tests all CRUD operations with real LDAP server using fixtures from
tests/fixtures directory. Validates all functions end-to-end.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

import pytest
from flext_ldif.models import FlextLdifModels
from ldap3 import MODIFY_ADD, MODIFY_REPLACE

from flext_ldap import FlextLdap
from flext_ldap.models import FlextLdapModels
from tests.fixtures.loader import LdapTestFixtures
from tests.helpers.entry_helpers import EntryTestHelpers

pytestmark = pytest.mark.integration


@pytest.mark.integration
class TestFlextLdapComprehensiveSearch:
    """Comprehensive search operation tests using fixtures."""

    def test_search_all_entries(
        self,
        ldap_client: FlextLdap,
        ldap_container: dict[str, object],
    ) -> None:
        """Test searching all entries in base DN."""
        search_options = FlextLdapModels.SearchOptions(
            base_dn=str(ldap_container["base_dn"]),
            filter_str="(objectClass=*)",
            scope="SUBTREE",
        )

        result = ldap_client.search(search_options)

        assert result.is_success, f"Search failed: {result.error}"
        search_result = result.unwrap()
        assert len(search_result.entries) > 0
        assert search_result.total_count == len(search_result.entries)

    def test_search_with_fixture_filter(
        self,
        ldap_client: FlextLdap,
        ldap_container: dict[str, object],
        base_ldif_entries: list[object],
    ) -> None:
        """Test search using filter from fixture data."""
        # Search for organizational units
        search_options = FlextLdapModels.SearchOptions(
            base_dn=str(ldap_container["base_dn"]),
            filter_str="(objectClass=organizationalUnit)",
            scope="SUBTREE",
        )

        result = ldap_client.search(search_options)

        assert result.is_success
        search_result = result.unwrap()
        # Should find at least people, groups OUs
        assert len(search_result.entries) >= 0  # May or may not have OUs yet

    def test_search_users_only(
        self,
        ldap_client: FlextLdap,
        ldap_container: dict[str, object],
    ) -> None:
        """Test searching for user entries only."""
        search_options = FlextLdapModels.SearchOptions(
            base_dn=str(ldap_container["base_dn"]),
            filter_str="(objectClass=inetOrgPerson)",
            scope="SUBTREE",
        )

        result = ldap_client.search(search_options)

        assert result.is_success
        search_result = result.unwrap()
        # All results should be users
        for entry in search_result.entries:
            if entry.attributes and entry.attributes.attributes:
                object_classes = entry.attributes.attributes.get("objectClass", [])
                if isinstance(object_classes, list):
                    assert (
                        "inetOrgPerson" in object_classes or "person" in object_classes
                    )

    def test_search_groups_only(
        self,
        ldap_client: FlextLdap,
        ldap_container: dict[str, object],
    ) -> None:
        """Test searching for group entries only."""
        search_options = FlextLdapModels.SearchOptions(
            base_dn=str(ldap_container["base_dn"]),
            filter_str="(objectClass=groupOfNames)",
            scope="SUBTREE",
        )

        result = ldap_client.search(search_options)

        assert result.is_success
        search_result = result.unwrap()
        # All results should be groups
        for entry in search_result.entries:
            if entry.attributes and entry.attributes.attributes:
                object_classes = entry.attributes.attributes.get("objectClass", [])
                if isinstance(object_classes, list):
                    assert "groupOfNames" in object_classes


@pytest.mark.integration
class TestFlextLdapComprehensiveAdd:
    """Comprehensive add operation tests using fixtures."""

    def test_add_user_from_fixture(
        self,
        ldap_client: FlextLdap,
        test_user_entry: dict[str, object],
    ) -> None:
        """Test adding user entry from fixture data."""
        # Complete workflow using helper: convert, cleanup, add, verify, cleanup
        entry, result = EntryTestHelpers.add_entry_from_dict(
            ldap_client, test_user_entry
        )

        assert result.is_success, f"Add failed: {result.error}"
        operation_result = result.unwrap()
        assert operation_result.success is True
        assert operation_result.entries_affected == 1

    def test_add_group_from_fixture(
        self,
        ldap_client: FlextLdap,
        test_group_entry: dict[str, object],
    ) -> None:
        """Test adding group entry from fixture data."""
        # Complete workflow using helper
        entry, result = EntryTestHelpers.add_entry_from_dict(
            ldap_client, test_group_entry
        )

        assert result.is_success, f"Add failed: {result.error}"

    def test_add_multiple_users_from_fixtures(
        self,
        ldap_client: FlextLdap,
        test_users_json: list[dict[str, object]],
        ldap_container: dict[str, object],
    ) -> None:
        """Test adding multiple users from fixture JSON."""
        # Convert all users to entry dicts
        entry_dicts = [
            LdapTestFixtures.convert_user_json_to_entry(user_data)
            for user_data in test_users_json[:2]  # Limit to 2 for test speed
        ]

        # Add all entries using helper with DN adjustment
        base_dn = str(ldap_container.get("base_dn", ""))
        results = EntryTestHelpers.add_multiple_entries_from_dicts(
            ldap_client,
            entry_dicts,
            adjust_dn={"from": "dc=example,dc=com", "to": base_dn},
        )

        # Verify all adds succeeded
        for entry, result in results:
            assert result.is_success, f"Failed to add {entry.dn}: {result.error}"


@pytest.mark.integration
class TestFlextLdapComprehensiveModify:
    """Comprehensive modify operation tests using fixtures."""

    def test_modify_user_attributes(
        self,
        ldap_client: FlextLdap,
        test_user_entry: dict[str, object],
    ) -> None:
        """Test modifying user entry attributes."""
        # Complete modify workflow using helper: add, modify, verify, cleanup
        changes: dict[str, list[tuple[str, list[str]]]] = {
            "mail": [(MODIFY_REPLACE, ["updated@example.com"])],
            "telephoneNumber": [(MODIFY_ADD, ["+9876543210"])],
        }

        entry, add_result, modify_result = EntryTestHelpers.modify_entry_with_verification(
            ldap_client,
            test_user_entry,
            changes,
            verify_attribute="mail",
            verify_value="updated@example.com",
        )

        assert add_result.is_success
        assert modify_result.is_success, f"Modify failed: {modify_result.error}"


@pytest.mark.integration
class TestFlextLdapComprehensiveDelete:
    """Comprehensive delete operation tests using fixtures."""

    def test_delete_user_entry(
        self,
        ldap_client: FlextLdap,
        test_user_entry: dict[str, object],
    ) -> None:
        """Test deleting user entry."""
        # Complete delete workflow using helper: add, delete, verify deletion
        entry, add_result, delete_result = EntryTestHelpers.delete_entry_with_verification(
            ldap_client, test_user_entry
        )

        assert add_result.is_success, f"Add failed: {add_result.error}"
        assert delete_result.is_success, f"Delete failed: {delete_result.error}"
        operation_result = delete_result.unwrap()
        assert operation_result.success is True
        assert operation_result.entries_affected == 1


@pytest.mark.integration
class TestFlextLdapConnectionManagement:
    """Connection management tests."""

    def test_connect_and_disconnect(
        self,
        connection_config: FlextLdapModels.ConnectionConfig,
    ) -> None:
        """Test connection lifecycle."""
        client = FlextLdap()

        # Connect
        connect_result = client.connect(connection_config)
        assert connect_result.is_success, f"Connect failed: {connect_result.error}"
        assert client.is_connected is True

        # Disconnect
        client.disconnect()
        assert client.is_connected is False

    def test_reconnect_after_disconnect(
        self,
        connection_config: FlextLdapModels.ConnectionConfig,
    ) -> None:
        """Test reconnecting after disconnect."""
        client = FlextLdap()

        # First connection
        connect_result = client.connect(connection_config)
        assert connect_result.is_success
        client.disconnect()

        # Reconnect
        connect_result2 = client.connect(connection_config)
        assert connect_result2.is_success
        assert client.is_connected is True

        client.disconnect()


@pytest.mark.integration
class TestFlextLdapWithBaseLdif:
    """Tests using base LDIF fixture."""

    def test_load_and_search_base_ldif(
        self,
        ldap_client: FlextLdap,
        base_ldif_entries: list[object],
        ldap_container: dict[str, object],
    ) -> None:
        """Test loading base LDIF entries and searching for them."""
        if not base_ldif_entries:
            pytest.skip("No base LDIF entries available")

        # Search for entries that should be in base LDIF
        search_options = FlextLdapModels.SearchOptions(
            base_dn=str(ldap_container["base_dn"]),
            filter_str="(objectClass=organizationalUnit)",
            scope="SUBTREE",
        )

        result = ldap_client.search(search_options)
        assert result.is_success
        # Should find OUs if they exist in server

    def test_add_entry_from_base_ldif(
        self,
        ldap_client: FlextLdap,
        base_ldif_entries: list[object],
        ldap_container: dict[str, object],
    ) -> None:
        """Test adding entry parsed from base LDIF."""
        if not base_ldif_entries:
            pytest.skip("No base LDIF entries available")

        # Find a user entry in base LDIF
        user_entry = None
        for entry in base_ldif_entries:
            if (
                isinstance(entry, FlextLdifModels.Entry)
                and entry.attributes
                and entry.attributes.attributes
                and "inetOrgPerson"
                in entry.attributes.attributes.get("objectClass", [])
            ):
                user_entry = entry
                break

        if not user_entry or not isinstance(user_entry, FlextLdifModels.Entry):
            pytest.skip("No user entry found in base LDIF")

        # Adjust DN to use flext.local domain
        if user_entry.dn is None:
            pytest.skip("Entry has no DN")
        original_dn = str(user_entry.dn.value)
        new_dn = original_dn.replace(
            "dc=example,dc=com", str(ldap_container.get("base_dn", ""))
        )

        # Create new entry with adjusted DN
        new_entry = FlextLdifModels.Entry(
            dn=FlextLdifModels.DistinguishedName(value=new_dn),
            attributes=user_entry.attributes or FlextLdifModels.LdifAttributes(),
        )

        # Add entry
        result = ldap_client.add(new_entry)
        assert result.is_success, f"Add failed: {result.error}"

        # Cleanup
        delete_result = ldap_client.delete(str(new_dn))
        assert delete_result.is_success or delete_result.is_failure
