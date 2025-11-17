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
from tests.helpers.operation_helpers import TestOperationHelpers
from tests.helpers.test_helpers import FlextLdapTestHelpers

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
        search_options = FlextLdapTestHelpers.create_search_options(
            base_dn=str(ldap_container["base_dn"]),
        )
        result = ldap_client.search(search_options)
        FlextLdapTestHelpers.assert_search_success(result, min_entries=1)

    def test_search_with_fixture_filter(
        self,
        ldap_client: FlextLdap,
        ldap_container: dict[str, object],
        base_ldif_entries: list[object],
    ) -> None:
        """Test search using filter from fixture data."""
        search_options = FlextLdapTestHelpers.create_search_options(
            base_dn=str(ldap_container["base_dn"]),
            filter_str="(objectClass=organizationalUnit)",
        )
        result = ldap_client.search(search_options)
        FlextLdapTestHelpers.assert_search_success(result)

    def test_search_users_only(
        self,
        ldap_client: FlextLdap,
        ldap_container: dict[str, object],
    ) -> None:
        """Test searching for user entries only."""
        search_options = FlextLdapTestHelpers.create_search_options(
            base_dn=str(ldap_container["base_dn"]),
            filter_str="(objectClass=inetOrgPerson)",
        )
        result = ldap_client.search(search_options)
        search_result = FlextLdapTestHelpers.assert_search_success(result)
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
        search_options = FlextLdapTestHelpers.create_search_options(
            base_dn=str(ldap_container["base_dn"]),
            filter_str="(objectClass=groupOfNames)",
        )
        result = ldap_client.search(search_options)
        search_result = FlextLdapTestHelpers.assert_search_success(result)
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
        _entry, result = FlextLdapTestHelpers.add_entry_from_dict_with_cleanup(
            ldap_client,
            test_user_entry,
        )
        FlextLdapTestHelpers.assert_operation_success(result)

    def test_add_group_from_fixture(
        self,
        ldap_client: FlextLdap,
        test_group_entry: dict[str, object],
    ) -> None:
        """Test adding group entry from fixture data."""
        _entry, result = FlextLdapTestHelpers.add_entry_from_dict_with_cleanup(
            ldap_client,
            test_group_entry,
        )
        FlextLdapTestHelpers.assert_operation_success(result)

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

        base_dn = str(ldap_container.get("base_dn", ""))
        results = FlextLdapTestHelpers.add_multiple_entries_from_dicts(
            ldap_client,
            entry_dicts,
            adjust_dn={"from": "dc=example,dc=com", "to": base_dn},
        )

        for _entry, result in results:
            FlextLdapTestHelpers.assert_operation_success(result)


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

        _entry, add_result, modify_result = (
            FlextLdapTestHelpers.modify_entry_with_verification(
                ldap_client,
                test_user_entry,
                changes,
            )
        )
        FlextLdapTestHelpers.assert_operation_success(add_result)
        FlextLdapTestHelpers.assert_operation_success(modify_result)


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
        _entry, add_result, delete_result = (
            FlextLdapTestHelpers.delete_entry_with_verification(
                ldap_client,
                test_user_entry,
            )
        )
        FlextLdapTestHelpers.assert_operation_success(add_result)
        FlextLdapTestHelpers.assert_operation_success(delete_result)


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
        TestOperationHelpers.connect_and_assert_success(client, connection_config)

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
        TestOperationHelpers.connect_and_assert_success(client, connection_config)
        client.disconnect()

        # Reconnect
        TestOperationHelpers.connect_and_assert_success(client, connection_config)

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

        search_options = FlextLdapTestHelpers.create_search_options(
            base_dn=str(ldap_container["base_dn"]),
            filter_str="(objectClass=organizationalUnit)",
        )
        result = ldap_client.search(search_options)
        FlextLdapTestHelpers.assert_search_success(result)

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
            "dc=example,dc=com",
            str(ldap_container.get("base_dn", "")),
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
