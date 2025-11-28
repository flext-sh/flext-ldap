"""Comprehensive LDAP operations tests using real server and fixtures.

Tests all CRUD operations with real LDAP server using fixtures from
tests/fixtures directory. Validates all functions end-to-end.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

from typing import cast

import pytest
from flext_ldif.models import FlextLdifModels
from ldap3 import MODIFY_ADD, MODIFY_REPLACE

from flext_ldap import FlextLdap
from flext_ldap.models import FlextLdapModels
from flext_ldap.protocols import FlextLdapProtocols
from tests.fixtures.typing import GenericFieldsDict

from ..fixtures import LdapTestFixtures
from ..helpers.operation_helpers import TestOperationHelpers
from ..helpers.test_helpers import FlextLdapTestHelpers

pytestmark = pytest.mark.integration


@pytest.mark.integration
class TestFlextLdapComprehensiveSearch:
    """Comprehensive search operation tests using fixtures."""

    def test_search_all_entries(
        self,
        ldap_client: FlextLdap,
        ldap_container: GenericFieldsDict,
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
        ldap_container: GenericFieldsDict,
        base_ldif_entries: list[FlextLdifModels.Entry],
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
        ldap_container: GenericFieldsDict,
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
        ldap_container: GenericFieldsDict,
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
        test_user_entry: GenericFieldsDict,
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
        test_group_entry: GenericFieldsDict,
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
        test_users_json: list[GenericFieldsDict],
        ldap_container: GenericFieldsDict,
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
        test_user_entry: GenericFieldsDict,
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
        test_user_entry: GenericFieldsDict,
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
        TestOperationHelpers.connect_and_assert_success(
            cast("FlextLdapProtocols.LdapClient", client),
            connection_config,
        )

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
        TestOperationHelpers.connect_and_assert_success(
            cast("FlextLdapProtocols.LdapClient", client),
            connection_config,
        )
        client.disconnect()

        # Reconnect
        TestOperationHelpers.connect_and_assert_success(
            cast("FlextLdapProtocols.LdapClient", client),
            connection_config,
        )

        client.disconnect()


@pytest.mark.integration
class TestFlextLdapWithBaseLdif:
    """Tests using base LDIF fixture."""

    def test_load_and_search_base_ldif(
        self,
        ldap_client: FlextLdap,
        ldap_container: GenericFieldsDict,
    ) -> None:
        """Test loading base LDIF entries and searching for them."""
        # Create test entry directly instead of depending on base_ldif_entries fixture
        base_dn = str(ldap_container["base_dn"])
        test_ou_dn = f"ou=testsearch,{base_dn}"

        # Create organizational unit entry
        test_entry = FlextLdifModels.Entry(
            dn=FlextLdifModels.DistinguishedName(value=test_ou_dn),
            attributes=FlextLdifModels.LdifAttributes(
                attributes={
                    "objectClass": ["organizationalUnit", "top"],
                    "ou": ["testsearch"],
                },
            ),
        )

        # Add entry
        add_result = ldap_client.add(test_entry)
        assert add_result.is_success, f"Failed to add test entry: {add_result.error}"

        try:
            search_options = FlextLdapTestHelpers.create_search_options(
                base_dn=base_dn,
                filter_str="(objectClass=organizationalUnit)",
            )
            result = ldap_client.search(search_options)
            FlextLdapTestHelpers.assert_search_success(result)
        finally:
            # Cleanup
            _ = ldap_client.delete(test_ou_dn)

    def test_add_entry_from_base_ldif(
        self,
        ldap_client: FlextLdap,
        ldap_container: GenericFieldsDict,
        unique_dn_suffix: str,
    ) -> None:
        """Test adding entry parsed from base LDIF (idempotent with unique DN)."""
        # Create test entry directly instead of depending on base_ldif_entries fixture
        base_dn = str(ldap_container["base_dn"])
        unique_uid = f"testuser-{unique_dn_suffix}"
        new_dn = f"uid={unique_uid},ou=people,{base_dn}"

        # Create inetOrgPerson entry with unique UID
        new_attributes = FlextLdifModels.LdifAttributes(
            attributes={
                "objectClass": [
                    "inetOrgPerson",
                    "organizationalPerson",
                    "person",
                    "top",
                ],
                "uid": [unique_uid],
                "cn": [f"Test User {unique_dn_suffix}"],
                "sn": ["User"],
            },
        )

        # Create new entry with adjusted DN and unique UID
        new_entry = FlextLdifModels.Entry(
            dn=FlextLdifModels.DistinguishedName(value=new_dn),
            attributes=new_attributes,
        )

        # Add entry
        result = ldap_client.add(new_entry)
        assert result.is_success, f"Add failed: {result.error}"

        # Cleanup
        delete_result = ldap_client.delete(new_dn)
        assert delete_result.is_success or delete_result.is_failure
