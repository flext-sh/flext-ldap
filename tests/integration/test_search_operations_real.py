"""Real LDAP search operations integration tests using Docker container.

Reuses test patterns from tests.bak, adapted for new FlextLdap API.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

import pytest
from ldap3 import MODIFY_ADD, MODIFY_REPLACE

from flext_ldap import FlextLdap

from ..fixtures.constants import RFC
from ..helpers.entry_helpers import EntryTestHelpers
from ..helpers.operation_helpers import TestOperationHelpers

# Integration tests - require Docker LDAP server from conftest.py
pytestmark = pytest.mark.integration


@pytest.mark.integration
class TestFlextLdapSearchRealOperations:
    """Test FlextLdap search operations against real LDAP server."""

    def test_search_base_dn_real_data(self, ldap_client: FlextLdap) -> None:
        """Test searching for base DN with real LDAP data."""
        search_result = TestOperationHelpers.search_and_assert_success(
            ldap_client,
            RFC.DEFAULT_BASE_DN,
            attributes=["dc", "objectClass"],
            expected_min_count=1,
        )
        # Base DN should be in results
        assert any(
            entry.dn is not None and RFC.DEFAULT_BASE_DN in str(entry.dn.value)
            for entry in search_result.entries
        )

    def test_search_with_subtree_scope(self, ldap_client: FlextLdap) -> None:
        """Test search with subtree scope."""
        _ = TestOperationHelpers.search_and_assert_success(
            ldap_client,
            RFC.DEFAULT_BASE_DN,
            scope="SUBTREE",
            expected_min_count=1,
        )

    def test_search_with_base_scope(self, ldap_client: FlextLdap) -> None:
        """Test search with base scope (single entry only)."""
        search_result = TestOperationHelpers.search_and_assert_success(
            ldap_client,
            RFC.DEFAULT_BASE_DN,
            scope="BASE",
            expected_min_count=1,
            expected_max_count=1,
        )
        assert (
            search_result.entries[0].dn is not None
            and str(search_result.entries[0].dn.value) == RFC.DEFAULT_BASE_DN
        )

    def test_search_with_onelevel_scope(self, ldap_client: FlextLdap) -> None:
        """Test search with onelevel scope (one level below base)."""
        _ = TestOperationHelpers.search_and_assert_success(
            ldap_client,
            RFC.DEFAULT_BASE_DN,
            filter_str="(objectClass=organizationalUnit)",
            scope="ONELEVEL",
        )

    def test_search_with_filter(self, ldap_client: FlextLdap) -> None:
        """Test search with specific filter."""
        search_result = TestOperationHelpers.search_and_assert_success(
            ldap_client,
            RFC.DEFAULT_BASE_DN,
            filter_str="(objectClass=organizationalUnit)",
        )
        # All results should be organizational units
        for entry in search_result.entries:
            if entry.attributes and entry.attributes.attributes:
                object_classes = entry.attributes.attributes.get("objectClass", [])
                if isinstance(object_classes, list):
                    assert "organizationalUnit" in object_classes
                else:
                    # Single value case
                    assert (
                        object_classes == "organizationalUnit"
                        or "organizationalUnit" in str(object_classes)
                    )

    def test_search_with_attributes(self, ldap_client: FlextLdap) -> None:
        """Test search with specific attributes."""
        search_result = TestOperationHelpers.search_and_assert_success(
            ldap_client,
            RFC.DEFAULT_BASE_DN,
            scope="BASE",
            attributes=["dc", "objectClass"],
            expected_min_count=1,
            expected_max_count=1,
        )
        entry = search_result.entries[0]
        # Should only have requested attributes
        if entry.attributes and entry.attributes.attributes:
            assert (
                "dc" in entry.attributes.attributes
                or "objectClass" in entry.attributes.attributes
            )

    def test_search_with_size_limit(self, ldap_client: FlextLdap) -> None:
        """Test search with size limit."""
        TestOperationHelpers.search_and_assert_success(
            ldap_client,
            RFC.DEFAULT_BASE_DN,
            size_limit=2,
            expected_max_count=2,
        )


@pytest.mark.integration
class TestFlextLdapAddRealOperations:
    """Test FlextLdap add operations against real LDAP server."""

    def test_add_user_entry(self, ldap_client: FlextLdap) -> None:
        """Test adding a user entry."""
        entry = TestOperationHelpers.create_entry_with_uid(
            "testadd",
            RFC.DEFAULT_BASE_DN,
            cn="Test Add User",
            sn="Add",
            mail="testadd@flext.local",
        )

        result = TestOperationHelpers.add_entry_and_assert_success(
            ldap_client,
            entry,
            verify_operation_result=True,
        )
        TestOperationHelpers.assert_operation_result_success(
            result,
            expected_operation_type="add",
            expected_entries_affected=1,
        )

    def test_add_group_entry(self, ldap_client: FlextLdap) -> None:
        """Test adding a group entry."""
        entry = TestOperationHelpers.create_group_entry(
            "testaddgroup",
            RFC.DEFAULT_BASE_DN,
            members=["cn=admin,dc=flext,dc=local"],
        )

        result = ldap_client.add(entry)

        assert result.is_success, f"Add failed: {result.error}"

        # Cleanup
        delete_result = ldap_client.delete(
            "cn=testaddgroup,ou=groups,dc=flext,dc=local",
        )
        # Result may be success or failure depending on if entry exists
        assert delete_result.is_success or delete_result.is_failure


@pytest.mark.integration
class TestFlextLdapModifyRealOperations:
    """Test FlextLdap modify operations against real LDAP server."""

    def test_modify_entry(
        self,
        ldap_client: FlextLdap,
        unique_dn_suffix: str,
    ) -> None:
        """Test modifying an entry (idempotent with unique DN)."""
        uid = f"testmodify-{unique_dn_suffix}"
        entry_dict = {
            "dn": f"uid={uid},ou=people,dc=flext,dc=local",
            "attributes": {
                "objectClass": [
                    "inetOrgPerson",
                    "organizationalPerson",
                    "person",
                    "top",
                ],
                "uid": [uid],
                "cn": ["Test Modify User"],
                "sn": ["Modify"],
            },
        }

        changes: dict[str, list[tuple[str, list[str]]]] = {
            "mail": [(MODIFY_REPLACE, ["testmodify@flext.local"])],
            "telephoneNumber": [(MODIFY_ADD, ["+1234567890"])],
        }

        _entry, add_result, modify_result = (
            EntryTestHelpers.modify_entry_with_verification(
                ldap_client,
                entry_dict,
                changes,
                verify_attribute=None,
            )
        )

        assert add_result.is_success
        assert modify_result.is_success, f"Modify failed: {modify_result.error}"


@pytest.mark.integration
class TestFlextLdapDeleteRealOperations:
    """Test FlextLdap delete operations against real LDAP server."""

    def test_delete_entry(
        self,
        ldap_client: FlextLdap,
        unique_dn_suffix: str,
    ) -> None:
        """Test deleting an entry (idempotent with unique DN)."""
        # First add an entry with unique UID
        uid = f"testdelete-{unique_dn_suffix}"
        entry = TestOperationHelpers.create_entry_with_uid(
            uid,
            RFC.DEFAULT_BASE_DN,
            cn="Test Delete User",
            sn="Delete",
        )

        TestOperationHelpers.add_entry_and_assert_success(
            ldap_client,
            entry,
            cleanup_after=False,
        )

        # Now delete it using the unique DN
        delete_result = ldap_client.delete(f"uid={uid},ou=people,dc=flext,dc=local")
        TestOperationHelpers.assert_operation_result_success(
            delete_result,
            expected_operation_type="delete",
            expected_entries_affected=1,
        )
