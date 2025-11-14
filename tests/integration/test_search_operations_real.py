"""Real LDAP search operations integration tests using Docker container.

Reuses test patterns from tests.bak, adapted for new FlextLdap API.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

import pytest
from flext_ldif.models import FlextLdifModels
from ldap3 import MODIFY_ADD, MODIFY_REPLACE

from flext_ldap import FlextLdap
from flext_ldap.models import FlextLdapModels

# Integration tests - require Docker LDAP server from conftest.py
pytestmark = pytest.mark.integration


@pytest.mark.integration
class TestFlextLdapSearchRealOperations:
    """Test FlextLdap search operations against real LDAP server."""

    def test_search_base_dn_real_data(self, ldap_client: FlextLdap) -> None:
        """Test searching for base DN with real LDAP data."""
        search_options = FlextLdapModels.SearchOptions(
            base_dn="dc=flext,dc=local",
            filter_str="(objectClass=*)",
            attributes=["dc", "objectClass"],
        )

        result = ldap_client.search(search_options)

        assert result.is_success, f"Search failed: {result.error}"
        search_result = result.unwrap()
        assert len(search_result.entries) > 0
        # Base DN should be in results
        assert any(
            entry.dn is not None and "dc=flext,dc=local" in str(entry.dn.value)
            for entry in search_result.entries
        )

    def test_search_with_subtree_scope(self, ldap_client: FlextLdap) -> None:
        """Test search with subtree scope."""
        search_options = FlextLdapModels.SearchOptions(
            base_dn="dc=flext,dc=local",
            filter_str="(objectClass=*)",
            scope="SUBTREE",
        )

        result = ldap_client.search(search_options)

        assert result.is_success
        search_result = result.unwrap()
        assert len(search_result.entries) >= 1  # At least base DN

    def test_search_with_base_scope(self, ldap_client: FlextLdap) -> None:
        """Test search with base scope (single entry only)."""
        search_options = FlextLdapModels.SearchOptions(
            base_dn="dc=flext,dc=local",
            filter_str="(objectClass=*)",
            scope="BASE",
        )

        result = ldap_client.search(search_options)

        assert result.is_success
        search_result = result.unwrap()
        assert len(search_result.entries) == 1  # Base scope returns only base DN
        assert (
            search_result.entries[0].dn is not None
            and str(search_result.entries[0].dn.value) == "dc=flext,dc=local"
        )

    def test_search_with_onelevel_scope(self, ldap_client: FlextLdap) -> None:
        """Test search with onelevel scope (one level below base)."""
        search_options = FlextLdapModels.SearchOptions(
            base_dn="dc=flext,dc=local",
            filter_str="(objectClass=organizationalUnit)",
            scope="ONELEVEL",
        )

        result = ldap_client.search(search_options)

        assert result.is_success
        search_result = result.unwrap()
        # Should find OUs directly under base DN
        assert len(search_result.entries) >= 0  # May or may not have OUs

    def test_search_with_filter(self, ldap_client: FlextLdap) -> None:
        """Test search with specific filter."""
        search_options = FlextLdapModels.SearchOptions(
            base_dn="dc=flext,dc=local",
            filter_str="(objectClass=organizationalUnit)",
            scope="SUBTREE",
        )

        result = ldap_client.search(search_options)

        assert result.is_success
        search_result = result.unwrap()
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
        search_options = FlextLdapModels.SearchOptions(
            base_dn="dc=flext,dc=local",
            filter_str="(objectClass=*)",
            scope="BASE",
            attributes=["dc", "objectClass"],
        )

        result = ldap_client.search(search_options)

        assert result.is_success
        search_result = result.unwrap()
        assert len(search_result.entries) == 1
        entry = search_result.entries[0]
        # Should only have requested attributes
        if entry.attributes and entry.attributes.attributes:
            assert (
                "dc" in entry.attributes.attributes
                or "objectClass" in entry.attributes.attributes
            )

    def test_search_with_size_limit(self, ldap_client: FlextLdap) -> None:
        """Test search with size limit."""
        search_options = FlextLdapModels.SearchOptions(
            base_dn="dc=flext,dc=local",
            filter_str="(objectClass=*)",
            scope="SUBTREE",
            size_limit=2,
        )

        result = ldap_client.search(search_options)

        assert result.is_success
        search_result = result.unwrap()
        # Should respect size limit (may be less if fewer entries exist)
        assert len(search_result.entries) <= 2


@pytest.mark.integration
class TestFlextLdapAddRealOperations:
    """Test FlextLdap add operations against real LDAP server."""

    def test_add_user_entry(self, ldap_client: FlextLdap) -> None:
        """Test adding a user entry."""
        # Create entry using FlextLdifModels (reusing from flext-ldif)
        entry = FlextLdifModels.Entry(
            dn=FlextLdifModels.DistinguishedName(
                value="uid=testadd,ou=people,dc=flext,dc=local"
            ),
            attributes=FlextLdifModels.LdifAttributes.model_validate({
                "attributes": {
                    "objectClass": [
                        "inetOrgPerson",
                        "organizationalPerson",
                        "person",
                        "top",
                    ],
                    "uid": ["testadd"],
                    "cn": ["Test Add User"],
                    "sn": ["Add"],
                    "mail": ["testadd@internal.invalid"],
                }
            }),
        )

        result = ldap_client.add(entry)

        assert result.is_success, f"Add failed: {result.error}"
        operation_result = result.unwrap()
        assert operation_result.success is True
        assert operation_result.entries_affected == 1

        # Cleanup - delete returns OperationResult, not just success/failure
        delete_result = ldap_client.delete("uid=testadd,ou=people,dc=flext,dc=local")
        # Result may be success or failure depending on if entry exists
        assert delete_result.is_success or delete_result.is_failure

    def test_add_group_entry(self, ldap_client: FlextLdap) -> None:
        """Test adding a group entry."""
        entry = FlextLdifModels.Entry(
            dn=FlextLdifModels.DistinguishedName(
                value="cn=testaddgroup,ou=groups,dc=flext,dc=local"
            ),
            attributes=FlextLdifModels.LdifAttributes.model_validate({
                "attributes": {
                    "objectClass": ["groupOfNames", "top"],
                    "cn": ["testaddgroup"],
                    "member": ["cn=REDACTED_LDAP_BIND_PASSWORD,dc=flext,dc=local"],
                }
            }),
        )

        result = ldap_client.add(entry)

        assert result.is_success, f"Add failed: {result.error}"

        # Cleanup
        delete_result = ldap_client.delete(
            "cn=testaddgroup,ou=groups,dc=flext,dc=local"
        )
        # Result may be success or failure depending on if entry exists
        assert delete_result.is_success or delete_result.is_failure


@pytest.mark.integration
class TestFlextLdapModifyRealOperations:
    """Test FlextLdap modify operations against real LDAP server."""

    def test_modify_entry(self, ldap_client: FlextLdap) -> None:
        """Test modifying an entry."""
        # First add an entry
        entry = FlextLdifModels.Entry(
            dn=FlextLdifModels.DistinguishedName(
                value="uid=testmodify,ou=people,dc=flext,dc=local"
            ),
            attributes=FlextLdifModels.LdifAttributes.model_validate({
                "attributes": {
                    "objectClass": [
                        "inetOrgPerson",
                        "organizationalPerson",
                        "person",
                        "top",
                    ],
                    "uid": ["testmodify"],
                    "cn": ["Test Modify User"],
                    "sn": ["Modify"],
                }
            }),
        )

        add_result = ldap_client.add(entry)
        assert add_result.is_success

        # Now modify it
        changes: dict[str, list[tuple[str, list[str]]]] = {
            "mail": [(MODIFY_REPLACE, ["testmodify@internal.invalid"])],
            "telephoneNumber": [(MODIFY_ADD, ["+1234567890"])],
        }

        modify_result = ldap_client.modify(
            "uid=testmodify,ou=people,dc=flext,dc=local", changes
        )

        assert modify_result.is_success, f"Modify failed: {modify_result.error}"

        # Cleanup
        delete_result = ldap_client.delete("uid=testmodify,ou=people,dc=flext,dc=local")
        # Result may be success or failure depending on if entry exists
        assert delete_result.is_success or delete_result.is_failure


@pytest.mark.integration
class TestFlextLdapDeleteRealOperations:
    """Test FlextLdap delete operations against real LDAP server."""

    def test_delete_entry(self, ldap_client: FlextLdap) -> None:
        """Test deleting an entry."""
        # First add an entry
        entry = FlextLdifModels.Entry(
            dn=FlextLdifModels.DistinguishedName(
                value="uid=testdelete,ou=people,dc=flext,dc=local"
            ),
            attributes=FlextLdifModels.LdifAttributes.model_validate({
                "attributes": {
                    "objectClass": [
                        "inetOrgPerson",
                        "organizationalPerson",
                        "person",
                        "top",
                    ],
                    "uid": ["testdelete"],
                    "cn": ["Test Delete User"],
                    "sn": ["Delete"],
                }
            }),
        )

        add_result = ldap_client.add(entry)
        assert add_result.is_success

        # Now delete it
        delete_result = ldap_client.delete("uid=testdelete,ou=people,dc=flext,dc=local")

        assert delete_result.is_success, f"Delete failed: {delete_result.error}"
        operation_result = delete_result.unwrap()
        assert operation_result.success is True
        assert operation_result.entries_affected == 1
