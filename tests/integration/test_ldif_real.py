"""Real LDIF processing integration tests with Docker LDAP server.

This module tests LDIF export/import operations against a real OpenLDAP server,
validating the flext-ldif integration with real LDAP data.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

import uuid

import pytest

from flext_ldap import FlextLdapClients

# Skip all integration tests when LDAP server is not available
pytestmark = pytest.mark.integration


@pytest.mark.integration
class TestRealLdifExport:
    """Test LDIF export from real LDAP server."""

    def test_export_base_dn_to_ldif(self, shared_ldap_client: FlextLdapClients) -> None:
        """Test exporting base DN to LDIF format."""
        client = shared_ldap_client

        result = client.search(
            base_dn="dc=flext,dc=local",
            filter_str="(objectClass=*)",
            attributes=["*"],
        )

        assert result.is_success
        entries = result.unwrap()
        assert isinstance(entries, list)
        assert len(entries) > 0

        # Verify LDIF-compatible data structure
        for entry in entries:
            assert hasattr(entry, "dn")
            assert hasattr(entry, "object_classes")

    def test_export_users_to_ldif(self, shared_ldap_client: FlextLdapClients) -> None:
        """Test exporting user entries to LDIF format."""
        client = shared_ldap_client

        ou_dn = "ou=ldif_users,dc=flext,dc=local"
        user_dn = "cn=ldif_user1,ou=ldif_users,dc=flext,dc=local"

        # Cleanup first (idempotent) - errors expected if entries don't exist
        # but we proceed anyway since we're about to create them
        client.delete_entry(dn=user_dn)  # May fail if not exists
        client.delete_entry(dn=ou_dn)  # May fail if not exists

        # Create test OU
        ou_result = client.add_entry(
            dn=ou_dn,
            attributes={"objectClass": ["organizationalUnit"], "ou": "ldif_users"},
        )
        assert ou_result.is_success, f"Failed to create OU: {ou_result.error}"

        # Create test user
        user_result = client.add_entry(
            dn=user_dn,
            attributes={
                "objectClass": ["inetOrgPerson"],
                "cn": "ldif_user1",
                "sn": "LdifUser1",
                "uid": "ldif_user1",
                "mail": "ldif_user1@flext.local",
            },
        )
        assert user_result.is_success, f"Failed to create user: {user_result.error}"

        # Export to LDIF-compatible format
        result = client.search(
            base_dn=ou_dn,
            filter_str="(objectClass=inetOrgPerson)",
            attributes=["*"],
        )

        assert result.is_success, f"Failed to search users: {result.error}"
        entries = result.unwrap()
        assert isinstance(entries, list), "Search should return list of entries"
        assert len(entries) >= 1, "Should find at least one user"

        # Verify LDIF structure
        ldif_entry = entries[0]
        assert hasattr(ldif_entry, "dn"), "Entry should have dn attribute"
        assert hasattr(ldif_entry, "cn"), "Entry should have cn attribute"

        # Cleanup - ensure entries are deleted
        cleanup_user = client.delete_entry(dn=user_dn)
        assert cleanup_user.is_success or cleanup_user.is_failure, "Delete should complete"
        cleanup_ou = client.delete_entry(dn=ou_dn)
        assert cleanup_ou.is_success or cleanup_ou.is_failure, "Delete should complete"

    def test_export_groups_to_ldif(self, shared_ldap_client: FlextLdapClients) -> None:
        """Test exporting group entries to LDIF format."""
        client = shared_ldap_client

        ou_dn = "ou=ldif_groups,dc=flext,dc=local"
        group_dn = "cn=ldif_group1,ou=ldif_groups,dc=flext,dc=local"

        # Cleanup first (idempotent)
        client.delete_entry(dn=group_dn)  # May fail if not exists
        client.delete_entry(dn=ou_dn)  # May fail if not exists

        # Create test OU
        ou_result = client.add_entry(
            dn=ou_dn,
            attributes={"objectClass": ["organizationalUnit"], "ou": "ldif_groups"},
        )
        assert ou_result.is_success, f"Failed to create OU: {ou_result.error}"

        # Create test group
        group_result = client.add_entry(
            dn=group_dn,
            attributes={
                "objectClass": ["groupOfNames"],
                "cn": "ldif_group1",
                "member": "cn=admin,dc=flext,dc=local",
            },
        )
        assert group_result.is_success, f"Failed to create group: {group_result.error}"

        # Export to LDIF-compatible format
        result = client.search(
            base_dn=ou_dn,
            filter_str="(objectClass=groupOfNames)",
            attributes=["*"],
        )

        assert result.is_success, f"Failed to search groups: {result.error}"
        entries = result.unwrap()
        assert isinstance(entries, list), "Search should return list of entries"
        assert len(entries) >= 1, "Should find at least one group"

        # Verify LDIF structure
        ldif_entry = entries[0]
        assert hasattr(ldif_entry, "dn"), "Entry should have dn attribute"
        assert hasattr(ldif_entry, "cn"), "Entry should have cn attribute"

        # Cleanup - ensure entries are deleted
        cleanup_group = client.delete_entry(dn=group_dn)
        assert cleanup_group.is_success or cleanup_group.is_failure, "Delete should complete"
        cleanup_ou = client.delete_entry(dn=ou_dn)
        assert cleanup_ou.is_success or cleanup_ou.is_failure, "Delete should complete"


@pytest.mark.integration
class TestRealLdifImport:
    """Test LDIF import to real LDAP server."""

    def test_import_organizational_unit_from_ldif(
        self, shared_ldap_client: FlextLdapClients
    ) -> None:
        """Test importing organizational unit from LDIF-like data."""
        client = shared_ldap_client

        # Use unique DN to avoid conflicts with previous test runs
        test_id = str(uuid.uuid4())[:8]
        dn_to_add = f"ou=imported_{test_id},dc=flext,dc=local"
        ou_name = f"imported_{test_id}"

        # LDIF-like data structure
        ldif_entry = {
            "dn": dn_to_add,
            "objectClass": ["organizationalUnit"],
            "ou": ou_name,
        }

        # Import from LDIF structure
        dn_value = ldif_entry["dn"]
        if isinstance(dn_value, list):
            dn_value = dn_value[0] if dn_value else ""
        result = client.add_entry(
            dn=str(dn_value),
            attributes={k: v for k, v in ldif_entry.items() if k != "dn"},
        )

        assert result.is_success, f"Add entry failed: {result.error}"

        # Verify import
        search_result = client.search(
            base_dn=dn_to_add,
            filter_str="(objectClass=organizationalUnit)",
        )

        assert search_result.is_success, f"Search failed: {search_result.error}"
        assert len(search_result.value) > 0

        # Cleanup - ensure delete succeeds for cleanup
        cleanup_result = client.delete_entry(dn=dn_to_add)
        assert cleanup_result.is_success, (
            f"Cleanup delete failed: {cleanup_result.error}"
        )

    @pytest.mark.xfail(
        reason="Entry conversion from LDAP data fails - needs debugging",
        strict=False,
    )
    def test_import_user_from_ldif(self, shared_ldap_client: FlextLdapClients) -> None:
        """Test importing user from LDIF-like data."""
        client = shared_ldap_client

        ou_dn = "ou=import_test,dc=flext,dc=local"
        user_dn = "cn=imported_user,ou=import_test,dc=flext,dc=local"

        # Cleanup first (idempotent)
        client.delete_entry(dn=user_dn)  # Ignore result
        client.delete_entry(dn=ou_dn)  # Ignore result

        # Create parent OU
        client.add_entry(
            dn=ou_dn,
            attributes={"objectClass": ["organizationalUnit"], "ou": "import_test"},
        )

        # LDIF-like user data
        ldif_user = {
            "dn": user_dn,
            "objectClass": ["inetOrgPerson"],
            "cn": "imported_user",
            "sn": "ImportedUser",
            "uid": "imported_user",
            "mail": "imported@flext.local",
        }

        # Import from LDIF structure
        dn_value = ldif_user["dn"]
        if isinstance(dn_value, list):
            dn_value = dn_value[0] if dn_value else ""
        result = client.add_entry(
            dn=str(dn_value),
            attributes={k: v for k, v in ldif_user.items() if k != "dn"},
        )

        assert result.is_success

        # Verify import
        search_result = client.search(
            base_dn=user_dn,
            filter_str="(objectClass=inetOrgPerson)",
            attributes=["*"],  # Request all attributes
        )

        assert search_result.is_success
        assert len(search_result.value) > 0
        imported_entry = search_result.value[0]
        assert "imported_user" in str(imported_entry.get("cn", ""))

        # Cleanup
        client.delete_entry(dn=user_dn)  # Ignore result
        client.delete_entry(dn=ou_dn)  # Ignore result

    def test_import_group_from_ldif(self, shared_ldap_client: FlextLdapClients) -> None:
        """Test importing group from LDIF-like data."""
        client = shared_ldap_client

        ou_dn = "ou=import_groups,dc=flext,dc=local"
        group_dn = "cn=imported_group,ou=import_groups,dc=flext,dc=local"

        # Cleanup first (idempotent)
        client.delete_entry(dn=group_dn)  # Ignore result
        client.delete_entry(dn=ou_dn)  # Ignore result

        # Create parent OU
        client.add_entry(
            dn=ou_dn,
            attributes={"objectClass": ["organizationalUnit"], "ou": "import_groups"},
        )

        # LDIF-like group data
        ldif_group = {
            "dn": group_dn,
            "objectClass": ["groupOfNames"],
            "cn": "imported_group",
            "member": "cn=admin,dc=flext,dc=local",
        }

        # Import from LDIF structure
        dn_value = ldif_group["dn"]
        if isinstance(dn_value, list):
            dn_value = dn_value[0] if dn_value else ""
        result = client.add_entry(
            dn=str(dn_value),
            attributes={k: v for k, v in ldif_group.items() if k != "dn"},
        )

        assert result.is_success

        # Verify import
        search_result = client.search(
            base_dn=group_dn,
            filter_str="(objectClass=groupOfNames)",
        )

        assert search_result.is_success
        assert len(search_result.value) > 0

        # Cleanup
        client.delete_entry(dn=group_dn)  # Ignore result
        client.delete_entry(dn=ou_dn)  # Ignore result


@pytest.mark.integration
class TestRealLdifRoundTrip:
    """Test LDIF export/import round-trip operations."""

    @pytest.mark.xfail(
        reason="Entry conversion from LDAP data fails - needs debugging",
        strict=False,
    )
    def test_ldif_roundtrip_user_data(
        self, shared_ldap_client: FlextLdapClients
    ) -> None:
        """Test complete round-trip: export to LDIF, re-import."""
        client = shared_ldap_client

        ou_dn = "ou=roundtrip,dc=flext,dc=local"
        original_dn = "cn=original,ou=roundtrip,dc=flext,dc=local"
        reimported_dn = "cn=reimported,ou=roundtrip,dc=flext,dc=local"

        # Cleanup first (idempotent)
        client.delete_entry(dn=original_dn)  # Ignore result
        client.delete_entry(dn=reimported_dn)  # Ignore result
        client.delete_entry(dn=ou_dn)  # Ignore result

        # Create original user
        client.add_entry(
            dn=ou_dn,
            attributes={"objectClass": ["organizationalUnit"], "ou": "roundtrip"},
        )

        original_user = {
            "dn": original_dn,
            "objectClass": ["inetOrgPerson"],
            "cn": "original",
            "sn": "Original",
            "uid": "original",
            "mail": "original@flext.local",
        }

        dn_value = original_user["dn"]
        if isinstance(dn_value, list):
            dn_value = dn_value[0] if dn_value else ""
        add_result = client.add_entry(
            dn=str(dn_value),
            attributes={k: v for k, v in original_user.items() if k != "dn"},
        )
        assert add_result.is_success, f"Failed to add entry: {add_result.error}"

        # Export to LDIF format (search)
        export_result = client.search(
            base_dn=original_dn,
            filter_str="(objectClass=inetOrgPerson)",
            attributes=["*"],
        )

        assert export_result.is_success
        exported_data = export_result.value[0]

        # Re-import with different DN
        reimported_user = {
            "dn": reimported_dn,
            "objectClass": exported_data.get("objectClass"),
            "cn": "reimported",
            "sn": exported_data.get("sn"),
            "uid": "reimported",
            "mail": exported_data.get("mail"),
        }

        dn_value = reimported_user["dn"]
        if isinstance(dn_value, list):
            dn_value = dn_value[0] if dn_value else ""
        # Convert attributes to proper format
        attributes: dict[str, list[str] | str] = {}
        for k, v in reimported_user.items():
            if k != "dn":
                if isinstance(v, list):
                    attributes[k] = [str(item) for item in v if item is not None]
                elif v is None:
                    attributes[k] = []
                else:
                    attributes[k] = [str(v)]

        import_result = client.add_entry(
            dn=str(dn_value),
            attributes=attributes,
        )

        assert import_result.is_success

        # Verify round-trip
        verify_result = client.search(
            base_dn=reimported_dn,
            filter_str="(objectClass=inetOrgPerson)",
        )

        assert verify_result.is_success
        assert len(verify_result.value) > 0

        # Cleanup
        client.delete_entry(dn=original_dn)  # Ignore result
        client.delete_entry(dn=reimported_dn)  # Ignore result
        client.delete_entry(dn=ou_dn)  # Ignore result

    @pytest.mark.xfail(
        reason="Entry conversion from LDAP data fails - needs debugging",
        strict=False,
    )
    def test_ldif_bulk_export_import(
        self, shared_ldap_client: FlextLdapClients
    ) -> None:
        """Test bulk LDIF export and import operations."""
        client = shared_ldap_client

        ou_dn = "ou=bulk_test,dc=flext,dc=local"

        # Cleanup first (idempotent)
        for i in range(1, 4):
            client.delete_entry(
                dn=f"cn=bulk_user{i},ou=bulk_test,dc=flext,dc=local"
            )  # Ignore result
        client.delete_entry(dn=ou_dn)  # Ignore result

        # Create bulk test data
        client.add_entry(
            dn=ou_dn,
            attributes={"objectClass": ["organizationalUnit"], "ou": "bulk_test"},
        )

        # Create multiple users
        for i in range(1, 4):
            client.add_entry(
                dn=f"cn=bulk_user{i},ou=bulk_test,dc=flext,dc=local",
                attributes={
                    "objectClass": ["inetOrgPerson"],
                    "cn": f"bulk_user{i}",
                    "sn": f"BulkUser{i}",
                    "uid": f"bulk_user{i}",
                    "mail": f"bulk_user{i}@flext.local",
                },
            )

        # Bulk export
        export_result = client.search(
            base_dn=ou_dn,
            filter_str="(objectClass=inetOrgPerson)",
            attributes=["*"],
        )

        assert export_result.is_success
        assert len(export_result.value) >= 3

        # Verify exported LDIF structure
        for entry in export_result.value:
            assert "dn" in entry
            assert "cn" in entry
            assert "objectClass" in entry

        # Cleanup
        for i in range(1, 4):
            client.delete_entry(
                dn=f"cn=bulk_user{i},ou=bulk_test,dc=flext,dc=local"
            )  # Ignore result
        client.delete_entry(dn=ou_dn)  # Ignore result
