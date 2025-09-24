"""Real LDIF processing integration tests with Docker LDAP server.

This module tests LDIF export/import operations against a real OpenLDAP server,
validating the flext-ldif integration with real LDAP data.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import pytest

from flext_ldap import FlextLdapClient


@pytest.mark.integration
@pytest.mark.asyncio
class TestRealLdifExport:
    """Test LDIF export from real LDAP server."""

    async def test_export_base_dn_to_ldif(
        self, shared_ldap_client: FlextLdapClient
    ) -> None:
        """Test exporting base DN to LDIF format."""
        client = shared_ldap_client

        result = await client.search(
            base_dn="dc=flext,dc=local",
            filter_str="(objectClass=*)",
            attributes=["*"],
        )

        assert result.is_success
        assert len(result.value) > 0

        # Verify LDIF-compatible data structure
        for entry in result.value:
            assert "dn" in entry
            assert "objectClass" in entry

    async def test_export_users_to_ldif(
        self, shared_ldap_client: FlextLdapClient
    ) -> None:
        """Test exporting user entries to LDIF format."""
        client = shared_ldap_client

        # Create test OU and users
        await client.add_entry_universal(
            dn="ou=ldif_users,dc=flext,dc=local",
            attributes={"objectClass": ["organizationalUnit"], "ou": "ldif_users"},
        )

        await client.add_entry_universal(
            dn="cn=ldif_user1,ou=ldif_users,dc=flext,dc=local",
            attributes={
                "objectClass": ["inetOrgPerson"],
                "cn": "ldif_user1",
                "sn": "LdifUser1",
                "uid": "ldif_user1",
                "mail": "ldif_user1@flext.local",
            },
        )

        # Export to LDIF-compatible format
        result = await client.search(
            base_dn="ou=ldif_users,dc=flext,dc=local",
            filter_str="(objectClass=inetOrgPerson)",
            attributes=["*"],
        )

        assert result.is_success
        assert len(result.value) >= 1

        # Verify LDIF structure
        ldif_entry = result.value[0]
        assert "dn" in ldif_entry
        assert "cn" in ldif_entry
        assert "sn" in ldif_entry
        assert "objectClass" in ldif_entry

        # Cleanup
        await client.delete_entry_universal(
            dn="cn=ldif_user1,ou=ldif_users,dc=flext,dc=local"
        )
        await client.delete_entry_universal(dn="ou=ldif_users,dc=flext,dc=local")

    async def test_export_groups_to_ldif(
        self, shared_ldap_client: FlextLdapClient
    ) -> None:
        """Test exporting group entries to LDIF format."""
        client = shared_ldap_client

        # Create test OU and group
        await client.add_entry_universal(
            dn="ou=ldif_groups,dc=flext,dc=local",
            attributes={"objectClass": ["organizationalUnit"], "ou": "ldif_groups"},
        )

        await client.add_entry_universal(
            dn="cn=ldif_group1,ou=ldif_groups,dc=flext,dc=local",
            attributes={
                "objectClass": ["groupOfNames"],
                "cn": "ldif_group1",
                "member": "cn=admin,dc=flext,dc=local",
            },
        )

        # Export to LDIF-compatible format
        result = await client.search(
            base_dn="ou=ldif_groups,dc=flext,dc=local",
            filter_str="(objectClass=groupOfNames)",
            attributes=["*"],
        )

        assert result.is_success
        assert len(result.value) >= 1

        # Verify LDIF structure
        ldif_entry = result.value[0]
        assert "dn" in ldif_entry
        assert "cn" in ldif_entry
        assert "member" in ldif_entry
        assert "objectClass" in ldif_entry

        # Cleanup
        await client.delete_entry_universal(
            dn="cn=ldif_group1,ou=ldif_groups,dc=flext,dc=local"
        )
        await client.delete_entry_universal(dn="ou=ldif_groups,dc=flext,dc=local")


@pytest.mark.integration
@pytest.mark.asyncio
class TestRealLdifImport:
    """Test LDIF import to real LDAP server."""

    async def test_import_organizational_unit_from_ldif(
        self, shared_ldap_client: FlextLdapClient
    ) -> None:
        """Test importing organizational unit from LDIF-like data."""
        client = shared_ldap_client

        # LDIF-like data structure
        ldif_entry = {
            "dn": "ou=imported,dc=flext,dc=local",
            "objectClass": ["organizationalUnit"],
            "ou": "imported",
        }

        # Import from LDIF structure
        result = await client.add_entry_universal(
            dn=ldif_entry["dn"],
            attributes={k: v for k, v in ldif_entry.items() if k != "dn"},
        )

        assert result.is_success

        # Verify import
        search_result = await client.search(
            base_dn="ou=imported,dc=flext,dc=local",
            filter_str="(objectClass=organizationalUnit)",
        )

        assert search_result.is_success
        assert len(search_result.value) > 0

        # Cleanup
        await client.delete_entry_universal(dn="ou=imported,dc=flext,dc=local")

    async def test_import_user_from_ldif(
        self, shared_ldap_client: FlextLdapClient
    ) -> None:
        """Test importing user from LDIF-like data."""
        client = shared_ldap_client

        # Create parent OU
        await client.add_entry_universal(
            dn="ou=import_test,dc=flext,dc=local",
            attributes={"objectClass": ["organizationalUnit"], "ou": "import_test"},
        )

        # LDIF-like user data
        ldif_user = {
            "dn": "cn=imported_user,ou=import_test,dc=flext,dc=local",
            "objectClass": ["inetOrgPerson"],
            "cn": "imported_user",
            "sn": "ImportedUser",
            "uid": "imported_user",
            "mail": "imported@flext.local",
        }

        # Import from LDIF structure
        result = await client.add_entry_universal(
            dn=ldif_user["dn"],
            attributes={k: v for k, v in ldif_user.items() if k != "dn"},
        )

        assert result.is_success

        # Verify import
        search_result = await client.search(
            base_dn="cn=imported_user,ou=import_test,dc=flext,dc=local",
            filter_str="(objectClass=inetOrgPerson)",
            attributes=["*"],  # Request all attributes
        )

        assert search_result.is_success
        assert len(search_result.value) > 0
        imported_entry = search_result.value[0]
        assert "imported_user" in str(imported_entry.get("cn", ""))

        # Cleanup
        await client.delete_entry_universal(
            dn="cn=imported_user,ou=import_test,dc=flext,dc=local"
        )
        await client.delete_entry_universal(dn="ou=import_test,dc=flext,dc=local")

    async def test_import_group_from_ldif(
        self, shared_ldap_client: FlextLdapClient
    ) -> None:
        """Test importing group from LDIF-like data."""
        client = shared_ldap_client

        # Create parent OU
        await client.add_entry_universal(
            dn="ou=import_groups,dc=flext,dc=local",
            attributes={"objectClass": ["organizationalUnit"], "ou": "import_groups"},
        )

        # LDIF-like group data
        ldif_group = {
            "dn": "cn=imported_group,ou=import_groups,dc=flext,dc=local",
            "objectClass": ["groupOfNames"],
            "cn": "imported_group",
            "member": "cn=admin,dc=flext,dc=local",
        }

        # Import from LDIF structure
        result = await client.add_entry_universal(
            dn=ldif_group["dn"],
            attributes={k: v for k, v in ldif_group.items() if k != "dn"},
        )

        assert result.is_success

        # Verify import
        search_result = await client.search(
            base_dn="cn=imported_group,ou=import_groups,dc=flext,dc=local",
            filter_str="(objectClass=groupOfNames)",
        )

        assert search_result.is_success
        assert len(search_result.value) > 0

        # Cleanup
        await client.delete_entry_universal(
            dn="cn=imported_group,ou=import_groups,dc=flext,dc=local"
        )
        await client.delete_entry_universal(dn="ou=import_groups,dc=flext,dc=local")


@pytest.mark.integration
@pytest.mark.asyncio
class TestRealLdifRoundTrip:
    """Test LDIF export/import round-trip operations."""

    async def test_ldif_roundtrip_user_data(
        self, shared_ldap_client: FlextLdapClient
    ) -> None:
        """Test complete round-trip: export to LDIF, re-import."""
        client = shared_ldap_client

        # Create original user
        await client.add_entry_universal(
            dn="ou=roundtrip,dc=flext,dc=local",
            attributes={"objectClass": ["organizationalUnit"], "ou": "roundtrip"},
        )

        original_user = {
            "dn": "cn=original,ou=roundtrip,dc=flext,dc=local",
            "objectClass": ["inetOrgPerson"],
            "cn": "original",
            "sn": "Original",
            "uid": "original",
            "mail": "original@flext.local",
        }

        await client.add_entry_universal(
            dn=original_user["dn"],
            attributes={k: v for k, v in original_user.items() if k != "dn"},
        )

        # Export to LDIF format (search)
        export_result = await client.search(
            base_dn="cn=original,ou=roundtrip,dc=flext,dc=local",
            filter_str="(objectClass=inetOrgPerson)",
            attributes=["*"],
        )

        assert export_result.is_success
        exported_data = export_result.value[0]

        # Re-import with different DN
        reimported_user = {
            "dn": "cn=reimported,ou=roundtrip,dc=flext,dc=local",
            "objectClass": exported_data.get("objectClass"),
            "cn": "reimported",
            "sn": exported_data.get("sn"),
            "uid": "reimported",
            "mail": exported_data.get("mail"),
        }

        import_result = await client.add_entry_universal(
            dn=reimported_user["dn"],
            attributes={k: v for k, v in reimported_user.items() if k != "dn"},
        )

        assert import_result.is_success

        # Verify round-trip
        verify_result = await client.search(
            base_dn="cn=reimported,ou=roundtrip,dc=flext,dc=local",
            filter_str="(objectClass=inetOrgPerson)",
        )

        assert verify_result.is_success
        assert len(verify_result.value) > 0

        # Cleanup
        await client.delete_entry_universal(
            dn="cn=original,ou=roundtrip,dc=flext,dc=local"
        )
        await client.delete_entry_universal(
            dn="cn=reimported,ou=roundtrip,dc=flext,dc=local"
        )
        await client.delete_entry_universal(dn="ou=roundtrip,dc=flext,dc=local")

    async def test_ldif_bulk_export_import(
        self, shared_ldap_client: FlextLdapClient
    ) -> None:
        """Test bulk LDIF export and import operations."""
        client = shared_ldap_client

        # Create bulk test data
        await client.add_entry_universal(
            dn="ou=bulk_test,dc=flext,dc=local",
            attributes={"objectClass": ["organizationalUnit"], "ou": "bulk_test"},
        )

        # Create multiple users
        for i in range(1, 4):
            await client.add_entry_universal(
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
        export_result = await client.search(
            base_dn="ou=bulk_test,dc=flext,dc=local",
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
            await client.delete_entry_universal(
                dn=f"cn=bulk_user{i},ou=bulk_test,dc=flext,dc=local"
            )
        await client.delete_entry_universal(dn="ou=bulk_test,dc=flext,dc=local")
