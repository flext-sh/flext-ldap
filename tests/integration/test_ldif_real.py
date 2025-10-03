"""Real LDIF processing integration tests with Docker LDAP server.

This module tests LDIF export/import operations against a real OpenLDAP server,
validating the flext-ldif integration with real LDAP data.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import pytest

from flext_ldap import FlextLdapClient
from flext_core import FlextTypes

# Skip all integration tests when LDAP server is not available
pytestmark = pytest.mark.integration


@pytest.mark.integration
class TestRealLdifExport:
    """Test LDIF export from real LDAP server."""

    def test_export_base_dn_to_ldif(self, shared_ldap_client: FlextLdapClient) -> None:
        """Test exporting base DN to LDIF format."""
        client = shared_ldap_client

        result = client.search(
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

    def test_export_users_to_ldif(self, shared_ldap_client: FlextLdapClient) -> None:
        """Test exporting user entries to LDIF format."""
        client = shared_ldap_client

        # Create test OU and users
        client.add_entry_universal(
            dn="ou=ldif_users,dc=flext,dc=local",
            attributes={"objectClass": ["organizationalUnit"], "ou": "ldif_users"},
        )

        client.add_entry_universal(
            dn="cn=ldif_user1,ou=ldif_users,dc=flext,dc=local",
            attributes={
                "objectClass": ["inetOrgPerson"],
                "cn": "ldif_user1",
                "sn": "LdifUser1",
                "uid": "ldif_user1",
                "mail": "ldif_user1@internal.invalid",
            },
        )

        # Export to LDIF-compatible format
        result = client.search(
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
        client.delete_entry_universal(
            dn="cn=ldif_user1,ou=ldif_users,dc=flext,dc=local"
        )
        client.delete_entry_universal(dn="ou=ldif_users,dc=flext,dc=local")

    def test_export_groups_to_ldif(self, shared_ldap_client: FlextLdapClient) -> None:
        """Test exporting group entries to LDIF format."""
        client = shared_ldap_client

        # Create test OU and group
        client.add_entry_universal(
            dn="ou=ldif_groups,dc=flext,dc=local",
            attributes={"objectClass": ["organizationalUnit"], "ou": "ldif_groups"},
        )

        client.add_entry_universal(
            dn="cn=ldif_group1,ou=ldif_groups,dc=flext,dc=local",
            attributes={
                "objectClass": ["groupOfNames"],
                "cn": "ldif_group1",
                "member": "cn=REDACTED_LDAP_BIND_PASSWORD,dc=flext,dc=local",
            },
        )

        # Export to LDIF-compatible format
        result = client.search(
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
        client.delete_entry_universal(
            dn="cn=ldif_group1,ou=ldif_groups,dc=flext,dc=local"
        )
        client.delete_entry_universal(dn="ou=ldif_groups,dc=flext,dc=local")


@pytest.mark.integration
class TestRealLdifImport:
    """Test LDIF import to real LDAP server."""

    def test_import_organizational_unit_from_ldif(
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
        dn_value = ldif_entry["dn"]
        if isinstance(dn_value, list):
            dn_value = dn_value[0] if dn_value else ""
        result = client.add_entry_universal(
            dn=str(dn_value),
            attributes={k: v for k, v in ldif_entry.items() if k != "dn"},
        )

        assert result.is_success

        # Verify import
        search_result = client.search(
            base_dn="ou=imported,dc=flext,dc=local",
            filter_str="(objectClass=organizationalUnit)",
        )

        assert search_result.is_success
        assert len(search_result.value) > 0

        # Cleanup
        client.delete_entry_universal(dn="ou=imported,dc=flext,dc=local")

    def test_import_user_from_ldif(self, shared_ldap_client: FlextLdapClient) -> None:
        """Test importing user from LDIF-like data."""
        client = shared_ldap_client

        # Create parent OU
        client.add_entry_universal(
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
            "mail": "imported@internal.invalid",
        }

        # Import from LDIF structure
        dn_value = ldif_user["dn"]
        if isinstance(dn_value, list):
            dn_value = dn_value[0] if dn_value else ""
        result = client.add_entry_universal(
            dn=str(dn_value),
            attributes={k: v for k, v in ldif_user.items() if k != "dn"},
        )

        assert result.is_success

        # Verify import
        search_result = client.search(
            base_dn="cn=imported_user,ou=import_test,dc=flext,dc=local",
            filter_str="(objectClass=inetOrgPerson)",
            attributes=["*"],  # Request all attributes
        )

        assert search_result.is_success
        assert len(search_result.value) > 0
        imported_entry = search_result.value[0]
        assert "imported_user" in str(imported_entry.get("cn", ""))

        # Cleanup
        client.delete_entry_universal(
            dn="cn=imported_user,ou=import_test,dc=flext,dc=local"
        )
        client.delete_entry_universal(dn="ou=import_test,dc=flext,dc=local")

    def test_import_group_from_ldif(self, shared_ldap_client: FlextLdapClient) -> None:
        """Test importing group from LDIF-like data."""
        client = shared_ldap_client

        # Create parent OU
        client.add_entry_universal(
            dn="ou=import_groups,dc=flext,dc=local",
            attributes={"objectClass": ["organizationalUnit"], "ou": "import_groups"},
        )

        # LDIF-like group data
        ldif_group = {
            "dn": "cn=imported_group,ou=import_groups,dc=flext,dc=local",
            "objectClass": ["groupOfNames"],
            "cn": "imported_group",
            "member": "cn=REDACTED_LDAP_BIND_PASSWORD,dc=flext,dc=local",
        }

        # Import from LDIF structure
        dn_value = ldif_group["dn"]
        if isinstance(dn_value, list):
            dn_value = dn_value[0] if dn_value else ""
        result = client.add_entry_universal(
            dn=str(dn_value),
            attributes={k: v for k, v in ldif_group.items() if k != "dn"},
        )

        assert result.is_success

        # Verify import
        search_result = client.search(
            base_dn="cn=imported_group,ou=import_groups,dc=flext,dc=local",
            filter_str="(objectClass=groupOfNames)",
        )

        assert search_result.is_success
        assert len(search_result.value) > 0

        # Cleanup
        client.delete_entry_universal(
            dn="cn=imported_group,ou=import_groups,dc=flext,dc=local"
        )
        client.delete_entry_universal(dn="ou=import_groups,dc=flext,dc=local")


@pytest.mark.integration
class TestRealLdifRoundTrip:
    """Test LDIF export/import round-trip operations."""

    def test_ldif_roundtrip_user_data(
        self, shared_ldap_client: FlextLdapClient
    ) -> None:
        """Test complete round-trip: export to LDIF, re-import."""
        client = shared_ldap_client

        # Create original user
        client.add_entry_universal(
            dn="ou=roundtrip,dc=flext,dc=local",
            attributes={"objectClass": ["organizationalUnit"], "ou": "roundtrip"},
        )

        original_user = {
            "dn": "cn=original,ou=roundtrip,dc=flext,dc=local",
            "objectClass": ["inetOrgPerson"],
            "cn": "original",
            "sn": "Original",
            "uid": "original",
            "mail": "original@internal.invalid",
        }

        dn_value = original_user["dn"]
        if isinstance(dn_value, list):
            dn_value = dn_value[0] if dn_value else ""
        client.add_entry_universal(
            dn=str(dn_value),
            attributes={k: v for k, v in original_user.items() if k != "dn"},
        )

        # Export to LDIF format (search)
        export_result = client.search(
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

        dn_value = reimported_user["dn"]
        if isinstance(dn_value, list):
            dn_value = dn_value[0] if dn_value else ""
        # Convert attributes to proper format
        attributes: dict[str, FlextTypes.StringList | str] = {}
        for k, v in reimported_user.items():
            if k != "dn":
                if isinstance(v, list):
                    attributes[k] = [str(item) for item in v if item is not None]
                elif v is None:
                    attributes[k] = []
                else:
                    attributes[k] = [str(v)]

        import_result = client.add_entry_universal(
            dn=str(dn_value),
            attributes=attributes,
        )

        assert import_result.is_success

        # Verify round-trip
        verify_result = client.search(
            base_dn="cn=reimported,ou=roundtrip,dc=flext,dc=local",
            filter_str="(objectClass=inetOrgPerson)",
        )

        assert verify_result.is_success
        assert len(verify_result.value) > 0

        # Cleanup
        client.delete_entry_universal(dn="cn=original,ou=roundtrip,dc=flext,dc=local")
        client.delete_entry_universal(dn="cn=reimported,ou=roundtrip,dc=flext,dc=local")
        client.delete_entry_universal(dn="ou=roundtrip,dc=flext,dc=local")

    def test_ldif_bulk_export_import(self, shared_ldap_client: FlextLdapClient) -> None:
        """Test bulk LDIF export and import operations."""
        client = shared_ldap_client

        # Create bulk test data
        client.add_entry_universal(
            dn="ou=bulk_test,dc=flext,dc=local",
            attributes={"objectClass": ["organizationalUnit"], "ou": "bulk_test"},
        )

        # Create multiple users
        for i in range(1, 4):
            client.add_entry_universal(
                dn=f"cn=bulk_user{i},ou=bulk_test,dc=flext,dc=local",
                attributes={
                    "objectClass": ["inetOrgPerson"],
                    "cn": f"bulk_user{i}",
                    "sn": f"BulkUser{i}",
                    "uid": f"bulk_user{i}",
                    "mail": f"bulk_user{i}@internal.invalid",
                },
            )

        # Bulk export
        export_result = client.search(
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
            client.delete_entry_universal(
                dn=f"cn=bulk_user{i},ou=bulk_test,dc=flext,dc=local"
            )
        client.delete_entry_universal(dn="ou=bulk_test,dc=flext,dc=local")
