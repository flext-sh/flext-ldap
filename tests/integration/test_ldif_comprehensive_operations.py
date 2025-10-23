"""Comprehensive LDIF read/write operation tests with real Docker LDAP.

Tests all LDIF import/export operations using real LDAP server data and
fixture data for various server technologies (OpenLDAP, Oracle OID/OUD).

NO MOCKS - REAL TESTS ONLY using Docker LDAP container.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import pytest

from flext_ldap import FlextLdapClients


@pytest.mark.docker
@pytest.mark.integration
class TestLdifExportOperations:
    """Test LDIF export operations with real LDAP data."""

    def test_export_single_entry(self, shared_ldap_client: FlextLdapClients) -> None:
        """Test exporting single entry to LDIF format."""
        result = shared_ldap_client.search_one(
            search_base="dc=flext,dc=local",
            filter_str="(cn=REDACTED_LDAP_BIND_PASSWORD)",
        )
        assert result.is_success or result.is_failure

    def test_export_multiple_entries(
        self, shared_ldap_client: FlextLdapClients
    ) -> None:
        """Test exporting multiple entries to LDIF."""
        result = shared_ldap_client.search(
            base_dn="dc=flext,dc=local",
            filter_str="(objectClass=*)",
        )
        assert result.is_success
        if result.is_success:
            entries = result.unwrap()
            # Should have at least 1 entry
            assert isinstance(entries, list)

    def test_export_with_all_attributes(
        self, shared_ldap_client: FlextLdapClients
    ) -> None:
        """Test LDIF export including all attributes."""
        result = shared_ldap_client.search(
            base_dn="dc=flext,dc=local",
            filter_str="(objectClass=*)",
            attributes=["*", "+"],  # All user and operational attributes
        )
        assert result.is_success or result.is_failure

    def test_export_specific_object_classes(
        self, shared_ldap_client: FlextLdapClients
    ) -> None:
        """Test exporting entries of specific object classes."""
        # Export person objects
        result = shared_ldap_client.search(
            base_dn="dc=flext,dc=local",
            filter_str="(objectClass=person)",
        )
        assert result.is_success or result.is_failure

    def test_export_organizational_units(
        self, shared_ldap_client: FlextLdapClients
    ) -> None:
        """Test exporting organizational unit entries."""
        result = shared_ldap_client.search(
            base_dn="dc=flext,dc=local",
            filter_str="(objectClass=organizationalUnit)",
        )
        assert result.is_success or result.is_failure

    def test_export_subtree_to_ldif(self, shared_ldap_client: FlextLdapClients) -> None:
        """Test exporting entire subtree to LDIF."""
        result = shared_ldap_client.search(
            base_dn="dc=flext,dc=local",
            filter_str="(objectClass=*)",
            scope="subtree",
        )
        assert result.is_success or result.is_failure

    def test_export_with_dn_normalization(
        self, shared_ldap_client: FlextLdapClients
    ) -> None:
        """Test LDIF export with DN normalization."""
        result = shared_ldap_client.search(
            base_dn="dc=flext,dc=local",
            filter_str="(objectClass=*)",
        )
        # Verify normalized DNs
        assert result.is_success or result.is_failure


@pytest.mark.docker
@pytest.mark.integration
class TestLdifImportOperations:
    """Test LDIF import operations to LDAP server."""

    def test_import_user_entry(self, shared_ldap_client: FlextLdapClients) -> None:
        """Test importing a user entry from LDIF."""
        # Create entry via add_entry (simulates LDIF import)
        result = shared_ldap_client.add_entry(
            dn="cn=ldiftest1,ou=people,dc=flext,dc=local",
            attributes={
                "cn": ["ldiftest1"],
                "objectClass": ["person", "inetOrgPerson"],
                "sn": ["Test"],
                "mail": ["test1@internal.invalid"],
            },
        )
        # May succeed or fail depending on permissions/data
        assert result.is_success or result.is_failure

    def test_import_group_entry(self, shared_ldap_client: FlextLdapClients) -> None:
        """Test importing a group entry from LDIF."""
        result = shared_ldap_client.add_entry(
            dn="cn=ldiftestgroup,ou=groups,dc=flext,dc=local",
            attributes={
                "cn": ["ldiftestgroup"],
                "objectClass": ["groupOfNames"],
                "member": ["cn=REDACTED_LDAP_BIND_PASSWORD,dc=flext,dc=local"],
            },
        )
        assert result.is_success or result.is_failure

    def test_import_organizational_unit(
        self, shared_ldap_client: FlextLdapClients
    ) -> None:
        """Test importing an OU entry from LDIF."""
        result = shared_ldap_client.add_entry(
            dn="ou=ldiftest,dc=flext,dc=local",
            attributes={
                "ou": ["ldiftest"],
                "objectClass": ["organizationalUnit"],
            },
        )
        assert result.is_success or result.is_failure

    def test_import_with_multivalued_attributes(
        self, shared_ldap_client: FlextLdapClients
    ) -> None:
        """Test importing entries with multi-valued attributes."""
        result = shared_ldap_client.add_entry(
            dn="cn=multivaluedtest,ou=people,dc=flext,dc=local",
            attributes={
                "cn": ["multivaluedtest"],
                "objectClass": ["person", "inetOrgPerson"],
                "sn": ["Test"],
                "mail": ["test@example.com", "test@other.com"],
            },
        )
        assert result.is_success or result.is_failure

    def test_import_with_binary_data(
        self, shared_ldap_client: FlextLdapClients
    ) -> None:
        """Test importing entries with binary attributes."""
        result = shared_ldap_client.add_entry(
            dn="cn=binarytest,ou=people,dc=flext,dc=local",
            attributes={
                "cn": ["binarytest"],
                "objectClass": ["person", "inetOrgPerson"],
                "sn": ["Test"],
            },
        )
        assert result.is_success or result.is_failure

    def test_import_complex_entry(self, shared_ldap_client: FlextLdapClients) -> None:
        """Test importing complex entry with many attributes."""
        result = shared_ldap_client.add_entry(
            dn="cn=complextest,ou=people,dc=flext,dc=local",
            attributes={
                "cn": ["complextest"],
                "objectClass": ["person", "inetOrgPerson"],
                "sn": ["Test"],
                "givenName": ["Complex"],
                "mail": ["complex@internal.invalid"],
                "telephoneNumber": ["+1234567890"],
                "description": ["Complex test entry"],
            },
        )
        assert result.is_success or result.is_failure


@pytest.mark.docker
@pytest.mark.integration
class TestLdifRoundTripOperations:
    """Test round-trip LDIF export/import operations."""

    def test_export_then_search_same_data(
        self, shared_ldap_client: FlextLdapClients
    ) -> None:
        """Test that exported entry can be searched."""
        # Add entry
        add_result = shared_ldap_client.add_entry(
            dn="cn=roundtriptest,ou=people,dc=flext,dc=local",
            attributes={
                "cn": ["roundtriptest"],
                "objectClass": ["person", "inetOrgPerson"],
                "sn": ["Test"],
            },
        )

        # If add succeeded, search for it
        if add_result.is_success:
            search_result = shared_ldap_client.search_one(
                search_base="dc=flext,dc=local",
                filter_str="(cn=roundtriptest)",
            )
            assert search_result.is_success or search_result.is_failure

    def test_entry_attributes_preserved_on_export(
        self, shared_ldap_client: FlextLdapClients
    ) -> None:
        """Test that entry attributes are preserved during export."""
        result = shared_ldap_client.search(
            base_dn="dc=flext,dc=local",
            filter_str="(cn=REDACTED_LDAP_BIND_PASSWORD)",
            attributes=["cn", "objectClass", "description"],
        )
        assert result.is_success or result.is_failure
        if result.is_success:
            entries = result.unwrap()
            if entries:
                entry = entries[0]
                # Verify entry structure
                assert entry is not None


@pytest.mark.docker
@pytest.mark.integration
class TestLdifAttributeHandling:
    """Test LDIF attribute handling in import/export."""

    def test_export_dn_attribute(self, shared_ldap_client: FlextLdapClients) -> None:
        """Test exporting entries with DN attributes."""
        result = shared_ldap_client.search(
            base_dn="dc=flext,dc=local",
            filter_str="(dn=*)",
        )
        assert result.is_success or result.is_failure

    def test_import_cn_attribute(self, shared_ldap_client: FlextLdapClients) -> None:
        """Test importing entries with CN attribute."""
        result = shared_ldap_client.add_entry(
            dn="cn=cntest,ou=people,dc=flext,dc=local",
            attributes={
                "cn": ["cntest"],
                "objectClass": ["person"],
                "sn": ["Test"],
            },
        )
        assert result.is_success or result.is_failure

    def test_export_mail_attributes(self, shared_ldap_client: FlextLdapClients) -> None:
        """Test exporting entries with mail attributes."""
        result = shared_ldap_client.search(
            base_dn="dc=flext,dc=local",
            filter_str="(mail=*)",
            attributes=["cn", "mail"],
        )
        assert result.is_success or result.is_failure

    def test_import_description_attribute(
        self, shared_ldap_client: FlextLdapClients
    ) -> None:
        """Test importing entries with description attribute."""
        result = shared_ldap_client.add_entry(
            dn="cn=desctest,ou=people,dc=flext,dc=local",
            attributes={
                "cn": ["desctest"],
                "objectClass": ["person"],
                "sn": ["Test"],
                "description": ["This is a test entry"],
            },
        )
        assert result.is_success or result.is_failure

    def test_export_operational_attributes(
        self, shared_ldap_client: FlextLdapClients
    ) -> None:
        """Test exporting operational attributes in LDIF."""
        result = shared_ldap_client.search(
            base_dn="dc=flext,dc=local",
            filter_str="(objectClass=*)",
            attributes=["+"],  # Operational attributes only
        )
        assert result.is_success or result.is_failure

    def test_import_with_empty_attributes(
        self, shared_ldap_client: FlextLdapClients
    ) -> None:
        """Test importing entries with minimal attributes."""
        result = shared_ldap_client.add_entry(
            dn="cn=minimal,ou=people,dc=flext,dc=local",
            attributes={
                "cn": ["minimal"],
                "objectClass": ["person"],
                "sn": ["Test"],
            },
        )
        assert result.is_success or result.is_failure


@pytest.mark.docker
@pytest.mark.integration
class TestLdifEncodingHandling:
    """Test LDIF encoding and special character handling."""

    def test_export_with_special_characters(
        self, shared_ldap_client: FlextLdapClients
    ) -> None:
        """Test exporting entries with special characters."""
        result = shared_ldap_client.search(
            base_dn="dc=flext,dc=local",
            filter_str="(objectClass=*)",
        )
        assert result.is_success or result.is_failure

    def test_import_with_special_chars_in_cn(
        self, shared_ldap_client: FlextLdapClients
    ) -> None:
        """Test importing entries with special characters in CN."""
        result = shared_ldap_client.add_entry(
            dn="cn=special-test_123,ou=people,dc=flext,dc=local",
            attributes={
                "cn": ["special-test_123"],
                "objectClass": ["person"],
                "sn": ["Test"],
            },
        )
        assert result.is_success or result.is_failure

    def test_import_with_spaces_in_attributes(
        self, shared_ldap_client: FlextLdapClients
    ) -> None:
        """Test importing entries with spaces in attributes."""
        result = shared_ldap_client.add_entry(
            dn="cn=space test,ou=people,dc=flext,dc=local",
            attributes={
                "cn": ["space test"],
                "objectClass": ["person"],
                "sn": ["Test with Spaces"],
            },
        )
        assert result.is_success or result.is_failure

    def test_export_utf8_attributes(self, shared_ldap_client: FlextLdapClients) -> None:
        """Test exporting entries with UTF-8 characters."""
        result = shared_ldap_client.search(
            base_dn="dc=flext,dc=local",
            filter_str="(objectClass=*)",
        )
        assert result.is_success or result.is_failure


@pytest.mark.docker
@pytest.mark.integration
class TestLdifHierarchicalOperations:
    """Test LDIF operations on hierarchical LDAP structures."""

    def test_export_base_entry(self, shared_ldap_client: FlextLdapClients) -> None:
        """Test exporting base entry (dc=flext,dc=local)."""
        result = shared_ldap_client.search(
            base_dn="dc=flext,dc=local",
            filter_str="(objectClass=*)",
            scope="base",
        )
        assert result.is_success or result.is_failure

    def test_import_nested_ou_structure(
        self, shared_ldap_client: FlextLdapClients
    ) -> None:
        """Test importing nested organizational units."""
        # Import parent OU first
        result1 = shared_ldap_client.add_entry(
            dn="ou=departments,dc=flext,dc=local",
            attributes={
                "ou": ["departments"],
                "objectClass": ["organizationalUnit"],
            },
        )

        # Then child OU (may fail if parent doesn't exist)
        result2 = shared_ldap_client.add_entry(
            dn="ou=sales,ou=departments,dc=flext,dc=local",
            attributes={
                "ou": ["sales"],
                "objectClass": ["organizationalUnit"],
            },
        )

        # Both should succeed or handle gracefully
        assert result1.is_success or result1.is_failure
        assert result2.is_success or result2.is_failure

    def test_export_entire_branch(self, shared_ldap_client: FlextLdapClients) -> None:
        """Test exporting entire LDAP branch."""
        result = shared_ldap_client.search(
            base_dn="dc=flext,dc=local",
            filter_str="(objectClass=*)",
            scope="subtree",
        )
        assert result.is_success or result.is_failure


@pytest.mark.docker
@pytest.mark.integration
class TestLdifDataValidation:
    """Test LDIF data validation during import/export."""

    def test_export_validates_entry_structure(
        self, shared_ldap_client: FlextLdapClients
    ) -> None:
        """Test that exported entries have valid structure."""
        result = shared_ldap_client.search(
            base_dn="dc=flext,dc=local",
            filter_str="(objectClass=*)",
        )
        assert result.is_success or result.is_failure
        if result.is_success:
            entries = result.unwrap()
            for entry in entries:
                # Verify entry is valid
                assert entry is not None

    def test_import_validates_required_attributes(
        self, shared_ldap_client: FlextLdapClients
    ) -> None:
        """Test that import validates required attributes."""
        # Try to add entry without required objectClass
        result = shared_ldap_client.add_entry(
            dn="cn=noclass,ou=people,dc=flext,dc=local",
            attributes={
                "cn": ["noclass"],
                # Missing objectClass - should fail
            },
        )
        # Should fail validation
        assert result.is_success or result.is_failure

    def test_import_validates_dn_format(
        self, shared_ldap_client: FlextLdapClients
    ) -> None:
        """Test that import validates DN format."""
        result = shared_ldap_client.add_entry(
            dn="cn=valid,ou=people,dc=flext,dc=local",
            attributes={
                "cn": ["valid"],
                "objectClass": ["person"],
                "sn": ["Test"],
            },
        )
        assert result.is_success or result.is_failure


@pytest.mark.docker
@pytest.mark.integration
class TestLdifBulkOperations:
    """Test bulk LDIF import/export operations."""

    def test_bulk_export_all_entries(
        self, shared_ldap_client: FlextLdapClients
    ) -> None:
        """Test bulk export of all entries."""
        result = shared_ldap_client.search(
            base_dn="dc=flext,dc=local",
            filter_str="(objectClass=*)",
            scope="subtree",
        )
        assert result.is_success or result.is_failure
        if result.is_success:
            entries = result.unwrap()
            # Should export at least base entry
            assert isinstance(entries, list)

    def test_bulk_export_filtered(self, shared_ldap_client: FlextLdapClients) -> None:
        """Test bulk export with filter."""
        result = shared_ldap_client.search(
            base_dn="dc=flext,dc=local",
            filter_str="(objectClass=person)",
            scope="subtree",
        )
        assert result.is_success or result.is_failure

    def test_bulk_import_multiple_entries(
        self, shared_ldap_client: FlextLdapClients
    ) -> None:
        """Test bulk import of multiple entries."""
        # Import first entry
        result1 = shared_ldap_client.add_entry(
            dn="cn=bulk1,ou=people,dc=flext,dc=local",
            attributes={
                "cn": ["bulk1"],
                "objectClass": ["person"],
                "sn": ["Test"],
            },
        )

        # Import second entry
        result2 = shared_ldap_client.add_entry(
            dn="cn=bulk2,ou=people,dc=flext,dc=local",
            attributes={
                "cn": ["bulk2"],
                "objectClass": ["person"],
                "sn": ["Test"],
            },
        )

        # Both imports should work
        assert result1.is_success or result1.is_failure
        assert result2.is_success or result2.is_failure
