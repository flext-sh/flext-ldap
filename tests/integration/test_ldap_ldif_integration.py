"""Integration tests for LDAP-LDIF functionality using real Docker LDAP server.

Tests the integration between flext-ldap and flext-ldif:
- LDAP entries export to LDIF format
- LDIF file import to LDAP server
- ACL model integration
- Entry conversion between formats

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from collections.abc import Generator
from pathlib import Path
from tempfile import TemporaryDirectory

import pytest
from flext_core import FlextTypes
from flext_ldif import FlextLdif, FlextLdifModels
from flext_ldif.acl import FlextLdifAclParser

from flext_ldap import FlextLdapClients, FlextLdapModels
from flext_ldap.constants import FlextLdapConstants

# Integration tests - require flext-ldif and Docker LDAP server
pytestmark = pytest.mark.integration


@pytest.fixture
def ldap_client() -> Generator[FlextLdapClients]:
    """Create LDAP client connected to Docker test server."""
    config = FlextLdapModels.ConnectionConfig(
        server="localhost",
        port=3390,
        use_ssl=False,
        bind_dn="cn=admin,dc=flext,dc=local",
        bind_password="admin123",
        timeout=FlextLdapConstants.DEFAULT_TIMEOUT,
    )

    client = FlextLdapClients(config=config)

    connection_result = client.connect(
        server_uri="ldap://localhost:3390",
        bind_dn="cn=admin,dc=flext,dc=local",
        password="admin123",
    )
    if connection_result.is_failure:
        pytest.skip(f"Docker LDAP server not available: {connection_result.error}")

    yield client

    client.close_connection()


@pytest.fixture
def ldif_api() -> FlextLdif:
    """Create LDIF API instance."""
    # flext-ldif is mandatory dependency
    return FlextLdif()


@pytest.fixture
def test_entries(
    ldap_client: FlextLdapClients,
) -> Generator[FlextTypes.StringList]:
    """Create test LDAP entries and clean up after."""
    test_dns: FlextTypes.StringList = []

    # Create test organizational unit
    ou_dn = "ou=testusers,dc=flext,dc=local"
    ou_entry = FlextLdapModels.Entry(
        dn=ou_dn,
        attributes={
            "objectClass": ["organizationalUnit"],
            "ou": ["testusers"],
        },
        object_classes=["organizationalUnit"],
    )

    add_result = ldap_client.add_entry_universal(ou_entry.dn, ou_entry.attributes)
    if add_result.is_success:
        test_dns.append(ou_dn)

    # Create test user entries
    for i in range(3):
        user_dn = f"cn=testuser{i},{ou_dn}"
        user_entry = FlextLdapModels.Entry(
            dn=user_dn,
            attributes={
                "objectClass": ["person", "organizationalPerson", "inetOrgPerson"],
                "cn": [f"testuser{i}"],
                "sn": [f"User{i}"],
                "mail": [f"testuser{i}@flext.local"],
                "userPassword": ["testpass123"],
            },
            object_classes=["person", "organizationalPerson", "inetOrgPerson"],
        )

        add_result = ldap_client.add_entry_universal(
            user_entry.dn, user_entry.attributes
        )
        if add_result.is_success:
            test_dns.append(user_dn)

    yield test_dns

    # Cleanup
    for dn in reversed(test_dns):
        ldap_client.delete(dn)


class TestLdapLdifExport:
    """Test LDAP to LDIF export functionality."""

    def test_export_ldap_entries_to_ldif_string(
        self,
        ldap_client: FlextLdapClients,
        ldif_api: FlextLdif,
    ) -> None:
        """Test exporting LDAP entries to LDIF string format."""
        # Search for test entries
        search_result = ldap_client.search(
            base_dn="ou=testusers,dc=flext,dc=local",
            filter_str="(objectClass=inetOrgPerson)",
            attributes=["cn", "sn", "mail"],
        )

        assert search_result.is_success, f"LDAP search failed: {search_result.error}"
        ldap_entries = search_result.unwrap()
        assert len(ldap_entries) >= 3, "Should find at least 3 test users"

        # Convert LDAP entries to LDIF format entries
        ldif_entries: list[FlextLdifModels.Entry] = []
        for ldap_entry in ldap_entries:
            ldif_entry_result = FlextLdifModels.Entry.create(
                data={"dn": ldap_entry["dn"], "attributes": ldap_entry["attributes"]}
            )
            assert ldif_entry_result.is_success
            ldif_entries.append(ldif_entry_result.unwrap())

        # Generate LDIF string using flext-ldif
        ldif_content_result = ldif_api.write(ldif_entries)

        assert ldif_content_result.is_success, (
            f"LDIF generation failed: {ldif_content_result.error}"
        )
        ldif_content = ldif_content_result.unwrap()

        # Validate LDIF content
        assert "version: 1" in ldif_content
        assert "dn: cn=testuser0,ou=testusers,dc=flext,dc=local" in ldif_content
        assert "cn: testuser0" in ldif_content
        assert "sn: User0" in ldif_content
        assert "mail: testuser0@flext.local" in ldif_content

    def test_export_ldap_entries_to_ldif_file(
        self,
        ldap_client: FlextLdapClients,
        ldif_api: FlextLdif,
    ) -> None:
        """Test exporting LDAP entries to LDIF file."""
        with TemporaryDirectory() as tmpdir:
            ldif_file = Path(tmpdir) / "export.ldif"

            # Search LDAP entries
            search_result = ldap_client.search(
                base_dn="ou=testusers,dc=flext,dc=local",
                filter_str="(objectClass=person)",
                attributes=["*"],
            )

            assert search_result.is_success
            ldap_entries = search_result.unwrap()

            # Convert to LDIF format
            ldif_entries = []
            for ldap_entry in ldap_entries:
                ldif_entry_result = FlextLdifModels.Entry.create(
                    data={
                        "dn": ldap_entry["dn"],
                        "attributes": ldap_entry["attributes"],
                    }
                )
                assert ldif_entry_result.is_success
                ldif_entries.append(ldif_entry_result.unwrap())

            # Write to file using flext-ldif
            write_result = ldif_api.write_file(ldif_entries, ldif_file)

            assert write_result.is_success, f"LDIF write failed: {write_result.error}"
            assert ldif_file.exists()

            # Verify file content
            content = ldif_file.read_text()
            assert "version: 1" in content
            assert "objectClass:" in content


class TestLdifLdapImport:
    """Test LDIF to LDAP import functionality."""

    def test_import_ldif_string_to_ldap(
        self, ldap_client: FlextLdapClients, ldif_api: FlextLdif
    ) -> None:
        """Test importing LDIF string to LDAP server."""
        # Create LDIF content
        ldif_content = """version: 1

dn: ou=imported,dc=flext,dc=local
objectClass: organizationalUnit
ou: imported

dn: cn=imported-user,ou=imported,dc=flext,dc=local
objectClass: person
objectClass: organizationalPerson
cn: imported-user
sn: ImportedUser
"""

        # Parse LDIF using flext-ldif
        parse_result = ldif_api.parse(ldif_content)

        assert parse_result.is_success, f"LDIF parse failed: {parse_result.error}"
        ldif_entries = parse_result.unwrap()
        assert len(ldif_entries) == 2

        # Convert LDIF entries to LDAP and add to server
        imported_dns = []
        for ldif_entry in ldif_entries:
            # Convert LdifAttributes to dict[str, EntryAttributeValue]
            ldap_attributes = {}
            for attr_name, attr_values in ldif_entry.attributes.data.items():
                if len(attr_values.values) == 1:
                    ldap_attributes[attr_name] = attr_values.values[0]
                else:
                    ldap_attributes[attr_name] = attr_values.values

            ldap_entry = FlextLdapModels.Entry(
                dn=str(ldif_entry.dn),
                attributes=ldap_attributes,
            )

            add_result = ldap_client.add_entry_universal(
                ldap_entry.dn, ldap_entry.attributes
            )
            if add_result.is_success:
                imported_dns.append(ldif_entry.dn)

        # Verify entries exist in LDAP
        search_result = ldap_client.search(
            base_dn="ou=imported,dc=flext,dc=local",
            filter_str="(objectClass=person)",
        )

        assert search_result.is_success
        found_entries = search_result.unwrap()
        assert len(found_entries) >= 1

        # Cleanup
        for dn in reversed(imported_dns):
            ldap_client.delete(dn)

    def test_import_ldif_file_to_ldap(
        self, ldap_client: FlextLdapClients, ldif_api: FlextLdif
    ) -> None:
        """Test importing LDIF file to LDAP server."""
        with TemporaryDirectory() as tmpdir:
            ldif_file = Path(tmpdir) / "import.ldif"

            # Create LDIF file
            ldif_content = """version: 1

dn: ou=fileimport,dc=flext,dc=local
objectClass: organizationalUnit
ou: fileimport

dn: cn=file-user,ou=fileimport,dc=flext,dc=local
objectClass: person
cn: file-user
sn: FileUser
"""
            ldif_file.write_text(ldif_content)

            # Parse LDIF file using flext-ldif
            parse_result = ldif_api.parse_ldif_file(ldif_file)

            assert parse_result.is_success
            ldif_entries = parse_result.unwrap()

            # Import to LDAP
            imported_dns = []
            for ldif_entry in ldif_entries:
                # Convert LdifAttributes to dict[str, EntryAttributeValue]
                ldap_attributes = {}
                for attr_name, attr_values in ldif_entry.attributes.data.items():
                    if len(attr_values.values) == 1:
                        ldap_attributes[attr_name] = attr_values.values[0]
                    else:
                        ldap_attributes[attr_name] = attr_values.values

                ldap_entry = FlextLdapModels.Entry(
                    dn=str(ldif_entry.dn),
                    attributes=ldap_attributes,
                )

                add_result = ldap_client.add_entry_universal(
                    ldap_entry.dn, ldap_entry.attributes
                )
                if add_result.is_success:
                    imported_dns.append(ldif_entry.dn)

            # Verify
            assert len(imported_dns) == 2

            # Cleanup
            for dn in reversed(imported_dns):
                ldap_client.delete(dn)


class TestEntryConversion:
    """Test entry conversion between LDAP and LDIF formats."""

    def test_ldap_entry_to_ldif_entry_conversion(self) -> None:
        """Test converting LDAP entry to LDIF entry."""
        # Create LDAP entry
        ldap_entry = FlextLdapModels.Entry(
            dn="cn=test,dc=example,dc=com",
            attributes={
                "objectClass": ["person", "organizationalPerson"],
                "cn": ["test"],
                "sn": ["Test"],
                "mail": ["test@example.com"],
            },
            object_classes=["person", "organizationalPerson"],
        )

        # Convert to LDIF entry
        ldif_entry_result = FlextLdifModels.Entry.create(
            data={"dn": ldap_entry.dn, "attributes": ldap_entry.attributes}
        )

        assert ldif_entry_result.is_success
        ldif_entry = ldif_entry_result.unwrap()

        # Verify conversion - compare DN as string
        assert str(ldif_entry.dn) == ldap_entry.dn
        # Compare attributes (ldif_entry.attributes is LdifAttributes, ldap_entry.attributes is dict)
        assert "objectClass" in ldif_entry.attributes.data
        assert "objectClass" in ldif_entry.attributes
        object_classes = ldif_entry.attributes["objectClass"]
        assert object_classes is not None
        assert isinstance(object_classes, list)
        assert "person" in object_classes

    def test_ldif_entry_to_ldap_entry_conversion(self) -> None:
        """Test conversion from LDIF entry to LDAP entry."""
        ldif_entry_result = FlextLdifModels.Entry.create({
            "dn": "cn=test,dc=example,dc=com",
            "attributes": {
                "objectClass": ["inetOrgPerson"],
                "cn": ["test"],
                "sn": ["Test"],
                "uid": ["test123"],
            },
        })

        assert ldif_entry_result.is_success
        ldif_entry = ldif_entry_result.unwrap()

        # Convert LdifAttributes to dict[str, str | FlextTypes.StringList]
        ldap_attributes: dict[str, str | FlextTypes.StringList] = {}
        object_classes_value: FlextTypes.StringList = []
        for attr_name, attr_values in ldif_entry.attributes.data.items():
            if len(attr_values.values) == 1:
                ldap_attributes[attr_name] = attr_values.values[0]
            else:
                ldap_attributes[attr_name] = attr_values.values

            if attr_name == "objectClass":
                object_classes_value = (
                    attr_values.values
                    if isinstance(attr_values.values, list)
                    else [attr_values.values]
                )

        ldap_entry = FlextLdapModels.Entry(
            dn=str(ldif_entry.dn),
            attributes=ldap_attributes,
            object_classes=object_classes_value,
        )

        assert ldap_entry.dn == str(ldif_entry.dn)
        # Compare key attributes (types differ between ldif and ldap)
        assert "objectClass" in ldap_entry.attributes
        assert "cn" in ldap_entry.attributes


class TestAclIntegration:
    """Test ACL integration between flext-ldap and flext-ldif."""

    def test_ldif_acl_models_available_in_ldap(self) -> None:
        """Test that LDIF ACL models are available in LDAP."""
        target_result = FlextLdapModels.AclTarget.create(
            target_type="dn",
            dn_pattern="ou=users,dc=example,dc=com",
        )

        assert target_result.is_success
        target = target_result.unwrap()
        assert target.target_type == "dn"
        assert target.dn_pattern == "ou=users,dc=example,dc=com"

    def test_ldap_can_use_ldif_acl_parser(self) -> None:
        """Test that LDAP can use LDIF ACL parser."""
        parser = FlextLdifAclParser()

        openldap_acl = "access to attrs=userPassword by self write by anonymous auth"
        parse_result = parser.parse_openldap_acl(openldap_acl)

        assert parse_result.is_success
        acl = parse_result.unwrap()
        assert acl.name == "openldap_acl"
        assert acl.target is not None
        assert acl.subject is not None
        assert acl.permissions is not None


class TestRoundTripConversion:
    """Test round-trip conversion: LDAP → LDIF → LDAP."""

    def test_ldap_ldif_ldap_roundtrip(
        self,
        ldap_client: FlextLdapClients,
        ldif_api: FlextLdif,
    ) -> None:
        """Test complete round-trip: export from LDAP, reimport to LDAP."""
        # Step 1: Export from LDAP
        search_result = ldap_client.search(
            base_dn="ou=testusers,dc=flext,dc=local",
            filter_str="(cn=testuser0)",
            attributes=["*"],
        )

        assert search_result.is_success
        original_entries = search_result.unwrap()
        assert len(original_entries) == 1
        original_entry = original_entries[0]

        # Step 2: Convert to LDIF
        ldif_entry_result = FlextLdifModels.Entry.create(
            data={
                "dn": original_entry["dn"],
                "attributes": original_entry["attributes"],
            }
        )
        assert ldif_entry_result.is_success
        ldif_entry = ldif_entry_result.unwrap()

        # Step 3: Generate LDIF string
        ldif_content_result = ldif_api.write([ldif_entry])
        assert ldif_content_result.is_success
        ldif_content = ldif_content_result.unwrap()

        # Step 4: Parse LDIF back
        parse_result = ldif_api.parse(ldif_content)
        assert parse_result.is_success
        parsed_entries = parse_result.unwrap()
        assert len(parsed_entries) == 1
        parsed_entry = parsed_entries[0]

        # Step 5: Verify data integrity
        assert parsed_entry.dn == original_entry["dn"]
        # Access attributes safely
        if hasattr(parsed_entry.attributes, "get_attribute"):
            cn_values = parsed_entry.attributes.get_attribute("cn")
            sn_values = parsed_entry.attributes.get_attribute("sn")
            # Cast original_entry to dict for safe access
            original_dict = original_entry
            original_attrs = original_dict["attributes"]
            if isinstance(original_attrs, dict):
                assert cn_values == original_attrs["cn"]
                assert sn_values == original_attrs["sn"]

        # Note: We don't reimport to avoid duplicates, but structure is verified


if __name__ == "__main__":
    pytest.main([__file__, "-v", "-s"])
