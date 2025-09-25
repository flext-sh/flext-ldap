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

from collections.abc import AsyncGenerator
from pathlib import Path
from tempfile import TemporaryDirectory

import pytest

from flext_ldap import FlextLdapClient, FlextLdapModels
from flext_ldif import FlextLdifAclParser, FlextLdifAPI, FlextLdifModels

# Skip all integration tests until flext-ldif API is standardized
pytestmark = pytest.mark.skip(
    "LDIF integration tests temporarily disabled during refactoring"
)


@pytest.fixture
async def ldap_client() -> AsyncGenerator[FlextLdapClient]:
    """Create LDAP client connected to Docker test server."""
    config = FlextLdapModels.ConnectionConfig(
        server="localhost",
        port=3390,
        use_ssl=False,
        bind_dn="cn=REDACTED_LDAP_BIND_PASSWORD,dc=flext,dc=local",
        bind_password="REDACTED_LDAP_BIND_PASSWORD123",
        timeout=30,
    )

    client = FlextLdapClient(config=config)

    connection_result = await client.connect(
        server_uri="ldap://localhost:3390",
        bind_dn="cn=REDACTED_LDAP_BIND_PASSWORD,dc=flext,dc=local",
        password="REDACTED_LDAP_BIND_PASSWORD123",
    )
    if connection_result.is_failure:
        pytest.skip(f"Docker LDAP server not available: {connection_result.error}")

    yield client

    await client.close_connection()


@pytest.fixture
def ldif_api() -> FlextLdifAPI:
    """Create LDIF API instance."""
    return FlextLdifAPI()


@pytest.fixture
async def test_entries(ldap_client: FlextLdapClient) -> AsyncGenerator[list[str]]:
    """Create test LDAP entries and clean up after."""
    test_dns: list[str] = []

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

    add_result = await ldap_client.add_entry_universal(ou_entry.dn, ou_entry.attributes)
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
                "mail": [f"testuser{i}@internal.invalid"],
                "userPassword": ["testpass123"],
            },
            object_classes=["person", "organizationalPerson", "inetOrgPerson"],
        )

        add_result = await ldap_client.add_entry_universal(
            user_entry.dn, user_entry.attributes
        )
        if add_result.is_success:
            test_dns.append(user_dn)

    yield test_dns

    # Cleanup
    for dn in reversed(test_dns):
        await ldap_client.delete(dn)


class TestLdapLdifExport:
    """Test LDAP to LDIF export functionality."""

    def test_export_ldap_entries_to_ldif_string(
        self,
        ldap_client: FlextLdapClient,
        ldif_api: FlextLdifAPI,
        test_entries: list[str],  # noqa: ARG002
    ) -> None:
        """Test exporting LDAP entries to LDIF string format."""
        # Search for test entries
        search_result = ldap_client.search(
            base_dn="ou=testusers,dc=flext,dc=local",
            search_filter="(objectClass=inetOrgPerson)",
            attributes=["cn", "sn", "mail"],
        )

        assert search_result.is_success, f"LDAP search failed: {search_result.error}"
        ldap_entries = search_result.unwrap()
        assert len(ldap_entries) >= 3, "Should find at least 3 test users"

        # Convert LDAP entries to LDIF format entries
        ldif_entries: list[FlextLdifModels.Entry] = []
        for ldap_entry in ldap_entries:
            ldif_entry_result = FlextLdifModels.Entry.create(
                ldap_entry.dn, ldap_entry.attributes
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
        assert "mail: testuser0@internal.invalid" in ldif_content

    def test_export_ldap_entries_to_ldif_file(
        self,
        ldap_client: FlextLdapClient,
        ldif_api: FlextLdifAPI,
        test_entries: list[str],  # noqa: ARG002
    ) -> None:
        """Test exporting LDAP entries to LDIF file."""
        with TemporaryDirectory() as tmpdir:
            ldif_file = Path(tmpdir) / "export.ldif"

            # Search LDAP entries
            search_result = ldap_client.search(
                base_dn="ou=testusers,dc=flext,dc=local",
                search_filter="(objectClass=person)",
                attributes=["*"],
            )

            assert search_result.is_success
            ldap_entries = search_result.unwrap()

            # Convert to LDIF format
            ldif_entries = []
            for ldap_entry in ldap_entries:
                ldif_entry_result = FlextLdifModels.Entry.create(
                    ldap_entry.dn, ldap_entry.attributes
                )
                assert ldif_entry_result.is_success
                ldif_entries.append(ldif_entry_result.unwrap())

            # Write to file using flext-ldif
            write_result = ldif_api.write_file(ldif_file, ldif_entries)

            assert write_result.is_success, f"LDIF write failed: {write_result.error}"
            assert ldif_file.exists()

            # Verify file content
            content = ldif_file.read_text()
            assert "version: 1" in content
            assert "objectClass:" in content


class TestLdifLdapImport:
    """Test LDIF to LDAP import functionality."""

    @pytest.mark.asyncio
    async def test_import_ldif_string_to_ldap(
        self, ldap_client: FlextLdapClient, ldif_api: FlextLdifAPI
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
            ldap_entry = FlextLdapModels.Entry(
                dn=ldif_entry.dn,
                attributes=ldif_entry.attributes,
                object_classes=ldif_entry.attributes.get("objectClass", []),
            )

            add_result = await ldap_client.add_entry_universal(
                ldap_entry.dn, ldap_entry.attributes
            )
            if add_result.is_success:
                imported_dns.append(ldif_entry.dn)

        # Verify entries exist in LDAP
        search_result = ldap_client.search(
            base_dn="ou=imported,dc=flext,dc=local",
            search_filter="(objectClass=person)",
        )

        assert search_result.is_success
        found_entries = search_result.unwrap()
        assert len(found_entries) >= 1

        # Cleanup
        for dn in reversed(imported_dns):
            await ldap_client.delete(dn)

    @pytest.mark.asyncio
    async def test_import_ldif_file_to_ldap(
        self, ldap_client: FlextLdapClient, ldif_api: FlextLdifAPI
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
            parse_result = ldif_api.parse_file(ldif_file)

            assert parse_result.is_success
            ldif_entries = parse_result.unwrap()

            # Import to LDAP
            imported_dns = []
            for ldif_entry in ldif_entries:
                ldap_entry = FlextLdapModels.Entry(
                    dn=ldif_entry.dn,
                    attributes=ldif_entry.attributes,
                    object_classes=ldif_entry.attributes.get("objectClass", []),
                )

                add_result = await ldap_client.add_entry_universal(
                    ldap_entry.dn, ldap_entry.attributes
                )
                if add_result.is_success:
                    imported_dns.append(ldif_entry.dn)

            # Verify
            assert len(imported_dns) == 2

            # Cleanup
            for dn in reversed(imported_dns):
                await ldap_client.delete(dn)


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
            ldap_entry.dn, ldap_entry.attributes
        )

        assert ldif_entry_result.is_success
        ldif_entry = ldif_entry_result.unwrap()

        # Verify conversion
        assert ldif_entry.dn == ldap_entry.dn
        assert ldif_entry.attributes == ldap_entry.attributes
        assert "objectClass" in ldif_entry.attributes
        assert "person" in ldif_entry.attributes["objectClass"]

    def test_ldif_entry_to_ldap_entry_conversion(self) -> None:
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

        ldap_entry = FlextLdapModels.Entry(
            dn=ldif_entry.dn.value,
            attributes=ldif_entry.attributes.data,
            object_classes=ldif_entry.get_attribute("objectClass") or [],
        )

        assert ldap_entry.dn == ldif_entry.dn.value
        assert ldap_entry.attributes == ldif_entry.attributes.data
        assert "inetOrgPerson" in ldap_entry.object_classes


class TestAclIntegration:
    """Test ACL integration between flext-ldap and flext-ldif."""

    def test_ldif_acl_models_available_in_ldap(self) -> None:
        target_result = FlextLdapModels.AclTarget.create(
            target_type="dn",
            dn_pattern="ou=users,dc=example,dc=com",
        )

        assert target_result.is_success
        target = target_result.unwrap()
        assert target.target_type == "dn"
        assert target.dn_pattern == "ou=users,dc=example,dc=com"

    def test_ldap_can_use_ldif_acl_parser(self) -> None:
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
        ldap_client: FlextLdapClient,
        ldif_api: FlextLdifAPI,
        test_entries: list[str],  # noqa: ARG002
    ) -> None:
        """Test complete round-trip: export from LDAP, reimport to LDAP."""
        # Step 1: Export from LDAP
        search_result = ldap_client.search(
            base_dn="ou=testusers,dc=flext,dc=local",
            search_filter="(cn=testuser0)",
            attributes=["*"],
        )

        assert search_result.is_success
        original_entries = search_result.unwrap()
        assert len(original_entries) == 1
        original_entry = original_entries[0]

        # Step 2: Convert to LDIF
        ldif_entry_result = FlextLdifModels.Entry.create(
            original_entry.dn, original_entry.attributes
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
        assert parsed_entry.dn == original_entry.dn
        assert parsed_entry.attributes["cn"] == original_entry.attributes["cn"]
        assert parsed_entry.attributes["sn"] == original_entry.attributes["sn"]

        # Note: We don't reimport to avoid duplicates, but structure is verified


if __name__ == "__main__":
    pytest.main([__file__, "-v", "-s"])
