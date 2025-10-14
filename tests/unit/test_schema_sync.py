"""Unit tests for FlextLdapSchemaSync service.

Tests idempotent schema synchronization logic for client-a OID → OUD migration Phase 1.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

from pathlib import Path
from typing import Final

import pytest
from flext_core import FlextCore

from flext_ldap.schema_sync import FlextLdapSchemaSync

# Test Constants - Schema LDIF Samples
SAMPLE_ATTRIBUTE_LDIF: Final[
    str
] = """attributeTypes: ( 2.5.4.3 NAME 'cn' DESC 'Common Name' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )
attributeTypes: ( 2.5.4.4 NAME 'sn' DESC 'Surname' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )
attributeTypes: ( 0.9.2342.19200300.100.1.1 NAME 'uid' DESC 'User ID' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )
attributeTypes: ( 2.16.840.1.113894.1.1.1.1 NAME 'orclGUID' DESC 'Oracle GUID' SYNTAX 1.3.6.1.4.1.1466.115.121.1.40 )
"""

SAMPLE_OBJECTCLASS_LDIF: Final[
    str
] = """objectClasses: ( 2.5.6.6 NAME 'person' DESC 'Person' SUP top STRUCTURAL MUST ( cn $ sn ) )
objectClasses: ( 2.5.6.7 NAME 'organizationalPerson' DESC 'Organizational Person' SUP person STRUCTURAL )
objectClasses: ( 0.9.2342.19200300.100.4.4 NAME 'pilotPerson' DESC 'Pilot Person' SUP person STRUCTURAL )
objectClasses: ( 2.16.840.1.113894.1.2.1.1 NAME 'orclUser' DESC 'Oracle User' SUP top STRUCTURAL )
"""

SAMPLE_MIXED_LDIF: Final[str] = SAMPLE_ATTRIBUTE_LDIF + "\n" + SAMPLE_OBJECTCLASS_LDIF


@pytest.fixture
def temp_schema_file(tmp_path: Path) -> Path:
    """Create temporary schema LDIF file for testing.

    Args:
        tmp_path: pytest temporary directory fixture

    Returns:
        Path to temporary schema file

    """
    schema_file = tmp_path / "test_schema.ldif"
    schema_file.write_text(SAMPLE_MIXED_LDIF, encoding="utf-8")
    return schema_file


@pytest.fixture
def existing_schema() -> FlextCore.Types.Dict:
    """Provide existing schema for idempotent testing.

    Returns:
        Dictionary with existing attributeTypes and objectClasses

    """
    return {
        "attributeTypes": {
            "cn": {
                "oid": "2.5.4.3",
                "name": "cn",
                "definition": "Common Name",
            },
        },
        "objectClasses": {
            "person": {
                "oid": "2.5.6.6",
                "name": "person",
                "definition": "Person",
            },
        },
    }


class TestSchemaSyncInitialization:
    """Test FlextLdapSchemaSync initialization and configuration."""

    def test_initialization_with_required_params(self, temp_schema_file: Path) -> None:
        """Test service initialization with required parameters."""
        service = FlextLdapSchemaSync(
            schema_ldif_file=temp_schema_file,
            server_host="localhost",
        )

        assert service._schema_file == temp_schema_file
        assert service._server_host == "localhost"
        assert service._server_port == 389
        assert service._server_type == "oracle_oud"
        assert service._use_ssl is False
        assert service._connection is None

    def test_initialization_with_full_params(self, temp_schema_file: Path) -> None:
        """Test service initialization with all parameters."""
        service = FlextLdapSchemaSync(
            schema_ldif_file=temp_schema_file,
            server_host="oud.example.com",
            server_port=1636,
            bind_dn="cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com",
            bind_password="secret",
            base_dn="dc=example,dc=com",
            server_type="openldap",
            use_ssl=True,
        )

        assert service._server_host == "oud.example.com"
        assert service._server_port == 1636
        assert service._bind_dn == "cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com"
        assert service._bind_password == "secret"
        assert service._base_dn == "dc=example,dc=com"
        assert service._server_type == "openldap"
        assert service._use_ssl is True

    def test_initialization_schema_file_path_conversion(self, tmp_path: Path) -> None:
        """Test that schema_ldif_file is converted to Path."""
        schema_file_str = str(tmp_path / "schema.ldif")
        service = FlextLdapSchemaSync(
            schema_ldif_file=schema_file_str,
            server_host="localhost",
        )

        assert isinstance(service._schema_file, Path)
        assert str(service._schema_file) == schema_file_str


class TestSchemaLdifParsing:
    """Test schema LDIF parsing functionality."""

    def test_parse_valid_schema_ldif(self, temp_schema_file: Path) -> None:
        """Test parsing valid schema LDIF file."""
        service = FlextLdapSchemaSync(
            schema_ldif_file=temp_schema_file,
            server_host="localhost",
        )

        result = service._parse_schema_ldif()

        assert result.is_success
        definitions = result.unwrap()
        assert len(definitions) > 0

        # Should have both attributeTypes and objectClasses
        has_attributes = any(d.get("type") == "attributeType" for d in definitions)
        has_objectclasses = any(d.get("type") == "objectClass" for d in definitions)
        assert has_attributes
        assert has_objectclasses

    def test_parse_nonexistent_file(self, tmp_path: Path) -> None:
        """Test parsing nonexistent schema file returns failure."""
        nonexistent_file = tmp_path / "nonexistent.ldif"
        service = FlextLdapSchemaSync(
            schema_ldif_file=nonexistent_file,
            server_host="localhost",
        )

        result = service._parse_schema_ldif()

        assert result.is_failure
        assert result.error is not None
        assert "not found" in result.error.lower()

    def test_parse_attribute_types(self, temp_schema_file: Path) -> None:
        """Test parsing attributeTypes from schema LDIF."""
        service = FlextLdapSchemaSync(
            schema_ldif_file=temp_schema_file,
            server_host="localhost",
        )

        result = service._parse_schema_ldif()
        assert result.is_success
        definitions = result.unwrap()

        attributes = [d for d in definitions if d.get("type") == "attributeType"]
        assert len(attributes) >= 3  # At least cn, sn, uid

        # Check cn attribute
        cn_attr = next((a for a in attributes if a.get("name") == "cn"), None)
        assert cn_attr is not None
        assert cn_attr["oid"] == "2.5.4.3"
        assert cn_attr["name"] == "cn"
        definition = str(cn_attr["definition"])
        assert "Common Name" in definition
        assert "raw_line" in cn_attr

    def test_parse_object_classes(self, temp_schema_file: Path) -> None:
        """Test parsing objectClasses from schema LDIF."""
        service = FlextLdapSchemaSync(
            schema_ldif_file=temp_schema_file,
            server_host="localhost",
        )

        result = service._parse_schema_ldif()
        assert result.is_success
        definitions = result.unwrap()

        objectclasses = [d for d in definitions if d.get("type") == "objectClass"]
        assert (
            len(objectclasses) >= 3
        )  # At least person, organizationalPerson, pilotPerson

        # Check person objectClass
        person_oc = next(
            (oc for oc in objectclasses if oc.get("name") == "person"), None
        )
        assert person_oc is not None
        assert person_oc["oid"] == "2.5.6.6"
        assert person_oc["name"] == "person"
        definition = str(person_oc["definition"])
        assert "Person" in definition

    def test_parse_empty_file(self, tmp_path: Path) -> None:
        """Test parsing empty schema file returns empty list."""
        empty_file = tmp_path / "empty.ldif"
        empty_file.write_text("", encoding="utf-8")

        service = FlextLdapSchemaSync(
            schema_ldif_file=empty_file,
            server_host="localhost",
        )

        result = service._parse_schema_ldif()

        assert result.is_success
        definitions = result.unwrap()
        assert len(definitions) == 0

    def test_extract_name_field(self, temp_schema_file: Path) -> None:
        """Test NAME field extraction from schema definitions."""
        service = FlextLdapSchemaSync(
            schema_ldif_file=temp_schema_file,
            server_host="localhost",
        )

        # Test valid NAME extraction
        definition = (
            "2.5.4.3 NAME 'cn' DESC 'Common Name' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15"
        )
        name = service._extract_name(definition)
        assert name == "cn"

        # Test definition without NAME
        definition_no_name = "2.5.4.999 DESC 'No Name Attribute'"
        name_empty = service._extract_name(definition_no_name)
        assert not name_empty


class TestIdempotentFiltering:
    """Test idempotent filtering logic (skip existing definitions)."""

    def test_filter_new_definitions_all_new(self, temp_schema_file: Path) -> None:
        """Test filtering when all definitions are new."""
        service = FlextLdapSchemaSync(
            schema_ldif_file=temp_schema_file,
            server_host="localhost",
        )

        definitions: list[FlextCore.Types.Dict] = [
            {
                "type": "attributeType",
                "oid": "2.5.4.4",
                "name": "sn",
                "definition": "Surname",
            },
            {
                "type": "objectClass",
                "oid": "2.5.6.7",
                "name": "organizationalPerson",
                "definition": "Organizational Person",
            },
        ]

        existing_schema: FlextCore.Types.Dict = {
            "attributeTypes": {},
            "objectClasses": {},
        }

        new_definitions = service._filter_new_definitions(definitions, existing_schema)

        assert len(new_definitions) == 2
        assert new_definitions == definitions

    def test_filter_new_definitions_all_existing(
        self, temp_schema_file: Path, existing_schema: FlextCore.Types.Dict
    ) -> None:
        """Test filtering when all definitions already exist."""
        service = FlextLdapSchemaSync(
            schema_ldif_file=temp_schema_file,
            server_host="localhost",
        )

        definitions: list[FlextCore.Types.Dict] = [
            {
                "type": "attributeType",
                "oid": "2.5.4.3",
                "name": "cn",
                "definition": "Common Name",
            },
            {
                "type": "objectClass",
                "oid": "2.5.6.6",
                "name": "person",
                "definition": "Person",
            },
        ]

        new_definitions = service._filter_new_definitions(definitions, existing_schema)

        # All should be filtered out (already existing)
        assert len(new_definitions) == 0

    def test_filter_new_definitions_mixed(
        self, temp_schema_file: Path, existing_schema: FlextCore.Types.Dict
    ) -> None:
        """Test filtering with mix of new and existing definitions."""
        service = FlextLdapSchemaSync(
            schema_ldif_file=temp_schema_file,
            server_host="localhost",
        )

        definitions: list[FlextCore.Types.Dict] = [
            {
                "type": "attributeType",
                "oid": "2.5.4.3",
                "name": "cn",
                "definition": "Common Name",
            },  # Existing
            {
                "type": "attributeType",
                "oid": "2.5.4.4",
                "name": "sn",
                "definition": "Surname",
            },  # New
            {
                "type": "objectClass",
                "oid": "2.5.6.6",
                "name": "person",
                "definition": "Person",
            },  # Existing
            {
                "type": "objectClass",
                "oid": "2.5.6.7",
                "name": "organizationalPerson",
                "definition": "Organizational Person",
            },  # New
        ]

        new_definitions = service._filter_new_definitions(definitions, existing_schema)

        # Should have 2 new definitions (sn, organizationalPerson)
        assert len(new_definitions) == 2
        new_names = [d.get("name") for d in new_definitions]
        assert "sn" in new_names
        assert "organizationalPerson" in new_names
        assert "cn" not in new_names
        assert "person" not in new_names

    def test_filter_new_definitions_by_oid(self, temp_schema_file: Path) -> None:
        """Test filtering checks both NAME and OID for existing definitions."""
        service = FlextLdapSchemaSync(
            schema_ldif_file=temp_schema_file,
            server_host="localhost",
        )

        definitions: list[FlextCore.Types.Dict] = [
            {
                "type": "attributeType",
                "oid": "2.5.4.3",
                "name": "commonName",  # Different name, same OID
                "definition": "CN Alias",
            },
        ]

        existing_schema: FlextCore.Types.Dict = {
            "attributeTypes": {
                "2.5.4.3": {  # Existing by OID
                    "oid": "2.5.4.3",
                    "name": "cn",
                    "definition": "Common Name",
                },
            },
            "objectClasses": {},
        }

        new_definitions = service._filter_new_definitions(definitions, existing_schema)

        # Should be filtered out (same OID exists)
        assert len(new_definitions) == 0


class TestConnectionAndSchema:
    """Test connection and schema discovery (Phase 1 placeholders)."""

    def test_connect_to_server_placeholder(self, temp_schema_file: Path) -> None:
        """Test server connection Phase 1 placeholder."""
        service = FlextLdapSchemaSync(
            schema_ldif_file=temp_schema_file,
            server_host="localhost",
        )

        result = service._connect_to_server()

        # Phase 1: Should succeed with placeholder
        assert result.is_success
        assert service._connection is not None
        assert isinstance(service._connection, dict)
        assert service._connection.get("connected") is True

    def test_get_existing_schema_placeholder(self, temp_schema_file: Path) -> None:
        """Test existing schema discovery Phase 1 placeholder."""
        service = FlextLdapSchemaSync(
            schema_ldif_file=temp_schema_file,
            server_host="localhost",
        )

        result = service._get_existing_schema()

        # Phase 1: Should succeed with empty schema
        assert result.is_success
        existing = result.unwrap()
        assert "attributeTypes" in existing
        assert "objectClasses" in existing
        assert isinstance(existing["attributeTypes"], dict)
        assert isinstance(existing["objectClasses"], dict)

    def test_add_schema_definitions_placeholder(self, temp_schema_file: Path) -> None:
        """Test schema addition Phase 1 placeholder."""
        service = FlextLdapSchemaSync(
            schema_ldif_file=temp_schema_file,
            server_host="localhost",
        )

        definitions: list[FlextCore.Types.Dict] = [
            {
                "type": "attributeType",
                "oid": "2.5.4.3",
                "name": "cn",
                "definition": "Common Name",
            },
        ]

        result = service._add_schema_definitions(definitions)

        # Phase 1: Should succeed with placeholder
        assert result.is_success

    def test_disconnect_clears_connection(self, temp_schema_file: Path) -> None:
        """Test disconnect clears connection."""
        service = FlextLdapSchemaSync(
            schema_ldif_file=temp_schema_file,
            server_host="localhost",
        )

        # Connect first
        service._connect_to_server()
        assert service._connection is not None

        # Disconnect
        service._disconnect()
        assert service._connection is None


class TestSchemaSyncExecution:
    """Test complete schema sync execution workflow."""

    def test_execute_complete_workflow(self, temp_schema_file: Path) -> None:
        """Test complete schema sync workflow execution."""
        service = FlextLdapSchemaSync(
            schema_ldif_file=temp_schema_file,
            server_host="localhost",
            server_port=1389,
        )

        result = service.execute()

        assert result.is_success
        sync_result = result.unwrap()

        # Check result structure
        assert "total_definitions" in sync_result
        assert "existing_definitions" in sync_result
        assert "new_definitions_added" in sync_result
        assert "skipped_count" in sync_result
        assert "server_type" in sync_result
        assert "server_host" in sync_result
        assert "idempotent" in sync_result
        assert "schema_file" in sync_result

        # Check values with type assertions
        assert isinstance(sync_result["total_definitions"], int)
        assert isinstance(sync_result["existing_definitions"], int)
        assert isinstance(sync_result["new_definitions_added"], int)
        assert sync_result["total_definitions"] > 0
        assert sync_result["idempotent"] is True
        assert sync_result["server_host"] == "localhost"

    def test_execute_with_all_new_definitions(self, temp_schema_file: Path) -> None:
        """Test execution when all definitions are new."""
        service = FlextLdapSchemaSync(
            schema_ldif_file=temp_schema_file,
            server_host="localhost",
        )

        result = service.execute()

        assert result.is_success
        sync_result = result.unwrap()

        # Phase 1: Empty existing schema, so all should be new
        total = sync_result["total_definitions"]
        new_added = sync_result["new_definitions_added"]
        skipped = sync_result["skipped_count"]

        assert isinstance(total, int)
        assert isinstance(new_added, int)
        assert isinstance(skipped, int)
        assert total == new_added
        assert skipped == 0

    def test_execute_nonexistent_file_failure(self, tmp_path: Path) -> None:
        """Test execution with nonexistent file returns failure."""
        nonexistent_file = tmp_path / "nonexistent.ldif"
        service = FlextLdapSchemaSync(
            schema_ldif_file=nonexistent_file,
            server_host="localhost",
        )

        result = service.execute()

        assert result.is_failure
        assert result.error is not None
        assert "parse schema ldif" in result.error.lower()

    def test_execute_statistics_accuracy(self, temp_schema_file: Path) -> None:
        """Test that execution statistics are calculated correctly."""
        service = FlextLdapSchemaSync(
            schema_ldif_file=temp_schema_file,
            server_host="localhost",
        )

        result = service.execute()

        assert result.is_success
        sync_result = result.unwrap()

        # Verify statistics consistency
        total = sync_result["total_definitions"]
        existing = sync_result["existing_definitions"]
        new_added = sync_result["new_definitions_added"]
        skipped = sync_result["skipped_count"]

        assert isinstance(total, int)
        assert isinstance(existing, int)
        assert isinstance(new_added, int)
        assert isinstance(skipped, int)

        # Total should equal existing + new
        assert total == existing + new_added
        # Skipped should equal existing
        assert skipped == existing


class TestSchemaSyncIntegration:
    """Integration tests for idempotent schema sync."""

    def test_idempotent_sync_preserves_existing(self, temp_schema_file: Path) -> None:
        """Test that idempotent sync preserves existing schema."""
        service = FlextLdapSchemaSync(
            schema_ldif_file=temp_schema_file,
            server_host="localhost",
        )

        # First execution
        result1 = service.execute()
        assert result1.is_success
        sync1 = result1.unwrap()

        # Phase 1: All should be new on first run
        assert isinstance(sync1["new_definitions_added"], int)
        assert isinstance(sync1["total_definitions"], int)
        assert sync1["new_definitions_added"] == sync1["total_definitions"]

        # Note: In Phase 2, second execution would skip all definitions

    def test_multiple_server_types(self, temp_schema_file: Path) -> None:
        """Test schema sync with different server types."""
        server_types = ["oracle_oud", "openldap", "ds389"]

        for server_type in server_types:
            service = FlextLdapSchemaSync(
                schema_ldif_file=temp_schema_file,
                server_host="localhost",
                server_type=server_type,
            )

            result = service.execute()

            assert result.is_success
            sync_result = result.unwrap()
            assert sync_result["server_type"] == server_type

    def test_schema_sync_with_ssl_config(self, temp_schema_file: Path) -> None:
        """Test schema sync with SSL configuration."""
        service = FlextLdapSchemaSync(
            schema_ldif_file=temp_schema_file,
            server_host="ldaps.example.com",
            server_port=636,
            use_ssl=True,
        )

        assert service._use_ssl is True
        assert service._server_port == 636

        result = service.execute()

        assert result.is_success


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
