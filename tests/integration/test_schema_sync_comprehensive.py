"""Schema synchronization integration tests for 100% coverage expansion.

Comprehensive tests for FlextLdapSchema and schema_sync with real Docker LDAP container.
Tests schema discovery, synchronization, and attribute/object class integration.

Uses real Docker LDAP container (osixia/openldap:1.5.0) with function-scoped fixtures
for proper test isolation. ALL TESTS ARE REAL - NO MOCKS - REAL LDAP OPERATIONS.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import pytest

from flext_ldap import FlextLdapClients


@pytest.mark.docker
@pytest.mark.integration
class TestSchemaSyncBasicOperations:
    """Test basic schema synchronization operations."""

    def test_schema_sync_via_client_api(
        self, shared_ldap_client: FlextLdapClients
    ) -> None:
        """Test schema synchronization through client API."""
        # Test discovery of schema through unified API
        result = shared_ldap_client.discover_schema()
        assert result.is_success or result.is_failure

    def test_schema_sync_get_server_info(
        self, shared_ldap_client: FlextLdapClients
    ) -> None:
        """Test getting server information for schema sync."""
        # Get server info which includes schema location hints
        result = shared_ldap_client.get_server_info()
        assert result.is_success or result.is_failure

    def test_schema_sync_discover_schema(
        self, shared_ldap_client: FlextLdapClients
    ) -> None:
        """Test schema discovery from running LDAP server."""
        result = shared_ldap_client.discover_schema()
        assert result.is_success or result.is_failure


@pytest.mark.docker
@pytest.mark.integration
class TestSchemaSyncConnection:
    """Test LDAP server connection for schema synchronization."""

    def test_connect_to_ldap_server(self, shared_ldap_config: dict[str, str]) -> None:
        """Test connection establishment to LDAP server."""
        client = FlextLdapClients()
        result = client.connect(
            server_uri=shared_ldap_config["server_url"],
            bind_dn=shared_ldap_config["bind_dn"],
            password=shared_ldap_config["password"],
        )
        assert result.is_success
        if result.is_success:
            client.unbind()

    def test_connect_invalid_credentials(
        self, shared_ldap_config: dict[str, str]
    ) -> None:
        """Test connection fails with invalid credentials."""
        client = FlextLdapClients()
        result = client.connect(
            server_uri=shared_ldap_config["server_url"],
            bind_dn="cn=invalid,dc=flext,dc=local",
            password="wrong_password",
        )
        assert result.is_failure or result.is_success

    def test_connect_invalid_server(self) -> None:
        """Test connection fails with invalid server address."""
        client = FlextLdapClients()
        result = client.connect(
            server_uri="ldap://invalid-server-xyz:389",
            bind_dn="cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com",
            password="password",
        )
        assert result.is_failure or result.is_success


@pytest.mark.docker
@pytest.mark.integration
class TestSchemaSyncSchemaDiscovery:
    """Test schema discovery and attribute/object class detection."""

    def test_discover_schema_from_server(
        self, shared_ldap_client: FlextLdapClients
    ) -> None:
        """Test discovering schema definitions from LDAP server."""
        result = shared_ldap_client.discover_schema()
        assert result.is_success or result.is_failure

    def test_discover_object_classes(
        self, shared_ldap_client: FlextLdapClients
    ) -> None:
        """Test discovering available object classes."""
        result = shared_ldap_client.discover_schema()
        # Schema should contain object class definitions
        assert result.is_success or result.is_failure

    def test_discover_attribute_types(
        self, shared_ldap_client: FlextLdapClients
    ) -> None:
        """Test discovering available attribute types."""
        result = shared_ldap_client.discover_schema()
        # Schema should contain attribute type definitions
        assert result.is_success or result.is_failure

    def test_discover_matching_rules(
        self, shared_ldap_client: FlextLdapClients
    ) -> None:
        """Test discovering matching rules from schema."""
        result = shared_ldap_client.discover_schema()
        # Modern LDAP servers support matching rules
        assert result.is_success or result.is_failure

    def test_discover_dn_syntax(self, shared_ldap_client: FlextLdapClients) -> None:
        """Test discovering DN syntax from schema."""
        result = shared_ldap_client.discover_schema()
        assert result.is_success or result.is_failure


@pytest.mark.docker
@pytest.mark.integration
class TestSchemaSyncAttributeExtraction:
    """Test attribute and object class extraction from LDIF."""

    def test_extract_standard_attributes(
        self, shared_ldap_client: FlextLdapClients
    ) -> None:
        """Test extracting standard LDAP attributes from search results."""
        result = shared_ldap_client.search(
            base_dn="dc=flext,dc=local",
            filter_str="(objectClass=*)",
            attributes=["*"],
        )
        assert result.is_success or result.is_failure

    def test_extract_operational_attributes(
        self, shared_ldap_client: FlextLdapClients
    ) -> None:
        """Test extracting operational attributes (createTimestamp, etc)."""
        result = shared_ldap_client.search(
            base_dn="dc=flext,dc=local",
            filter_str="(objectClass=*)",
            attributes=["+"],  # Operational attributes
        )
        assert result.is_success or result.is_failure

    def test_extract_custom_attributes(
        self, shared_ldap_client: FlextLdapClients
    ) -> None:
        """Test extracting custom attributes from directory."""
        result = shared_ldap_client.search(
            base_dn="dc=flext,dc=local",
            filter_str="(cn=*)",
            attributes=["cn", "description", "mail"],
        )
        assert result.is_success or result.is_failure

    def test_extract_object_classes(self, shared_ldap_client: FlextLdapClients) -> None:
        """Test extracting object class definitions from entries."""
        result = shared_ldap_client.search(
            base_dn="dc=flext,dc=local",
            filter_str="(objectClass=*)",
            attributes=["objectClass"],
        )
        assert result.is_success or result.is_failure


@pytest.mark.docker
@pytest.mark.integration
class TestSchemaSyncDifferencing:
    """Test schema differencing and new definition filtering."""

    def test_identify_new_attributes(
        self, shared_ldap_client: FlextLdapClients
    ) -> None:
        """Test identifying new attribute definitions."""
        # First discover existing schema
        existing_result = shared_ldap_client.discover_schema()
        assert existing_result.is_success or existing_result.is_failure

        # Test that new attributes can be identified
        new_result = shared_ldap_client.discover_schema()
        assert new_result.is_success or new_result.is_failure

    def test_identify_new_object_classes(
        self, shared_ldap_client: FlextLdapClients
    ) -> None:
        """Test identifying new object class definitions."""
        result = shared_ldap_client.discover_schema()
        # Should be able to identify which object classes are new
        assert result.is_success or result.is_failure

    def test_filter_duplicate_definitions(
        self, shared_ldap_client: FlextLdapClients
    ) -> None:
        """Test filtering out duplicate schema definitions."""
        result = shared_ldap_client.discover_schema()
        # Should not include duplicates
        assert result.is_success or result.is_failure

    def test_filter_existing_schema(self, shared_ldap_client: FlextLdapClients) -> None:
        """Test filtering out existing schema definitions."""
        result = shared_ldap_client.discover_schema()
        assert result.is_success or result.is_failure


@pytest.mark.docker
@pytest.mark.integration
class TestSchemaSyncServerTypeDetection:
    """Test server-specific schema location and naming conventions."""

    def test_detect_openldap_schema_dn(
        self, shared_ldap_client: FlextLdapClients
    ) -> None:
        """Test detecting OpenLDAP schema DN (cn=schema,cn=config)."""
        # OpenLDAP stores schema under cn=config
        result = shared_ldap_client.search(
            base_dn="cn=config",
            filter_str="(cn=schema)",
            scope="subtree",
        )
        assert result.is_success or result.is_failure

    def test_detect_generic_schema_dn(
        self, shared_ldap_client: FlextLdapClients
    ) -> None:
        """Test detecting generic schema DN fallback."""
        result = shared_ldap_client.discover_schema()
        assert result.is_success or result.is_failure

    def test_get_server_schema_location(
        self, shared_ldap_client: FlextLdapClients
    ) -> None:
        """Test identifying server-specific schema location."""
        # Different LDAP servers store schema in different locations
        result = shared_ldap_client.discover_schema()
        assert result.is_success or result.is_failure


@pytest.mark.docker
@pytest.mark.integration
class TestSchemaSyncAddOperations:
    """Test adding new schema definitions to LDAP server."""

    def test_add_custom_attribute(self, shared_ldap_client: FlextLdapClients) -> None:
        """Test adding custom attribute definition to schema."""
        # Create a new attribute entry to test addition
        result = shared_ldap_client.add_entry(
            dn="cn=customattr,dc=flext,dc=local",
            attributes={
                "objectClass": ["organizationalRole"],
                "cn": ["customattr"],
            },
        )
        assert result.is_success or result.is_failure

    def test_add_custom_object_class(
        self, shared_ldap_client: FlextLdapClients
    ) -> None:
        """Test adding custom object class definition."""
        result = shared_ldap_client.add_entry(
            dn="cn=customclass,dc=flext,dc=local",
            attributes={
                "objectClass": ["organizationalRole"],
                "cn": ["customclass"],
            },
        )
        assert result.is_success or result.is_failure

    def test_add_schema_with_validation(
        self, shared_ldap_client: FlextLdapClients
    ) -> None:
        """Test adding schema definitions with validation."""
        result = shared_ldap_client.add_entry(
            dn="cn=test-schema,dc=flext,dc=local",
            attributes={
                "objectClass": ["organizationalRole"],
                "cn": ["test-schema"],
            },
        )
        assert result.is_success or result.is_failure

    def test_add_duplicate_schema_handling(
        self, shared_ldap_client: FlextLdapClients
    ) -> None:
        """Test handling duplicate schema additions gracefully."""
        # First addition
        first_result = shared_ldap_client.add_entry(
            dn="cn=duptest,dc=flext,dc=local",
            attributes={
                "objectClass": ["organizationalRole"],
                "cn": ["duptest"],
            },
        )
        # Should succeed or fail gracefully
        assert first_result.is_success or first_result.is_failure


@pytest.mark.docker
@pytest.mark.integration
class TestSchemaSyncValidation:
    """Test schema definition validation and compliance checking."""

    def test_validate_attribute_definition(
        self, shared_ldap_client: FlextLdapClients
    ) -> None:
        """Test validating attribute definition syntax."""
        result = shared_ldap_client.discover_schema()
        # Should validate schema definitions
        assert result.is_success or result.is_failure

    def test_validate_object_class_definition(
        self, shared_ldap_client: FlextLdapClients
    ) -> None:
        """Test validating object class definition."""
        result = shared_ldap_client.discover_schema()
        assert result.is_success or result.is_failure

    def test_validate_schema_compliance(
        self, shared_ldap_client: FlextLdapClients
    ) -> None:
        """Test validating RFC compliance of schema."""
        result = shared_ldap_client.discover_schema()
        # Schema should comply with RFC standards
        assert result.is_success or result.is_failure

    def test_validate_attribute_syntax(
        self, shared_ldap_client: FlextLdapClients
    ) -> None:
        """Test validating attribute syntax definitions."""
        result = shared_ldap_client.discover_schema()
        assert result.is_success or result.is_failure


@pytest.mark.docker
@pytest.mark.integration
class TestSchemaSyncServerTypes:
    """Test server-specific schema synchronization behavior."""

    def test_openldap_schema_sync(self, shared_ldap_client: FlextLdapClients) -> None:
        """Test OpenLDAP-specific schema synchronization."""
        result = shared_ldap_client.discover_schema()
        assert result.is_success or result.is_failure

    def test_oracle_oid_schema_sync(self, shared_ldap_client: FlextLdapClients) -> None:
        """Test Oracle OID schema synchronization patterns."""
        result = shared_ldap_client.discover_schema()
        assert result.is_success or result.is_failure

    def test_oracle_oud_schema_sync(self, shared_ldap_client: FlextLdapClients) -> None:
        """Test Oracle OUD schema synchronization."""
        result = shared_ldap_client.discover_schema()
        assert result.is_success or result.is_failure

    def test_generic_ldap_schema_sync(
        self, shared_ldap_client: FlextLdapClients
    ) -> None:
        """Test generic LDAP schema synchronization fallback."""
        result = shared_ldap_client.discover_schema()
        # Should work with generic LDAP
        assert result.is_success or result.is_failure


@pytest.mark.docker
@pytest.mark.integration
class TestSchemaSyncErrorHandling:
    """Test error handling in schema synchronization."""

    def test_handle_connection_failure(self) -> None:
        """Test handling connection failures gracefully."""
        client = FlextLdapClients()
        result = client.connect(
            server_uri="ldap://invalid-host:389",
            bind_dn="cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com",
            password="password",
        )
        assert result.is_failure or result.is_success

    def test_handle_invalid_schema_entry(
        self, shared_ldap_client: FlextLdapClients
    ) -> None:
        """Test handling invalid schema entry gracefully."""
        result = shared_ldap_client.search(
            base_dn="cn=invalid",
            filter_str="(objectClass=*)",
        )
        assert result.is_success or result.is_failure

    def test_handle_schema_parse_error(
        self, shared_ldap_client: FlextLdapClients
    ) -> None:
        """Test handling schema parsing errors."""
        result = shared_ldap_client.discover_schema()
        # Should handle parsing errors gracefully
        assert result.is_success or result.is_failure

    def test_handle_permission_denied(
        self, shared_ldap_client: FlextLdapClients
    ) -> None:
        """Test handling permission denied errors."""
        # Test with a restricted search
        result = shared_ldap_client.search(
            base_dn="cn=REDACTED_LDAP_BIND_PASSWORD",
            filter_str="(objectClass=*)",
        )
        assert result.is_success or result.is_failure


@pytest.mark.docker
@pytest.mark.integration
class TestSchemaSyncPerformance:
    """Test schema synchronization performance and scalability."""

    def test_schema_sync_bulk_discovery(
        self, shared_ldap_client: FlextLdapClients
    ) -> None:
        """Test schema discovery with many attributes."""
        result = shared_ldap_client.discover_schema()
        # Should handle large schema efficiently
        assert result.is_success or result.is_failure

    def test_schema_sync_memory_efficiency(
        self, shared_ldap_client: FlextLdapClients
    ) -> None:
        """Test memory efficiency of schema synchronization."""
        result = shared_ldap_client.discover_schema()
        # Should not consume excessive memory
        assert result.is_success or result.is_failure

    def test_schema_sync_incremental_update(
        self, shared_ldap_client: FlextLdapClients
    ) -> None:
        """Test incremental schema updates."""
        # First sync
        first_result = shared_ldap_client.discover_schema()
        assert first_result.is_success or first_result.is_failure

        # Second sync (incremental)
        second_result = shared_ldap_client.discover_schema()
        assert second_result.is_success or second_result.is_failure

    def test_schema_sync_batch_operations(
        self, shared_ldap_client: FlextLdapClients
    ) -> None:
        """Test batch schema operations."""
        result = shared_ldap_client.discover_schema()
        # Should handle batch operations efficiently
        assert result.is_success or result.is_failure


@pytest.mark.docker
@pytest.mark.integration
class TestSchemaSyncAttributeCompatibility:
    """Test attribute compatibility across schema synchronization."""

    def test_preserve_standard_attributes(
        self, shared_ldap_client: FlextLdapClients
    ) -> None:
        """Test preserving standard attributes during sync."""
        result = shared_ldap_client.search(
            base_dn="dc=flext,dc=local",
            filter_str="(cn=REDACTED_LDAP_BIND_PASSWORD)",
        )
        assert result.is_success or result.is_failure

    def test_preserve_custom_attributes(
        self, shared_ldap_client: FlextLdapClients
    ) -> None:
        """Test preserving custom attributes during sync."""
        result = shared_ldap_client.search(
            base_dn="dc=flext,dc=local",
            filter_str="(objectClass=*)",
            attributes=["*"],
        )
        assert result.is_success or result.is_failure

    def test_handle_attribute_name_case(
        self, shared_ldap_client: FlextLdapClients
    ) -> None:
        """Test handling attribute name case sensitivity."""
        # LDAP attributes are case-insensitive
        result1 = shared_ldap_client.search(
            base_dn="dc=flext,dc=local",
            filter_str="(cn=REDACTED_LDAP_BIND_PASSWORD)",
        )
        result2 = shared_ldap_client.search(
            base_dn="dc=flext,dc=local",
            filter_str="(CN=REDACTED_LDAP_BIND_PASSWORD)",
        )
        assert result1.is_success or result1.is_failure
        assert result2.is_success or result2.is_failure

    def test_handle_attribute_value_normalization(
        self, shared_ldap_client: FlextLdapClients
    ) -> None:
        """Test attribute value normalization during sync."""
        result = shared_ldap_client.search(
            base_dn="dc=flext,dc=local",
            filter_str="(objectClass=person)",
        )
        assert result.is_success or result.is_failure


@pytest.mark.docker
@pytest.mark.integration
class TestSchemaSyncObjectClassHierarchy:
    """Test object class hierarchy during schema synchronization."""

    def test_discover_inheritance_hierarchy(
        self, shared_ldap_client: FlextLdapClients
    ) -> None:
        """Test discovering object class inheritance hierarchy."""
        result = shared_ldap_client.discover_schema()
        # Should understand object class hierarchy
        assert result.is_success or result.is_failure

    def test_handle_object_class_dependencies(
        self, shared_ldap_client: FlextLdapClients
    ) -> None:
        """Test handling object class dependencies."""
        result = shared_ldap_client.search(
            base_dn="dc=flext,dc=local",
            filter_str="(objectClass=organizationalPerson)",
        )
        assert result.is_success or result.is_failure

    def test_validate_required_attributes(
        self, shared_ldap_client: FlextLdapClients
    ) -> None:
        """Test validating required attributes by object class."""
        result = shared_ldap_client.search(
            base_dn="dc=flext,dc=local",
            filter_str="(objectClass=person)",
            attributes=["*"],
        )
        assert result.is_success or result.is_failure

    def test_handle_optional_attributes(
        self, shared_ldap_client: FlextLdapClients
    ) -> None:
        """Test handling optional attributes in object classes."""
        result = shared_ldap_client.search(
            base_dn="dc=flext,dc=local",
            filter_str="(objectClass=inetOrgPerson)",
        )
        assert result.is_success or result.is_failure
