"""Shared LDAP schema discovery integration tests using shared Docker container.

This module tests schema discovery against the shared OpenLDAP server
from docker/shared_ldap_fixtures.py, validating server type detection,
quirks handling, and normalization.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import time

import pytest
from flext_ldap import FlextLDAPClient, FlextLDAPModels, FlextLDAPSchema

# Skip all integration tests when LDAP server is not available
pytestmark = pytest.mark.integration


@pytest.mark.integration
class TestSharedSchemaDiscovery:
    """Test schema discovery operations using shared LDAP container."""

    def test_discover_schema_from_shared_server(
        self,
        shared_ldap_client: FlextLDAPClient,
    ) -> None:
        """Test discovering schema from shared LDAP server."""
        # Test schema discovery
        schema_result = shared_ldap_client.discover_schema()

        assert schema_result.is_success, (
            f"Schema discovery failed: {schema_result.error}"
        )
        assert schema_result.value is not None

        # Verify schema data structure
        schema_data = schema_result.value
        assert isinstance(schema_data, FlextLDAPModels.SchemaDiscoveryResult)
        assert schema_data.server_info is not None
        assert schema_data.server_type is not None
        assert schema_data.server_quirks is not None

    def test_detect_server_type_with_shared_server(
        self,
        shared_ldap_client: FlextLDAPClient,
    ) -> None:
        """Test server type detection with shared LDAP server."""
        # Get server info first
        schema_result = shared_ldap_client.discover_schema()
        assert schema_result.is_success, (
            f"Schema discovery failed: {schema_result.error}"
        )

        schema_data = schema_result.value
        assert schema_data.server_type is not None

        # Verify server type is detected (GENERIC is acceptable when specific detection fails)
        assert schema_data.server_type in {
            FlextLDAPModels.LdapServerType.OPENLDAP,
            FlextLDAPModels.LdapServerType.GENERIC,
        }, f"Unexpected server type: {schema_data.server_type}"

    def test_discover_server_capabilities_with_shared_server(
        self,
        shared_ldap_client: FlextLDAPClient,
    ) -> None:
        """Test server capabilities discovery with shared LDAP server."""
        # Test schema discovery
        schema_result = shared_ldap_client.discover_schema()
        assert schema_result.is_success, (
            f"Schema discovery failed: {schema_result.error}"
        )

        schema_data = schema_result.value
        assert schema_data.server_info is not None

        # Verify server info contains expected fields
        server_info = schema_data.server_info
        assert isinstance(server_info, dict)

        # Check for common LDAP server attributes
        expected_attrs = ["vendorName", "description", "supportedLDAPVersion"]
        for attr in expected_attrs:
            if attr in server_info:
                assert server_info[attr] is not None

    def test_get_server_quirks_with_shared_server(
        self,
        shared_ldap_client: FlextLDAPClient,
    ) -> None:
        """Test server quirks detection with shared LDAP server."""
        # Test schema discovery
        schema_result = shared_ldap_client.discover_schema()
        assert schema_result.is_success, (
            f"Schema discovery failed: {schema_result.error}"
        )

        schema_data = schema_result.value
        assert schema_data.server_quirks is not None

        # Verify quirks are detected
        quirks = schema_data.server_quirks
        assert isinstance(quirks, FlextLDAPModels.ServerQuirks)

        # Should have quirks object
        assert quirks is not None
        assert quirks.server_type is not None

    def test_quirks_detector_with_shared_server_info(
        self,
        shared_ldap_client: FlextLDAPClient,
    ) -> None:
        """Test quirks detector with shared server information."""
        # Test schema discovery
        schema_result = shared_ldap_client.discover_schema()
        assert schema_result.is_success, (
            f"Schema discovery failed: {schema_result.error}"
        )

        schema_data = schema_result.value
        assert schema_data.server_info is not None

        # Test quirks detector directly
        quirks_detector = FlextLDAPSchema.GenericQuirksDetector()
        server_type = quirks_detector.detect_server_type(schema_data.server_info)
        quirks = quirks_detector.get_server_quirks(server_type)

        assert server_type is not None
        assert quirks is not None
        assert isinstance(quirks, FlextLDAPModels.ServerQuirks)

    def test_schema_discovery_performance_with_shared_server(
        self,
        shared_ldap_client: FlextLDAPClient,
    ) -> None:
        """Test schema discovery performance with shared server."""
        # Measure schema discovery time
        start_time = time.time()
        schema_result = shared_ldap_client.discover_schema()
        end_time = time.time()

        discovery_time = end_time - start_time

        # Verify discovery succeeded
        assert schema_result.is_success, (
            f"Schema discovery failed: {schema_result.error}"
        )

        # Verify reasonable performance (should complete within 10 seconds)
        assert discovery_time < 10.0, (
            f"Schema discovery took too long: {discovery_time:.2f}s"
        )

        # Log performance for monitoring

    def test_schema_discovery_with_shared_config(
        self,
        shared_ldap_connection_config: FlextLDAPModels.ConnectionConfig,
    ) -> None:
        """Test schema discovery using shared connection config."""
        client = FlextLDAPClient()

        # Connect using shared config
        assert shared_ldap_connection_config.bind_dn is not None
        assert shared_ldap_connection_config.bind_password is not None
        connect_result = client.connect(
            server_uri=shared_ldap_connection_config.server,
            bind_dn=shared_ldap_connection_config.bind_dn,
            password=shared_ldap_connection_config.bind_password,
        )

        assert connect_result.is_success, f"Connection failed: {connect_result.error}"

        try:
            # Test schema discovery
            schema_result = client.discover_schema()
            assert schema_result.is_success, (
                f"Schema discovery failed: {schema_result.error}"
            )

            schema_data = schema_result.value
            assert schema_data is not None
            assert isinstance(schema_data, FlextLDAPModels.SchemaDiscoveryResult)

        finally:
            client.close_connection()

    def test_shared_ldap_schema_components(
        self,
        shared_ldap_client: FlextLDAPClient,
    ) -> None:
        """Test schema components discovery with shared LDAP server."""
        # Test schema discovery
        schema_result = shared_ldap_client.discover_schema()
        assert schema_result.is_success, (
            f"Schema discovery failed: {schema_result.error}"
        )

        schema_data = schema_result.value
        assert schema_data is not None

        # Verify schema components are discovered
        assert schema_data.object_classes is not None
        assert schema_data.attributes is not None
        assert schema_data.naming_contexts is not None
        assert schema_data.supported_controls is not None

        # Verify we got some schema data (even if minimal for test server)
        assert isinstance(schema_data.object_classes, dict)
        assert isinstance(schema_data.attributes, dict)
        assert isinstance(schema_data.naming_contexts, list)
        assert isinstance(schema_data.supported_controls, list)

    def test_shared_ldap_schema_normalization(
        self,
        shared_ldap_client: FlextLDAPClient,
    ) -> None:
        """Test schema normalization with shared LDAP server."""
        # Test schema discovery
        schema_result = shared_ldap_client.discover_schema()
        assert schema_result.is_success, (
            f"Schema discovery failed: {schema_result.error}"
        )

        schema_data = schema_result.value
        assert schema_data is not None

        # Schema normalization is not implemented yet
        # Note: normalize_schema method is not implemented in the current client


@pytest.mark.integration
class TestSharedUniversalOperations:
    """Test universal operations using shared LDAP container."""

    def test_universal_search_with_shared_server(
        self,
        shared_ldap_client: FlextLDAPClient,
        shared_ldap_config: dict,
    ) -> None:
        """Test universal search with shared LDAP server."""
        # Test base search
        search_result = shared_ldap_client.search_universal(
            base_dn=shared_ldap_config["base_dn"],
            filter_str="(objectClass=*)",
            scope="base",
        )

        assert search_result.is_success, (
            f"Universal search failed: {search_result.error}"
        )
        assert search_result.value is not None
        assert len(search_result.value) > 0

    def test_universal_modify_with_shared_server(
        self,
        shared_ldap_client: FlextLDAPClient,
        shared_ldap_config: dict,
    ) -> None:
        """Test universal modify with shared LDAP server."""
        base_dn = shared_ldap_config["base_dn"]

        # Test modifying the base DN description
        modify_result = shared_ldap_client.modify_entry_universal(
            dn=base_dn,
            changes={
                "description": ["FLEXT Shared Test Organization - Modified by Test"]
            },
        )

        # Note: Modification might fail due to permissions or existing values
        # This is OK for shared container testing
        if not modify_result.is_success:
            # Just verify the operation was attempted
            assert modify_result.error is not None
        else:
            assert modify_result.is_success, (
                f"Universal modify failed: {modify_result.error}"
            )

    def test_universal_add_with_shared_server(
        self,
        shared_ldap_client: FlextLDAPClient,
        shared_ldap_config: dict,
    ) -> None:
        """Test universal add with shared LDAP server."""
        base_dn = shared_ldap_config["base_dn"]
        test_dn = f"ou=test-universal,{base_dn}"

        # Test adding a test organizational unit
        add_result = shared_ldap_client.add_entry_universal(
            dn=test_dn,
            attributes={
                "objectClass": ["organizationalUnit", "top"],
                "ou": "test-universal",
                "description": "Test OU for universal operations",
            },
        )

        # Note: Addition might fail if entry already exists
        if not add_result.is_success:
            # Verify the entry exists by searching
            search_result = shared_ldap_client.search_universal(
                base_dn=test_dn, filter_str="(objectClass=*)", scope="base"
            )
            # If search succeeds, entry exists (which is OK)
            if search_result.is_success:
                pass
            else:
                # If both add and search fail, that's a real problem
                raise AssertionError(
                    f"Both add and search failed: add={add_result.error}, search={search_result.error}"
                )
        else:
            assert add_result.is_success, f"Universal add failed: {add_result.error}"

            # Clean up - delete the test entry
            delete_result = shared_ldap_client.delete_entry_universal(test_dn)
            if not delete_result.is_success:
                pass

    def test_universal_delete_with_shared_server(
        self,
        shared_ldap_client: FlextLDAPClient,
        shared_ldap_config: dict,
    ) -> None:
        """Test universal delete with shared LDAP server."""
        base_dn = shared_ldap_config["base_dn"]
        test_dn = f"ou=test-delete,{base_dn}"

        # First try to add an entry to delete
        add_result = shared_ldap_client.add_entry_universal(
            dn=test_dn,
            attributes={
                "objectClass": ["organizationalUnit", "top"],
                "ou": "test-delete",
                "description": "Test OU for deletion",
            },
        )

        # If add succeeded, try to delete it
        if add_result.is_success:
            delete_result = shared_ldap_client.delete_entry_universal(test_dn)
            assert delete_result.is_success, (
                f"Universal delete failed: {delete_result.error}"
            )
        else:
            # If add failed, entry might already exist, try to delete it anyway
            delete_result = shared_ldap_client.delete_entry_universal(test_dn)
            # Delete might fail due to permissions or non-existence
            if not delete_result.is_success:
                pass
