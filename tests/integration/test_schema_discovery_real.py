"""Real LDAP schema discovery integration tests using Docker container.

This module tests schema discovery against a real OpenLDAP server,
validating server type detection, quirks handling, and normalization.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

import time

import pytest
from flext_ldif import FlextLdifModels
from flext_ldif.constants import FlextLdifConstants

from flext_ldap import FlextLdapClients, FlextLdapModels, FlextLdapSchema

# Skip all integration tests when LDAP server is not available
pytestmark = pytest.mark.integration


@pytest.mark.integration
class TestRealSchemaDiscovery:
    """Test real schema discovery operations."""

    def test_discover_schema_from_real_server(
        self, shared_ldap_client: FlextLdapClients
    ) -> None:
        """Test discovering schema from real LDAP server."""
        client = shared_ldap_client

        # Discover schema
        result = client.discover_schema()

        assert result.is_success, f"Schema discovery failed: {result.error}"
        assert result.value is not None

        schema = result.value
        assert isinstance(schema, FlextLdifModels.SchemaDiscoveryResult)
        assert schema.server_type is not None
        assert schema.server_quirks is not None

    @pytest.mark.xfail(
        reason="Type mismatch in server type detection comparison",
        strict=False,
    )
    def test_detect_server_type(self, shared_ldap_client: FlextLdapClients) -> None:
        """Test detecting server type from real server."""
        client = shared_ldap_client

        # Discover schema
        result = client.discover_schema()
        assert result.is_success

        # Get server type
        server_type = client.server_type
        assert server_type is not None

        # OpenLDAP should be detected or GENERIC (enum values)
        assert server_type in {
            FlextLdifConstants.LdapServerType.OPENLDAP,
            FlextLdifConstants.LdapServerType.GENERIC,
        }, f"Unexpected server type: {server_type}"

    def test_discover_server_capabilities(
        self, shared_ldap_client: FlextLdapClients
    ) -> None:
        """Test discovering server capabilities."""
        client = shared_ldap_client

        # Discover schema
        client.discover_schema()

        # Get server capabilities
        capabilities_result = client.get_server_capabilities()
        assert capabilities_result.is_success, (
            f"Failed to get capabilities: {capabilities_result.error}"
        )

        capabilities = capabilities_result.unwrap()
        assert capabilities is not None
        # Check it's a ServerCapabilities model
        assert isinstance(capabilities, FlextLdapModels.ServerCapabilities), (
            f"Expected ServerCapabilities, got {type(capabilities)}"
        )
        # Verify server capabilities properties
        assert hasattr(capabilities, "supports_ssl")
        assert hasattr(capabilities, "supports_paged_results")
        assert capabilities.supports_paged_results is True

    def test_self(self, shared_ldap_client: FlextLdapClients) -> None:
        """Test getting server-specific quirks."""
        client = shared_ldap_client

        # Discover schema
        client.discover_schema()

        # Get quirks
        quirks = client.server_quirks

        # Schema discovery may fail but should return default quirks
        assert quirks is not None
        assert isinstance(quirks, FlextLdapModels.ServerQuirks)
        # Default quirks should have sensible values
        assert quirks.max_page_size > 0
        assert quirks.default_timeout > 0


@pytest.mark.integration
class TestRealServerQuirksDetection:
    """Test server quirks detection with real server."""

    def test_quirks_detector_with_real_server_info(
        self, shared_ldap_client: FlextLdapClients
    ) -> None:
        """Test quirks detector with real server information."""
        client = shared_ldap_client

        # Discover schema
        discovery_result = client.discover_schema()

        # NOTE: Schema may not be available on all LDAP servers
        if discovery_result.is_failure:
            pytest.skip("Schema not available on this LDAP server")

        schema = discovery_result.value
        # discover_schema returns SchemaDiscoveryResult, not plain dict
        assert isinstance(schema, FlextLdifModels.SchemaDiscoveryResult)
        assert schema is not None  # Should have schema object

        # Test quirks detector directly
        detector = FlextLdapSchema.GenericQuirksDetector()
        # Extract server_info from schema definitions
        server_info = schema.server_info
        assert server_info is not None
        server_type = detector.detect_server_type(server_info)

        assert server_type is not None
        assert isinstance(server_type, FlextLdifConstants.LdapServerType)

        # Get quirks for detected type
        quirks = detector.get_server_quirks(str(server_type))
        assert quirks is not None
        if isinstance(quirks, dict):
            assert quirks.get("server_type") == str(server_type)
        else:
            # For non-dict objects, compare enum values directly
            # Handle both enum and string values (Pydantic may serialize enums to strings)
            quirks_server_type = getattr(quirks, "server_type", None)
            expected_values = {server_type, server_type.value}
            assert quirks_server_type in expected_values, (
                f"Expected {expected_values}, got {quirks_server_type}"
            )

    def test_openldap_detection(self, shared_ldap_client: FlextLdapClients) -> None:
        """Test OpenLDAP specific quirks detection."""
        client = shared_ldap_client

        # Discover schema
        client.discover_schema()

        quirks = client.server_quirks
        assert quirks is not None

        # OpenLDAP typically has these characteristics
        if quirks.server_type == FlextLdifConstants.LdapServerType.OPENLDAP:
            assert quirks.case_sensitive_dns is True
            assert quirks.case_sensitive_attributes is True
            assert quirks.supports_paged_results is True


@pytest.mark.integration
class TestRealSchemaNormalization:
    """Test schema normalization with real server."""

    def test_normalize_attribute_names(
        self, shared_ldap_client: FlextLdapClients
    ) -> None:
        """Test normalizing attribute names with real schema."""
        client = shared_ldap_client

        # Discover schema
        client.discover_schema()

        # Test attribute normalization
        normalized_cn = client.normalize_attribute_name("CN")
        normalized_mail = client.normalize_attribute_name("MAIL")

        # Normalization depends on server quirks
        assert normalized_cn is not None
        assert normalized_mail is not None

    def test_self(self, shared_ldap_client: FlextLdapClients) -> None:
        """Test normalizing DNs with real schema."""
        client = shared_ldap_client

        # Discover schema
        client.discover_schema()

        # Test DN normalization
        test_dn = "CN=Test,OU=Users,DC=Flext,DC=Local"
        normalized_dn = client.normalize_dn(test_dn)

        assert normalized_dn is not None
        assert isinstance(normalized_dn, str)

    def test_normalize_object_classes(
        self, shared_ldap_client: FlextLdapClients
    ) -> None:
        """Test normalizing object class names with real schema."""
        client = shared_ldap_client

        # Discover schema
        client.discover_schema()

        # Test object class normalization
        normalized_person = client.normalize_object_class("PERSON")
        normalized_group = client.normalize_object_class("GROUPOFNAMES")

        assert normalized_person is not None
        assert normalized_group is not None


@pytest.mark.integration
class TestRealUniversalOperations:
    """Test universal LDAP operations with real server."""

    def test_universal_search_with_normalization(
        self, shared_ldap_client: FlextLdapClients
    ) -> None:
        """Test universal search with automatic normalization."""
        client = shared_ldap_client

        # Discover schema for normalization
        client.discover_schema()

        # Use universal search
        result = client.search(
            base_dn="dc=flext,dc=local",
            filter_str="(objectClass=*)",
            attributes=["dc", "objectClass"],
        )

        assert result.is_success, f"Universal search failed: {result.error}"
        assert len(result.value) > 0

    def test_universal_add_with_normalization(
        self, shared_ldap_client: FlextLdapClients
    ) -> None:
        """Test universal add with automatic normalization."""
        client = shared_ldap_client

        # Discover schema
        client.discover_schema()

        # Use universal add
        result = client.add_entry(
            dn="ou=universal-test,dc=flext,dc=local",
            attributes={"objectClass": ["organizationalUnit"], "ou": "universal-test"},
        )

        assert result.is_success, f"Universal add failed: {result.error}"

        # Cleanup
        client.delete_entry(dn="ou=universal-test,dc=flext,dc=local")

    def test_schema_discovery_performance(
        self, shared_ldap_client: FlextLdapClients
    ) -> None:
        """Test schema discovery performance with real server."""
        client = shared_ldap_client

        # Measure discovery time
        start_time = time.time()
        result = client.discover_schema()
        discovery_time = time.time() - start_time

        assert result.is_success
        assert discovery_time < 10.0, (
            f"Schema discovery took {discovery_time}s (too slow)"
        )
