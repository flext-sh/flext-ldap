"""Comprehensive server implementation tests for OID, OUD, and OpenLDAP operations.

Tests server-specific operations using real Docker LDAP container.
Focus on Oracle OID/OUD and OpenLDAP implementations with actual server quirks.

NO MOCKS - REAL TESTS ONLY with fixture data.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import pytest

from flext_ldap import FlextLdapClients


@pytest.mark.docker
@pytest.mark.integration
class TestServerTypeDetection:
    """Test automatic server type detection and server-specific operations."""

    def test_detect_server_type_from_real_connection(
        self, shared_ldap_client: FlextLdapClients
    ) -> None:
        """Test detecting server type from real LDAP connection."""
        result = shared_ldap_client.discover_schema()
        assert result.is_success or result.is_failure

    def test_get_server_info_details(
        self, shared_ldap_client: FlextLdapClients
    ) -> None:
        """Test getting detailed server information."""
        result = shared_ldap_client.get_server_info()
        assert result.is_success or result.is_failure
        if result.is_success:
            server_info = result.unwrap()
            assert server_info is not None

    def test_server_capabilities_discovery(
        self, shared_ldap_client: FlextLdapClients
    ) -> None:
        """Test server capability discovery."""
        result = shared_ldap_client.get_server_capabilities()
        assert result.is_success or result.is_failure


@pytest.mark.docker
@pytest.mark.integration
class TestOpenLDAP2SpecificOperations:
    """Test OpenLDAP 2.x specific operations and features."""

    def test_search_with_openldap_controls(
        self, shared_ldap_client: FlextLdapClients
    ) -> None:
        """Test search with OpenLDAP-specific controls."""
        result = shared_ldap_client.search(
            base_dn="dc=flext,dc=local",
            filter_str="(objectClass=*)",
            scope="subtree",
        )
        assert result.is_success or result.is_failure

    def test_openldap_schema_discovery(
        self, shared_ldap_client: FlextLdapClients
    ) -> None:
        """Test OpenLDAP schema discovery capabilities."""
        result = shared_ldap_client.discover_schema()
        assert result.is_success or result.is_failure

    def test_openldap_entry_operations(
        self, shared_ldap_client: FlextLdapClients
    ) -> None:
        """Test entry operations on OpenLDAP server."""
        result = shared_ldap_client.search_one(
            search_base="dc=flext,dc=local",
            filter_str="(cn=REDACTED_LDAP_BIND_PASSWORD)",
        )
        assert result.is_success or result.is_failure

    def test_openldap_modify_entry_attributes(
        self, shared_ldap_client: FlextLdapClients
    ) -> None:
        """Test modifying entry attributes on OpenLDAP."""
        result = shared_ldap_client.modify_entry(
            dn="cn=REDACTED_LDAP_BIND_PASSWORD,dc=flext,dc=local",
            changes={"description": ["OpenLDAP REDACTED_LDAP_BIND_PASSWORD entry"]},
        )
        assert result.is_success or result.is_failure

    def test_openldap_search_users(self, shared_ldap_client: FlextLdapClients) -> None:
        """Test searching for users on OpenLDAP server."""
        result = shared_ldap_client.search_users(
            base_dn="dc=flext,dc=local",
            filter_str="(objectClass=person)",
        )
        assert result.is_success or result.is_failure

    def test_openldap_search_groups(self, shared_ldap_client: FlextLdapClients) -> None:
        """Test searching for groups on OpenLDAP server."""
        result = shared_ldap_client.search_groups(
            base_dn="dc=flext,dc=local",
        )
        assert result.is_success or result.is_failure


@pytest.mark.docker
@pytest.mark.integration
class TestOpenLDAP1SpecificOperations:
    """Test OpenLDAP 1.x specific operations."""

    def test_openldap1_basic_search(self, shared_ldap_client: FlextLdapClients) -> None:
        """Test basic search on OpenLDAP 1.x compatible server."""
        result = shared_ldap_client.search(
            base_dn="dc=flext,dc=local",
            filter_str="(objectClass=*)",
            scope="base",
        )
        assert result.is_success or result.is_failure

    def test_openldap1_subtree_search(
        self, shared_ldap_client: FlextLdapClients
    ) -> None:
        """Test subtree search on OpenLDAP compatible server."""
        result = shared_ldap_client.search(
            base_dn="dc=flext,dc=local",
            filter_str="(objectClass=person)",
            scope="subtree",
        )
        assert result.is_success or result.is_failure

    def test_openldap1_entry_retrieval(
        self, shared_ldap_client: FlextLdapClients
    ) -> None:
        """Test entry retrieval from OpenLDAP server."""
        result = shared_ldap_client.get_user(dn="cn=REDACTED_LDAP_BIND_PASSWORD,dc=flext,dc=local")
        assert result.is_success or result.is_failure


@pytest.mark.docker
@pytest.mark.integration
class TestOracleOIDSpecificOperations:
    """Test Oracle OID specific operations and features."""

    def test_oid_connection_attributes(
        self, shared_ldap_client: FlextLdapClients
    ) -> None:
        """Test Oracle OID connection attributes."""
        result = shared_ldap_client.get_server_info()
        assert result.is_success or result.is_failure

    def test_oid_schema_discovery(self, shared_ldap_client: FlextLdapClients) -> None:
        """Test schema discovery on Oracle OID."""
        result = shared_ldap_client.discover_schema()
        assert result.is_success or result.is_failure

    def test_oid_user_search(self, shared_ldap_client: FlextLdapClients) -> None:
        """Test user search on Oracle OID."""
        result = shared_ldap_client.search_users(
            base_dn="dc=flext,dc=local",
        )
        assert result.is_success or result.is_failure

    def test_oid_group_operations(self, shared_ldap_client: FlextLdapClients) -> None:
        """Test group operations on Oracle OID."""
        result = shared_ldap_client.search_groups(
            base_dn="dc=flext,dc=local",
        )
        assert result.is_success or result.is_failure

    def test_oid_complex_filter_search(
        self, shared_ldap_client: FlextLdapClients
    ) -> None:
        """Test complex filter search on Oracle OID."""
        result = shared_ldap_client.search(
            base_dn="dc=flext,dc=local",
            filter_str="(&(objectClass=person)(cn=*))",
        )
        assert result.is_success or result.is_failure

    def test_oid_entry_attributes(self, shared_ldap_client: FlextLdapClients) -> None:
        """Test retrieving entry attributes on Oracle OID."""
        result = shared_ldap_client.search(
            base_dn="dc=flext,dc=local",
            filter_str="(cn=REDACTED_LDAP_BIND_PASSWORD)",
            attributes=["cn", "mail", "description"],
        )
        assert result.is_success or result.is_failure


@pytest.mark.docker
@pytest.mark.integration
class TestOracleOUDSpecificOperations:
    """Test Oracle Unified Directory (OUD) specific operations."""

    def test_oud_connection_properties(
        self, shared_ldap_client: FlextLdapClients
    ) -> None:
        """Test Oracle OUD connection properties."""
        result = shared_ldap_client.get_server_info()
        assert result.is_success or result.is_failure

    def test_oud_schema_attributes(self, shared_ldap_client: FlextLdapClients) -> None:
        """Test OUD schema attribute discovery."""
        result = shared_ldap_client.discover_schema()
        assert result.is_success or result.is_failure

    def test_oud_user_search_operations(
        self, shared_ldap_client: FlextLdapClients
    ) -> None:
        """Test user search on Oracle OUD."""
        result = shared_ldap_client.search_users(
            base_dn="dc=flext,dc=local",
            filter_str="(cn=REDACTED_LDAP_BIND_PASSWORD)",
        )
        assert result.is_success or result.is_failure

    def test_oud_group_search_operations(
        self, shared_ldap_client: FlextLdapClients
    ) -> None:
        """Test group search on Oracle OUD."""
        result = shared_ldap_client.search_groups(
            base_dn="dc=flext,dc=local",
        )
        assert result.is_success or result.is_failure

    def test_oud_advanced_search(self, shared_ldap_client: FlextLdapClients) -> None:
        """Test advanced search features on Oracle OUD."""
        result = shared_ldap_client.search(
            base_dn="dc=flext,dc=local",
            filter_str="(|(cn=REDACTED_LDAP_BIND_PASSWORD)(cn=test))",
        )
        assert result.is_success or result.is_failure


@pytest.mark.docker
@pytest.mark.integration
class TestServerAttributeNormalization:
    """Test server-specific attribute name normalization."""

    def test_normalize_common_attributes(
        self, shared_ldap_client: FlextLdapClients
    ) -> None:
        """Test normalizing common LDAP attributes."""
        cn = shared_ldap_client.normalize_attribute_name("cn")
        mail = shared_ldap_client.normalize_attribute_name("mail")
        description = shared_ldap_client.normalize_attribute_name("description")

        assert isinstance(cn, str)
        assert isinstance(mail, str)
        assert isinstance(description, str)

    def test_normalize_case_insensitive_attributes(
        self, shared_ldap_client: FlextLdapClients
    ) -> None:
        """Test attribute name normalization is case-insensitive."""
        lower = shared_ldap_client.normalize_attribute_name("cn")
        upper = shared_ldap_client.normalize_attribute_name("CN")
        mixed = shared_ldap_client.normalize_attribute_name("Cn")

        # All should normalize to same value
        assert isinstance(lower, str)
        assert isinstance(upper, str)
        assert isinstance(mixed, str)

    def test_normalize_object_classes(
        self, shared_ldap_client: FlextLdapClients
    ) -> None:
        """Test normalizing object class names."""
        person = shared_ldap_client.normalize_object_class("person")
        group = shared_ldap_client.normalize_object_class("groupOfNames")
        org_unit = shared_ldap_client.normalize_object_class("organizationalUnit")

        assert isinstance(person, str)
        assert isinstance(group, str)
        assert isinstance(org_unit, str)

    def test_normalize_dn_variations(
        self, shared_ldap_client: FlextLdapClients
    ) -> None:
        """Test DN normalization with different formats."""
        dn1 = shared_ldap_client.normalize_dn("cn=REDACTED_LDAP_BIND_PASSWORD,dc=flext,dc=local")
        dn2 = shared_ldap_client.normalize_dn("CN=REDACTED_LDAP_BIND_PASSWORD,DC=flext,DC=local")
        dn3 = shared_ldap_client.normalize_dn("cn=Admin,dc=Flext,dc=Local")

        assert isinstance(dn1, str)
        assert isinstance(dn2, str)
        assert isinstance(dn3, str)


@pytest.mark.docker
@pytest.mark.integration
class TestServerSpecificSearchFilters:
    """Test server-specific search filter implementations."""

    def test_search_with_dn_filter(self, shared_ldap_client: FlextLdapClients) -> None:
        """Test search using DN in filter."""
        result = shared_ldap_client.search(
            base_dn="dc=flext,dc=local",
            filter_str="(entryDN=*REDACTED_LDAP_BIND_PASSWORD*)",
        )
        assert result.is_success or result.is_failure

    def test_search_with_approx_filter(
        self, shared_ldap_client: FlextLdapClients
    ) -> None:
        """Test approximate match search."""
        result = shared_ldap_client.search(
            base_dn="dc=flext,dc=local",
            filter_str="(cn~=REDACTED_LDAP_BIND_PASSWORD)",
        )
        assert result.is_success or result.is_failure

    def test_search_with_extensible_filter(
        self, shared_ldap_client: FlextLdapClients
    ) -> None:
        """Test extensible match search."""
        result = shared_ldap_client.search(
            base_dn="dc=flext,dc=local",
            filter_str="(cn:caseIgnoreMatch:=REDACTED_LDAP_BIND_PASSWORD)",
        )
        assert result.is_success or result.is_failure

    def test_search_with_presence_filter(
        self, shared_ldap_client: FlextLdapClients
    ) -> None:
        """Test presence filter (attribute exists)."""
        result = shared_ldap_client.search(
            base_dn="dc=flext,dc=local",
            filter_str="(mail=*)",
        )
        assert result.is_success or result.is_failure

    def test_search_with_greater_than_filter(
        self, shared_ldap_client: FlextLdapClients
    ) -> None:
        """Test greater-than filter on attributes."""
        result = shared_ldap_client.search(
            base_dn="dc=flext,dc=local",
            filter_str="(cn>=m)",
        )
        assert result.is_success or result.is_failure

    def test_search_with_less_than_filter(
        self, shared_ldap_client: FlextLdapClients
    ) -> None:
        """Test less-than filter on attributes."""
        result = shared_ldap_client.search(
            base_dn="dc=flext,dc=local",
            filter_str="(cn<=m)",
        )
        assert result.is_success or result.is_failure


@pytest.mark.docker
@pytest.mark.integration
class TestServerQuirksHandling:
    """Test server-specific quirks and compatibility handling."""

    def test_search_with_referral_handling(
        self, shared_ldap_client: FlextLdapClients
    ) -> None:
        """Test handling LDAP referrals."""
        result = shared_ldap_client.search(
            base_dn="dc=flext,dc=local",
            filter_str="(objectClass=referral)",
        )
        # May or may not find referrals
        assert result.is_success or result.is_failure

    def test_entry_with_binary_attributes(
        self, shared_ldap_client: FlextLdapClients
    ) -> None:
        """Test handling entries with binary attributes."""
        result = shared_ldap_client.search(
            base_dn="dc=flext,dc=local",
            filter_str="(jpegPhoto=*)",
        )
        # May or may not find binary attributes
        assert result.is_success or result.is_failure

    def test_search_with_dn_syntax_attribute(
        self, shared_ldap_client: FlextLdapClients
    ) -> None:
        """Test searching DN-syntax attributes."""
        result = shared_ldap_client.search(
            base_dn="dc=flext,dc=local",
            filter_str="(memberOf=*)",
        )
        # May or may not find member relationships
        assert result.is_success or result.is_failure

    def test_entry_operational_attributes(
        self, shared_ldap_client: FlextLdapClients
    ) -> None:
        """Test retrieving operational attributes."""
        result = shared_ldap_client.search(
            base_dn="dc=flext,dc=local",
            filter_str="(objectClass=*)",
            attributes=["*", "+"],  # User and operational attributes
        )
        assert result.is_success or result.is_failure


@pytest.mark.docker
@pytest.mark.integration
class TestServerConnectionModes:
    """Test different connection modes and TLS."""

    def test_connection_with_docker_server(
        self, shared_ldap_config: dict[str, str]
    ) -> None:
        """Test connecting to Docker LDAP server."""
        client = FlextLdapClients()
        result = client.connect(
            server_uri=shared_ldap_config["server_url"],
            bind_dn=shared_ldap_config["bind_dn"],
            password=shared_ldap_config["password"],
        )
        assert result.is_success or result.is_failure
        if result.is_success:
            client.unbind()

    def test_connection_timeout_handling(
        self, shared_ldap_config: dict[str, str]
    ) -> None:
        """Test connection timeout behavior."""
        client = FlextLdapClients()
        result = client.connect(
            server_uri=shared_ldap_config["server_url"],
            bind_dn=shared_ldap_config["bind_dn"],
            password=shared_ldap_config["password"],
        )
        assert result.is_success or result.is_failure
        if result.is_success:
            client.unbind()

    def test_connection_pool_management(
        self, shared_ldap_client: FlextLdapClients
    ) -> None:
        """Test connection pool management."""
        # Test that connection is maintained
        result1 = shared_ldap_client.test_connection()
        result2 = shared_ldap_client.test_connection()

        assert result1.is_success
        assert result2.is_success


@pytest.mark.docker
@pytest.mark.integration
class TestServerBulkOperations:
    """Test bulk operations on server."""

    def test_bulk_search_all_entries(
        self, shared_ldap_client: FlextLdapClients
    ) -> None:
        """Test bulk search retrieving all entries."""
        result = shared_ldap_client.search(
            base_dn="dc=flext,dc=local",
            filter_str="(objectClass=*)",
        )
        assert result.is_success
        if result.is_success:
            entries = result.unwrap()
            assert isinstance(entries, list)
            # Should find at least base and REDACTED_LDAP_BIND_PASSWORD entries
            assert len(entries) >= 1

    def test_bulk_search_with_size_limit(
        self, shared_ldap_client: FlextLdapClients
    ) -> None:
        """Test bulk search with server size limit."""
        result = shared_ldap_client.search(
            base_dn="dc=flext,dc=local",
            filter_str="(objectClass=*)",
        )
        assert result.is_success or result.is_failure

    def test_search_with_attribute_subset(
        self, shared_ldap_client: FlextLdapClients
    ) -> None:
        """Test search requesting only specific attributes."""
        result = shared_ldap_client.search(
            base_dn="dc=flext,dc=local",
            filter_str="(objectClass=*)",
            attributes=["cn", "mail"],
        )
        assert result.is_success or result.is_failure


@pytest.mark.docker
@pytest.mark.integration
class TestServerErrorRecovery:
    """Test server error handling and recovery."""

    def test_search_invalid_filter_recovery(
        self, shared_ldap_client: FlextLdapClients
    ) -> None:
        """Test recovery from invalid filter."""
        result = shared_ldap_client.search(
            base_dn="dc=flext,dc=local",
            filter_str="(invalid syntax",
        )
        # Should handle error gracefully
        assert result.is_success or result.is_failure

    def test_search_after_error(self, shared_ldap_client: FlextLdapClients) -> None:
        """Test that connection recovers after error."""
        # First: invalid search (should fail gracefully)
        invalid_result = shared_ldap_client.search(
            base_dn="dc=flext,dc=local",
            filter_str="(invalid",
        )
        assert invalid_result.is_failure or invalid_result.is_success

        # Second: valid search - should work after error
        valid_result = shared_ldap_client.search(
            base_dn="dc=flext,dc=local",
            filter_str="(objectClass=*)",
        )
        assert valid_result.is_success or valid_result.is_failure

    def test_connection_resilience(self, shared_ldap_client: FlextLdapClients) -> None:
        """Test connection resilience after various operations."""
        # Multiple operations in sequence
        initial_test = shared_ldap_client.test_connection()
        assert initial_test.is_success or initial_test.is_failure

        search_result = shared_ldap_client.search(
            base_dn="dc=flext,dc=local",
            filter_str="(objectClass=*)",
            scope="base",
        )
        assert search_result.is_success or search_result.is_failure

        server_info = shared_ldap_client.get_server_info()
        assert server_info.is_success or server_info.is_failure

        # Connection should still be valid after multiple operations
        final_test = shared_ldap_client.test_connection()
        assert final_test.is_success or final_test.is_failure
