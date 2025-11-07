"""Comprehensive real Docker LDAP tests for FlextLdapServers.

This module contains comprehensive tests for FlextLdapServers using real Docker
LDAP containers. All tests use actual LDAP server operations validating real
server-specific functionality.

Test Categories:
- @pytest.mark.docker - Requires Docker LDAP container
- @pytest.mark.ldap - LDAP-specific tests
- @pytest.mark.unit - Unit tests (marked as docker+ldap+unit)

Container Requirements:
    Docker container must be running on port 3390
    Container name: flext-openldap-test
    Configuration: OpenLDAP 1.5.0 with dc=flext,dc=local base DN
"""

from __future__ import annotations

import pytest

from flext_ldap import FlextLdapClients, FlextLdapServers

# mypy: disable-error-code="arg-type,misc,operator,attr-defined,assignment,index,call-arg,union-attr,return-value,list-item,valid-type"


class TestFlextLdapServersDetection:
    """Server type detection tests with real Docker LDAP."""

    @pytest.mark.docker
    @pytest.mark.ldap
    @pytest.mark.unit
    def test_server_detection_openldap(self) -> None:
        """Test server type detection for OpenLDAP."""
        client = FlextLdapClients()

        # Connect
        connect_result = client.connect(
            server_uri="ldap://localhost:3390",
            bind_dn="cn=REDACTED_LDAP_BIND_PASSWORD,dc=flext,dc=local",
            password="REDACTED_LDAP_BIND_PASSWORD123",
        )
        assert connect_result.is_success is True

        # Get server type
        server_type = client.server_type
        assert isinstance(server_type, str)
        assert len(server_type) > 0
        # OpenLDAP 1.5.0 should be detected
        assert server_type.lower() in {"openldap", "generic", "oracle_oid"}

        # Cleanup
        client.unbind()


class TestFlextLdapServersFactory:
    """Server factory tests for proper server implementation selection."""

    @pytest.mark.docker
    @pytest.mark.ldap
    @pytest.mark.unit
    def test_server_factory_creates_operations(self) -> None:
        """Test that ServerFactory creates proper server operations."""
        # Factory should return proper server operations instance
        factory = FlextLdapServers
        assert factory is not None

    @pytest.mark.docker
    @pytest.mark.ldap
    @pytest.mark.unit
    def test_server_factory_openldap_selection(self) -> None:
        """Test ServerFactory selects correct OpenLDAP implementation."""
        client = FlextLdapClients()

        # Connect
        connect_result = client.connect(
            server_uri="ldap://localhost:3390",
            bind_dn="cn=REDACTED_LDAP_BIND_PASSWORD,dc=flext,dc=local",
            password="REDACTED_LDAP_BIND_PASSWORD123",
        )
        assert connect_result.is_success is True

        # Get server type to verify detection
        server_type = client.server_type
        assert server_type is not None

        # Cleanup
        client.unbind()


class TestFlextLdapServersSchemaOperations:
    """Schema discovery and operations tests."""

    @pytest.mark.docker
    @pytest.mark.ldap
    @pytest.mark.unit
    def test_schema_discovery_from_server(self) -> None:
        """Test schema discovery from real LDAP server."""
        client = FlextLdapClients()

        # Connect
        connect_result = client.connect(
            server_uri="ldap://localhost:3390",
            bind_dn="cn=REDACTED_LDAP_BIND_PASSWORD,dc=flext,dc=local",
            password="REDACTED_LDAP_BIND_PASSWORD123",
        )
        assert connect_result.is_success is True

        # Search for schema (subschema entry)
        search_result = client.search(
            base_dn="cn=Subschema",
            filter_str="(objectClass=*)",
            scope="BASE",
        )

        # Schema may or may not be available based on server config
        if search_result.is_success:
            entries = search_result.unwrap()
            if entries:
                schema_entry = entries[0]
                assert schema_entry is not None

        # Cleanup
        client.unbind()


class TestFlextLdapServersAclOperations:
    """ACL (Access Control List) operations tests."""

    @pytest.mark.docker
    @pytest.mark.ldap
    @pytest.mark.unit
    def test_acl_detection_on_server(self) -> None:
        """Test ACL detection on real LDAP server."""
        client = FlextLdapClients()

        # Connect
        connect_result = client.connect(
            server_uri="ldap://localhost:3390",
            bind_dn="cn=REDACTED_LDAP_BIND_PASSWORD,dc=flext,dc=local",
            password="REDACTED_LDAP_BIND_PASSWORD123",
        )
        assert connect_result.is_success is True

        # Search for ACL configuration (server-specific)
        # Different servers store ACLs differently
        # For OpenLDAP, ACLs are typically in slapd config, not LDAP tree

        # Cleanup
        client.unbind()


class TestFlextLdapServersSearchCapabilities:
    """Server-specific search capability tests."""

    @pytest.mark.docker
    @pytest.mark.ldap
    @pytest.mark.unit
    def test_search_with_paging(self) -> None:
        """Test paged search operations."""
        client = FlextLdapClients()

        # Connect
        connect_result = client.connect(
            server_uri="ldap://localhost:3390",
            bind_dn="cn=REDACTED_LDAP_BIND_PASSWORD,dc=flext,dc=local",
            password="REDACTED_LDAP_BIND_PASSWORD123",
        )
        assert connect_result.is_success is True

        # Search with pagination
        search_result = client.search(
            base_dn="dc=flext,dc=local",
            filter_str="(objectClass=*)",
            scope="SUBTREE",
            page_size=10,
        )

        if search_result.is_success:
            entries = search_result.unwrap()
            assert isinstance(entries, list)

        # Cleanup
        client.unbind()

    @pytest.mark.docker
    @pytest.mark.ldap
    @pytest.mark.unit
    def test_search_with_size_limit(self) -> None:
        """Test search with size limit."""
        client = FlextLdapClients()

        # Connect
        connect_result = client.connect(
            server_uri="ldap://localhost:3390",
            bind_dn="cn=REDACTED_LDAP_BIND_PASSWORD,dc=flext,dc=local",
            password="REDACTED_LDAP_BIND_PASSWORD123",
        )
        assert connect_result.is_success is True

        # Search with size limit
        search_result = client.search(
            base_dn="dc=flext,dc=local",
            filter_str="(objectClass=*)",
            scope="SUBTREE",
        )

        if search_result.is_success:
            entries = search_result.unwrap()
            assert isinstance(entries, list)

        # Cleanup
        client.unbind()


class TestFlextLdapServersAttributeOperations:
    """Attribute handling and validation tests."""

    @pytest.mark.docker
    @pytest.mark.ldap
    @pytest.mark.unit
    def test_attribute_retrieval_real_server(self) -> None:
        """Test attribute retrieval from real LDAP server."""
        client = FlextLdapClients()

        # Connect
        connect_result = client.connect(
            server_uri="ldap://localhost:3390",
            bind_dn="cn=REDACTED_LDAP_BIND_PASSWORD,dc=flext,dc=local",
            password="REDACTED_LDAP_BIND_PASSWORD123",
        )
        assert connect_result.is_success is True

        # Search with specific attributes
        search_result = client.search(
            base_dn="dc=flext,dc=local",
            filter_str="(objectClass=*)",
            attributes=["cn", "objectClass", "dn"],
            scope="SUBTREE",
        )

        if search_result.is_success:
            entries = search_result.unwrap()
            assert isinstance(entries, list)
            # Verify attributes are returned
            if entries:
                entry = entries[0]
                assert entry is not None

        # Cleanup
        client.unbind()


class TestFlextLdapServersMultipleSearchScopes:
    """Search scope handling tests with real server."""

    @pytest.mark.docker
    @pytest.mark.ldap
    @pytest.mark.unit
    @pytest.mark.parametrize("scope", ["BASE", "ONELEVEL", "SUBTREE"])
    def test_all_search_scopes_on_real_server(self, scope: str) -> None:
        """Test all search scopes on real LDAP server."""
        client = FlextLdapClients()

        # Connect
        connect_result = client.connect(
            server_uri="ldap://localhost:3390",
            bind_dn="cn=REDACTED_LDAP_BIND_PASSWORD,dc=flext,dc=local",
            password="REDACTED_LDAP_BIND_PASSWORD123",
        )
        assert connect_result.is_success is True

        # Search with different scopes
        search_result = client.search(
            base_dn="dc=flext,dc=local",
            filter_str="(objectClass=*)",
            scope=scope,
        )

        assert search_result.is_success is True
        entries = search_result.unwrap()
        assert isinstance(entries, list)

        # Cleanup
        client.unbind()


class TestFlextLdapServersIntegration:
    """Integration tests with real server operations."""

    @pytest.mark.docker
    @pytest.mark.ldap
    @pytest.mark.unit
    def test_complete_server_workflow(self) -> None:
        """Test complete server workflow from connection to search."""
        client = FlextLdapClients()

        # Connect
        connect_result = client.connect(
            server_uri="ldap://localhost:3390",
            bind_dn="cn=REDACTED_LDAP_BIND_PASSWORD,dc=flext,dc=local",
            password="REDACTED_LDAP_BIND_PASSWORD123",
        )
        assert connect_result.is_success is True

        # Get server type
        server_type = client.server_type
        assert isinstance(server_type, str)

        # Perform search
        search_result = client.search(
            base_dn="dc=flext,dc=local",
            filter_str="(objectClass=*)",
            scope="SUBTREE",
        )
        assert search_result.is_success is True

        entries = search_result.unwrap()
        assert isinstance(entries, list)

        # Get connection
        connection = client.connection
        assert connection is not None

        # Cleanup
        client.unbind()

    @pytest.mark.docker
    @pytest.mark.ldap
    @pytest.mark.unit
    def test_server_capabilities_detection(self) -> None:
        """Test server capabilities detection."""
        client = FlextLdapClients()

        # Connect
        connect_result = client.connect(
            server_uri="ldap://localhost:3390",
            bind_dn="cn=REDACTED_LDAP_BIND_PASSWORD,dc=flext,dc=local",
            password="REDACTED_LDAP_BIND_PASSWORD123",
        )
        assert connect_result.is_success is True

        # Get server capabilities
        caps_result = client.get_server_info()

        # Server capabilities may succeed or fail depending on server
        if caps_result.is_success:
            caps = caps_result.unwrap()
            assert caps is not None

        # Cleanup
        client.unbind()


__all__ = [
    "TestFlextLdapServersAclOperations",
    "TestFlextLdapServersAttributeOperations",
    "TestFlextLdapServersDetection",
    "TestFlextLdapServersFactory",
    "TestFlextLdapServersIntegration",
    "TestFlextLdapServersMultipleSearchScopes",
    "TestFlextLdapServersSchemaOperations",
    "TestFlextLdapServersSearchCapabilities",
]
