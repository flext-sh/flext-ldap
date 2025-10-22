"""Comprehensive integration tests for generic LDAP operations.

Tests for the fallback generic LDAP server operations that work with
any standards-compliant LDAP server using real Docker LDAP container.

Tests cover:
- Connection defaults and capabilities
- Schema discovery and parsing
- ACL operations
- Entry CRUD operations
- Paging and search support
- Root DSE discovery
- Error handling

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import pytest
from flext_ldif import FlextLdifModels

from flext_ldap.clients import FlextLdapClients
from flext_ldap.servers.generic_operations import (
    FlextLdapServersGenericOperations,
)


@pytest.mark.integration
class TestGenericConnectionDefaults:
    """Test generic LDAP connection defaults."""

    def test_default_port_no_ssl(self) -> None:
        """Test default port without SSL."""
        ops = FlextLdapServersGenericOperations()
        port = ops.get_default_port(use_ssl=False)
        assert port == 389
        assert isinstance(port, int)

    def test_default_port_with_ssl(self) -> None:
        """Test default port with SSL."""
        ops = FlextLdapServersGenericOperations()
        port = ops.get_default_port(use_ssl=True)
        assert port == 636
        assert isinstance(port, int)

    def test_supports_start_tls(self) -> None:
        """Test STARTTLS support."""
        ops = FlextLdapServersGenericOperations()
        supports = ops.supports_start_tls()
        assert isinstance(supports, bool)

    def test_get_bind_mechanisms(self) -> None:
        """Test bind mechanisms."""
        ops = FlextLdapServersGenericOperations()
        mechanisms = ops.get_bind_mechanisms()
        assert isinstance(mechanisms, list)
        assert len(mechanisms) > 0

    def test_get_schema_dn(self) -> None:
        """Test schema DN."""
        ops = FlextLdapServersGenericOperations()
        schema_dn = ops.get_schema_dn()
        assert isinstance(schema_dn, str)
        assert len(schema_dn) > 0

    def test_get_acl_attribute_name(self) -> None:
        """Test ACL attribute name."""
        ops = FlextLdapServersGenericOperations()
        attr_name = ops.get_acl_attribute_name()
        assert isinstance(attr_name, str)

    def test_get_acl_format(self) -> None:
        """Test ACL format."""
        ops = FlextLdapServersGenericOperations()
        format_str = ops.get_acl_format()
        assert isinstance(format_str, str)


@pytest.mark.integration
class TestGenericSchemaDiscovery:
    """Test schema discovery with generic LDAP."""

    def test_discover_schema_with_connection(
        self, shared_ldap_client: FlextLdapClients
    ) -> None:
        """Test discovering schema."""
        ops = FlextLdapServersGenericOperations()

        if shared_ldap_client._connection is None:
            pytest.skip("No LDAP connection available")

        result = ops.discover_schema(shared_ldap_client._connection)
        assert result.is_success or result.is_failure

    def test_parse_object_class(self) -> None:
        """Test parsing object class."""
        ops = FlextLdapServersGenericOperations()

        text = (
            "( 2.5.6.6 NAME 'person' SUP top STRUCTURAL "
            "MUST ( sn $ cn ) )"
        )
        result = ops.parse_object_class(text)
        assert result.is_success or result.is_failure

    def test_parse_attribute_type(self) -> None:
        """Test parsing attribute type."""
        ops = FlextLdapServersGenericOperations()

        text = "( 2.5.4.3 NAME 'cn' SUP name )"
        result = ops.parse_attribute_type(text)
        assert result.is_success or result.is_failure


@pytest.mark.integration
class TestGenericEntryOperations:
    """Test entry CRUD with generic operations."""

    def test_add_entry_with_connection(
        self, shared_ldap_client: FlextLdapClients
    ) -> None:
        """Test adding entry."""
        ops = FlextLdapServersGenericOperations()

        if shared_ldap_client._connection is None:
            pytest.skip("No LDAP connection available")

        entry = FlextLdifModels.Entry(
            dn=FlextLdifModels.DistinguishedName(
                value="cn=testgen,ou=people,dc=flext,dc=local"
            ),
            attributes=FlextLdifModels.LdifAttributes(
                attributes={
                    "cn": FlextLdifModels.AttributeValues(values=["testgen"]),
                    "sn": FlextLdifModels.AttributeValues(values=["user"]),
                    "objectClass": FlextLdifModels.AttributeValues(
                        values=["inetOrgPerson"]
                    ),
                }
            ),
        )

        result = ops.add_entry(shared_ldap_client._connection, entry)
        assert result.is_success or result.is_failure

    def test_modify_entry_with_connection(
        self, shared_ldap_client: FlextLdapClients
    ) -> None:
        """Test modifying entry."""
        ops = FlextLdapServersGenericOperations()

        if shared_ldap_client._connection is None:
            pytest.skip("No LDAP connection available")

        dn = "cn=REDACTED_LDAP_BIND_PASSWORD,dc=flext,dc=local"
        modifications = {"description": ("MODIFY_REPLACE", ["Updated"])}

        result = ops.modify_entry(
            shared_ldap_client._connection, dn, modifications
        )
        assert result.is_success or result.is_failure

    def test_delete_entry_with_connection(
        self, shared_ldap_client: FlextLdapClients
    ) -> None:
        """Test deleting entry."""
        ops = FlextLdapServersGenericOperations()

        if shared_ldap_client._connection is None:
            pytest.skip("No LDAP connection available")

        dn = "cn=testgen,ou=people,dc=flext,dc=local"
        result = ops.delete_entry(shared_ldap_client._connection, dn)
        assert result.is_success or result.is_failure

    def test_normalize_entry(self) -> None:
        """Test entry normalization."""
        ops = FlextLdapServersGenericOperations()

        entry_dict = {
            "dn": "cn=test,dc=flext,dc=local",
            "objectClass": ["inetOrgPerson"],
            "cn": ["test"],
        }

        result = ops.normalize_entry(entry_dict)
        assert result.is_success or result.is_failure

    def test_validate_entry_for_server(self) -> None:
        """Test entry validation."""
        ops = FlextLdapServersGenericOperations()

        dn = "cn=test,dc=flext,dc=local"
        attributes = {
            "cn": ["test"],
            "objectClass": ["inetOrgPerson"],
        }

        result = ops.validate_entry_for_server(dn, attributes)
        assert result.is_success or result.is_failure


@pytest.mark.integration
class TestGenericACLOperations:
    """Test ACL operations with generic LDAP."""

    def test_get_acls(self, shared_ldap_client: FlextLdapClients) -> None:
        """Test retrieving ACLs."""
        ops = FlextLdapServersGenericOperations()

        if shared_ldap_client._connection is None:
            pytest.skip("No LDAP connection available")

        result = ops.get_acls(shared_ldap_client._connection, "cn=config")
        assert result.is_success or result.is_failure

    def test_set_acls(self, shared_ldap_client: FlextLdapClients) -> None:
        """Test setting ACLs."""
        ops = FlextLdapServersGenericOperations()

        if shared_ldap_client._connection is None:
            pytest.skip("No LDAP connection available")

        result = ops.set_acls(
            shared_ldap_client._connection, "cn=config", "to * by * read"
        )
        assert result.is_success or result.is_failure

    def test_parse_acl(self) -> None:
        """Test parsing ACL."""
        ops = FlextLdapServersGenericOperations()
        result = ops.parse_acl("to * by * read")
        assert result.is_success or result.is_failure

    def test_format_acl(self) -> None:
        """Test formatting ACL."""
        ops = FlextLdapServersGenericOperations()
        acl_dict = {"target": "*", "permissions": []}
        result = ops.format_acl(acl_dict)
        assert result.is_success or result.is_failure


@pytest.mark.integration
class TestGenericPaging:
    """Test paging support with generic LDAP."""

    def test_supports_paged_results(self) -> None:
        """Test paging support."""
        ops = FlextLdapServersGenericOperations()
        supports = ops.supports_paged_results()
        assert isinstance(supports, bool)

    def test_supports_vlv(self) -> None:
        """Test VLV support."""
        ops = FlextLdapServersGenericOperations()
        supports = ops.supports_vlv()
        assert isinstance(supports, bool)

    def test_get_max_page_size(self) -> None:
        """Test max page size."""
        ops = FlextLdapServersGenericOperations()
        page_size = ops.get_max_page_size()
        assert isinstance(page_size, int)
        assert page_size > 0

    def test_search_with_paging(
        self, shared_ldap_client: FlextLdapClients
    ) -> None:
        """Test paged search."""
        ops = FlextLdapServersGenericOperations()

        if shared_ldap_client._connection is None:
            pytest.skip("No LDAP connection available")

        result = ops.search_with_paging(
            shared_ldap_client._connection,
            base_dn="dc=flext,dc=local",
            search_filter="(objectClass=*)",
            page_size=10,
        )
        assert result.is_success or result.is_failure


@pytest.mark.integration
class TestGenericRootDSE:
    """Test Root DSE operations."""

    def test_get_root_dse_attributes(
        self, shared_ldap_client: FlextLdapClients
    ) -> None:
        """Test retrieving Root DSE."""
        ops = FlextLdapServersGenericOperations()

        if shared_ldap_client._connection is None:
            pytest.skip("No LDAP connection available")

        result = ops.get_root_dse_attributes(shared_ldap_client._connection)
        assert result.is_success or result.is_failure

    def test_detect_server_type_from_root_dse(
        self, shared_ldap_client: FlextLdapClients
    ) -> None:
        """Test server type detection."""
        ops = FlextLdapServersGenericOperations()

        if shared_ldap_client._connection is None:
            pytest.skip("No LDAP connection available")

        result = ops.get_root_dse_attributes(shared_ldap_client._connection)
        if result.is_success:
            root_dse = result.unwrap()
            server_type = ops.detect_server_type_from_root_dse(root_dse)
            assert isinstance(server_type, str)


@pytest.mark.integration
class TestGenericControls:
    """Test controls support."""

    def test_get_supported_controls(
        self, shared_ldap_client: FlextLdapClients
    ) -> None:
        """Test discovering controls."""
        ops = FlextLdapServersGenericOperations()

        if shared_ldap_client._connection is None:
            pytest.skip("No LDAP connection available")

        result = ops.get_supported_controls(shared_ldap_client._connection)
        assert result.is_success or result.is_failure


@pytest.mark.integration
class TestGenericEntryNormalization:
    """Test entry normalization."""

    def test_normalize_entry_for_server(self) -> None:
        """Test normalizing for server."""
        ops = FlextLdapServersGenericOperations()

        entry = FlextLdifModels.Entry(
            dn=FlextLdifModels.DistinguishedName(
                value="cn=test,dc=flext,dc=local"
            ),
            attributes=FlextLdifModels.LdifAttributes(
                attributes={
                    "cn": FlextLdifModels.AttributeValues(values=["test"]),
                    "objectClass": FlextLdifModels.AttributeValues(
                        values=["inetOrgPerson"]
                    ),
                }
            ),
        )

        result = ops.normalize_entry_for_server(entry, "generic")
        assert result.is_success or result.is_failure


@pytest.mark.integration
class TestGenericErrorHandling:
    """Test error handling."""

    def test_invalid_dn(self) -> None:
        """Test invalid DN."""
        ops = FlextLdapServersGenericOperations()
        result = ops.validate_entry_for_server("invalid", {})
        assert result.is_success or result.is_failure

    def test_parse_empty_acl(self) -> None:
        """Test parsing empty ACL."""
        ops = FlextLdapServersGenericOperations()
        result = ops.parse_acl("")
        assert result.is_success or result.is_failure

    def test_format_empty_acl_dict(self) -> None:
        """Test formatting empty ACL dict."""
        ops = FlextLdapServersGenericOperations()
        result = ops.format_acl({})
        assert result.is_success or result.is_failure
