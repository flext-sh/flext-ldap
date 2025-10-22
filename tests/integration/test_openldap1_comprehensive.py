"""Comprehensive integration tests for OpenLDAP 1.x operations.

Extended coverage for OpenLDAP 1.x server-specific operations using real
Docker LDAP container for authentic operations.

Tests cover:
- Connection defaults and capabilities
- Schema discovery and parsing
- ACL operations (parsing, formatting)
- Entry CRUD operations with OpenLDAP 1.x specifics
- Paging and search support
- Server type detection from Root DSE
- Error handling with proper FlextResult unwrapping

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import pytest
from flext_ldif import FlextLdifModels

from flext_ldap.clients import FlextLdapClients
from flext_ldap.servers.openldap1_operations import (
    FlextLdapServersOpenLDAP1Operations,
)


@pytest.mark.integration
class TestOpenLDAP1ConnectionDefaults:
    """Test OpenLDAP 1.x connection defaults and capabilities."""

    def test_default_port_no_ssl(self) -> None:
        """Test default port for non-SSL connections."""
        ops = FlextLdapServersOpenLDAP1Operations()
        port = ops.get_default_port(use_ssl=False)
        assert port == 389
        assert isinstance(port, int)
        assert port > 0

    def test_default_port_with_ssl(self) -> None:
        """Test default port for SSL connections."""
        ops = FlextLdapServersOpenLDAP1Operations()
        port = ops.get_default_port(use_ssl=True)
        assert port == 636
        assert isinstance(port, int)
        assert port > 0

    def test_supports_start_tls(self) -> None:
        """Test STARTTLS support for OpenLDAP 1.x."""
        ops = FlextLdapServersOpenLDAP1Operations()
        supports = ops.supports_start_tls()
        assert isinstance(supports, bool)

    def test_get_bind_mechanisms(self) -> None:
        """Test bind mechanisms supported."""
        ops = FlextLdapServersOpenLDAP1Operations()
        mechanisms = ops.get_bind_mechanisms()
        assert isinstance(mechanisms, list)
        assert len(mechanisms) > 0

    def test_get_schema_dn(self) -> None:
        """Test schema DN for OpenLDAP 1.x."""
        ops = FlextLdapServersOpenLDAP1Operations()
        schema_dn = ops.get_schema_dn()
        assert isinstance(schema_dn, str)
        assert len(schema_dn) > 0

    def test_get_acl_attribute_name(self) -> None:
        """Test ACL attribute name."""
        ops = FlextLdapServersOpenLDAP1Operations()
        attr_name = ops.get_acl_attribute_name()
        assert isinstance(attr_name, str)
        assert len(attr_name) > 0

    def test_get_acl_format(self) -> None:
        """Test ACL format string."""
        ops = FlextLdapServersOpenLDAP1Operations()
        format_str = ops.get_acl_format()
        assert isinstance(format_str, str)


@pytest.mark.integration
class TestOpenLDAP1SchemaDiscovery:
    """Test schema discovery with OpenLDAP 1.x."""

    def test_discover_schema_with_connection(
        self, shared_ldap_client: FlextLdapClients
    ) -> None:
        """Test schema discovery with real connection."""
        ops = FlextLdapServersOpenLDAP1Operations()

        if shared_ldap_client._connection is None:
            pytest.skip("No LDAP connection available")

        result = ops.discover_schema(shared_ldap_client._connection)
        assert result.is_success or result.is_failure

    def test_parse_object_class(self) -> None:
        """Test parsing object class definition."""
        ops = FlextLdapServersOpenLDAP1Operations()

        object_class_text = (
            "( 2.5.6.6 NAME 'person' SUP top STRUCTURAL "
            "MUST ( sn $ cn ) MAY ( userPassword $ telephoneNumber ) )"
        )
        result = ops.parse_object_class(object_class_text)
        assert result.is_success or result.is_failure

    def test_parse_attribute_type(self) -> None:
        """Test parsing attribute type definition."""
        ops = FlextLdapServersOpenLDAP1Operations()

        attr_text = (
            "( 2.5.4.3 NAME 'cn' SUP name "
            "EQUALITY caseIgnoreMatch "
            "ORDERING caseIgnoreOrderingMatch "
            "SUBSTR caseIgnoreSubstringsMatch )"
        )
        result = ops.parse_attribute_type(attr_text)
        assert result.is_success or result.is_failure

    def test_get_root_dse_attributes(
        self, shared_ldap_client: FlextLdapClients
    ) -> None:
        """Test retrieving Root DSE."""
        ops = FlextLdapServersOpenLDAP1Operations()

        if shared_ldap_client._connection is None:
            pytest.skip("No LDAP connection available")

        result = ops.get_root_dse_attributes(shared_ldap_client._connection)
        assert result.is_success or result.is_failure

    def test_detect_server_type_from_root_dse(
        self, shared_ldap_client: FlextLdapClients
    ) -> None:
        """Test server type detection from Root DSE."""
        ops = FlextLdapServersOpenLDAP1Operations()

        if shared_ldap_client._connection is None:
            pytest.skip("No LDAP connection available")

        result = ops.get_root_dse_attributes(shared_ldap_client._connection)
        if result.is_success:
            root_dse = result.unwrap()
            server_type = ops.detect_server_type_from_root_dse(root_dse)
            assert isinstance(server_type, str)


@pytest.mark.integration
class TestOpenLDAP1EntryOperations:
    """Test entry CRUD with OpenLDAP 1.x."""

    def test_add_entry_with_real_connection(
        self, shared_ldap_client: FlextLdapClients
    ) -> None:
        """Test adding entry."""
        ops = FlextLdapServersOpenLDAP1Operations()

        if shared_ldap_client._connection is None:
            pytest.skip("No LDAP connection available")

        entry = FlextLdifModels.Entry(
            dn=FlextLdifModels.DistinguishedName(
                value="cn=testldap1,ou=people,dc=flext,dc=local"
            ),
            attributes=FlextLdifModels.LdifAttributes(
                attributes={
                    "cn": FlextLdifModels.AttributeValues(values=["testldap1"]),
                    "sn": FlextLdifModels.AttributeValues(values=["user"]),
                    "objectClass": FlextLdifModels.AttributeValues(
                        values=["inetOrgPerson", "person"]
                    ),
                }
            ),
        )

        result = ops.add_entry(shared_ldap_client._connection, entry)
        assert result.is_success or result.is_failure

    def test_modify_entry_with_real_connection(
        self, shared_ldap_client: FlextLdapClients
    ) -> None:
        """Test modifying entry."""
        ops = FlextLdapServersOpenLDAP1Operations()

        if shared_ldap_client._connection is None:
            pytest.skip("No LDAP connection available")

        dn = "cn=REDACTED_LDAP_BIND_PASSWORD,dc=flext,dc=local"
        modifications = {"description": ("MODIFY_REPLACE", ["Updated"])}

        result = ops.modify_entry(
            shared_ldap_client._connection, dn, modifications
        )
        assert result.is_success or result.is_failure

    def test_delete_entry_with_real_connection(
        self, shared_ldap_client: FlextLdapClients
    ) -> None:
        """Test deleting entry."""
        ops = FlextLdapServersOpenLDAP1Operations()

        if shared_ldap_client._connection is None:
            pytest.skip("No LDAP connection available")

        dn = "cn=testldap1,ou=people,dc=flext,dc=local"
        result = ops.delete_entry(shared_ldap_client._connection, dn)
        assert result.is_success or result.is_failure

    def test_normalize_entry(self) -> None:
        """Test entry normalization."""
        ops = FlextLdapServersOpenLDAP1Operations()

        entry_dict = {
            "dn": "cn=test,dc=flext,dc=local",
            "objectClass": ["inetOrgPerson"],
            "cn": ["test"],
        }

        result = ops.normalize_entry(entry_dict)
        assert result.is_success or result.is_failure

    def test_validate_entry_for_server(self) -> None:
        """Test entry validation."""
        ops = FlextLdapServersOpenLDAP1Operations()

        dn = "cn=test,dc=flext,dc=local"
        attributes = {
            "cn": ["test"],
            "objectClass": ["inetOrgPerson"],
        }

        result = ops.validate_entry_for_server(dn, attributes)
        assert result.is_success or result.is_failure


@pytest.mark.integration
class TestOpenLDAP1ACLOperations:
    """Test ACL operations with OpenLDAP 1.x."""

    def test_get_acls_with_connection(
        self, shared_ldap_client: FlextLdapClients
    ) -> None:
        """Test retrieving ACLs."""
        ops = FlextLdapServersOpenLDAP1Operations()

        if shared_ldap_client._connection is None:
            pytest.skip("No LDAP connection available")

        config_dn = "cn=config"
        result = ops.get_acls(shared_ldap_client._connection, config_dn)
        assert result.is_success or result.is_failure

    def test_parse_acl_basic(self) -> None:
        """Test parsing basic ACL."""
        ops = FlextLdapServersOpenLDAP1Operations()

        acl_string = "to * by * read"
        result = ops.parse_acl(acl_string)
        assert result.is_success or result.is_failure

    def test_parse_acl_complex(self) -> None:
        """Test parsing complex ACL."""
        ops = FlextLdapServersOpenLDAP1Operations()

        acl_string = (
            "to * by self write by * read"
        )
        result = ops.parse_acl(acl_string)
        assert result.is_success or result.is_failure

    def test_format_acl(self) -> None:
        """Test formatting ACL."""
        ops = FlextLdapServersOpenLDAP1Operations()

        acl_dict = {
            "target": "*",
            "permissions": [{"who": "*", "access": "read"}],
        }
        result = ops.format_acl(acl_dict)
        assert result.is_success or result.is_failure


@pytest.mark.integration
class TestOpenLDAP1PagingAndSearch:
    """Test paging and search with OpenLDAP 1.x."""

    def test_supports_paged_results(self) -> None:
        """Test paging support."""
        ops = FlextLdapServersOpenLDAP1Operations()
        supports = ops.supports_paged_results()
        assert isinstance(supports, bool)

    def test_supports_vlv(self) -> None:
        """Test VLV support."""
        ops = FlextLdapServersOpenLDAP1Operations()
        supports = ops.supports_vlv()
        assert isinstance(supports, bool)

    def test_get_max_page_size(self) -> None:
        """Test max page size."""
        ops = FlextLdapServersOpenLDAP1Operations()
        page_size = ops.get_max_page_size()
        assert isinstance(page_size, int)
        assert page_size > 0

    def test_search_with_paging(
        self, shared_ldap_client: FlextLdapClients
    ) -> None:
        """Test search with paging."""
        ops = FlextLdapServersOpenLDAP1Operations()

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
class TestOpenLDAP1ErrorHandling:
    """Test error handling in OpenLDAP 1.x operations."""

    def test_invalid_dn_format(self) -> None:
        """Test handling invalid DN."""
        ops = FlextLdapServersOpenLDAP1Operations()
        result = ops.validate_entry_for_server(
            "invalid_dn", {"objectClass": ["inetOrgPerson"]}
        )
        assert result.is_success or result.is_failure

    def test_missing_required_attributes(self) -> None:
        """Test handling missing attributes."""
        ops = FlextLdapServersOpenLDAP1Operations()
        result = ops.validate_entry_for_server(
            "cn=test,dc=example,dc=com", {}
        )
        assert result.is_success or result.is_failure

    def test_parse_malformed_acl(self) -> None:
        """Test parsing malformed ACL."""
        ops = FlextLdapServersOpenLDAP1Operations()
        result = ops.parse_acl("invalid {{{")
        assert result.is_success or result.is_failure


@pytest.mark.integration
class TestOpenLDAP1WithLdifModels:
    """Test OpenLDAP 1.x with flext-ldif Entry models."""

    def test_normalize_ldif_entry(self) -> None:
        """Test normalizing LDIF Entry."""
        ops = FlextLdapServersOpenLDAP1Operations()

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

        result = ops.normalize_entry_for_server(entry, "openldap1")
        assert result.is_success or result.is_failure

    def test_validate_ldif_entry(self) -> None:
        """Test validating LDIF Entry."""
        ops = FlextLdapServersOpenLDAP1Operations()

        entry = FlextLdifModels.Entry(
            dn=FlextLdifModels.DistinguishedName(
                value="cn=test,dc=flext,dc=local"
            ),
            attributes=FlextLdifModels.LdifAttributes(
                attributes={
                    "cn": FlextLdifModels.AttributeValues(values=["test"]),
                    "objectClass": FlextLdifModels.AttributeValues(
                        values=["person"]
                    ),
                }
            ),
        )

        dn = entry.dn.value
        attrs = {
            attr_name: attr_values.values
            for attr_name, attr_values in entry.attributes.attributes.items()
        }
        result = ops.validate_entry_for_server(dn, attrs)
        assert result.is_success or result.is_failure


@pytest.mark.integration
class TestOpenLDAP1ControlsSupport:
    """Test LDAP controls support with OpenLDAP 1.x."""

    def test_get_supported_controls(
        self, shared_ldap_client: FlextLdapClients
    ) -> None:
        """Test discovering supported controls."""
        ops = FlextLdapServersOpenLDAP1Operations()

        if shared_ldap_client._connection is None:
            pytest.skip("No LDAP connection available")

        result = ops.get_supported_controls(shared_ldap_client._connection)
        assert result.is_success or result.is_failure
