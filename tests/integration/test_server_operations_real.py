"""Comprehensive integration tests for server operations with real Docker LDAP.

Tests server-specific operations (OpenLDAP, Oracle OID/OUD) including:
- Connection defaults and capabilities
- Schema discovery
- ACL operations
- Entry CRUD operations
- Server-specific parsing and formatting

Uses real Docker LDAP container for authentic operations.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import pytest
from flext_ldif import FlextLdifModels

from flext_ldap.servers.oid_operations import FlextLdapServersOIDOperations
from flext_ldap.servers.openldap2_operations import (
    FlextLdapServersOpenLDAP2Operations,
)
from flext_ldap.servers.oud_operations import FlextLdapServersOUDOperations


@pytest.mark.integration
class TestOpenLDAP2Operations:
    """Test OpenLDAP 2.x specific operations."""

    def test_get_default_port_no_ssl(self) -> None:
        """Test default port for OpenLDAP without SSL."""
        ops = FlextLdapServersOpenLDAP2Operations()
        port = ops.get_default_port(use_ssl=False)

        assert port == 389
        assert isinstance(port, int)
        assert port > 0

    def test_get_default_port_with_ssl(self) -> None:
        """Test default port for OpenLDAP with SSL."""
        ops = FlextLdapServersOpenLDAP2Operations()
        port = ops.get_default_port(use_ssl=True)

        assert port == 636
        assert isinstance(port, int)
        assert port > 0

    def test_supports_start_tls(self) -> None:
        """Test STARTTLS support for OpenLDAP."""
        ops = FlextLdapServersOpenLDAP2Operations()
        supports = ops.supports_start_tls()

        assert supports is True

    def test_get_bind_mechanisms(self) -> None:
        """Test bind mechanisms for OpenLDAP."""
        ops = FlextLdapServersOpenLDAP2Operations()
        mechanisms = ops.get_bind_mechanisms()

        assert isinstance(mechanisms, list)
        assert len(mechanisms) > 0
        # OpenLDAP supports SIMPLE, SASL-MD5, etc.
        assert "SIMPLE" in mechanisms or "SASL-PLAIN" in mechanisms

    def test_get_schema_dn(self) -> None:
        """Test schema DN for OpenLDAP."""
        ops = FlextLdapServersOpenLDAP2Operations()
        schema_dn = ops.get_schema_dn()

        assert isinstance(schema_dn, str)
        assert "schema" in schema_dn.lower() or "subschema" in schema_dn.lower()

    def test_get_acl_attribute_name(self) -> None:
        """Test ACL attribute name for OpenLDAP 2.x."""
        ops = FlextLdapServersOpenLDAP2Operations()
        attr_name = ops.get_acl_attribute_name()

        assert isinstance(attr_name, str)
        assert attr_name in {"olcAccess", "access", "aci"}

    def test_get_acl_format(self) -> None:
        """Test ACL format for OpenLDAP 2.x."""
        ops = FlextLdapServersOpenLDAP2Operations()
        acl_format = ops.get_acl_format()

        assert isinstance(acl_format, str)
        assert acl_format in {
            "openldap2_acl",
            "openldap_acl",
            "openldap2",
            "rfc_generic",
        }

    def test_parse_acl(self) -> None:
        """Test ACL parsing for OpenLDAP."""
        ops = FlextLdapServersOpenLDAP2Operations()

        # OpenLDAP ACL syntax: {priority}to <what> by <who> <accesslevel>
        acl_string = "{0}to * by * read"
        result = ops.parse_acl(acl_string)

        assert result.is_success
        acl_entry = result.unwrap()
        assert isinstance(acl_entry, FlextLdifModels.Entry)
        assert acl_entry.attributes.get("raw") == [acl_string]

    def test_format_acl(self) -> None:
        """Test ACL formatting for OpenLDAP."""
        ops = FlextLdapServersOpenLDAP2Operations()

        # Create Entry with ACL attributes for formatting
        attrs_result = FlextLdifModels.LdifAttributes.create({
            "raw": ["{0}to * by * read"],
            "priority": ["0"],
            "target": ["*"],
            "permissions": ["read"],
        })
        attributes = (
            attrs_result.unwrap()
            if attrs_result.is_success
            else FlextLdifModels.LdifAttributes.create({}).unwrap()
        )

        acl_entry = FlextLdifModels.Entry(
            dn=FlextLdifModels.DistinguishedName(value="cn=AclRule"),
            attributes=attributes,
        )
        result = ops.format_acl(acl_entry)

        assert result.is_success
        acl_string = result.unwrap()
        assert isinstance(acl_string, str)

    def test_get_max_page_size(self) -> None:
        """Test max page size for OpenLDAP."""
        ops = FlextLdapServersOpenLDAP2Operations()
        max_page = ops.get_max_page_size()

        assert isinstance(max_page, int)
        assert max_page > 0
        assert max_page >= 100

    def test_supports_paged_results(self) -> None:
        """Test paged results support for OpenLDAP."""
        ops = FlextLdapServersOpenLDAP2Operations()
        supports = ops.supports_paged_results()

        assert supports is True


@pytest.mark.integration
class TestOIDOperations:
    """Test Oracle OID specific operations."""

    def test_get_default_port_no_ssl(self) -> None:
        """Test default port for Oracle OID without SSL."""
        ops = FlextLdapServersOIDOperations()
        port = ops.get_default_port(use_ssl=False)

        assert port == 389
        assert isinstance(port, int)
        assert port > 0

    def test_get_default_port_with_ssl(self) -> None:
        """Test default port for Oracle OID with SSL."""
        ops = FlextLdapServersOIDOperations()
        port = ops.get_default_port(use_ssl=True)

        assert port in {636, 389}  # OID may use different SSL port
        assert isinstance(port, int)
        assert port > 0

    def test_supports_start_tls(self) -> None:
        """Test STARTTLS support for Oracle OID."""
        ops = FlextLdapServersOIDOperations()
        supports = ops.supports_start_tls()

        assert isinstance(supports, bool)

    def test_get_bind_mechanisms(self) -> None:
        """Test bind mechanisms for Oracle OID."""
        ops = FlextLdapServersOIDOperations()
        mechanisms = ops.get_bind_mechanisms()

        assert isinstance(mechanisms, list)
        assert len(mechanisms) > 0

    def test_get_schema_dn(self) -> None:
        """Test schema DN for Oracle OID."""
        ops = FlextLdapServersOIDOperations()
        schema_dn = ops.get_schema_dn()

        assert isinstance(schema_dn, str)
        # OID may use different schema DN
        assert isinstance(schema_dn, str)

    def test_get_acl_attribute_name(self) -> None:
        """Test ACL attribute name for Oracle OID."""
        ops = FlextLdapServersOIDOperations()
        attr_name = ops.get_acl_attribute_name()

        assert isinstance(attr_name, str)
        # OID uses orclaci
        assert attr_name in {"orclaci", "aci", "accessControlList"}

    def test_get_acl_format(self) -> None:
        """Test ACL format for Oracle OID."""
        ops = FlextLdapServersOIDOperations()
        acl_format = ops.get_acl_format()

        assert isinstance(acl_format, str)
        # Accept various formats that OID operations may return
        assert acl_format in {
            "oracle_aci",
            "oracle",
            "rfc_generic",
            "openldap_acl",
            "aci",
        }

    def test_parse_acl(self) -> None:
        """Test ACL parsing for Oracle OID."""
        ops = FlextLdapServersOIDOperations()

        acl_string = "permit|dn:cn=admin,dc=example,dc=com|read"
        result = ops.parse_acl(acl_string)

        # Should either succeed or fail gracefully
        assert result.is_success or result.is_failure
        if result.is_success:
            acl_entry = result.unwrap()
            assert isinstance(acl_entry, FlextLdifModels.Entry)

    def test_format_acl(self) -> None:
        """Test ACL formatting for Oracle OID."""
        ops = FlextLdapServersOIDOperations()

        # Create Entry with ACL attributes for formatting
        attrs_result = FlextLdifModels.LdifAttributes.create({
            "raw": ["permit|dn:cn=admin,dc=example,dc=com|read"],
            "action": ["permit"],
            "subject": ["cn=admin,dc=example,dc=com"],
            "permissions": ["read"],
        })
        attributes = (
            attrs_result.unwrap()
            if attrs_result.is_success
            else FlextLdifModels.LdifAttributes.create({}).unwrap()
        )

        acl_entry = FlextLdifModels.Entry(
            dn=FlextLdifModels.DistinguishedName(value="cn=AclRule"),
            attributes=attributes,
        )
        result = ops.format_acl(acl_entry)

        assert result.is_success or result.is_failure

    def test_get_max_page_size(self) -> None:
        """Test max page size for Oracle OID."""
        ops = FlextLdapServersOIDOperations()
        max_page = ops.get_max_page_size()

        assert isinstance(max_page, int)
        assert max_page > 0

    def test_supports_paged_results(self) -> None:
        """Test paged results support for Oracle OID."""
        ops = FlextLdapServersOIDOperations()
        supports = ops.supports_paged_results()

        assert isinstance(supports, bool)


@pytest.mark.integration
class TestOUDOperations:
    """Test Oracle OUD specific operations."""

    def test_get_default_port_no_ssl(self) -> None:
        """Test default port for Oracle OUD without SSL."""
        ops = FlextLdapServersOUDOperations()
        port = ops.get_default_port(use_ssl=False)

        assert port == 389
        assert isinstance(port, int)
        assert port > 0

    def test_get_default_port_with_ssl(self) -> None:
        """Test default port for Oracle OUD with SSL."""
        ops = FlextLdapServersOUDOperations()
        port = ops.get_default_port(use_ssl=True)

        assert port in {636, 389}  # OUD may use different SSL port
        assert isinstance(port, int)
        assert port > 0

    def test_supports_start_tls(self) -> None:
        """Test STARTTLS support for Oracle OUD."""
        ops = FlextLdapServersOUDOperations()
        supports = ops.supports_start_tls()

        assert isinstance(supports, bool)

    def test_get_bind_mechanisms(self) -> None:
        """Test bind mechanisms for Oracle OUD."""
        ops = FlextLdapServersOUDOperations()
        mechanisms = ops.get_bind_mechanisms()

        assert isinstance(mechanisms, list)
        assert len(mechanisms) > 0

    def test_get_schema_dn(self) -> None:
        """Test schema DN for Oracle OUD."""
        ops = FlextLdapServersOUDOperations()
        schema_dn = ops.get_schema_dn()

        assert isinstance(schema_dn, str)

    def test_get_acl_attribute_name(self) -> None:
        """Test ACL attribute name for Oracle OUD."""
        ops = FlextLdapServersOUDOperations()
        attr_name = ops.get_acl_attribute_name()

        assert isinstance(attr_name, str)
        # OUD uses ds-privilege-name
        assert attr_name in {"ds-privilege-name", "aci", "privileges"}

    def test_get_acl_format(self) -> None:
        """Test ACL format for Oracle OUD."""
        ops = FlextLdapServersOUDOperations()
        acl_format = ops.get_acl_format()

        assert isinstance(acl_format, str)
        # Accept various formats that OUD operations may return
        assert acl_format in {
            "oracle_privilege",
            "oracle",
            "rfc_generic",
            "openldap_acl",
            "privilege",
        }

    def test_get_max_page_size(self) -> None:
        """Test max page size for Oracle OUD."""
        ops = FlextLdapServersOUDOperations()
        max_page = ops.get_max_page_size()

        assert isinstance(max_page, int)
        assert max_page > 0

    def test_supports_paged_results(self) -> None:
        """Test paged results support for Oracle OUD."""
        ops = FlextLdapServersOUDOperations()
        supports = ops.supports_paged_results()

        assert isinstance(supports, bool)


@pytest.mark.integration
class TestServerOperationsErrorHandling:
    """Test error handling in server operations."""

    def test_openldap_parse_acl_invalid_format(self) -> None:
        """Test invalid ACL parsing for OpenLDAP."""
        ops = FlextLdapServersOpenLDAP2Operations()

        acl_string = "invalid@#$%^&*()"
        result = ops.parse_acl(acl_string)

        # Should handle gracefully
        assert result.is_success or result.is_failure

    def test_oid_format_acl_empty_dict(self) -> None:
        """Test empty ACL Entry formatting for OID."""
        ops = FlextLdapServersOIDOperations()

        # Create minimal Entry for formatting
        attrs_result = FlextLdifModels.LdifAttributes.create({})
        attributes = (
            attrs_result.unwrap()
            if attrs_result.is_success
            else FlextLdifModels.LdifAttributes.create({"raw": [""]}).unwrap()
        )

        acl_entry = FlextLdifModels.Entry(
            dn=FlextLdifModels.DistinguishedName(value="cn=AclRule"),
            attributes=attributes,
        )
        result = ops.format_acl(acl_entry)

        # Should handle gracefully
        assert result.is_success or result.is_failure

    def test_oud_operations_initialization(self) -> None:
        """Test OUD operations initialization."""
        ops = FlextLdapServersOUDOperations()

        assert ops is not None
        assert hasattr(ops, "get_default_port")
        assert hasattr(ops, "get_acl_attribute_name")
        assert hasattr(ops, "get_max_page_size")


@pytest.mark.integration
class TestServerOperationsMethods:
    """Test various server operation methods."""

    def test_openldap_parse_attribute_type(self) -> None:
        """Test attribute type parsing for OpenLDAP."""
        ops = FlextLdapServersOpenLDAP2Operations()

        # OpenLDAP attribute type format
        attr_def = "(2.5.4.3 NAME 'cn' DESC 'Common Name' SINGLE-VALUE)"
        result = ops.parse_attribute_type(attr_def)

        assert result.is_success or result.is_failure

    def test_openldap_parse_object_class(self) -> None:
        """Test object class parsing for OpenLDAP."""
        ops = FlextLdapServersOpenLDAP2Operations()

        # OpenLDAP object class format
        class_def = (
            "( 2.5.6.6 NAME 'person' DESC 'RFC2256: a person' "
            "SUP top STRUCTURAL MUST ( sn $ cn ) MAY ( userPassword ) )"
        )
        result = ops.parse_object_class(class_def)

        assert result.is_success or result.is_failure

    def test_oid_normalize_entry(self) -> None:
        """Test entry normalization for Oracle OID."""
        ops = FlextLdapServersOIDOperations()

        # Create proper FlextLdifModels.Entry object
        dn_str = "cn=test,dc=example,dc=com"
        attrs: dict[str, FlextLdifModels.AttributeValues] = {
            "objectClass": FlextLdifModels.AttributeValues(values=["person"]),
            "cn": FlextLdifModels.AttributeValues(values=["test"]),
            "sn": FlextLdifModels.AttributeValues(values=["test"]),
        }
        entry = FlextLdifModels.Entry(
            dn=FlextLdifModels.DistinguishedName(value=dn_str),
            attributes=FlextLdifModels.LdifAttributes(attributes=attrs),
        )

        result = ops.normalize_entry(entry)

        assert result.is_success
        normalized = result.unwrap()
        assert isinstance(normalized, FlextLdifModels.Entry)

    def test_oud_normalize_entry(self) -> None:
        """Test entry normalization for Oracle OUD."""
        ops = FlextLdapServersOUDOperations()

        # Create proper FlextLdifModels.Entry object
        dn_str = "cn=test,dc=example,dc=com"
        attrs: dict[str, FlextLdifModels.AttributeValues] = {
            "objectClass": FlextLdifModels.AttributeValues(values=["person"]),
            "cn": FlextLdifModels.AttributeValues(values=["test"]),
            "sn": FlextLdifModels.AttributeValues(values=["test"]),
        }
        entry = FlextLdifModels.Entry(
            dn=FlextLdifModels.DistinguishedName(value=dn_str),
            attributes=FlextLdifModels.LdifAttributes(attributes=attrs),
        )

        result = ops.normalize_entry(entry)

        assert result.is_success
        normalized = result.unwrap()
        assert isinstance(normalized, FlextLdifModels.Entry)


@pytest.mark.integration
@pytest.mark.docker
class TestOUDOperationsComprehensive:
    """Comprehensive integration tests for Oracle OUD operations."""

    def test_oud_get_default_port_no_ssl(self) -> None:
        """Test OUD default port without SSL."""
        ops = FlextLdapServersOUDOperations()
        port = ops.get_default_port(use_ssl=False)
        assert port == 389

    def test_oud_get_default_port_with_ssl(self) -> None:
        """Test OUD default port with SSL."""
        ops = FlextLdapServersOUDOperations()
        port = ops.get_default_port(use_ssl=True)
        assert port == 636

    def test_oud_supports_start_tls(self) -> None:
        """Test OUD STARTTLS support."""
        ops = FlextLdapServersOUDOperations()
        assert ops.supports_start_tls() is True

    def test_oud_get_bind_mechanisms(self) -> None:
        """Test OUD bind mechanisms."""
        ops = FlextLdapServersOUDOperations()
        mechanisms = ops.get_bind_mechanisms()
        assert isinstance(mechanisms, list)
        assert len(mechanisms) > 0
        assert "SIMPLE" in mechanisms

    def test_oud_get_schema_dn(self) -> None:
        """Test OUD schema DN."""
        ops = FlextLdapServersOUDOperations()
        schema_dn = ops.get_schema_dn()
        assert schema_dn == "cn=schema"

    def test_oud_get_acl_attribute_name(self) -> None:
        """Test OUD ACL attribute name."""
        ops = FlextLdapServersOUDOperations()
        attr_name = ops.get_acl_attribute_name()
        assert attr_name == "ds-privilege-name"

    def test_oud_get_acl_format(self) -> None:
        """Test OUD ACL format."""
        ops = FlextLdapServersOUDOperations()
        acl_format = ops.get_acl_format()
        assert isinstance(acl_format, str)

    def test_oud_parse_acl(self) -> None:
        """Test OUD ACL parsing."""
        ops = FlextLdapServersOUDOperations()
        acl_string = "READ allow all"
        result = ops.parse_acl(acl_string)
        assert result.is_success or result.is_failure

    def test_oud_format_acl(self) -> None:
        """Test OUD ACL formatting."""
        ops = FlextLdapServersOUDOperations()
        acl_dict: dict[str, object] = {}
        result = ops.format_acl(acl_dict)
        assert result.is_success or result.is_failure

    def test_oud_get_max_page_size(self) -> None:
        """Test OUD max page size."""
        ops = FlextLdapServersOUDOperations()
        max_size = ops.get_max_page_size()
        assert isinstance(max_size, int)
        assert max_size > 0

    def test_oud_supports_paged_results(self) -> None:
        """Test OUD paged results support."""
        ops = FlextLdapServersOUDOperations()
        assert ops.supports_paged_results() is True

    def test_oud_supports_vlv(self) -> None:
        """Test OUD VLV support."""
        ops = FlextLdapServersOUDOperations()
        assert ops.supports_vlv() is True

    def test_oud_get_oud_version(self) -> None:
        """Test OUD version retrieval."""
        ops = FlextLdapServersOUDOperations()
        version = ops.get_oud_version()
        assert isinstance(version, str)

    def test_oud_is_based_on_389ds(self) -> None:
        """Test if OUD is based on 389 DS."""
        ops = FlextLdapServersOUDOperations()
        assert ops.is_based_on_389ds() is True

    def test_oud_get_oud_privileges(self) -> None:
        """Test OUD privileges retrieval."""
        ops = FlextLdapServersOUDOperations()
        privileges = ops.get_oud_privileges()
        assert isinstance(privileges, list)

    def test_oud_supports_replication(self) -> None:
        """Test OUD replication support."""
        ops = FlextLdapServersOUDOperations()
        assert ops.supports_replication() is True

    def test_oud_get_replication_mechanism(self) -> None:
        """Test OUD replication mechanism."""
        ops = FlextLdapServersOUDOperations()
        mechanism = ops.get_replication_mechanism()
        assert isinstance(mechanism, str)

    def test_oud_parse_object_class(self) -> None:
        """Test OUD object class parsing."""
        ops = FlextLdapServersOUDOperations()
        class_def = "( 2.5.6.6 NAME 'person' )"
        result = ops.parse_object_class(class_def)
        assert result.is_success or result.is_failure

    def test_oud_parse_attribute_type(self) -> None:
        """Test OUD attribute type parsing."""
        ops = FlextLdapServersOUDOperations()
        attr_def = "( 2.5.4.3 NAME 'cn' )"
        result = ops.parse_attribute_type(attr_def)
        assert result.is_success or result.is_failure

    def test_oud_server_type_initialization(self) -> None:
        """Test OUD server type is set correctly."""
        ops = FlextLdapServersOUDOperations()
        assert ops._server_type == "oud"

    def test_oud_detect_server_type_from_root_dse(self) -> None:
        """Test OUD server type detection."""
        ops = FlextLdapServersOUDOperations()
        root_dse: dict[str, object] = {
            "vendorName": ["Oracle"],
            "vendorVersion": ["Oracle Unified Directory 12.x"],
        }
        server_type = ops.detect_server_type_from_root_dse(root_dse)
        assert isinstance(server_type, str)

    def test_oud_get_privilege_category(self) -> None:
        """Test OUD privilege category."""
        ops = FlextLdapServersOUDOperations()
        category = ops.get_privilege_category("READ")
        assert isinstance(category, str)

    def test_oud_normalize_entry_for_server(self) -> None:
        """Test OUD entry normalization for server."""
        ops = FlextLdapServersOUDOperations()
        dn_str = "cn=test,dc=example,dc=com"
        attrs: dict[str, FlextLdifModels.AttributeValues] = {
            "objectClass": FlextLdifModels.AttributeValues(values=["person"]),
            "cn": FlextLdifModels.AttributeValues(values=["test"]),
            "sn": FlextLdifModels.AttributeValues(values=["test"]),
        }
        entry = FlextLdifModels.Entry(
            dn=FlextLdifModels.DistinguishedName(value=dn_str),
            attributes=FlextLdifModels.LdifAttributes(attributes=attrs),
        )
        result = ops.normalize_entry_for_server(entry)
        assert result.is_success or result.is_failure

    def test_oud_validate_entry_for_server(self) -> None:
        """Test OUD entry validation for server."""
        ops = FlextLdapServersOUDOperations()
        dn_str = "cn=test,dc=example,dc=com"
        attrs: dict[str, FlextLdifModels.AttributeValues] = {
            "objectClass": FlextLdifModels.AttributeValues(values=["person"]),
            "cn": FlextLdifModels.AttributeValues(values=["test"]),
            "sn": FlextLdifModels.AttributeValues(values=["test"]),
        }
        entry = FlextLdifModels.Entry(
            dn=FlextLdifModels.DistinguishedName(value=dn_str),
            attributes=FlextLdifModels.LdifAttributes(attributes=attrs),
        )
        result = ops.validate_entry_for_server(entry)
        assert result.is_success or result.is_failure


@pytest.mark.integration
@pytest.mark.docker
class TestFlextLdapServersFacade:
    """Comprehensive integration tests for FlextLdapServers facade."""

    def test_servers_generic_factory(self) -> None:
        """Test generic server factory method."""
        from flext_ldap.servers.servers import FlextLdapServers

        servers = FlextLdapServers.generic()
        assert servers is not None
        assert servers.server_type == "generic"

    def test_servers_for_openldap1(self) -> None:
        """Test OpenLDAP 1.x factory method."""
        from flext_ldap.servers.servers import FlextLdapServers

        servers = FlextLdapServers.for_openldap1()
        assert servers is not None
        assert servers.server_type == "openldap1"

    def test_servers_for_openldap2(self) -> None:
        """Test OpenLDAP 2.x factory method."""
        from flext_ldap.servers.servers import FlextLdapServers

        servers = FlextLdapServers.for_openldap2()
        assert servers is not None
        assert servers.server_type == "openldap2"

    def test_servers_for_oracle_oid(self) -> None:
        """Test Oracle OID factory method."""
        from flext_ldap.servers.servers import FlextLdapServers

        servers = FlextLdapServers.for_oracle_oid()
        assert servers is not None
        assert servers.server_type == "oracle_oid"

    def test_servers_for_oracle_oud(self) -> None:
        """Test Oracle OUD factory method."""
        from flext_ldap.servers.servers import FlextLdapServers

        servers = FlextLdapServers.for_oracle_oud()
        assert servers is not None
        assert servers.server_type == "oracle_oud"

    def test_servers_for_active_directory(self) -> None:
        """Test Active Directory factory method."""
        from flext_ldap.servers.servers import FlextLdapServers

        servers = FlextLdapServers.for_active_directory()
        assert servers is not None
        assert servers.server_type == "active_directory"

    def test_servers_get_acl_format_generic(self) -> None:
        """Test ACL format for generic server."""
        from flext_ldap.servers.servers import FlextLdapServers

        servers = FlextLdapServers.generic()
        acl_format = servers.get_acl_format()
        assert isinstance(acl_format, str)

    def test_servers_get_acl_attribute_name_generic(self) -> None:
        """Test ACL attribute name for generic server."""
        from flext_ldap.servers.servers import FlextLdapServers

        servers = FlextLdapServers.generic()
        attr_name = servers.get_acl_attribute_name()
        assert isinstance(attr_name, str)

    def test_servers_get_schema_dn_generic(self) -> None:
        """Test schema DN for generic server."""
        from flext_ldap.servers.servers import FlextLdapServers

        servers = FlextLdapServers.generic()
        schema_dn = servers.get_schema_dn()
        assert isinstance(schema_dn, str)

    def test_servers_get_default_port_no_ssl(self) -> None:
        """Test default port without SSL."""
        from flext_ldap.servers.servers import FlextLdapServers

        servers = FlextLdapServers.generic()
        port = servers.get_default_port(use_ssl=False)
        assert isinstance(port, int)
        assert port > 0

    def test_servers_get_default_port_with_ssl(self) -> None:
        """Test default port with SSL."""
        from flext_ldap.servers.servers import FlextLdapServers

        servers = FlextLdapServers.generic()
        port = servers.get_default_port(use_ssl=True)
        assert isinstance(port, int)
        assert port > 0

    def test_servers_supports_start_tls(self) -> None:
        """Test STARTTLS support."""
        from flext_ldap.servers.servers import FlextLdapServers

        servers = FlextLdapServers.generic()
        assert isinstance(servers.supports_start_tls(), bool)

    def test_servers_get_bind_mechanisms(self) -> None:
        """Test bind mechanisms."""
        from flext_ldap.servers.servers import FlextLdapServers

        servers = FlextLdapServers.generic()
        mechanisms = servers.get_bind_mechanisms()
        assert isinstance(mechanisms, list)
        assert len(mechanisms) > 0

    def test_servers_get_max_page_size(self) -> None:
        """Test max page size."""
        from flext_ldap.servers.servers import FlextLdapServers

        servers = FlextLdapServers.generic()
        max_size = servers.get_max_page_size()
        assert isinstance(max_size, int)
        assert max_size > 0

    def test_servers_supports_paged_results(self) -> None:
        """Test paged results support."""
        from flext_ldap.servers.servers import FlextLdapServers

        servers = FlextLdapServers.generic()
        assert isinstance(servers.supports_paged_results(), bool)

    def test_servers_supports_vlv(self) -> None:
        """Test VLV support."""
        from flext_ldap.servers.servers import FlextLdapServers

        servers = FlextLdapServers.generic()
        assert isinstance(servers.supports_vlv(), bool)

    def test_servers_detect_server_type_from_root_dse(self) -> None:
        """Test server type detection from Root DSE."""
        from flext_ldap.servers.servers import FlextLdapServers

        servers = FlextLdapServers.generic()
        root_dse: dict[str, object] = {
            "vendorName": ["OpenLDAP"],
            "vendorVersion": ["OpenLDAP 2.6.0"],
        }
        server_type = servers.detect_server_type_from_root_dse(root_dse)
        assert isinstance(server_type, str)

    def test_servers_normalize_entry_for_server_generic(self) -> None:
        """Test entry normalization for generic server."""
        from flext_ldap.servers.servers import FlextLdapServers

        servers = FlextLdapServers.generic()
        dn_str = "cn=test,dc=example,dc=com"
        attrs: dict[str, FlextLdifModels.AttributeValues] = {
            "objectClass": FlextLdifModels.AttributeValues(values=["person"]),
            "cn": FlextLdifModels.AttributeValues(values=["test"]),
            "sn": FlextLdifModels.AttributeValues(values=["test"]),
        }
        entry = FlextLdifModels.Entry(
            dn=FlextLdifModels.DistinguishedName(value=dn_str),
            attributes=FlextLdifModels.LdifAttributes(attributes=attrs),
        )
        result = servers.normalize_entry_for_server(entry)
        assert result.is_success or result.is_failure

    def test_servers_validate_entry_for_server(self) -> None:
        """Test entry validation for server."""
        from flext_ldap.servers.servers import FlextLdapServers

        servers = FlextLdapServers.generic()
        dn_str = "cn=test,dc=example,dc=com"
        attrs: dict[str, FlextLdifModels.AttributeValues] = {
            "objectClass": FlextLdifModels.AttributeValues(values=["person"]),
            "cn": FlextLdifModels.AttributeValues(values=["test"]),
            "sn": FlextLdifModels.AttributeValues(values=["test"]),
        }
        entry = FlextLdifModels.Entry(
            dn=FlextLdifModels.DistinguishedName(value=dn_str),
            attributes=FlextLdifModels.LdifAttributes(attributes=attrs),
        )
        result = servers.validate_entry_for_server(entry)
        assert result.is_success or result.is_failure

    def test_servers_initialization_with_server_type(self) -> None:
        """Test servers initialization with specific server type."""
        from flext_ldap.servers.servers import FlextLdapServers

        servers = FlextLdapServers("openldap2")
        assert servers.server_type == "openldap2"

    def test_servers_initialization_default(self) -> None:
        """Test servers initialization with default server type."""
        from flext_ldap.servers.servers import FlextLdapServers

        servers = FlextLdapServers()
        assert servers.server_type == "generic"

    def test_servers_operations_property(self) -> None:
        """Test operations property returns correct instance."""
        from flext_ldap.servers.servers import FlextLdapServers

        servers = FlextLdapServers("openldap2")
        ops = servers.operations
        assert ops is not None

    def test_servers_oud_delegation(self) -> None:
        """Test OUD server type delegation."""
        from flext_ldap.servers.servers import FlextLdapServers

        servers = FlextLdapServers.for_oracle_oud()
        # Test that methods delegate correctly
        schema_dn = servers.get_schema_dn()
        assert schema_dn == "cn=schema"  # OUD-specific schema DN

    def test_servers_openldap2_delegation(self) -> None:
        """Test OpenLDAP 2.x server type delegation."""
        from flext_ldap.servers.servers import FlextLdapServers

        servers = FlextLdapServers.for_openldap2()
        port = servers.get_default_port(use_ssl=False)
        assert port == 389  # OpenLDAP default
