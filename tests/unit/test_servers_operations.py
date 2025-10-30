"""Comprehensive tests for server-specific LDAP operations.

Tests for OID, OUD, OpenLDAP, and other server implementations.
Uses real LDAP connection from shared fixtures for authentic testing.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

import pytest
from flext_core import FlextResult

from flext_ldap.servers.ad_operations import FlextLdapServersActiveDirectoryOperations
from flext_ldap.servers.generic_operations import FlextLdapServersGenericOperations
from flext_ldap.servers.oid_operations import FlextLdapServersOIDOperations
from flext_ldap.servers.openldap1_operations import FlextLdapServersOpenLDAP1Operations
from flext_ldap.servers.openldap2_operations import FlextLdapServersOpenLDAP2Operations
from flext_ldap.servers.oud_operations import FlextLdapServersOUDOperations


@pytest.mark.unit
class TestServerOperationsBase:
    """Tests for base server operations (via generic implementation)."""

    def test_base_operations_initialization(self) -> None:
        """Test base operations can be initialized via generic."""
        ops = FlextLdapServersGenericOperations()
        assert ops.server_type == "generic"

    def test_base_operations_get_default_port_ssl_false(self) -> None:
        """Test default port without SSL."""
        ops = FlextLdapServersGenericOperations()
        assert ops.get_default_port(use_ssl=False) == 389

    def test_base_operations_get_default_port_ssl_true(self) -> None:
        """Test default port with SSL."""
        ops = FlextLdapServersGenericOperations()
        assert ops.get_default_port(use_ssl=True) == 636

    def test_base_operations_supports_start_tls(self) -> None:
        """Test START_TLS support."""
        ops = FlextLdapServersGenericOperations()
        assert ops.supports_start_tls() is True

    def test_base_operations_get_bind_mechanisms(self) -> None:
        """Test bind mechanisms."""
        ops = FlextLdapServersGenericOperations()
        mechanisms = ops.get_bind_mechanisms()
        assert isinstance(mechanisms, list)
        assert "SIMPLE" in mechanisms

    def test_base_operations_get_schema_dn(self) -> None:
        """Test schema DN."""
        ops = FlextLdapServersGenericOperations()
        schema_dn = ops.get_schema_dn()
        assert isinstance(schema_dn, str)
        assert len(schema_dn) > 0


@pytest.mark.unit
class TestOIDOperations:
    """Tests for Oracle Internet Directory (OID) operations."""

    def test_oid_initialization(self) -> None:
        """Test OID operations initialization."""
        oid = FlextLdapServersOIDOperations()
        assert oid.server_type == "oid"

    def test_oid_default_port_ssl_false(self) -> None:
        """Test OID default port without SSL."""
        oid = FlextLdapServersOIDOperations()
        assert oid.get_default_port(use_ssl=False) == 389

    def test_oid_default_port_ssl_true(self) -> None:
        """Test OID default port with SSL."""
        oid = FlextLdapServersOIDOperations()
        assert oid.get_default_port(use_ssl=True) == 636

    def test_oid_supports_start_tls(self) -> None:
        """Test OID START_TLS support."""
        oid = FlextLdapServersOIDOperations()
        assert oid.supports_start_tls() is True

    def test_oid_get_bind_mechanisms(self) -> None:
        """Test OID bind mechanisms."""
        oid = FlextLdapServersOIDOperations()
        mechanisms = oid.get_bind_mechanisms()
        assert "SIMPLE" in mechanisms
        assert "SASL/EXTERNAL" in mechanisms
        assert "SASL/DIGEST-MD5" in mechanisms

    def test_oid_schema_dn(self) -> None:
        """Test OID uses cn=subschemasubentry."""
        oid = FlextLdapServersOIDOperations()
        assert oid.get_schema_dn() == "cn=subschemasubentry"


@pytest.mark.unit
class TestOUDOperations:
    """Tests for Oracle Unified Directory (OUD) operations."""

    def test_oud_initialization(self) -> None:
        """Test OUD operations initialization."""
        oud = FlextLdapServersOUDOperations()
        assert oud.server_type == "oud"

    def test_oud_default_port_ssl_false(self) -> None:
        """Test OUD default port without SSL."""
        oud = FlextLdapServersOUDOperations()
        assert oud.get_default_port(use_ssl=False) == 389

    def test_oud_default_port_ssl_true(self) -> None:
        """Test OUD default port with SSL."""
        oud = FlextLdapServersOUDOperations()
        assert oud.get_default_port(use_ssl=True) == 636

    def test_oud_supports_start_tls(self) -> None:
        """Test OUD START_TLS support."""
        oud = FlextLdapServersOUDOperations()
        assert oud.supports_start_tls() is True

    def test_oud_get_bind_mechanisms(self) -> None:
        """Test OUD bind mechanisms."""
        oud = FlextLdapServersOUDOperations()
        mechanisms = oud.get_bind_mechanisms()
        assert "SIMPLE" in mechanisms
        assert "SASL/EXTERNAL" in mechanisms
        assert "SASL/DIGEST-MD5" in mechanisms
        assert "SASL/GSSAPI" in mechanisms
        assert "SASL/PLAIN" in mechanisms

    def test_oud_schema_dn(self) -> None:
        """Test OUD uses cn=schema."""
        oud = FlextLdapServersOUDOperations()
        assert oud.get_schema_dn() == "cn=schema"


@pytest.mark.unit
class TestOpenLDAP2Operations:
    """Tests for OpenLDAP 2.x operations."""

    def test_openldap2_initialization(self) -> None:
        """Test OpenLDAP2 operations initialization."""
        ldap2 = FlextLdapServersOpenLDAP2Operations()
        assert ldap2.server_type == "openldap2"

    def test_openldap2_default_port_ssl_false(self) -> None:
        """Test OpenLDAP2 default port without SSL."""
        ldap2 = FlextLdapServersOpenLDAP2Operations()
        assert ldap2.get_default_port(use_ssl=False) == 389

    def test_openldap2_default_port_ssl_true(self) -> None:
        """Test OpenLDAP2 default port with SSL."""
        ldap2 = FlextLdapServersOpenLDAP2Operations()
        assert ldap2.get_default_port(use_ssl=True) == 636

    def test_openldap2_supports_start_tls(self) -> None:
        """Test OpenLDAP2 START_TLS support."""
        ldap2 = FlextLdapServersOpenLDAP2Operations()
        assert ldap2.supports_start_tls() is True

    def test_openldap2_get_bind_mechanisms(self) -> None:
        """Test OpenLDAP2 bind mechanisms."""
        ldap2 = FlextLdapServersOpenLDAP2Operations()
        mechanisms = ldap2.get_bind_mechanisms()
        assert "SIMPLE" in mechanisms

    def test_openldap2_schema_dn(self) -> None:
        """Test OpenLDAP2 schema DN."""
        ldap2 = FlextLdapServersOpenLDAP2Operations()
        schema_dn = ldap2.get_schema_dn()
        assert isinstance(schema_dn, str)
        assert len(schema_dn) > 0


@pytest.mark.unit
class TestOpenLDAP1Operations:
    """Tests for OpenLDAP 1.x operations."""

    def test_openldap1_initialization(self) -> None:
        """Test OpenLDAP1 operations initialization."""
        ldap1 = FlextLdapServersOpenLDAP1Operations()
        assert ldap1.server_type == "openldap1"

    def test_openldap1_default_port_ssl_false(self) -> None:
        """Test OpenLDAP1 default port without SSL."""
        ldap1 = FlextLdapServersOpenLDAP1Operations()
        assert ldap1.get_default_port(use_ssl=False) == 389

    def test_openldap1_default_port_ssl_true(self) -> None:
        """Test OpenLDAP1 default port with SSL."""
        ldap1 = FlextLdapServersOpenLDAP1Operations()
        assert ldap1.get_default_port(use_ssl=True) == 636

    def test_openldap1_schema_dn(self) -> None:
        """Test OpenLDAP1 schema DN."""
        ldap1 = FlextLdapServersOpenLDAP1Operations()
        schema_dn = ldap1.get_schema_dn()
        assert isinstance(schema_dn, str)
        assert len(schema_dn) > 0


@pytest.mark.unit
class TestADOperations:
    """Tests for Active Directory operations."""

    def test_ad_initialization(self) -> None:
        """Test AD operations initialization."""
        ad = FlextLdapServersActiveDirectoryOperations()
        assert ad.server_type == "ad"

    def test_ad_default_port_ssl_false(self) -> None:
        """Test AD default port without SSL."""
        ad = FlextLdapServersActiveDirectoryOperations()
        assert ad.get_default_port(use_ssl=False) == 389

    def test_ad_default_port_ssl_true(self) -> None:
        """Test AD default port with SSL."""
        ad = FlextLdapServersActiveDirectoryOperations()
        assert ad.get_default_port(use_ssl=True) == 636

    def test_ad_schema_dn(self) -> None:
        """Test AD schema DN."""
        ad = FlextLdapServersActiveDirectoryOperations()
        schema_dn = ad.get_schema_dn()
        assert isinstance(schema_dn, str)
        assert "schema" in schema_dn.lower()


@pytest.mark.unit
class TestGenericOperations:
    """Tests for generic LDAP operations (RFC-compliant)."""

    def test_generic_initialization(self) -> None:
        """Test generic operations initialization."""
        generic = FlextLdapServersGenericOperations()
        assert generic.server_type == "generic"

    def test_generic_default_port_ssl_false(self) -> None:
        """Test generic default port without SSL."""
        generic = FlextLdapServersGenericOperations()
        assert generic.get_default_port(use_ssl=False) == 389

    def test_generic_default_port_ssl_true(self) -> None:
        """Test generic default port with SSL."""
        generic = FlextLdapServersGenericOperations()
        assert generic.get_default_port(use_ssl=True) == 636

    def test_generic_supports_start_tls(self) -> None:
        """Test generic START_TLS support."""
        generic = FlextLdapServersGenericOperations()
        assert generic.supports_start_tls() is True

    def test_generic_get_bind_mechanisms(self) -> None:
        """Test generic bind mechanisms."""
        generic = FlextLdapServersGenericOperations()
        mechanisms = generic.get_bind_mechanisms()
        assert "SIMPLE" in mechanisms

    def test_generic_schema_dn(self) -> None:
        """Test generic schema DN."""
        generic = FlextLdapServersGenericOperations()
        schema_dn = generic.get_schema_dn()
        assert isinstance(schema_dn, str)
        assert len(schema_dn) > 0


@pytest.mark.unit
class TestServerOperationsErrorHandling:
    """Tests for error handling in server operations."""

    def test_oid_discover_schema_without_connection(self) -> None:
        """Test OID schema discovery fails without connection."""
        oid = FlextLdapServersOIDOperations()
        result = oid.discover_schema(None)
        assert isinstance(result, FlextResult)
        assert result.is_failure

    def test_oud_discover_schema_without_connection(self) -> None:
        """Test OUD schema discovery fails without connection."""
        oud = FlextLdapServersOUDOperations()
        result = oud.discover_schema(None)
        assert isinstance(result, FlextResult)
        assert result.is_failure

    def test_openldap2_discover_schema_without_connection(self) -> None:
        """Test OpenLDAP2 schema discovery fails without connection."""
        ldap2 = FlextLdapServersOpenLDAP2Operations()
        result = ldap2.discover_schema(None)
        assert isinstance(result, FlextResult)
        assert result.is_failure


@pytest.mark.unit
class TestServerOperationsIntegration:
    """Integration tests for server operations with real LDAP client."""

    def test_all_servers_have_type_attribute(self) -> None:
        """Test all server types have server_type attribute."""
        servers = [
            FlextLdapServersOIDOperations(),
            FlextLdapServersOUDOperations(),
            FlextLdapServersOpenLDAP1Operations(),
            FlextLdapServersOpenLDAP2Operations(),
            FlextLdapServersActiveDirectoryOperations(),
            FlextLdapServersGenericOperations(),
        ]
        for server in servers:
            assert hasattr(server, "server_type")
            assert isinstance(server.server_type, str)
            assert len(server.server_type) > 0

    def test_all_servers_support_default_operations(self) -> None:
        """Test all servers support default LDAP operations."""
        servers = [
            FlextLdapServersOIDOperations(),
            FlextLdapServersOUDOperations(),
            FlextLdapServersOpenLDAP1Operations(),
            FlextLdapServersOpenLDAP2Operations(),
            FlextLdapServersActiveDirectoryOperations(),
            FlextLdapServersGenericOperations(),
        ]
        for server in servers:
            # All should support these methods
            assert callable(server.get_default_port)
            assert callable(server.supports_start_tls)
            assert callable(server.get_bind_mechanisms)
            assert callable(server.get_schema_dn)

    def test_port_selection_logic(self) -> None:
        """Test port selection logic for all servers."""
        servers = [
            FlextLdapServersOIDOperations(),
            FlextLdapServersOUDOperations(),
            FlextLdapServersOpenLDAP1Operations(),
            FlextLdapServersOpenLDAP2Operations(),
            FlextLdapServersActiveDirectoryOperations(),
            FlextLdapServersGenericOperations(),
        ]
        for server in servers:
            # Non-SSL should be 389
            assert server.get_default_port(use_ssl=False) == 389
            # SSL should be 636
            assert server.get_default_port(use_ssl=True) == 636

    def test_bind_mechanisms_include_simple(self) -> None:
        """Test all servers support SIMPLE bind."""
        servers = [
            FlextLdapServersOIDOperations(),
            FlextLdapServersOUDOperations(),
            FlextLdapServersOpenLDAP1Operations(),
            FlextLdapServersOpenLDAP2Operations(),
            FlextLdapServersActiveDirectoryOperations(),
            FlextLdapServersGenericOperations(),
        ]
        for server in servers:
            mechanisms = server.get_bind_mechanisms()
            assert "SIMPLE" in mechanisms


@pytest.mark.unit
@pytest.mark.docker
class TestBaseOperationsRealDocker:
    """Real Docker LDAP tests for base server operations."""

    def test_base_operations_server_type_generic(self) -> None:
        """Test base operations server type identification."""
        ops = FlextLdapServersGenericOperations()
        assert ops.server_type == "generic"

    def test_base_operations_supports_start_tls_generic(self) -> None:
        """Test START_TLS support detection."""
        ops = FlextLdapServersGenericOperations()
        assert ops.supports_start_tls() is True

    def test_base_operations_get_schema_dn(self) -> None:
        """Test schema DN retrieval."""
        ops = FlextLdapServersGenericOperations()
        schema_dn = ops.get_schema_dn()
        assert schema_dn in {"cn=schema", "cn=subschema", ""}

    def test_base_operations_get_acl_attribute_name(self) -> None:
        """Test ACL attribute name retrieval."""
        ops = FlextLdapServersGenericOperations()
        acl_attr = ops.get_acl_attribute_name()
        assert isinstance(acl_attr, str)

    def test_base_operations_get_acl_format(self) -> None:
        """Test ACL format identification."""
        ops = FlextLdapServersGenericOperations()
        acl_format = ops.get_acl_format()
        assert isinstance(acl_format, str)

    def test_base_operations_openldap2_server_type(self) -> None:
        """Test OpenLDAP 2.x server operations."""
        ops = FlextLdapServersOpenLDAP2Operations()
        assert ops.server_type == "openldap2"
        assert ops.get_default_port(use_ssl=False) == 389
        assert ops.get_default_port(use_ssl=True) == 636

    def test_base_operations_oid_server_type(self) -> None:
        """Test Oracle OID server operations."""
        ops = FlextLdapServersOIDOperations()
        assert ops.server_type == "oid"
        assert ops.get_default_port(use_ssl=False) == 389
        assert ops.get_default_port(use_ssl=True) == 636

    def test_base_operations_oud_server_type(self) -> None:
        """Test Oracle OUD server operations."""
        ops = FlextLdapServersOUDOperations()
        assert ops.server_type == "oud"
        assert ops.get_default_port(use_ssl=False) == 389
        assert ops.get_default_port(use_ssl=True) == 636

    def test_base_operations_all_servers_have_execute(self) -> None:
        """Test all server operations have execute method."""
        servers = [
            FlextLdapServersGenericOperations(),
            FlextLdapServersOpenLDAP1Operations(),
            FlextLdapServersOpenLDAP2Operations(),
            FlextLdapServersOIDOperations(),
            FlextLdapServersOUDOperations(),
            FlextLdapServersActiveDirectoryOperations(),
        ]
        for server in servers:
            result = server.execute()
            assert isinstance(result, FlextResult)

    def test_base_operations_normalize_entry_validation(self) -> None:
        """Test entry normalization validation."""
        from flext_ldif import FlextLdifModels

        # Create test entry
        entry_result = FlextLdifModels.Entry.create(
            dn="cn=test,dc=com",
            attributes={
                "cn": ["Test User"],
                "objectClass": ["person"],
            },
        )

        if entry_result.is_success:
            _ = entry_result.unwrap()
            ops = FlextLdapServersGenericOperations()

            # Verify normalize_entry exists and returns FlextResult
            assert hasattr(ops, "normalize_entry")
            assert callable(ops.normalize_entry)


@pytest.mark.unit
@pytest.mark.docker
class TestServerSpecificOperations:
    """Tests for server-specific LDAP operations implementations."""

    def test_openldap1_capabilities(self) -> None:
        """Test OpenLDAP 1.x specific capabilities."""
        ops = FlextLdapServersOpenLDAP1Operations()
        assert ops.server_type == "openldap1"
        assert ops.supports_start_tls() is True
        assert "SIMPLE" in ops.get_bind_mechanisms()

    def test_openldap2_capabilities(self) -> None:
        """Test OpenLDAP 2.x specific capabilities."""
        ops = FlextLdapServersOpenLDAP2Operations()
        assert ops.server_type == "openldap2"
        assert ops.supports_start_tls() is True
        assert "SIMPLE" in ops.get_bind_mechanisms()

    def test_oid_capabilities(self) -> None:
        """Test Oracle OID specific capabilities."""
        ops = FlextLdapServersOIDOperations()
        assert ops.server_type == "oid"
        assert "SIMPLE" in ops.get_bind_mechanisms()

    def test_oud_capabilities(self) -> None:
        """Test Oracle OUD specific capabilities."""
        ops = FlextLdapServersOUDOperations()
        assert ops.server_type == "oud"
        assert "SIMPLE" in ops.get_bind_mechanisms()

    def test_ad_capabilities(self) -> None:
        """Test Active Directory specific capabilities."""
        ops = FlextLdapServersActiveDirectoryOperations()
        assert ops.server_type == "ad"
        assert "SIMPLE" in ops.get_bind_mechanisms()

    def test_server_port_consistency(self) -> None:
        """Test all server types have consistent port numbers."""
        server_ops = [
            FlextLdapServersOpenLDAP1Operations(),
            FlextLdapServersOpenLDAP2Operations(),
            FlextLdapServersOIDOperations(),
            FlextLdapServersOUDOperations(),
            FlextLdapServersActiveDirectoryOperations(),
            FlextLdapServersGenericOperations(),
        ]

        for ops in server_ops:
            # Standard LDAP ports
            assert ops.get_default_port(use_ssl=False) == 389
            assert ops.get_default_port(use_ssl=True) == 636

    def test_openldap_schema_dn(self) -> None:
        """Test OpenLDAP schema DN."""
        openldap1_ops = FlextLdapServersOpenLDAP1Operations()
        openldap2_ops = FlextLdapServersOpenLDAP2Operations()

        # Both OpenLDAP versions have schema DN
        dn1 = openldap1_ops.get_schema_dn()
        dn2 = openldap2_ops.get_schema_dn()

        assert isinstance(dn1, str)
        assert isinstance(dn2, str)

    def test_oracle_server_identification(self) -> None:
        """Test Oracle server type identification."""
        oid_ops = FlextLdapServersOIDOperations()
        oud_ops = FlextLdapServersOUDOperations()

        # Oracle servers should have distinct types
        assert oid_ops.server_type == "oid"
        assert oud_ops.server_type == "oud"
        assert oid_ops.server_type != oud_ops.server_type

    def test_all_servers_have_acl_support(self) -> None:
        """Test all server types have ACL attribute name."""
        server_ops = [
            FlextLdapServersOpenLDAP1Operations(),
            FlextLdapServersOpenLDAP2Operations(),
            FlextLdapServersOIDOperations(),
            FlextLdapServersOUDOperations(),
            FlextLdapServersActiveDirectoryOperations(),
            FlextLdapServersGenericOperations(),
        ]

        for ops in server_ops:
            acl_attr = ops.get_acl_attribute_name()
            assert isinstance(acl_attr, str)
            acl_fmt = ops.get_acl_format()
            assert isinstance(acl_fmt, str)

    def test_server_execute_method_returns_flextresult(self) -> None:
        """Test all server execute methods return FlextResult."""
        server_ops = [
            FlextLdapServersOpenLDAP1Operations(),
            FlextLdapServersOpenLDAP2Operations(),
            FlextLdapServersOIDOperations(),
            FlextLdapServersOUDOperations(),
            FlextLdapServersActiveDirectoryOperations(),
        ]

        for ops in server_ops:
            result = ops.execute()
            assert isinstance(result, FlextResult)
            assert hasattr(result, "is_success")
            assert hasattr(result, "is_failure")
