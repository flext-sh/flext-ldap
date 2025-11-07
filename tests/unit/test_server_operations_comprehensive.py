"""Comprehensive unit tests for all LDAP server operation implementations.

Tests all server-specific operation methods with real edge cases and error scenarios.

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

# mypy: disable-error-code="arg-type,misc,operator,attr-defined,assignment,index,call-arg,union-attr,return-value,list-item,valid-type"


@pytest.mark.unit
class TestAllServerOperationsBindMechanisms:
    """Test bind mechanism support across all server types."""

    def test_oid_bind_mechanisms(self) -> None:
        """Test OID bind mechanisms."""
        oid = FlextLdapServersOIDOperations()
        mechs = oid.get_bind_mechanisms()

        assert "SIMPLE" in mechs
        assert "SASL/EXTERNAL" in mechs
        assert "SASL/DIGEST-MD5" in mechs
        assert isinstance(mechs, list)

    def test_oud_bind_mechanisms(self) -> None:
        """Test OUD bind mechanisms (superset of OID)."""
        oud = FlextLdapServersOUDOperations()
        mechs = oud.get_bind_mechanisms()

        assert "SIMPLE" in mechs
        assert "SASL/EXTERNAL" in mechs
        assert "SASL/DIGEST-MD5" in mechs
        assert "SASL/GSSAPI" in mechs
        assert "SASL/PLAIN" in mechs

    def test_openldap2_bind_mechanisms(self) -> None:
        """Test OpenLDAP2 bind mechanisms."""
        ldap2 = FlextLdapServersOpenLDAP2Operations()
        mechs = ldap2.get_bind_mechanisms()

        assert "SIMPLE" in mechs
        assert isinstance(mechs, list)

    def test_openldap1_bind_mechanisms(self) -> None:
        """Test OpenLDAP1 bind mechanisms."""
        ldap1 = FlextLdapServersOpenLDAP1Operations()
        mechs = ldap1.get_bind_mechanisms()

        assert "SIMPLE" in mechs
        assert isinstance(mechs, list)

    def test_ad_bind_mechanisms(self) -> None:
        """Test Active Directory bind mechanisms."""
        ad = FlextLdapServersActiveDirectoryOperations()
        mechs = ad.get_bind_mechanisms()

        assert "SIMPLE" in mechs
        assert isinstance(mechs, list)

    def test_generic_bind_mechanisms(self) -> None:
        """Test generic RFC-compliant bind mechanisms."""
        generic = FlextLdapServersGenericOperations()
        mechs = generic.get_bind_mechanisms()

        assert "SIMPLE" in mechs
        assert isinstance(mechs, list)


@pytest.mark.unit
class TestAllServerOperationsPorts:
    """Test port configuration across all server types."""

    def test_all_servers_port_389_without_ssl(self) -> None:
        """All servers should default to port 389 without SSL."""
        servers = [
            FlextLdapServersOIDOperations(),
            FlextLdapServersOUDOperations(),
            FlextLdapServersOpenLDAP1Operations(),
            FlextLdapServersOpenLDAP2Operations(),
            FlextLdapServersActiveDirectoryOperations(),
            FlextLdapServersGenericOperations(),
        ]

        for server in servers:
            port = server.get_default_port(use_ssl=False)
            assert port == 389, f"{server.server_type} should use port 389 without SSL"

    def test_all_servers_port_636_with_ssl(self) -> None:
        """All servers should default to port 636 with SSL."""
        servers = [
            FlextLdapServersOIDOperations(),
            FlextLdapServersOUDOperations(),
            FlextLdapServersOpenLDAP1Operations(),
            FlextLdapServersOpenLDAP2Operations(),
            FlextLdapServersActiveDirectoryOperations(),
            FlextLdapServersGenericOperations(),
        ]

        for server in servers:
            port = server.get_default_port(use_ssl=True)
            assert port == 636, f"{server.server_type} should use port 636 with SSL"


@pytest.mark.unit
class TestAllServerOperationsSchemaDN:
    """Test schema DN configuration across all server types."""

    def test_oid_schema_dn(self) -> None:
        """Test OID schema DN."""
        oid = FlextLdapServersOIDOperations()
        schema_dn = oid.get_schema_dn()

        assert schema_dn == "cn=subschemasubentry"
        assert isinstance(schema_dn, str)

    def test_oud_schema_dn(self) -> None:
        """Test OUD schema DN."""
        oud = FlextLdapServersOUDOperations()
        schema_dn = oud.get_schema_dn()

        assert schema_dn == "cn=schema"
        assert isinstance(schema_dn, str)

    def test_openldap_schema_dn(self) -> None:
        """Test OpenLDAP schema DNs."""
        ldap2 = FlextLdapServersOpenLDAP2Operations()
        ldap1 = FlextLdapServersOpenLDAP1Operations()

        schema_dn_2 = ldap2.get_schema_dn()
        schema_dn_1 = ldap1.get_schema_dn()

        assert isinstance(schema_dn_2, str)
        assert isinstance(schema_dn_1, str)
        assert len(schema_dn_2) > 0
        assert len(schema_dn_1) > 0

    def test_ad_schema_dn(self) -> None:
        """Test Active Directory schema DN."""
        ad = FlextLdapServersActiveDirectoryOperations()
        schema_dn = ad.get_schema_dn()

        assert schema_dn and "schema" in schema_dn.lower()
        assert isinstance(schema_dn, str)

    def test_generic_schema_dn(self) -> None:
        """Test generic schema DN."""
        generic = FlextLdapServersGenericOperations()
        schema_dn = generic.get_schema_dn()

        assert isinstance(schema_dn, str)
        assert len(schema_dn) > 0


@pytest.mark.unit
class TestAllServerOperationsTLS:
    """Test TLS support across all server types."""

    def test_all_servers_support_start_tls(self) -> None:
        """All servers should support START_TLS."""
        servers = [
            FlextLdapServersOIDOperations(),
            FlextLdapServersOUDOperations(),
            FlextLdapServersOpenLDAP1Operations(),
            FlextLdapServersOpenLDAP2Operations(),
            FlextLdapServersActiveDirectoryOperations(),
            FlextLdapServersGenericOperations(),
        ]

        for server in servers:
            supports_tls = server.supports_start_tls()
            assert supports_tls is True, (
                f"{server.server_type} should support START_TLS"
            )
            assert isinstance(supports_tls, bool)


@pytest.mark.unit
class TestServerOperationsInitialization:
    """Test server operations initialization."""

    def test_oid_initialization(self) -> None:
        """Test OID initialization."""
        oid = FlextLdapServersOIDOperations()
        assert oid.server_type == "oid"

    def test_oud_initialization(self) -> None:
        """Test OUD initialization."""
        oud = FlextLdapServersOUDOperations()
        assert oud.server_type == "oud"

    def test_openldap1_initialization(self) -> None:
        """Test OpenLDAP1 initialization."""
        ldap1 = FlextLdapServersOpenLDAP1Operations()
        assert ldap1.server_type == "openldap1"

    def test_openldap2_initialization(self) -> None:
        """Test OpenLDAP2 initialization."""
        ldap2 = FlextLdapServersOpenLDAP2Operations()
        assert ldap2.server_type == "openldap2"

    def test_ad_initialization(self) -> None:
        """Test Active Directory initialization."""
        ad = FlextLdapServersActiveDirectoryOperations()
        assert ad.server_type == "ad"

    def test_generic_initialization(self) -> None:
        """Test generic server initialization."""
        generic = FlextLdapServersGenericOperations()
        assert generic.server_type == "generic"


@pytest.mark.unit
class TestServerOperationsAttributes:
    """Test server operations have required attributes."""

    def test_all_servers_have_server_type(self) -> None:
        """All servers should have server_type attribute."""
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

    def test_all_servers_have_required_methods(self) -> None:
        """All servers should have required methods."""
        servers = [
            FlextLdapServersOIDOperations(),
            FlextLdapServersOUDOperations(),
            FlextLdapServersOpenLDAP1Operations(),
            FlextLdapServersOpenLDAP2Operations(),
            FlextLdapServersActiveDirectoryOperations(),
            FlextLdapServersGenericOperations(),
        ]

        required_methods = [
            "get_default_port",
            "supports_start_tls",
            "get_bind_mechanisms",
            "get_schema_dn",
        ]

        for server in servers:
            for method_name in required_methods:
                assert hasattr(server, method_name)
                assert callable(getattr(server, method_name))


@pytest.mark.unit
class TestServerOperationsErrorHandling:
    """Test error handling in server operations."""

    def test_discover_schema_without_connection(self) -> None:
        """Test discover_schema returns error without connection."""
        servers = [
            FlextLdapServersOIDOperations(),
            FlextLdapServersOUDOperations(),
            FlextLdapServersOpenLDAP2Operations(),
        ]

        for server in servers:
            result = server.discover_schema(None)
            assert isinstance(result, FlextResult)
            assert result.is_failure


@pytest.mark.unit
class TestServerOperationsConsistency:
    """Test consistency across server operations."""

    def test_bind_mechanisms_always_include_simple(self) -> None:
        """All servers should support SIMPLE bind mechanism."""
        servers = [
            FlextLdapServersOIDOperations(),
            FlextLdapServersOUDOperations(),
            FlextLdapServersOpenLDAP1Operations(),
            FlextLdapServersOpenLDAP2Operations(),
            FlextLdapServersActiveDirectoryOperations(),
            FlextLdapServersGenericOperations(),
        ]

        for server in servers:
            mechs = server.get_bind_mechanisms()
            assert "SIMPLE" in mechs

    def test_tls_support_consistent(self) -> None:
        """TLS support should be consistent across servers."""
        servers = [
            FlextLdapServersOIDOperations(),
            FlextLdapServersOUDOperations(),
            FlextLdapServersOpenLDAP1Operations(),
            FlextLdapServersOpenLDAP2Operations(),
            FlextLdapServersActiveDirectoryOperations(),
            FlextLdapServersGenericOperations(),
        ]

        results = [server.supports_start_tls() for server in servers]
        assert all(results), "All servers should support START_TLS"

    def test_port_consistency(self) -> None:
        """Port selection should be consistent."""
        servers = [
            FlextLdapServersOIDOperations(),
            FlextLdapServersOUDOperations(),
            FlextLdapServersOpenLDAP1Operations(),
            FlextLdapServersOpenLDAP2Operations(),
            FlextLdapServersActiveDirectoryOperations(),
            FlextLdapServersGenericOperations(),
        ]

        for server in servers:
            # Non-SSL port
            port_no_ssl = server.get_default_port(use_ssl=False)
            assert port_no_ssl == 389

            # SSL port
            port_ssl = server.get_default_port(use_ssl=True)
            assert port_ssl == 636
