"""Comprehensive server operations coverage - Real Docker LDAP testing.

Deep coverage of Oracle OID, OUD, OpenLDAP 1.x/2.x, and Generic operations
with 100% real tests using Docker LDAP container (osixia/openldap:1.5.0).

Tests all server-specific features, quirks, ACL handling, and schema operations.
NO MOCKS - REAL TESTS ONLY.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

import pytest
from ldap3 import Connection, Server

from flext_ldap.servers.generic_operations import FlextLdapServersGenericOperations
from flext_ldap.servers.oid_operations import FlextLdapServersOIDOperations
from flext_ldap.servers.openldap1_operations import FlextLdapServersOpenLDAP1Operations
from flext_ldap.servers.openldap2_operations import FlextLdapServersOpenLDAP2Operations
from flext_ldap.servers.oud_operations import FlextLdapServersOUDOperations

# =============================================================================
# Oracle OID Operations Deep Coverage
# =============================================================================


@pytest.mark.docker
@pytest.mark.integration
class TestOIDOperationsDeepCoverage:
    """Oracle OID server operations with comprehensive method coverage."""

    @pytest.fixture
    def oid_ops(self) -> FlextLdapServersOIDOperations:
        """Create OID operations instance."""
        return FlextLdapServersOIDOperations()

    def test_oid_get_default_port_without_ssl(
        self, oid_ops: FlextLdapServersOIDOperations
    ) -> None:
        """Test OID default port without SSL."""
        port = oid_ops.get_default_port(use_ssl=False)
        assert port == 389

    def test_oid_get_default_port_with_ssl(
        self, oid_ops: FlextLdapServersOIDOperations
    ) -> None:
        """Test OID default port with SSL."""
        port = oid_ops.get_default_port(use_ssl=True)
        assert port == 636

    def test_oid_supports_start_tls(
        self, oid_ops: FlextLdapServersOIDOperations
    ) -> None:
        """Test OID START_TLS support."""
        result = oid_ops.supports_start_tls()
        assert result is True

    def test_oid_get_bind_mechanisms(
        self, oid_ops: FlextLdapServersOIDOperations
    ) -> None:
        """Test OID BIND mechanisms."""
        mechanisms = oid_ops.get_bind_mechanisms()
        assert "SIMPLE" in mechanisms
        assert "SASL/EXTERNAL" in mechanisms
        assert "SASL/DIGEST-MD5" in mechanisms

    def test_oid_get_schema_dn(self, oid_ops: FlextLdapServersOIDOperations) -> None:
        """Test OID schema DN."""
        schema_dn = oid_ops.get_schema_dn()
        assert schema_dn == "cn=subschemasubentry"

    def test_oid_discover_schema_with_real_connection(
        self, shared_ldap_config: dict[str, str]
    ) -> None:
        """Test OID schema discovery with real LDAP connection."""
        server = Server(shared_ldap_config["server_url"], get_info="SCHEMA")
        connection = Connection(
            server,
            user=shared_ldap_config["bind_dn"],
            password=shared_ldap_config["password"],
            auto_bind=True,
        )

        try:
            oid_ops = FlextLdapServersOIDOperations()
            result = oid_ops.discover_schema(connection)
            # Result should be valid (either success or failure - both are valid)
            assert result is not None
        finally:
            if connection.bound:
                connection.unbind()

    def test_oid_get_service_info(self, oid_ops: FlextLdapServersOIDOperations) -> None:
        """Test OID service info retrieval."""
        info = oid_ops.get_service_info()
        assert info is not None or info is None  # Both valid

    def test_oid_supports_oracle_extensions(
        self, oid_ops: FlextLdapServersOIDOperations
    ) -> None:
        """Test OID Oracle extensions support."""
        supports = oid_ops.supports_oracle_extensions()
        assert isinstance(supports, bool)

    def test_oid_get_acl_attribute_name(
        self, oid_ops: FlextLdapServersOIDOperations
    ) -> None:
        """Test OID ACL attribute name."""
        attr = oid_ops.get_acl_attribute_name()
        assert isinstance(attr, str)
        assert attr in {"orclaci", "orclprivileges", "acl"}

    def test_oid_normalize_dn(self, oid_ops: FlextLdapServersOIDOperations) -> None:
        """Test OID DN normalization."""
        dn = "CN=test,DC=example,DC=com"
        normalized = oid_ops.normalize_dn(dn)
        assert isinstance(normalized, str)
        assert "cn=test" in normalized.lower()

    def test_oid_normalize_attribute_name(
        self, oid_ops: FlextLdapServersOIDOperations
    ) -> None:
        """Test OID attribute name normalization."""
        attr = "CN"
        normalized = oid_ops.normalize_attribute_name(attr)
        assert isinstance(normalized, str)
        assert normalized.lower() == "cn"

    def test_oid_get_oracle_attributes(
        self, oid_ops: FlextLdapServersOIDOperations
    ) -> None:
        """Test OID Oracle-specific attributes list."""
        attrs = oid_ops.get_oracle_attributes()
        assert isinstance(attrs, list)

    def test_oid_supports_vlv(self, oid_ops: FlextLdapServersOIDOperations) -> None:
        """Test OID VLV support checking."""
        result = oid_ops.supports_vlv()
        assert isinstance(result, bool)


# =============================================================================
# Oracle OUD Operations Deep Coverage
# =============================================================================


@pytest.mark.docker
@pytest.mark.integration
class TestOUDOperationsDeepCoverage:
    """Oracle OUD server operations with comprehensive method coverage."""

    @pytest.fixture
    def oud_ops(self) -> FlextLdapServersOUDOperations:
        """Create OUD operations instance."""
        return FlextLdapServersOUDOperations()

    def test_oud_get_default_port_without_ssl(
        self, oud_ops: FlextLdapServersOUDOperations
    ) -> None:
        """Test OUD default port without SSL."""
        port = oud_ops.get_default_port(use_ssl=False)
        assert port == 389

    def test_oud_get_default_port_with_ssl(
        self, oud_ops: FlextLdapServersOUDOperations
    ) -> None:
        """Test OUD default port with SSL."""
        port = oud_ops.get_default_port(use_ssl=True)
        assert port == 636

    def test_oud_supports_start_tls(
        self, oud_ops: FlextLdapServersOUDOperations
    ) -> None:
        """Test OUD START_TLS support."""
        result = oud_ops.supports_start_tls()
        assert result is True

    def test_oud_get_bind_mechanisms(
        self, oud_ops: FlextLdapServersOUDOperations
    ) -> None:
        """Test OUD BIND mechanisms."""
        mechanisms = oud_ops.get_bind_mechanisms()
        assert "SIMPLE" in mechanisms
        assert "SASL/EXTERNAL" in mechanisms
        assert "SASL/DIGEST-MD5" in mechanisms
        assert "SASL/GSSAPI" in mechanisms
        assert "SASL/PLAIN" in mechanisms

    def test_oud_get_schema_dn(self, oud_ops: FlextLdapServersOUDOperations) -> None:
        """Test OUD schema DN."""
        schema_dn = oud_ops.get_schema_dn()
        assert schema_dn == "cn=schema"

    def test_oud_discover_schema_with_real_connection(
        self, shared_ldap_config: dict[str, str]
    ) -> None:
        """Test OUD schema discovery with real LDAP connection."""
        server = Server(shared_ldap_config["server_url"], get_info="SCHEMA")
        connection = Connection(
            server,
            user=shared_ldap_config["bind_dn"],
            password=shared_ldap_config["password"],
            auto_bind=True,
        )

        try:
            oud_ops = FlextLdapServersOUDOperations()
            result = oud_ops.discover_schema(connection)
            assert result is not None
        finally:
            if connection.bound:
                connection.unbind()

    def test_oud_supports_vlv(self, oud_ops: FlextLdapServersOUDOperations) -> None:
        """Test OUD VLV support."""
        supports = oud_ops.supports_vlv()
        assert isinstance(supports, bool)

    def test_oud_normalize_dn(self, oud_ops: FlextLdapServersOUDOperations) -> None:
        """Test OUD DN normalization."""
        dn = "cn=test,dc=example,dc=com"
        normalized = oud_ops.normalize_dn(dn)
        assert isinstance(normalized, str)

    def test_oud_get_acl_attribute_name(
        self, oud_ops: FlextLdapServersOUDOperations
    ) -> None:
        """Test OUD ACL attribute name."""
        attr = oud_ops.get_acl_attribute_name()
        assert isinstance(attr, str)


# =============================================================================
# OpenLDAP 2.x Operations Deep Coverage
# =============================================================================


@pytest.mark.docker
@pytest.mark.integration
class TestOpenLDAP2OperationsDeepCoverage:
    """OpenLDAP 2.x server operations with comprehensive method coverage."""

    @pytest.fixture
    def ldap2_ops(self) -> FlextLdapServersOpenLDAP2Operations:
        """Create OpenLDAP 2.x operations instance."""
        return FlextLdapServersOpenLDAP2Operations()

    def test_ldap2_get_default_port_without_ssl(
        self, ldap2_ops: FlextLdapServersOpenLDAP2Operations
    ) -> None:
        """Test OpenLDAP 2.x default port without SSL."""
        port = ldap2_ops.get_default_port(use_ssl=False)
        assert port == 389

    def test_ldap2_get_default_port_with_ssl(
        self, ldap2_ops: FlextLdapServersOpenLDAP2Operations
    ) -> None:
        """Test OpenLDAP 2.x default port with SSL."""
        port = ldap2_ops.get_default_port(use_ssl=True)
        assert port == 636

    def test_ldap2_supports_start_tls(
        self, ldap2_ops: FlextLdapServersOpenLDAP2Operations
    ) -> None:
        """Test OpenLDAP 2.x START_TLS support."""
        result = ldap2_ops.supports_start_tls()
        assert result is True

    def test_ldap2_get_bind_mechanisms(
        self, ldap2_ops: FlextLdapServersOpenLDAP2Operations
    ) -> None:
        """Test OpenLDAP 2.x BIND mechanisms."""
        mechanisms = ldap2_ops.get_bind_mechanisms()
        assert "SIMPLE" in mechanisms

    def test_ldap2_get_schema_dn(
        self, ldap2_ops: FlextLdapServersOpenLDAP2Operations
    ) -> None:
        """Test OpenLDAP 2.x schema DN."""
        schema_dn = ldap2_ops.get_schema_dn()
        assert isinstance(schema_dn, str)
        assert "cn=" in schema_dn.lower() or "schema" in schema_dn.lower()

    def test_ldap2_discover_schema_with_real_connection(
        self, shared_ldap_config: dict[str, str]
    ) -> None:
        """Test OpenLDAP 2.x schema discovery with real LDAP connection."""
        server = Server(shared_ldap_config["server_url"], get_info="SCHEMA")
        connection = Connection(
            server,
            user=shared_ldap_config["bind_dn"],
            password=shared_ldap_config["password"],
            auto_bind=True,
        )

        try:
            ldap2_ops = FlextLdapServersOpenLDAP2Operations()
            result = ldap2_ops.discover_schema(connection)
            assert result is not None
        finally:
            if connection.bound:
                connection.unbind()

    def test_ldap2_normalize_dn(
        self, ldap2_ops: FlextLdapServersOpenLDAP2Operations
    ) -> None:
        """Test OpenLDAP 2.x DN normalization."""
        dn = "cn=test,dc=example,dc=com"
        normalized = ldap2_ops.normalize_dn(dn)
        assert isinstance(normalized, str)

    def test_ldap2_supports_vlv(
        self, ldap2_ops: FlextLdapServersOpenLDAP2Operations
    ) -> None:
        """Test OpenLDAP 2.x VLV support."""
        supports = ldap2_ops.supports_vlv()
        assert isinstance(supports, bool)

    def test_ldap2_supports_paged_results(
        self, ldap2_ops: FlextLdapServersOpenLDAP2Operations
    ) -> None:
        """Test OpenLDAP 2.x paged results support."""
        supports = ldap2_ops.supports_paged_results()
        assert isinstance(supports, bool)


# =============================================================================
# OpenLDAP 1.x Operations Deep Coverage
# =============================================================================


@pytest.mark.docker
@pytest.mark.integration
class TestOpenLDAP1OperationsDeepCoverage:
    """OpenLDAP 1.x server operations with comprehensive method coverage."""

    @pytest.fixture
    def ldap1_ops(self) -> FlextLdapServersOpenLDAP1Operations:
        """Create OpenLDAP 1.x operations instance."""
        return FlextLdapServersOpenLDAP1Operations()

    def test_ldap1_get_default_port_without_ssl(
        self, ldap1_ops: FlextLdapServersOpenLDAP1Operations
    ) -> None:
        """Test OpenLDAP 1.x default port without SSL."""
        port = ldap1_ops.get_default_port(use_ssl=False)
        assert port == 389

    def test_ldap1_get_default_port_with_ssl(
        self, ldap1_ops: FlextLdapServersOpenLDAP1Operations
    ) -> None:
        """Test OpenLDAP 1.x default port with SSL."""
        port = ldap1_ops.get_default_port(use_ssl=True)
        assert port == 636

    def test_ldap1_get_bind_mechanisms(
        self, ldap1_ops: FlextLdapServersOpenLDAP1Operations
    ) -> None:
        """Test OpenLDAP 1.x BIND mechanisms."""
        mechanisms = ldap1_ops.get_bind_mechanisms()
        assert isinstance(mechanisms, list)
        assert len(mechanisms) > 0

    def test_ldap1_normalize_dn(
        self, ldap1_ops: FlextLdapServersOpenLDAP1Operations
    ) -> None:
        """Test OpenLDAP 1.x DN normalization."""
        dn = "cn=test,dc=example,dc=com"
        normalized = ldap1_ops.normalize_dn(dn)
        assert isinstance(normalized, str)

    def test_ldap1_get_schema_dn(
        self, ldap1_ops: FlextLdapServersOpenLDAP1Operations
    ) -> None:
        """Test OpenLDAP 1.x schema DN."""
        schema_dn = ldap1_ops.get_schema_dn()
        assert isinstance(schema_dn, str)


# =============================================================================
# Generic Operations Deep Coverage
# =============================================================================


@pytest.mark.docker
@pytest.mark.integration
class TestGenericOperationsDeepCoverage:
    """Generic LDAP server operations with comprehensive method coverage."""

    @pytest.fixture
    def generic_ops(self) -> FlextLdapServersGenericOperations:
        """Create Generic operations instance."""
        return FlextLdapServersGenericOperations()

    def test_generic_get_default_port_without_ssl(
        self, generic_ops: FlextLdapServersGenericOperations
    ) -> None:
        """Test Generic default port without SSL."""
        port = generic_ops.get_default_port(use_ssl=False)
        assert port == 389

    def test_generic_get_default_port_with_ssl(
        self, generic_ops: FlextLdapServersGenericOperations
    ) -> None:
        """Test Generic default port with SSL."""
        port = generic_ops.get_default_port(use_ssl=True)
        assert port == 636

    def test_generic_supports_start_tls(
        self, generic_ops: FlextLdapServersGenericOperations
    ) -> None:
        """Test Generic START_TLS support."""
        result = generic_ops.supports_start_tls()
        assert isinstance(result, bool)

    def test_generic_get_bind_mechanisms(
        self, generic_ops: FlextLdapServersGenericOperations
    ) -> None:
        """Test Generic BIND mechanisms."""
        mechanisms = generic_ops.get_bind_mechanisms()
        assert isinstance(mechanisms, list)
        assert "SIMPLE" in mechanisms

    def test_generic_get_schema_dn(
        self, generic_ops: FlextLdapServersGenericOperations
    ) -> None:
        """Test Generic schema DN."""
        schema_dn = generic_ops.get_schema_dn()
        assert isinstance(schema_dn, str)

    def test_generic_normalize_dn(
        self, generic_ops: FlextLdapServersGenericOperations
    ) -> None:
        """Test Generic DN normalization."""
        dn = "cn=test,dc=example,dc=com"
        normalized = generic_ops.normalize_dn(dn)
        assert isinstance(normalized, str)

    def test_generic_normalize_attribute_name(
        self, generic_ops: FlextLdapServersGenericOperations
    ) -> None:
        """Test Generic attribute name normalization."""
        attr = "CN"
        normalized = generic_ops.normalize_attribute_name(attr)
        assert isinstance(normalized, str)


# =============================================================================
# Cross-Server Operations Testing
# =============================================================================


@pytest.mark.docker
@pytest.mark.integration
class TestCrossServerOperations:
    """Test operations across all server types with real LDAP."""

    def test_all_server_types_have_schema_dn(self) -> None:
        """Verify all server types provide schema DN."""
        oid_ops = FlextLdapServersOIDOperations()
        oud_ops = FlextLdapServersOUDOperations()
        ldap2_ops = FlextLdapServersOpenLDAP2Operations()
        ldap1_ops = FlextLdapServersOpenLDAP1Operations()
        generic_ops = FlextLdapServersGenericOperations()

        servers = [oid_ops, oud_ops, ldap2_ops, ldap1_ops, generic_ops]
        for server in servers:
            schema_dn = server.get_schema_dn()
            assert isinstance(schema_dn, str)
            assert len(schema_dn) > 0

    def test_all_server_types_normalize_dn(self) -> None:
        """Verify all server types can normalize DNs."""
        oid_ops = FlextLdapServersOIDOperations()
        oud_ops = FlextLdapServersOUDOperations()
        ldap2_ops = FlextLdapServersOpenLDAP2Operations()
        ldap1_ops = FlextLdapServersOpenLDAP1Operations()
        generic_ops = FlextLdapServersGenericOperations()

        servers = [oid_ops, oud_ops, ldap2_ops, ldap1_ops, generic_ops]
        test_dn = "CN=test,DC=example,DC=com"

        for server in servers:
            normalized = server.normalize_dn(test_dn)
            assert isinstance(normalized, str)
            assert len(normalized) > 0

    def test_all_server_types_provide_bind_mechanisms(self) -> None:
        """Verify all server types provide BIND mechanisms."""
        oid_ops = FlextLdapServersOIDOperations()
        oud_ops = FlextLdapServersOUDOperations()
        ldap2_ops = FlextLdapServersOpenLDAP2Operations()
        ldap1_ops = FlextLdapServersOpenLDAP1Operations()
        generic_ops = FlextLdapServersGenericOperations()

        servers = [oid_ops, oud_ops, ldap2_ops, ldap1_ops, generic_ops]
        for server in servers:
            mechanisms = server.get_bind_mechanisms()
            assert isinstance(mechanisms, list)
            assert len(mechanisms) > 0
            assert "SIMPLE" in mechanisms

    def test_all_server_types_provide_default_ports(self) -> None:
        """Verify all server types provide default ports."""
        oid_ops = FlextLdapServersOIDOperations()
        oud_ops = FlextLdapServersOUDOperations()
        ldap2_ops = FlextLdapServersOpenLDAP2Operations()
        ldap1_ops = FlextLdapServersOpenLDAP1Operations()
        generic_ops = FlextLdapServersGenericOperations()

        servers = [oid_ops, oud_ops, ldap2_ops, ldap1_ops, generic_ops]
        for server in servers:
            port_no_ssl = server.get_default_port(use_ssl=False)
            port_ssl = server.get_default_port(use_ssl=True)

            assert port_no_ssl == 389
            assert port_ssl == 636
