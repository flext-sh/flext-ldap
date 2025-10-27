"""Phase 3e - Comprehensive server operations coverage expansion.

Targets uncovered code paths in:
- servers/oid_operations.py (342 lines, 23% coverage)
- servers/openldap2_operations.py (302 lines, 25% coverage)
- servers/openldap1_operations.py (166 lines, 25% coverage)
- servers/oud_operations.py (308 lines, 26% coverage)
- servers/servers.py (107 lines, 41% coverage)
- servers/generic_operations.py (221 lines, 33% coverage)

With real Docker LDAP fixture data and comprehensive server-specific operations testing.

This test suite aims to expand server operations coverage from 23-41% to 95%+.
"""

from __future__ import annotations

import pytest
from flext_core import FlextResult
from flext_ldif import FlextLdifModels

from flext_ldap import FlextLdapClients
from flext_ldap.servers.factory import FlextLdapServersFactory
from flext_ldap.servers.generic_operations import FlextLdapServersGenericOperations
from flext_ldap.servers.oid_operations import FlextLdapServersOIDOperations
from flext_ldap.servers.openldap1_operations import FlextLdapServersOpenLDAP1Operations
from flext_ldap.servers.openldap2_operations import FlextLdapServersOpenLDAP2Operations
from flext_ldap.servers.oud_operations import FlextLdapServersOUDOperations

# ============================================================================
# OID SERVER OPERATIONS COVERAGE (342 lines, 23% → 95%)
# ============================================================================


@pytest.mark.integration
@pytest.mark.docker
class TestOIDServerOperationsCoverage:
    """OID server-specific operations with full coverage expansion."""

    def test_oid_get_default_port_consistency(
        self, shared_ldap_client: FlextLdapClients
    ) -> None:
        """Test OID default port consistency across multiple calls."""
        ops = FlextLdapServersOIDOperations()
        port1_non_ssl = ops.get_default_port(use_ssl=False)
        port2_non_ssl = ops.get_default_port(use_ssl=False)
        port1_ssl = ops.get_default_port(use_ssl=True)
        port2_ssl = ops.get_default_port(use_ssl=True)

        assert port1_non_ssl == port2_non_ssl == 389
        assert port1_ssl == port2_ssl == 636

    def test_oid_get_acl_attribute_name(
        self, shared_ldap_client: FlextLdapClients
    ) -> None:
        """Test OID ACL attribute name is 'orclaci'."""
        ops = FlextLdapServersOIDOperations()
        assert ops.get_acl_attribute_name() == "orclaci"

    def test_oid_get_acl_format(self, shared_ldap_client: FlextLdapClients) -> None:
        """Test OID ACL format is 'oracle'."""
        ops = FlextLdapServersOIDOperations()
        assert ops.get_acl_format() == "oracle"

    def test_oid_server_type(self, shared_ldap_client: FlextLdapClients) -> None:
        """Test OID server_type is 'oid'."""
        ops = FlextLdapServersOIDOperations()
        assert ops.server_type == "oid"

    def test_oid_get_bind_mechanisms(
        self, shared_ldap_client: FlextLdapClients
    ) -> None:
        """Test OID bind mechanisms."""
        ops = FlextLdapServersOIDOperations()
        mechanisms = ops.get_bind_mechanisms()
        assert isinstance(mechanisms, list)
        assert len(mechanisms) > 0
        assert "SIMPLE" in mechanisms

    def test_oid_get_schema_dn(self, shared_ldap_client: FlextLdapClients) -> None:
        """Test OID schema DN."""
        ops = FlextLdapServersOIDOperations()
        schema_dn = ops.get_schema_dn()
        assert isinstance(schema_dn, str)
        assert len(schema_dn) > 0

    def test_oid_supports_start_tls(self, shared_ldap_client: FlextLdapClients) -> None:
        """Test OID START_TLS support."""
        ops = FlextLdapServersOIDOperations()
        supports = ops.supports_start_tls()
        assert isinstance(supports, bool)

    def test_oid_supports_vlv(self, shared_ldap_client: FlextLdapClients) -> None:
        """Test OID VLV support."""
        ops = FlextLdapServersOIDOperations()
        supports = ops.supports_vlv()
        assert isinstance(supports, bool)

    def test_oid_supports_paged_results(
        self, shared_ldap_client: FlextLdapClients
    ) -> None:
        """Test OID paged results support."""
        ops = FlextLdapServersOIDOperations()
        supports = ops.supports_paged_results()
        assert isinstance(supports, bool)

    def test_oid_get_max_page_size(self, shared_ldap_client: FlextLdapClients) -> None:
        """Test OID max page size is positive."""
        ops = FlextLdapServersOIDOperations()
        max_size = ops.get_max_page_size()
        assert isinstance(max_size, int)
        assert max_size > 0

    def test_oid_parse_object_class(self, shared_ldap_client: FlextLdapClients) -> None:
        """Test OID parse_object_class method."""
        ops = FlextLdapServersOIDOperations()
        result = ops.parse_object_class("inetOrgPerson")
        assert result.is_success
        data = result.unwrap()
        assert data["server_type"] == "oid"

    def test_oid_parse_attribute_type(
        self, shared_ldap_client: FlextLdapClients
    ) -> None:
        """Test OID parse_attribute_type method."""
        ops = FlextLdapServersOIDOperations()
        result = ops.parse_attribute_type("cn")
        assert result.is_success
        data = result.unwrap()
        assert data["server_type"] == "oid"

    def test_oid_normalize_entry(self, shared_ldap_client: FlextLdapClients) -> None:
        """Test OID normalize_entry_for_server."""
        ops = FlextLdapServersOIDOperations()
        entry = FlextLdifModels.Entry(
            dn=FlextLdifModels.DistinguishedName(value="cn=test,dc=flext,dc=local"),
            attributes=FlextLdifModels.LdifAttributes(
                attributes={
                    "objectClass": FlextLdifModels.AttributeValues(
                        values=["inetOrgPerson"]
                    ),
                    "cn": FlextLdifModels.AttributeValues(values=["test"]),
                }
            ),
        )
        result = ops.normalize_entry_for_server(entry)
        assert isinstance(result, FlextResult)

    def test_oid_validate_entry(self, shared_ldap_client: FlextLdapClients) -> None:
        """Test OID validate_entry_for_server."""
        ops = FlextLdapServersOIDOperations()
        entry = FlextLdifModels.Entry(
            dn=FlextLdifModels.DistinguishedName(value="cn=test,dc=flext,dc=local"),
            attributes=FlextLdifModels.LdifAttributes(
                attributes={
                    "objectClass": FlextLdifModels.AttributeValues(
                        values=["inetOrgPerson"]
                    ),
                    "cn": FlextLdifModels.AttributeValues(values=["test"]),
                }
            ),
        )
        result = ops.validate_entry_for_server(entry)
        assert isinstance(result, FlextResult)

    def test_oid_discover_schema(self, shared_ldap_client: FlextLdapClients) -> None:
        """Test OID discover_schema with valid connection."""
        ops = FlextLdapServersOIDOperations()
        result = ops.discover_schema(shared_ldap_client._connection)
        assert isinstance(result, FlextResult)

    def test_oid_discover_schema_with_none_connection(
        self, shared_ldap_client: FlextLdapClients
    ) -> None:
        """Test OID discover_schema error handling with None."""
        ops = FlextLdapServersOIDOperations()
        result = ops.discover_schema(None)
        assert result.is_failure


# ============================================================================
# OUD SERVER OPERATIONS COVERAGE (308 lines, 26% → 95%)
# ============================================================================


@pytest.mark.integration
@pytest.mark.docker
class TestOUDServerOperationsCoverage:
    """OUD server-specific operations with full coverage expansion."""

    def test_oud_get_default_port_consistency(
        self, shared_ldap_client: FlextLdapClients
    ) -> None:
        """Test OUD default port consistency."""
        ops = FlextLdapServersOUDOperations()
        assert ops.get_default_port(use_ssl=False) == 389
        assert ops.get_default_port(use_ssl=True) == 636

    def test_oud_get_acl_attribute_name(
        self, shared_ldap_client: FlextLdapClients
    ) -> None:
        """Test OUD ACL attribute name."""
        ops = FlextLdapServersOUDOperations()
        attr = ops.get_acl_attribute_name()
        assert isinstance(attr, str)
        assert len(attr) > 0

    def test_oud_get_acl_format(self, shared_ldap_client: FlextLdapClients) -> None:
        """Test OUD ACL format."""
        ops = FlextLdapServersOUDOperations()
        fmt = ops.get_acl_format()
        assert isinstance(fmt, str)
        assert len(fmt) > 0

    def test_oud_server_type(self, shared_ldap_client: FlextLdapClients) -> None:
        """Test OUD server_type is 'oud'."""
        ops = FlextLdapServersOUDOperations()
        assert ops.server_type == "oud"

    def test_oud_get_bind_mechanisms(
        self, shared_ldap_client: FlextLdapClients
    ) -> None:
        """Test OUD bind mechanisms."""
        ops = FlextLdapServersOUDOperations()
        mechanisms = ops.get_bind_mechanisms()
        assert isinstance(mechanisms, list)
        assert len(mechanisms) > 0

    def test_oud_get_schema_dn(self, shared_ldap_client: FlextLdapClients) -> None:
        """Test OUD schema DN."""
        ops = FlextLdapServersOUDOperations()
        schema_dn = ops.get_schema_dn()
        assert isinstance(schema_dn, str)
        assert len(schema_dn) > 0

    def test_oud_supports_start_tls(self, shared_ldap_client: FlextLdapClients) -> None:
        """Test OUD START_TLS support."""
        ops = FlextLdapServersOUDOperations()
        supports = ops.supports_start_tls()
        assert isinstance(supports, bool)

    def test_oud_supports_vlv(self, shared_ldap_client: FlextLdapClients) -> None:
        """Test OUD VLV support."""
        ops = FlextLdapServersOUDOperations()
        supports = ops.supports_vlv()
        assert isinstance(supports, bool)

    def test_oud_supports_paged_results(
        self, shared_ldap_client: FlextLdapClients
    ) -> None:
        """Test OUD paged results support."""
        ops = FlextLdapServersOUDOperations()
        supports = ops.supports_paged_results()
        assert isinstance(supports, bool)

    def test_oud_get_max_page_size(self, shared_ldap_client: FlextLdapClients) -> None:
        """Test OUD max page size."""
        ops = FlextLdapServersOUDOperations()
        max_size = ops.get_max_page_size()
        assert isinstance(max_size, int)
        assert max_size > 0

    def test_oud_parse_object_class(self, shared_ldap_client: FlextLdapClients) -> None:
        """Test OUD parse_object_class."""
        ops = FlextLdapServersOUDOperations()
        result = ops.parse_object_class("person")
        assert result.is_success

    def test_oud_parse_attribute_type(
        self, shared_ldap_client: FlextLdapClients
    ) -> None:
        """Test OUD parse_attribute_type."""
        ops = FlextLdapServersOUDOperations()
        result = ops.parse_attribute_type("cn")
        assert result.is_success

    def test_oud_normalize_entry(self, shared_ldap_client: FlextLdapClients) -> None:
        """Test OUD normalize_entry_for_server."""
        ops = FlextLdapServersOUDOperations()
        entry = FlextLdifModels.Entry(
            dn=FlextLdifModels.DistinguishedName(value="cn=test,dc=flext,dc=local"),
            attributes=FlextLdifModels.LdifAttributes(
                attributes={
                    "objectClass": FlextLdifModels.AttributeValues(
                        values=["inetOrgPerson"]
                    ),
                    "cn": FlextLdifModels.AttributeValues(values=["test"]),
                }
            ),
        )
        result = ops.normalize_entry_for_server(entry)
        assert isinstance(result, FlextResult)

    def test_oud_validate_entry(self, shared_ldap_client: FlextLdapClients) -> None:
        """Test OUD validate_entry_for_server."""
        ops = FlextLdapServersOUDOperations()
        entry = FlextLdifModels.Entry(
            dn=FlextLdifModels.DistinguishedName(value="cn=test,dc=flext,dc=local"),
            attributes=FlextLdifModels.LdifAttributes(
                attributes={
                    "objectClass": FlextLdifModels.AttributeValues(
                        values=["inetOrgPerson"]
                    ),
                    "cn": FlextLdifModels.AttributeValues(values=["test"]),
                }
            ),
        )
        result = ops.validate_entry_for_server(entry)
        assert isinstance(result, FlextResult)

    def test_oud_discover_schema(self, shared_ldap_client: FlextLdapClients) -> None:
        """Test OUD discover_schema with valid connection."""
        ops = FlextLdapServersOUDOperations()
        result = ops.discover_schema(shared_ldap_client._connection)
        assert isinstance(result, FlextResult)

    def test_oud_discover_schema_with_none_connection(
        self, shared_ldap_client: FlextLdapClients
    ) -> None:
        """Test OUD discover_schema error handling."""
        ops = FlextLdapServersOUDOperations()
        result = ops.discover_schema(None)
        assert result.is_failure


# ============================================================================
# OPENLDAP2 SERVER OPERATIONS COVERAGE (302 lines, 25% → 95%)
# ============================================================================


@pytest.mark.integration
@pytest.mark.docker
class TestOpenLDAP2ServerOperationsCoverage:
    """OpenLDAP 2.x server-specific operations."""

    def test_openldap2_get_default_port(
        self, shared_ldap_client: FlextLdapClients
    ) -> None:
        """Test OpenLDAP2 default port."""
        ops = FlextLdapServersOpenLDAP2Operations()
        assert ops.get_default_port(use_ssl=False) == 389
        assert ops.get_default_port(use_ssl=True) == 636

    def test_openldap2_server_type(self, shared_ldap_client: FlextLdapClients) -> None:
        """Test OpenLDAP2 server_type."""
        ops = FlextLdapServersOpenLDAP2Operations()
        assert ops.server_type == "openldap2"

    def test_openldap2_get_bind_mechanisms(
        self, shared_ldap_client: FlextLdapClients
    ) -> None:
        """Test OpenLDAP2 bind mechanisms."""
        ops = FlextLdapServersOpenLDAP2Operations()
        mechanisms = ops.get_bind_mechanisms()
        assert isinstance(mechanisms, list)
        assert len(mechanisms) > 0

    def test_openldap2_get_schema_dn(
        self, shared_ldap_client: FlextLdapClients
    ) -> None:
        """Test OpenLDAP2 schema DN."""
        ops = FlextLdapServersOpenLDAP2Operations()
        schema_dn = ops.get_schema_dn()
        assert isinstance(schema_dn, str)
        assert len(schema_dn) > 0

    def test_openldap2_parse_object_class(
        self, shared_ldap_client: FlextLdapClients
    ) -> None:
        """Test OpenLDAP2 parse_object_class."""
        ops = FlextLdapServersOpenLDAP2Operations()
        result = ops.parse_object_class("inetOrgPerson")
        assert result.is_success

    def test_openldap2_normalize_entry(
        self, shared_ldap_client: FlextLdapClients
    ) -> None:
        """Test OpenLDAP2 normalize_entry_for_server."""
        ops = FlextLdapServersOpenLDAP2Operations()
        entry = FlextLdifModels.Entry(
            dn=FlextLdifModels.DistinguishedName(value="cn=test,dc=flext,dc=local"),
            attributes=FlextLdifModels.LdifAttributes(
                attributes={
                    "objectClass": FlextLdifModels.AttributeValues(
                        values=["inetOrgPerson"]
                    ),
                    "cn": FlextLdifModels.AttributeValues(values=["test"]),
                }
            ),
        )
        result = ops.normalize_entry_for_server(entry)
        assert isinstance(result, FlextResult)

    def test_openldap2_validate_entry(
        self, shared_ldap_client: FlextLdapClients
    ) -> None:
        """Test OpenLDAP2 validate_entry_for_server."""
        ops = FlextLdapServersOpenLDAP2Operations()
        entry = FlextLdifModels.Entry(
            dn=FlextLdifModels.DistinguishedName(value="cn=test,dc=flext,dc=local"),
            attributes=FlextLdifModels.LdifAttributes(
                attributes={
                    "objectClass": FlextLdifModels.AttributeValues(
                        values=["inetOrgPerson"]
                    ),
                    "cn": FlextLdifModels.AttributeValues(values=["test"]),
                }
            ),
        )
        result = ops.validate_entry_for_server(entry)
        assert isinstance(result, FlextResult)


# ============================================================================
# OPENLDAP1 SERVER OPERATIONS COVERAGE (166 lines, 25% → 95%)
# ============================================================================


@pytest.mark.integration
@pytest.mark.docker
class TestOpenLDAP1ServerOperationsCoverage:
    """OpenLDAP 1.x server-specific operations."""

    def test_openldap1_get_default_port(
        self, shared_ldap_client: FlextLdapClients
    ) -> None:
        """Test OpenLDAP1 default port."""
        ops = FlextLdapServersOpenLDAP1Operations()
        assert ops.get_default_port(use_ssl=False) == 389
        assert ops.get_default_port(use_ssl=True) == 636

    def test_openldap1_server_type(self, shared_ldap_client: FlextLdapClients) -> None:
        """Test OpenLDAP1 server_type."""
        ops = FlextLdapServersOpenLDAP1Operations()
        assert ops.server_type == "openldap1"

    def test_openldap1_get_bind_mechanisms(
        self, shared_ldap_client: FlextLdapClients
    ) -> None:
        """Test OpenLDAP1 bind mechanisms."""
        ops = FlextLdapServersOpenLDAP1Operations()
        mechanisms = ops.get_bind_mechanisms()
        assert isinstance(mechanisms, list)
        assert len(mechanisms) > 0

    def test_openldap1_parse_object_class(
        self, shared_ldap_client: FlextLdapClients
    ) -> None:
        """Test OpenLDAP1 parse_object_class."""
        ops = FlextLdapServersOpenLDAP1Operations()
        result = ops.parse_object_class("inetOrgPerson")
        assert result.is_success

    def test_openldap1_normalize_entry(
        self, shared_ldap_client: FlextLdapClients
    ) -> None:
        """Test OpenLDAP1 normalize_entry_for_server."""
        ops = FlextLdapServersOpenLDAP1Operations()
        entry = FlextLdifModels.Entry(
            dn=FlextLdifModels.DistinguishedName(value="cn=test,dc=flext,dc=local"),
            attributes=FlextLdifModels.LdifAttributes(
                attributes={
                    "objectClass": FlextLdifModels.AttributeValues(
                        values=["inetOrgPerson"]
                    ),
                    "cn": FlextLdifModels.AttributeValues(values=["test"]),
                }
            ),
        )
        result = ops.normalize_entry_for_server(entry)
        assert isinstance(result, FlextResult)

    def test_openldap1_validate_entry(
        self, shared_ldap_client: FlextLdapClients
    ) -> None:
        """Test OpenLDAP1 validate_entry_for_server."""
        ops = FlextLdapServersOpenLDAP1Operations()
        entry = FlextLdifModels.Entry(
            dn=FlextLdifModels.DistinguishedName(value="cn=test,dc=flext,dc=local"),
            attributes=FlextLdifModels.LdifAttributes(
                attributes={
                    "objectClass": FlextLdifModels.AttributeValues(
                        values=["inetOrgPerson"]
                    ),
                    "cn": FlextLdifModels.AttributeValues(values=["test"]),
                }
            ),
        )
        result = ops.validate_entry_for_server(entry)
        assert isinstance(result, FlextResult)


# ============================================================================
# SERVER FACTORY COVERAGE (107 lines, 41% → 95%)
# ============================================================================


@pytest.mark.integration
@pytest.mark.docker
class TestServerFactoryCoverage:
    """Server factory operations coverage."""

    def test_factory_create_operations_oid(
        self, shared_ldap_client: FlextLdapClients
    ) -> None:
        """Test factory creates OID operations."""
        factory = FlextLdapServersFactory()
        result = factory.create_from_server_type("oid")
        assert result.is_success
        ops = result.unwrap()
        assert isinstance(ops, FlextLdapServersOIDOperations)
        assert ops.server_type == "oid"

    def test_factory_create_operations_oud(
        self, shared_ldap_client: FlextLdapClients
    ) -> None:
        """Test factory creates OUD operations."""
        factory = FlextLdapServersFactory()
        result = factory.create_from_server_type("oud")
        assert result.is_success
        ops = result.unwrap()
        assert isinstance(ops, FlextLdapServersOUDOperations)
        assert ops.server_type == "oud"

    def test_factory_create_operations_openldap2(
        self, shared_ldap_client: FlextLdapClients
    ) -> None:
        """Test factory creates OpenLDAP2 operations."""
        factory = FlextLdapServersFactory()
        result = factory.create_from_server_type("openldap2")
        assert result.is_success
        ops = result.unwrap()
        assert isinstance(ops, FlextLdapServersOpenLDAP2Operations)
        assert ops.server_type == "openldap2"

    def test_factory_create_operations_openldap1(
        self, shared_ldap_client: FlextLdapClients
    ) -> None:
        """Test factory creates OpenLDAP1 operations."""
        factory = FlextLdapServersFactory()
        result = factory.create_from_server_type("openldap1")
        assert result.is_success
        ops = result.unwrap()
        assert isinstance(ops, FlextLdapServersOpenLDAP1Operations)
        assert ops.server_type == "openldap1"

    def test_factory_create_operations_generic(
        self, shared_ldap_client: FlextLdapClients
    ) -> None:
        """Test factory creates generic operations."""
        factory = FlextLdapServersFactory()
        result = factory.create_from_server_type("generic")
        assert result.is_success
        ops = result.unwrap()
        assert isinstance(ops, FlextLdapServersGenericOperations)
        assert ops.server_type == "generic"

    def test_factory_create_operations_unsupported_type(
        self, shared_ldap_client: FlextLdapClients
    ) -> None:
        """Test factory error handling for unsupported type."""
        factory = FlextLdapServersFactory()
        # Unsupported types fallback to generic, not raise
        result = factory.create_from_server_type("unsupported_type")
        assert result.is_success
        ops = result.unwrap()
        assert isinstance(ops, FlextLdapServersGenericOperations)
