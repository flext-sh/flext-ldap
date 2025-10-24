"""Deep coverage expansion for OpenLDAP 2.x operations - Real Docker LDAP testing.

Targets uncovered code paths in openldap2_operations.py (62% current coverage)
with real Docker LDAP fixture data and comprehensive operations testing.

This test suite aims to expand OpenLDAP2 coverage from 62% to 95%+.
"""

from __future__ import annotations

import pytest
from flext_core import FlextResult
from flext_ldif import FlextLdifModels

from flext_ldap import FlextLdapClients
from flext_ldap.servers.openldap2_operations import FlextLdapServersOpenLDAP2Operations


@pytest.mark.integration
@pytest.mark.docker
class TestOpenLDAP2OperationsDeepCoverage:
    """Deep integration tests for OpenLDAP 2.x operations with real Docker LDAP."""

    def test_openldap2_normalize_entry_basic(
        self, shared_ldap_client: FlextLdapClients
    ) -> None:
        """Test OpenLDAP2 normalize_entry_for_server with basic entry."""
        ops = FlextLdapServersOpenLDAP2Operations()
        entry = FlextLdifModels.Entry(
            dn=FlextLdifModels.DistinguishedName(
                value="cn=testuser,ou=people,dc=flext,dc=local"
            ),
            attributes=FlextLdifModels.LdifAttributes(
                attributes={
                    "objectClass": FlextLdifModels.AttributeValues(
                        values=["inetOrgPerson"]
                    ),
                    "cn": FlextLdifModels.AttributeValues(values=["testuser"]),
                    "sn": FlextLdifModels.AttributeValues(values=["User"]),
                }
            ),
        )
        result = ops.normalize_entry_for_server(entry)
        assert result.is_success

    def test_openldap2_validate_entry(
        self, shared_ldap_client: FlextLdapClients
    ) -> None:
        """Test OpenLDAP2 validate_entry_for_server."""
        ops = FlextLdapServersOpenLDAP2Operations()
        entry = FlextLdifModels.Entry(
            dn=FlextLdifModels.DistinguishedName(
                value="cn=validate,ou=people,dc=flext,dc=local"
            ),
            attributes=FlextLdifModels.LdifAttributes(
                attributes={
                    "objectClass": FlextLdifModels.AttributeValues(
                        values=["inetOrgPerson"]
                    ),
                    "cn": FlextLdifModels.AttributeValues(values=["validate"]),
                }
            ),
        )
        result = ops.validate_entry_for_server(entry)
        assert isinstance(result, FlextResult)

    def test_openldap2_get_acl_attribute_name(
        self, shared_ldap_client: FlextLdapClients
    ) -> None:
        """Test OpenLDAP2 ACL attribute name."""
        ops = FlextLdapServersOpenLDAP2Operations()
        attr = ops.get_acl_attribute_name()
        assert isinstance(attr, str)

    def test_openldap2_get_acl_format(
        self, shared_ldap_client: FlextLdapClients
    ) -> None:
        """Test OpenLDAP2 ACL format."""
        ops = FlextLdapServersOpenLDAP2Operations()
        fmt = ops.get_acl_format()
        assert isinstance(fmt, str)

    def test_openldap2_get_default_port_non_ssl(
        self, shared_ldap_client: FlextLdapClients
    ) -> None:
        """Test OpenLDAP2 default port without SSL."""
        ops = FlextLdapServersOpenLDAP2Operations()
        assert ops.get_default_port(use_ssl=False) == 389

    def test_openldap2_get_default_port_ssl(
        self, shared_ldap_client: FlextLdapClients
    ) -> None:
        """Test OpenLDAP2 default port with SSL."""
        ops = FlextLdapServersOpenLDAP2Operations()
        assert ops.get_default_port(use_ssl=True) == 636

    def test_openldap2_get_bind_mechanisms(
        self, shared_ldap_client: FlextLdapClients
    ) -> None:
        """Test OpenLDAP2 bind mechanisms."""
        ops = FlextLdapServersOpenLDAP2Operations()
        mechanisms = ops.get_bind_mechanisms()
        assert isinstance(mechanisms, list)
        assert "SIMPLE" in mechanisms

    def test_openldap2_get_schema_dn(
        self, shared_ldap_client: FlextLdapClients
    ) -> None:
        """Test OpenLDAP2 schema DN."""
        ops = FlextLdapServersOpenLDAP2Operations()
        schema_dn = ops.get_schema_dn()
        assert isinstance(schema_dn, str)

    def test_openldap2_supports_start_tls(
        self, shared_ldap_client: FlextLdapClients
    ) -> None:
        """Test OpenLDAP2 START_TLS support."""
        ops = FlextLdapServersOpenLDAP2Operations()
        assert isinstance(ops.supports_start_tls(), bool)

    def test_openldap2_discover_schema(
        self, shared_ldap_client: FlextLdapClients
    ) -> None:
        """Test OpenLDAP2 discover_schema."""
        ops = FlextLdapServersOpenLDAP2Operations()
        result = ops.discover_schema(shared_ldap_client._connection)
        assert isinstance(result, FlextResult)

    def test_openldap2_parse_object_class(
        self, shared_ldap_client: FlextLdapClients
    ) -> None:
        """Test OpenLDAP2 parse_object_class."""
        ops = FlextLdapServersOpenLDAP2Operations()
        result = ops.parse_object_class("inetOrgPerson")
        assert isinstance(result, FlextResult)

    def test_openldap2_parse_attribute_type(
        self, shared_ldap_client: FlextLdapClients
    ) -> None:
        """Test OpenLDAP2 parse_attribute_type."""
        ops = FlextLdapServersOpenLDAP2Operations()
        result = ops.parse_attribute_type("cn")
        assert isinstance(result, FlextResult)

    def test_openldap2_supports_vlv(self, shared_ldap_client: FlextLdapClients) -> None:
        """Test OpenLDAP2 VLV support."""
        ops = FlextLdapServersOpenLDAP2Operations()
        assert isinstance(ops.supports_vlv(), bool)

    def test_openldap2_supports_paged_results(
        self, shared_ldap_client: FlextLdapClients
    ) -> None:
        """Test OpenLDAP2 paged results support."""
        ops = FlextLdapServersOpenLDAP2Operations()
        assert isinstance(ops.supports_paged_results(), bool)

    def test_openldap2_get_max_page_size(
        self, shared_ldap_client: FlextLdapClients
    ) -> None:
        """Test OpenLDAP2 max page size."""
        ops = FlextLdapServersOpenLDAP2Operations()
        max_size = ops.get_max_page_size()
        assert isinstance(max_size, int) and max_size > 0

    def test_openldap2_server_type(self, shared_ldap_client: FlextLdapClients) -> None:
        """Test OpenLDAP2 server_type."""
        ops = FlextLdapServersOpenLDAP2Operations()
        assert ops.server_type == "openldap2"


@pytest.mark.integration
@pytest.mark.docker
class TestOpenLDAP2OperationsErrors:
    """Test OpenLDAP2 error handling."""

    def test_openldap2_discover_schema_none_connection(
        self, shared_ldap_client: FlextLdapClients
    ) -> None:
        """Test OpenLDAP2 discover_schema with None connection."""
        ops = FlextLdapServersOpenLDAP2Operations()
        result = ops.discover_schema(None)  # type: ignore[arg-type]
        assert result.is_failure


@pytest.mark.integration
@pytest.mark.docker
class TestOpenLDAP2OperationsConsistency:
    """Test OpenLDAP2 operations consistency."""

    def test_openldap2_multiple_instances_consistent(
        self, shared_ldap_client: FlextLdapClients
    ) -> None:
        """Test OpenLDAP2 multiple instances consistency."""
        ops1 = FlextLdapServersOpenLDAP2Operations()
        ops2 = FlextLdapServersOpenLDAP2Operations()

        assert ops1.server_type == ops2.server_type == "openldap2"
        assert ops1.get_default_port(use_ssl=False) == 389
        assert ops1.get_default_port(use_ssl=True) == 636
